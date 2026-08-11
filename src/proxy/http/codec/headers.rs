use anyhow::{Result, anyhow, bail};
use http::{
    HeaderMap,
    header::{HeaderName, HeaderValue},
};
use zeroize::Zeroizing;

use crate::proxy::headers::{HeaderAction, RequestHeaderSanitizer};

#[derive(Clone)]
pub(crate) struct Http1HeaderLine {
    name: HeaderName,
    value: HeaderValue,
    name_text: String,
    value_text: String,
}

impl Http1HeaderLine {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Result<Self> {
        let name_text = name.into();
        let value_text = value.into();
        let name = parse_header_name(&name_text)?;
        let value = parse_header_value(name.as_str(), &value_text)?;
        Ok(Self {
            name,
            value,
            name_text,
            value_text,
        })
    }

    pub fn lower_name(&self) -> &str {
        self.name.as_str()
    }

    pub fn name_text(&self) -> &str {
        &self.name_text
    }

    pub fn value_text(&self) -> &str {
        &self.value_text
    }

    pub fn value_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }

    pub fn header_name(&self) -> &HeaderName {
        &self.name
    }

    pub fn header_value(&self) -> &HeaderValue {
        &self.value
    }
}

pub(crate) fn parse_header_name(name: &str) -> Result<HeaderName> {
    if name.is_empty() {
        bail!("header name must not be empty");
    }
    HeaderName::from_bytes(name.as_bytes()).map_err(|_| anyhow!("invalid header name '{name}'"))
}

pub(crate) fn parse_header_value(name: &str, value: &str) -> Result<HeaderValue> {
    HeaderValue::from_bytes(value.as_bytes())
        .map_err(|_| anyhow!("invalid header value for '{name}'"))
}

pub(crate) fn parse_header_line(line: &str) -> Result<Option<(&str, &str)>> {
    if !line.ends_with("\r\n") {
        bail!("header line must end with CRLF");
    }

    let field = &line[..line.len() - 2];
    if field.is_empty() {
        return Ok(None);
    }
    if field.contains(['\r', '\n']) {
        bail!("header line must contain exactly one terminating CRLF");
    }

    let (name, value) = field
        .split_once(':')
        .ok_or_else(|| anyhow!("header missing ':' separator"))?;
    let value = value.trim_matches(|ch| matches!(ch, ' ' | '\t'));
    parse_header_name(name)?;
    parse_header_value(name, value)?;
    Ok(Some((name, value)))
}

pub(crate) struct Http1HeaderAccumulator {
    sanitizer: RequestHeaderSanitizer,
    headers: Vec<Http1HeaderLine>,
    proxy_authorizations: Vec<Zeroizing<Vec<u8>>>,
}

impl Http1HeaderAccumulator {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            sanitizer: RequestHeaderSanitizer::new(max_bytes),
            headers: Vec::new(),
            proxy_authorizations: Vec::new(),
        }
    }

    pub fn push_line(&mut self, line: &str) -> Result<bool> {
        let line_len = line.len();
        let Some((name, value)) = parse_header_line(line)? else {
            self.sanitizer.reserve(line_len)?;
            return Ok(false);
        };
        let action = self.sanitizer.record(name, value, line_len)?;
        if name.eq_ignore_ascii_case("proxy-authorization") {
            self.proxy_authorizations
                .push(Zeroizing::new(value.as_bytes().to_vec()));
        }
        match action {
            HeaderAction::Forward => {
                self.headers.push(Http1HeaderLine::new(name, value)?);
            }
            HeaderAction::Skip => {}
        }
        Ok(true)
    }

    pub fn host(&self) -> Option<&str> {
        self.sanitizer.host()
    }

    pub fn content_length(&self) -> Option<usize> {
        self.sanitizer.content_length()
    }

    pub fn is_chunked(&self) -> bool {
        self.sanitizer.is_chunked()
    }

    pub fn forward_headers(&self) -> impl Iterator<Item = &Http1HeaderLine> {
        self.headers
            .iter()
            .filter(move |header| !self.has_connection_token(header.lower_name()))
    }

    pub fn forward_header_map(&self) -> HeaderMap {
        header_lines_to_map(self.forward_headers())
    }

    pub fn has_header(&self, lower_name: &str) -> bool {
        self.headers
            .iter()
            .any(|header| header.lower_name() == lower_name)
    }

    pub(crate) fn proxy_authorizations(&self) -> &[Zeroizing<Vec<u8>>] {
        &self.proxy_authorizations
    }

    pub fn has_sensitive_cache_headers(&self) -> bool {
        self.has_header("authorization") || self.has_header("cookie")
    }

    pub fn expect_continue(&self) -> Result<bool> {
        let mut seen = false;
        for header in &self.headers {
            if header.lower_name() != "expect" {
                continue;
            }
            if seen {
                bail!("multiple Expect headers are not supported");
            }
            if !header.value_text().eq_ignore_ascii_case("100-continue") {
                bail!("unsupported Expect header value '{}'", header.value_text());
            }
            seen = true;
        }
        Ok(seen)
    }

    pub fn total_bytes(&self) -> usize {
        self.sanitizer.total_bytes()
    }

    pub fn has_connection_token(&self, token: &str) -> bool {
        self.sanitizer.connection_tokens().contains(token)
    }

    pub fn wants_connection_close(&self) -> bool {
        self.has_connection_token("close")
    }
}

pub(super) fn header_lines_to_map<'a, I>(headers: I) -> HeaderMap
where
    I: Iterator<Item = &'a Http1HeaderLine>,
{
    let mut map = HeaderMap::new();
    for header in headers {
        map.append(header.header_name().clone(), header.header_value().clone());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::Http1HeaderAccumulator;

    #[test]
    fn forward_headers_skip_connection_tokens() {
        let mut accumulator = Http1HeaderAccumulator::new(256);
        assert!(matches!(
            accumulator.push_line("Connection: Foo\r\n"),
            Ok(true)
        ));
        assert!(matches!(accumulator.push_line("Foo: bar\r\n"), Ok(true)));
        assert!(matches!(accumulator.push_line("Bar: baz\r\n"), Ok(true)));
        assert!(matches!(accumulator.push_line("\r\n"), Ok(false)));
        let names: Vec<_> = accumulator
            .forward_headers()
            .map(|header| header.name_text())
            .collect();
        assert!(
            names.contains(&"Bar"),
            "Expected Bar header to be forwarded: {names:?}"
        );
        assert!(
            !names.contains(&"Foo"),
            "Foo header should be skipped due to Connection token"
        );
    }

    #[test]
    fn expect_continue_detects_header() -> anyhow::Result<()> {
        let mut accumulator = Http1HeaderAccumulator::new(256);
        assert!(matches!(
            accumulator.push_line("Expect: 100-continue\r\n"),
            Ok(true)
        ));
        assert!(matches!(accumulator.push_line("\r\n"), Ok(false)));
        assert!(accumulator.expect_continue()?);
        Ok(())
    }

    #[test]
    fn proxy_authorization_is_captured_but_never_forwarded() {
        let mut accumulator = Http1HeaderAccumulator::new(256);
        accumulator
            .push_line("Proxy-Authorization: ExfilGuard opaque-token\r\n")
            .unwrap();
        accumulator.push_line("\r\n").unwrap();
        assert_eq!(
            accumulator.proxy_authorizations()[0].as_slice(),
            b"ExfilGuard opaque-token"
        );
        assert!(
            accumulator
                .forward_headers()
                .all(|header| header.lower_name() != "proxy-authorization")
        );
    }

    #[test]
    fn expect_continue_rejects_unknown_value() {
        let mut accumulator = Http1HeaderAccumulator::new(256);
        accumulator
            .push_line("Expect: something-else\r\n")
            .expect("header accepted");
        accumulator.push_line("\r\n").expect("header end");
        let err = accumulator
            .expect_continue()
            .expect_err("unsupported Expect should error");
        assert!(
            err.to_string().contains("unsupported Expect"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reject_invalid_header_name() {
        let mut accumulator = Http1HeaderAccumulator::new(256);
        let err = accumulator
            .push_line("Bad Name: value\r\n")
            .expect_err("invalid header name should error");
        assert!(
            err.to_string().contains("invalid header name"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reject_invalid_header_value() {
        let mut accumulator = Http1HeaderAccumulator::new(256);
        let err = accumulator
            .push_line("X-Test: ok\rX-Evil: 1\r\n")
            .expect_err("invalid header value should error");
        assert!(
            err.to_string().contains("terminating CRLF"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reject_header_line_without_crlf() {
        let mut accumulator = Http1HeaderAccumulator::new(256);
        let err = accumulator
            .push_line("Host: example.com\n")
            .expect_err("header line without CRLF should error");
        assert!(err.to_string().contains("CRLF"), "unexpected error: {err}");
    }

    #[test]
    fn reject_whitespace_around_header_name() {
        for line in [
            " Host: example.com\r\n",
            "Host : example.com\r\n",
            "\tHost: example.com\r\n",
            "Host\t: example.com\r\n",
        ] {
            let mut accumulator = Http1HeaderAccumulator::new(256);
            let err = accumulator
                .push_line(line)
                .expect_err("whitespace around header name should error");
            assert!(
                err.to_string().contains("invalid header name"),
                "unexpected error for {line:?}: {err}"
            );
        }
    }

    #[test]
    fn trim_only_legal_header_value_ows() {
        let mut accumulator = Http1HeaderAccumulator::new(256);
        accumulator
            .push_line("X-Test:\t value \t\r\n")
            .expect("legal OWS should be accepted");
        let header = accumulator
            .forward_headers()
            .next()
            .expect("header should be retained");
        assert_eq!(header.value_text(), "value");

        let err = accumulator
            .push_line("X-Control: \u{b}value\r\n")
            .expect_err("non-OWS whitespace should be rejected");
        assert!(
            err.to_string().contains("invalid header value"),
            "unexpected error: {err}"
        );
    }
}
