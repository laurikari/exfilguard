use anyhow::{Result, anyhow, bail};
use http::{
    HeaderMap,
    header::{HeaderName, HeaderValue},
};

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

pub(crate) struct Http1HeaderAccumulator {
    sanitizer: RequestHeaderSanitizer,
    headers: Vec<Http1HeaderLine>,
}

impl Http1HeaderAccumulator {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            sanitizer: RequestHeaderSanitizer::new(max_bytes),
            headers: Vec::new(),
        }
    }

    pub fn push_line(&mut self, line: &str) -> Result<bool> {
        let line_len = line.len();
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            self.sanitizer.reserve(line_len)?;
            return Ok(false);
        }

        let (name, value) = trimmed
            .split_once(':')
            .ok_or_else(|| anyhow!("header missing ':' separator"))?;
        let name = name.trim();
        let value = value.trim();
        parse_header_name(name)?;
        parse_header_value(name, value)?;
        match self.sanitizer.record(name, value, line_len)? {
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

    pub fn content_length(&self) -> Result<Option<usize>> {
        Ok(self.sanitizer.content_length())
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
            err.to_string().contains("invalid header value"),
            "unexpected error: {err}"
        );
    }
}
