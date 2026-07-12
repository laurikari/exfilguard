use std::collections::HashSet;

use anyhow::{Context, Result, anyhow, ensure};
use http::{
    HeaderMap,
    header::{HeaderName, HeaderValue},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderDisposition {
    Connection,
    Host,
    ContentLength,
    TransferEncoding,
    Skip,
    Forward,
}

/// Returns true when the header conveys forwarding metadata that should be stripped.
pub fn is_forwarding_header(name: &str) -> bool {
    if name.starts_with("x-forwarded-") {
        return true;
    }
    matches!(
        name,
        "forwarded"
            | "x-real-ip"
            | "x-client-ip"
            | "x-cluster-client-ip"
            | "true-client-ip"
            | "cf-connecting-ip"
            | "fastly-client-ip"
            | "fly-client-ip"
            | "x-forwarded-client-cert"
            | "x-forwarded-proto"
            | "x-forwarded-port"
            | "x-forwarded-host"
    ) || name.ends_with("-client-ip")
}

pub fn classify_request_header(name: &str) -> HeaderDisposition {
    if name == "connection" {
        HeaderDisposition::Connection
    } else if name == "host" {
        HeaderDisposition::Host
    } else if name == "content-length" {
        HeaderDisposition::ContentLength
    } else if name == "transfer-encoding" {
        HeaderDisposition::TransferEncoding
    } else if name.starts_with("proxy-")
        || matches!(name, "keep-alive" | "upgrade" | "proxy-connection" | "te")
        || is_forwarding_header(name)
    {
        HeaderDisposition::Skip
    } else {
        HeaderDisposition::Forward
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderAction {
    Forward,
    Skip,
}

const HEADER_OVERHEAD: usize = 4; // ': ' plus CRLF

pub(crate) fn canonical_header_line(name: &str, value: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(name.len() + value.len() + HEADER_OVERHEAD);
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(b": ");
    bytes.extend_from_slice(value.as_bytes());
    bytes.extend_from_slice(b"\r\n");
    bytes
}

#[derive(Debug, Clone)]
pub struct RequestHeaderSanitizer {
    max_bytes: usize,
    consumed: usize,
    host: Option<String>,
    content_length: Option<usize>,
    chunked: bool,
    connection_tokens: HashSet<String>,
    connection_seen: bool,
    transfer_encoding_seen: bool,
}

impl RequestHeaderSanitizer {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            consumed: 0,
            host: None,
            content_length: None,
            chunked: false,
            connection_tokens: HashSet::new(),
            connection_seen: false,
            transfer_encoding_seen: false,
        }
    }

    pub fn reserve(&mut self, byte_len: usize) -> Result<()> {
        self.consumed = self
            .consumed
            .checked_add(byte_len)
            .ok_or_else(|| anyhow!("header section exceeds configured limit"))?;
        ensure!(
            self.consumed <= self.max_bytes,
            "header section exceeds configured limit"
        );
        Ok(())
    }

    pub fn record(&mut self, name: &str, value: &str, byte_len: usize) -> Result<HeaderAction> {
        self.reserve(byte_len)?;

        let name_lower = name.to_ascii_lowercase();
        match classify_request_header(&name_lower) {
            HeaderDisposition::Connection => {
                if self.connection_seen {
                    anyhow::bail!("duplicate Connection header");
                }
                self.connection_seen = true;
                self.record_connection_tokens(value);
                Ok(HeaderAction::Skip)
            }
            HeaderDisposition::Host => {
                if self.host.is_some() {
                    anyhow::bail!("duplicate Host header");
                }
                ensure!(!value.is_empty(), "Host header must not be empty");
                self.host = Some(value.to_ascii_lowercase());
                Ok(HeaderAction::Skip)
            }
            HeaderDisposition::ContentLength => {
                if self.chunked {
                    anyhow::bail!(
                        "request must not include both Content-Length and Transfer-Encoding"
                    );
                }
                if self.content_length.is_some() {
                    anyhow::bail!("multiple Content-Length headers are not supported");
                }
                let length: usize = value
                    .parse()
                    .with_context(|| format!("invalid Content-Length value '{value}'"))?;
                self.content_length = Some(length);
                Ok(HeaderAction::Skip)
            }
            HeaderDisposition::TransferEncoding => {
                if self.transfer_encoding_seen {
                    anyhow::bail!("duplicate Transfer-Encoding header");
                }
                self.transfer_encoding_seen = true;
                let encodings: Vec<String> = value
                    .split(',')
                    .map(|item| item.trim().to_ascii_lowercase())
                    .filter(|item| !item.is_empty())
                    .collect();
                if encodings.is_empty() || encodings.len() != 1 || encodings[0] != "chunked" {
                    anyhow::bail!("unsupported Transfer-Encoding '{value}'");
                }
                if self.content_length.is_some() {
                    anyhow::bail!(
                        "request must not include both Content-Length and Transfer-Encoding"
                    );
                }
                self.chunked = true;
                Ok(HeaderAction::Skip)
            }
            HeaderDisposition::Skip => Ok(HeaderAction::Skip),
            HeaderDisposition::Forward => Ok(HeaderAction::Forward),
        }
    }

    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    pub fn content_length(&self) -> Option<usize> {
        self.content_length
    }

    pub fn is_chunked(&self) -> bool {
        self.chunked
    }

    pub fn total_bytes(&self) -> usize {
        self.consumed
    }

    pub fn connection_tokens(&self) -> &HashSet<String> {
        &self.connection_tokens
    }

    fn record_connection_tokens(&mut self, value: &str) {
        for token in value.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }
            self.connection_tokens.insert(trimmed.to_ascii_lowercase());
        }
    }

    pub fn record_name_value(&mut self, name: &str, value: &str) -> Result<HeaderAction> {
        let byte_len = name
            .len()
            .checked_add(value.len())
            .and_then(|len| len.checked_add(HEADER_OVERHEAD))
            .ok_or_else(|| anyhow!("header section exceeds configured limit"))?;
        self.record(name, value, byte_len)
    }
}

pub(crate) fn sanitize_request_trailer_lines(lines: &[String]) -> Result<Vec<Vec<u8>>> {
    let mut sanitized = Vec::with_capacity(lines.len());
    for line in lines {
        let (name, value) = parse_header_line(line)?;
        if name.eq_ignore_ascii_case("expect") {
            anyhow::bail!("request trailers must not include Expect");
        }
        if name.eq_ignore_ascii_case("trailer") {
            anyhow::bail!("request trailers must not include Trailer");
        }

        match classify_request_header(&name.to_ascii_lowercase()) {
            HeaderDisposition::Connection => {
                anyhow::bail!("request trailers must not include Connection");
            }
            HeaderDisposition::Host => {
                anyhow::bail!("request trailers must not include Host");
            }
            HeaderDisposition::ContentLength => {
                anyhow::bail!("request trailers must not include Content-Length");
            }
            HeaderDisposition::TransferEncoding => {
                anyhow::bail!("request trailers must not include Transfer-Encoding");
            }
            HeaderDisposition::Skip => {}
            HeaderDisposition::Forward => {
                sanitized.push(canonical_header_line(&name, &value));
            }
        }
    }
    Ok(sanitized)
}

pub(crate) fn sanitize_request_trailer_map(
    headers: &HeaderMap,
    max_bytes: usize,
) -> Result<HeaderMap> {
    let mut total = 0usize;
    let mut sanitized = HeaderMap::new();

    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        let value_str = value
            .to_str()
            .with_context(|| format!("request trailer '{name_str}' contains invalid characters"))?;
        let line_bytes = name_str
            .len()
            .checked_add(value.as_bytes().len())
            .and_then(|len| len.checked_add(HEADER_OVERHEAD))
            .ok_or_else(|| anyhow!("request trailer section exceeds configured limit"))?;
        total = total
            .checked_add(line_bytes)
            .ok_or_else(|| anyhow!("request trailer section exceeds configured limit"))?;
        ensure!(
            total <= max_bytes,
            "request trailer section exceeds configured limit"
        );

        if name_str.eq_ignore_ascii_case("expect") {
            anyhow::bail!("request trailers must not include Expect");
        }
        if name_str.eq_ignore_ascii_case("trailer") {
            anyhow::bail!("request trailers must not include Trailer");
        }

        match classify_request_header(name_str) {
            HeaderDisposition::Connection => {
                anyhow::bail!("request trailers must not include Connection");
            }
            HeaderDisposition::Host => {
                anyhow::bail!("request trailers must not include Host");
            }
            HeaderDisposition::ContentLength => {
                anyhow::bail!("request trailers must not include Content-Length");
            }
            HeaderDisposition::TransferEncoding => {
                anyhow::bail!("request trailers must not include Transfer-Encoding");
            }
            HeaderDisposition::Skip => {}
            HeaderDisposition::Forward => {
                sanitized.append(name.clone(), HeaderValue::from_str(value_str)?);
            }
        }
    }

    Ok(sanitized)
}

pub(crate) fn response_header_should_skip(
    name_lower: &str,
    connection_tokens: &HashSet<String>,
) -> bool {
    name_lower == "connection"
        || name_lower == "keep-alive"
        || name_lower == "proxy-connection"
        || name_lower == "proxy-authenticate"
        || name_lower == "proxy-authorization"
        || name_lower == "te"
        || name_lower == "upgrade"
        || name_lower == "transfer-encoding"
        || name_lower == "trailer"
        || connection_tokens.contains(name_lower)
}

pub(crate) fn sanitize_response_trailer_lines(lines: &[String]) -> Result<Vec<Vec<u8>>> {
    let parsed = parse_response_trailers(lines)?;
    Ok(parsed
        .into_iter()
        .map(|(name, value)| canonical_header_line(&name, &value))
        .collect())
}

pub(crate) fn sanitize_response_trailer_map(
    headers: &HeaderMap,
    max_bytes: usize,
) -> Result<HeaderMap> {
    let mut total = 0usize;
    let mut connection_tokens = HashSet::new();

    for value in headers.get_all(http::header::CONNECTION) {
        if let Ok(s) = value.to_str() {
            record_connection_tokens(&mut connection_tokens, s);
        }
    }

    let mut sanitized = HeaderMap::new();
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        let line_bytes = name_str
            .len()
            .checked_add(value.as_bytes().len())
            .and_then(|len| len.checked_add(HEADER_OVERHEAD))
            .ok_or_else(|| anyhow!("response trailer section exceeds configured limit"))?;
        total = total
            .checked_add(line_bytes)
            .ok_or_else(|| anyhow!("response trailer section exceeds configured limit"))?;
        ensure!(
            total <= max_bytes,
            "response trailer section exceeds configured limit"
        );

        let lower = name_str.to_ascii_lowercase();
        if lower == "content-length" || response_header_should_skip(&lower, &connection_tokens) {
            continue;
        }
        sanitized.append(name.clone(), value.clone());
    }

    Ok(sanitized)
}

fn parse_header_line(line: &str) -> Result<(String, String)> {
    let (name, value) = line
        .split_once(':')
        .ok_or_else(|| anyhow!("header missing ':' separator"))?;
    let name = name.trim().to_string();
    let value = value.trim().to_string();
    parse_header_name_value(&name, &value)?;
    Ok((name, value))
}

fn parse_response_trailers(lines: &[String]) -> Result<Vec<(String, String)>> {
    let mut parsed = Vec::with_capacity(lines.len());
    let mut connection_tokens = HashSet::new();

    for line in lines {
        let (name, value) = parse_header_line(line)?;
        if name.eq_ignore_ascii_case("connection") {
            record_connection_tokens(&mut connection_tokens, &value);
        }
        parsed.push((name, value));
    }

    Ok(parsed
        .into_iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            lower != "content-length" && !response_header_should_skip(&lower, &connection_tokens)
        })
        .collect())
}

fn parse_header_name_value(name: &str, value: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("header name must not be empty");
    }
    HeaderName::from_bytes(name.as_bytes()).map_err(|_| anyhow!("invalid header name '{name}'"))?;
    HeaderValue::from_bytes(value.as_bytes())
        .map_err(|_| anyhow!("invalid header value for '{name}'"))?;
    Ok(())
}

fn record_connection_tokens(tokens: &mut HashSet<String>, value: &str) {
    for token in value.split(',') {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        tokens.insert(trimmed.to_ascii_lowercase());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{
        HeaderMap,
        header::{HeaderName, HeaderValue},
    };

    #[test]
    fn rejects_duplicate_host() {
        let mut sanitizer = RequestHeaderSanitizer::new(256);
        assert!(matches!(
            sanitizer.record("Host", "example.com", 16),
            Ok(HeaderAction::Skip)
        ));
        let err = sanitizer
            .record("Host", "other.example.com", 32)
            .expect_err("expected duplicate host to error");
        assert!(
            err.to_string().contains("duplicate Host"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn allows_duplicate_set_cookie() {
        let mut sanitizer = RequestHeaderSanitizer::new(256);
        assert!(matches!(
            sanitizer.record("Set-Cookie", "a=1", 18),
            Ok(HeaderAction::Forward)
        ));
        assert!(matches!(
            sanitizer.record("Set-Cookie", "b=2", 18),
            Ok(HeaderAction::Forward)
        ));
    }

    #[test]
    fn allows_duplicate_standard_headers() {
        let mut sanitizer = RequestHeaderSanitizer::new(256);
        assert!(matches!(
            sanitizer.record("Accept", "text/plain", 24),
            Ok(HeaderAction::Forward)
        ));
        assert!(matches!(
            sanitizer.record("Accept", "application/json", 32),
            Ok(HeaderAction::Forward)
        ));
    }

    #[test]
    fn rejects_conflicting_content_length_and_transfer_encoding() {
        let mut sanitizer = RequestHeaderSanitizer::new(256);
        assert!(matches!(
            sanitizer.record("Transfer-Encoding", "chunked", 32),
            Ok(HeaderAction::Skip)
        ));
        let err = sanitizer
            .record("Content-Length", "10", 24)
            .expect_err("expected conflict to error");
        assert!(
            err.to_string()
                .contains("must not include both Content-Length and Transfer-Encoding"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn rejects_invalid_content_length_value() {
        let mut sanitizer = RequestHeaderSanitizer::new(256);
        let err = sanitizer
            .record("Content-Length", "nope", 24)
            .expect_err("expected invalid Content-Length to error");
        assert!(
            err.to_string().contains("invalid Content-Length value"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn rejects_duplicate_content_length() {
        let mut sanitizer = RequestHeaderSanitizer::new(256);
        assert!(matches!(
            sanitizer.record("Content-Length", "10", 24),
            Ok(HeaderAction::Skip)
        ));
        let err = sanitizer
            .record("Content-Length", "10", 24)
            .expect_err("expected duplicate Content-Length to error");
        assert!(
            err.to_string()
                .contains("multiple Content-Length headers are not supported"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn rejects_exceeding_max_bytes() {
        let mut sanitizer = RequestHeaderSanitizer::new(16);
        let err = sanitizer
            .record("User-Agent", "toolong", 32)
            .expect_err("expected oversize header to error");
        assert!(
            err.to_string()
                .contains("header section exceeds configured limit"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn skip_connection_tokens_and_track_close() {
        let mut sanitizer = RequestHeaderSanitizer::new(128);
        assert!(matches!(
            sanitizer.record("Connection", "keep-alive, Close", 32),
            Ok(HeaderAction::Skip)
        ));
        assert!(sanitizer.connection_tokens().contains("close"));
        assert!(matches!(
            sanitizer.record("Foo", "bar", 16),
            Ok(HeaderAction::Forward)
        ));
    }

    #[test]
    fn request_trailers_reject_host_and_strip_forwarding_headers() {
        let err = sanitize_request_trailer_lines(&["Host: example.com".to_string()])
            .expect_err("Host trailer should be rejected");
        assert!(err.to_string().contains("Host"), "unexpected error: {err}");

        let sanitized = sanitize_request_trailer_lines(&[
            "Digest: sha-256=abc".to_string(),
            "X-Forwarded-For: 127.0.0.1".to_string(),
        ])
        .expect("sanitize request trailers");
        assert_eq!(sanitized, vec![b"Digest: sha-256=abc\r\n".to_vec()]);
    }

    #[test]
    fn response_trailers_strip_hop_by_hop_fields() {
        let sanitized = sanitize_response_trailer_lines(&[
            "Connection: Foo".to_string(),
            "Foo: bar".to_string(),
            "Digest: sha-256=abc".to_string(),
            "Content-Length: 5".to_string(),
            "Transfer-Encoding: chunked".to_string(),
        ])
        .expect("sanitize response trailers");
        assert_eq!(sanitized, vec![b"Digest: sha-256=abc\r\n".to_vec()]);
    }

    #[test]
    fn response_header_skip_keeps_content_length() {
        let tokens = HashSet::new();
        assert!(!response_header_should_skip("content-length", &tokens));
        assert!(response_header_should_skip("te", &tokens));
    }

    #[test]
    fn request_trailer_map_enforces_size_limit() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("digest"),
            HeaderValue::from_static("sha-256=abc"),
        );
        let err = sanitize_request_trailer_map(&headers, 4).expect_err("expected size error");
        assert!(
            err.to_string().contains("exceeds configured limit"),
            "unexpected error: {err}"
        );
    }
}
