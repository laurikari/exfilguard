use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use http::{HeaderMap, StatusCode, Version};
use tokio::io::{AsyncRead, BufReader};
use tracing::warn;

use crate::proxy::forward_limits::HeaderBudget;
use crate::proxy::http::forward::ResponseBodyPlan;

use super::headers::{Http1HeaderLine, header_lines_to_map};
use super::line::read_line_with_timeout;

#[derive(Clone, Copy)]
pub(crate) enum ConnectionOverride {
    Close,
}

impl ConnectionOverride {
    pub fn as_str(&self) -> &str {
        match self {
            ConnectionOverride::Close => "close",
        }
    }
}

pub(crate) struct Http1ResponseHead {
    pub status_line: String,
    pub status: StatusCode,
    pub headers: Vec<Http1HeaderLine>,
    pub content_length: Option<u64>,
    pub chunked: bool,
    pub transfer_encoding_present: bool,
    pub connection_close: bool,
}

impl Http1ResponseHead {
    pub fn encode(
        &self,
        body_plan: ResponseBodyPlan,
        override_connection: Option<ConnectionOverride>,
    ) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(256);
        buffer.extend_from_slice(self.status_line.as_bytes());
        buffer.extend_from_slice(b"\r\n");

        let mut connection_tokens = HashSet::new();
        for header in &self.headers {
            if header.lower_name() == "connection" {
                for token in header.value.split(',') {
                    let token = token.trim();
                    if token.is_empty() {
                        continue;
                    }
                    connection_tokens.insert(token.to_ascii_lowercase());
                }
            }
        }

        let mut transfer_encodings = Vec::new();
        let mut trailers = Vec::new();

        for header in &self.headers {
            let name_lower = header.lower_name();
            if name_lower == "transfer-encoding" {
                transfer_encodings.push(header.value.clone());
                continue;
            }
            if name_lower == "trailer" {
                trailers.push(header.value.clone());
                continue;
            }
            if name_lower == "content-length" {
                continue;
            }
            if name_lower == "connection"
                || name_lower == "keep-alive"
                || name_lower == "proxy-connection"
                || name_lower == "proxy-authenticate"
                || name_lower == "proxy-authorization"
                || name_lower == "upgrade"
                || connection_tokens.contains(name_lower)
            {
                continue;
            }

            buffer.extend_from_slice(header.name.as_bytes());
            buffer.extend_from_slice(b": ");
            buffer.extend_from_slice(header.value.as_bytes());
            buffer.extend_from_slice(b"\r\n");
        }

        match body_plan {
            ResponseBodyPlan::Chunked => {
                let value = if transfer_encodings.is_empty() {
                    "chunked".to_string()
                } else {
                    transfer_encodings.join(", ")
                };
                buffer.extend_from_slice(b"Transfer-Encoding: ");
                buffer.extend_from_slice(value.as_bytes());
                buffer.extend_from_slice(b"\r\n");
                if !trailers.is_empty() {
                    buffer.extend_from_slice(b"Trailer: ");
                    buffer.extend_from_slice(trailers.join(", ").as_bytes());
                    buffer.extend_from_slice(b"\r\n");
                }
            }
            ResponseBodyPlan::Fixed(length) => {
                buffer.extend_from_slice(b"Content-Length: ");
                buffer.extend_from_slice(length.to_string().as_bytes());
                buffer.extend_from_slice(b"\r\n");
            }
            ResponseBodyPlan::Empty => {
                if let Some(length) = self.content_length {
                    buffer.extend_from_slice(b"Content-Length: ");
                    buffer.extend_from_slice(length.to_string().as_bytes());
                    buffer.extend_from_slice(b"\r\n");
                }
            }
            ResponseBodyPlan::UntilClose => {
                if !transfer_encodings.is_empty() {
                    buffer.extend_from_slice(b"Transfer-Encoding: ");
                    buffer.extend_from_slice(transfer_encodings.join(", ").as_bytes());
                    buffer.extend_from_slice(b"\r\n");
                }
            }
        }

        if let Some(connection) = override_connection {
            buffer.extend_from_slice(b"Connection: ");
            buffer.extend_from_slice(connection.as_str().as_bytes());
            buffer.extend_from_slice(b"\r\n");
        }

        buffer.extend_from_slice(b"\r\n");
        buffer
    }

    pub fn header_map(&self) -> HeaderMap {
        header_lines_to_map(self.headers.iter())
    }
}

pub(crate) fn encode_cached_http1_response(
    status_line: &str,
    headers: &HeaderMap,
    body_plan: ResponseBodyPlan,
    content_length: Option<u64>,
    override_connection: Option<ConnectionOverride>,
) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(256);
    buffer.extend_from_slice(status_line.as_bytes());
    buffer.extend_from_slice(b"\r\n");

    let mut connection_tokens = HashSet::new();
    for value in headers.get_all(http::header::CONNECTION) {
        if let Ok(s) = value.to_str() {
            for token in s.split(',') {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                connection_tokens.insert(token.to_ascii_lowercase());
            }
        }
    }

    let mut transfer_encodings = Vec::new();
    let mut trailers = Vec::new();
    let mut content_length_header = None;

    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        let name_lower = name_str.to_ascii_lowercase();
        if name_lower == "transfer-encoding" {
            transfer_encodings.push(value.as_bytes().to_vec());
            continue;
        }
        if name_lower == "trailer" {
            trailers.push(value.as_bytes().to_vec());
            continue;
        }
        if name_lower == "content-length" {
            if content_length_header.is_none() {
                content_length_header = Some(value.as_bytes().to_vec());
            }
            continue;
        }
        if name_lower == "connection"
            || name_lower == "keep-alive"
            || name_lower == "proxy-connection"
            || name_lower == "proxy-authenticate"
            || name_lower == "proxy-authorization"
            || name_lower == "upgrade"
            || connection_tokens.contains(&name_lower)
        {
            continue;
        }

        buffer.extend_from_slice(name_str.as_bytes());
        buffer.extend_from_slice(b": ");
        buffer.extend_from_slice(value.as_bytes());
        buffer.extend_from_slice(b"\r\n");
    }

    match body_plan {
        ResponseBodyPlan::Chunked => {
            if transfer_encodings.is_empty() {
                buffer.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
            } else {
                for value in &transfer_encodings {
                    buffer.extend_from_slice(b"Transfer-Encoding: ");
                    buffer.extend_from_slice(value);
                    buffer.extend_from_slice(b"\r\n");
                }
            }
            for value in &trailers {
                buffer.extend_from_slice(b"Trailer: ");
                buffer.extend_from_slice(value);
                buffer.extend_from_slice(b"\r\n");
            }
        }
        ResponseBodyPlan::UntilClose => {
            for value in &transfer_encodings {
                buffer.extend_from_slice(b"Transfer-Encoding: ");
                buffer.extend_from_slice(value);
                buffer.extend_from_slice(b"\r\n");
            }
        }
        ResponseBodyPlan::Fixed(length) => {
            buffer.extend_from_slice(b"Content-Length: ");
            if let Some(value) = content_length_header.as_ref() {
                buffer.extend_from_slice(value);
            } else {
                buffer.extend_from_slice(length.to_string().as_bytes());
            }
            buffer.extend_from_slice(b"\r\n");
        }
        ResponseBodyPlan::Empty => {
            if let Some(value) = content_length_header.as_ref() {
                buffer.extend_from_slice(b"Content-Length: ");
                buffer.extend_from_slice(value);
                buffer.extend_from_slice(b"\r\n");
            } else if let Some(length) = content_length {
                buffer.extend_from_slice(b"Content-Length: ");
                buffer.extend_from_slice(length.to_string().as_bytes());
                buffer.extend_from_slice(b"\r\n");
            }
        }
    }

    if let Some(connection) = override_connection {
        buffer.extend_from_slice(b"Connection: ");
        buffer.extend_from_slice(connection.as_str().as_bytes());
        buffer.extend_from_slice(b"\r\n");
    }

    buffer.extend_from_slice(b"\r\n");
    buffer
}

pub(crate) async fn read_http1_response_head<S>(
    reader: &mut BufReader<S>,
    timeout_dur: Duration,
    peer: SocketAddr,
    max_header_bytes: usize,
) -> Result<Http1ResponseHead>
where
    S: AsyncRead + Unpin,
{
    ensure!(
        max_header_bytes > 0,
        "max response header size must be greater than zero"
    );
    let mut status_line = String::new();
    let mut budget = HeaderBudget::new(
        max_header_bytes,
        "upstream response headers exceed configured limit",
    )?;

    let bytes = read_line_with_timeout(
        reader,
        &mut status_line,
        timeout_dur,
        peer,
        max_header_bytes,
    )
    .await?;
    if bytes == 0 {
        bail!("upstream closed connection before sending status line");
    }
    budget.record(bytes)?;
    let trimmed = status_line.trim_end_matches(['\r', '\n']);
    let (version, status, _) = parse_http1_status_line(trimmed)?;

    let mut headers = Vec::new();
    let mut content_length = None;
    let mut content_length_seen = false;
    let mut chunked = false;
    let mut transfer_encoding_present = false;
    let mut connection_close = matches!(version, Version::HTTP_10);

    let mut header_line = String::new();
    loop {
        header_line.clear();
        let read = read_line_with_timeout(
            reader,
            &mut header_line,
            timeout_dur,
            peer,
            max_header_bytes,
        )
        .await?;
        if read == 0 {
            bail!("upstream closed connection during headers");
        }
        budget.record(read)?;
        let trimmed_line = header_line.trim_end_matches(['\r', '\n']);
        if trimmed_line.is_empty() {
            break;
        }
        let (name, value) = trimmed_line
            .split_once(':')
            .ok_or_else(|| anyhow!("header missing ':' separator from upstream"))?;
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length_seen {
                bail!("multiple Content-Length headers from upstream are not supported");
            }
            let parsed: u64 = value
                .parse()
                .with_context(|| format!("invalid Content-Length value '{value}'"))?;
            content_length = Some(parsed);
            content_length_seen = true;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoding_present = true;
            if value.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
        if name.eq_ignore_ascii_case("connection") {
            let mut saw_close = false;
            let mut saw_keep_alive = false;
            for token in value.split(',').map(|token| token.trim()) {
                if token.eq_ignore_ascii_case("close") {
                    saw_close = true;
                } else if token.eq_ignore_ascii_case("keep-alive") {
                    saw_keep_alive = true;
                }
            }
            if saw_close {
                connection_close = true;
            } else if saw_keep_alive {
                connection_close = false;
            }
        }
        headers.push(Http1HeaderLine::new(name, value));
    }

    if transfer_encoding_present && content_length_seen {
        warn!(
            peer = %peer,
            "upstream response contained both Transfer-Encoding and Content-Length; rejecting"
        );
        bail!("upstream response must not include both Transfer-Encoding and Content-Length");
    }

    Ok(Http1ResponseHead {
        status_line: trimmed.to_string(),
        status,
        headers,
        content_length,
        chunked,
        transfer_encoding_present,
        connection_close,
    })
}

pub(crate) fn parse_http1_status_line(value: &str) -> Result<(Version, StatusCode, String)> {
    let mut parts = value.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| anyhow!("upstream status line missing HTTP version"))?;
    let status = parts
        .next()
        .ok_or_else(|| anyhow!("upstream status line missing status code"))?;
    let reason = parts.collect::<Vec<_>>().join(" ");

    let version = match version {
        "HTTP/1.1" => Version::HTTP_11,
        other => bail!("unsupported upstream HTTP version '{other}'"),
    };

    let status_code: u16 = status
        .parse()
        .with_context(|| format!("invalid upstream status code '{status}'"))?;
    let status = StatusCode::from_u16(status_code)
        .map_err(|_| anyhow!("unsupported upstream status code '{status_code}'"))?;

    Ok((version, status, reason))
}

#[cfg(test)]
mod tests {
    use super::super::headers::Http1HeaderLine;
    use super::{
        ConnectionOverride, Http1ResponseHead, encode_cached_http1_response,
        parse_http1_status_line, read_http1_response_head,
    };
    use crate::proxy::http::forward::ResponseBodyPlan;
    use http::{StatusCode, Version};
    use std::time::Duration;

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn response_encode_strips_hop_by_hop_and_connection_tokens() {
        let head = Http1ResponseHead {
            status_line: "HTTP/1.1 200 OK".to_string(),
            status: http::StatusCode::OK,
            headers: vec![
                Http1HeaderLine::new("Connection", "Foo, Upgrade"),
                Http1HeaderLine::new("Foo", "bar"),
                Http1HeaderLine::new("Upgrade", "websocket"),
                Http1HeaderLine::new("Transfer-Encoding", "chunked"),
                Http1HeaderLine::new("Trailer", "X-Trailer"),
                Http1HeaderLine::new("Content-Length", "123"),
                Http1HeaderLine::new("X-Test", "1"),
            ],
            content_length: Some(123),
            chunked: true,
            transfer_encoding_present: true,
            connection_close: false,
        };

        let encoded = head.encode(ResponseBodyPlan::Chunked, None);
        let text = String::from_utf8(encoded).unwrap();

        assert!(!text.contains("Connection:"));
        assert!(!text.contains("Foo:"));
        assert!(!text.contains("Upgrade:"));
        assert!(!text.contains("Content-Length:"));
        assert!(text.contains("Transfer-Encoding: chunked"));
        assert!(text.contains("Trailer: X-Trailer"));
        assert!(text.contains("X-Test: 1"));
    }

    #[test]
    fn response_encode_sets_content_length_for_fixed() {
        let head = Http1ResponseHead {
            status_line: "HTTP/1.1 200 OK".to_string(),
            status: http::StatusCode::OK,
            headers: vec![Http1HeaderLine::new("Transfer-Encoding", "chunked")],
            content_length: Some(5),
            chunked: false,
            transfer_encoding_present: true,
            connection_close: false,
        };

        let encoded = head.encode(ResponseBodyPlan::Fixed(5), Some(ConnectionOverride::Close));
        let text = String::from_utf8(encoded).unwrap();

        assert!(text.contains("Content-Length: 5"));
        assert!(!text.contains("Transfer-Encoding:"));
        assert!(text.contains("Connection: close"));
    }

    #[test]
    fn encode_cached_response_preserves_bytes_and_strips_hop_by_hop() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("Foo, Upgrade"),
        );
        headers.insert(
            http::header::HeaderName::from_static("foo"),
            http::HeaderValue::from_static("bar"),
        );
        headers.insert(
            http::header::UPGRADE,
            http::HeaderValue::from_static("websocket"),
        );
        headers.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("chunked"),
        );
        headers.insert(
            http::header::TRAILER,
            http::HeaderValue::from_static("X-Trailer"),
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("123"),
        );
        headers.insert(
            http::header::HeaderName::from_static("x-test"),
            http::HeaderValue::from_static("1"),
        );
        headers.insert(
            http::header::HeaderName::from_static("x-binary"),
            http::HeaderValue::from_bytes(b"foo\xffbar").unwrap(),
        );

        let encoded = encode_cached_http1_response(
            "HTTP/1.1 200 OK",
            &headers,
            ResponseBodyPlan::Chunked,
            Some(123),
            Some(ConnectionOverride::Close),
        );

        assert!(!contains_bytes(&encoded, b"Connection: Foo"));
        assert!(!contains_bytes(&encoded, b"foo: bar\r\n"));
        assert!(!contains_bytes(&encoded, b"upgrade: websocket\r\n"));
        assert!(!contains_bytes(&encoded, b"Content-Length:"));
        assert!(contains_bytes(&encoded, b"Transfer-Encoding: chunked\r\n"));
        assert!(contains_bytes(&encoded, b"Trailer: X-Trailer\r\n"));
        assert!(contains_bytes(&encoded, b"x-test: 1\r\n"));
        assert!(contains_bytes(&encoded, b"x-binary: foo\xffbar\r\n"));
        assert!(contains_bytes(&encoded, b"Connection: close\r\n"));
    }

    #[test]
    fn encode_cached_response_uses_origin_content_length_for_empty() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("42"),
        );

        let encoded = encode_cached_http1_response(
            "HTTP/1.1 200 OK",
            &headers,
            ResponseBodyPlan::Empty,
            Some(5),
            Some(ConnectionOverride::Close),
        );

        assert!(contains_bytes(&encoded, b"Content-Length: 42\r\n"));
        assert!(!contains_bytes(&encoded, b"Content-Length: 5\r\n"));
    }

    #[test]
    fn parse_status_line_accepts_valid_line() -> anyhow::Result<()> {
        let (version, status, reason) = parse_http1_status_line("HTTP/1.1 404 Not Found")?;
        assert_eq!(version, Version::HTTP_11);
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(reason, "Not Found");
        Ok(())
    }

    #[test]
    fn parse_status_line_rejects_invalid_version() {
        let err = parse_http1_status_line("BAD 200 OK").unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported upstream HTTP version"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_status_line_rejects_http10() {
        let err = parse_http1_status_line("HTTP/1.0 200 OK").unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported upstream HTTP version"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_status_line_rejects_missing_code() {
        let err = parse_http1_status_line("HTTP/1.1").unwrap_err();
        assert!(
            err.to_string().contains("missing status code"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_status_line_rejects_non_numeric_code() {
        let err = parse_http1_status_line("HTTP/1.1 twohundred OK").unwrap_err();
        assert!(
            err.to_string().contains("invalid upstream status code"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn read_response_head_rejects_duplicate_content_length() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nContent-Length: 10\r\n\r\n";
        let mut reader = tokio::io::BufReader::new(&response[..]);
        let result = read_http1_response_head(
            &mut reader,
            Duration::from_secs(1),
            "127.0.0.1:80".parse().unwrap(),
            1024,
        )
        .await;
        if let Err(err) = result {
            assert!(
                err.to_string().contains("multiple Content-Length"),
                "unexpected error: {err}"
            );
        } else {
            panic!("duplicate Content-Length should be rejected");
        }
    }

    #[tokio::test]
    async fn read_response_head_rejects_transfer_encoding_with_content_length() {
        let response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n";
        let mut reader = tokio::io::BufReader::new(&response[..]);
        let result = read_http1_response_head(
            &mut reader,
            Duration::from_secs(1),
            "127.0.0.1:80".parse().unwrap(),
            1024,
        )
        .await;
        if let Err(err) = result {
            assert!(
                err.to_string()
                    .contains("must not include both Transfer-Encoding and Content-Length"),
                "unexpected error: {err}"
            );
        } else {
            panic!("Transfer-Encoding with Content-Length should be rejected");
        }
    }
}
