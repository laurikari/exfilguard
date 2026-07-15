use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow, bail, ensure};
use http::{HeaderMap, StatusCode, Version};
use tokio::io::{AsyncRead, BufReader};
use tracing::warn;

use crate::proxy::forward_limits::HeaderBudget;
use crate::proxy::http::forward::ResponseBodyPlan;

use super::headers::{Http1HeaderLine, header_lines_to_map, parse_header_line, parse_header_name};
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
    pub status_line: Vec<u8>,
    pub status: StatusCode,
    pub headers: Vec<Http1HeaderLine>,
    pub content_length: Option<u64>,
    pub chunked: bool,
    pub transfer_encoding_present: bool,
    pub connection_close: bool,
}

impl Http1ResponseHead {
    /// Ensure the forwarded/stored response has one valid Date field and
    /// return the value used for cache age calculations.
    pub fn normalize_date(&mut self, response_time: SystemTime) -> SystemTime {
        let mut dates = self
            .headers
            .iter()
            .filter(|header| header.lower_name() == "date");
        let valid_date = dates
            .next()
            .and_then(|header| httpdate::parse_http_date(header.value_text()).ok())
            .filter(|_| dates.next().is_none());
        if let Some(date) = valid_date {
            return date;
        }

        self.headers.retain(|header| header.lower_name() != "date");
        self.headers.push(
            Http1HeaderLine::new("Date", httpdate::fmt_http_date(response_time))
                .expect("generated Date header is valid"),
        );
        response_time
    }

    pub fn encode(
        &self,
        body_plan: ResponseBodyPlan,
        override_connection: Option<ConnectionOverride>,
    ) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(256);
        buffer.extend_from_slice(&self.status_line);
        buffer.extend_from_slice(b"\r\n");

        let mut connection_tokens = HashSet::new();
        for header in &self.headers {
            if header.lower_name() == "connection" {
                for token in header.value_text().split(',') {
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
                transfer_encodings.push(header.value_text().to_string());
                continue;
            }
            if name_lower == "trailer" {
                trailers.push(header.value_text().to_string());
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

            buffer.extend_from_slice(header.name_text().as_bytes());
            buffer.extend_from_slice(b": ");
            buffer.extend_from_slice(header.value_bytes());
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
    status_line: &[u8],
    headers: &HeaderMap,
    body_plan: ResponseBodyPlan,
    content_length: Option<u64>,
    override_connection: Option<ConnectionOverride>,
) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(256);
    buffer.extend_from_slice(status_line);
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

fn parse_transfer_codings(value: &str) -> Result<Vec<String>> {
    let mut items = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;

    for (index, byte) in value.bytes().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if byte == b',' {
            items.push(&value[start..index]);
            start = index + 1;
        }
    }
    if quoted || escaped {
        bail!("unterminated quoted string in upstream Transfer-Encoding");
    }
    items.push(&value[start..]);

    let mut codings = Vec::with_capacity(items.len());
    for item in items {
        let item = item.trim();
        if item.is_empty() {
            bail!("empty transfer coding in upstream Transfer-Encoding");
        }
        let (coding, parameters) = item
            .split_once(';')
            .map_or((item, None), |(coding, parameters)| {
                (coding, Some(parameters))
            });
        let coding = coding.trim();
        parse_header_name(coding)
            .map_err(|_| anyhow!("invalid transfer coding '{coding}' from upstream"))?;
        if coding.eq_ignore_ascii_case("chunked") && parameters.is_some() {
            bail!("chunked transfer coding must not include parameters");
        }
        codings.push(coding.to_ascii_lowercase());
    }
    Ok(codings)
}

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) async fn read_http1_response_head<S>(
    reader: &mut BufReader<S>,
    timeout_dur: Duration,
    peer: SocketAddr,
    max_header_bytes: usize,
) -> Result<Http1ResponseHead>
where
    S: AsyncRead + Unpin,
{
    let mut budget = HeaderBudget::new(
        max_header_bytes,
        "upstream response headers exceed configured limit",
    )?;
    read_http1_response_head_with_budget(reader, timeout_dur, peer, max_header_bytes, &mut budget)
        .await
}

pub(crate) async fn read_http1_response_head_with_budget<S>(
    reader: &mut BufReader<S>,
    timeout_dur: Duration,
    peer: SocketAddr,
    max_header_bytes: usize,
    budget: &mut HeaderBudget,
) -> Result<Http1ResponseHead>
where
    S: AsyncRead + Unpin,
{
    ensure!(
        max_header_bytes > 0,
        "max response header size must be greater than zero"
    );
    let mut status_line = Vec::new();

    let bytes = super::line::read_line_bytes_with_timeout(
        reader,
        &mut status_line,
        timeout_dur,
        peer,
        max_header_bytes,
        |context| anyhow!("timed out {context}"),
    )
    .await?;
    if bytes == 0 {
        return Err(crate::proxy::forward_error::UpstreamClosed.into());
    }
    budget.record(bytes)?;
    let (version, status, _) = parse_http1_status_line(&status_line)?;

    let mut headers = Vec::new();
    let mut content_length = None;
    let mut content_length_seen = false;
    let mut transfer_codings = Vec::new();
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
            return Err(crate::proxy::forward_error::UpstreamClosed.into());
        }
        budget.record(read)?;
        let Some((name, value)) =
            parse_header_line(&header_line).context("invalid response header from upstream")?
        else {
            break;
        };
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
            transfer_codings.extend(parse_transfer_codings(value)?);
        }
        if name.eq_ignore_ascii_case("connection") {
            for token in value.split(',').map(|token| token.trim()) {
                if token.eq_ignore_ascii_case("close") {
                    connection_close = true;
                }
            }
        }
        headers.push(Http1HeaderLine::new(name, value)?);
    }

    if transfer_encoding_present && content_length_seen {
        warn!(
            peer = %peer,
            "upstream response contained both Transfer-Encoding and Content-Length; rejecting"
        );
        bail!("upstream response must not include both Transfer-Encoding and Content-Length");
    }

    let chunked_count = transfer_codings
        .iter()
        .filter(|coding| coding.as_str() == "chunked")
        .count();
    if chunked_count > 1 {
        bail!("chunked transfer coding must not appear more than once");
    }
    if chunked_count == 1 && transfer_codings.last().map(String::as_str) != Some("chunked") {
        bail!("chunked transfer coding must be final");
    }
    let chunked = transfer_codings.last().map(String::as_str) == Some("chunked");

    Ok(Http1ResponseHead {
        status_line: status_line[..status_line.len() - 2].to_vec(),
        status,
        headers,
        content_length,
        chunked,
        transfer_encoding_present,
        connection_close,
    })
}

pub(crate) fn parse_http1_status_line(value: &[u8]) -> Result<(Version, StatusCode, &[u8])> {
    ensure!(
        value.ends_with(b"\r\n"),
        "upstream status line must end with CRLF"
    );
    let line = &value[..value.len() - 2];
    ensure!(
        line.len() >= 13,
        "upstream status line is missing required fields"
    );
    ensure!(
        &line[..9] == b"HTTP/1.1 ",
        "upstream status line must start with 'HTTP/1.1 '"
    );
    let status_bytes = &line[9..12];
    ensure!(
        status_bytes.iter().all(u8::is_ascii_digit),
        "upstream status code must contain exactly three digits"
    );
    ensure!(
        line[12] == b' ',
        "upstream status code must be followed by a space"
    );

    let reason = &line[13..];
    ensure!(
        reason
            .iter()
            .all(|byte| *byte == b'\t' || matches!(*byte, b' '..=b'~' | 0x80..=0xff)),
        "upstream reason phrase contains invalid control bytes"
    );

    let status_code = u16::from(status_bytes[0] - b'0') * 100
        + u16::from(status_bytes[1] - b'0') * 10
        + u16::from(status_bytes[2] - b'0');
    let status = StatusCode::from_u16(status_code)
        .map_err(|_| anyhow!("unsupported upstream status code '{status_code}'"))?;

    Ok((Version::HTTP_11, status, reason))
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
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn empty_response_head(headers: Vec<Http1HeaderLine>) -> Http1ResponseHead {
        Http1ResponseHead {
            status_line: b"HTTP/1.1 200 OK".to_vec(),
            status: StatusCode::OK,
            headers,
            content_length: Some(0),
            chunked: false,
            transfer_encoding_present: false,
            connection_close: false,
        }
    }

    #[test]
    fn normalize_date_adds_missing_date() {
        let response_time = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut head = empty_response_head(Vec::new());

        head.normalize_date(response_time);

        assert_eq!(
            head.header_map()
                .get(http::header::DATE)
                .unwrap()
                .to_str()
                .unwrap(),
            httpdate::fmt_http_date(response_time).as_str()
        );
    }

    #[test]
    fn normalize_date_preserves_one_valid_date() {
        let response_time = UNIX_EPOCH + Duration::from_secs(1_000);
        let origin_date = response_time - Duration::from_secs(60);
        let mut head = empty_response_head(vec![
            Http1HeaderLine::new("Date", httpdate::fmt_http_date(origin_date)).unwrap(),
        ]);

        let normalized = head.normalize_date(response_time);

        assert_eq!(normalized, origin_date);
        assert_eq!(
            head.header_map()
                .get(http::header::DATE)
                .unwrap()
                .to_str()
                .unwrap(),
            httpdate::fmt_http_date(origin_date).as_str()
        );
    }

    #[test]
    fn normalize_date_replaces_invalid_or_multiple_values() {
        let response_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut head = empty_response_head(vec![
            Http1HeaderLine::new("Date", "invalid").unwrap(),
            Http1HeaderLine::new("Date", "Thu, 01 Jan 1970 00:00:01 GMT").unwrap(),
        ]);

        head.normalize_date(response_time);

        let headers = head.header_map();
        assert_eq!(headers.get_all(http::header::DATE).iter().count(), 1);
        assert_eq!(
            headers.get(http::header::DATE).unwrap().to_str().unwrap(),
            httpdate::fmt_http_date(response_time).as_str()
        );
    }

    #[test]
    fn response_encode_strips_hop_by_hop_and_connection_tokens() {
        let head = Http1ResponseHead {
            status_line: b"HTTP/1.1 200 OK".to_vec(),
            status: http::StatusCode::OK,
            headers: vec![
                Http1HeaderLine::new("Connection", "Foo, Upgrade").expect("valid header"),
                Http1HeaderLine::new("Foo", "bar").expect("valid header"),
                Http1HeaderLine::new("Upgrade", "websocket").expect("valid header"),
                Http1HeaderLine::new("Transfer-Encoding", "chunked").expect("valid header"),
                Http1HeaderLine::new("Trailer", "X-Trailer").expect("valid header"),
                Http1HeaderLine::new("Content-Length", "123").expect("valid header"),
                Http1HeaderLine::new("X-Test", "1").expect("valid header"),
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
            status_line: b"HTTP/1.1 200 OK".to_vec(),
            status: http::StatusCode::OK,
            headers: vec![
                Http1HeaderLine::new("Transfer-Encoding", "chunked").expect("valid header"),
            ],
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
            b"HTTP/1.1 200 OK",
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
            b"HTTP/1.1 200 OK",
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
        let (version, status, reason) = parse_http1_status_line(b"HTTP/1.1 404 Not Found\r\n")?;
        assert_eq!(version, Version::HTTP_11);
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(reason, b"Not Found");
        Ok(())
    }

    #[test]
    fn parse_status_line_rejects_invalid_version() {
        let err = parse_http1_status_line(b"NOTHTTP! 200 OK\r\n").unwrap_err();
        assert!(
            err.to_string().contains("must start with 'HTTP/1.1 '"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_status_line_rejects_http10() {
        let err = parse_http1_status_line(b"HTTP/1.0 200 OK\r\n").unwrap_err();
        assert!(
            err.to_string().contains("must start with 'HTTP/1.1 '"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_status_line_rejects_missing_code() {
        let err = parse_http1_status_line(b"HTTP/1.1\r\n").unwrap_err();
        assert!(
            err.to_string().contains("missing required fields"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_status_line_rejects_non_numeric_code() {
        let err = parse_http1_status_line(b"HTTP/1.1 twohundred OK\r\n").unwrap_err();
        assert!(
            err.to_string().contains("exactly three digits"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_status_line_accepts_standard_reason_bytes() -> anyhow::Result<()> {
        for (line, expected_reason) in [
            (&b"HTTP/1.1 204 \r\n"[..], &b""[..]),
            (
                &b"HTTP/1.1 299 unusual\t!~ \xff\r\n"[..],
                &b"unusual\t!~ \xff"[..],
            ),
        ] {
            let (_, _, reason) = parse_http1_status_line(line)?;
            assert_eq!(reason, expected_reason);
        }
        Ok(())
    }

    #[test]
    fn parse_status_line_rejects_ambiguous_framing_and_controls() {
        for line in [
            &b"HTTP/1.1 200 OK\n"[..],
            &b"HTTP/1.1 200 OK\r\r\n"[..],
            &b"HTTP/1.1 200 OK\rInjected\r\n"[..],
            &b" HTTP/1.1 200 OK\r\n"[..],
            &b"HTTP/1.1\t200 OK\r\n"[..],
            &b"HTTP/1.1  200 OK\r\n"[..],
            &b"HTTP/1.1 200\r\n"[..],
            &b"HTTP/1.1 0200 OK\r\n"[..],
            &b"HTTP/1.1 +200 OK\r\n"[..],
            &b"HTTP/1.1 200 bad\0reason\r\n"[..],
            &b"HTTP/1.1 200 bad\x0breason\r\n"[..],
            &b"HTTP/1.1 200 bad\x0creason\r\n"[..],
            &b"HTTP/1.1 200 bad\x7freason\r\n"[..],
        ] {
            assert!(
                parse_http1_status_line(line).is_err(),
                "malformed status line was accepted: {line:?}"
            );
        }
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

    #[tokio::test]
    async fn read_response_head_requires_exact_chunked_coding() -> anyhow::Result<()> {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: xchunked\r\n\r\n";
        let mut reader = tokio::io::BufReader::new(&response[..]);
        let head = read_http1_response_head(
            &mut reader,
            Duration::from_secs(1),
            "127.0.0.1:80".parse().unwrap(),
            1024,
        )
        .await?;
        assert!(head.transfer_encoding_present);
        assert!(!head.chunked);
        Ok(())
    }

    #[tokio::test]
    async fn read_response_head_parses_ordered_transfer_codings() -> anyhow::Result<()> {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip; note=\"a,b\", chunked\r\n\r\n";
        let mut reader = tokio::io::BufReader::new(&response[..]);
        let head = read_http1_response_head(
            &mut reader,
            Duration::from_secs(1),
            "127.0.0.1:80".parse().unwrap(),
            1024,
        )
        .await?;
        assert!(head.chunked);
        Ok(())
    }

    #[tokio::test]
    async fn read_response_head_rejects_non_final_chunked_coding() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n";
        let mut reader = tokio::io::BufReader::new(&response[..]);
        let result = read_http1_response_head(
            &mut reader,
            Duration::from_secs(1),
            "127.0.0.1:80".parse().unwrap(),
            1024,
        )
        .await;
        let err = match result {
            Ok(_) => panic!("non-final chunked coding should be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("chunked transfer coding must be final"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn read_response_head_rejects_invalid_header_value() {
        let response = b"HTTP/1.1 200 OK\r\nX-Test: ok\rX-Evil: 1\r\n\r\n";
        let mut reader = tokio::io::BufReader::new(&response[..]);
        let result = read_http1_response_head(
            &mut reader,
            Duration::from_secs(1),
            "127.0.0.1:80".parse().unwrap(),
            1024,
        )
        .await;
        match result {
            Ok(_) => panic!("invalid header value should be rejected"),
            Err(err) => {
                let message = format!("{err:#}");
                assert!(
                    message.contains("terminating CRLF"),
                    "unexpected error: {message}"
                );
            }
        }
    }

    #[tokio::test]
    async fn read_response_head_requires_exact_header_crlf() {
        let cases: &[&[u8]] = &[
            b"HTTP/1.1 200 OK\r\nX-Test: value\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-Test: value\r\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\n",
        ];

        for response in cases {
            let mut reader = tokio::io::BufReader::new(*response);
            let result = read_http1_response_head(
                &mut reader,
                Duration::from_secs(1),
                "127.0.0.1:80".parse().unwrap(),
                1024,
            )
            .await;
            assert!(
                result.is_err(),
                "ambiguous response header ending was accepted: {response:?}"
            );
        }
    }

    #[tokio::test]
    async fn read_response_head_makes_connection_close_monotonic() -> anyhow::Result<()> {
        let cases: &[&[u8]] = &[
            b"HTTP/1.1 200 OK\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive, close\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nConnection: close, keep-alive\r\n\r\n",
        ];

        for response in cases {
            let mut reader = tokio::io::BufReader::new(*response);
            let head = read_http1_response_head(
                &mut reader,
                Duration::from_secs(1),
                "127.0.0.1:80".parse().unwrap(),
                1024,
            )
            .await?;
            assert!(
                head.connection_close,
                "Connection: close was overridden in {response:?}"
            );
        }
        Ok(())
    }
}
