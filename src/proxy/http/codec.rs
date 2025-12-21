use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use http::{HeaderMap, Method, StatusCode, Version};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::{
    proxy::{
        forward_limits::HeaderBudget,
        headers::{HeaderAction, RequestHeaderSanitizer},
    },
    util::timeout_with_context,
};

use super::forward::ResponseBodyPlan;

pub struct HeaderAccumulator {
    sanitizer: RequestHeaderSanitizer,
    headers: Vec<HeaderLine>,
}

#[derive(Clone)]
pub struct HeaderLine {
    pub name: String,
    pub value: String,
    lower_name: String,
}

impl HeaderLine {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        let name_string = name.into();
        let lower_name = name_string.to_ascii_lowercase();
        let value_string = value.into();
        Self {
            name: name_string,
            value: value_string,
            lower_name,
        }
    }

    pub fn lower_name(&self) -> &str {
        &self.lower_name
    }
}

impl HeaderAccumulator {
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
        if name.is_empty() {
            bail!("header name must not be empty");
        }
        match self.sanitizer.record(name, value, line_len)? {
            HeaderAction::Forward => {
                self.headers.push(HeaderLine::new(name, value));
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

    pub fn forward_headers(&self) -> impl Iterator<Item = &HeaderLine> {
        self.headers
            .iter()
            .filter(move |header| !self.has_connection_token(header.lower_name()))
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
            if !header.value.eq_ignore_ascii_case("100-continue") {
                bail!("unsupported Expect header value '{}'", header.value);
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

pub struct RequestHead {
    pub method: Method,
    pub target: String,
    pub headers: HeaderAccumulator,
    pub request_line_bytes: usize,
    pub header_bytes: usize,
}

pub async fn read_request_head<S>(
    reader: &mut BufReader<S>,
    peer: SocketAddr,
    timeout: Duration,
    max_header_bytes: usize,
) -> Result<Option<RequestHead>>
where
    S: AsyncRead + Unpin,
{
    let request_line_limit = max_header_bytes;
    let deadline = Instant::now() + timeout;
    let Some((request_line, request_line_bytes)) =
        read_request_line(reader, peer, deadline, request_line_limit).await?
    else {
        debug!(peer = %peer, "connection closed before request line");
        return Ok(None);
    };
    if request_line.is_empty() {
        bail!("empty request line from {peer}");
    }

    let mut parts = request_line.split_whitespace();
    let method_str = parts
        .next()
        .ok_or_else(|| anyhow!("malformed request line: missing method"))?;
    let target = parts
        .next()
        .ok_or_else(|| anyhow!("malformed request line: missing target"))?;
    let version = parts
        .next()
        .ok_or_else(|| anyhow!("malformed request line: missing version"))?;
    match version {
        "HTTP/1.1" | "HTTP/1.0" => {}
        other => bail!("invalid HTTP version '{other}'"),
    }

    let method = Method::from_bytes(method_str.as_bytes())
        .with_context(|| format!("invalid method '{method_str}'"))?;
    let target = target.to_string();

    let remaining = max_header_bytes
        .checked_sub(request_line_bytes)
        .ok_or_else(|| anyhow!("request headers exceed configured limit"))?;
    ensure!(remaining > 0, "request headers exceed configured limit");
    let mut headers = HeaderAccumulator::new(remaining);
    let mut header_line = String::new();
    loop {
        header_line.clear();
        let read =
            read_line_with_deadline(reader, &mut header_line, deadline, peer, remaining).await?;
        if read == 0 {
            break;
        }
        if !headers
            .push_line(&header_line)
            .with_context(|| format!("invalid header from {peer}"))?
        {
            break;
        }
    }
    let header_bytes = headers.total_bytes();

    Ok(Some(RequestHead {
        method,
        target,
        headers,
        request_line_bytes,
        header_bytes,
    }))
}

pub async fn read_request_line<S>(
    reader: &mut BufReader<S>,
    peer: SocketAddr,
    deadline: Instant,
    max_len: usize,
) -> Result<Option<(String, usize)>>
where
    S: AsyncRead + Unpin,
{
    if max_len == 0 {
        bail!("request line limit must be greater than zero");
    }

    let mut line = Vec::new();
    let mut total = 0usize;
    let context = format!("reading request line from {peer}");

    loop {
        let remaining = remaining_deadline(deadline, &context)?;
        let available =
            timeout_with_context(remaining, reader.fill_buf(), context.as_str()).await?;

        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            bail!("connection closed while reading request line from {peer}");
        }

        let newline_pos = available.iter().position(|byte| *byte == b'\n');
        let consume = newline_pos.map(|idx| idx + 1).unwrap_or(available.len());

        if total + consume > max_len {
            bail!("request line exceeds configured limit of {max_len} bytes for {peer}");
        }

        line.extend_from_slice(&available[..consume]);
        reader.consume(consume);
        total += consume;

        if newline_pos.is_some() {
            break;
        }
    }

    let mut string = String::from_utf8(line)
        .map_err(|_| anyhow!("request line for {peer} contained invalid bytes"))?;

    if !string.ends_with('\n') {
        bail!("request line for {peer} missing newline terminator");
    }
    string.pop();
    if string.ends_with('\r') {
        string.pop();
    }

    Ok(Some((string, total)))
}

pub async fn read_line_with_deadline<S>(
    reader: &mut BufReader<S>,
    buf: &mut String,
    deadline: Instant,
    peer: SocketAddr,
    max_len: usize,
) -> Result<usize>
where
    S: AsyncRead + Unpin,
{
    ensure!(max_len > 0, "line length limit must be greater than zero");
    buf.clear();
    let mut collected = Vec::new();
    let context = format!("reading line from {peer}");

    loop {
        let remaining = remaining_deadline(deadline, &context)?;
        let available =
            timeout_with_context(remaining, reader.fill_buf(), context.as_str()).await?;

        if available.is_empty() {
            if collected.is_empty() {
                return Ok(0);
            }
            bail!("connection closed while reading line from {peer}");
        }

        let newline_pos = available.iter().position(|byte| *byte == b'\n');
        let consume = newline_pos.map(|idx| idx + 1).unwrap_or(available.len());

        if collected
            .len()
            .checked_add(consume)
            .ok_or_else(|| anyhow!("line length overflow for {peer}"))?
            > max_len
        {
            bail!("line from {peer} exceeds configured limit of {max_len} bytes");
        }

        collected.extend_from_slice(&available[..consume]);
        reader.consume(consume);

        if newline_pos.is_some() {
            break;
        }
    }

    let string = String::from_utf8(collected)
        .map_err(|_| anyhow!("line from {peer} contained invalid bytes"))?;
    let len = string.len();
    *buf = string;
    Ok(len)
}

pub async fn read_line_with_timeout<S>(
    reader: &mut BufReader<S>,
    buf: &mut String,
    timeout_dur: Duration,
    peer: SocketAddr,
    max_len: usize,
) -> Result<usize>
where
    S: AsyncRead + Unpin,
{
    ensure!(max_len > 0, "line length limit must be greater than zero");
    buf.clear();
    let mut collected = Vec::new();

    loop {
        let available = timeout_with_context(
            timeout_dur,
            reader.fill_buf(),
            format!("reading line from {peer}"),
        )
        .await?;

        if available.is_empty() {
            if collected.is_empty() {
                return Ok(0);
            }
            bail!("connection closed while reading line from {peer}");
        }

        let newline_pos = available.iter().position(|byte| *byte == b'\n');
        let consume = newline_pos.map(|idx| idx + 1).unwrap_or(available.len());

        if collected
            .len()
            .checked_add(consume)
            .ok_or_else(|| anyhow!("line length overflow for {peer}"))?
            > max_len
        {
            bail!("line from {peer} exceeds configured limit of {max_len} bytes");
        }

        collected.extend_from_slice(&available[..consume]);
        reader.consume(consume);

        if newline_pos.is_some() {
            break;
        }
    }

    let string = String::from_utf8(collected)
        .map_err(|_| anyhow!("line from {peer} contained invalid bytes"))?;
    let len = string.len();
    *buf = string;
    Ok(len)
}

fn remaining_deadline(deadline: Instant, context: &str) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| anyhow!("timed out {context}"))
}

#[derive(Clone, Copy)]
pub enum ConnectionDirective {
    Close,
}

impl ConnectionDirective {
    pub fn as_str(&self) -> &str {
        match self {
            ConnectionDirective::Close => "close",
        }
    }
}

pub struct ResponseHead {
    pub status_line: String,
    pub status: StatusCode,
    pub headers: Vec<HeaderLine>,
    pub content_length: Option<u64>,
    pub chunked: bool,
    pub transfer_encoding_present: bool,
    pub connection_close: bool,
}

impl ResponseHead {
    pub fn encode(
        &self,
        body_plan: ResponseBodyPlan,
        override_connection: Option<ConnectionDirective>,
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
}

pub fn encode_cached_response(
    status_line: &str,
    headers: &HeaderMap,
    body_plan: ResponseBodyPlan,
    content_length: Option<u64>,
    override_connection: Option<ConnectionDirective>,
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

pub async fn read_response_head<S>(
    reader: &mut BufReader<S>,
    timeout_dur: Duration,
    peer: SocketAddr,
    max_header_bytes: usize,
) -> Result<ResponseHead>
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
    let (version, status, _) = parse_status_line(trimmed)?;

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
        headers.push(HeaderLine::new(name, value));
    }

    if transfer_encoding_present && content_length_seen {
        warn!(
            peer = %peer,
            "upstream response contained both Transfer-Encoding and Content-Length; rejecting"
        );
        bail!("upstream response must not include both Transfer-Encoding and Content-Length");
    }

    Ok(ResponseHead {
        status_line: trimmed.to_string(),
        status,
        headers,
        content_length,
        chunked,
        transfer_encoding_present,
        connection_close,
    })
}

pub(crate) fn parse_status_line(value: &str) -> Result<(Version, StatusCode, String)> {
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
        "HTTP/1.0" => Version::HTTP_10,
        other => bail!("invalid upstream HTTP version '{other}'"),
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
    use super::*;
    use anyhow::Result;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn forward_headers_skip_connection_tokens() {
        let mut accumulator = HeaderAccumulator::new(256);
        assert!(matches!(
            accumulator.push_line("Connection: Foo\r\n"),
            Ok(true)
        ));
        assert!(matches!(accumulator.push_line("Foo: bar\r\n"), Ok(true)));
        assert!(matches!(accumulator.push_line("Bar: baz\r\n"), Ok(true)));
        assert!(matches!(accumulator.push_line("\r\n"), Ok(false)));
        let names: Vec<_> = accumulator
            .forward_headers()
            .map(|header| header.name.as_str())
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
    fn response_encode_strips_hop_by_hop_and_connection_tokens() {
        let head = ResponseHead {
            status_line: "HTTP/1.1 200 OK".to_string(),
            status: StatusCode::OK,
            headers: vec![
                HeaderLine::new("Connection", "Foo, Upgrade"),
                HeaderLine::new("Foo", "bar"),
                HeaderLine::new("Upgrade", "websocket"),
                HeaderLine::new("Transfer-Encoding", "chunked"),
                HeaderLine::new("Trailer", "X-Trailer"),
                HeaderLine::new("Content-Length", "123"),
                HeaderLine::new("X-Test", "1"),
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
        let head = ResponseHead {
            status_line: "HTTP/1.1 200 OK".to_string(),
            status: StatusCode::OK,
            headers: vec![HeaderLine::new("Transfer-Encoding", "chunked")],
            content_length: Some(5),
            chunked: false,
            transfer_encoding_present: true,
            connection_close: false,
        };

        let encoded = head.encode(ResponseBodyPlan::Fixed(5), Some(ConnectionDirective::Close));
        let text = String::from_utf8(encoded).unwrap();

        assert!(text.contains("Content-Length: 5"));
        assert!(!text.contains("Transfer-Encoding:"));
        assert!(text.contains("Connection: close"));
    }

    #[test]
    fn expect_continue_detects_header() -> Result<()> {
        let mut accumulator = HeaderAccumulator::new(256);
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
        let mut accumulator = HeaderAccumulator::new(256);
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

    #[tokio::test(start_paused = true)]
    async fn read_request_head_times_out_on_partial_line() {
        let (mut client, server) = tokio::io::duplex(64);
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let handle = tokio::spawn(async move {
            let mut reader = BufReader::new(server);
            read_request_head(&mut reader, peer, Duration::from_millis(50), 1024).await
        });

        tokio::task::yield_now().await;
        client
            .write_all(b"GET / HTTP/1.1")
            .await
            .expect("write partial line");
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_millis(100)).await;

        let result = handle.await.expect("request head join");
        match result {
            Ok(_) => panic!("expected timeout on partial line"),
            Err(err) => {
                assert!(
                    err.to_string().contains("timed out"),
                    "unexpected error: {err}"
                );
            }
        }
    }

    #[tokio::test]
    async fn read_response_head_rejects_duplicate_content_length() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nContent-Length: 10\r\n\r\n";
        let mut reader = tokio::io::BufReader::new(&response[..]);
        let result = read_response_head(
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
        let result = read_response_head(
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

        let encoded = encode_cached_response(
            "HTTP/1.1 200 OK",
            &headers,
            ResponseBodyPlan::Chunked,
            Some(123),
            Some(ConnectionDirective::Close),
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

        let encoded = encode_cached_response(
            "HTTP/1.1 200 OK",
            &headers,
            ResponseBodyPlan::Empty,
            Some(5),
            Some(ConnectionDirective::Close),
        );

        assert!(contains_bytes(&encoded, b"Content-Length: 42\r\n"));
        assert!(!contains_bytes(&encoded, b"Content-Length: 5\r\n"));
    }
}
