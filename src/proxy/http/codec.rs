use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use http::{Method, StatusCode, Version};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tracing::debug;

use crate::{
    proxy::{
        forward_limits::HeaderBudget,
        headers::{HeaderAction, RequestHeaderSanitizer},
    },
    util::timeout_with_context,
};

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
    let Some((request_line, request_line_bytes)) =
        read_request_line(reader, peer, timeout, request_line_limit).await?
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
    let _version = parts
        .next()
        .ok_or_else(|| anyhow!("malformed request line: missing version"))?;

    let method = Method::from_bytes(method_str.as_bytes())
        .with_context(|| format!("invalid method '{method_str}'"))?;
    let target = target.to_string();

    let mut headers = HeaderAccumulator::new(max_header_bytes);
    let mut header_line = String::new();
    loop {
        header_line.clear();
        let read =
            read_line_with_timeout(reader, &mut header_line, timeout, peer, max_header_bytes)
                .await?;
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
    timeout_dur: Duration,
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

    loop {
        let available = timeout_with_context(
            timeout_dur,
            reader.fill_buf(),
            format!("reading request line from {peer}"),
        )
        .await?;

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
    pub connection_close: bool,
}

impl ResponseHead {
    pub fn encode(&self, override_connection: Option<ConnectionDirective>) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(256);
        buffer.extend_from_slice(self.status_line.as_bytes());
        buffer.extend_from_slice(b"\r\n");

        for header in &self.headers {
            buffer.extend_from_slice(header.name.as_bytes());
            buffer.extend_from_slice(b": ");
            buffer.extend_from_slice(header.value.as_bytes());
            buffer.extend_from_slice(b"\r\n");
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
    let mut chunked = false;
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
        if name.eq_ignore_ascii_case("content-length") && content_length.is_none() {
            let parsed: u64 = value
                .parse()
                .with_context(|| format!("invalid Content-Length value '{value}'"))?;
            content_length = Some(parsed);
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
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

    Ok(ResponseHead {
        status_line: trimmed.to_string(),
        status,
        headers,
        content_length,
        chunked,
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
}
