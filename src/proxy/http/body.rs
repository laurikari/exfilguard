use std::future::Future;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::timeout;

use crate::{
    io_util::write_all_with_timeout,
    proxy::{
        forward_error::{ClientBodyIdleTimeout, RequestTimeout},
        forward_limits::BodySizeTracker,
        headers::{sanitize_request_trailer_lines, sanitize_response_trailer_lines},
        http::codec::read_line_bytes_with_timeout,
    },
    util::timeout_with_context,
};

const MAX_CHUNK_LINE_LENGTH: usize = 8192;

#[derive(Debug, Error)]
#[error("request body exceeds configured limit")]
pub struct BodyTooLarge {
    pub bytes_read: u64,
}

#[derive(Debug, Error)]
#[error("invalid request body: {detail}")]
pub struct InvalidRequestBody {
    pub bytes_read: u64,
    detail: String,
}

impl InvalidRequestBody {
    pub(crate) fn new(bytes_read: u64, detail: impl Into<String>) -> Self {
        Self {
            bytes_read,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Error)]
#[error("invalid chunked body: {detail}")]
struct InvalidChunkedBody {
    bytes_read: u64,
    detail: String,
}

#[derive(Clone, Copy)]
pub enum BodyPlan {
    Empty,
    Fixed(usize),
    Chunked,
}

impl BodyPlan {
    /// Whether parsing proved that the request has no body bytes.
    ///
    /// A chunked request is not definitely empty until its framing is consumed,
    /// so it deliberately returns false here.
    pub const fn is_definitely_empty(self) -> bool {
        matches!(self, Self::Empty | Self::Fixed(0))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChunkedRelayStats {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub had_trailers: bool,
}

type TrailerSanitizer = fn(&[String]) -> Result<Vec<Vec<u8>>>;

fn exact_crlf_content<'a>(line: &'a [u8], element: &str) -> Result<&'a [u8]> {
    let content = line
        .strip_suffix(b"\r\n")
        .ok_or_else(|| anyhow!("{element} line must end with CRLF"))?;
    if content.contains(&b'\r') || content.contains(&b'\n') {
        bail!("{element} line contains an embedded CR or LF");
    }
    Ok(content)
}

fn hex_value(byte: u8) -> Option<usize> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as usize),
        b'a'..=b'f' => Some((byte - b'a' + 10) as usize),
        b'A'..=b'F' => Some((byte - b'A' + 10) as usize),
        _ => None,
    }
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_bws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

fn is_qdtext(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~') || byte >= 0x80
}

fn is_quoted_pair_value(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ' | b'!'..=b'~') || byte >= 0x80
}

fn skip_bws(bytes: &[u8], index: &mut usize) {
    while bytes.get(*index).is_some_and(|byte| is_bws(*byte)) {
        *index += 1;
    }
}

fn parse_quoted_extension_value(bytes: &[u8], index: &mut usize) -> Result<()> {
    debug_assert_eq!(bytes.get(*index), Some(&b'"'));
    *index += 1;

    loop {
        let Some(byte) = bytes.get(*index).copied() else {
            bail!("unterminated quoted chunk extension value");
        };
        match byte {
            b'"' => {
                *index += 1;
                return Ok(());
            }
            b'\\' => {
                *index += 1;
                let Some(escaped) = bytes.get(*index).copied() else {
                    bail!("unterminated quoted-pair in chunk extension value");
                };
                if !is_quoted_pair_value(escaped) {
                    bail!("invalid quoted-pair in chunk extension value");
                }
                *index += 1;
            }
            byte if is_qdtext(byte) => *index += 1,
            _ => bail!("invalid byte in quoted chunk extension value"),
        }
    }
}

fn parse_chunk_extensions(bytes: &[u8]) -> Result<()> {
    let mut index = 0usize;
    while index < bytes.len() {
        skip_bws(bytes, &mut index);
        if index == bytes.len() {
            bail!("chunk size must not end with whitespace");
        }
        if bytes[index] != b';' {
            bail!("invalid data after chunk size");
        }
        index += 1;
        skip_bws(bytes, &mut index);

        let name_start = index;
        while bytes.get(index).is_some_and(|byte| is_tchar(*byte)) {
            index += 1;
        }
        if index == name_start {
            bail!("chunk extension name must be a nonempty token");
        }

        let name_end = index;
        skip_bws(bytes, &mut index);
        if bytes.get(index) != Some(&b'=') {
            if index == bytes.len() && index > name_end {
                bail!("chunk size must not end with whitespace");
            }
            continue;
        }
        index += 1;
        skip_bws(bytes, &mut index);

        if bytes.get(index) == Some(&b'"') {
            parse_quoted_extension_value(bytes, &mut index)?;
        } else {
            let value_start = index;
            while bytes.get(index).is_some_and(|byte| is_tchar(*byte)) {
                index += 1;
            }
            if index == value_start {
                bail!("chunk extension value must be a token or quoted string");
            }
        }
    }
    Ok(())
}

fn parse_chunk_size_line(line: &[u8]) -> Result<usize> {
    let content = exact_crlf_content(line, "chunk size")?;
    let mut size_end = 0usize;
    let mut chunk_size = 0usize;

    while let Some(value) = content.get(size_end).and_then(|byte| hex_value(*byte)) {
        chunk_size = chunk_size
            .checked_mul(16)
            .and_then(|size| size.checked_add(value))
            .ok_or_else(|| anyhow!("chunk size exceeds platform limit"))?;
        size_end += 1;
    }
    if size_end == 0 {
        bail!("chunk size must contain at least one hexadecimal digit");
    }

    parse_chunk_extensions(&content[size_end..])?;
    Ok(chunk_size)
}

fn invalid_chunked_body(stats: &ChunkedRelayStats, detail: impl Into<String>) -> anyhow::Error {
    InvalidChunkedBody {
        bytes_read: stats.bytes_read,
        detail: detail.into(),
    }
    .into()
}

async fn with_total_deadline<F, T>(total_deadline: Option<Instant>, future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    if let Some(deadline) = total_deadline {
        let now = Instant::now();
        if now >= deadline {
            return Err(RequestTimeout.into());
        }
        let remaining = deadline - now;
        match timeout(remaining, future).await {
            Ok(result) => result,
            Err(_) => Err(RequestTimeout.into()),
        }
    } else {
        future.await
    }
}

async fn with_idle_and_total<F, T, E>(
    idle_timeout: Duration,
    total_deadline: Option<Instant>,
    future: F,
    context: impl Into<String>,
    read_source: BodyReadSource,
) -> Result<T>
where
    F: Future<Output = Result<T, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    let context = context.into();
    let idle_fut = async {
        timeout(idle_timeout, future)
            .await
            .map_err(|_| read_source.timeout_error(&context))?
            .map_err(anyhow::Error::from)
            .with_context(|| format!("failed while {context}"))
    };
    with_total_deadline(total_deadline, idle_fut).await
}

#[derive(Clone, Copy)]
enum BodyReadSource {
    Client,
    Upstream,
}

impl BodyReadSource {
    fn timeout_error(self, context: &str) -> anyhow::Error {
        match self {
            Self::Client => ClientBodyIdleTimeout.into(),
            Self::Upstream => anyhow!("timed out {context}"),
        }
    }
}

pub async fn stream_fixed_body<S, U>(
    reader: &mut BufReader<S>,
    upstream: &mut U,
    mut remaining: usize,
    read_timeout: Duration,
    write_timeout: Duration,
    total_deadline: Option<Instant>,
) -> Result<u64>
where
    S: AsyncRead + Unpin,
    U: AsyncWrite + Unpin,
{
    let mut transferred = 0u64;
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let to_read = remaining.min(buffer.len());
        let read = with_idle_and_total(
            read_timeout,
            total_deadline,
            reader.read(&mut buffer[..to_read]),
            "reading request body from client",
            BodyReadSource::Client,
        )
        .await?;
        if read == 0 {
            bail!("unexpected EOF while reading request body from client");
        }
        remaining -= read;
        with_total_deadline(
            total_deadline,
            write_all_with_timeout(
                upstream,
                &buffer[..read],
                write_timeout,
                "writing request body to upstream",
            ),
        )
        .await?;
        transferred = transferred.saturating_add(read as u64);
    }
    Ok(transferred)
}

pub(crate) async fn buffer_fixed_body<S>(
    reader: &mut BufReader<S>,
    length: usize,
    read_timeout: Duration,
    total_deadline: Option<Instant>,
) -> Result<(Vec<u8>, u64)>
where
    S: AsyncRead + Unpin,
{
    let mut body = Vec::with_capacity(length);
    let mut remaining = length;
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let to_read = remaining.min(buffer.len());
        let read = with_idle_and_total(
            read_timeout,
            total_deadline,
            reader.read(&mut buffer[..to_read]),
            "buffering credential-bearing request body",
            BodyReadSource::Client,
        )
        .await?;
        if read == 0 {
            return Err(InvalidRequestBody::new(
                (length - remaining) as u64,
                "unexpected EOF while buffering credential-bearing request body",
            )
            .into());
        }
        body.extend_from_slice(&buffer[..read]);
        remaining -= read;
    }
    Ok((body, length as u64))
}

#[allow(clippy::too_many_arguments)]
async fn relay_chunked_body_generic<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    read_timeout: Duration,
    write_timeout: Duration,
    total_deadline: Option<Instant>,
    peer: SocketAddr,
    write_target: &str,
    mut limit: Option<&mut BodySizeTracker>,
    max_trailer_bytes: usize,
    trailer_limit_error: &'static str,
    sanitize_trailers: TrailerSanitizer,
    mut payload_copy: Option<&mut (dyn AsyncWrite + Unpin + Send)>,
    read_source: BodyReadSource,
) -> Result<ChunkedRelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut stats = ChunkedRelayStats::default();
    let mut line = Vec::new();

    loop {
        line.clear();
        let size_bytes = with_total_deadline(
            total_deadline,
            read_line_bytes_with_timeout(
                reader,
                &mut line,
                read_timeout,
                peer,
                MAX_CHUNK_LINE_LENGTH,
                |context| read_source.timeout_error(context),
            ),
        )
        .await?;
        if size_bytes == 0 {
            return Err(invalid_chunked_body(
                &stats,
                format!("unexpected EOF while reading chunk size from {peer}"),
            ));
        }
        stats.bytes_read = stats.bytes_read.saturating_add(size_bytes as u64);
        let chunk_size = parse_chunk_size_line(&line)
            .map_err(|err| invalid_chunked_body(&stats, err.to_string()))?;

        if let Some(limit_tracker) = limit.as_deref_mut() {
            limit_tracker.record(chunk_size)?;
        }

        with_total_deadline(
            total_deadline,
            write_all_with_timeout(
                writer,
                &line,
                write_timeout,
                format!("forwarding chunk size {write_target}"),
            ),
        )
        .await?;
        stats.bytes_written = stats.bytes_written.saturating_add(line.len() as u64);

        if chunk_size == 0 {
            let mut trailer_lines = Vec::new();
            let mut trailer_bytes_total = 0usize;
            loop {
                line.clear();
                let trailer_line_bytes = with_total_deadline(
                    total_deadline,
                    read_line_bytes_with_timeout(
                        reader,
                        &mut line,
                        read_timeout,
                        peer,
                        MAX_CHUNK_LINE_LENGTH,
                        |context| read_source.timeout_error(context),
                    ),
                )
                .await?;
                if trailer_line_bytes == 0 {
                    return Err(invalid_chunked_body(
                        &stats,
                        format!("unexpected EOF while reading chunk trailer from {peer}"),
                    ));
                }
                stats.bytes_read = stats.bytes_read.saturating_add(trailer_line_bytes as u64);
                let trailer = exact_crlf_content(&line, "chunk trailer")
                    .map_err(|err| invalid_chunked_body(&stats, err.to_string()))?;
                if trailer.is_empty() {
                    break;
                }
                trailer_bytes_total = trailer_bytes_total
                    .checked_add(line.len())
                    .ok_or_else(|| invalid_chunked_body(&stats, trailer_limit_error))?;
                if trailer_bytes_total > max_trailer_bytes {
                    return Err(invalid_chunked_body(&stats, trailer_limit_error));
                }
                let trailer = std::str::from_utf8(trailer).map_err(|_| {
                    invalid_chunked_body(&stats, "chunk trailer contained invalid bytes")
                })?;
                trailer_lines.push(trailer.to_string());
            }

            stats.had_trailers = !trailer_lines.is_empty();
            let sanitized_trailers = sanitize_trailers(&trailer_lines)
                .map_err(|err| invalid_chunked_body(&stats, err.to_string()))?;
            for trailer_line in sanitized_trailers {
                with_total_deadline(
                    total_deadline,
                    write_all_with_timeout(
                        writer,
                        &trailer_line,
                        write_timeout,
                        format!("forwarding chunk trailer {write_target}"),
                    ),
                )
                .await?;
                stats.bytes_written = stats
                    .bytes_written
                    .saturating_add(trailer_line.len() as u64);
            }
            with_total_deadline(
                total_deadline,
                write_all_with_timeout(
                    writer,
                    b"\r\n",
                    write_timeout,
                    format!("forwarding chunk trailer terminator {write_target}"),
                ),
            )
            .await?;
            stats.bytes_written = stats.bytes_written.saturating_add(2);
            break;
        }

        let mut remaining = chunk_size;
        let mut buffer = [0u8; 8192];
        while remaining > 0 {
            let to_read = remaining.min(buffer.len());
            let read = with_idle_and_total(
                read_timeout,
                total_deadline,
                reader.read(&mut buffer[..to_read]),
                format!("reading chunk data from {peer}"),
                read_source,
            )
            .await?;
            if read == 0 {
                return Err(invalid_chunked_body(
                    &stats,
                    format!("unexpected EOF while reading chunk data from {peer}"),
                ));
            }
            remaining -= read;
            with_total_deadline(
                total_deadline,
                write_all_with_timeout(
                    writer,
                    &buffer[..read],
                    write_timeout,
                    format!("forwarding chunk data {write_target}"),
                ),
            )
            .await?;
            if let Some(payload_copy) = payload_copy.as_deref_mut() {
                with_total_deadline(
                    total_deadline,
                    timeout_with_context(
                        write_timeout,
                        payload_copy.write_all(&buffer[..read]),
                        "writing decoded chunk payload copy",
                    ),
                )
                .await?;
            }
            stats.bytes_read = stats.bytes_read.saturating_add(read as u64);
            stats.bytes_written = stats.bytes_written.saturating_add(read as u64);
        }

        let mut crlf = [0u8; 2];
        let terminator_result = with_idle_and_total(
            read_timeout,
            total_deadline,
            reader.read_exact(&mut crlf),
            format!("reading chunk terminator from {peer}"),
            read_source,
        )
        .await;
        if let Err(err) = terminator_result {
            if err
                .chain()
                .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
                .any(|io_err| io_err.kind() == std::io::ErrorKind::UnexpectedEof)
            {
                return Err(invalid_chunked_body(
                    &stats,
                    format!("unexpected EOF while reading chunk terminator from {peer}"),
                ));
            }
            return Err(err);
        }
        if &crlf != b"\r\n" {
            return Err(invalid_chunked_body(
                &stats,
                format!("invalid chunk terminator when reading from {peer}"),
            ));
        }
        with_total_deadline(
            total_deadline,
            write_all_with_timeout(
                writer,
                &crlf,
                write_timeout,
                format!("forwarding chunk terminator {write_target}"),
            ),
        )
        .await?;
        stats.bytes_read = stats.bytes_read.saturating_add(2);
        stats.bytes_written = stats.bytes_written.saturating_add(2);
    }

    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
pub async fn stream_chunked_body<S, U>(
    reader: &mut BufReader<S>,
    upstream: &mut U,
    read_timeout: Duration,
    write_timeout: Duration,
    total_deadline: Option<Instant>,
    peer: SocketAddr,
    max_request_body_size: usize,
    max_request_trailer_bytes: usize,
) -> Result<u64>
where
    S: AsyncRead + Unpin,
    U: AsyncWrite + Unpin,
{
    let mut tracker = BodySizeTracker::new(max_request_body_size);
    let result = relay_chunked_body_generic(
        reader,
        upstream,
        read_timeout,
        write_timeout,
        total_deadline,
        peer,
        "to upstream",
        Some(&mut tracker),
        max_request_trailer_bytes,
        "request trailer section exceeds configured limit",
        sanitize_request_trailer_lines,
        None,
        BodyReadSource::Client,
    )
    .await;

    match result {
        Ok(stats) => Ok(stats.bytes_read),
        Err(err) => {
            if let Some(invalid) = err.downcast_ref::<InvalidChunkedBody>() {
                return Err(
                    InvalidRequestBody::new(invalid.bytes_read, invalid.detail.clone()).into(),
                );
            }
            Err(err)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn buffer_chunked_body<S>(
    reader: &mut BufReader<S>,
    read_timeout: Duration,
    total_deadline: Option<Instant>,
    peer: SocketAddr,
    max_payload_size: usize,
    max_trailer_bytes: usize,
) -> Result<(Vec<u8>, u64)>
where
    S: AsyncRead + Unpin,
{
    let mut tracker = BodySizeTracker::new(max_payload_size);
    let mut framing_sink = tokio::io::sink();
    let mut payload = Vec::with_capacity(max_payload_size);
    let result = relay_chunked_body_generic(
        reader,
        &mut framing_sink,
        read_timeout,
        read_timeout,
        total_deadline,
        peer,
        "to credential buffer",
        Some(&mut tracker),
        max_trailer_bytes,
        "request trailer section exceeds configured limit",
        sanitize_request_trailer_lines,
        Some(&mut payload),
        BodyReadSource::Client,
    )
    .await;

    match result {
        Ok(stats) if stats.had_trailers => Err(InvalidRequestBody::new(
            stats.bytes_read,
            "credential-bearing requests must not contain trailers",
        )
        .into()),
        Ok(stats) => Ok((payload, stats.bytes_read)),
        Err(err) => {
            if let Some(invalid) = err.downcast_ref::<InvalidChunkedBody>() {
                return Err(
                    InvalidRequestBody::new(invalid.bytes_read, invalid.detail.clone()).into(),
                );
            }
            Err(err)
        }
    }
}

pub async fn relay_fixed_body<S, C>(
    upstream: &mut BufReader<S>,
    client: &mut C,
    mut remaining: u64,
    read_timeout: Duration,
    write_timeout: Duration,
    peer: SocketAddr,
    total_deadline: Option<Instant>,
) -> Result<u64>
where
    S: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut transferred = 0u64;
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let to_read = remaining.min(buffer.len() as u64) as usize;
        let read = with_total_deadline(
            total_deadline,
            timeout_with_context(
                read_timeout,
                upstream.read(&mut buffer[..to_read]),
                format!("reading upstream response body from {peer}"),
            ),
        )
        .await?;
        if read == 0 {
            bail!("upstream closed connection early while sending response body");
        }
        remaining -= read as u64;
        with_total_deadline(
            total_deadline,
            write_all_with_timeout(
                client,
                &buffer[..read],
                write_timeout,
                "writing response body to client",
            ),
        )
        .await?;
        transferred = transferred.saturating_add(read as u64);
    }
    Ok(transferred)
}

pub async fn relay_chunked_body<S, C>(
    upstream: &mut BufReader<S>,
    client: &mut C,
    read_timeout: Duration,
    write_timeout: Duration,
    peer: SocketAddr,
    total_deadline: Option<Instant>,
    max_response_trailer_bytes: usize,
) -> Result<ChunkedRelayStats>
where
    S: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    relay_chunked_body_generic(
        upstream,
        client,
        read_timeout,
        write_timeout,
        total_deadline,
        peer,
        "to client",
        None,
        max_response_trailer_bytes,
        "response trailer section exceeds configured limit",
        sanitize_response_trailer_lines,
        None,
        BodyReadSource::Upstream,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn relay_chunked_body_with_payload_copy<S, C, P>(
    upstream: &mut BufReader<S>,
    client: &mut C,
    payload_copy: &mut P,
    read_timeout: Duration,
    write_timeout: Duration,
    peer: SocketAddr,
    total_deadline: Option<Instant>,
    max_response_trailer_bytes: usize,
) -> Result<ChunkedRelayStats>
where
    S: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
    P: AsyncWrite + Unpin + Send,
{
    relay_chunked_body_generic(
        upstream,
        client,
        read_timeout,
        write_timeout,
        total_deadline,
        peer,
        "to client",
        None,
        max_response_trailer_bytes,
        "response trailer section exceeds configured limit",
        sanitize_response_trailer_lines,
        Some(payload_copy),
        BodyReadSource::Upstream,
    )
    .await
}

pub async fn relay_until_close<S, C>(
    upstream: &mut BufReader<S>,
    client: &mut C,
    read_timeout: Duration,
    write_timeout: Duration,
    peer: SocketAddr,
    total_deadline: Option<Instant>,
) -> Result<u64>
where
    S: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let read = with_total_deadline(
            total_deadline,
            timeout_with_context(
                read_timeout,
                upstream.read(&mut buffer),
                format!("reading response body from upstream {peer}"),
            ),
        )
        .await?;
        if read == 0 {
            break;
        }
        with_total_deadline(
            total_deadline,
            write_all_with_timeout(
                client,
                &buffer[..read],
                write_timeout,
                "writing response body to client",
            ),
        )
        .await?;
        total = total.saturating_add(read as u64);
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::{
        InvalidRequestBody, buffer_chunked_body, parse_chunk_size_line, relay_chunked_body,
        relay_chunked_body_with_payload_copy, stream_chunked_body,
    };
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, duplex};

    fn peer() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443))
    }

    async fn stream_request_body(body: &[u8]) -> anyhow::Result<u64> {
        let (client_stream, mut client_writer) = duplex(body.len().max(1) * 2);
        client_writer.write_all(body).await?;
        drop(client_writer);

        let mut reader = BufReader::new(client_stream);
        stream_chunked_body(
            &mut reader,
            &mut tokio::io::sink(),
            Duration::from_secs(1),
            Duration::from_secs(1),
            None,
            peer(),
            4096,
            1024,
        )
        .await
    }

    #[test]
    fn chunk_size_parser_accepts_complete_rfc_extension_grammar() {
        assert_eq!(parse_chunk_size_line(b"A\r\n").unwrap(), 10);
        assert_eq!(
            parse_chunk_size_line(b"5 \t; chunk-signature = abc123; quoted=\"a\\\"b\"; flag\r\n")
                .unwrap(),
            5
        );

        let with_obs_text = b"1; opaque=\"\x80\"\r\n";
        assert_eq!(parse_chunk_size_line(with_obs_text).unwrap(), 1);
    }

    #[test]
    fn chunk_size_parser_rejects_ambiguous_or_malformed_lines() {
        for line in [
            b"1\n".as_slice(),
            b"1\r\r\n",
            b"1;\x01=x\r\n",
            b"1;foo=\"unterminated\r\n",
            b"1;foo=bar junk\r\n",
            b"1;\r\n",
            b"1;foo=\r\n",
            b"1 \r\n",
        ] {
            assert!(
                parse_chunk_size_line(line).is_err(),
                "unexpectedly accepted {line:?}"
            );
        }

        let overflow = format!("{}\r\n", "F".repeat(usize::BITS as usize / 4 + 1));
        assert!(parse_chunk_size_line(overflow.as_bytes()).is_err());
    }

    #[tokio::test]
    async fn stream_chunked_body_strips_forwarding_request_trailers() {
        let body = b"5;chunk-signature=abc123\r\nhello\r\n0\r\nX-Forwarded-For: 1.2.3.4\r\nDigest: sha-256=abc\r\n\r\n";
        let expected = b"5;chunk-signature=abc123\r\nhello\r\n0\r\nDigest: sha-256=abc\r\n\r\n";

        let (client_stream, mut client_writer) = duplex(1024);
        let (mut upstream_source, mut upstream_sink) = duplex(1024);
        client_writer
            .write_all(body)
            .await
            .expect("write chunked body");
        drop(client_writer);

        let mut reader = BufReader::new(client_stream);
        let transferred = stream_chunked_body(
            &mut reader,
            &mut upstream_sink,
            Duration::from_secs(1),
            Duration::from_secs(1),
            None,
            peer(),
            4096,
            1024,
        )
        .await
        .expect("chunked request should stream successfully");

        assert_eq!(transferred, body.len() as u64);

        drop(upstream_sink);
        let mut forwarded = Vec::new();
        upstream_source
            .read_to_end(&mut forwarded)
            .await
            .expect("read forwarded body");
        assert_eq!(forwarded, expected);
    }

    #[tokio::test]
    async fn stream_chunked_body_rejects_invalid_size_and_trailer_line_endings() {
        for body in [
            b"".as_slice(),
            b"1\nx\r\n0\r\n\r\n".as_slice(),
            b"1\r\r\nx\r\n0\r\n\r\n",
            b"1\r\nx",
            b"0\r\nDigest: value\n\n",
            b"0\r\nDigest: value\r\r\n\r\n",
        ] {
            let err = stream_request_body(body)
                .await
                .expect_err("ambiguous chunk framing should be rejected");
            assert!(
                err.downcast_ref::<InvalidRequestBody>().is_some(),
                "unexpected error for {body:?}: {err:#}"
            );
        }
    }

    #[tokio::test]
    async fn relay_chunked_body_rejects_ambiguous_upstream_size_line() {
        let body = b"1\nx\r\n0\r\n\r\n";
        let (upstream_stream, mut upstream_writer) = duplex(128);
        upstream_writer.write_all(body).await.unwrap();
        drop(upstream_writer);

        let mut upstream = BufReader::new(upstream_stream);
        let err = relay_chunked_body(
            &mut upstream,
            &mut tokio::io::sink(),
            Duration::from_secs(1),
            Duration::from_secs(1),
            peer(),
            None,
            1024,
        )
        .await
        .expect_err("ambiguous upstream chunk framing should be rejected");
        assert!(err.to_string().contains("must end with CRLF"));
    }

    #[tokio::test]
    async fn relay_chunked_body_copies_only_decoded_payload() {
        let body = b"5;extension=yes\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (upstream_stream, mut upstream_writer) = duplex(256);
        let (mut client_source, mut client_sink) = duplex(256);
        let (mut payload_source, mut payload_sink) = duplex(256);
        upstream_writer.write_all(body).await.unwrap();
        drop(upstream_writer);

        let stats = relay_chunked_body_with_payload_copy(
            &mut BufReader::new(upstream_stream),
            &mut client_sink,
            &mut payload_sink,
            Duration::from_secs(1),
            Duration::from_secs(1),
            peer(),
            None,
            1024,
        )
        .await
        .expect("relay chunked body");
        drop(client_sink);
        drop(payload_sink);

        let mut forwarded = Vec::new();
        client_source.read_to_end(&mut forwarded).await.unwrap();
        let mut payload = Vec::new();
        payload_source.read_to_end(&mut payload).await.unwrap();
        assert_eq!(forwarded, body);
        assert_eq!(payload, b"hello world");
        assert_eq!(stats.bytes_written, body.len() as u64);
        assert!(!stats.had_trailers);
    }

    #[tokio::test]
    async fn relay_chunked_body_strips_hop_by_hop_response_trailers() {
        let body = b"5\r\nhello\r\n0\r\nConnection: close\r\nETag: abc\r\n\r\n";
        let expected = b"5\r\nhello\r\n0\r\nETag: abc\r\n\r\n";

        let (upstream_stream, mut upstream_writer) = duplex(1024);
        let (mut client_reader, mut client_stream) = duplex(1024);
        upstream_writer
            .write_all(body)
            .await
            .expect("write chunked response");
        drop(upstream_writer);

        let mut upstream = BufReader::new(upstream_stream);
        let stats = relay_chunked_body(
            &mut upstream,
            &mut client_stream,
            Duration::from_secs(1),
            Duration::from_secs(1),
            peer(),
            None,
            1024,
        )
        .await
        .expect("chunked response should relay successfully");

        assert_eq!(stats.bytes_read, body.len() as u64);
        assert_eq!(stats.bytes_written, expected.len() as u64);
        assert!(stats.had_trailers);

        drop(client_stream);
        let mut forwarded = Vec::new();
        client_reader
            .read_to_end(&mut forwarded)
            .await
            .expect("read relayed response");
        assert_eq!(forwarded, expected);
    }

    #[tokio::test]
    async fn credential_buffer_decodes_payload_and_rejects_trailers() {
        let body = b"5;extension=yes\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (client_stream, mut writer) = duplex(256);
        writer.write_all(body).await.unwrap();
        drop(writer);
        let (payload, wire_bytes) = buffer_chunked_body(
            &mut BufReader::new(client_stream),
            Duration::from_secs(1),
            None,
            peer(),
            1024,
            1024,
        )
        .await
        .unwrap();
        assert_eq!(payload, b"hello world");
        assert_eq!(payload.capacity(), 1024);
        assert_eq!(wire_bytes, body.len() as u64);

        let body = b"1\r\nx\r\n0\r\nDigest: value\r\n\r\n";
        let (client_stream, mut writer) = duplex(256);
        writer.write_all(body).await.unwrap();
        drop(writer);
        let error = buffer_chunked_body(
            &mut BufReader::new(client_stream),
            Duration::from_secs(1),
            None,
            peer(),
            1024,
            1024,
        )
        .await
        .unwrap_err();
        assert!(error.downcast_ref::<InvalidRequestBody>().is_some());
    }

    #[tokio::test]
    async fn credential_buffer_enforces_payload_limit() {
        let body = b"5\r\nhello\r\n0\r\n\r\n";
        let (client_stream, mut writer) = duplex(256);
        writer.write_all(body).await.unwrap();
        drop(writer);
        assert!(
            buffer_chunked_body(
                &mut BufReader::new(client_stream),
                Duration::from_secs(1),
                None,
                peer(),
                4,
                1024,
            )
            .await
            .is_err()
        );
    }
}
