use std::future::Future;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader};
use tokio::time::timeout;

use crate::{
    io_util::write_all_with_timeout,
    proxy::{
        forward_error::RequestTimeout, forward_limits::BodySizeTracker,
        http::codec::read_line_with_timeout,
    },
    util::timeout_with_context,
};

const MAX_CHUNK_LINE_LENGTH: usize = 8192;

#[derive(Debug, Error)]
#[error("request body exceeds configured limit")]
pub struct BodyTooLarge {
    pub bytes_read: u64,
}

#[derive(Clone, Copy)]
pub enum BodyPlan {
    Empty,
    Fixed(usize),
    Chunked,
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
) -> Result<T>
where
    F: Future<Output = Result<T, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    let context = context.into();
    let idle_fut = timeout_with_context(idle_timeout, future, context);
    with_total_deadline(total_deadline, idle_fut).await
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
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total_bytes = 0u64;
    let mut line = String::new();

    loop {
        line.clear();
        let size_bytes = with_total_deadline(
            total_deadline,
            read_line_with_timeout(reader, &mut line, read_timeout, peer, MAX_CHUNK_LINE_LENGTH),
        )
        .await?;
        if size_bytes == 0 {
            bail!("unexpected EOF while reading chunk size from {peer}");
        }
        total_bytes = total_bytes.saturating_add(size_bytes as u64);
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let size_str = trimmed
            .split_once(';')
            .map(|(size, _)| size)
            .unwrap_or(trimmed);
        let chunk_size = usize::from_str_radix(size_str, 16)
            .with_context(|| format!("invalid chunk size '{size_str}'"))?;

        if let Some(limit_tracker) = limit.as_deref_mut() {
            limit_tracker.record(chunk_size)?;
        }

        with_total_deadline(
            total_deadline,
            write_all_with_timeout(
                writer,
                line.as_bytes(),
                write_timeout,
                format!("forwarding chunk size {write_target}"),
            ),
        )
        .await?;

        if chunk_size == 0 {
            loop {
                line.clear();
                let trailer_bytes = with_total_deadline(
                    total_deadline,
                    read_line_with_timeout(
                        reader,
                        &mut line,
                        read_timeout,
                        peer,
                        MAX_CHUNK_LINE_LENGTH,
                    ),
                )
                .await?;
                if trailer_bytes == 0 {
                    bail!("unexpected EOF while reading chunk trailer from {peer}");
                }
                with_total_deadline(
                    total_deadline,
                    write_all_with_timeout(
                        writer,
                        line.as_bytes(),
                        write_timeout,
                        format!("forwarding chunk trailer {write_target}"),
                    ),
                )
                .await?;
                total_bytes = total_bytes.saturating_add(trailer_bytes as u64);
                if line.trim_end_matches(['\r', '\n']).is_empty() {
                    break;
                }
            }
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
            )
            .await?;
            if read == 0 {
                bail!("unexpected EOF while reading chunk data from {peer}");
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
            total_bytes = total_bytes.saturating_add(read as u64);
        }

        let mut crlf = [0u8; 2];
        with_idle_and_total(
            read_timeout,
            total_deadline,
            reader.read_exact(&mut crlf),
            format!("reading chunk terminator from {peer}"),
        )
        .await?;
        if &crlf != b"\r\n" {
            bail!("invalid chunk terminator when reading from {peer}");
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
        total_bytes = total_bytes.saturating_add(2);
    }

    Ok(total_bytes)
}

pub async fn stream_chunked_body<S, U>(
    reader: &mut BufReader<S>,
    upstream: &mut U,
    read_timeout: Duration,
    write_timeout: Duration,
    total_deadline: Option<Instant>,
    peer: SocketAddr,
    max_request_body_size: usize,
) -> Result<u64>
where
    S: AsyncRead + Unpin,
    U: AsyncWrite + Unpin,
{
    let mut tracker = BodySizeTracker::new(max_request_body_size);
    relay_chunked_body_generic(
        reader,
        upstream,
        read_timeout,
        write_timeout,
        total_deadline,
        peer,
        "to upstream",
        Some(&mut tracker),
    )
    .await
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
) -> Result<u64>
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
