use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{
    proxy::{forward_limits::BodySizeTracker, http::codec::read_line_with_timeout},
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

pub async fn stream_fixed_body<S, U>(
    reader: &mut BufReader<S>,
    upstream: &mut U,
    mut remaining: usize,
    client_timeout: Duration,
    upstream_timeout: Duration,
) -> Result<u64>
where
    S: AsyncRead + Unpin,
    U: AsyncWrite + Unpin,
{
    let mut transferred = 0u64;
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let to_read = remaining.min(buffer.len());
        let read = timeout_with_context(
            client_timeout,
            reader.read(&mut buffer[..to_read]),
            "reading request body from client",
        )
        .await?;
        if read == 0 {
            bail!("unexpected EOF while reading request body from client");
        }
        remaining -= read;
        timeout_with_context(
            upstream_timeout,
            upstream.write_all(&buffer[..read]),
            "writing request body to upstream",
        )
        .await?;
        transferred = transferred.saturating_add(read as u64);
    }
    Ok(transferred)
}

async fn relay_chunked_body_generic<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    read_timeout: Duration,
    write_timeout: Duration,
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
        let size_bytes =
            read_line_with_timeout(reader, &mut line, read_timeout, peer, MAX_CHUNK_LINE_LENGTH)
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

        timeout_with_context(
            write_timeout,
            writer.write_all(line.as_bytes()),
            format!("forwarding chunk size {write_target}"),
        )
        .await?;

        if chunk_size == 0 {
            loop {
                line.clear();
                let trailer_bytes = read_line_with_timeout(
                    reader,
                    &mut line,
                    read_timeout,
                    peer,
                    MAX_CHUNK_LINE_LENGTH,
                )
                .await?;
                if trailer_bytes == 0 {
                    bail!("unexpected EOF while reading chunk trailer from {peer}");
                }
                timeout_with_context(
                    write_timeout,
                    writer.write_all(line.as_bytes()),
                    format!("forwarding chunk trailer {write_target}"),
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
            let read = timeout_with_context(
                read_timeout,
                reader.read(&mut buffer[..to_read]),
                format!("reading chunk data from {peer}"),
            )
            .await?;
            if read == 0 {
                bail!("unexpected EOF while reading chunk data from {peer}");
            }
            remaining -= read;
            timeout_with_context(
                write_timeout,
                writer.write_all(&buffer[..read]),
                format!("forwarding chunk data {write_target}"),
            )
            .await?;
            total_bytes = total_bytes.saturating_add(read as u64);
        }

        let mut crlf = [0u8; 2];
        timeout_with_context(
            read_timeout,
            reader.read_exact(&mut crlf),
            format!("reading chunk terminator from {peer}"),
        )
        .await?;
        if &crlf != b"\r\n" {
            bail!("invalid chunk terminator when reading from {peer}");
        }
        timeout_with_context(
            write_timeout,
            writer.write_all(&crlf),
            format!("forwarding chunk terminator {write_target}"),
        )
        .await?;
        total_bytes = total_bytes.saturating_add(2);
    }

    Ok(total_bytes)
}

pub async fn stream_chunked_body<S, U>(
    reader: &mut BufReader<S>,
    upstream: &mut U,
    client_timeout: Duration,
    upstream_timeout: Duration,
    peer: SocketAddr,
    max_body_size: usize,
) -> Result<u64>
where
    S: AsyncRead + Unpin,
    U: AsyncWrite + Unpin,
{
    let mut tracker = BodySizeTracker::new(max_body_size);
    relay_chunked_body_generic(
        reader,
        upstream,
        client_timeout,
        upstream_timeout,
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
    upstream_timeout: Duration,
    client_timeout: Duration,
    peer: SocketAddr,
) -> Result<u64>
where
    S: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut transferred = 0u64;
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let to_read = remaining.min(buffer.len() as u64) as usize;
        let read = timeout_with_context(
            upstream_timeout,
            upstream.read(&mut buffer[..to_read]),
            format!("reading upstream response body from {peer}"),
        )
        .await?;
        if read == 0 {
            bail!("upstream closed connection early while sending response body");
        }
        remaining -= read as u64;
        timeout_with_context(
            client_timeout,
            client.write_all(&buffer[..read]),
            "writing response body to client",
        )
        .await?;
        transferred = transferred.saturating_add(read as u64);
    }
    Ok(transferred)
}

pub async fn relay_chunked_body<S, C>(
    upstream: &mut BufReader<S>,
    client: &mut C,
    upstream_timeout: Duration,
    client_timeout: Duration,
    peer: SocketAddr,
) -> Result<u64>
where
    S: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    relay_chunked_body_generic(
        upstream,
        client,
        upstream_timeout,
        client_timeout,
        peer,
        "to client",
        None,
    )
    .await
}

pub async fn relay_until_close<S, C>(
    upstream: &mut BufReader<S>,
    client: &mut C,
    upstream_timeout: Duration,
    client_timeout: Duration,
    peer: SocketAddr,
) -> Result<u64>
where
    S: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let read = timeout_with_context(
            upstream_timeout,
            upstream.read(&mut buffer),
            format!("reading response body from upstream {peer}"),
        )
        .await?;
        if read == 0 {
            break;
        }
        timeout_with_context(
            client_timeout,
            client.write_all(&buffer[..read]),
            "writing response body to client",
        )
        .await?;
        total = total.saturating_add(read as u64);
    }
    Ok(total)
}
