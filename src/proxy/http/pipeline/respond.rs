use std::time::Duration;

use anyhow::Result;
use http::StatusCode;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::io_util::write_all_with_timeout;
use crate::logging::AccessLogBuilder;
use crate::util::timeout_with_context;

#[allow(clippy::too_many_arguments)]
pub async fn respond_with_access_log<S>(
    stream: &mut S,
    status: StatusCode,
    reason: Option<&str>,
    body: &[u8],
    timeout_dur: Duration,
    bytes_in: u64,
    elapsed: Duration,
    log_builder: AccessLogBuilder,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let bytes_out = send_response(stream, status, reason, body, timeout_dur).await?;
    shutdown_stream(stream, timeout_dur).await?;
    log_builder
        .status(status)
        .bytes(bytes_in, bytes_out as u64)
        .elapsed(elapsed)
        .log();
    Ok(())
}

pub async fn send_response<S>(
    stream: &mut S,
    status: StatusCode,
    reason: Option<&str>,
    body: &[u8],
    timeout_dur: Duration,
) -> Result<usize>
where
    S: AsyncWrite + Unpin,
{
    let reason_text = reason
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("Unknown"));
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
        status.as_u16(),
        reason_text,
        body.len()
    );
    write_all_with_timeout(
        stream,
        header.as_bytes(),
        timeout_dur,
        "writing response header",
    )
    .await?;
    let mut written = header.len();
    if !body.is_empty() {
        write_all_with_timeout(stream, body, timeout_dur, "writing response body").await?;
        written += body.len();
    }
    Ok(written)
}

pub async fn shutdown_stream<S>(stream: &mut S, timeout_dur: Duration) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    timeout_with_context(
        timeout_dur,
        stream.shutdown(),
        "shutting down client stream",
    )
    .await
}
