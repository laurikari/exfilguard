use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Result, anyhow, bail, ensure};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::time::Instant;

use crate::util::timeout_with_context;

pub(super) async fn read_line_with_deadline<S>(
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

pub(crate) async fn read_line_with_timeout<S>(
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

pub(super) fn remaining_deadline(deadline: Instant, context: &str) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| anyhow!("timed out {context}"))
}
