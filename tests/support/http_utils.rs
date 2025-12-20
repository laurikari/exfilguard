use std::time::Duration as StdDuration;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub async fn read_http_response<S>(stream: &mut S) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

pub async fn read_response_status(reader: &mut BufReader<TcpStream>) -> Result<u16> {
    let mut line = String::new();
    let bytes = timeout(StdDuration::from_secs(2), reader.read_line(&mut line)).await??;
    if bytes == 0 {
        return Err(anyhow!("connection closed before response status line"));
    }
    let status = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("missing status code in response line"))?
        .parse::<u16>()
        .map_err(|err| anyhow!("invalid status code: {err}"))?;
    loop {
        line.clear();
        let n = timeout(StdDuration::from_secs(2), reader.read_line(&mut line)).await??;
        if n == 0 || line == "\r\n" {
            break;
        }
    }
    Ok(status)
}

pub async fn read_until_double_crlf(stream: &mut TcpStream) -> Result<String> {
    let mut buffer = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let bytes = stream.read(&mut byte).await?;
        if bytes == 0 {
            break;
        }
        buffer.extend_from_slice(&byte);
        if buffer.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(buffer).context("invalid UTF-8 response")
}
