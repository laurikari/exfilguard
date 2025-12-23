use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use http::Method;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::time::Instant;
use tracing::debug;

use crate::util::timeout_with_context;

use super::headers::Http1HeaderAccumulator;
use super::line::{read_line_with_deadline, remaining_deadline};

pub(crate) struct Http1RequestHead {
    pub method: Method,
    pub target: String,
    pub headers: Http1HeaderAccumulator,
    pub request_line_bytes: usize,
    pub header_bytes: usize,
}

pub(crate) async fn read_http1_request_head<S>(
    reader: &mut BufReader<S>,
    peer: SocketAddr,
    idle_timeout: Duration,
    header_timeout: Duration,
    max_header_bytes: usize,
) -> Result<Option<Http1RequestHead>>
where
    S: AsyncRead + Unpin,
{
    let request_line_limit = max_header_bytes;
    let available = match tokio::time::timeout(idle_timeout, reader.fill_buf()).await {
        Ok(Ok(buf)) => buf,
        Ok(Err(err)) => {
            return Err(err).with_context(|| format!("waiting for request data from {peer}"));
        }
        Err(_) => return Ok(None),
    };
    if available.is_empty() {
        return Ok(None);
    }

    let deadline = Instant::now() + header_timeout;
    let Some((request_line, request_line_bytes)) =
        read_http1_request_line(reader, peer, deadline, request_line_limit).await?
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
    if parts.next().is_some() {
        bail!("malformed request line: unexpected data");
    }
    match version {
        "HTTP/1.1" => {}
        "HTTP/1.0" => bail!("HTTP/1.0 requests are not supported"),
        other => bail!("invalid HTTP version '{other}'"),
    }

    let method = Method::from_bytes(method_str.as_bytes())
        .with_context(|| format!("invalid method '{method_str}'"))?;
    let target = target.to_string();

    let remaining = max_header_bytes
        .checked_sub(request_line_bytes)
        .ok_or_else(|| anyhow!("request headers exceed configured limit"))?;
    ensure!(remaining > 0, "request headers exceed configured limit");
    let mut headers = Http1HeaderAccumulator::new(remaining);
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

    Ok(Some(Http1RequestHead {
        method,
        target,
        headers,
        request_line_bytes,
        header_bytes,
    }))
}

async fn read_http1_request_line<S>(
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

#[cfg(test)]
mod tests {
    use super::read_http1_request_head;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncWriteExt, BufReader};

    #[tokio::test(start_paused = true)]
    async fn read_request_head_times_out_on_partial_line() {
        let (mut client, server) = tokio::io::duplex(64);
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let handle = tokio::spawn(async move {
            let mut reader = BufReader::new(server);
            read_http1_request_head(
                &mut reader,
                peer,
                Duration::from_millis(50),
                Duration::from_millis(50),
                1024,
            )
            .await
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
    async fn read_request_head_rejects_http10() {
        let (mut client, server) = tokio::io::duplex(128);
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        client
            .write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
            .await
            .expect("write request");
        drop(client);

        let mut reader = BufReader::new(server);
        let err = match read_http1_request_head(
            &mut reader,
            peer,
            Duration::from_secs(1),
            Duration::from_secs(1),
            1024,
        )
        .await
        {
            Ok(_) => panic!("HTTP/1.0 should be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("HTTP/1.0"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn read_request_head_rejects_extra_tokens() {
        let (mut client, server) = tokio::io::duplex(128);
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        client
            .write_all(b"GET / HTTP/1.1 extra\r\nHost: example.com\r\n\r\n")
            .await
            .expect("write request");
        drop(client);

        let mut reader = BufReader::new(server);
        let err = match read_http1_request_head(
            &mut reader,
            peer,
            Duration::from_secs(1),
            Duration::from_secs(1),
            1024,
        )
        .await
        {
            Ok(_) => panic!("request line with extra tokens should be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("unexpected data"),
            "unexpected error: {err}"
        );
    }
}
