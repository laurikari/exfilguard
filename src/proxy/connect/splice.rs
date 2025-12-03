use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{
    proxy::{AppContext, upstream},
    util::timeout_with_context,
};

use super::resolve::ResolvedTarget;
use super::target::ConnectTarget;

pub struct SpliceStats {
    pub client_stream_bytes: u64,
    pub upstream_stream_bytes: u64,
    pub handshake_bytes: u64,
    pub upstream_addr: SocketAddr,
}

pub async fn handle_splice(
    client_stream: &mut TcpStream,
    target: &ConnectTarget,
    resolved: &ResolvedTarget,
    app: &AppContext,
) -> Result<SpliceStats> {
    debug_assert_eq!(resolved.port(), target.port);
    let connect_timeout = app.settings.upstream_connect_timeout();
    let (mut upstream_stream, upstream_addr) =
        upstream::connect_to_addrs(resolved.addresses(), connect_timeout).await?;
    let client_timeout = app.settings.client_timeout();
    let upstream_timeout = app.settings.upstream_timeout();

    let handshake_bytes = send_connect_established(client_stream, client_timeout).await?;

    let (client_stream_bytes, upstream_stream_bytes) = relay_with_idle_timeouts(
        client_stream,
        &mut upstream_stream,
        client_timeout,
        upstream_timeout,
    )
    .await
    .context("CONNECT splice relay failed")?;

    timeout_with_context(
        client_timeout,
        client_stream.shutdown(),
        "closing client stream after CONNECT",
    )
    .await?;
    timeout_with_context(
        upstream_timeout,
        upstream_stream.shutdown(),
        "closing upstream stream after CONNECT",
    )
    .await?;
    Ok(SpliceStats {
        client_stream_bytes,
        upstream_stream_bytes,
        handshake_bytes,
        upstream_addr,
    })
}

pub async fn send_connect_established(
    stream: &mut TcpStream,
    client_timeout: Duration,
) -> Result<u64> {
    let established = b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: exfilguard\r\n\r\n";
    timeout_with_context(
        client_timeout,
        stream.write_all(established),
        "writing CONNECT response",
    )
    .await?;
    timeout_with_context(client_timeout, stream.flush(), "flushing CONNECT response").await?;
    Ok(established.len() as u64)
}

async fn relay_with_idle_timeouts(
    client_stream: &mut TcpStream,
    upstream_stream: &mut TcpStream,
    client_timeout: Duration,
    upstream_timeout: Duration,
) -> Result<(u64, u64)> {
    let (mut client_reader, mut client_writer) = io::split(client_stream);
    let (mut upstream_reader, mut upstream_writer) = io::split(upstream_stream);

    let client_to_upstream = transfer_half(
        &mut client_reader,
        &mut upstream_writer,
        client_timeout,
        upstream_timeout,
        "CONNECT client",
        "upstream server",
    );
    let upstream_to_client = transfer_half(
        &mut upstream_reader,
        &mut client_writer,
        client_timeout,
        client_timeout,
        "upstream server",
        "CONNECT client",
    );

    let (client_bytes, upstream_bytes) = tokio::try_join!(client_to_upstream, upstream_to_client)?;
    Ok((client_bytes, upstream_bytes))
}

async fn transfer_half<R, W>(
    reader: &mut R,
    writer: &mut W,
    read_timeout: Duration,
    write_timeout: Duration,
    read_label: &str,
    write_label: &str,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut transferred = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let read = timeout_with_context(
            read_timeout,
            reader.read(&mut buffer),
            format!("reading from {read_label} during CONNECT splice"),
        )
        .await?;
        if read == 0 {
            timeout_with_context(
                write_timeout,
                writer.shutdown(),
                format!("shutting down {write_label} during CONNECT splice"),
            )
            .await?;
            break;
        }

        timeout_with_context(
            write_timeout,
            writer.write_all(&buffer[..read]),
            format!("forwarding to {write_label} during CONNECT splice"),
        )
        .await?;
        transferred = transferred.saturating_add(read as u64);
    }

    timeout_with_context(
        write_timeout,
        writer.flush(),
        format!("flushing {write_label} during CONNECT splice"),
    )
    .await?;

    Ok(transferred)
}
