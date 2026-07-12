use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Error, Result};
use thiserror::Error;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until};

use crate::{
    io_util::write_all_with_timeout,
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

#[derive(Debug, Error)]
#[error("CONNECT tunnel max lifetime exceeded")]
pub struct ConnectTunnelTimeout;

#[derive(Debug, Error)]
#[error("CONNECT tunnel idle timeout exceeded")]
struct ConnectTunnelIdleTimeout;

#[derive(Debug, Error)]
#[error("CONNECT tunnel failed after the downstream response was committed: {source}")]
pub struct ConnectTunnelCommittedError {
    pub handshake_bytes: u64,
    pub upstream_addr: SocketAddr,
    pub error_reason: &'static str,
    #[source]
    pub source: Error,
}

impl ConnectTunnelCommittedError {
    fn new(
        handshake_bytes: u64,
        upstream_addr: SocketAddr,
        error_reason: &'static str,
        source: Error,
    ) -> Self {
        Self {
            handshake_bytes,
            upstream_addr,
            error_reason,
            source,
        }
    }
}

pub async fn handle_splice(
    client_stream: &mut TcpStream,
    prefetched: &[u8],
    target: &ConnectTarget,
    resolved: &ResolvedTarget,
    app: &AppContext,
) -> Result<SpliceStats> {
    debug_assert_eq!(resolved.port(), target.port);
    let connect_timeout = app.settings.upstream_connect_timeout();
    let (mut upstream_stream, upstream_addr) =
        upstream::connect_to_addrs(resolved.addresses(), connect_timeout).await?;
    let tunnel_idle_timeout = app.settings.connect_tunnel_idle_timeout();
    let tunnel_max_lifetime = app.settings.connect_tunnel_max_lifetime();

    let handshake_bytes = send_connect_established(client_stream, tunnel_idle_timeout)
        .await
        .map_err(|source| {
            ConnectTunnelCommittedError::new(0, upstream_addr, "tunnel_establish_failed", source)
        })?;
    let _tunnel_guard = crate::metrics::track_connect_tunnel();

    if !prefetched.is_empty() {
        write_all_with_timeout(
            &mut upstream_stream,
            prefetched,
            tunnel_idle_timeout,
            "forwarding prefetched CONNECT payload upstream",
        )
        .await
        .map_err(|source| {
            ConnectTunnelCommittedError::new(
                handshake_bytes,
                upstream_addr,
                "tunnel_relay_failed",
                source,
            )
        })?;
    }

    let relay = relay_with_idle_timeout(client_stream, &mut upstream_stream, tunnel_idle_timeout);
    let relay_result = if let Some(limit) = tunnel_max_lifetime {
        match tokio::time::timeout(limit, relay).await {
            Ok(result) => result,
            Err(_) => Err(ConnectTunnelTimeout.into()),
        }
    } else {
        relay.await
    };
    let (relayed_client_bytes, upstream_stream_bytes) = relay_result
        .context("CONNECT splice relay failed")
        .map_err(|source| {
            let error_reason = if source.downcast_ref::<ConnectTunnelTimeout>().is_some() {
                "tunnel_max_lifetime"
            } else {
                "tunnel_relay_failed"
            };
            ConnectTunnelCommittedError::new(handshake_bytes, upstream_addr, error_reason, source)
        })?;
    let client_stream_bytes = (prefetched.len() as u64).saturating_add(relayed_client_bytes);

    timeout_with_context(
        tunnel_idle_timeout,
        client_stream.shutdown(),
        "closing client stream after CONNECT",
    )
    .await
    .map_err(|source| {
        ConnectTunnelCommittedError::new(
            handshake_bytes,
            upstream_addr,
            "tunnel_shutdown_failed",
            source,
        )
    })?;
    timeout_with_context(
        tunnel_idle_timeout,
        upstream_stream.shutdown(),
        "closing upstream stream after CONNECT",
    )
    .await
    .map_err(|source| {
        ConnectTunnelCommittedError::new(
            handshake_bytes,
            upstream_addr,
            "tunnel_shutdown_failed",
            source,
        )
    })?;
    Ok(SpliceStats {
        client_stream_bytes,
        upstream_stream_bytes,
        handshake_bytes,
        upstream_addr,
    })
}

pub async fn send_connect_established<S>(stream: &mut S, write_timeout: Duration) -> Result<u64>
where
    S: AsyncWrite + Unpin,
{
    let established = b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: exfilguard\r\n\r\n";
    write_all_with_timeout(
        stream,
        established,
        write_timeout,
        "writing CONNECT response",
    )
    .await?;
    timeout_with_context(write_timeout, stream.flush(), "flushing CONNECT response").await?;
    Ok(established.len() as u64)
}

async fn relay_with_idle_timeout<C, U>(
    client_stream: &mut C,
    upstream_stream: &mut U,
    idle_timeout: Duration,
) -> Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_reader, mut client_writer) = io::split(client_stream);
    let (mut upstream_reader, mut upstream_writer) = io::split(upstream_stream);
    let (activity_tx, activity_rx) = watch::channel(Instant::now());

    let client_to_upstream = transfer_half(
        &mut client_reader,
        &mut upstream_writer,
        idle_timeout,
        "CONNECT client",
        "upstream server",
        &activity_tx,
    );
    let upstream_to_client = transfer_half(
        &mut upstream_reader,
        &mut client_writer,
        idle_timeout,
        "upstream server",
        "CONNECT client",
        &activity_tx,
    );

    let relay = async {
        let (client_bytes, upstream_bytes) =
            tokio::try_join!(client_to_upstream, upstream_to_client)?;
        Ok((client_bytes, upstream_bytes))
    };
    tokio::pin!(relay);
    tokio::select! {
        biased;
        result = &mut relay => result,
        result = wait_for_tunnel_idle(activity_rx, idle_timeout) => {
            result?;
            unreachable!("tunnel idle watchdog only returns errors")
        }
    }
}

async fn wait_for_tunnel_idle(
    mut activity: watch::Receiver<Instant>,
    idle_timeout: Duration,
) -> Result<()> {
    loop {
        let last_activity = *activity.borrow_and_update();
        let deadline = last_activity
            .checked_add(idle_timeout)
            .ok_or_else(|| anyhow::anyhow!("CONNECT tunnel idle timeout is too large"))?;
        tokio::select! {
            biased;
            changed = activity.changed() => {
                if changed.is_err() {
                    std::future::pending::<()>().await;
                }
            }
            _ = sleep_until(deadline) => {
                if *activity.borrow() <= last_activity {
                    return Err(ConnectTunnelIdleTimeout.into());
                }
            }
        }
    }
}

async fn transfer_half<R, W>(
    reader: &mut R,
    writer: &mut W,
    write_timeout: Duration,
    read_label: &str,
    write_label: &str,
    activity: &watch::Sender<Instant>,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut transferred = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .with_context(|| format!("reading from {read_label} during CONNECT splice"))?;
        if read == 0 {
            timeout_with_context(
                write_timeout,
                writer.shutdown(),
                format!("shutting down {write_label} during CONNECT splice"),
            )
            .await?;
            activity.send_replace(Instant::now());
            break;
        }

        write_all_with_timeout(
            writer,
            &buffer[..read],
            write_timeout,
            format!("forwarding to {write_label} during CONNECT splice"),
        )
        .await?;
        transferred = transferred.saturating_add(read as u64);
        activity.send_replace(Instant::now());
    }

    timeout_with_context(
        write_timeout,
        writer.flush(),
        format!("flushing {write_label} during CONNECT splice"),
    )
    .await?;

    Ok(transferred)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use tokio::io::duplex;
    use tokio::net::TcpListener;

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_applies_to_the_whole_tunnel() -> Result<()> {
        let client_listener = TcpListener::bind("127.0.0.1:0").await?;
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;

        let client_addr = client_listener.local_addr()?;
        let upstream_addr = upstream_listener.local_addr()?;

        let client_accept = tokio::spawn(async move { client_listener.accept().await });
        let upstream_accept = tokio::spawn(async move { upstream_listener.accept().await });

        let client_peer = TcpStream::connect(client_addr).await?;
        let upstream_peer = TcpStream::connect(upstream_addr).await?;

        let (mut client_stream, _) = client_accept.await??;
        let (mut upstream_stream, _) = upstream_accept.await??;

        let idle_timeout = Duration::from_secs(1);

        let handle = tokio::spawn(async move {
            relay_with_idle_timeout(&mut client_stream, &mut upstream_stream, idle_timeout).await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(idle_timeout - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(!handle.is_finished(), "tunnel expired before idle timeout");

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;

        assert!(
            handle.is_finished(),
            "expected tunnel idle timeout to trigger"
        );

        let err = handle.await.expect("join should succeed").unwrap_err();
        assert!(
            err.to_string()
                .contains("CONNECT tunnel idle timeout exceeded"),
            "unexpected error: {err}"
        );

        drop(client_peer);
        drop(upstream_peer);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn continuous_upload_keeps_response_silent_tunnel_active() -> Result<()> {
        let (mut client_peer, mut client_stream) = duplex(1024);
        let (mut upstream_stream, mut upstream_peer) = duplex(1024);
        let idle_timeout = Duration::from_secs(1);
        let handle = tokio::spawn(async move {
            relay_with_idle_timeout(&mut client_stream, &mut upstream_stream, idle_timeout).await
        });

        for byte in 0u8..4 {
            client_peer.write_all(&[byte]).await?;
            let mut received = [0u8; 1];
            upstream_peer.read_exact(&mut received).await?;
            assert_eq!(received, [byte]);
            tokio::time::advance(Duration::from_millis(750)).await;
            tokio::task::yield_now().await;
            assert!(!handle.is_finished(), "active upload tunnel timed out");
        }

        drop(client_peer);
        drop(upstream_peer);
        let (client_bytes, upstream_bytes) = handle.await??;
        assert_eq!(client_bytes, 4);
        assert_eq!(upstream_bytes, 0);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn continuous_download_keeps_request_silent_tunnel_active() -> Result<()> {
        let (mut client_peer, mut client_stream) = duplex(1024);
        let (mut upstream_stream, mut upstream_peer) = duplex(1024);
        let idle_timeout = Duration::from_secs(1);
        let handle = tokio::spawn(async move {
            relay_with_idle_timeout(&mut client_stream, &mut upstream_stream, idle_timeout).await
        });

        for byte in 0u8..4 {
            upstream_peer.write_all(&[byte]).await?;
            let mut received = [0u8; 1];
            client_peer.read_exact(&mut received).await?;
            assert_eq!(received, [byte]);
            tokio::time::advance(Duration::from_millis(750)).await;
            tokio::task::yield_now().await;
            assert!(!handle.is_finished(), "active download tunnel timed out");
        }

        drop(client_peer);
        drop(upstream_peer);
        let (client_bytes, upstream_bytes) = handle.await??;
        assert_eq!(client_bytes, 0);
        assert_eq!(upstream_bytes, 4);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn half_closed_upload_allows_long_running_download() -> Result<()> {
        let (mut client_peer, mut client_stream) = duplex(1024);
        let (mut upstream_stream, mut upstream_peer) = duplex(1024);
        let idle_timeout = Duration::from_secs(1);
        let handle = tokio::spawn(async move {
            relay_with_idle_timeout(&mut client_stream, &mut upstream_stream, idle_timeout).await
        });

        client_peer.write_all(b"upload").await?;
        client_peer.shutdown().await?;
        let mut upload = [0u8; 6];
        upstream_peer.read_exact(&mut upload).await?;
        assert_eq!(&upload, b"upload");
        let mut eof = [0u8; 1];
        assert_eq!(upstream_peer.read(&mut eof).await?, 0);

        for byte in 0u8..4 {
            upstream_peer.write_all(&[byte]).await?;
            let mut received = [0u8; 1];
            client_peer.read_exact(&mut received).await?;
            assert_eq!(received, [byte]);
            tokio::time::advance(Duration::from_millis(750)).await;
            tokio::task::yield_now().await;
            assert!(!handle.is_finished(), "half-closed active tunnel timed out");
        }

        upstream_peer.shutdown().await?;
        assert_eq!(client_peer.read(&mut eof).await?, 0);
        let (client_bytes, upstream_bytes) = handle.await??;
        assert_eq!(client_bytes, 6);
        assert_eq!(upstream_bytes, 4);
        Ok(())
    }
}
