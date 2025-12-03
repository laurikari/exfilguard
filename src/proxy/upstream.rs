use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::proxy::{connect::ResolvedTarget, resolver};

/// Attempt to connect to the supplied socket addresses without performing name resolution.
pub async fn connect_to_addrs(
    addrs: &[SocketAddr],
    connect_timeout: Duration,
) -> Result<(TcpStream, SocketAddr)> {
    let mut last_err = None;
    for addr in addrs {
        let connect_future = TcpStream::connect(addr);
        match timeout(connect_timeout, connect_future).await {
            Ok(Ok(stream)) => {
                if let Err(err) = stream.set_nodelay(true) {
                    debug!(
                        host = %addr.ip(),
                        port = addr.port(),
                        error = %err,
                        "failed to set TCP_NODELAY on upstream stream"
                    );
                }
                debug!(host = %addr.ip(), port = addr.port(), "connected to upstream");
                return Ok((stream, *addr));
            }
            Ok(Err(err)) => {
                let err = Err::<(), std::io::Error>(err)
                    .with_context(|| format!("failed to connect to {}", addr))
                    .unwrap_err();
                last_err = Some(err);
            }
            Err(_) => {
                last_err = Some(anyhow::anyhow!("connection to {} timed out", addr));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no addresses provided for upstream connect")))
}

/// Returns the socket addresses to use for an upstream request, either by reusing a validated
/// CONNECT binding or by resolving the hostname with the standard policy filters applied.
pub async fn resolve_or_use_binding(
    host: &str,
    port: u16,
    binding: Option<&ResolvedTarget>,
    resolve_timeout: Duration,
    allow_private: bool,
    allow_private_message: &'static str,
) -> Result<Vec<SocketAddr>> {
    if let Some(binding) = binding {
        if host != binding.host() || port != binding.port() {
            bail!(
                "upstream request {}:{} mismatches CONNECT target {}:{}",
                host,
                port,
                binding.host(),
                binding.port()
            );
        }
        return Ok(binding.addresses().to_vec());
    }

    let filtered = resolver::ResolveRequest::new(host, port, resolve_timeout)
        .allow_private(allow_private)
        .context("upstream")
        .allow_private_message(allow_private_message)
        .resolve_filtered()
        .await?;
    Ok(filtered.allowed)
}
