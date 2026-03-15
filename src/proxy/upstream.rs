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
        .resolve_filtered()
        .await?;
    Ok(filtered.allowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::connect::ResolvedTarget;
    use crate::proxy::resolver::PrivateAddressError;
    use std::time::Duration;

    #[tokio::test]
    async fn binding_reuses_validated_private_target() -> Result<()> {
        let binding = ResolvedTarget::from_addresses(
            "internal.test".to_string(),
            443,
            vec!["10.0.0.5:443".parse().unwrap()],
        );
        let addrs = resolve_or_use_binding(
            "internal.test",
            443,
            Some(&binding),
            Duration::from_secs(1),
            false,
        )
        .await?;
        assert_eq!(addrs, vec!["10.0.0.5:443".parse().unwrap()]);
        Ok(())
    }

    #[tokio::test]
    async fn direct_resolution_rejects_private_targets_when_disallowed() {
        let err = resolve_or_use_binding("10.0.0.5", 443, None, Duration::from_secs(1), false)
            .await
            .expect_err("private upstream should be rejected");
        assert!(err.downcast_ref::<PrivateAddressError>().is_some());
    }
}
