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
        let filtered = resolver::filter_addresses(binding.addresses().to_vec(), allow_private);
        resolver::bail_if_empty(&filtered, host, port, "upstream")?;
        return Ok(filtered.allowed);
    }

    let filtered = resolver::ResolveRequest::new(host, port, resolve_timeout)
        .allow_private(allow_private)
        .context("upstream")
        .allow_private_message(allow_private_message)
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
    async fn binding_private_only_rejected_when_disallowed() {
        let binding = ResolvedTarget::from_addresses(
            "internal.test".to_string(),
            443,
            vec!["10.0.0.5:443".parse().unwrap()],
        );
        let err = resolve_or_use_binding(
            "internal.test",
            443,
            Some(&binding),
            Duration::from_secs(1),
            false,
            "unused",
        )
        .await
        .expect_err("private binding should be rejected when allow_private=false");
        assert!(err.downcast_ref::<PrivateAddressError>().is_some());
    }

    #[tokio::test]
    async fn binding_filters_private_when_disallowed() -> Result<()> {
        let private_addr: SocketAddr = "10.0.0.5:443".parse().unwrap();
        let public_addr: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let binding = ResolvedTarget::from_addresses(
            "example.com".to_string(),
            443,
            vec![private_addr, public_addr],
        );
        let addrs = resolve_or_use_binding(
            "example.com",
            443,
            Some(&binding),
            Duration::from_secs(1),
            false,
            "unused",
        )
        .await?;
        assert_eq!(addrs, vec![public_addr]);
        Ok(())
    }

    #[tokio::test]
    async fn binding_allows_private_when_enabled() -> Result<()> {
        let private_addr: SocketAddr = "10.0.0.5:443".parse().unwrap();
        let public_addr: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let binding = ResolvedTarget::from_addresses(
            "example.com".to_string(),
            443,
            vec![private_addr, public_addr],
        );
        let addrs = resolve_or_use_binding(
            "example.com",
            443,
            Some(&binding),
            Duration::from_secs(1),
            true,
            "unused",
        )
        .await?;
        assert_eq!(addrs, vec![private_addr, public_addr]);
        Ok(())
    }
}
