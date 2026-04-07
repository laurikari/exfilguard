use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use async_trait::async_trait;
use thiserror::Error;
use tokio::net::lookup_host;

use crate::util::{is_private_ip, timeout_with_context};

#[derive(Debug, Error)]
#[error("resolved {context} {host}:{port} only to private addresses")]
pub struct PrivateAddressError {
    pub host: String,
    pub port: u16,
    pub context: &'static str,
}

impl PrivateAddressError {
    pub fn new(host: &str, port: u16, context: &'static str) -> Self {
        Self {
            host: host.to_string(),
            port,
            context,
        }
    }
}

#[derive(Debug)]
pub struct FilteredAddresses {
    pub allowed: Vec<SocketAddr>,
    pub filtered_private: usize,
}

#[async_trait]
pub(crate) trait UpstreamResolver: Send + Sync {
    async fn resolve_filtered(
        &self,
        host: &str,
        port: u16,
        timeout_dur: Duration,
        context: &'static str,
    ) -> Result<FilteredAddresses>;
}

#[derive(Debug, Default)]
pub(crate) struct PublicInternetResolver;

#[derive(Debug, Default)]
pub(crate) struct PermissiveTestResolver;

pub(crate) fn default_upstream_resolver() -> Arc<dyn UpstreamResolver> {
    Arc::new(PublicInternetResolver)
}

pub(crate) fn permissive_test_upstream_resolver() -> Arc<dyn UpstreamResolver> {
    Arc::new(PermissiveTestResolver)
}

#[async_trait]
impl UpstreamResolver for PublicInternetResolver {
    async fn resolve_filtered(
        &self,
        host: &str,
        port: u16,
        timeout_dur: Duration,
        context: &'static str,
    ) -> Result<FilteredAddresses> {
        resolve_host_with_policy_inner(host, port, timeout_dur, false, context).await
    }
}

#[async_trait]
impl UpstreamResolver for PermissiveTestResolver {
    async fn resolve_filtered(
        &self,
        host: &str,
        port: u16,
        timeout_dur: Duration,
        context: &'static str,
    ) -> Result<FilteredAddresses> {
        resolve_host_with_policy_inner(host, port, timeout_dur, true, context).await
    }
}

pub async fn resolve_host(host: &str, port: u16, timeout_dur: Duration) -> Result<Vec<SocketAddr>> {
    let lookup = lookup_host((host, port));
    let addrs = timeout_with_context(
        timeout_dur,
        lookup,
        format!("resolving DNS for {host}:{port}"),
    )
    .await?;
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for addr in addrs {
        if seen.insert(addr) {
            unique.push(addr);
        }
    }
    Ok(unique)
}

pub fn filter_addresses(addrs: Vec<SocketAddr>, allow_private: bool) -> FilteredAddresses {
    let mut allowed = Vec::new();
    let mut filtered_private = 0usize;

    for addr in addrs {
        if is_private_ip(addr.ip()) {
            if allow_private {
                allowed.push(addr);
            } else {
                filtered_private += 1;
            }
        } else {
            allowed.push(addr);
        }
    }

    FilteredAddresses {
        allowed,
        filtered_private,
    }
}

async fn resolve_host_with_policy_inner(
    host: &str,
    port: u16,
    timeout_dur: Duration,
    allow_private: bool,
    context: &'static str,
) -> Result<FilteredAddresses> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        let addrs = ensure_literal_ip(ip, port, allow_private, context, host)?;
        return Ok(FilteredAddresses {
            allowed: addrs,
            filtered_private: 0,
        });
    }

    let resolved = resolve_host(host, port, timeout_dur).await?;
    let filtered = filter_addresses(resolved, allow_private);
    bail_if_empty(&filtered, host, port, context)?;
    Ok(filtered)
}

pub fn ensure_literal_ip(
    ip: IpAddr,
    port: u16,
    allow_private: bool,
    context: &'static str,
    host: &str,
) -> Result<Vec<SocketAddr>> {
    if is_private_ip(ip) && !allow_private {
        return Err(PrivateAddressError::new(host, port, context).into());
    }
    Ok(vec![SocketAddr::new(ip, port)])
}

pub fn bail_if_empty(
    filtered: &FilteredAddresses,
    host: &str,
    port: u16,
    context: &'static str,
) -> Result<()> {
    if filtered.allowed.is_empty() {
        if filtered.filtered_private > 0 {
            return Err(PrivateAddressError::new(host, port, context).into());
        }
        bail!("DNS lookup for {host}:{port} returned no usable addresses");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[tokio::test]
    async fn resolve_request_respects_private_policy() {
        let host = "10.0.0.1";
        let port = 8443;
        let timeout = Duration::from_secs(1);

        let err = resolve_host_with_policy_inner(host, port, timeout, false, "unit-test")
            .await
            .expect_err("private address should be rejected");
        assert!(err.downcast_ref::<PrivateAddressError>().is_some());

        let addrs = resolve_host_with_policy_inner(host, port, timeout, true, "unit-test")
            .await
            .expect("private address allowed");
        assert_eq!(addrs.allowed.len(), 1);
        assert_eq!(
            addrs.allowed[0],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
        );
    }
}
