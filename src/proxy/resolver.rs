use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use async_trait::async_trait;
use ipnet::IpNet;
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
pub(crate) struct ConfiguredUpstreamResolver {
    allowed_private_cidrs: Vec<IpNet>,
}

#[derive(Debug, Default)]
pub(crate) struct PermissiveTestResolver;

pub(crate) fn configured_upstream_resolver(
    allowed_private_cidrs: &[IpNet],
) -> Arc<dyn UpstreamResolver> {
    Arc::new(ConfiguredUpstreamResolver {
        allowed_private_cidrs: allowed_private_cidrs.to_vec(),
    })
}

pub(crate) fn permissive_test_upstream_resolver() -> Arc<dyn UpstreamResolver> {
    Arc::new(PermissiveTestResolver)
}

#[async_trait]
impl UpstreamResolver for ConfiguredUpstreamResolver {
    async fn resolve_filtered(
        &self,
        host: &str,
        port: u16,
        timeout_dur: Duration,
        context: &'static str,
    ) -> Result<FilteredAddresses> {
        resolve_host_with_policy_inner(
            host,
            port,
            timeout_dur,
            &self.allowed_private_cidrs,
            context,
        )
        .await
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
        resolve_host_with_policy_inner(
            host,
            port,
            timeout_dur,
            &["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            context,
        )
        .await
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

fn address_allowed(ip: IpAddr, allowed_private_cidrs: &[IpNet]) -> bool {
    !is_private_ip(ip) || allowed_private_cidrs.iter().any(|net| net.contains(&ip))
}

pub fn filter_addresses(
    addrs: Vec<SocketAddr>,
    allowed_private_cidrs: &[IpNet],
) -> FilteredAddresses {
    let mut allowed = Vec::new();
    let mut filtered_private = 0usize;

    for addr in addrs {
        if address_allowed(addr.ip(), allowed_private_cidrs) {
            allowed.push(addr);
        } else {
            filtered_private += 1;
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
    allowed_private_cidrs: &[IpNet],
    context: &'static str,
) -> Result<FilteredAddresses> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        let addrs = ensure_literal_ip(ip, port, allowed_private_cidrs, context, host)?;
        return Ok(FilteredAddresses {
            allowed: addrs,
            filtered_private: 0,
        });
    }

    let resolved = resolve_host(host, port, timeout_dur).await?;
    let filtered = filter_addresses(resolved, allowed_private_cidrs);
    bail_if_empty(&filtered, host, port, context)?;
    Ok(filtered)
}

pub fn ensure_literal_ip(
    ip: IpAddr,
    port: u16,
    allowed_private_cidrs: &[IpNet],
    context: &'static str,
    host: &str,
) -> Result<Vec<SocketAddr>> {
    if !address_allowed(ip, allowed_private_cidrs) {
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

    #[test]
    fn private_exceptions_match_cidr_boundaries_and_address_families() {
        let cidrs: Vec<IpNet> = [
            "10.0.201.0/24",
            "100.64.0.0/10",
            "fd00:1234::/48",
            "127.0.0.1/32",
            "::1/128",
            "169.254.1.2/32",
            "fe80::1/128",
        ]
        .iter()
        .map(|net| net.parse().unwrap())
        .collect();
        for (host, allowed) in [
            ("10.0.201.0", true),
            ("10.0.201.255", true),
            ("10.0.200.255", false),
            ("10.0.202.0", false),
            ("100.64.0.0", true),
            ("100.127.255.255", true),
            ("fd00:1234::", true),
            ("fd00:1234:0:ffff:ffff:ffff:ffff:ffff", true),
            ("fd00:1234:1::", false),
            ("fd00:1233:ffff::", false),
            ("127.0.0.1", true),
            ("127.0.0.2", false),
            ("::1", true),
            ("::", false),
            ("169.254.1.2", true),
            ("169.254.1.3", false),
            ("fe80::1", true),
            ("fe80::2", false),
            ("::ffff:10.0.201.6", false),
            ("64:ff9b::10.0.201.6", false),
            ("8.8.8.8", true),
            ("2001:4860:4860::8888", true),
        ] {
            let ip = host.parse().unwrap();
            assert_eq!(
                ensure_literal_ip(ip, 443, &cidrs, "test", host).is_ok(),
                allowed,
                "{host}"
            );
            let filtered = filter_addresses(vec![SocketAddr::new(ip, 443)], &cidrs);
            assert_eq!(!filtered.allowed.is_empty(), allowed, "{host}");
            assert_eq!(filtered.filtered_private, usize::from(!allowed), "{host}");
        }
        for host in ["::ffff:10.0.201.6", "64:ff9b::10.0.201.6"] {
            let cidr = format!("{host}/128").parse().unwrap();
            assert!(ensure_literal_ip(host.parse().unwrap(), 443, &[cidr], "test", host).is_ok());
        }
    }

    #[test]
    fn filtering_preserves_eligible_candidates_and_reports_complete_rejection() {
        let candidates: Vec<SocketAddr> = [
            "10.0.201.6:443",
            "10.0.201.7:443",
            "8.8.8.8:443",
            "[fd00::1]:443",
            "[2001:4860:4860::8888]:443",
        ]
        .iter()
        .map(|addr| addr.parse().unwrap())
        .collect();
        let cidrs = ["10.0.201.6/32".parse().unwrap()];
        let filtered = filter_addresses(candidates.clone(), &cidrs);
        assert_eq!(
            filtered.allowed,
            vec![candidates[0], candidates[2], candidates[4]]
        );
        assert_eq!(filtered.filtered_private, 2);
        bail_if_empty(&filtered, "example.test", 443, "test").unwrap();
        let filtered = filter_addresses(vec![candidates[1], candidates[3]], &cidrs);
        assert_eq!(filtered.filtered_private, 2);
        assert!(
            bail_if_empty(&filtered, "example.test", 443, "test")
                .unwrap_err()
                .downcast_ref::<PrivateAddressError>()
                .is_some()
        );
        let filtered = filter_addresses(candidates.clone(), &[]);
        assert_eq!(filtered.allowed, vec![candidates[2], candidates[4]]);
    }

    #[tokio::test]
    async fn resolve_request_respects_private_policy() {
        let host = "10.0.0.1";
        let port = 8443;
        let timeout = Duration::from_secs(1);

        let err = resolve_host_with_policy_inner(host, port, timeout, &[], "unit-test")
            .await
            .expect_err("private address should be rejected");
        assert!(err.downcast_ref::<PrivateAddressError>().is_some());

        let addrs = resolve_host_with_policy_inner(
            host,
            port,
            timeout,
            &["10.0.0.1/32".parse().unwrap()],
            "unit-test",
        )
        .await
        .expect("private address allowed");
        assert_eq!(addrs.allowed.len(), 1);
        assert_eq!(
            addrs.allowed[0],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
        );
    }

    #[tokio::test]
    async fn literal_resolution_rejects_non_global_special_destinations() {
        let timeout = Duration::from_secs(1);

        for host in [
            "64:ff9b::10.0.0.1",
            "64:ff9b::127.0.0.1",
            "64:ff9b::169.254.169.254",
            "100:0:0:1::1",
            "192.88.99.2",
        ] {
            let err = resolve_host_with_policy_inner(host, 443, timeout, &[], "unit-test")
                .await
                .expect_err("non-global special destination should be rejected");
            assert!(
                err.downcast_ref::<PrivateAddressError>().is_some(),
                "unexpected error for {host}: {err:#}"
            );
        }
    }

    #[tokio::test]
    async fn literal_resolution_allows_nat64_public_destination() {
        let host = "64:ff9b::8.8.8.8";
        let port = 443;
        let timeout = Duration::from_secs(1);

        let addrs = resolve_host_with_policy_inner(host, port, timeout, &[], "unit-test")
            .await
            .expect("public NAT64 destination should be allowed");
        assert_eq!(
            addrs.allowed,
            vec![SocketAddr::new(host.parse::<IpAddr>().unwrap(), port)]
        );
    }
}
