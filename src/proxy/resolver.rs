use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Result, bail};
use thiserror::Error;
use tokio::net::lookup_host;
use tracing::{info, warn};

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
    pub allowed_private: usize,
}

/// Builder-style configuration for DNS resolution that enforces policy constraints.
pub struct ResolveRequest<'a> {
    host: &'a str,
    port: u16,
    timeout: Duration,
    allow_private: bool,
    context: &'static str,
    allow_private_message: Option<&'static str>,
}

impl<'a> ResolveRequest<'a> {
    pub fn new(host: &'a str, port: u16, timeout: Duration) -> Self {
        Self {
            host,
            port,
            timeout,
            allow_private: false,
            context: "host",
            allow_private_message: None,
        }
    }

    pub fn allow_private(mut self, allow: bool) -> Self {
        self.allow_private = allow;
        self
    }

    pub fn context(mut self, context: &'static str) -> Self {
        self.context = context;
        self
    }

    pub fn allow_private_message(mut self, message: &'static str) -> Self {
        self.allow_private_message = Some(message);
        self
    }

    pub async fn resolve_filtered(self) -> Result<FilteredAddresses> {
        let Self {
            host,
            port,
            timeout,
            allow_private,
            context,
            allow_private_message,
        } = self;
        let filtered =
            resolve_host_with_policy_inner(host, port, timeout, allow_private, context).await?;
        if let Some(message) = allow_private_message {
            log_resolution_outcome(host, &filtered, allow_private, message);
        }
        Ok(filtered)
    }

    pub async fn resolve(self) -> Result<Vec<SocketAddr>> {
        let filtered = self.resolve_filtered().await?;
        Ok(filtered.allowed)
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
    let mut allowed_private = 0usize;

    for addr in addrs {
        if is_private_ip(addr.ip()) {
            if allow_private {
                allowed_private += 1;
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
        allowed_private,
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
        let allowed_private = if is_private_ip(ip) { addrs.len() } else { 0 };
        return Ok(FilteredAddresses {
            allowed: addrs,
            filtered_private: 0,
            allowed_private,
        });
    }

    let resolved = resolve_host(host, port, timeout_dur).await?;
    let filtered = filter_addresses(resolved, allow_private);
    bail_if_empty(&filtered, host, port, context)?;
    Ok(filtered)
}

pub fn log_resolution_outcome(
    host: &str,
    filtered: &FilteredAddresses,
    allow_private: bool,
    allow_private_message: &str,
) {
    if filtered.filtered_private > 0 {
        warn!(
            host,
            filtered = filtered.filtered_private,
            "filtered private addresses from DNS response"
        );
    }
    if allow_private && filtered.allowed_private > 0 {
        info!(
            host,
            allowed_private = filtered.allowed_private,
            "{allow_private_message}"
        );
    }
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

        let err = ResolveRequest::new(host, port, timeout)
            .context("unit-test")
            .resolve()
            .await
            .expect_err("private address should be rejected");
        assert!(err.downcast_ref::<PrivateAddressError>().is_some());

        let addrs = ResolveRequest::new(host, port, timeout)
            .context("unit-test")
            .allow_private(true)
            .resolve()
            .await
            .expect("private address allowed");
        assert_eq!(addrs.len(), 1);
        assert_eq!(
            addrs[0],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
        );
    }
}
