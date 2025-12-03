use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use crate::proxy::resolver;

use super::target::ConnectTarget;

#[derive(Clone, Debug)]
pub struct ResolvedTarget {
    host: Arc<str>,
    port: u16,
    addresses: Arc<[SocketAddr]>,
}

impl ResolvedTarget {
    pub fn from_addresses(host: String, port: u16, addresses: Vec<SocketAddr>) -> Self {
        debug_assert!(!addresses.is_empty());
        let host_arc: Arc<str> = Arc::from(host.into_boxed_str());
        Self {
            host: host_arc,
            port,
            addresses: Arc::from(addresses.into_boxed_slice()),
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn addresses(&self) -> &[SocketAddr] {
        self.addresses.as_ref()
    }
}

pub async fn resolve_connect_target(
    target: &ConnectTarget,
    resolve_timeout: Duration,
    allow_private: bool,
) -> Result<ResolvedTarget> {
    let addresses =
        resolver::ResolveRequest::new(target.host.as_str(), target.port, resolve_timeout)
            .allow_private(allow_private)
            .context("host")
            .allow_private_message("CONNECT allowed to private address due to configuration")
            .resolve()
            .await?;

    Ok(ResolvedTarget::from_addresses(
        target.host.clone(),
        target.port,
        addresses,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::resolver::PrivateAddressError;
    use std::time::Duration;

    fn target(host: &str) -> ConnectTarget {
        ConnectTarget {
            host: host.to_string(),
            port: 443,
        }
    }

    #[tokio::test]
    async fn rejects_private_ip_when_disallowed() {
        let err = resolve_connect_target(&target("10.0.0.5"), Duration::from_secs(1), false)
            .await
            .expect_err("private IP should be rejected");
        assert!(err.downcast_ref::<PrivateAddressError>().is_some());
    }

    #[tokio::test]
    async fn allows_private_ip_when_permitted() {
        let resolved = resolve_connect_target(&target("10.0.0.5"), Duration::from_secs(1), true)
            .await
            .expect("private IP allowed");
        assert_eq!(resolved.addresses().len(), 1);
        assert_eq!(resolved.addresses()[0], "10.0.0.5:443".parse().unwrap());
    }
}
