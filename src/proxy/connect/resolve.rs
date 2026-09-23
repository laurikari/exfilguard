use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use crate::{
    config::Scheme,
    proxy::{
        forward_error::MisdirectedRequest, request::ParsedRequest, resolver::UpstreamResolver,
    },
};

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

    /// Check every inspected request before policy, cache, or forwarding work.
    pub(crate) fn validate_request(&self, request: &ParsedRequest) -> Result<()> {
        let port = request.port.unwrap_or(request.scheme.default_port());
        if request.scheme != Scheme::Https || request.host != self.host() || port != self.port() {
            return Err(MisdirectedRequest::new(
                crate::proxy::request::scheme_name(request.scheme),
                self.host().to_string(),
                self.port(),
                request.host.clone(),
                port,
            )
            .into());
        }
        Ok(())
    }
}

pub async fn resolve_connect_target(
    target: &ConnectTarget,
    resolve_timeout: Duration,
    resolver: &dyn UpstreamResolver,
) -> Result<ResolvedTarget> {
    let filtered = resolver
        .resolve_filtered(target.host.as_str(), target.port, resolve_timeout, "host")
        .await?;

    Ok(ResolvedTarget::from_addresses(
        target.host.clone(),
        target.port,
        filtered.allowed,
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

    #[test]
    fn inspected_requests_match_canonical_host_and_effective_https_port() -> Result<()> {
        use crate::proxy::request::parse_http1_request;
        use http::Method;

        for (host, targets) in [
            (
                "example.com",
                vec![
                    "https://EXAMPLE.com/",
                    "https://example.com:443/",
                    "https://example.com.:0443/",
                ],
            ),
            (
                "2001:db8::10",
                vec![
                    "https://[2001:0DB8:0:0:0:0:0:10]/",
                    "https://[2001:db8::10]:443/",
                ],
            ),
        ] {
            let binding =
                ResolvedTarget::from_addresses(host.into(), 443, vec!["192.0.2.1:443".parse()?]);
            for target in targets {
                let parsed = parse_http1_request(Method::GET, target, None, Scheme::Https)?;
                binding.validate_request(&parsed)?;
                assert_eq!(
                    parsed.authority_host(),
                    target
                        .strip_prefix("https://")
                        .unwrap()
                        .trim_end_matches('/')
                );
            }
        }
        let binding = ResolvedTarget::from_addresses(
            "example.com".into(),
            8443,
            vec!["192.0.2.1:8443".parse()?],
        );
        for target in [
            "https://example.com/",
            "http://example.com:8443/",
            "https://other.test:8443/",
        ] {
            let parsed = parse_http1_request(Method::GET, target, None, Scheme::Https)?;
            assert!(
                binding
                    .validate_request(&parsed)
                    .unwrap_err()
                    .is::<MisdirectedRequest>(),
                "{target}"
            );
        }
        let parsed = parse_http1_request(
            Method::GET,
            "https://example.com:8443/",
            None,
            Scheme::Https,
        )?;
        binding.validate_request(&parsed)?;
        Ok(())
    }

    #[tokio::test]
    async fn rejects_private_ip_when_disallowed() {
        let resolver = crate::proxy::resolver::PublicInternetResolver;
        let err = resolve_connect_target(&target("10.0.0.5"), Duration::from_secs(1), &resolver)
            .await
            .expect_err("private IP should be rejected");
        assert!(err.downcast_ref::<PrivateAddressError>().is_some());
    }

    #[tokio::test]
    async fn allows_private_ip_when_permitted() {
        let resolver = crate::proxy::resolver::PermissiveTestResolver;
        let resolved =
            resolve_connect_target(&target("10.0.0.5"), Duration::from_secs(1), &resolver)
                .await
                .expect("private IP allowed");
        assert_eq!(resolved.addresses().len(), 1);
        assert_eq!(resolved.addresses()[0], "10.0.0.5:443".parse().unwrap());
    }
}
