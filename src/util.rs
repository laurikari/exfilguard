use std::{future::Future, net::IpAddr, time::Duration};

use anyhow::{Context, Result, anyhow};
use ipnet::IpNet;
use once_cell::sync::Lazy;
use tokio::time::timeout;

/// Represents either a single IP address or a CIDR network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpOrCidr {
    Ip(IpAddr),
    Cidr(IpNet),
}

/// Parses a string into either an IP address or a CIDR block.
pub fn parse_ip_or_cidr(value: &str) -> Result<IpOrCidr> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("value must not be empty"));
    }

    if trimmed.contains('/') {
        let net = trimmed
            .parse::<IpNet>()
            .with_context(|| format!("invalid CIDR '{trimmed}'"))?;
        Ok(IpOrCidr::Cidr(net))
    } else {
        let ip = trimmed
            .parse::<IpAddr>()
            .with_context(|| format!("invalid IP address '{trimmed}'"))?;
        Ok(IpOrCidr::Ip(ip))
    }
}

/// Returns true if the provided IP address is within a private, loopback, or link-local range.
pub fn is_private_ip(addr: IpAddr) -> bool {
    if PRIVATE_NETS.iter().any(|net| net.contains(&addr)) {
        return true;
    }

    if let IpAddr::V6(v6) = addr
        && let Some(mapped) = v6.to_ipv4_mapped()
    {
        let mapped_addr = IpAddr::V4(mapped);
        return PRIVATE_NETS.iter().any(|net| net.contains(&mapped_addr));
    }

    false
}

/// Returns true if the provided CIDR ranges overlap (including identical ranges).
pub fn cidrs_overlap(a: &IpNet, b: &IpNet) -> bool {
    match (a, b) {
        (IpNet::V4(a), IpNet::V4(b)) => a.contains(&b.network()) || b.contains(&a.network()),
        (IpNet::V6(a), IpNet::V6(b)) => a.contains(&b.network()) || b.contains(&a.network()),
        _ => false,
    }
}

/// Wraps `tokio::time::timeout`, converting elapsed deadlines and inner errors into contextual
/// `anyhow::Error` values for consistent diagnostics.
pub async fn timeout_with_context<F, T, E>(
    duration: Duration,
    future: F,
    context: impl Into<String>,
) -> Result<T>
where
    F: Future<Output = Result<T, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    let context = context.into();
    timeout(duration, future)
        .await
        .map_err(|_| anyhow!("timed out {context}"))?
        .with_context(|| format!("failed while {context}"))
}

static PRIVATE_NETS: Lazy<Vec<IpNet>> = Lazy::new(|| {
    [
        // IPv4 local-use and special-purpose ranges (RFC 6890, RFC 5735)
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "192.88.99.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        // IPv6 local-use and special-purpose ranges (RFC 6890)
        "::/128",
        "::1/128",
        "100::/64",
        "2001:2::/48",
        "2001:10::/28",
        "2001:20::/28",
        "2001:db8::/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ]
    .into_iter()
    .map(|cidr| cidr.parse::<IpNet>().expect("static CIDR parse failed"))
    .collect()
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_ipv4_address() {
        let parsed = parse_ip_or_cidr("192.168.1.1").unwrap();
        assert_eq!(
            parsed,
            IpOrCidr::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn parses_ipv6_address() {
        let parsed = parse_ip_or_cidr("2001:db8::1").unwrap();
        assert_eq!(
            parsed,
            IpOrCidr::Ip(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()))
        );
    }

    #[test]
    fn parses_ipv4_cidr() {
        let parsed = parse_ip_or_cidr("10.0.0.0/8").unwrap();
        assert_eq!(
            parsed,
            IpOrCidr::Cidr("10.0.0.0/8".parse::<IpNet>().unwrap())
        );
    }

    #[test]
    fn parses_ipv6_cidr() {
        let parsed = parse_ip_or_cidr("2001:db8::/32").unwrap();
        assert_eq!(
            parsed,
            IpOrCidr::Cidr("2001:db8::/32".parse::<IpNet>().unwrap())
        );
    }

    #[test]
    fn rejects_empty_string() {
        let err = parse_ip_or_cidr("  ").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn rejects_invalid_input() {
        let err = parse_ip_or_cidr("not-an-ip").unwrap_err();
        assert!(err.to_string().contains("invalid IP address"));
    }

    #[test]
    fn detects_private_ipv4() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 4, 20))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 10, 10))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 5))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn detects_private_ipv6() {
        assert!(is_private_ip(IpAddr::V6(
            "fc00::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(is_private_ip(IpAddr::V6(
            "fe80::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(is_private_ip(IpAddr::V6(
            "::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(is_private_ip(IpAddr::V6(
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(is_private_ip(IpAddr::V6(
            "ff02::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(!is_private_ip(IpAddr::V6(
            "2001:4860::1".parse::<Ipv6Addr>().unwrap()
        )));
    }

    #[test]
    fn detects_private_ipv4_mapped_ipv6() {
        let mapped = IpAddr::V6("::ffff:192.168.1.10".parse::<Ipv6Addr>().unwrap());
        assert!(is_private_ip(mapped));
        let loopback = IpAddr::V6("::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap());
        assert!(is_private_ip(loopback));
    }

    #[test]
    fn allows_public_ipv4_mapped_ipv6() {
        let mapped = IpAddr::V6("::ffff:8.8.8.8".parse::<Ipv6Addr>().unwrap());
        assert!(!is_private_ip(mapped));
    }

    #[test]
    fn detects_overlapping_ipv4_cidrs() {
        let a = "10.0.0.0/24".parse::<IpNet>().unwrap();
        let b = "10.0.0.128/25".parse::<IpNet>().unwrap();
        assert!(cidrs_overlap(&a, &b));
    }

    #[test]
    fn detects_non_overlapping_ipv4_cidrs() {
        let a = "10.0.0.0/24".parse::<IpNet>().unwrap();
        let b = "10.0.1.0/24".parse::<IpNet>().unwrap();
        assert!(!cidrs_overlap(&a, &b));
    }

    #[test]
    fn detects_overlapping_ipv6_cidrs() {
        let a = "2001:db8::/48".parse::<IpNet>().unwrap();
        let b = "2001:db8:0:1::/64".parse::<IpNet>().unwrap();
        assert!(cidrs_overlap(&a, &b));
    }

    #[test]
    fn ignores_ipv4_vs_ipv6_cidrs() {
        let a = "10.0.0.0/24".parse::<IpNet>().unwrap();
        let b = "2001:db8::/32".parse::<IpNet>().unwrap();
        assert!(!cidrs_overlap(&a, &b));
    }
}
