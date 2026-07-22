use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use ipnet::IpNet;
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

/// Return the canonical textual representation when `value` is an IP literal.
pub fn canonicalize_ip_literal(value: &str) -> Option<String> {
    value.parse::<IpAddr>().ok().map(|addr| addr.to_string())
}

/// Treat an IPv4-mapped IPv6 address as the IPv4 address it represents.
pub fn normalize_mapped_ip(addr: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = addr
        && let Some(mapped) = v6.to_ipv4_mapped()
    {
        return IpAddr::V4(mapped);
    }
    addr
}

/// Returns true if the provided IP address should be treated as non-public for upstream filtering.
///
/// Historical note: despite the name, this is intentionally broader than RFC1918/RFC4193 private
/// space. ExfilGuard blocks upstream addresses that are not valid public-Internet destinations by
/// default.
///
/// Keep the baseline aligned with the current unstable `std::net::IpAddr::is_global()` logic until
/// that API stabilizes. The stdlib logic is based on the IANA special-purpose registries, but we
/// also reject multicast and translation forms that could reach non-global IPv4 destinations.
pub fn is_private_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => ipv4_is_non_global_upstream(v4),
        IpAddr::V6(v6) => ipv6_is_non_global_upstream(v6),
    }
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

fn ipv4_is_non_global_upstream(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 0
        || addr.is_private()
        || ipv4_is_shared(addr)
        || addr.is_loopback()
        || addr.is_link_local()
        || ipv4_is_protocol_assignment(addr)
        || ipv4_is_6to4_relay_anycast(addr)
        || addr.is_documentation()
        || ipv4_is_benchmarking(addr)
        || ipv4_is_reserved(addr)
        || addr.is_broadcast()
        || addr.is_multicast()
}

fn ipv4_is_shared(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

fn ipv4_is_protocol_assignment(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 192 && octets[1] == 0 && octets[2] == 0 && octets[3] != 9 && octets[3] != 10
}

fn ipv4_is_6to4_relay_anycast(addr: Ipv4Addr) -> bool {
    addr.octets() == [192, 88, 99, 2]
}

fn ipv4_is_benchmarking(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 198 && (octets[1] & 0xfe) == 18
}

fn ipv4_is_reserved(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    (octets[0] & 0xf0) == 0xf0 && !addr.is_broadcast()
}

fn ipv6_is_non_global_upstream(addr: Ipv6Addr) -> bool {
    addr.is_unspecified()
        || addr.is_loopback()
        || addr.to_ipv4_mapped().is_some()
        || ipv6_is_non_global_translation(addr)
        || ipv6_is_discard_only(addr)
        || ipv6_is_dummy(addr)
        || ipv6_is_protocol_assignment(addr)
        || ipv6_is_6to4(addr)
        || ipv6_is_documentation(addr)
        || ipv6_is_srv6_sid(addr)
        || addr.is_unique_local()
        || addr.is_unicast_link_local()
        || addr.is_multicast()
}

fn ipv6_is_non_global_translation(addr: Ipv6Addr) -> bool {
    if matches!(addr.segments(), [0x64, 0xff9b, 1, _, _, _, _, _]) {
        return true;
    }

    if !matches!(addr.segments(), [0x64, 0xff9b, 0, 0, 0, 0, _, _]) {
        return false;
    }

    // The NAT64 well-known prefix exposes an IPv4 destination in its low 32 bits. Apply the same
    // public-Internet check so translation cannot disguise a private or otherwise special target.
    let octets = addr.octets();
    ipv4_is_non_global_upstream(Ipv4Addr::new(
        octets[12], octets[13], octets[14], octets[15],
    ))
}

fn ipv6_is_discard_only(addr: Ipv6Addr) -> bool {
    matches!(addr.segments(), [0x100, 0, 0, 0, _, _, _, _])
}

fn ipv6_is_dummy(addr: Ipv6Addr) -> bool {
    matches!(addr.segments(), [0x100, 0, 0, 1, _, _, _, _])
}

fn ipv6_is_protocol_assignment(addr: Ipv6Addr) -> bool {
    matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
        && !ipv6_is_protocol_assignment_exception(addr)
}

fn ipv6_is_protocol_assignment_exception(addr: Ipv6Addr) -> bool {
    let segments = addr.segments();
    let bits = u128::from_be_bytes(addr.octets());
    bits == 0x2001_0001_0000_0000_0000_0000_0000_0001
        || bits == 0x2001_0001_0000_0000_0000_0000_0000_0002
        || matches!(segments, [0x2001, 3, _, _, _, _, _, _])
        || matches!(segments, [0x2001, 4, 0x112, _, _, _, _, _])
        || matches!(segments, [0x2001, b, _, _, _, _, _, _] if (0x20..=0x3f).contains(&b))
}

fn ipv6_is_6to4(addr: Ipv6Addr) -> bool {
    matches!(addr.segments(), [0x2002, _, _, _, _, _, _, _])
}

fn ipv6_is_documentation(addr: Ipv6Addr) -> bool {
    matches!(
        addr.segments(),
        [0x2001, 0xdb8, ..] | [0x3fff, 0..=0x0fff, ..]
    )
}

fn ipv6_is_srv6_sid(addr: Ipv6Addr) -> bool {
    matches!(addr.segments(), [0x5f00, ..])
}

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
    fn canonicalizes_equivalent_ipv6_literals() {
        assert_eq!(
            canonicalize_ip_literal("2001:0DB8:0:0:0:0:0:10").as_deref(),
            Some("2001:db8::10")
        );
        assert_eq!(canonicalize_ip_literal("api.example.com"), None);
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
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 8))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 88, 99, 2))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 5))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 9))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 10))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 88, 99, 1))));
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
            "64:ff9b:1::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(is_private_ip(IpAddr::V6(
            "100::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(is_private_ip(IpAddr::V6(
            "100:0:0:1::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(is_private_ip(IpAddr::V6(
            "2002::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(is_private_ip(IpAddr::V6(
            "3fff::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(is_private_ip(IpAddr::V6(
            "ff02::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(!is_private_ip(IpAddr::V6(
            "2001:4860::1".parse::<Ipv6Addr>().unwrap()
        )));
    }

    #[test]
    fn filters_nat64_well_known_prefix_by_embedded_ipv4() {
        for address in [
            "64:ff9b::10.0.0.1",
            "64:ff9b::127.0.0.1",
            "64:ff9b::169.254.169.254",
        ] {
            assert!(is_private_ip(IpAddr::V6(
                address.parse::<Ipv6Addr>().unwrap()
            )));
        }

        assert!(!is_private_ip(IpAddr::V6(
            "64:ff9b::8.8.8.8".parse::<Ipv6Addr>().unwrap()
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
    fn blocks_ipv4_mapped_ipv6_even_when_embedded_ipv4_is_public() {
        let mapped = IpAddr::V6("::ffff:8.8.8.8".parse::<Ipv6Addr>().unwrap());
        assert!(is_private_ip(mapped));
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
