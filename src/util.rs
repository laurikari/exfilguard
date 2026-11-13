use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::LazyLock,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use ipnet::{IpNet, Ipv6Net};
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

/// Reject nonstandard IPv4 spellings recognized by the system resolver.
/// Call this on the host spelling that will actually be passed to the resolver.
pub(crate) fn reject_legacy_ipv4(host: &str) -> Result<()> {
    use nix::libc;

    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let host = std::ffi::CString::new(host).context("host contains a NUL byte")?;
    // SAFETY: addrinfo is a C struct whose unspecified hints must be zero/null.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_INET;
    hints.ai_socktype = libc::SOCK_STREAM;
    hints.ai_flags = libc::AI_NUMERICHOST;
    let mut result = std::ptr::null_mut();
    // SAFETY: all pointers are valid for this call. AI_NUMERICHOST prohibits DNS
    // lookups, so even ordinary hostnames are checked locally and synchronously.
    let status = unsafe { libc::getaddrinfo(host.as_ptr(), std::ptr::null(), &hints, &mut result) };
    match status {
        0 => {
            // SAFETY: a successful getaddrinfo call owns this result list.
            unsafe { libc::freeaddrinfo(result) };
            bail!("IPv4 addresses must use four decimal components without leading zeros");
        }
        libc::EAI_NONAME => Ok(()),
        _ => bail!("numeric host validation failed (resolver error {status})"),
    }
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
/// IPv4 excludes non-public special-purpose ranges. IPv6 requires an allocated public prefix,
/// with the well-known NAT64 prefix checked against its embedded IPv4 destination. Reserved and
/// unallocated space must not become implicitly reachable through an allowed hostname.
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
        || ipv4_is_deprecated_relay(addr)
        || addr.is_documentation()
        || ipv4_is_benchmarking(addr)
        || ipv4_is_reserved(addr)
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

fn ipv4_is_deprecated_relay(addr: Ipv4Addr) -> bool {
    matches!(addr.octets(), [192, 88, 99, _])
}

fn ipv4_is_benchmarking(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 198 && (octets[1] & 0xfe) == 18
}

fn ipv4_is_reserved(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    (octets[0] & 0xf0) == 0xf0
}

// IANA allocations checked 2026-11-11. Keep this list explicit so reserved gaps inside 2000::/3
// cannot pass the guard. Newly allocated ranges need an update or a configured CIDR exception.
// https://www.iana.org/assignments/ipv6-unicast-address-assignments/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
static PUBLIC_IPV6_NETWORKS: LazyLock<Vec<Ipv6Net>> = LazyLock::new(|| {
    [
        // Public IP locators within 2001::/23. ORCHID/DRIP identifiers are not locators
        // (RFC 7343 and RFC 9374), so they require explicit exceptions too.
        "2001:1::1/128",
        "2001:1::2/128",
        "2001:1::3/128",
        "2001:3::/32",
        "2001:4:112::/48",
        // Public unicast allocations to regional Internet registries.
        "2001:200::/23",
        "2001:400::/23",
        "2001:600::/23",
        "2001:800::/22",
        "2001:c00::/23",
        "2001:e00::/23",
        "2001:1200::/23",
        "2001:1400::/22",
        "2001:1800::/23",
        "2001:1a00::/23",
        "2001:1c00::/22",
        "2001:2000::/19",
        "2001:4000::/23",
        "2001:4200::/23",
        "2001:4400::/23",
        "2001:4600::/23",
        "2001:4800::/23",
        "2001:4a00::/23",
        "2001:4c00::/23",
        "2001:5000::/20",
        "2001:8000::/19",
        "2001:a000::/20",
        "2001:b000::/20",
        "2003::/18",
        "2400::/12",
        "2410::/12",
        "2600::/12",
        "2610::/23",
        "2620::/23",
        "2630::/12",
        "2800::/12",
        "2a00::/12",
        "2a10::/12",
        "2c00::/12",
    ]
    .into_iter()
    .map(|cidr| cidr.parse().expect("valid public IPv6 allocation"))
    .collect()
});

fn ipv6_is_non_global_upstream(addr: Ipv6Addr) -> bool {
    if matches!(addr.segments(), [0x64, 0xff9b, 0, 0, 0, 0, _, _]) {
        // NAT64 must not disguise a private or reserved IPv4 destination.
        let octets = addr.octets();
        return ipv4_is_non_global_upstream(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }

    // Documentation space is carved out of an otherwise public RIR allocation.
    matches!(addr.segments(), [0x2001, 0xdb8, ..])
        || !PUBLIC_IPV6_NETWORKS.iter().any(|net| net.contains(&addr))
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
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 88, 99, 1))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn blocks_reserved_and_retired_ipv4_space() {
        for address in [
            "0.255.255.255",
            "192.88.99.0",
            "192.88.99.255",
            "240.0.0.0",
            "255.255.255.254",
            "255.255.255.255",
        ] {
            assert!(is_private_ip(address.parse().unwrap()), "{address}");
        }
        for address in [
            "192.88.98.255",
            "192.88.100.0",
            "192.31.196.1",
            "192.52.193.1",
            "192.175.48.1",
        ] {
            assert!(!is_private_ip(address.parse().unwrap()), "{address}");
        }
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
    fn blocks_deprecated_site_local_ipv6() {
        for address in [
            "fec0::",
            "fec0::1",
            "fed0::1234",
            "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(is_private_ip(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn blocks_reserved_ipv6_space() {
        for address in [
            "::2",
            "::192.168.1.1",
            "::ffff:0:192.168.1.1",
            "100:0:0:2::1",
            "200::1",
            "400::1",
            "800::1",
            "1000::1",
            "2000::1",
            "2004::1",
            "2d00::1",
            "2e00::1",
            "3000::1",
            "3ffe::1",
            "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "4000::1",
            "5f00::1",
            "6000::1",
            "8000::1",
            "a000::1",
            "c000::1",
            "e000::1",
            "f000::1",
            "f800::1",
            "fe00::1",
        ] {
            assert!(is_private_ip(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn public_ipv6_allocations_preserve_boundaries_and_reserved_gaps() {
        for (address, public) in [
            ("2001:1::1", true),
            ("2001:1::2", true),
            ("2001:1::3", true),
            ("2001:1::4", false),
            ("2001:3::1", true),
            ("2001:4:112::1", true),
            ("2001:20::1", false),
            ("2001:2f:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:30::1", false),
            ("2001:3f:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:40::1", false),
            ("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:200::", true),
            ("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:db8::", false),
            ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:db9::", true),
            ("2001:fff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:1000::", false),
            ("2001:11ff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:1200::", true),
            ("2001:4dff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:4e00::", false),
            ("2001:4fff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:5000::", true),
            ("2001:5fff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:6000::", false),
            ("2001:7fff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:8000::", true),
            ("2001:bfff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:c000::", false),
            ("2003:3fff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2003:4000::", false),
            ("2410::1", true),
            ("241f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2420::", false),
            ("2606:4700:4700::1111", true),
            ("2610:1ff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2610:200::", false),
            ("2611::", false),
            ("2620:1ff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2620:200::", false),
            ("2621::", false),
            ("263f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2640::", false),
            ("2800::1", true),
            ("2810::", false),
            ("2a10::1", true),
            ("2a20::", false),
            ("2c00::1", true),
            ("2c10::", false),
        ] {
            assert_eq!(
                !is_private_ip(address.parse().unwrap()),
                public,
                "{address}"
            );
        }
    }

    #[test]
    fn filters_nat64_well_known_prefix_by_embedded_ipv4() {
        for address in [
            "64:ff9b::10.0.0.1",
            "64:ff9b::127.0.0.1",
            "64:ff9b::169.254.169.254",
            "64:ff9b::192.88.99.1",
            "64:ff9b::240.0.0.1",
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
