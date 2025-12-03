use anyhow::{Context, Result};

use crate::proxy::request::parse_host_header;

#[derive(Clone, Debug)]
pub struct ConnectTarget {
    pub host: String,
    pub port: u16,
}

pub fn parse_connect_target(target: &str, host_header: Option<&str>) -> Result<ConnectTarget> {
    match parse_host_port(target) {
        Ok(parsed) => Ok(parsed),
        Err(first_err) => {
            if let Some(host) = host_header {
                parse_host_port(host).with_context(|| {
                    format!(
                        "failed to parse CONNECT target '{}'; Host fallback '{}' also invalid",
                        target, host
                    )
                })
            } else {
                Err(first_err.context("CONNECT request missing Host header fallback"))
            }
        }
    }
}

fn parse_host_port(value: &str) -> Result<ConnectTarget> {
    let (host, port) = parse_host_header(value)?;
    let port = port.unwrap_or(443);
    Ok(ConnectTarget { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_direct_target() {
        let parsed = parse_connect_target("example.com:8443", None).expect("parse target");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 8443);
    }

    #[test]
    fn falls_back_to_host_header() {
        let parsed = parse_connect_target("", Some("fallback.test:9443")).expect("fallback parse");
        assert_eq!(parsed.host, "fallback.test");
        assert_eq!(parsed.port, 9443);
    }

    #[test]
    fn errors_when_both_invalid() {
        let err = parse_connect_target("", None).unwrap_err();
        assert!(
            err.to_string().contains("missing Host header fallback"),
            "unexpected error: {err:?}"
        );
    }
}
