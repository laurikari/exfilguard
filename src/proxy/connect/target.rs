use anyhow::{Context, Result, bail};

use crate::proxy::request::parse_host_header;

#[derive(Clone, Debug)]
pub struct ConnectTarget {
    pub host: String,
    pub port: u16,
}

pub fn parse_connect_target(target: &str) -> Result<ConnectTarget> {
    parse_host_port(target).with_context(|| format!("failed to parse CONNECT target '{target}'"))
}

fn parse_host_port(value: &str) -> Result<ConnectTarget> {
    let (host, port) = parse_host_header(value)?;
    let Some(port) = port else {
        bail!("CONNECT target must include an explicit port");
    };
    Ok(ConnectTarget { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error_chain_contains(err: &anyhow::Error, needle: &str) -> bool {
        err.chain().any(|cause| cause.to_string().contains(needle))
    }

    #[test]
    fn parses_direct_target() {
        let parsed = parse_connect_target("example.com:8443").expect("parse target");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 8443);
    }

    #[test]
    fn rejects_empty_target() {
        let err = parse_connect_target("").unwrap_err();
        assert!(
            error_chain_contains(&err, "failed to parse CONNECT target"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn rejects_target_without_port() {
        let err = parse_connect_target("example.com").unwrap_err();
        assert!(
            error_chain_contains(&err, "explicit port"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn does_not_fall_back_to_host_header() {
        let err = parse_connect_target("").unwrap_err();
        assert!(
            error_chain_contains(&err, "failed to parse CONNECT target"),
            "unexpected error: {err:?}"
        );
    }
}
