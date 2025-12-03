use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow, bail};
use http::{Method, Uri};

use crate::config::Scheme;
use crate::logging::AccessLogBuilder;

/// Common representation of an HTTP request after parsing the start line / pseudo headers.
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub method: Method,
    pub scheme: Scheme,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
}

/// Parse an HTTP/1.1 request target into a normalized [`ParsedRequest`].
pub fn parse_http1_request(
    method: Method,
    target: &str,
    host_header: Option<&str>,
    fallback_scheme: Scheme,
) -> Result<ParsedRequest> {
    let uri: Uri = target
        .parse()
        .with_context(|| format!("invalid request target '{target}'"))?;

    if uri.scheme().is_some() {
        return parse_uri_request(method, &uri, fallback_scheme);
    }

    let host_header = host_header
        .ok_or_else(|| anyhow!("request missing Host header required for origin-form request"))?;
    let (host, port) = parse_host_header(host_header)?;
    let port = port.or(Some(fallback_scheme.default_port()));
    let path = if target.is_empty() {
        "/".to_string()
    } else {
        target.to_string()
    };

    Ok(ParsedRequest {
        method,
        scheme: fallback_scheme,
        host,
        port,
        path,
    })
}

/// Parse a full URI (e.g. from CONNECT or HTTP/2 pseudo headers) into [`ParsedRequest`].
pub fn parse_uri_request(
    method: Method,
    uri: &Uri,
    default_scheme: Scheme,
) -> Result<ParsedRequest> {
    let scheme = match uri.scheme_str() {
        Some(value) => parse_scheme(value)?,
        None => default_scheme,
    };
    let authority = uri
        .authority()
        .map(|auth| auth.as_str())
        .ok_or_else(|| anyhow!("request missing authority"))?;
    let (host, port) = parse_host_header(authority)?;
    let port = port.or(Some(scheme.default_port()));
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    Ok(ParsedRequest {
        method,
        scheme,
        host,
        port,
        path,
    })
}

/// Return a path with query parameters removed for logging purposes.
pub fn redacted_path(path: &str) -> String {
    path.split('?').next().unwrap_or("/").to_string()
}

/// Parse the HTTP scheme into the internal enum.
pub fn parse_scheme(value: &str) -> Result<Scheme> {
    match value {
        "http" | "HTTP" => Ok(Scheme::Http),
        "https" | "HTTPS" => Ok(Scheme::Https),
        other => bail!("unsupported scheme '{other}'"),
    }
}

/// Parse a Host / :authority header value into a normalized host + port.
pub fn parse_host_header(value: &str) -> Result<(String, Option<u16>)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("empty Host header");
    }
    let uri: Uri = format!("http://{trimmed}")
        .parse()
        .with_context(|| format!("invalid Host header '{trimmed}'"))?;
    let host = uri
        .host()
        .ok_or_else(|| anyhow!("Host header missing hostname"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    Ok((host, uri.port_u16()))
}

/// Helper for converting [`Scheme`] into a displayable string.
pub fn scheme_name(scheme: Scheme) -> &'static str {
    match scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    }
}

impl ParsedRequest {
    pub fn access_log_builder(
        &self,
        peer: SocketAddr,
        path: impl Into<String>,
    ) -> AccessLogBuilder {
        AccessLogBuilder::new(peer)
            .method(self.method.as_str())
            .scheme(scheme_name(self.scheme))
            .host(self.host.clone())
            .path(path)
    }

    pub fn authority_host(&self) -> String {
        let mut host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if let Some(port) = self.port.filter(|port| *port != self.scheme.default_port()) {
            host.push(':');
            host.push_str(&port.to_string());
        }
        host
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    #[test]
    fn parse_http1_request_fills_default_port() -> Result<()> {
        let parsed =
            parse_http1_request(Method::GET, "/resource", Some("example.com"), Scheme::Https)?;
        assert_eq!(parsed.port, Some(443));
        Ok(())
    }

    #[test]
    fn parse_uri_request_normalizes_ipv6_host() -> Result<()> {
        let uri: Uri = "https://[2001:db8::10]/".parse()?;
        let parsed = parse_uri_request(Method::GET, &uri, Scheme::Https)?;
        assert_eq!(parsed.host, "2001:db8::10");
        assert_eq!(parsed.port, Some(443));
        assert_eq!(parsed.authority_host(), "[2001:db8::10]");
        Ok(())
    }

    #[test]
    fn authority_host_wraps_ipv6_literals() -> Result<()> {
        let uri: Uri = "https://[fd00::1]:8443/".parse()?;
        let parsed = parse_uri_request(Method::GET, &uri, Scheme::Https)?;
        assert_eq!(parsed.authority_host(), "[fd00::1]:8443");
        Ok(())
    }
}
