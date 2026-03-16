use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use http::{Method, Uri};

use crate::config::Scheme;
use crate::logging::AccessLogBuilder;
use crate::policy::matcher::Request as PolicyRequest;

/// Common representation of an HTTP request after parsing the start line / pseudo headers.
///
/// `path` preserves the raw request target bytes used for forwarding, logging,
/// and cache keying. `policy_path` is a separate canonical path used only for
/// policy evaluation.
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub method: Method,
    pub scheme: Scheme,
    pub authority: String,
    pub host: String,
    pub port: Option<u16>,
    /// Raw request path/query preserved for forwarding, logging, and cache keying.
    pub path: String,
    /// Canonical path used only for policy evaluation.
    pub policy_path: String,
    pub flow: Option<RequestFlowContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveMode {
    Bump,
    Tunnel,
}

impl EffectiveMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bump => "bump",
            Self::Tunnel => "tunnel",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestFlowContext {
    pub session_id: Arc<str>,
    pub outer_method: Arc<str>,
    pub effective_mode: EffectiveMode,
}

#[derive(Clone, Copy, Debug)]
enum Http1TargetMode {
    Proxy,
    OriginOnly,
}

/// Parse an HTTP/1.1 request target into a [`ParsedRequest`] with separate raw
/// forwarding and canonical policy paths.
pub fn parse_http1_request(
    method: Method,
    target: &str,
    host_header: Option<&str>,
    fallback_scheme: Scheme,
) -> Result<ParsedRequest> {
    parse_http1_request_with_mode(
        method,
        target,
        host_header,
        fallback_scheme,
        Http1TargetMode::Proxy,
    )
}

/// Parse an HTTP/1.1 request target that must be origin-form (no absolute-form).
pub(crate) fn parse_http1_request_origin_form(
    method: Method,
    target: &str,
    host_header: Option<&str>,
    fallback_scheme: Scheme,
) -> Result<ParsedRequest> {
    parse_http1_request_with_mode(
        method,
        target,
        host_header,
        fallback_scheme,
        Http1TargetMode::OriginOnly,
    )
}

fn parse_http1_request_with_mode(
    method: Method,
    target: &str,
    host_header: Option<&str>,
    fallback_scheme: Scheme,
    mode: Http1TargetMode,
) -> Result<ParsedRequest> {
    let uri: Uri = target
        .parse()
        .with_context(|| format!("invalid request target '{target}'"))?;

    if uri.scheme().is_some() {
        match mode {
            Http1TargetMode::Proxy => return parse_uri_request(method, &uri, fallback_scheme),
            Http1TargetMode::OriginOnly => {
                bail!(
                    "absolute-form request targets are not allowed over bumped HTTPS connections"
                );
            }
        }
    }

    if target == "*" {
        if method != Method::OPTIONS {
            bail!("asterisk-form request target is only valid for OPTIONS");
        }
    } else if !target.starts_with('/') {
        bail!("request target must be origin-form (start with '/')");
    }

    let host_header = host_header
        .ok_or_else(|| anyhow!("request missing Host header required for origin-form request"))?;
    let authority = host_header.trim().to_string();
    let (host, port) = parse_host_header(host_header)?;
    let port = port.or(Some(fallback_scheme.default_port()));
    let path = if target.is_empty() {
        "/".to_string()
    } else {
        target.to_string()
    };

    build_parsed_request(method, fallback_scheme, authority, host, port, path)
}

/// Parse a full URI (e.g. from HTTP proxy absolute-form or HTTP/2 pseudo
/// headers) into [`ParsedRequest`].
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

    build_parsed_request(method, scheme, authority.to_string(), host, port, path)
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
    if trimmed.chars().any(|c| c.is_whitespace()) {
        bail!("authority must not contain whitespace");
    }
    if trimmed.contains('@') {
        bail!("authority must not contain userinfo");
    }
    if trimmed.contains('/')
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains('\\')
    {
        bail!("authority must not contain path or query");
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
    pub fn as_policy_request(&self) -> PolicyRequest<'_> {
        PolicyRequest {
            method: &self.method,
            scheme: self.scheme,
            host: &self.host,
            port: self.port,
            path: self.policy_path(),
        }
    }

    pub fn access_log_builder(
        &self,
        peer: SocketAddr,
        path: impl Into<String>,
    ) -> AccessLogBuilder {
        AccessLogBuilder::new(peer)
            .apply_flow_context(self.flow.as_ref(), self.method.as_str())
            .method(self.method.as_str())
            .scheme(scheme_name(self.scheme))
            .host(self.host.clone())
            .path(path)
    }

    pub fn authority_host(&self) -> &str {
        &self.authority
    }

    /// Return the canonical path used for policy evaluation.
    pub fn policy_path(&self) -> &str {
        &self.policy_path
    }

    pub fn set_flow_context(&mut self, flow: RequestFlowContext) {
        self.flow = Some(flow);
    }

    pub fn flow_context(&self) -> Option<&RequestFlowContext> {
        self.flow.as_ref()
    }

    /// Build an absolute URI for cache keying that includes scheme, host, port, and path/query.
    pub fn cache_uri(&self) -> Result<Uri> {
        let port = self.port.unwrap_or_else(|| self.scheme.default_port());
        let authority = if self.host.contains(':') {
            format!("[{}]:{}", self.host, port)
        } else {
            format!("{}:{}", self.host, port)
        };
        Uri::builder()
            .scheme(scheme_name(self.scheme))
            .authority(authority.as_str())
            .path_and_query(self.path.as_str())
            .build()
            .with_context(|| {
                format!(
                    "failed to build cache URI for {}://{}",
                    scheme_name(self.scheme),
                    authority
                )
            })
    }
}

fn build_parsed_request(
    method: Method,
    scheme: Scheme,
    authority: String,
    host: String,
    port: Option<u16>,
    path: String,
) -> Result<ParsedRequest> {
    let policy_path = canonicalize_policy_path(&path)?;
    Ok(ParsedRequest {
        method,
        scheme,
        authority,
        host,
        port,
        path,
        policy_path,
        flow: None,
    })
}

fn canonicalize_policy_path(raw_path: &str) -> Result<String> {
    if raw_path == "*" {
        return Ok("*".to_string());
    }

    let path = raw_path.split('?').next().unwrap_or("/");
    if path.is_empty() {
        return Ok("/".to_string());
    }
    if !path.starts_with('/') {
        bail!("request path must be absolute");
    }

    validate_policy_path(path)?;
    Ok(remove_literal_dot_segments(path))
}

fn validate_policy_path(path: &str) -> Result<()> {
    for segment in path.split('/') {
        validate_policy_segment(segment)?;
    }
    Ok(())
}

fn validate_policy_segment(segment: &str) -> Result<()> {
    let bytes = segment.as_bytes();
    let mut idx = 0usize;
    let mut only_dots = true;
    let mut dot_count = 0usize;
    let mut used_encoded_dot = false;

    while idx < bytes.len() {
        match bytes[idx] {
            b'%' => {
                if idx + 2 >= bytes.len() {
                    bail!("request path contains invalid percent-escape");
                }
                let decoded = decode_hex_byte(bytes[idx + 1], bytes[idx + 2])?;
                if decoded == b'/' || decoded == b'\\' {
                    bail!("request path must not contain encoded path separators");
                }
                if decoded.is_ascii_control() || decoded == 0x7f {
                    bail!("request path must not contain encoded control characters");
                }
                if decoded == b'.' {
                    used_encoded_dot = true;
                    dot_count += 1;
                } else {
                    only_dots = false;
                }
                idx += 3;
            }
            b'\\' => bail!("request path must not contain backslashes"),
            byte if byte.is_ascii_control() || byte == 0x7f => {
                bail!("request path must not contain control characters");
            }
            b'.' => {
                dot_count += 1;
                idx += 1;
            }
            _ => {
                only_dots = false;
                idx += 1;
            }
        }
    }

    if used_encoded_dot && only_dots && (dot_count == 1 || dot_count == 2) {
        bail!("request path must not contain encoded dot segments");
    }

    Ok(())
}

fn decode_hex_byte(high: u8, low: u8) -> Result<u8> {
    let high = decode_hex_nibble(high)?;
    let low = decode_hex_nibble(low)?;
    Ok((high << 4) | low)
}

fn decode_hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("request path contains invalid percent-escape"),
    }
}

fn remove_literal_dot_segments(path: &str) -> String {
    let mut input = path;
    let mut output = String::new();

    while !input.is_empty() {
        if let Some(rest) = input.strip_prefix("../") {
            input = rest;
            continue;
        }
        if let Some(rest) = input.strip_prefix("./") {
            input = rest;
            continue;
        }
        if input.starts_with("/./") {
            input = &input[2..];
            continue;
        }
        if input == "/." {
            input = "/";
            continue;
        }
        if input.starts_with("/../") {
            input = &input[3..];
            remove_last_path_segment(&mut output);
            continue;
        }
        if input == "/.." {
            input = "/";
            remove_last_path_segment(&mut output);
            continue;
        }
        if input == "." || input == ".." {
            input = "";
            continue;
        }

        let next = next_path_segment_end(input);
        output.push_str(&input[..next]);
        input = &input[next..];
    }

    if output.is_empty() {
        "/".to_string()
    } else {
        output
    }
}

fn next_path_segment_end(input: &str) -> usize {
    if let Some(rest) = input.strip_prefix('/') {
        match rest.find('/') {
            Some(offset) => offset + 1,
            None => input.len(),
        }
    } else {
        input.find('/').unwrap_or(input.len())
    }
}

fn remove_last_path_segment(output: &mut String) {
    if output.is_empty() {
        return;
    }
    if let Some(idx) = output.rfind('/') {
        output.truncate(idx);
    } else {
        output.clear();
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
        assert_eq!(parsed.authority_host(), "example.com");
        assert_eq!(parsed.policy_path(), "/resource");
        Ok(())
    }

    #[test]
    fn parse_http1_request_preserves_explicit_default_port_in_authority() -> Result<()> {
        let parsed = parse_http1_request(
            Method::GET,
            "/resource",
            Some("example.com:443"),
            Scheme::Https,
        )?;
        assert_eq!(parsed.port, Some(443));
        assert_eq!(parsed.authority_host(), "example.com:443");
        Ok(())
    }

    #[test]
    fn parse_http1_request_origin_form_rejects_absolute_form() {
        let err = parse_http1_request_origin_form(
            Method::GET,
            "http://example.com/resource",
            Some("example.com"),
            Scheme::Https,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("absolute-form"),
            "unexpected error: {err:?}"
        );
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
    fn parse_uri_request_preserves_explicit_default_port_in_authority() -> Result<()> {
        let uri: Uri = "https://example.com:443/upload".parse()?;
        let parsed = parse_uri_request(Method::GET, &uri, Scheme::Https)?;
        assert_eq!(parsed.port, Some(443));
        assert_eq!(parsed.authority_host(), "example.com:443");
        Ok(())
    }

    #[test]
    fn authority_host_wraps_ipv6_literals() -> Result<()> {
        let uri: Uri = "https://[fd00::1]:8443/".parse()?;
        let parsed = parse_uri_request(Method::GET, &uri, Scheme::Https)?;
        assert_eq!(parsed.authority_host(), "[fd00::1]:8443");
        Ok(())
    }

    #[test]
    fn reject_non_origin_form_target() {
        let err = parse_http1_request(
            Method::GET,
            "example.com:443",
            Some("example.com"),
            Scheme::Https,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("origin-form"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn allow_options_asterisk_form() -> Result<()> {
        let parsed = parse_http1_request(Method::OPTIONS, "*", Some("example.com"), Scheme::Http)?;
        assert_eq!(parsed.path, "*");
        assert_eq!(parsed.policy_path(), "*");
        Ok(())
    }

    #[test]
    fn reject_asterisk_form_for_non_options() {
        let err =
            parse_http1_request(Method::GET, "*", Some("example.com"), Scheme::Http).unwrap_err();
        assert!(
            err.to_string().contains("asterisk-form"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_host_header_rejects_userinfo() {
        let err = parse_host_header("user@example.com").unwrap_err();
        assert!(
            err.to_string().contains("userinfo"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_host_header_rejects_path() {
        let err = parse_host_header("example.com/path").unwrap_err();
        assert!(
            err.to_string().contains("path or query"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_request_keeps_raw_path_and_normalizes_policy_path() -> Result<()> {
        let parsed = parse_http1_request(
            Method::GET,
            "/public/../admin/./panel?token=abc",
            Some("example.com"),
            Scheme::Https,
        )?;
        assert_eq!(parsed.path, "/public/../admin/./panel?token=abc");
        assert_eq!(parsed.policy_path(), "/admin/panel");
        Ok(())
    }

    #[test]
    fn as_policy_request_uses_canonical_policy_path() -> Result<()> {
        let parsed = parse_http1_request(
            Method::GET,
            "/public/../admin/./panel?token=abc",
            Some("example.com"),
            Scheme::Https,
        )?;

        let request = parsed.as_policy_request();

        assert_eq!(*request.method, Method::GET);
        assert_eq!(request.scheme, Scheme::Https);
        assert_eq!(request.host, "example.com");
        assert_eq!(request.port, Some(443));
        assert_eq!(request.path, "/admin/panel");
        Ok(())
    }

    #[test]
    fn parse_request_rejects_encoded_dot_segments() {
        let err = parse_http1_request(
            Method::GET,
            "/public/%2e%2e/admin",
            Some("example.com"),
            Scheme::Https,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("encoded dot segments"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_request_rejects_encoded_path_separator() {
        let err = parse_http1_request(
            Method::GET,
            "/public%2fadmin",
            Some("example.com"),
            Scheme::Https,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("encoded path separators"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_request_rejects_backslash_in_path() {
        let err = parse_http1_request(
            Method::GET,
            "/public\\admin",
            Some("example.com"),
            Scheme::Https,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("backslashes"),
            "unexpected error: {err:?}"
        );
    }
}
