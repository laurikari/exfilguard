use std::net::SocketAddr;

use anyhow::Result;
use http::StatusCode;

use crate::logging::AccessLogBuilder;
use crate::proxy::{
    forward_error::{ForwardErrorKind, classify_forward_error, log_forward_error},
    policy_eval::{AllowDecision, DenyDecision, RequestLogContext},
};

#[derive(Clone, Copy)]
pub struct ForwardErrorSpec {
    pub status: StatusCode,
    pub body_http1: &'static [u8],
    pub body_http2: &'static str,
    pub decision: &'static str,
    pub extra_client_bytes: u64,
}

pub fn forward_error_spec(kind: &ForwardErrorKind<'_>) -> ForwardErrorSpec {
    match kind {
        ForwardErrorKind::BodyTooLarge(body) => ForwardErrorSpec {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            body_http1: b"request body exceeds configured limit\r\n",
            body_http2: "request body exceeds configured limit",
            decision: "DENY",
            extra_client_bytes: body.bytes_read,
        },
        ForwardErrorKind::PrivateAddress(_) => ForwardErrorSpec {
            status: StatusCode::FORBIDDEN,
            body_http1: b"request blocked by policy\r\n",
            body_http2: "request blocked by policy",
            decision: "DENY",
            extra_client_bytes: 0,
        },
        ForwardErrorKind::MisdirectedRequest(_) => ForwardErrorSpec {
            status: StatusCode::MISDIRECTED_REQUEST,
            body_http1: b"misdirected request\r\n",
            body_http2: "misdirected request",
            decision: "ERROR",
            extra_client_bytes: 0,
        },
        ForwardErrorKind::Other => ForwardErrorSpec {
            status: StatusCode::BAD_GATEWAY,
            body_http1: b"upstream request failed\r\n",
            body_http2: "upstream request failed",
            decision: "ERROR",
            extra_client_bytes: 0,
        },
    }
}

pub fn forward_error_log_builder(
    builder: AccessLogBuilder,
    allow: &AllowDecision,
    spec: &ForwardErrorSpec,
) -> AccessLogBuilder {
    builder
        .client(allow.client.as_ref())
        .decision(spec.decision)
        .policy(allow.policy.as_ref())
        .rule(allow.rule.as_ref())
        .inspect_payload(allow.inspect_payload)
}

/// Indicates whether forwarding completed successfully or the protocol already
/// responded to the client following an upstream failure.
pub enum ForwardOutcome<T, E> {
    Completed(T),
    Responded(E),
}

pub struct ForwardErrorContext<'a> {
    pub spec: ForwardErrorSpec,
    pub log: RequestLogContext<'a>,
    pub decision: AllowDecision,
}

/// Shared helper for responding to forwarding failures after a policy ALLOW decision.
pub async fn handle_forward_result<'a, T>(
    decision: &AllowDecision,
    log: RequestLogContext<'a>,
    result: anyhow::Result<T>,
    peer: SocketAddr,
    host: &str,
) -> Result<ForwardOutcome<T, ForwardErrorContext<'a>>> {
    match result {
        Ok(value) => Ok(ForwardOutcome::Completed(value)),
        Err(err) => {
            let kind = classify_forward_error(&err);
            let kind_label = match kind {
                ForwardErrorKind::BodyTooLarge(_) => "body_too_large",
                ForwardErrorKind::PrivateAddress(_) => "private_address",
                ForwardErrorKind::MisdirectedRequest(_) => "misdirected_request",
                ForwardErrorKind::Other => "other",
            };
            crate::metrics::record_upstream_error(kind_label);
            log_forward_error(&kind, peer, host, &err);
            let spec = forward_error_spec(&kind);
            Ok(ForwardOutcome::Responded(ForwardErrorContext {
                spec,
                log,
                decision: decision.clone(),
            }))
        }
    }
}

pub struct PolicyDenySpec<'a> {
    pub status: StatusCode,
    pub reason: Option<&'a str>,
    pub body_http1: &'a [u8],
    pub body_http2: &'a str,
}

pub fn policy_deny_spec<'a>(decision: &'a DenyDecision) -> PolicyDenySpec<'a> {
    let body = decision.body.as_deref().unwrap_or("");
    PolicyDenySpec {
        status: decision.status,
        reason: decision.reason.as_deref(),
        body_http1: body.as_bytes(),
        body_http2: body,
    }
}

pub fn decorate_policy_deny_log(
    builder: AccessLogBuilder,
    deny: &DenyDecision,
) -> AccessLogBuilder {
    builder
        .client(deny.client.as_ref())
        .decision("DENY")
        .policy(deny.policy.as_ref())
        .rule(deny.rule.as_ref())
}

pub struct PolicyDenyResponse<'a> {
    pub spec: PolicyDenySpec<'a>,
    pub log_builder: AccessLogBuilder,
}

pub fn build_policy_deny_response<'a>(
    log: &RequestLogContext<'a>,
    decision: &'a DenyDecision,
) -> PolicyDenyResponse<'a> {
    PolicyDenyResponse {
        spec: policy_deny_spec(decision),
        log_builder: decorate_policy_deny_log(log.access_log_builder(), decision),
    }
}

pub fn build_default_deny_response<'a>(log: &RequestLogContext<'a>) -> PolicyDenyResponse<'a> {
    PolicyDenyResponse {
        spec: default_deny_spec(),
        log_builder: decorate_default_deny_log(log.access_log_builder()),
    }
}

pub const DEFAULT_DENY_BODY_HTTP1: &[u8] = b"request blocked by policy\r\n";
pub const DEFAULT_DENY_BODY_HTTP2: &str = "request blocked by policy";

pub fn default_deny_spec() -> PolicyDenySpec<'static> {
    PolicyDenySpec {
        status: StatusCode::FORBIDDEN,
        reason: None,
        body_http1: DEFAULT_DENY_BODY_HTTP1,
        body_http2: DEFAULT_DENY_BODY_HTTP2,
    }
}

pub fn decorate_default_deny_log(builder: AccessLogBuilder) -> AccessLogBuilder {
    builder.decision("DENY")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Scheme,
        proxy::{
            forward_error::MisdirectedRequest,
            policy_eval::{AllowDecision, DenyDecision},
            request::ParsedRequest,
        },
    };
    use anyhow::{Result, anyhow};
    use http::Method;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    fn sample_decision() -> AllowDecision {
        AllowDecision {
            client: Arc::<str>::from("client"),
            policy: Arc::<str>::from("policy"),
            rule: Arc::<str>::from("rule"),
            inspect_payload: true,
            allow_private_connect: false,
            cache: None,
        }
    }

    fn sample_deny() -> DenyDecision {
        DenyDecision {
            client: Arc::<str>::from("client"),
            policy: Arc::<str>::from("policy"),
            rule: Arc::<str>::from("rule"),
            status: StatusCode::FORBIDDEN,
            reason: Some(Arc::<str>::from("Policy Blocked")),
            body: Some(Arc::<str>::from("blocked")),
        }
    }

    fn sample_request() -> ParsedRequest {
        ParsedRequest {
            method: Method::GET,
            scheme: Scheme::Https,
            host: "example.com".to_string(),
            port: None,
            path: "/resource".to_string(),
        }
    }

    fn sample_log(parsed: &ParsedRequest) -> RequestLogContext<'_> {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        RequestLogContext::new(peer, parsed, false)
    }

    #[tokio::test]
    async fn forward_result_passes_success_through() -> Result<()> {
        let decision = sample_decision();
        let parsed = sample_request();
        let log = sample_log(&parsed);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let outcome = handle_forward_result(
            &decision,
            log,
            Ok::<_, anyhow::Error>(()),
            peer,
            parsed.host.as_str(),
        )
        .await?;

        assert!(matches!(outcome, ForwardOutcome::Completed(())));
        Ok(())
    }

    #[tokio::test]
    async fn forward_result_invokes_responder_on_error() -> Result<()> {
        let decision = sample_decision();
        let parsed = sample_request();
        let log = sample_log(&parsed);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9090);

        let outcome = handle_forward_result(
            &decision,
            log,
            Err::<(), _>(anyhow!("boom")),
            peer,
            parsed.host.as_str(),
        )
        .await?;

        if let ForwardOutcome::Responded(ctx) = outcome {
            assert_eq!(ctx.spec.status, StatusCode::BAD_GATEWAY);
            assert_eq!(ctx.log.logged_path(), "/resource");
            assert_eq!(ctx.decision.rule.as_ref(), "rule");
        } else {
            panic!("expected responded outcome");
        }
        Ok(())
    }

    #[test]
    fn builds_policy_deny_spec() {
        let deny = sample_deny();
        let spec = policy_deny_spec(&deny);
        assert_eq!(spec.status, StatusCode::FORBIDDEN);
        assert_eq!(spec.reason, Some("Policy Blocked"));
        assert_eq!(spec.body_http2, "blocked");
        assert_eq!(spec.body_http1, b"blocked");
    }

    #[test]
    fn default_deny_spec_uses_constants() {
        let spec = default_deny_spec();
        assert_eq!(spec.status, StatusCode::FORBIDDEN);
        assert!(spec.reason.is_none());
        assert_eq!(spec.body_http2, DEFAULT_DENY_BODY_HTTP2);
        assert_eq!(spec.body_http1, DEFAULT_DENY_BODY_HTTP1);
    }

    #[test]
    fn misdirected_request_maps_to_421() {
        let err = anyhow::Error::new(MisdirectedRequest::new(
            "upstream.test".to_string(),
            443,
            "requested.test".to_string(),
            8443,
        ));
        let kind = classify_forward_error(&err);
        let spec = forward_error_spec(&kind);
        assert_eq!(spec.status, StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(spec.body_http2, "misdirected request");
        assert_eq!(spec.body_http1, b"misdirected request\r\n");
    }
}
