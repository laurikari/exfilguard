use std::{net::SocketAddr, sync::Arc};

use http::StatusCode;
use tracing::{Level, debug, error, info, trace, warn};

macro_rules! log_with_level {
    ($level:expr, $($tt:tt)*) => {
        match $level {
            Level::ERROR => error!($($tt)*),
            Level::WARN => warn!($($tt)*),
            Level::INFO => info!($($tt)*),
            Level::DEBUG => debug!($($tt)*),
            Level::TRACE => trace!($($tt)*),
        }
    };
}

use crate::{
    logging::AccessLogBuilder,
    policy::{
        Decision,
        matcher::{EvaluationResult, PolicySnapshot, Request},
        model::CompiledCacheConfig,
    },
    proxy::request::{ParsedRequest, redacted_path, scheme_name},
};

#[derive(Clone, Copy)]
pub struct PolicyLogConfig {
    pub allow_level: Level,
    pub deny_level: Level,
    pub default_level: Level,
    pub allow_message: &'static str,
    pub deny_message: &'static str,
    pub default_message: &'static str,
}

impl PolicyLogConfig {
    pub const fn http1() -> Self {
        Self {
            allow_level: Level::INFO,
            deny_level: Level::INFO,
            default_level: Level::WARN,
            allow_message: "policy allow decision",
            deny_message: "policy deny decision",
            default_message: "no matching policy decision; default deny",
        }
    }

    pub const fn connect_tunnel() -> Self {
        Self {
            allow_level: Level::INFO,
            deny_level: Level::INFO,
            default_level: Level::DEBUG,
            allow_message: "policy allow decision (CONNECT tunnel)",
            deny_message: "policy deny decision (CONNECT tunnel)",
            default_message: "no matching CONNECT tunnel policy; checking TLS bump preflight",
        }
    }
}

pub enum PolicyOutcome<'a> {
    Allow(AllowOutcome<'a>),
    Deny(DenyOutcome<'a>),
    DefaultDeny(DefaultDenyOutcome<'a>),
}

pub struct AllowOutcome<'a> {
    pub decision: AllowDecision,
    pub log: RequestLogContext<'a>,
}

pub struct DenyOutcome<'a> {
    pub decision: DenyDecision,
    pub log: RequestLogContext<'a>,
}

pub struct DefaultDenyOutcome<'a> {
    pub log: RequestLogContext<'a>,
}

#[derive(Clone)]
pub struct RequestLogContext<'a> {
    peer: SocketAddr,
    parsed: &'a ParsedRequest,
    logged_path: String,
}

impl<'a> RequestLogContext<'a> {
    pub fn new(peer: SocketAddr, parsed: &'a ParsedRequest, log_queries: bool) -> Self {
        let logged_path = if log_queries {
            parsed.path.clone()
        } else {
            redacted_path(&parsed.path)
        };
        Self {
            peer,
            parsed,
            logged_path,
        }
    }

    pub fn logged_path(&self) -> &str {
        &self.logged_path
    }

    pub fn access_log_builder(&self) -> AccessLogBuilder {
        self.parsed
            .access_log_builder(self.peer, self.logged_path.clone())
    }
}

pub fn evaluate_request<'a>(
    peer: SocketAddr,
    parsed: &'a ParsedRequest,
    snapshot: &'a PolicySnapshot,
    log_queries: bool,
    log_config: PolicyLogConfig,
) -> PolicyOutcome<'a> {
    let log_ctx = RequestLogContext::new(peer, parsed, log_queries);
    let policy_request = Request {
        method: &parsed.method,
        scheme: parsed.scheme,
        host: &parsed.host,
        port: parsed.port,
        path: parsed.policy_path(),
    };

    match snapshot.evaluate_request(peer.ip(), &policy_request) {
        Some(result) => match into_decision(result) {
            PolicyOutcomeInternal::Allow(decision) => {
                crate::metrics::record_rule_hit(decision.rule.as_ref());
                log_policy_allow(
                    log_config.allow_level,
                    log_config.allow_message,
                    peer,
                    parsed,
                    log_ctx.logged_path(),
                    &decision,
                );
                PolicyOutcome::Allow(AllowOutcome {
                    decision,
                    log: log_ctx,
                })
            }
            PolicyOutcomeInternal::Deny(decision) => {
                crate::metrics::record_rule_hit(decision.rule.as_ref());
                log_policy_deny(
                    log_config.deny_level,
                    log_config.deny_message,
                    peer,
                    parsed,
                    log_ctx.logged_path(),
                    &decision,
                );
                PolicyOutcome::Deny(DenyOutcome {
                    decision,
                    log: log_ctx,
                })
            }
        },
        None => {
            log_policy_default(
                log_config.default_level,
                log_config.default_message,
                peer,
                parsed,
                log_ctx.logged_path(),
            );
            PolicyOutcome::DefaultDeny(DefaultDenyOutcome { log: log_ctx })
        }
    }
}

enum PolicyOutcomeInternal {
    Allow(AllowDecision),
    Deny(DenyDecision),
}

fn into_decision(result: EvaluationResult) -> PolicyOutcomeInternal {
    let EvaluationResult { client, decision } = result;
    match decision {
        Decision::Allow {
            policy,
            rule,
            https_mode,
            cache,
        } => PolicyOutcomeInternal::Allow(AllowDecision {
            client,
            policy,
            rule,
            https_mode,
            cache,
        }),
        Decision::Deny {
            policy,
            rule,
            status,
            reason,
            body,
        } => PolicyOutcomeInternal::Deny(DenyDecision {
            client,
            policy,
            rule,
            status,
            reason,
            body,
        }),
    }
}

fn log_policy_allow(
    level: Level,
    message: &str,
    peer: SocketAddr,
    parsed: &ParsedRequest,
    logged_path: &str,
    decision: &AllowDecision,
) {
    let flow = parsed.flow_context();
    let session_id = flow.map(|flow| flow.session_id.as_ref());
    let outer_method = flow.map(|flow| flow.outer_method.as_ref());
    let inner_method = flow.map(|_| parsed.method.as_str());
    let effective_mode = flow.map(|flow| flow.effective_mode.as_str()).or_else(|| {
        (parsed.method == http::Method::CONNECT).then_some(decision.https_mode.as_str())
    });
    log_with_level!(
        level,
        peer = %peer,
        client = %decision.client,
        policy = %decision.policy,
        rule = %decision.rule,
        policy_basis = %decision.rule,
        method = %parsed.method,
        scheme = scheme_name(parsed.scheme),
        host = %parsed.host,
        path = %logged_path,
        session_id = session_id,
        outer_method = outer_method,
        inner_method = inner_method,
        effective_mode = effective_mode,
        "{message}"
    );
}

fn log_policy_deny(
    level: Level,
    message: &str,
    peer: SocketAddr,
    parsed: &ParsedRequest,
    logged_path: &str,
    decision: &DenyDecision,
) {
    let flow = parsed.flow_context();
    let session_id = flow.map(|flow| flow.session_id.as_ref());
    let outer_method = flow.map(|flow| flow.outer_method.as_ref());
    let inner_method = flow.map(|_| parsed.method.as_str());
    let effective_mode = flow
        .map(|flow| flow.effective_mode.as_str())
        .or_else(|| (parsed.method == http::Method::CONNECT).then_some("tunnel"));
    log_with_level!(
        level,
        peer = %peer,
        client = %decision.client,
        policy = %decision.policy,
        rule = %decision.rule,
        policy_basis = %decision.rule,
        status = decision.status.as_u16(),
        method = %parsed.method,
        scheme = scheme_name(parsed.scheme),
        host = %parsed.host,
        path = %logged_path,
        session_id = session_id,
        outer_method = outer_method,
        inner_method = inner_method,
        effective_mode = effective_mode,
        "{message}"
    );
}

fn log_policy_default(
    level: Level,
    message: &str,
    peer: SocketAddr,
    parsed: &ParsedRequest,
    logged_path: &str,
) {
    let flow = parsed.flow_context();
    let session_id = flow.map(|flow| flow.session_id.as_ref());
    let outer_method = flow.map(|flow| flow.outer_method.as_ref());
    let inner_method = flow.map(|_| parsed.method.as_str());
    let effective_mode = flow.map(|flow| flow.effective_mode.as_str());
    log_with_level!(
        level,
        peer = %peer,
        method = %parsed.method,
        scheme = scheme_name(parsed.scheme),
        host = %parsed.host,
        path = %logged_path,
        session_id = session_id,
        outer_method = outer_method,
        inner_method = inner_method,
        effective_mode = effective_mode,
        "{message}"
    );
}
#[derive(Debug, Clone)]
pub struct AllowDecision {
    pub client: Arc<str>,
    pub policy: Arc<str>,
    pub rule: Arc<str>,
    pub https_mode: crate::config::HttpsMode,
    pub cache: Option<CompiledCacheConfig>,
}

#[derive(Debug, Clone)]
pub struct DenyDecision {
    pub client: Arc<str>,
    pub policy: Arc<str>,
    pub rule: Arc<str>,
    pub status: StatusCode,
    pub reason: Option<Arc<str>>,
    pub body: Option<Arc<str>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Client, ClientSelector, Config, HttpsMode, MethodMatch, Policy, Rule, RuleAction, Scheme,
        UrlPattern, ValidatedConfig,
    };
    use crate::policy::compile::compile_config;
    use crate::policy::matcher::PolicySnapshot;
    use http::Method;
    use ipnet::IpNet;
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn build_snapshot() -> PolicySnapshot {
        let policy = Policy {
            name: Arc::<str>::from("allow-api"),
            rules: Arc::from(
                vec![Rule {
                    id: Arc::<str>::from("allow-api#0"),
                    action: RuleAction::Allow,
                    methods: MethodMatch::List(vec![Method::GET]),
                    url_pattern: Some(UrlPattern {
                        scheme: Scheme::Https,
                        host: Arc::<str>::from("example.com"),
                        port: None,
                        path: Some(Arc::<str>::from("/api/**")),
                        original: Arc::<str>::from("https://example.com/api/**"),
                    }),
                    https_mode: HttpsMode::Inspect,
                    cache: None,
                }]
                .into_boxed_slice(),
            ),
        };
        let clients = vec![Client {
            name: Arc::<str>::from("default"),
            selector: ClientSelector::Cidr("0.0.0.0/0".parse::<IpNet>().unwrap()),
            policies: Arc::from(vec![policy.name.clone()].into_boxed_slice()),
            fallback: true,
        }];
        let config = Config {
            clients,
            policies: vec![policy],
        };
        let validated = ValidatedConfig::new(config).expect("validate config");
        let compiled = Arc::new(compile_config(&validated).expect("compile config"));
        PolicySnapshot::new(compiled)
    }

    #[test]
    fn policy_eval_ignores_query_in_path() {
        let snapshot = build_snapshot();
        let parsed = ParsedRequest {
            method: Method::GET,
            scheme: Scheme::Https,
            authority: "example.com".to_string(),
            host: "example.com".to_string(),
            port: None,
            path: "/api/v1/items?token=abc".to_string(),
            policy_path: "/api/v1/items".to_string(),
            flow: None,
        };
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let outcome = evaluate_request(peer, &parsed, &snapshot, false, PolicyLogConfig::http1());
        match outcome {
            PolicyOutcome::Allow(_) => {}
            _ => panic!("expected allow decision"),
        }
    }

    #[test]
    fn policy_eval_uses_canonical_policy_path() {
        let snapshot = build_snapshot();
        let parsed = ParsedRequest {
            method: Method::GET,
            scheme: Scheme::Https,
            authority: "example.com".to_string(),
            host: "example.com".to_string(),
            port: None,
            path: "/other/../api/v1/items?token=abc".to_string(),
            policy_path: "/api/v1/items".to_string(),
            flow: None,
        };
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let outcome = evaluate_request(peer, &parsed, &snapshot, false, PolicyLogConfig::http1());
        match outcome {
            PolicyOutcome::Allow(_) => {}
            _ => panic!("expected allow decision"),
        }
    }
}
