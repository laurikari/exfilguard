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

    pub const fn http2_connect_bump() -> Self {
        Self {
            allow_level: Level::DEBUG,
            deny_level: Level::DEBUG,
            default_level: Level::WARN,
            allow_message: "policy allow decision (HTTP/2 CONNECT bump)",
            deny_message: "policy deny decision (HTTP/2 CONNECT bump)",
            default_message: "no matching policy decision for HTTP/2 CONNECT bump; default deny",
        }
    }

    pub const fn connect() -> Self {
        Self {
            allow_level: Level::INFO,
            deny_level: Level::INFO,
            default_level: Level::WARN,
            allow_message: "policy allow decision (CONNECT)",
            deny_message: "policy deny decision (CONNECT)",
            default_message: "no matching policy decision for CONNECT; default deny",
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
        path: &parsed.path,
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
            inspect_payload,
            allow_private_connect,
            cache,
        } => PolicyOutcomeInternal::Allow(AllowDecision {
            client,
            policy,
            rule,
            inspect_payload,
            allow_private_connect,
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
    log_with_level!(
        level,
        peer = %peer,
        client = %decision.client,
        policy = %decision.policy,
        rule = %decision.rule,
        inspect_payload = decision.inspect_payload,
        method = %parsed.method,
        scheme = scheme_name(parsed.scheme),
        host = %parsed.host,
        path = %logged_path,
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
    log_with_level!(
        level,
        peer = %peer,
        client = %decision.client,
        policy = %decision.policy,
        rule = %decision.rule,
        status = decision.status.as_u16(),
        method = %parsed.method,
        scheme = scheme_name(parsed.scheme),
        host = %parsed.host,
        path = %logged_path,
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
    log_with_level!(
        level,
        peer = %peer,
        method = %parsed.method,
        scheme = scheme_name(parsed.scheme),
        host = %parsed.host,
        path = %logged_path,
        "{message}"
    );
}
#[derive(Debug, Clone)]
pub struct AllowDecision {
    pub client: Arc<str>,
    pub policy: Arc<str>,
    pub rule: Arc<str>,
    pub inspect_payload: bool,
    pub allow_private_connect: bool,
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
