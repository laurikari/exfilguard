use std::{net::SocketAddr, sync::Arc};

use http::StatusCode;
use tracing::Level;
use uuid::Uuid;

use crate::{
    authorization::{AuthorizationToken, DelegatedAuthorization, ResolvedAuthorizationPolicy},
    logging::{AccessLogBuilder, log_with_level},
    policy::{
        Decision,
        matcher::{EvaluationResult, PolicySnapshot},
        model::CompiledCacheConfig,
    },
    proxy::request::{ParsedRequest, request_target_for_log, scheme_name},
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
    TlsBumpPreflight(TlsBumpPreflightOutcome<'a>),
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

pub struct TlsBumpPreflightOutcome<'a> {
    pub client: Arc<str>,
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
    request_id: Arc<str>,
}

impl<'a> RequestLogContext<'a> {
    pub fn new(peer: SocketAddr, parsed: &'a ParsedRequest, log_queries: bool) -> Self {
        let logged_path = request_target_for_log(&parsed.path, log_queries);
        Self {
            peer,
            parsed,
            logged_path,
            request_id: Arc::<str>::from(Uuid::new_v4().to_string()),
        }
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub fn request_id(&self) -> &str {
        self.request_id.as_ref()
    }

    pub fn method(&self) -> &str {
        self.parsed.method.as_str()
    }

    pub fn host(&self) -> &str {
        &self.parsed.host
    }

    pub fn logged_path(&self) -> &str {
        &self.logged_path
    }

    pub fn session_id(&self) -> Option<&str> {
        self.parsed
            .flow_context()
            .map(|flow| flow.session_id.as_ref())
    }

    pub fn outer_method(&self) -> Option<&str> {
        self.parsed
            .flow_context()
            .map(|flow| flow.outer_method.as_ref())
    }

    pub fn inner_method(&self) -> Option<&str> {
        self.parsed
            .flow_context()
            .map(|_| self.parsed.method.as_str())
    }

    pub fn effective_mode(&self) -> Option<&str> {
        self.parsed
            .flow_context()
            .map(|flow| flow.effective_mode.as_str())
    }

    pub fn access_log_builder(&self) -> AccessLogBuilder {
        self.parsed
            .access_log_builder(self.peer, self.logged_path.clone())
            .request_id(self.request_id.as_ref())
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
    let policy_request = parsed.as_policy_request();

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
                    log_ctx.request_id(),
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
                    log_ctx.request_id(),
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
                log_ctx.request_id(),
            );
            PolicyOutcome::DefaultDeny(DefaultDenyOutcome { log: log_ctx })
        }
    }
}

pub(crate) fn evaluate_delegated_request<'a>(
    peer: SocketAddr,
    parsed: &'a ParsedRequest,
    snapshot: &'a PolicySnapshot,
    authorization: (Arc<AuthorizationToken>, Arc<ResolvedAuthorizationPolicy>),
    log_queries: bool,
    log_config: PolicyLogConfig,
) -> PolicyOutcome<'a> {
    let (token, authorization_policy) = authorization;
    let log_ctx = RequestLogContext::new(peer, parsed, log_queries);
    let policy_request = parsed.as_policy_request();
    let Some(_client) = snapshot.resolve_client(peer.ip()) else {
        log_policy_default(
            log_config.default_level,
            log_config.default_message,
            peer,
            parsed,
            log_ctx.logged_path(),
            log_ctx.request_id(),
        );
        return PolicyOutcome::DefaultDeny(DefaultDenyOutcome { log: log_ctx });
    };
    if parsed.method == http::Method::CONNECT {
        return evaluate_delegated_connect(
            peer,
            parsed,
            snapshot,
            token,
            authorization_policy,
            log_ctx,
            log_config,
        );
    }
    let Some(static_result) = snapshot.evaluate_request(peer.ip(), &policy_request) else {
        log_policy_default(
            log_config.default_level,
            log_config.default_message,
            peer,
            parsed,
            log_ctx.logged_path(),
            log_ctx.request_id(),
        );
        return PolicyOutcome::DefaultDeny(DefaultDenyOutcome { log: log_ctx });
    };
    let static_client = static_result.client.clone();
    let mut decision = match into_decision(static_result) {
        PolicyOutcomeInternal::Allow(decision) => decision,
        PolicyOutcomeInternal::Deny(decision) => {
            crate::metrics::record_rule_hit(decision.rule.as_ref());
            log_policy_deny(
                log_config.deny_level,
                log_config.deny_message,
                peer,
                parsed,
                log_ctx.logged_path(),
                log_ctx.request_id(),
                &decision,
            );
            return PolicyOutcome::Deny(DenyOutcome {
                decision,
                log: log_ctx,
            });
        }
    };
    crate::metrics::record_rule_hit(decision.rule.as_ref());

    let Some(dynamic_decision) = authorization_policy.dynamic.evaluate(&policy_request) else {
        log_authorization_deny(
            peer,
            parsed,
            &log_ctx,
            static_client.as_ref(),
            token.correlation(),
            authorization_policy.policy_version.as_ref(),
            None,
        );
        return PolicyOutcome::DefaultDeny(DefaultDenyOutcome { log: log_ctx });
    };
    let dynamic_rule = match dynamic_decision {
        crate::policy::Decision::Allow { rule, .. } => rule,
        crate::policy::Decision::Deny { rule, .. } => {
            log_authorization_deny(
                peer,
                parsed,
                &log_ctx,
                static_client.as_ref(),
                token.correlation(),
                authorization_policy.policy_version.as_ref(),
                Some(rule.as_ref()),
            );
            return PolicyOutcome::DefaultDeny(DefaultDenyOutcome { log: log_ctx });
        }
    };
    decision.authorization = Some(DelegatedAuthorization {
        token,
        policy: authorization_policy,
        rule: dynamic_rule,
    });
    // Delegated requests are isolated from the shared response cache because the authorization
    // token is not part of that cache key.
    decision.cache = None;
    log_policy_allow(
        log_config.allow_level,
        log_config.allow_message,
        peer,
        parsed,
        log_ctx.logged_path(),
        log_ctx.request_id(),
        &decision,
    );
    PolicyOutcome::Allow(AllowOutcome {
        decision,
        log: log_ctx,
    })
}

#[allow(clippy::too_many_arguments)]
fn evaluate_delegated_connect<'a>(
    peer: SocketAddr,
    parsed: &'a ParsedRequest,
    snapshot: &'a PolicySnapshot,
    token: Arc<AuthorizationToken>,
    authorization_policy: Arc<ResolvedAuthorizationPolicy>,
    log_ctx: RequestLogContext<'a>,
    log_config: PolicyLogConfig,
) -> PolicyOutcome<'a> {
    let request = parsed.as_policy_request();
    if let Some(static_result) = snapshot.evaluate_request(peer.ip(), &request) {
        match into_decision(static_result) {
            PolicyOutcomeInternal::Deny(decision) => {
                crate::metrics::record_rule_hit(decision.rule.as_ref());
                log_policy_deny(
                    log_config.deny_level,
                    log_config.deny_message,
                    peer,
                    parsed,
                    log_ctx.logged_path(),
                    log_ctx.request_id(),
                    &decision,
                );
                return PolicyOutcome::Deny(DenyOutcome {
                    decision,
                    log: log_ctx,
                });
            }
            PolicyOutcomeInternal::Allow(decision) => {
                crate::metrics::record_rule_hit(decision.rule.as_ref());
            }
        }
    } else {
        log_policy_default(
            log_config.default_level,
            log_config.default_message,
            peer,
            parsed,
            log_ctx.logged_path(),
            log_ctx.request_id(),
        );
    }

    tracing::debug!(
        peer = %peer,
        authorization_token_id = token.correlation(),
        policy_version = %authorization_policy.policy_version,
        "raw CONNECT tunnel disabled for delegated authorization; evaluating TLS inspection preflight"
    );
    if let Some(preflight) = snapshot.evaluate_tls_bump_preflight(peer.ip(), &request)
        && authorization_policy.dynamic.allows_tls_bump(&request)
    {
        return PolicyOutcome::TlsBumpPreflight(TlsBumpPreflightOutcome {
            client: preflight.client,
            log: log_ctx,
        });
    }

    PolicyOutcome::DefaultDeny(DefaultDenyOutcome { log: log_ctx })
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
            authorization: None,
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
    request_id: &str,
    decision: &AllowDecision,
) {
    let flow = parsed.flow_context();
    let session_id = flow.map(|flow| flow.session_id.as_ref());
    let outer_method = flow.map(|flow| flow.outer_method.as_ref());
    let inner_method = flow.map(|_| parsed.method.as_str());
    let effective_mode = flow.map(|flow| flow.effective_mode.as_str()).or_else(|| {
        (parsed.method == http::Method::CONNECT).then_some(decision.https_mode.as_str())
    });
    let authorization_token_id = decision
        .authorization
        .as_ref()
        .map(|authorization| authorization.token.correlation());
    let authorization_policy_version = decision
        .authorization
        .as_ref()
        .map(|authorization| authorization.policy.policy_version.as_ref());
    let authorization_rule = decision
        .authorization
        .as_ref()
        .map(|authorization| authorization.rule.as_ref());
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
        request_id = request_id,
        session_id = session_id,
        outer_method = outer_method,
        inner_method = inner_method,
        effective_mode = effective_mode,
        authorization_token_id = authorization_token_id,
        authorization_policy_version = authorization_policy_version,
        authorization_rule = authorization_rule,
        "{message}"
    );
}

fn log_authorization_deny(
    peer: SocketAddr,
    parsed: &ParsedRequest,
    log: &RequestLogContext<'_>,
    client: &str,
    authorization_token_id: &str,
    policy_version: &str,
    authorization_rule: Option<&str>,
) {
    tracing::info!(
        peer = %peer,
        client,
        authorization_token_id,
        authorization_policy_version = policy_version,
        authorization_rule,
        method = %parsed.method,
        scheme = scheme_name(parsed.scheme),
        host = %parsed.host,
        path = log.logged_path(),
        request_id = log.request_id(),
        "authorization service deny decision"
    );
}

fn log_policy_deny(
    level: Level,
    message: &str,
    peer: SocketAddr,
    parsed: &ParsedRequest,
    logged_path: &str,
    request_id: &str,
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
        request_id = request_id,
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
    request_id: &str,
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
        request_id = request_id,
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
    pub(crate) authorization: Option<DelegatedAuthorization>,
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
            selector: ClientSelector::Fallback,
            policies: Arc::from(vec![policy.name.clone()].into_boxed_slice()),
            authorization_service: None,
            max_connections: 1024,
        }];
        let config = Config {
            clients,
            policies: vec![policy],
        };
        let validated = ValidatedConfig::new(config).expect("validate config");
        let compiled = Arc::new(compile_config(&validated).expect("compile config"));
        PolicySnapshot::new(compiled)
    }

    fn build_tunnel_snapshot() -> PolicySnapshot {
        let policy = Policy {
            name: Arc::from("tunnel"),
            rules: Arc::from(
                vec![Rule {
                    id: Arc::from("tunnel#0"),
                    action: RuleAction::Allow,
                    methods: MethodMatch::List(vec![Method::CONNECT]),
                    url_pattern: Some(
                        crate::config::parse_url_pattern("https://example.com:443/**").unwrap(),
                    ),
                    https_mode: HttpsMode::Tunnel,
                    cache: None,
                }]
                .into_boxed_slice(),
            ),
        };
        let config = Config {
            clients: vec![Client {
                name: Arc::from("default"),
                selector: ClientSelector::Fallback,
                policies: Arc::from([policy.name.clone()]),
                authorization_service: None,
                max_connections: 1024,
            }],
            policies: vec![policy],
        };
        let validated = ValidatedConfig::new(config).unwrap();
        PolicySnapshot::new(Arc::new(compile_config(&validated).unwrap()))
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

    #[test]
    fn authorization_policy_and_static_policy_must_both_allow() {
        let snapshot = build_snapshot();
        let token =
            crate::authorization::AuthorizationToken::parse(b"ExfilGuard test-token", 128).unwrap();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let dynamic_post =
            crate::authorization::ResolvedAuthorizationPolicy::from_test_rules(vec![
                crate::authorization::policy::make_dynamic_rule(
                    0,
                    RuleAction::Allow,
                    MethodMatch::List(vec![Method::POST]),
                    Some(crate::config::parse_url_pattern("https://example.com/api/**").unwrap()),
                ),
            ]);
        let static_denies = ParsedRequest {
            method: Method::POST,
            scheme: Scheme::Https,
            authority: "example.com".to_string(),
            host: "example.com".to_string(),
            port: None,
            path: "/api/items".to_string(),
            policy_path: "/api/items".to_string(),
            flow: None,
        };
        assert!(matches!(
            evaluate_delegated_request(
                peer,
                &static_denies,
                &snapshot,
                (token.clone(), dynamic_post),
                false,
                PolicyLogConfig::http1(),
            ),
            PolicyOutcome::DefaultDeny(_)
        ));

        let dynamic_other_path =
            crate::authorization::ResolvedAuthorizationPolicy::from_test_rules(vec![
                crate::authorization::policy::make_dynamic_rule(
                    0,
                    RuleAction::Allow,
                    MethodMatch::List(vec![Method::GET]),
                    Some(crate::config::parse_url_pattern("https://example.com/other/**").unwrap()),
                ),
            ]);
        let static_allows = ParsedRequest {
            method: Method::GET,
            ..static_denies
        };
        assert!(matches!(
            evaluate_delegated_request(
                peer,
                &static_allows,
                &snapshot,
                (token, dynamic_other_path),
                false,
                PolicyLogConfig::http1(),
            ),
            PolicyOutcome::DefaultDeny(_)
        ));
    }

    #[test]
    fn delegated_authorization_never_directly_allows_raw_connect() {
        let snapshot = build_tunnel_snapshot();
        let token =
            crate::authorization::AuthorizationToken::parse(b"ExfilGuard test-token", 128).unwrap();
        let dynamic = crate::authorization::ResolvedAuthorizationPolicy::from_test_rules(vec![
            crate::authorization::policy::make_dynamic_rule(
                0,
                RuleAction::Allow,
                MethodMatch::Any,
                Some(crate::config::parse_url_pattern("https://example.com:443/**").unwrap()),
            ),
        ]);
        let parsed = ParsedRequest {
            method: Method::CONNECT,
            scheme: Scheme::Https,
            authority: "example.com:443".to_string(),
            host: "example.com".to_string(),
            port: Some(443),
            path: "example.com:443".to_string(),
            policy_path: "example.com:443".to_string(),
            flow: None,
        };
        assert!(matches!(
            evaluate_delegated_request(
                "127.0.0.1:12345".parse().unwrap(),
                &parsed,
                &snapshot,
                (token, dynamic),
                false,
                PolicyLogConfig::connect_tunnel(),
            ),
            PolicyOutcome::DefaultDeny(_)
        ));
    }

    #[test]
    fn delegated_connect_carries_one_resolved_policy_into_tls_preflight() {
        let snapshot = build_snapshot();
        let token =
            crate::authorization::AuthorizationToken::parse(b"ExfilGuard test-token", 128).unwrap();
        let dynamic = crate::authorization::ResolvedAuthorizationPolicy::from_test_rules(vec![
            crate::authorization::policy::make_dynamic_rule(
                0,
                RuleAction::Allow,
                MethodMatch::List(vec![Method::GET]),
                Some(crate::config::parse_url_pattern("https://example.com/api/**").unwrap()),
            ),
        ]);
        let parsed = ParsedRequest {
            method: Method::CONNECT,
            scheme: Scheme::Https,
            authority: "example.com:443".to_string(),
            host: "example.com".to_string(),
            port: Some(443),
            path: "example.com:443".to_string(),
            policy_path: "example.com:443".to_string(),
            flow: None,
        };

        assert!(matches!(
            evaluate_delegated_request(
                "127.0.0.1:12345".parse().unwrap(),
                &parsed,
                &snapshot,
                (token, dynamic),
                Arc::from("test"),
                false,
                PolicyLogConfig::connect_tunnel(),
            ),
            PolicyOutcome::TlsBumpPreflight(_)
        ));
    }
}
