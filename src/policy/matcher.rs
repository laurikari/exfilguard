use std::net::IpAddr;
use std::sync::Arc;

use http::Method;

use crate::config::{RuleAction, Scheme};

use super::Decision;
use super::model::{ClientEntry, CompiledConfig};

#[derive(Clone)]
pub struct PolicyMatcher {
    config: Arc<CompiledConfig>,
}

impl PolicyMatcher {
    pub fn new(config: Arc<CompiledConfig>) -> Self {
        Self { config }
    }

    pub fn evaluate(&self, policy_indices: &[usize], request: &Request) -> Option<Decision> {
        for &policy_idx in policy_indices {
            let Some(policy) = self.config.policies.get(policy_idx) else {
                continue;
            };
            if let Some(decision) = evaluate_policy(policy.as_ref(), request) {
                return Some(decision);
            }
        }
        None
    }
}

/// PolicySnapshot provides a thread-safe, point-in-time view of the security configuration.
///
/// The evaluation follows a two-stage hierarchy:
/// 1. Client Resolution: Maps the source IP to a `ClientEntry` using a CIDR trie.
/// 2. Rule Matching: Iterates through the client's assigned policies. The first
///    `Rule` that matches the request's method and URL pattern determines the outcome.
#[derive(Clone)]
pub struct PolicySnapshot {
    pub compiled: Arc<CompiledConfig>,
    pub matcher: PolicyMatcher,
}

impl PolicySnapshot {
    pub fn new(compiled: Arc<CompiledConfig>) -> Self {
        let matcher = PolicyMatcher::new(compiled.clone());
        Self { compiled, matcher }
    }

    pub fn resolve_client(&self, addr: IpAddr) -> Option<&ClientEntry> {
        let addr = normalize_peer_ip(addr);
        if let Some(index) = self.compiled.cidr_trie.find(addr)
            && let Some(client) = self.compiled.clients.get(index)
        {
            return Some(client);
        }

        self.compiled.clients.get(self.compiled.default_client)
    }

    pub fn evaluate_request(&self, addr: IpAddr, request: &Request) -> Option<EvaluationResult> {
        let client = self.resolve_client(addr)?;
        let decision = self.matcher.evaluate(client.policies.as_ref(), request)?;
        Some(EvaluationResult {
            client: client.name.clone(),
            decision,
        })
    }
}

fn normalize_peer_ip(addr: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = addr
        && let Some(mapped) = v6.to_ipv4_mapped()
    {
        return IpAddr::V4(mapped);
    }
    addr
}

#[derive(Debug, Clone)]
pub struct EvaluationResult {
    pub client: Arc<str>,
    pub decision: Decision,
}

fn evaluate_policy(policy: &super::model::CompiledPolicy, request: &Request) -> Option<Decision> {
    for rule in policy.rules.iter() {
        if !rule.methods.allows(request.method) {
            continue;
        }
        if let Some(url) = &rule.url {
            let ignore_path = request.method == Method::CONNECT;
            if !url.matches(
                request.scheme,
                request.host,
                request.port,
                request.path,
                ignore_path,
            ) {
                continue;
            }
        }
        return Some(make_decision(policy, rule));
    }
    None
}

fn make_decision(
    policy: &super::model::CompiledPolicy,
    rule: &super::model::CompiledRule,
) -> Decision {
    match &rule.action {
        RuleAction::Allow => Decision::Allow {
            policy: policy.name.clone(),
            rule: rule.id.clone(),
            inspect_payload: rule.inspect_payload,
            allow_private_upstream: rule.allow_private_upstream,
            cache: rule.cache.clone(),
        },
        RuleAction::Deny {
            status,
            reason,
            body,
        } => Decision::Deny {
            policy: policy.name.clone(),
            rule: rule.id.clone(),
            status: *status,
            reason: reason.clone(),
            body: body.clone(),
        },
    }
}

#[derive(Debug)]
pub struct Request<'a> {
    pub method: &'a Method,
    pub scheme: Scheme,
    pub host: &'a str,
    pub port: Option<u16>,
    pub path: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Client, ClientSelector, Config, MethodMatch, Policy, Rule, RuleAction, UrlPattern,
        ValidatedConfig,
    };
    use crate::policy::compile::compile_config;
    use http::{Method, StatusCode};
    use ipnet::IpNet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    fn allow_policy() -> Policy {
        Policy {
            name: Arc::<str>::from("allow-api"),
            rules: Arc::from(
                vec![Rule {
                    id: Arc::<str>::from("allow#0"),
                    action: RuleAction::Allow,
                    methods: MethodMatch::List(vec![Method::GET, Method::POST]),
                    url_pattern: Some(UrlPattern {
                        scheme: Scheme::Https,
                        host: Arc::<str>::from("*.example.com"),
                        port: None,
                        path: Some(Arc::<str>::from("/api/**")),
                        original: Arc::<str>::from("https://*.example.com/api/**"),
                    }),
                    inspect_payload: false,
                    allow_private_upstream: false,
                    cache: None,
                }]
                .into_boxed_slice(),
            ),
        }
    }

    fn deny_policy() -> Policy {
        Policy {
            name: Arc::<str>::from("deny-all"),
            rules: Arc::from(
                vec![Rule {
                    id: Arc::<str>::from("deny#0"),
                    action: RuleAction::Deny {
                        status: StatusCode::FORBIDDEN,
                        reason: None,
                        body: Some(Arc::<str>::from("Blocked")),
                    },
                    methods: MethodMatch::Any,
                    url_pattern: None,
                    inspect_payload: false,
                    allow_private_upstream: false,
                    cache: None,
                }]
                .into_boxed_slice(),
            ),
        }
    }

    fn build_config(include_deny: bool) -> ValidatedConfig {
        let mut policies = vec![allow_policy()];
        let mut policy_refs = vec![Arc::<str>::from("allow-api")];
        if include_deny {
            policies.push(deny_policy());
            policy_refs.push(Arc::<str>::from("deny-all"));
        }
        let clients = vec![Client {
            name: Arc::<str>::from("default"),
            selector: ClientSelector::Cidr("0.0.0.0/0".parse::<IpNet>().unwrap()),
            policies: Arc::from(policy_refs.into_boxed_slice()),
            catch_all: true,
        }];
        ValidatedConfig::new(Config { clients, policies }).expect("validate config")
    }

    #[test]
    fn evaluate_allow_rule() {
        let config = build_config(true);
        let compiled = std::sync::Arc::new(compile_config(&config).expect("compile config"));
        let matcher = PolicyMatcher::new(compiled.clone());
        let client = &compiled.clients[0];
        let request = Request {
            method: &Method::GET,
            scheme: Scheme::Https,
            host: "api.example.com",
            port: None,
            path: "/api/v1/items",
        };
        let decision = matcher
            .evaluate(client.policies.as_ref(), &request)
            .expect("decision");
        match decision {
            Decision::Allow { policy, rule, .. } => {
                assert_eq!(policy.as_ref(), "allow-api");
                assert_eq!(rule.as_ref(), "allow#0");
            }
            other => panic!("expected allow decision, got {:?}", other),
        }
    }

    #[test]
    fn evaluate_deny_fallback() {
        let config = build_config(true);
        let compiled = std::sync::Arc::new(compile_config(&config).expect("compile config"));
        let matcher = PolicyMatcher::new(compiled.clone());
        let client = &compiled.clients[0];
        let request = Request {
            method: &Method::DELETE,
            scheme: Scheme::Https,
            host: "api.example.com",
            port: None,
            path: "/api/v1/items",
        };
        let decision = matcher
            .evaluate(client.policies.as_ref(), &request)
            .expect("decision");
        match decision {
            Decision::Deny {
                policy,
                rule,
                status,
                reason,
                body,
            } => {
                assert_eq!(policy.as_ref(), "deny-all");
                assert_eq!(rule.as_ref(), "deny#0");
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert!(reason.is_none());
                assert_eq!(body.unwrap().as_ref(), "Blocked");
            }
            other => panic!("expected deny decision, got {:?}", other),
        }
    }

    #[test]
    fn evaluate_no_match() {
        let config = build_config(false);
        let compiled = std::sync::Arc::new(compile_config(&config).expect("compile config"));
        let matcher = PolicyMatcher::new(compiled.clone());
        let client = &compiled.clients[0];
        let request = Request {
            method: &Method::GET,
            scheme: Scheme::Http,
            host: "unmatched.example.net",
            port: None,
            path: "/",
        };
        let decision = matcher.evaluate(client.policies.as_ref(), &request);
        assert!(decision.is_none(), "unexpected decision: {:?}", decision);
    }

    #[test]
    fn connect_allows_when_rule_has_path() {
        let policy = Policy {
            name: Arc::<str>::from("allow-site"),
            rules: Arc::from(
                vec![Rule {
                    id: Arc::<str>::from("allow-site#0"),
                    action: RuleAction::Allow,
                    methods: MethodMatch::Any,
                    url_pattern: Some(UrlPattern {
                        scheme: Scheme::Https,
                        host: Arc::<str>::from("example.com"),
                        port: Some(443),
                        path: Some(Arc::<str>::from("/privacy-policy/")),
                        original: Arc::<str>::from("https://example.com/privacy-policy/"),
                    }),
                    inspect_payload: false,
                    allow_private_upstream: false,
                    cache: None,
                }]
                .into_boxed_slice(),
            ),
        };
        let config = ValidatedConfig::new(Config {
            clients: vec![Client {
                name: Arc::<str>::from("default"),
                selector: ClientSelector::Cidr("0.0.0.0/0".parse::<IpNet>().unwrap()),
                policies: Arc::from(vec![policy.name.clone()].into_boxed_slice()),
                catch_all: true,
            }],
            policies: vec![policy],
        })
        .expect("validate config");
        let compiled = Arc::new(compile_config(&config).expect("compile config"));
        let matcher = PolicyMatcher::new(compiled.clone());
        let client = &compiled.clients[0];
        let request = Request {
            method: &Method::CONNECT,
            scheme: Scheme::Https,
            host: "example.com",
            port: Some(443),
            path: "/",
        };
        let decision = matcher
            .evaluate(client.policies.as_ref(), &request)
            .expect("decision");
        match decision {
            Decision::Allow { .. } => {}
            other => panic!("expected allow decision, got {:?}", other),
        }
    }

    #[test]
    fn resolve_client_precedence() {
        let policies = vec![allow_policy()];
        let policy_refs: Arc<[Arc<str>]> =
            Arc::from(vec![Arc::<str>::from("allow-api")].into_boxed_slice());
        let clients = vec![
            Client {
                name: Arc::<str>::from("exact"),
                selector: ClientSelector::Ip(IpAddr::from(Ipv4Addr::new(10, 0, 2, 5))),
                policies: policy_refs.clone(),
                catch_all: false,
            },
            Client {
                name: Arc::<str>::from("cidr24"),
                selector: ClientSelector::Cidr("10.0.0.0/24".parse::<IpNet>().unwrap()),
                policies: policy_refs.clone(),
                catch_all: false,
            },
            Client {
                name: Arc::<str>::from("cidr_other"),
                selector: ClientSelector::Cidr("10.1.0.0/24".parse::<IpNet>().unwrap()),
                policies: policy_refs.clone(),
                catch_all: false,
            },
            Client {
                name: Arc::<str>::from("default"),
                selector: ClientSelector::Cidr("0.0.0.0/0".parse::<IpNet>().unwrap()),
                policies: policy_refs.clone(),
                catch_all: true,
            },
        ];

        let config = ValidatedConfig::new(Config { clients, policies }).expect("validate config");
        let compiled = Arc::new(compile_config(&config).expect("compile config"));
        let snapshot = PolicySnapshot::new(compiled);

        let exact = snapshot
            .resolve_client(IpAddr::from(Ipv4Addr::new(10, 0, 2, 5)))
            .expect("exact client");
        assert_eq!(exact.name.as_ref(), "exact");

        let cidr24 = snapshot
            .resolve_client(IpAddr::from(Ipv4Addr::new(10, 0, 0, 99)))
            .expect("cidr24 client");
        assert_eq!(cidr24.name.as_ref(), "cidr24");

        let cidr_other = snapshot
            .resolve_client(IpAddr::from(Ipv4Addr::new(10, 1, 0, 10)))
            .expect("cidr_other client");
        assert_eq!(cidr_other.name.as_ref(), "cidr_other");

        let default = snapshot
            .resolve_client(IpAddr::from(Ipv4Addr::new(192, 168, 1, 1)))
            .expect("default client");
        assert_eq!(default.name.as_ref(), "default");
    }

    #[test]
    fn resolve_client_maps_ipv4_mapped_ipv6() {
        let policies = vec![allow_policy()];
        let policy_refs: Arc<[Arc<str>]> =
            Arc::from(vec![Arc::<str>::from("allow-api")].into_boxed_slice());
        let clients = vec![
            Client {
                name: Arc::<str>::from("ipv4-client"),
                selector: ClientSelector::Ip("10.0.0.5".parse().unwrap()),
                policies: policy_refs.clone(),
                catch_all: false,
            },
            Client {
                name: Arc::<str>::from("default"),
                selector: ClientSelector::Cidr("0.0.0.0/0".parse::<IpNet>().unwrap()),
                policies: policy_refs,
                catch_all: true,
            },
        ];

        let config = ValidatedConfig::new(Config { clients, policies }).expect("validate config");
        let compiled = Arc::new(compile_config(&config).expect("compile config"));
        let snapshot = PolicySnapshot::new(compiled);

        let mapped = IpAddr::V6("::ffff:10.0.0.5".parse::<Ipv6Addr>().unwrap());
        let resolved = snapshot.resolve_client(mapped).expect("mapped client");
        assert_eq!(resolved.name.as_ref(), "ipv4-client");
    }

    #[test]
    fn evaluate_request_api_returns_client_and_decision() {
        let config = build_config(true);
        let compiled = Arc::new(compile_config(&config).expect("compile config"));
        let snapshot = PolicySnapshot::new(compiled);
        let request = Request {
            method: &Method::GET,
            scheme: Scheme::Https,
            host: "api.example.com",
            port: None,
            path: "/api/v1/items",
        };
        let addr = IpAddr::from(Ipv4Addr::new(10, 0, 0, 10));
        let result = snapshot
            .evaluate_request(addr, &request)
            .expect("evaluation result");
        assert_eq!(result.client.as_ref(), "default");
        match result.decision {
            Decision::Allow { policy, rule, .. } => {
                assert_eq!(policy.as_ref(), "allow-api");
                assert_eq!(rule.as_ref(), "allow#0");
            }
            other => panic!("unexpected decision: {:?}", other),
        }
    }

    #[test]
    fn rule_with_explicit_default_port_matches_missing_port_request() {
        let policy = Policy {
            name: Arc::<str>::from("allow-default-port"),
            rules: Arc::from(
                vec![Rule {
                    id: Arc::<str>::from("allow-default-port#0"),
                    action: RuleAction::Allow,
                    methods: MethodMatch::List(vec![Method::GET]),
                    url_pattern: Some(UrlPattern {
                        scheme: Scheme::Https,
                        host: Arc::<str>::from("api.example.com"),
                        port: Some(443),
                        path: Some(Arc::<str>::from("/v1/**")),
                        original: Arc::<str>::from("https://api.example.com:443/v1/**"),
                    }),
                    inspect_payload: false,
                    allow_private_upstream: false,
                    cache: None,
                }]
                .into_boxed_slice(),
            ),
        };
        let clients = vec![Client {
            name: Arc::<str>::from("default"),
            selector: ClientSelector::Cidr("0.0.0.0/0".parse::<IpNet>().unwrap()),
            policies: Arc::from(vec![policy.name.clone()].into_boxed_slice()),
            catch_all: true,
        }];
        let config = ValidatedConfig::new(Config {
            clients,
            policies: vec![policy],
        })
        .expect("config");
        let compiled = Arc::new(compile_config(&config).expect("compile config"));
        let matcher = PolicyMatcher::new(compiled.clone());
        let client = &compiled.clients[0];
        let request = Request {
            method: &Method::GET,
            scheme: Scheme::Https,
            host: "api.example.com",
            port: None,
            path: "/v1/data",
        };
        let decision = matcher
            .evaluate(client.policies.as_ref(), &request)
            .expect("decision");
        assert!(matches!(decision, Decision::Allow { .. }));
    }

    #[test]
    fn ipv6_policy_host_matches_request() {
        let policy = Policy {
            name: Arc::<str>::from("allow-ipv6"),
            rules: Arc::from(
                vec![Rule {
                    id: Arc::<str>::from("allow-ipv6#0"),
                    action: RuleAction::Allow,
                    methods: MethodMatch::Any,
                    url_pattern: Some(UrlPattern {
                        scheme: Scheme::Https,
                        host: Arc::<str>::from("2001:db8::10"),
                        port: Some(443),
                        path: Some(Arc::<str>::from("/")),
                        original: Arc::<str>::from("https://[2001:db8::10]:443/"),
                    }),
                    inspect_payload: false,
                    allow_private_upstream: false,
                    cache: None,
                }]
                .into_boxed_slice(),
            ),
        };
        let clients = vec![Client {
            name: Arc::<str>::from("default"),
            selector: ClientSelector::Cidr("0.0.0.0/0".parse::<IpNet>().unwrap()),
            policies: Arc::from(vec![policy.name.clone()].into_boxed_slice()),
            catch_all: true,
        }];
        let config = ValidatedConfig::new(Config {
            clients,
            policies: vec![policy],
        })
        .expect("config");
        let compiled = Arc::new(compile_config(&config).expect("compile config"));
        let matcher = PolicyMatcher::new(compiled.clone());
        let client = &compiled.clients[0];
        let request = Request {
            method: &Method::GET,
            scheme: Scheme::Https,
            host: "2001:db8::10",
            port: None,
            path: "/",
        };
        let decision = matcher
            .evaluate(client.policies.as_ref(), &request)
            .expect("decision");
        assert!(matches!(decision, Decision::Allow { .. }));
    }
}
