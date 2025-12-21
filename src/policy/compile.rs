use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use regex::Regex;

use crate::config::{
    Client, ClientSelector, MethodMatch, Policy, Rule, UrlPattern, ValidatedConfig,
};

use super::model::{
    CidrTrie, ClientEntry, CompiledCacheConfig, CompiledConfig, CompiledPolicy, CompiledRule,
    HostLabel, HostMatcher, HostPattern, MethodMask, PathMatcher, UrlMatcher,
};

/// Transforms a validated configuration into a performance-optimized memory model.
///
/// Compilation involves:
/// 1. Building a `CidrTrie` for O(log N) client lookups by source IP.
/// 2. Converting URL patterns into specialized `HostMatcher` (Glob/Exact)
///    and `PathMatcher` (Regex) structures for fast evaluation.
/// 3. Resolving policy name references into direct indices to avoid string lookups at runtime.
pub fn compile_config(config: &ValidatedConfig) -> Result<CompiledConfig> {
    let config = config.as_ref();

    let mut policies = Vec::with_capacity(config.policies.len());
    let mut policy_lookup: HashMap<String, usize> = HashMap::new();

    for policy in &config.policies {
        let compiled = compile_policy(policy)?;
        let index = policies.len();
        policy_lookup.insert(policy.name.as_ref().to_string(), index);
        policies.push(Arc::new(compiled));
    }

    let mut compiled_clients = Vec::with_capacity(config.clients.len());
    for client in &config.clients {
        let mut indices = Vec::with_capacity(client.policies.len());
        for policy_name in client.policies.iter() {
            let index = policy_lookup
                .get(policy_name.as_ref())
                .copied()
                .ok_or_else(|| {
                    anyhow!(
                        "client '{}' references unknown policy '{}'",
                        client.name,
                        policy_name
                    )
                })?;
            indices.push(index);
        }
        compiled_clients.push(ClientEntry {
            name: client.name.clone(),
            policies: Arc::from(indices.into_boxed_slice()),
        });
    }

    let catch_all_index = config
        .clients
        .iter()
        .position(|client| client.catch_all)
        .expect("validate_clients guarantees a catch-all client");
    let (ip_clients, cidr_trie) = build_client_maps(&config.clients)?;

    Ok(CompiledConfig {
        clients: compiled_clients,
        policies: Arc::from(policies.into_boxed_slice()),
        ip_clients,
        cidr_trie,
        default_client: catch_all_index,
    })
}

fn build_client_maps(clients: &[Client]) -> Result<(HashMap<IpAddr, usize>, CidrTrie)> {
    let mut ip_clients: HashMap<IpAddr, usize> = HashMap::new();
    let mut cidr_trie = CidrTrie::new();

    for (index, client) in clients.iter().enumerate() {
        match &client.selector {
            ClientSelector::Ip(addr) => {
                let prev = ip_clients.insert(*addr, index);
                debug_assert!(
                    prev.is_none(),
                    "validate_clients should prevent duplicate IP claims"
                );
            }
            ClientSelector::Cidr(net) => {
                cidr_trie.insert(*net, index);
            }
        }
    }

    Ok((ip_clients, cidr_trie))
}

fn compile_policy(policy: &Policy) -> Result<CompiledPolicy> {
    let mut compiled_rules = Vec::with_capacity(policy.rules.len());
    for rule in policy.rules.iter() {
        let methods = compile_methods(&rule.methods);
        let url = match &rule.url_pattern {
            Some(pattern) => Some(compile_url_pattern(pattern).with_context(|| {
                format!("failed to compile url pattern '{}'", pattern.original)
            })?),
            None => None,
        };
        let cache = compile_cache_config(rule);

        compiled_rules.push(CompiledRule {
            id: rule.id.clone(),
            action: rule.action.clone(),
            methods,
            url,
            inspect_payload: rule.inspect_payload,
            allow_private_upstream: rule.allow_private_upstream,
            cache,
        });
    }

    Ok(CompiledPolicy {
        name: policy.name.clone(),
        rules: Arc::from(compiled_rules.into_boxed_slice()),
    })
}

fn compile_cache_config(rule: &Rule) -> Option<CompiledCacheConfig> {
    rule.cache.as_ref().map(|c| CompiledCacheConfig {
        force_cache_duration: c.force_cache_duration.map(Duration::from_secs),
    })
}

fn compile_methods(methods: &MethodMatch) -> MethodMask {
    match methods {
        MethodMatch::Any => MethodMask::any(),
        MethodMatch::List(list) => MethodMask::from_methods(list),
    }
}

fn compile_url_pattern(pattern: &UrlPattern) -> Result<UrlMatcher> {
    let host_matcher = compile_host_pattern(pattern.host.as_ref())?;
    let path = match pattern.path.as_ref() {
        Some(path) => Some(
            compile_path_pattern(path)
                .with_context(|| format!("invalid path pattern '{}'", path))?,
        ),
        None => None,
    };

    Ok(UrlMatcher {
        scheme: pattern.scheme,
        host: host_matcher,
        port: pattern.port,
        path,
        original: pattern.original.clone(),
    })
}

fn compile_host_pattern(host: &str) -> Result<HostMatcher> {
    if host == "*" {
        return Ok(HostMatcher::Any);
    }

    if !host.contains('*') {
        return Ok(HostMatcher::Exact(host.to_ascii_lowercase()));
    }

    let labels = host
        .split('.')
        .map(|label| match label {
            "*" => HostLabel::Single,
            "**" => HostLabel::Multi,
            other => HostLabel::Exact(Arc::from(other.to_ascii_lowercase())),
        })
        .collect();

    Ok(HostMatcher::Pattern(HostPattern::new(labels)))
}

fn compile_path_pattern(pattern: &Arc<str>) -> Result<PathMatcher> {
    if !pattern.starts_with('/') {
        return Err(anyhow!("path pattern must start with '/'"));
    }

    let mut regex = String::from("^/");
    let mut first_segment = true;
    for segment in pattern.split('/').skip(1) {
        if !first_segment {
            regex.push('/');
        }
        first_segment = false;

        if segment == "**" {
            regex.push_str(".*");
            continue;
        }

        let mut literal = String::new();
        let chars = segment.chars().peekable();
        for ch in chars {
            match ch {
                '*' => {
                    if !literal.is_empty() {
                        regex.push_str(&regex::escape(&literal));
                        literal.clear();
                    }
                    regex.push_str("[^/]*");
                }
                '{' | '}' => {
                    return Err(anyhow!(
                        "path pattern must not contain '{{' or '}}' segments: '{}'",
                        pattern
                    ));
                }
                _ => literal.push(ch),
            }
        }
        if !literal.is_empty() {
            regex.push_str(&regex::escape(&literal));
        }
    }

    if first_segment {
        // Pattern was just "/"; we already have "^/" in the regex.
    }

    regex.push('$');
    let compiled = Regex::new(&regex).with_context(|| format!("invalid path regex '{}'", regex))?;
    Ok(PathMatcher::new(compiled, pattern.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Client, ClientSelector, Config, MethodMatch, Policy, Rule, RuleAction, Scheme,
        ValidatedConfig,
    };
    use http::{Method, StatusCode};
    use ipnet::IpNet;

    fn sample_policy() -> Policy {
        let allow_rule = Rule {
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
            inspect_payload: true,
            allow_private_upstream: false,
            cache: None,
        };
        Policy {
            name: Arc::<str>::from("allow-api"),
            rules: Arc::from(vec![allow_rule].into_boxed_slice()),
        }
    }

    fn validated_config(config: Config) -> ValidatedConfig {
        ValidatedConfig::new(config).expect("validate config")
    }

    #[test]
    fn compile_basic_policy() {
        let deny_rule = Rule {
            id: Arc::<str>::from("deny#0"),
            action: RuleAction::Deny {
                status: StatusCode::FORBIDDEN,
                reason: None,
                body: None,
            },
            methods: MethodMatch::Any,
            url_pattern: None,
            inspect_payload: true,
            allow_private_upstream: false,
            cache: None,
        };
        let policy = Policy {
            name: Arc::<str>::from("deny-all"),
            rules: Arc::from(vec![deny_rule].into_boxed_slice()),
        };
        let compiled = compile_policy(&policy).expect("compile policy");
        assert_eq!(compiled.rules.len(), 1);
    }

    #[test]
    fn compile_full_config() {
        let clients = vec![Client {
            name: Arc::<str>::from("default"),
            selector: ClientSelector::Cidr("0.0.0.0/0".parse::<IpNet>().unwrap()),
            policies: Arc::from(
                vec![Arc::<str>::from("allow-api"), Arc::<str>::from("deny-all")]
                    .into_boxed_slice(),
            ),
            catch_all: true,
        }];

        let policies = vec![
            sample_policy(),
            Policy {
                name: Arc::<str>::from("deny-all"),
                rules: Arc::from(
                    vec![Rule {
                        id: Arc::<str>::from("deny-all#0"),
                        action: RuleAction::Deny {
                            status: StatusCode::FORBIDDEN,
                            reason: None,
                            body: None,
                        },
                        methods: MethodMatch::Any,
                        url_pattern: None,
                        inspect_payload: true,
                        allow_private_upstream: false,
                        cache: None,
                    }]
                    .into_boxed_slice(),
                ),
            },
        ];

        let config = validated_config(Config { clients, policies });
        let compiled = compile_config(&config).expect("compile config");
        assert_eq!(compiled.clients.len(), 1);
        assert_eq!(compiled.policies.len(), 2);
    }

    #[test]
    fn reject_duplicate_ip_clients() {
        let policies = vec![sample_policy()];
        let clients = vec![
            Client {
                name: Arc::<str>::from("a"),
                selector: ClientSelector::Ip("10.0.0.5".parse().unwrap()),
                policies: Arc::from(vec![policies[0].name.clone()].into_boxed_slice()),
                catch_all: false,
            },
            Client {
                name: Arc::<str>::from("b"),
                selector: ClientSelector::Ip("10.0.0.5".parse().unwrap()),
                policies: Arc::from(vec![policies[0].name.clone()].into_boxed_slice()),
                catch_all: false,
            },
        ];
        let config = Config { clients, policies };
        let err = ValidatedConfig::new(config).unwrap_err();
        assert!(
            err.to_string()
                .contains("specifies IP 10.0.0.5 which is already claimed")
        );
    }

    #[test]
    fn reject_overlapping_cidr_clients() {
        let policies = vec![sample_policy()];
        let clients = vec![
            Client {
                name: Arc::<str>::from("finance"),
                selector: ClientSelector::Cidr("10.10.1.0/24".parse::<IpNet>().unwrap()),
                policies: Arc::from(vec![policies[0].name.clone()].into_boxed_slice()),
                catch_all: false,
            },
            Client {
                name: Arc::<str>::from("ops"),
                selector: ClientSelector::Cidr("10.10.1.128/25".parse::<IpNet>().unwrap()),
                policies: Arc::from(vec![policies[0].name.clone()].into_boxed_slice()),
                catch_all: false,
            },
        ];
        let config = Config { clients, policies };
        let err = ValidatedConfig::new(config).unwrap_err();
        assert!(err.to_string().contains("overlaps with client"));
    }
}
