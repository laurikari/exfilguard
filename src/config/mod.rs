mod loader;
pub mod model;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::ops::Deref;

use anyhow::{Context, Result, bail, ensure};
use http::Method;
use ipnet::IpNet;

pub use loader::{load_config, load_config_with_dirs};
pub use model::{
    Client, ClientSelector, Config, HttpsMode, MethodMatch, Policy, Rule, RuleAction, Scheme,
    UrlPattern,
};

use crate::util::cidrs_overlap;

fn methods_include_connect(methods: &MethodMatch) -> bool {
    match methods {
        MethodMatch::Any => false,
        MethodMatch::List(list) => list.contains(&Method::CONNECT),
    }
}

fn methods_connect_only(methods: &MethodMatch) -> bool {
    match methods {
        MethodMatch::Any => false,
        MethodMatch::List(list) => list.len() == 1 && list[0] == Method::CONNECT,
    }
}

fn validate_host_pattern(host: &str) -> Result<()> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if host.contains('*') {
            bail!("IP literals must not contain '*'");
        }
        match ip {
            IpAddr::V4(_) | IpAddr::V6(_) => return Ok(()),
        }
    }

    if host.contains('/') {
        bail!("host must not contain '/'");
    }

    if host.chars().any(|c| c.is_whitespace()) {
        bail!("host must not contain whitespace");
    }

    for label in host.split('.') {
        if label.is_empty() {
            bail!("host contains empty label");
        }
        if label == "*" || label == "**" {
            continue;
        }
        if label.contains('*') {
            bail!("'*' may only appear as entire host label");
        }
        for ch in label.chars() {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                continue;
            }
            bail!("host label '{}' contains invalid character '{}'", label, ch);
        }
    }

    Ok(())
}

fn validate_path_pattern(path: &str) -> Result<()> {
    if !path.starts_with('/') {
        bail!("path pattern must start with '/'");
    }
    for segment in path.split('/').skip(1) {
        if segment.is_empty() {
            continue;
        }
        if segment == "*" || segment == "**" {
            continue;
        }
        if segment.contains('{') || segment.contains('}') {
            bail!("path segment '{}' must not contain '{{' or '}}'", segment);
        }
        if segment.contains("**") {
            bail!("'**' may only appear as its own segment");
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._*".contains(c))
        {
            bail!("path segment '{}' contains invalid character", segment);
        }
    }
    Ok(())
}

fn validate_reason(reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        bail!("reason must not be empty");
    }
    if reason.contains('\r') || reason.contains('\n') {
        bail!("reason must not contain CR or LF");
    }
    Ok(())
}

fn validate_connect_pattern(
    policy: &str,
    idx: usize,
    url_pattern: &Option<UrlPattern>,
) -> Result<()> {
    let pattern = url_pattern.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "policy '{}' rule {}: CONNECT rules require https:// url_pattern ending with '/**'",
            policy,
            idx
        )
    })?;
    if pattern.scheme != Scheme::Https {
        bail!(
            "policy '{}' rule {}: CONNECT rules must use https:// url_pattern",
            policy,
            idx
        );
    }
    match pattern.path.as_ref().map(|path| path.as_ref()) {
        Some("/**") => Ok(()),
        _ => bail!(
            "policy '{}' rule {}: CONNECT rules require https:// url_pattern ending with '/**'",
            policy,
            idx
        ),
    }
}

fn validate_rule_constraints(
    policy: &str,
    idx: usize,
    https_mode: HttpsMode,
    methods: &MethodMatch,
    url_pattern: &Option<UrlPattern>,
) -> Result<()> {
    let connect_only = methods_connect_only(methods);
    match https_mode {
        HttpsMode::Inspect => {
            if connect_only {
                bail!(
                    "policy '{}' rule {}: CONNECT rules must set https_mode = \"tunnel\"",
                    policy,
                    idx
                );
            }
            Ok(())
        }
        HttpsMode::Tunnel => {
            if !connect_only {
                bail!(
                    "policy '{}' rule {}: https_mode=\"tunnel\" rules must restrict methods to CONNECT",
                    policy,
                    idx
                );
            }
            validate_connect_pattern(policy, idx, url_pattern)
        }
    }
}

fn validate_policy_rules(policy: &Policy) -> Result<()> {
    if policy.rules.is_empty() {
        bail!("policy '{}' must contain at least one rule", policy.name);
    }

    let mut seen_non_connect_rule = false;
    for (idx, rule) in policy.rules.iter().enumerate() {
        let has_connect = methods_include_connect(&rule.methods);
        let is_connect_only = methods_connect_only(&rule.methods);
        if has_connect && !is_connect_only {
            bail!(
                "policy '{}' rule {}: CONNECT method must not be combined with other methods",
                policy.name,
                idx
            );
        }
        if is_connect_only {
            if seen_non_connect_rule {
                bail!(
                    "policy '{}' rule {}: CONNECT rules must appear before non-CONNECT rules",
                    policy.name,
                    idx
                );
            }
        } else {
            seen_non_connect_rule = true;
        }

        if let Some(pattern) = &rule.url_pattern {
            validate_host_pattern(pattern.host.as_ref()).with_context(|| {
                format!(
                    "policy '{}' has invalid url_pattern '{}'",
                    policy.name, pattern.original
                )
            })?;
            if let Some(path) = &pattern.path {
                validate_path_pattern(path.as_ref()).with_context(|| {
                    format!(
                        "policy '{}' has invalid url_pattern '{}'",
                        policy.name, pattern.original
                    )
                })?;
            }
        }

        if let RuleAction::Deny {
            reason: Some(reason),
            ..
        } = &rule.action
        {
            validate_reason(reason).with_context(|| {
                format!(
                    "policy '{}' DENY rule has invalid reason phrase '{}'",
                    policy.name, reason
                )
            })?;
        }

        validate_rule_constraints(
            policy.name.as_ref(),
            idx,
            rule.https_mode,
            &rule.methods,
            &rule.url_pattern,
        )?;
    }

    Ok(())
}

fn validate_config(config: &Config) -> Result<()> {
    ensure!(
        !config.policies.is_empty(),
        "policies config must define at least one policy"
    );

    let mut policy_names = HashSet::new();
    for policy in &config.policies {
        if !policy_names.insert(policy.name.as_ref()) {
            bail!("duplicate policy name '{}'", policy.name);
        }
        validate_policy_rules(policy)?;
    }

    let mut client_names = HashSet::new();
    for client in &config.clients {
        if !client_names.insert(client.name.as_ref()) {
            bail!("duplicate client name '{}'", client.name);
        }
        if client.policies.is_empty() {
            bail!(
                "client '{}' must reference at least one policy",
                client.name
            );
        }
        for policy_name in client.policies.iter() {
            if !policy_names.contains(policy_name.as_ref()) {
                bail!(
                    "client '{}' references unknown policy '{}'",
                    client.name,
                    policy_name
                );
            }
        }
    }

    validate_clients(&config.clients)
}

/// Ensures that client selectors do not conflict (duplicate IPs or overlapping CIDRs except for the
/// designated fallback). This validation is shared by both the configuration loader and
/// the policy compiler so that runtime policy reloads and programmatic configs
/// get identical guarantees.
pub fn validate_clients(clients: &[Client]) -> Result<()> {
    struct CidrClaim<'a> {
        name: &'a str,
        net: IpNet,
        fallback: bool,
    }

    struct IpClaim<'a> {
        name: &'a str,
        fallback: bool,
    }

    let mut fallback_seen = false;
    let mut ip_claims: HashMap<IpAddr, IpClaim<'_>> = HashMap::new();
    let mut cidr_claims: Vec<CidrClaim<'_>> = Vec::new();

    for client in clients {
        if client.fallback {
            ensure!(
                !fallback_seen,
                "multiple fallback clients defined; exactly one client must set fallback=true"
            );
            fallback_seen = true;
        }

        match &client.selector {
            ClientSelector::Ip(addr) => {
                if let Some(existing) = ip_claims.insert(
                    *addr,
                    IpClaim {
                        name: client.name.as_ref(),
                        fallback: client.fallback,
                    },
                ) {
                    bail!(
                        "client '{}' specifies IP {} which is already claimed by client '{}'",
                        client.name,
                        addr,
                        existing.name
                    );
                }
                for claim in &cidr_claims {
                    if client.fallback || claim.fallback {
                        continue;
                    }
                    if claim.net.contains(addr) {
                        bail!(
                            "client '{}' IP {} overlaps with client '{}' CIDR {}",
                            client.name,
                            addr,
                            claim.name,
                            claim.net
                        );
                    }
                }
            }
            ClientSelector::Cidr(net) => {
                for claim in &cidr_claims {
                    if client.fallback || claim.fallback {
                        continue;
                    }
                    if cidrs_overlap(&claim.net, net) {
                        bail!(
                            "client '{}' CIDR {} overlaps with client '{}' CIDR {}",
                            client.name,
                            net,
                            claim.name,
                            claim.net
                        );
                    }
                }
                for (addr, claim) in &ip_claims {
                    if client.fallback || claim.fallback {
                        continue;
                    }
                    if net.contains(addr) {
                        bail!(
                            "client '{}' CIDR {} overlaps with client '{}' IP {}",
                            client.name,
                            net,
                            claim.name,
                            addr
                        );
                    }
                }
                cidr_claims.push(CidrClaim {
                    name: client.name.as_ref(),
                    net: *net,
                    fallback: client.fallback,
                });
            }
        }
    }

    ensure!(
        fallback_seen,
        "exactly one client must set fallback=true to act as the fallback"
    );

    Ok(())
}

#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    inner: Config,
}

impl ValidatedConfig {
    pub fn new(config: Config) -> Result<Self> {
        validate_config(&config)?;
        Ok(Self { inner: config })
    }

    pub fn into_inner(self) -> Config {
        self.inner
    }
}

impl AsRef<Config> for ValidatedConfig {
    fn as_ref(&self) -> &Config {
        &self.inner
    }
}

impl Deref for ValidatedConfig {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Client, ClientSelector, Config, HttpsMode, MethodMatch, Policy, Rule, RuleAction, Scheme,
        UrlPattern, ValidatedConfig,
    };
    use http::{Method, StatusCode};
    use ipnet::IpNet;
    use std::sync::Arc;

    fn fallback_client(policy_name: &str) -> Client {
        Client {
            name: Arc::from("default"),
            selector: ClientSelector::Cidr("0.0.0.0/0".parse::<IpNet>().unwrap()),
            policies: Arc::from(vec![Arc::<str>::from(policy_name)].into_boxed_slice()),
            fallback: true,
        }
    }

    fn allow_rule(
        methods: MethodMatch,
        https_mode: HttpsMode,
        url_pattern: Option<UrlPattern>,
    ) -> Rule {
        Rule {
            id: Arc::from("rule#0"),
            action: RuleAction::Allow,
            methods,
            url_pattern,
            https_mode,
            cache: None,
        }
    }

    #[test]
    fn validated_config_rejects_unknown_policy_references() {
        let config = Config {
            clients: vec![fallback_client("missing")],
            policies: vec![Policy {
                name: Arc::from("known"),
                rules: Arc::from(
                    vec![allow_rule(MethodMatch::Any, HttpsMode::Inspect, None)].into_boxed_slice(),
                ),
            }],
        };

        let err = ValidatedConfig::new(config).unwrap_err();
        assert!(err.to_string().contains("references unknown policy"));
    }

    #[test]
    fn validated_config_rejects_invalid_tunnel_rule() {
        let config = Config {
            clients: vec![fallback_client("allow")],
            policies: vec![Policy {
                name: Arc::from("allow"),
                rules: Arc::from(
                    vec![allow_rule(
                        MethodMatch::List(vec![Method::GET]),
                        HttpsMode::Tunnel,
                        Some(UrlPattern {
                            scheme: Scheme::Https,
                            host: Arc::from("example.com"),
                            port: None,
                            path: Some(Arc::from("/**")),
                            original: Arc::from("https://example.com/**"),
                        }),
                    )]
                    .into_boxed_slice(),
                ),
            }],
        };

        let err = ValidatedConfig::new(config).unwrap_err();
        assert!(
            err.to_string()
                .contains("https_mode=\"tunnel\" rules must restrict methods to CONNECT")
        );
    }

    #[test]
    fn validated_config_rejects_invalid_deny_reason() {
        let config = Config {
            clients: vec![fallback_client("deny")],
            policies: vec![Policy {
                name: Arc::from("deny"),
                rules: Arc::from(
                    vec![Rule {
                        id: Arc::from("rule#0"),
                        action: RuleAction::Deny {
                            status: StatusCode::FORBIDDEN,
                            reason: Some(Arc::from("bad\r\nreason")),
                            body: None,
                        },
                        methods: MethodMatch::Any,
                        url_pattern: None,
                        https_mode: HttpsMode::Inspect,
                        cache: None,
                    }]
                    .into_boxed_slice(),
                ),
            }],
        };

        let err = ValidatedConfig::new(config).unwrap_err();
        assert!(err.to_string().contains("invalid reason phrase"));
    }
}
