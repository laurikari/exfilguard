use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use http::{Method, StatusCode};
use serde::Deserialize;

use super::{
    ValidatedConfig,
    model::{
        CacheConfig, Client, ClientSelector, Config, MethodMatch, Policy, Rule, RuleAction, Scheme,
        UrlPattern,
    },
};
use crate::util::{IpOrCidr, parse_ip_or_cidr};

pub fn load_config<P: AsRef<Path>, Q: AsRef<Path>>(
    clients_path: P,
    policies_path: Q,
) -> Result<ValidatedConfig> {
    load_config_with_dirs(clients_path, None, policies_path, None)
}

pub fn load_config_with_dirs<P: AsRef<Path>, Q: AsRef<Path>>(
    clients_path: P,
    clients_dir: Option<&Path>,
    policies_path: Q,
    policies_dir: Option<&Path>,
) -> Result<ValidatedConfig> {
    let policies = load_policies(policies_path.as_ref(), policies_dir)?;
    let clients = load_clients(clients_path.as_ref(), clients_dir, &policies)?;
    let config = Config { clients, policies };
    super::ValidatedConfig::new(config)
}

fn load_clients(path: &Path, dir: Option<&Path>, policies: &[Policy]) -> Result<Vec<Client>> {
    let mut raw_clients = parse_clients_file(path)?;
    if let Some(dir) = dir {
        let files = collect_toml_files(dir, "clients")?;
        for file in files {
            raw_clients.extend(parse_clients_file(&file)?);
        }
    }

    let mut seen_names = HashSet::new();
    let mut policy_lookup: HashMap<&str, Arc<str>> = HashMap::new();
    for policy in policies {
        policy_lookup.insert(policy.name.as_ref(), policy.name.clone());
    }

    let mut clients = Vec::with_capacity(raw_clients.len());
    for client in raw_clients {
        let RawClient {
            name,
            ip,
            cidr,
            policies: policy_names,
            fallback,
        } = client;

        if !seen_names.insert(name.clone()) {
            bail!("duplicate client name '{}'", name);
        }
        let selector = match (ip, cidr) {
            (Some(ip), None) => match parse_ip_or_cidr(&ip)? {
                IpOrCidr::Ip(addr) => ClientSelector::Ip(addr),
                IpOrCidr::Cidr(_) => bail!("client '{}' ip must not be a CIDR", name),
            },
            (None, Some(cidr)) => match parse_ip_or_cidr(&cidr)? {
                IpOrCidr::Cidr(net) => ClientSelector::Cidr(net),
                IpOrCidr::Ip(_) => bail!("client '{}' cidr must include slash notation", name),
            },
            (None, None) => bail!("client '{}' must specify either ip or cidr", name),
            (Some(_), Some(_)) => bail!("client '{}' must not specify both ip and cidr", name),
        };

        if policy_names.is_empty() {
            bail!("client '{}' must reference at least one policy", name);
        }

        let mut policy_refs = Vec::with_capacity(policy_names.len());
        for policy_name in policy_names {
            let policy = policy_lookup.get(policy_name.as_str()).ok_or_else(|| {
                anyhow!(
                    "client '{}' references unknown policy '{}'",
                    name,
                    policy_name
                )
            })?;
            policy_refs.push(policy.clone());
        }

        let arc_name = Arc::<str>::from(name.as_str());
        clients.push(Client {
            name: arc_name,
            selector,
            policies: Arc::from(policy_refs.into_boxed_slice()),
            fallback,
        });
    }

    Ok(clients)
}

fn load_policies(path: &Path, dir: Option<&Path>) -> Result<Vec<Policy>> {
    let mut raw_policies = parse_policies_file(path)?;
    if let Some(dir) = dir {
        let files = collect_toml_files(dir, "policies")?;
        for file in files {
            raw_policies.extend(parse_policies_file(&file)?);
        }
    }

    if raw_policies.is_empty() {
        bail!("policies config must define at least one policy");
    }

    let mut seen_names = HashSet::new();
    let mut policies = Vec::with_capacity(raw_policies.len());
    for policy in raw_policies {
        let RawPolicy { name, rules } = policy;
        if !seen_names.insert(name.clone()) {
            bail!("duplicate policy name '{}'", name);
        }
        if rules.is_empty() {
            bail!("policy '{}' must contain at least one rule", name);
        }

        let mut compiled_rules = Vec::with_capacity(rules.len());
        let policy_name = Arc::<str>::from(name.as_str());
        for (idx, rule) in rules.into_iter().enumerate() {
            let action = parse_action(&name, &rule)?;
            let methods = parse_methods(&rule)?;
            let url_pattern = match &rule.url_pattern {
                Some(pattern) => Some(parse_url_pattern(pattern).with_context(|| {
                    format!("policy '{}' has invalid url_pattern '{}'", name, pattern)
                })?),
                None => None,
            };
            if rule.splice.is_some() {
                bail!(
                    "policy '{}' rule {} uses deprecated field 'splice'; set inspect_payload instead",
                    name,
                    idx
                );
            }
            if matches!(action, RuleAction::Deny { .. }) && !rule.inspect_payload {
                bail!(
                    "policy '{}' rule {}: inspect_payload=false is not allowed for DENY action",
                    name,
                    idx
                );
            }
            if rule.allow_private_upstream && !matches!(action, RuleAction::Allow) {
                bail!(
                    "policy '{}' rule {}: allow_private_upstream may only be used with ALLOW action",
                    name,
                    idx
                );
            }

            let id = Arc::<str>::from(format!("{}#{}", policy_name, idx));
            validate_inspection_constraints(
                &name,
                idx,
                rule.inspect_payload,
                &methods,
                &url_pattern,
            )?;
            compiled_rules.push(Rule {
                id,
                action,
                methods,
                url_pattern,
                inspect_payload: rule.inspect_payload,
                allow_private_upstream: rule.allow_private_upstream,
                cache: rule.cache.map(|c| CacheConfig {
                    force_cache_duration: c.force_cache_duration,
                }),
            });
        }

        policies.push(Policy {
            name: policy_name,
            rules: Arc::from(compiled_rules.into_boxed_slice()),
        });
    }

    Ok(policies)
}

fn parse_clients_file(path: &Path) -> Result<Vec<RawClient>> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("failed to read clients config at {}", path.display()))?;
    let doc: ClientsDoc = toml::from_str(&data)
        .with_context(|| format!("failed to parse clients config at {}", path.display()))?;
    Ok(doc.clients)
}

fn parse_policies_file(path: &Path) -> Result<Vec<RawPolicy>> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("failed to read policies config at {}", path.display()))?;
    let doc: PoliciesDoc = toml::from_str(&data)
        .with_context(|| format!("failed to parse policies config at {}", path.display()))?;
    Ok(doc.policies)
}

fn collect_toml_files(dir: &Path, kind: &str) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    if !dir.is_dir() {
        bail!(
            "{} config directory {} is not a directory",
            kind,
            dir.display()
        );
    }

    let mut files = Vec::new();
    let entries = fs::read_dir(dir)
        .with_context(|| format!("failed to read {} config directory {}", kind, dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "failed to read entry in {} directory {}",
                kind,
                dir.display()
            )
        })?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to stat {} entry {}", kind, path.display()))?;
        if file_type.is_file() && is_toml_file(&path) {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn is_toml_file(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .map(|ext| ext.eq_ignore_ascii_case("toml"))
        .unwrap_or(false)
}

fn parse_action(policy: &str, rule: &RawRule) -> Result<RuleAction> {
    let action = rule
        .action
        .as_deref()
        .ok_or_else(|| anyhow!("policy '{}' rule missing action", policy))?;
    match action {
        "ALLOW" => {
            if rule.status.is_some() {
                bail!("policy '{}' ALLOW rule must not set status", policy);
            }
            if rule.body.is_some() {
                bail!("policy '{}' ALLOW rule must not set body", policy);
            }
            if rule.reason.is_some() {
                bail!("policy '{}' ALLOW rule must not set reason", policy);
            }
            Ok(RuleAction::Allow)
        }
        "DENY" => {
            let raw_status = rule
                .status
                .ok_or_else(|| anyhow!("policy '{}' DENY rule must set status", policy))?;
            let status = StatusCode::from_u16(raw_status).with_context(|| {
                format!(
                    "policy '{}' DENY rule has invalid status code {}",
                    policy, raw_status
                )
            })?;
            let reason = match &rule.reason {
                Some(reason) => {
                    validate_reason(reason).with_context(|| {
                        format!(
                            "policy '{}' DENY rule has invalid reason phrase '{}'",
                            policy, reason
                        )
                    })?;
                    Some(Arc::<str>::from(reason.as_str()))
                }
                None => None,
            };
            let body = rule.body.clone().map(Arc::<str>::from);
            Ok(RuleAction::Deny {
                status,
                reason,
                body,
            })
        }
        other => bail!("policy '{}' has unsupported action '{}'", policy, other),
    }
}

fn parse_methods(rule: &RawRule) -> Result<MethodMatch> {
    match &rule.methods {
        None => Ok(MethodMatch::Any),
        Some(methods) if methods.is_empty() => bail!("methods array must not be empty"),
        Some(methods) => {
            if methods.len() == 1 && methods[0].eq_ignore_ascii_case("ANY") {
                return Ok(MethodMatch::Any);
            }
            let mut seen = HashSet::new();
            let mut parsed = Vec::with_capacity(methods.len());
            for method in methods {
                if method.eq_ignore_ascii_case("ANY") {
                    bail!("methods array must not mix ANY with explicit methods");
                }
                let normalized = method.to_ascii_uppercase();
                let parsed_method: Method = normalized
                    .parse()
                    .with_context(|| format!("invalid HTTP method '{}' in policy rule", method))?;
                if !seen.insert(parsed_method.clone()) {
                    bail!("duplicate HTTP method '{}' in policy rule", method);
                }
                parsed.push(parsed_method);
            }
            Ok(MethodMatch::List(parsed))
        }
    }
}

fn parse_url_pattern(raw: &str) -> Result<UrlPattern> {
    let (scheme_part, rest) = raw
        .split_once("://")
        .ok_or_else(|| anyhow!("pattern must include scheme"))?;
    let scheme = match scheme_part {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        other => bail!("unsupported scheme '{}'", other),
    };

    if rest.is_empty() {
        bail!("pattern must include host");
    }

    let mut host_and_path = rest.splitn(2, '/');
    let host_port = host_and_path
        .next()
        .ok_or_else(|| anyhow!("pattern missing host"))?;

    let (host, port) = parse_host_and_port(host_port)?;
    validate_host_pattern(host)?;

    let path = host_and_path.next().map(|path| format!("/{}", path));
    if let Some(path_ref) = path.as_ref() {
        validate_path_pattern(path_ref)?;
    }

    Ok(UrlPattern {
        scheme,
        host: Arc::<str>::from(host.to_string()),
        port,
        path: path.map(Arc::<str>::from),
        original: Arc::<str>::from(raw.to_string()),
    })
}

fn parse_host_and_port(value: &str) -> Result<(&str, Option<u16>)> {
    if value.starts_with('[') {
        let end = value
            .find(']')
            .ok_or_else(|| anyhow!("invalid IPv6 host pattern"))?;
        let host = &value[1..end];
        let rest = &value[end + 1..];
        if rest.is_empty() {
            return Ok((host, None));
        }
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("invalid port delimiter in host"))?;
        let port_num: u16 = port
            .parse()
            .with_context(|| format!("invalid port '{}'", port))?;
        return Ok((host, Some(port_num)));
    }

    if let Some((host_part, port_part)) = value.rsplit_once(':')
        && !port_part.is_empty()
        && port_part.chars().all(|c| c.is_ascii_digit())
    {
        let port_num: u16 = port_part.parse().context("invalid port")?;
        if host_part.is_empty() {
            bail!("host must not be empty");
        }
        return Ok((host_part, Some(port_num)));
    }

    if value.is_empty() {
        bail!("host must not be empty");
    }

    Ok((value, None))
}

fn validate_host_pattern(host: &str) -> Result<()> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if host.contains('*') {
            bail!("IP literals must not contain '*'");
        }
        // Additional validation already handled by parse::<IpAddr>.
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

#[derive(Debug, Deserialize)]
struct ClientsDoc {
    #[serde(default, rename = "client")]
    clients: Vec<RawClient>,
}

#[derive(Debug, Deserialize)]
struct RawClient {
    name: String,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    cidr: Option<String>,
    #[serde(default)]
    policies: Vec<String>,
    #[serde(default)]
    fallback: bool,
}

#[derive(Debug, Deserialize)]
struct PoliciesDoc {
    #[serde(default, rename = "policy")]
    policies: Vec<RawPolicy>,
}

#[derive(Debug, Deserialize)]
struct RawPolicy {
    name: String,
    #[serde(default, rename = "rule")]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
struct RawCacheConfig {
    #[serde(default)]
    force_cache_duration: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    #[serde(default)]
    url_pattern: Option<String>,
    #[serde(default)]
    methods: Option<Vec<String>>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default = "default_inspect_payload")]
    inspect_payload: bool,
    #[serde(default)]
    splice: Option<bool>,
    #[serde(default)]
    allow_private_upstream: bool,
    #[serde(default)]
    cache: Option<RawCacheConfig>,
}

fn default_inspect_payload() -> bool {
    true
}

fn validate_inspection_constraints(
    policy: &str,
    idx: usize,
    inspect_payload: bool,
    methods: &MethodMatch,
    url_pattern: &Option<UrlPattern>,
) -> Result<()> {
    if inspect_payload {
        return Ok(());
    }

    match methods {
        MethodMatch::Any => bail!(
            "policy '{}' rule {}: inspect_payload=false rules must restrict methods to CONNECT",
            policy,
            idx
        ),
        MethodMatch::List(list) => {
            if !list.iter().all(|method| method == Method::CONNECT) {
                bail!(
                    "policy '{}' rule {}: inspect_payload=false rules must restrict methods to CONNECT",
                    policy,
                    idx
                );
            }
        }
    }

    let pattern = url_pattern.as_ref().ok_or_else(|| {
        anyhow!(
            "policy '{}' rule {}: inspect_payload=false requires url_pattern ending with '/**'",
            policy,
            idx
        )
    })?;

    match pattern.path.as_ref().map(|path| path.as_ref()) {
        Some("/**") => Ok(()),
        _ => bail!(
            "policy '{}' rule {}: inspect_payload=false requires url_pattern ending with '/**'",
            policy,
            idx
        ),
    }
}

fn validate_reason(reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        bail!("reason must not be empty");
    }
    if reason.chars().any(|c| c == '\r' || c == '\n') {
        bail!("reason must not contain CR or LF characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    fn write_temp(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    fn write_dir_file(dir: &TempDir, name: &str, content: &str) {
        let path = dir.path().join(name);
        fs::write(path, content).unwrap();
    }

    #[test]
    fn load_valid_configs() {
        let clients = write_temp(
            r#"[[client]]
name = "localhost"
ip = "127.0.0.1"
policies = ["allow"]

[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["deny"]
fallback = true
"#,
        );
        let policies = write_temp(
            r#"[[policy]]
name = "deny"
  [[policy.rule]]
  action = "DENY"
  status = 403

[[policy]]
name = "allow"
  [[policy.rule]]
  action = "ALLOW"
  url_pattern = "http://example.com/api/**"
  methods = ["GET", "POST"]
"#,
        );

        let config = load_config(clients.path(), policies.path()).expect("load config");
        assert_eq!(config.clients.len(), 2);
        assert_eq!(config.policies.len(), 2);
    }

    #[test]
    fn reject_unknown_policy() {
        let clients = write_temp(
            r#"[[client]]
name = "test"
ip = "127.0.0.1"
policies = ["missing"]
fallback = true
"#,
        );
        let policies = write_temp(
            r#"[[policy]]
name = "only"
  [[policy.rule]]
  action = "DENY"
  status = 403
"#,
        );

        let err = load_config(clients.path(), policies.path()).unwrap_err();
        assert!(err.to_string().contains("unknown policy"));
    }

    #[test]
    fn deny_reason_parsed() {
        let clients = write_temp(
            r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["deny"]
fallback = true
"#,
        );
        let policies = write_temp(
            r#"[[policy]]
name = "deny"
  [[policy.rule]]
  action = "DENY"
  status = 470
  reason = "Policy Blocked"
"#,
        );

        let config = load_config(clients.path(), policies.path()).expect("load config");
        let policy = &config.policies[0];
        match &policy.rules[0].action {
            RuleAction::Deny { reason, .. } => {
                assert_eq!(reason.as_ref().map(|r| r.as_ref()), Some("Policy Blocked"))
            }
            other => panic!("expected deny action, got {:?}", other),
        }
    }

    #[test]
    fn reject_duplicate_client_ip() {
        let clients = write_temp(
            r#"[[client]]
name = "a"
ip = "10.0.0.5"
policies = ["allow"]
fallback = true

[[client]]
name = "b"
ip = "10.0.0.5"
policies = ["allow"]
"#,
        );
        let policies = write_temp(
            r#"[[policy]]
name = "allow"
  [[policy.rule]]
  action = "ALLOW"
"#,
        );
        let err = load_config(clients.path(), policies.path()).unwrap_err();
        assert!(err.to_string().contains("already claimed"));
    }

    #[test]
    fn reject_overlapping_client_cidrs() {
        let clients = write_temp(
            r#"[[client]]
name = "finance"
cidr = "10.10.1.0/24"
policies = ["allow"]
fallback = false

[[client]]
name = "ops"
cidr = "10.10.1.128/25"
policies = ["allow"]

[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow"]
fallback = true
"#,
        );
        let policies = write_temp(
            r#"[[policy]]
name = "allow"
  [[policy.rule]]
  action = "ALLOW"
"#,
        );
        let err = load_config(clients.path(), policies.path()).unwrap_err();
        assert!(err.to_string().contains("overlaps"));
    }

    #[test]
    fn reject_ip_overlaps_cidr() {
        let clients = write_temp(
            r#"[[client]]
name = "range"
cidr = "10.10.1.0/24"
policies = ["allow"]

[[client]]
name = "pin"
ip = "10.10.1.5"
policies = ["allow"]

[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow"]
fallback = true
"#,
        );
        let policies = write_temp(
            r#"[[policy]]
name = "allow"
  [[policy.rule]]
  action = "ALLOW"
"#,
        );
        let err = load_config(clients.path(), policies.path()).unwrap_err();
        assert!(err.to_string().contains("overlaps"));
    }

    #[test]
    fn fallback_overlap_is_allowed_regardless_of_order() {
        let clients = write_temp(
            r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow"]
fallback = true

[[client]]
name = "finance"
cidr = "10.10.1.0/24"
policies = ["allow"]
"#,
        );
        let policies = write_temp(
            r#"[[policy]]
name = "allow"
  [[policy.rule]]
  action = "ALLOW"
"#,
        );
        let config = load_config(clients.path(), policies.path()).expect("config should load");
        assert_eq!(config.clients.len(), 2);
    }

    #[test]
    fn reject_inspect_payload_false_without_connect_methods() {
        let clients = write_temp(
            r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["pass"]
fallback = true
"#,
        );
        let policies = write_temp(
            r#"[[policy]]
name = "pass"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "https://example.com/**"
  inspect_payload = false
"#,
        );
        let err = load_config(clients.path(), policies.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("inspect_payload=false rules must restrict methods to CONNECT")
        );
    }

    #[test]
    fn reject_inspect_payload_false_without_wildcard_path() {
        let clients = write_temp(
            r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["pass"]
fallback = true
"#,
        );
        let policies = write_temp(
            r#"[[policy]]
name = "pass"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["CONNECT"]
  url_pattern = "https://example.com/strict"
  inspect_payload = false
"#,
        );
        let err = load_config(clients.path(), policies.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("inspect_payload=false requires url_pattern ending with '/**'")
        );
    }

    #[test]
    fn clients_directory_is_loaded() {
        let clients = write_temp(
            r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow"]
fallback = true
"#,
        );
        let clients_dir = TempDir::new().unwrap();
        write_dir_file(
            &clients_dir,
            "workers.toml",
            r#"[[client]]
name = "workers"
cidr = "10.0.0.0/25"
policies = ["allow"]
"#,
        );
        let policies = write_temp(
            r#"[[policy]]
name = "allow"
  [[policy.rule]]
  action = "ALLOW"
"#,
        );
        let config = load_config_with_dirs(
            clients.path(),
            Some(clients_dir.path()),
            policies.path(),
            None,
        )
        .expect("config should load with clients.d");
        assert_eq!(config.clients.len(), 2);
    }

    #[test]
    fn duplicate_policy_names_across_directory_are_rejected() {
        let clients = write_temp(
            r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow"]
fallback = true
"#,
        );
        let policies = write_temp(
            r#"[[policy]]
name = "allow"
  [[policy.rule]]
  action = "ALLOW"
"#,
        );
        let policies_dir = TempDir::new().unwrap();
        write_dir_file(
            &policies_dir,
            "dup.toml",
            r#"[[policy]]
name = "allow"
  [[policy.rule]]
  action = "ALLOW"
"#,
        );
        let err = load_config_with_dirs(
            clients.path(),
            None,
            policies.path(),
            Some(policies_dir.path()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate policy name"));
    }
}
