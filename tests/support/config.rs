use std::fmt::Write;

#[derive(Debug, Clone, Default)]
pub struct TestConfigBuilder {
    clients: Vec<ClientSpec>,
    policies: Vec<PolicySpec>,
}

impl TestConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn default_client(mut self, policies: &[&str]) -> Self {
        self.clients
            .push(ClientSpec::cidr("default", "0.0.0.0/0", policies, true));
        self
    }

    pub fn client_cidr(
        mut self,
        name: &str,
        cidr: &str,
        policies: &[&str],
        fallback: bool,
    ) -> Self {
        self.clients
            .push(ClientSpec::cidr(name, cidr, policies, fallback));
        self
    }

    pub fn client_ip(mut self, name: &str, ip: &str, policies: &[&str], fallback: bool) -> Self {
        self.clients
            .push(ClientSpec::ip(name, ip, policies, fallback));
        self
    }

    pub fn policy(mut self, policy: PolicySpec) -> Self {
        self.policies.push(policy);
        self
    }

    pub fn render(self) -> (String, String) {
        let mut clients_doc = String::new();
        for (idx, client) in self.clients.iter().enumerate() {
            if idx > 0 {
                clients_doc.push('\n');
            }
            let _ = writeln!(clients_doc, "[[client]]");
            let _ = writeln!(clients_doc, "name = \"{}\"", toml_escape(&client.name));
            match &client.selector {
                ClientSelectorSpec::Ip(ip) => {
                    let _ = writeln!(clients_doc, "ip = \"{}\"", toml_escape(ip));
                }
                ClientSelectorSpec::Cidr(cidr) => {
                    let _ = writeln!(clients_doc, "cidr = \"{}\"", toml_escape(cidr));
                }
            }
            let _ = writeln!(
                clients_doc,
                "policies = [{}]",
                format_string_list(&client.policies)
            );
            if client.fallback {
                let _ = writeln!(clients_doc, "fallback = true");
            }
        }

        let mut policies_doc = String::new();
        for (idx, policy) in self.policies.iter().enumerate() {
            if idx > 0 {
                policies_doc.push('\n');
            }
            let _ = writeln!(policies_doc, "[[policy]]");
            let _ = writeln!(policies_doc, "name = \"{}\"", toml_escape(&policy.name));
            for rule in &policy.rules {
                let _ = writeln!(policies_doc, "  [[policy.rule]]");
                let action = match rule.action {
                    ActionSpec::Allow => "ALLOW",
                    ActionSpec::Deny => "DENY",
                };
                let _ = writeln!(policies_doc, "  action = \"{}\"", action);
                if let Some(methods) = &rule.methods {
                    let _ = writeln!(
                        policies_doc,
                        "  methods = [{}]",
                        format_string_list(methods)
                    );
                }
                if let Some(status) = rule.status {
                    let _ = writeln!(policies_doc, "  status = {}", status);
                }
                if let Some(reason) = &rule.reason {
                    let _ = writeln!(policies_doc, "  reason = \"{}\"", toml_escape(reason));
                }
                if let Some(body) = &rule.body {
                    let _ = writeln!(policies_doc, "  body = \"{}\"", toml_escape(body));
                }
                if let Some(pattern) = &rule.url_pattern {
                    let _ = writeln!(policies_doc, "  url_pattern = \"{}\"", toml_escape(pattern));
                }
                if let Some(inspect_payload) = rule.inspect_payload {
                    let _ = writeln!(policies_doc, "  inspect_payload = {}", inspect_payload);
                }
                if let Some(allow_private_upstream) = rule.allow_private_upstream {
                    let _ = writeln!(
                        policies_doc,
                        "  allow_private_upstream = {}",
                        allow_private_upstream
                    );
                }
                if let Some(cache) = &rule.cache {
                    let _ = writeln!(policies_doc, "  [policy.rule.cache]");
                    if let Some(duration) = cache.force_cache_duration {
                        let _ = writeln!(policies_doc, "  force_cache_duration = {}", duration);
                    }
                }
            }
        }

        (clients_doc, policies_doc)
    }
}

#[derive(Debug, Clone)]
pub struct ClientSpec {
    name: String,
    selector: ClientSelectorSpec,
    policies: Vec<String>,
    fallback: bool,
}

impl ClientSpec {
    pub fn cidr(name: &str, cidr: &str, policies: &[&str], fallback: bool) -> Self {
        Self {
            name: name.to_string(),
            selector: ClientSelectorSpec::Cidr(cidr.to_string()),
            policies: policies
                .iter()
                .map(|policy| (*policy).to_string())
                .collect(),
            fallback,
        }
    }

    pub fn ip(name: &str, ip: &str, policies: &[&str], fallback: bool) -> Self {
        Self {
            name: name.to_string(),
            selector: ClientSelectorSpec::Ip(ip.to_string()),
            policies: policies
                .iter()
                .map(|policy| (*policy).to_string())
                .collect(),
            fallback,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ClientSelectorSpec {
    Ip(String),
    Cidr(String),
}

#[derive(Debug, Clone)]
pub struct PolicySpec {
    name: String,
    rules: Vec<RuleSpec>,
}

impl PolicySpec {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            rules: Vec::new(),
        }
    }

    pub fn rule(mut self, rule: RuleSpec) -> Self {
        self.rules.push(rule);
        self
    }
}

#[derive(Debug, Clone)]
pub struct RuleSpec {
    action: ActionSpec,
    methods: Option<Vec<String>>,
    url_pattern: Option<String>,
    inspect_payload: Option<bool>,
    allow_private_upstream: Option<bool>,
    status: Option<u16>,
    reason: Option<String>,
    body: Option<String>,
    cache: Option<CacheSpec>,
}

#[derive(Debug, Clone, Copy)]
pub enum ActionSpec {
    Allow,
    Deny,
}

impl RuleSpec {
    pub fn allow(methods: &[&str], url_pattern: impl Into<String>) -> Self {
        Self {
            action: ActionSpec::Allow,
            methods: Some(methods.iter().map(|method| (*method).to_string()).collect()),
            url_pattern: Some(url_pattern.into()),
            inspect_payload: None,
            allow_private_upstream: None,
            status: None,
            reason: None,
            body: None,
            cache: None,
        }
    }

    pub fn allow_any(url_pattern: impl Into<String>) -> Self {
        Self::allow(&["ANY"], url_pattern)
    }

    pub fn deny(methods: &[&str], url_pattern: impl Into<String>) -> Self {
        Self {
            action: ActionSpec::Deny,
            methods: Some(methods.iter().map(|method| (*method).to_string()).collect()),
            url_pattern: Some(url_pattern.into()),
            inspect_payload: None,
            allow_private_upstream: None,
            status: None,
            reason: None,
            body: None,
            cache: None,
        }
    }

    pub fn inspect_payload(mut self, inspect_payload: bool) -> Self {
        self.inspect_payload = Some(inspect_payload);
        self
    }

    pub fn allow_private_upstream(mut self, allow_private_upstream: bool) -> Self {
        self.allow_private_upstream = Some(allow_private_upstream);
        self
    }

    pub fn status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    pub fn reason(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_string());
        self
    }

    pub fn body(mut self, body: &str) -> Self {
        self.body = Some(body.to_string());
        self
    }

    pub fn cache_enabled(mut self) -> Self {
        self.cache = Some(CacheSpec {
            force_cache_duration: None,
        });
        self
    }

    pub fn cache_force_duration(mut self, duration_seconds: u64) -> Self {
        self.cache = Some(CacheSpec {
            force_cache_duration: Some(duration_seconds),
        });
        self
    }
}

fn format_string_list(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("\"{}\"", toml_escape(value)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn toml_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[derive(Debug, Clone)]
pub struct CacheSpec {
    force_cache_duration: Option<u64>,
}
