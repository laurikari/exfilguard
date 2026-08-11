use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail, ensure};
use serde::Deserialize;

const fn default_token_header_size() -> usize {
    1024
}

const fn default_cache_capacity() -> usize {
    4096
}

const fn default_cache_duration() -> u64 {
    30
}

const fn default_negative_cache_duration() -> u64 {
    1
}

const fn default_remote_timeout() -> u64 {
    5
}

const fn default_remote_concurrency() -> usize {
    32
}

const fn default_policy_response_size() -> usize {
    256 * 1024
}

const fn default_policy_rule_count() -> usize {
    1024
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationSettings {
    #[serde(default, rename = "service")]
    pub services: Vec<AuthorizationServiceSettings>,
    #[serde(default = "default_token_header_size")]
    pub max_token_header_size: usize,
    #[serde(default = "default_cache_capacity")]
    pub policy_cache_capacity: usize,
    #[serde(default = "default_cache_duration")]
    pub max_policy_cache_duration: u64,
    #[serde(default = "default_negative_cache_duration")]
    pub negative_cache_duration: u64,
    #[serde(default = "default_policy_response_size")]
    pub max_policy_response_size: usize,
    #[serde(default = "default_policy_rule_count")]
    pub max_policy_rules: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationServiceSettings {
    pub name: String,
    pub audience: String,
    pub policy_url: String,
    pub server_ca_cert: PathBuf,
    pub client_certificate: AuthorizationClientCertificateSettings,
    #[serde(default = "default_remote_timeout")]
    pub timeout: u64,
    #[serde(default = "default_remote_concurrency")]
    pub max_concurrency: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorizationClientCertificateSettings {
    Files { cert: PathBuf, key: PathBuf },
}

impl AuthorizationSettings {
    pub(crate) fn apply_base_dir(&mut self, base_dir: &Path) {
        for service in &mut self.services {
            service.apply_base_dir(base_dir);
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.services.is_empty(),
            "authorization.service must define at least one service"
        );
        ensure!(
            self.max_token_header_size > 0,
            "authorization.max_token_header_size must be greater than 0"
        );
        ensure!(
            self.policy_cache_capacity > 0,
            "authorization.policy_cache_capacity must be greater than 0"
        );
        ensure!(
            self.max_policy_cache_duration > 0,
            "authorization.max_policy_cache_duration must be greater than 0 seconds"
        );
        ensure!(
            self.negative_cache_duration > 0
                && self.negative_cache_duration <= self.max_policy_cache_duration,
            "authorization.negative_cache_duration must be between 1 and max_policy_cache_duration"
        );
        ensure!(
            self.max_policy_response_size > 0,
            "authorization.max_policy_response_size must be greater than 0"
        );
        ensure!(
            self.max_policy_rules > 0,
            "authorization.max_policy_rules must be greater than 0"
        );
        let mut names = HashSet::new();
        for service in &self.services {
            service.validate()?;
            ensure!(
                names.insert(service.name.as_str()),
                "duplicate authorization service '{}'",
                service.name
            );
        }
        Ok(())
    }

    pub(crate) fn validate_clients(&self, clients: &[crate::config::Client]) -> Result<()> {
        let service_names: HashSet<&str> = self
            .services
            .iter()
            .map(|service| service.name.as_str())
            .collect();
        for client in clients {
            if let Some(service) = &client.authorization_service {
                ensure!(
                    service_names.contains(service.as_ref()),
                    "client '{}' references unknown authorization service '{}'",
                    client.name,
                    service
                );
            }
        }
        Ok(())
    }
}

impl AuthorizationServiceSettings {
    fn apply_base_dir(&mut self, base_dir: &Path) {
        self.server_ca_cert = absolutize(&self.server_ca_cert, base_dir);
        match &mut self.client_certificate {
            AuthorizationClientCertificateSettings::Files { cert, key } => {
                *cert = absolutize(cert, base_dir);
                *key = absolutize(key, base_dir);
            }
        }
    }

    fn validate(&self) -> Result<()> {
        let field = format!("authorization.service[{}]", self.name);
        ensure_nonempty(&format!("{field}.name"), &self.name)?;
        ensure_nonempty(&format!("{field}.audience"), &self.audience)?;
        validate_url(&format!("{field}.policy_url"), &self.policy_url)?;
        ensure!(self.timeout > 0, "{field}.timeout must be greater than 0");
        ensure!(
            self.max_concurrency > 0 && self.max_concurrency <= tokio::sync::Semaphore::MAX_PERMITS,
            "{field}.max_concurrency must be within the runtime semaphore limit"
        );
        match &self.client_certificate {
            AuthorizationClientCertificateSettings::Files { cert, key } => {
                if cert == key {
                    bail!(
                        "{field}.client_certificate.cert and client_certificate.key must be different files"
                    );
                }
            }
        }
        Ok(())
    }
}

fn validate_url(field: &str, value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value)
        .map_err(|error| anyhow::anyhow!("{field} is invalid: {error}"))?;
    ensure!(url.scheme() == "https", "{field} must use https");
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "{field} must not contain userinfo"
    );
    ensure!(url.host_str().is_some(), "{field} must contain a host");
    ensure!(
        url.fragment().is_none(),
        "{field} must not contain a fragment"
    );
    Ok(())
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{field} must not be empty");
    Ok(())
}

fn absolutize(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::AuthorizationSettings;

    #[test]
    fn minimal_service_uses_secure_defaults() {
        let settings: AuthorizationSettings = toml::from_str(
            r#"
[[service]]
name = "central"
audience = "production"
policy_url = "https://authorization.example/policy"
server_ca_cert = "/etc/exfilguard/authorization/ca.pem"

[service.client_certificate]
source = "files"
cert = "/etc/exfilguard/authorization/client.pem"
key = "/etc/exfilguard/authorization/client.key"
"#,
        )
        .unwrap();

        settings.validate().unwrap();
        assert_eq!(settings.max_token_header_size, 1024);
        assert_eq!(settings.policy_cache_capacity, 4096);
        assert_eq!(settings.max_policy_cache_duration, 30);
        assert_eq!(settings.negative_cache_duration, 1);
        assert_eq!(settings.max_policy_response_size, 256 * 1024);
        assert_eq!(settings.max_policy_rules, 1024);
        assert_eq!(settings.services.len(), 1);
        assert_eq!(settings.services[0].timeout, 5);
        assert_eq!(settings.services[0].max_concurrency, 32);
    }
}
