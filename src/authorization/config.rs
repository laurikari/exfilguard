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

const fn default_credential_response_size() -> usize {
    32 * 1024
}

const fn default_protected_header_count() -> usize {
    16
}

const fn default_buffered_body_size() -> usize {
    1024 * 1024
}

const fn default_buffered_body_capacity() -> usize {
    16 * 1024 * 1024
}

// A buffered payload remains resident while its authorization-service request is serialized.
// JSON represents each byte as up to three decimal digits plus a comma, so the body array needs
// at most four bytes per payload byte, plus its brackets. Reserve both representations before
// reading the payload.
const BUFFERED_BODY_MEMORY_MULTIPLIER: usize = 5;

pub(super) fn buffered_body_memory_reservation(payload_size: usize) -> Result<usize> {
    payload_size
        .checked_mul(BUFFERED_BODY_MEMORY_MULTIPLIER)
        .and_then(|bytes| bytes.checked_add(2))
        .ok_or_else(|| anyhow::anyhow!("credential body memory reservation exceeds platform limit"))
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
    #[serde(default = "default_credential_response_size")]
    pub max_credential_response_size: usize,
    #[serde(default = "default_protected_header_count")]
    pub max_protected_headers: usize,
    #[serde(default = "default_buffered_body_size")]
    pub max_buffered_body_size: usize,
    #[serde(default = "default_buffered_body_capacity")]
    pub max_buffered_body_capacity: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationServiceSettings {
    pub name: String,
    pub audience: String,
    pub policy_url: String,
    pub credential_url: String,
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
    Vault { role: String, common_name: String },
}

impl AuthorizationSettings {
    pub(crate) fn uses_vault(&self) -> bool {
        self.services.iter().any(|service| {
            matches!(
                &service.client_certificate,
                AuthorizationClientCertificateSettings::Vault { .. }
            )
        })
    }

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
        ensure!(
            self.max_credential_response_size > 0,
            "authorization.max_credential_response_size must be greater than 0"
        );
        ensure!(
            self.max_protected_headers > 0,
            "authorization.max_protected_headers must be greater than 0"
        );
        ensure!(
            self.max_buffered_body_size > 0,
            "authorization.max_buffered_body_size must be greater than 0"
        );
        let minimum_body_capacity = buffered_body_memory_reservation(self.max_buffered_body_size)?;
        ensure!(
            self.max_buffered_body_capacity >= minimum_body_capacity,
            "authorization.max_buffered_body_capacity must cover one max_buffered_body_size request ({minimum_body_capacity} bytes)"
        );
        ensure!(
            self.max_buffered_body_capacity <= tokio::sync::Semaphore::MAX_PERMITS
                && self.max_buffered_body_capacity <= u32::MAX as usize,
            "authorization.max_buffered_body_capacity exceeds the runtime semaphore limit"
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
            for (index, limit) in client.credential_limits.iter().enumerate() {
                ensure!(
                    limit.protected_headers.len() <= self.max_protected_headers,
                    "client '{}' credential_limit[{index}].protected_headers exceeds authorization.max_protected_headers",
                    client.name
                );
                for name in limit.protected_headers.iter() {
                    let name = http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                        anyhow::anyhow!(
                            "client '{}' credential_limit[{index}] contains invalid protected header name '{}'",
                            client.name,
                            name
                        )
                    })?;
                    ensure!(
                        !super::policy::is_forbidden_protected_header(name.as_str()),
                        "client '{}' credential_limit[{index}] contains forbidden protected header '{}'",
                        client.name,
                        name.as_str()
                    );
                }
            }
        }
        Ok(())
    }
}

impl AuthorizationServiceSettings {
    fn apply_base_dir(&mut self, base_dir: &Path) {
        self.server_ca_cert = absolutize(&self.server_ca_cert, base_dir);
        if let AuthorizationClientCertificateSettings::Files { cert, key } =
            &mut self.client_certificate
        {
            *cert = absolutize(cert, base_dir);
            *key = absolutize(key, base_dir);
        }
    }

    fn validate(&self) -> Result<()> {
        let field = format!("authorization.service[{}]", self.name);
        ensure_nonempty(&format!("{field}.name"), &self.name)?;
        ensure_nonempty(&format!("{field}.audience"), &self.audience)?;
        validate_url(&format!("{field}.policy_url"), &self.policy_url)?;
        validate_url(&format!("{field}.credential_url"), &self.credential_url)?;
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
            AuthorizationClientCertificateSettings::Vault { role, common_name } => {
                ensure_nonempty(&format!("{field}.client_certificate.role"), role)?;
                ensure_nonempty(
                    &format!("{field}.client_certificate.common_name"),
                    common_name,
                )?;
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
    use super::{AuthorizationSettings, buffered_body_memory_reservation};

    #[test]
    fn minimal_service_uses_secure_defaults() {
        let settings: AuthorizationSettings = toml::from_str(
            r#"
[[service]]
name = "central"
audience = "production"
policy_url = "https://authorization.example/policy"
credential_url = "https://authorization.example/credential"
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
        assert_eq!(settings.max_credential_response_size, 32 * 1024);
        assert_eq!(settings.max_protected_headers, 16);
        assert_eq!(settings.max_buffered_body_size, 1024 * 1024);
        assert_eq!(settings.max_buffered_body_capacity, 16 * 1024 * 1024);
        assert_eq!(settings.services.len(), 1);
        assert_eq!(settings.services[0].timeout, 5);
        assert_eq!(settings.services[0].max_concurrency, 32);
    }

    #[test]
    fn body_memory_reservation_covers_raw_and_worst_case_json() {
        assert_eq!(buffered_body_memory_reservation(1).unwrap(), 7);
        assert_eq!(buffered_body_memory_reservation(1024).unwrap(), 5122);
    }
}
