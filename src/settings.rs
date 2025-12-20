use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, bail, ensure};
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

use crate::cli::{Cli, LogFormat};
use crate::config as runtime_config;

fn default_leaf_ttl() -> u64 {
    86_400
}

fn default_log_queries() -> bool {
    false
}

fn default_client_timeout() -> u64 {
    30
}

fn default_upstream_connect_timeout() -> u64 {
    5
}

fn default_upstream_timeout() -> u64 {
    60
}

fn default_upstream_pool_capacity() -> usize {
    32
}

fn default_max_header_size() -> usize {
    32 * 1024
}

fn default_max_response_header_size() -> usize {
    32 * 1024
}

fn default_max_request_body_size() -> usize {
    64 * 1024 * 1024
}

fn default_log_format() -> LogFormat {
    LogFormat::Json
}

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub listen: SocketAddr,
    pub ca_dir: PathBuf,
    pub clients: PathBuf,
    pub policies: PathBuf,
    #[serde(default)]
    pub clients_dir: Option<PathBuf>,
    #[serde(default)]
    pub policies_dir: Option<PathBuf>,
    #[serde(default)]
    pub cert_cache_dir: Option<PathBuf>,
    #[serde(default = "default_log_format")]
    pub log: LogFormat,
    #[serde(default = "default_leaf_ttl")]
    pub leaf_ttl: u64,
    #[serde(default = "default_log_queries")]
    pub log_queries: bool,
    #[serde(default = "default_client_timeout")]
    pub client_timeout: u64,
    #[serde(default = "default_upstream_connect_timeout")]
    pub upstream_connect_timeout: u64,
    #[serde(default = "default_upstream_timeout")]
    pub upstream_timeout: u64,
    #[serde(default = "default_upstream_pool_capacity")]
    pub upstream_pool_capacity: usize,
    #[serde(default = "default_max_header_size")]
    pub max_header_size: usize,
    #[serde(default = "default_max_response_header_size")]
    pub max_response_header_size: usize,
    #[serde(default = "default_max_request_body_size")]
    pub max_request_body_size: usize,
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,
    #[serde(default = "default_cache_max_entry_size")]
    pub cache_max_entry_size: u64,
    #[serde(default = "default_cache_max_entries")]
    pub cache_max_entries: usize,
    #[serde(default = "default_cache_total_capacity")]
    pub cache_total_capacity: u64,
    #[serde(default = "default_cache_sweeper_interval")]
    pub cache_sweeper_interval: u64,
    #[serde(default = "default_cache_sweeper_batch_size")]
    pub cache_sweeper_batch_size: usize,
    #[serde(default)]
    pub metrics_listen: Option<SocketAddr>,
    #[serde(default)]
    pub metrics_tls_cert: Option<PathBuf>,
    #[serde(default)]
    pub metrics_tls_key: Option<PathBuf>,
}

impl Settings {
    pub fn load(cli: &Cli) -> Result<Self> {
        let mut builder = Config::builder();
        let config_path = resolve_config_path(cli)?;

        builder = builder.add_source(File::from(config_path.clone()).required(true));

        builder = builder.add_source(
            Environment::with_prefix("EXFILGUARD")
                .separator("__")
                .try_parsing(true),
        );

        let cfg = builder.build().map_err(to_anyhow)?;
        let mut settings: Settings = cfg.try_deserialize().map_err(to_anyhow)?;
        settings.apply_base_dir(&config_path);
        settings.validate()?;
        Ok(settings)
    }

    /// Load settings and return them alongside a validated runtime config
    /// (clients + policies). Useful for preflight checks that should fail fast
    /// before the proxy binds a listener.
    pub fn load_with_config(cli: &Cli) -> Result<(Self, runtime_config::ValidatedConfig)> {
        let settings = Self::load(cli)?;
        let runtime = settings.load_runtime_config()?;
        Ok((settings, runtime))
    }

    /// Load and validate the client/policy configuration using the resolved
    /// paths from these settings.
    pub fn load_runtime_config(&self) -> Result<runtime_config::ValidatedConfig> {
        runtime_config::load_config_with_dirs(
            &self.clients,
            self.clients_dir.as_deref(),
            &self.policies,
            self.policies_dir.as_deref(),
        )
    }

    pub fn leaf_ttl(&self) -> Duration {
        Duration::from_secs(self.leaf_ttl)
    }

    pub fn client_timeout(&self) -> Duration {
        Duration::from_secs(self.client_timeout)
    }

    pub fn upstream_connect_timeout(&self) -> Duration {
        Duration::from_secs(self.upstream_connect_timeout)
    }

    pub fn upstream_timeout(&self) -> Duration {
        Duration::from_secs(self.upstream_timeout)
    }

    pub fn cache_sweeper_interval(&self) -> Duration {
        Duration::from_secs(self.cache_sweeper_interval)
    }

    pub fn upstream_pool_capacity_nonzero(&self) -> std::num::NonZeroUsize {
        std::num::NonZeroUsize::new(self.upstream_pool_capacity)
            .expect("upstream_pool_capacity must be at least 1")
    }
}

fn to_anyhow(err: ConfigError) -> anyhow::Error {
    anyhow::anyhow!(err)
}

impl Cli {
    pub fn config_path(&self) -> Option<&Path> {
        self.config.as_deref()
    }
}

fn resolve_config_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(path) = cli.config_path() {
        return Ok(path.to_path_buf());
    }

    for candidate in default_config_candidates() {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    bail!(
        "no configuration file provided via --config and none found in default locations: {}",
        default_config_candidates()
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

fn default_config_candidates() -> [PathBuf; 2] {
    [
        PathBuf::from("/etc/exfilguard/exfilguard.toml"),
        PathBuf::from("exfilguard.toml"),
    ]
}

impl Settings {
    fn apply_base_dir(&mut self, config_path: &Path) {
        let base_dir = config_path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        self.ca_dir = absolutize(&self.ca_dir, base_dir);
        if let Some(cache_dir) = self.cert_cache_dir.clone() {
            self.cert_cache_dir = Some(absolutize(&cache_dir, base_dir));
        }
        if let Some(cache_dir) = self.cache_dir.clone() {
            self.cache_dir = Some(absolutize(&cache_dir, base_dir));
        }
        self.clients = absolutize(&self.clients, base_dir);
        self.clients_dir = self
            .clients_dir
            .as_ref()
            .map(|path| absolutize(path, base_dir));
        self.policies = absolutize(&self.policies, base_dir);
        self.policies_dir = self
            .policies_dir
            .as_ref()
            .map(|path| absolutize(path, base_dir));
        if let Some(cert) = self.metrics_tls_cert.clone() {
            self.metrics_tls_cert = Some(absolutize(&cert, base_dir));
        }
        if let Some(key) = self.metrics_tls_key.clone() {
            self.metrics_tls_key = Some(absolutize(&key, base_dir));
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.upstream_pool_capacity > 0,
            "upstream_pool_capacity must be at least 1 (got {})",
            self.upstream_pool_capacity
        );
        ensure!(
            self.max_header_size > 0,
            "max_header_size must be greater than 0 (got {})",
            self.max_header_size
        );
        ensure!(
            self.max_response_header_size > 0,
            "max_response_header_size must be greater than 0 (got {})",
            self.max_response_header_size
        );
        ensure!(
            self.max_request_body_size > 0,
            "max_request_body_size must be greater than 0 (got {})",
            self.max_request_body_size
        );
        ensure!(
            self.client_timeout > 0,
            "client_timeout must be greater than 0 seconds (got {})",
            self.client_timeout
        );
        ensure!(
            self.upstream_connect_timeout > 0,
            "upstream_connect_timeout must be greater than 0 seconds (got {})",
            self.upstream_connect_timeout
        );
        ensure!(
            self.upstream_timeout > 0,
            "upstream_timeout must be greater than 0 seconds (got {})",
            self.upstream_timeout
        );
        ensure!(
            self.leaf_ttl > 0,
            "leaf_ttl must be greater than 0 seconds (got {})",
            self.leaf_ttl
        );
        if self.cache_dir.is_some() {
            ensure!(
                self.cache_max_entry_size > 0,
                "cache_max_entry_size must be greater than 0 (got {})",
                self.cache_max_entry_size
            );
            ensure!(
                self.cache_max_entries > 0,
                "cache_max_entries must be greater than 0 (got {})",
                self.cache_max_entries
            );
            ensure!(
                self.cache_total_capacity > 0,
                "cache_total_capacity must be greater than 0 (got {})",
                self.cache_total_capacity
            );
            ensure!(
                self.cache_sweeper_interval > 0,
                "cache_sweeper_interval must be greater than 0 seconds (got {})",
                self.cache_sweeper_interval
            );
            ensure!(
                self.cache_sweeper_batch_size > 0,
                "cache_sweeper_batch_size must be greater than 0 (got {})",
                self.cache_sweeper_batch_size
            );
        }
        let tls_cert_set = self.metrics_tls_cert.is_some();
        let tls_key_set = self.metrics_tls_key.is_some();
        ensure!(
            tls_cert_set == tls_key_set,
            "metrics_tls_cert and metrics_tls_key must both be set or both be absent"
        );
        if tls_cert_set && self.metrics_listen.is_none() {
            bail!("metrics_tls_cert/metrics_tls_key provided but metrics_listen is not set");
        }
        Ok(())
    }
}

fn absolutize(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn default_cache_max_entry_size() -> u64 {
    10 * 1024 * 1024 // 10 MiB
}

fn default_cache_max_entries() -> usize {
    10_000
}

fn default_cache_total_capacity() -> u64 {
    1024 * 1024 * 1024 // 1 GiB
}

fn default_cache_sweeper_interval() -> u64 {
    300
}

fn default_cache_sweeper_batch_size() -> usize {
    1000
}

#[cfg(test)]
mod tests {
    use crate::cli::LogFormat;
    use crate::settings::Settings;
    use std::path::PathBuf;

    #[test]
    fn test_settings_validation_cache_enabled() {
        let settings = Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            ca_dir: PathBuf::from("ca"),
            clients: PathBuf::from("clients.toml"),
            policies: PathBuf::from("policies.toml"),
            clients_dir: None,
            policies_dir: None,
            cert_cache_dir: None,
            log: LogFormat::Text,
            leaf_ttl: 3600,
            log_queries: false,
            client_timeout: 30,
            upstream_connect_timeout: 5,
            upstream_timeout: 60,
            upstream_pool_capacity: 32,
            max_header_size: 1024,
            max_response_header_size: 1024,
            max_request_body_size: 1024,
            // Cache enabled
            cache_dir: Some(PathBuf::from("cache")),
            cache_max_entry_size: 1024,
            cache_max_entries: 1024,
            cache_total_capacity: 1024,
            cache_sweeper_interval: 300,
            cache_sweeper_batch_size: 1000,
            metrics_listen: None,
            metrics_tls_cert: None,
            metrics_tls_key: None,
        };
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn test_settings_validation_cache_invalid_sizes() {
        let mut settings = Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            ca_dir: PathBuf::from("ca"),
            clients: PathBuf::from("clients.toml"),
            policies: PathBuf::from("policies.toml"),
            clients_dir: None,
            policies_dir: None,
            cert_cache_dir: None,
            log: LogFormat::Text,
            leaf_ttl: 3600,
            log_queries: false,
            client_timeout: 30,
            upstream_connect_timeout: 5,
            upstream_timeout: 60,
            upstream_pool_capacity: 32,
            max_header_size: 1024,
            max_response_header_size: 1024,
            max_request_body_size: 1024,
            // Cache enabled but invalid
            cache_dir: Some(PathBuf::from("cache")),
            cache_max_entry_size: 0,
            cache_max_entries: 1024,
            cache_total_capacity: 1024,
            cache_sweeper_interval: 300,
            cache_sweeper_batch_size: 1000,
            metrics_listen: None,
            metrics_tls_cert: None,
            metrics_tls_key: None,
        };
        assert!(settings.validate().is_err());

        settings.cache_max_entry_size = 1024;
        settings.cache_total_capacity = 0;
        assert!(settings.validate().is_err());
    }

    #[test]
    fn test_settings_validation_cache_disabled_sizes_ignored() {
        let settings = Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            ca_dir: PathBuf::from("ca"),
            clients: PathBuf::from("clients.toml"),
            policies: PathBuf::from("policies.toml"),
            clients_dir: None,
            policies_dir: None,
            cert_cache_dir: None,
            log: LogFormat::Text,
            leaf_ttl: 3600,
            log_queries: false,
            client_timeout: 30,
            upstream_connect_timeout: 5,
            upstream_timeout: 60,
            upstream_pool_capacity: 32,
            max_header_size: 1024,
            max_response_header_size: 1024,
            max_request_body_size: 1024,
            // Cache disabled (None), sizes should be ignored even if 0 (though defaults are non-zero)
            cache_dir: None,
            cache_max_entry_size: 0,
            cache_max_entries: 0,
            cache_total_capacity: 0,
            cache_sweeper_interval: 0,
            cache_sweeper_batch_size: 0,
            metrics_listen: None,
            metrics_tls_cert: None,
            metrics_tls_key: None,
        };
        // Should be OK because cache_dir is None
        assert!(settings.validate().is_ok());
    }
}
