use std::ffi::OsStr;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use config::{Config, ConfigError, Environment, File};
use ipnet::IpNet;
use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};

use crate::cli::{Cli, LogFormat};
use crate::config as runtime_config;

struct SettingsDefaults;

const CONFIG_FRAGMENT_DIR: &str = "config.d";

impl SettingsDefaults {
    fn vault_pki_mount() -> String {
        "pki".to_string()
    }

    const fn vault_intermediate_ttl() -> u64 {
        2_592_000
    }

    const fn vault_renewal_threshold() -> u64 {
        1_296_000
    }

    const fn vault_request_timeout() -> u64 {
        10
    }

    fn vault_approle_mount() -> String {
        "approle".to_string()
    }

    const fn leaf_ttl() -> u64 {
        86_400
    }

    const fn leaf_cache_capacity() -> usize {
        4096
    }

    const fn leaf_mint_concurrency() -> usize {
        4
    }

    const fn log_queries() -> bool {
        false
    }

    const fn dns_resolve_timeout() -> u64 {
        2
    }

    const fn upstream_connect_timeout() -> u64 {
        5
    }

    const fn tls_handshake_timeout() -> u64 {
        10
    }

    const fn request_header_timeout() -> u64 {
        10
    }

    const fn request_body_idle_timeout() -> u64 {
        30
    }

    const fn response_header_timeout() -> u64 {
        60
    }

    const fn response_body_idle_timeout() -> u64 {
        60
    }

    const fn request_total_timeout() -> u64 {
        0
    }

    const fn client_keepalive_idle_timeout() -> u64 {
        30
    }

    const fn connect_tunnel_idle_timeout() -> u64 {
        60
    }

    const fn connect_tunnel_max_lifetime() -> u64 {
        0
    }

    const fn upstream_pool_capacity() -> usize {
        32
    }

    const fn http2_max_concurrent_streams() -> u32 {
        100
    }

    const fn max_request_header_size() -> usize {
        32 * 1024
    }

    const fn max_response_header_size() -> usize {
        32 * 1024
    }

    const fn max_request_body_size() -> usize {
        0
    }

    const fn log_format() -> LogFormat {
        LogFormat::Json
    }

    const fn cache_max_entry_size() -> u64 {
        100 * 1024 * 1024
    }

    const fn cache_max_entries() -> usize {
        10_000
    }

    const fn cache_total_capacity() -> u64 {
        1024 * 1024 * 1024
    }

    const fn cache_sweeper_interval() -> u64 {
        300
    }

    const fn cache_sweeper_batch_size() -> usize {
        1000
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaSettings {
    Builtin { dir: PathBuf },
    Files { dir: PathBuf },
    Vault(Box<VaultCaSettings>),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultCaSettings {
    pub address: String,
    #[serde(default)]
    pub tls_ca_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_server_name: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default = "SettingsDefaults::vault_pki_mount")]
    pub pki_mount: String,
    pub issuer: String,
    pub expected_root_certs: PathBuf,
    #[serde(default = "SettingsDefaults::vault_intermediate_ttl")]
    pub intermediate_ttl: u64,
    #[serde(default = "SettingsDefaults::vault_renewal_threshold")]
    pub renewal_threshold: u64,
    #[serde(default = "SettingsDefaults::vault_request_timeout")]
    pub request_timeout: u64,
    #[serde(default)]
    pub tls_client_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_client_key: Option<PathBuf>,
    pub auth: VaultAuth,
}

impl VaultCaSettings {
    pub fn intermediate_ttl(&self) -> Duration {
        Duration::from_secs(self.intermediate_ttl)
    }

    pub fn renewal_threshold(&self) -> Duration {
        Duration::from_secs(self.renewal_threshold)
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout)
    }
}

impl CaSettings {
    fn apply_base_dir(&mut self, base_dir: &Path) {
        match self {
            Self::Builtin { dir } | Self::Files { dir } => {
                *dir = absolutize(dir, base_dir);
            }
            Self::Vault(settings) => settings.apply_base_dir(base_dir),
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Builtin { .. } | Self::Files { .. } => Ok(()),
            Self::Vault(settings) => settings.validate(),
        }
    }
}

impl VaultCaSettings {
    fn apply_base_dir(&mut self, base_dir: &Path) {
        self.tls_ca_cert = self
            .tls_ca_cert
            .as_ref()
            .map(|path| absolutize(path, base_dir));
        self.expected_root_certs = absolutize(&self.expected_root_certs, base_dir);
        self.tls_client_cert = self
            .tls_client_cert
            .as_ref()
            .map(|path| absolutize(path, base_dir));
        self.tls_client_key = self
            .tls_client_key
            .as_ref()
            .map(|path| absolutize(path, base_dir));
        self.auth.apply_base_dir(base_dir);
    }

    fn validate(&self) -> Result<()> {
        ensure_nonempty("ca.address", &self.address)?;
        if let Some(server_name) = self.tls_server_name.as_deref() {
            ensure_nonempty("ca.tls_server_name", server_name)?;
        }
        if let Some(namespace) = self.namespace.as_deref() {
            ensure_nonempty("ca.namespace", namespace)?;
        }
        ensure_nonempty("ca.pki_mount", &self.pki_mount)?;
        ensure_nonempty("ca.issuer", &self.issuer)?;
        ensure!(
            self.intermediate_ttl > 0,
            "ca.intermediate_ttl must be greater than 0 seconds (got {})",
            self.intermediate_ttl
        );
        ensure!(
            self.renewal_threshold > 0,
            "ca.renewal_threshold must be greater than 0 seconds (got {})",
            self.renewal_threshold
        );
        ensure!(
            self.renewal_threshold < self.intermediate_ttl,
            "ca.renewal_threshold must be less than ca.intermediate_ttl"
        );
        ensure!(
            self.request_timeout > 0,
            "ca.request_timeout must be greater than 0 seconds (got {})",
            self.request_timeout
        );
        ensure!(
            self.tls_client_cert.is_some() == self.tls_client_key.is_some(),
            "ca.tls_client_cert and ca.tls_client_key must both be set or both be absent"
        );
        self.auth.validate()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum VaultAuth {
    #[serde(rename = "approle")]
    AppRole {
        #[serde(default = "SettingsDefaults::vault_approle_mount")]
        mount: String,
        role_id: String,
        secret_id_file: PathBuf,
    },
    TokenFile {
        token_file: PathBuf,
    },
    Proxy {},
}

impl VaultAuth {
    fn apply_base_dir(&mut self, base_dir: &Path) {
        match self {
            Self::AppRole { secret_id_file, .. } => {
                *secret_id_file = absolutize(secret_id_file, base_dir);
            }
            Self::TokenFile { token_file } => {
                *token_file = absolutize(token_file, base_dir);
            }
            Self::Proxy {} => {}
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::AppRole { mount, role_id, .. } => {
                ensure_nonempty("ca.auth.mount", mount)?;
                ensure_nonempty("ca.auth.role_id", role_id)
            }
            Self::TokenFile { .. } | Self::Proxy {} => Ok(()),
        }
    }
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{field} must not be empty");
    Ok(())
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolMode {
    #[default]
    Off,
    Optional,
    Required,
}

fn deserialize_proxy_protocol_mode<'de, D>(deserializer: D) -> Result<ProxyProtocolMode, D::Error>
where
    D: Deserializer<'de>,
{
    struct ModeVisitor;

    impl<'de> Visitor<'de> for ModeVisitor {
        type Value = ProxyProtocolMode;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("off, optional, required, or a boolean")
        }

        fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(if value {
                ProxyProtocolMode::Required
            } else {
                ProxyProtocolMode::Off
            })
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            match value.to_ascii_lowercase().as_str() {
                "off" => Ok(ProxyProtocolMode::Off),
                "optional" => Ok(ProxyProtocolMode::Optional),
                "required" => Ok(ProxyProtocolMode::Required),
                _ => Err(de::Error::custom(format!(
                    "unsupported proxy_protocol value '{value}'"
                ))),
            }
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&value)
        }
    }

    deserializer.deserialize_any(ModeVisitor)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub listen: SocketAddr,
    #[serde(default, deserialize_with = "deserialize_proxy_protocol_mode")]
    pub proxy_protocol: ProxyProtocolMode,
    #[serde(default)]
    pub proxy_protocol_allowed_cidrs: Option<Vec<IpNet>>,
    pub ca: CaSettings,
    pub clients: PathBuf,
    pub policies: PathBuf,
    #[serde(default)]
    pub clients_dir: Option<PathBuf>,
    #[serde(default)]
    pub policies_dir: Option<PathBuf>,
    #[serde(default = "SettingsDefaults::log_format")]
    pub log: LogFormat,
    #[serde(default = "SettingsDefaults::leaf_ttl")]
    pub leaf_ttl: u64,
    #[serde(default = "SettingsDefaults::leaf_cache_capacity")]
    pub leaf_cache_capacity: usize,
    #[serde(default = "SettingsDefaults::leaf_mint_concurrency")]
    pub leaf_mint_concurrency: usize,
    #[serde(default = "SettingsDefaults::log_queries")]
    pub log_queries: bool,
    #[serde(default = "SettingsDefaults::dns_resolve_timeout")]
    pub dns_resolve_timeout: u64,
    #[serde(default = "SettingsDefaults::upstream_connect_timeout")]
    pub upstream_connect_timeout: u64,
    #[serde(default = "SettingsDefaults::tls_handshake_timeout")]
    pub tls_handshake_timeout: u64,
    #[serde(default = "SettingsDefaults::request_header_timeout")]
    pub request_header_timeout: u64,
    #[serde(default = "SettingsDefaults::request_body_idle_timeout")]
    pub request_body_idle_timeout: u64,
    #[serde(default = "SettingsDefaults::response_header_timeout")]
    pub response_header_timeout: u64,
    #[serde(default = "SettingsDefaults::response_body_idle_timeout")]
    pub response_body_idle_timeout: u64,
    #[serde(default = "SettingsDefaults::request_total_timeout")]
    pub request_total_timeout: u64,
    #[serde(default = "SettingsDefaults::client_keepalive_idle_timeout")]
    pub client_keepalive_idle_timeout: u64,
    #[serde(default = "SettingsDefaults::connect_tunnel_idle_timeout")]
    pub connect_tunnel_idle_timeout: u64,
    #[serde(default = "SettingsDefaults::connect_tunnel_max_lifetime")]
    pub connect_tunnel_max_lifetime: u64,
    #[serde(default = "SettingsDefaults::upstream_pool_capacity")]
    pub upstream_pool_capacity: usize,
    #[serde(default = "SettingsDefaults::http2_max_concurrent_streams")]
    pub http2_max_concurrent_streams: u32,
    #[serde(default = "SettingsDefaults::max_request_header_size")]
    pub max_request_header_size: usize,
    #[serde(default = "SettingsDefaults::max_response_header_size")]
    pub max_response_header_size: usize,
    #[serde(default = "SettingsDefaults::max_request_body_size")]
    pub max_request_body_size: usize,
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,
    #[serde(default = "SettingsDefaults::cache_max_entry_size")]
    pub cache_max_entry_size: u64,
    #[serde(default = "SettingsDefaults::cache_max_entries")]
    pub cache_max_entries: usize,
    #[serde(default = "SettingsDefaults::cache_total_capacity")]
    pub cache_total_capacity: u64,
    #[serde(default = "SettingsDefaults::cache_sweeper_interval")]
    pub cache_sweeper_interval: u64,
    #[serde(default = "SettingsDefaults::cache_sweeper_batch_size")]
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
        for fragment in collect_config_fragments(&config_path)? {
            builder = builder.add_source(File::from(fragment).required(true));
        }

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

    pub fn dns_resolve_timeout(&self) -> Duration {
        Duration::from_secs(self.dns_resolve_timeout)
    }

    pub fn upstream_connect_timeout(&self) -> Duration {
        Duration::from_secs(self.upstream_connect_timeout)
    }

    pub fn tls_handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.tls_handshake_timeout)
    }

    pub fn request_header_timeout(&self) -> Duration {
        Duration::from_secs(self.request_header_timeout)
    }

    pub fn request_body_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.request_body_idle_timeout)
    }

    pub fn response_header_timeout(&self) -> Duration {
        Duration::from_secs(self.response_header_timeout)
    }

    pub fn response_body_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.response_body_idle_timeout)
    }

    pub fn request_total_timeout(&self) -> Option<Duration> {
        if self.request_total_timeout == 0 {
            None
        } else {
            Some(Duration::from_secs(self.request_total_timeout))
        }
    }

    pub fn client_keepalive_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.client_keepalive_idle_timeout)
    }

    pub fn connect_tunnel_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_tunnel_idle_timeout)
    }

    pub fn connect_tunnel_max_lifetime(&self) -> Option<Duration> {
        if self.connect_tunnel_max_lifetime == 0 {
            None
        } else {
            Some(Duration::from_secs(self.connect_tunnel_max_lifetime))
        }
    }

    pub fn max_request_body_size_limit(&self) -> Option<usize> {
        if self.max_request_body_size == 0 {
            None
        } else {
            Some(self.max_request_body_size)
        }
    }

    pub fn proxy_protocol_allows_peer(&self, peer: IpAddr) -> bool {
        match &self.proxy_protocol_allowed_cidrs {
            None => true,
            Some(cidrs) => cidrs.iter().any(|cidr| cidr.contains(&peer)),
        }
    }

    pub fn cache_sweeper_interval(&self) -> Duration {
        Duration::from_secs(self.cache_sweeper_interval)
    }

    pub fn upstream_pool_capacity_nonzero(&self) -> std::num::NonZeroUsize {
        std::num::NonZeroUsize::new(self.upstream_pool_capacity)
            .expect("upstream_pool_capacity must be at least 1")
    }

    pub fn http2_max_concurrent_streams_usize(&self) -> usize {
        self.http2_max_concurrent_streams as usize
    }
}

fn collect_config_fragments(config_path: &Path) -> Result<Vec<PathBuf>> {
    let base_dir = config_path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let fragment_dir = base_dir.join(CONFIG_FRAGMENT_DIR);
    if !fragment_dir.exists() {
        return Ok(Vec::new());
    }
    if !fragment_dir.is_dir() {
        bail!(
            "global config fragment path {} is not a directory",
            fragment_dir.display()
        );
    }

    let mut fragments = Vec::new();
    let entries = fs::read_dir(&fragment_dir).with_context(|| {
        format!(
            "failed to read global config fragment directory {}",
            fragment_dir.display()
        )
    })?;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "failed to read entry in global config fragment directory {}",
                fragment_dir.display()
            )
        })?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to stat global config fragment {}", path.display()))?;
        if file_type.is_file()
            && path
                .extension()
                .and_then(OsStr::to_str)
                .is_some_and(|extension| extension.eq_ignore_ascii_case("toml"))
        {
            fragments.push(path);
        }
    }
    fragments.sort();
    Ok(fragments)
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

        self.ca.apply_base_dir(base_dir);
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
        self.ca.validate()?;
        if self.proxy_protocol != ProxyProtocolMode::Off {
            ensure!(
                matches!(
                    self.proxy_protocol_allowed_cidrs.as_ref(),
                    Some(cidrs) if !cidrs.is_empty()
                ),
                "proxy_protocol_allowed_cidrs must be set when proxy_protocol is enabled"
            );
        }
        ensure!(
            self.upstream_pool_capacity > 0,
            "upstream_pool_capacity must be at least 1 (got {})",
            self.upstream_pool_capacity
        );
        ensure!(
            self.http2_max_concurrent_streams > 0,
            "http2_max_concurrent_streams must be at least 1 (got {})",
            self.http2_max_concurrent_streams
        );
        ensure!(
            self.max_request_header_size > 0,
            "max_request_header_size must be greater than 0 (got {})",
            self.max_request_header_size
        );
        ensure!(
            self.max_response_header_size > 0,
            "max_response_header_size must be greater than 0 (got {})",
            self.max_response_header_size
        );
        ensure!(
            self.dns_resolve_timeout > 0,
            "dns_resolve_timeout must be greater than 0 seconds (got {})",
            self.dns_resolve_timeout
        );
        ensure!(
            self.upstream_connect_timeout > 0,
            "upstream_connect_timeout must be greater than 0 seconds (got {})",
            self.upstream_connect_timeout
        );
        ensure!(
            self.tls_handshake_timeout > 0,
            "tls_handshake_timeout must be greater than 0 seconds (got {})",
            self.tls_handshake_timeout
        );
        ensure!(
            self.request_header_timeout > 0,
            "request_header_timeout must be greater than 0 seconds (got {})",
            self.request_header_timeout
        );
        ensure!(
            self.request_body_idle_timeout > 0,
            "request_body_idle_timeout must be greater than 0 seconds (got {})",
            self.request_body_idle_timeout
        );
        ensure!(
            self.response_header_timeout > 0,
            "response_header_timeout must be greater than 0 seconds (got {})",
            self.response_header_timeout
        );
        ensure!(
            self.response_body_idle_timeout > 0,
            "response_body_idle_timeout must be greater than 0 seconds (got {})",
            self.response_body_idle_timeout
        );
        ensure!(
            self.client_keepalive_idle_timeout > 0,
            "client_keepalive_idle_timeout must be greater than 0 seconds (got {})",
            self.client_keepalive_idle_timeout
        );
        ensure!(
            self.connect_tunnel_idle_timeout > 0,
            "connect_tunnel_idle_timeout must be greater than 0 seconds (got {})",
            self.connect_tunnel_idle_timeout
        );
        ensure!(
            self.leaf_ttl > 0,
            "leaf_ttl must be greater than 0 seconds (got {})",
            self.leaf_ttl
        );
        ensure!(
            self.leaf_cache_capacity > 0,
            "leaf_cache_capacity must be greater than 0 (got {})",
            self.leaf_cache_capacity
        );
        ensure!(
            self.leaf_mint_concurrency > 0,
            "leaf_mint_concurrency must be greater than 0 (got {})",
            self.leaf_mint_concurrency
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
                self.cache_max_entry_size <= self.cache_total_capacity,
                "cache_max_entry_size ({}) must not exceed cache_total_capacity ({})",
                self.cache_max_entry_size,
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

#[cfg(test)]
mod tests {
    use crate::cli::{Cli, LogFormat};
    use crate::settings::{CaSettings, ProxyProtocolMode, Settings, VaultAuth, VaultCaSettings};
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::TempDir;

    fn write_settings_config(dir: &TempDir, ca_config: &str) -> PathBuf {
        let config_path = dir.path().join("exfilguard.toml");
        fs::write(
            &config_path,
            format!(
                r#"
listen = "127.0.0.1:3128"
clients = "clients.toml"
policies = "policies.toml"

{ca_config}
"#
            ),
        )
        .unwrap();
        config_path
    }

    fn valid_vault_settings(auth: VaultAuth) -> VaultCaSettings {
        VaultCaSettings {
            address: "https://vault.example.com".to_string(),
            tls_ca_cert: Some(PathBuf::from("vault-ca.pem")),
            tls_server_name: Some("vault.example.com".to_string()),
            namespace: Some("team-a".to_string()),
            pki_mount: "pki".to_string(),
            issuer: "exfilguard".to_string(),
            expected_root_certs: PathBuf::from("expected-roots.pem"),
            intermediate_ttl: 2_592_000,
            renewal_threshold: 1_296_000,
            request_timeout: 10,
            tls_client_cert: Some(PathBuf::from("client.pem")),
            tls_client_key: Some(PathBuf::from("client.key")),
            auth,
        }
    }

    #[test]
    fn load_resolves_builtin_and_files_ca_directories() {
        for source in ["builtin", "files"] {
            let dir = TempDir::new().unwrap();
            let config_path = write_settings_config(
                &dir,
                &format!(
                    r#"[ca]
source = "{source}"
dir = "ca-material""#
                ),
            );

            let settings = Settings::load(&Cli {
                config: Some(config_path),
            })
            .unwrap();

            let ca_dir = match settings.ca {
                CaSettings::Builtin { dir } | CaSettings::Files { dir } => dir,
                CaSettings::Vault(_) => panic!("unexpected Vault CA settings"),
            };
            assert_eq!(ca_dir, dir.path().join("ca-material"));
        }
    }

    #[test]
    fn load_vault_ca_applies_defaults_and_resolves_paths() {
        let dir = TempDir::new().unwrap();
        let config_path = write_settings_config(
            &dir,
            r#"[ca]
source = "vault"
address = "https://vault.example.com"
tls_ca_cert = "vault-ca.pem"
tls_server_name = "vault.internal"
namespace = "team-a"
issuer = "exfilguard"
expected_root_certs = "expected-roots.pem"
tls_client_cert = "client.pem"
tls_client_key = "client.key"

[ca.auth]
method = "approle"
role_id = "role-id"
secret_id_file = "secret-id""#,
        );

        let settings = Settings::load(&Cli {
            config: Some(config_path),
        })
        .unwrap();
        let CaSettings::Vault(vault) = settings.ca else {
            panic!("expected Vault CA settings");
        };

        assert_eq!(vault.pki_mount, "pki");
        assert_eq!(vault.intermediate_ttl(), Duration::from_secs(2_592_000));
        assert_eq!(vault.renewal_threshold(), Duration::from_secs(1_296_000));
        assert_eq!(vault.request_timeout(), Duration::from_secs(10));
        assert_eq!(vault.tls_ca_cert, Some(dir.path().join("vault-ca.pem")));
        assert_eq!(
            vault.expected_root_certs,
            dir.path().join("expected-roots.pem")
        );
        assert_eq!(vault.tls_client_cert, Some(dir.path().join("client.pem")));
        assert_eq!(vault.tls_client_key, Some(dir.path().join("client.key")));
        assert_eq!(
            vault.auth,
            VaultAuth::AppRole {
                mount: "approle".to_string(),
                role_id: "role-id".to_string(),
                secret_id_file: dir.path().join("secret-id"),
            }
        );
    }

    #[test]
    fn load_vault_token_file_and_proxy_auth() {
        let token_dir = TempDir::new().unwrap();
        let token_config = write_settings_config(
            &token_dir,
            r#"[ca]
source = "vault"
address = "https://vault.example.com"
issuer = "exfilguard"
expected_root_certs = "roots.pem"

[ca.auth]
method = "token_file"
token_file = "vault-token""#,
        );
        let token_settings = Settings::load(&Cli {
            config: Some(token_config),
        })
        .unwrap();
        let CaSettings::Vault(token_vault) = token_settings.ca else {
            panic!("expected Vault CA settings");
        };
        assert_eq!(
            token_vault.auth,
            VaultAuth::TokenFile {
                token_file: token_dir.path().join("vault-token")
            }
        );

        let proxy_dir = TempDir::new().unwrap();
        let proxy_config = write_settings_config(
            &proxy_dir,
            r#"[ca]
source = "vault"
address = "https://vault.example.com"
issuer = "exfilguard"
expected_root_certs = "roots.pem"

[ca.auth]
method = "proxy""#,
        );
        let proxy_settings = Settings::load(&Cli {
            config: Some(proxy_config),
        })
        .unwrap();
        let CaSettings::Vault(proxy_vault) = proxy_settings.ca else {
            panic!("expected Vault CA settings");
        };
        assert_eq!(proxy_vault.auth, VaultAuth::Proxy {});
    }

    #[test]
    fn vault_ca_validation_rejects_invalid_values() {
        let auth = VaultAuth::AppRole {
            mount: "approle".to_string(),
            role_id: "role-id".to_string(),
            secret_id_file: PathBuf::from("secret-id"),
        };

        let mut invalid = valid_vault_settings(auth.clone());
        invalid.address = " ".to_string();
        assert!(invalid.validate().is_err());

        let mut invalid = valid_vault_settings(auth.clone());
        invalid.tls_server_name = Some(String::new());
        assert!(invalid.validate().is_err());

        let mut invalid = valid_vault_settings(auth.clone());
        invalid.namespace = Some(String::new());
        assert!(invalid.validate().is_err());

        let mut invalid = valid_vault_settings(auth.clone());
        invalid.pki_mount = String::new();
        assert!(invalid.validate().is_err());

        let mut invalid = valid_vault_settings(auth.clone());
        invalid.issuer = String::new();
        assert!(invalid.validate().is_err());

        let mut invalid = valid_vault_settings(auth.clone());
        invalid.intermediate_ttl = 0;
        assert!(invalid.validate().is_err());

        let mut invalid = valid_vault_settings(auth.clone());
        invalid.renewal_threshold = 0;
        assert!(invalid.validate().is_err());

        let mut invalid = valid_vault_settings(auth.clone());
        invalid.renewal_threshold = invalid.intermediate_ttl;
        assert!(invalid.validate().is_err());

        let mut invalid = valid_vault_settings(auth.clone());
        invalid.request_timeout = 0;
        assert!(invalid.validate().is_err());

        let mut invalid = valid_vault_settings(auth.clone());
        invalid.tls_client_key = None;
        assert!(invalid.validate().is_err());

        let mut invalid = valid_vault_settings(auth.clone());
        invalid.auth = VaultAuth::AppRole {
            mount: String::new(),
            role_id: "role-id".to_string(),
            secret_id_file: PathBuf::from("secret-id"),
        };
        assert!(invalid.validate().is_err());

        let mut invalid = valid_vault_settings(auth);
        invalid.auth = VaultAuth::AppRole {
            mount: "approle".to_string(),
            role_id: String::new(),
            secret_id_file: PathBuf::from("secret-id"),
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn load_rejects_removed_ca_dir_setting() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("exfilguard.toml");
        fs::write(
            &config_path,
            r#"
listen = "127.0.0.1:3128"
ca_dir = "ca"
clients = "clients.toml"
policies = "policies.toml"
"#,
        )
        .unwrap();

        let error = Settings::load(&Cli {
            config: Some(config_path),
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("ca_dir") && error.to_string().contains("unknown field"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_merges_config_fragments_in_filename_order() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("exfilguard.toml");
        fs::write(
            &config_path,
            r#"
	listen = "127.0.0.1:3128"
	clients = "clients.toml"
	policies = "policies.toml"
	response_header_timeout = 30

	[ca]
	source = "builtin"
	dir = "ca"
"#,
        )
        .unwrap();
        let fragment_dir = dir.path().join("config.d");
        fs::create_dir(&fragment_dir).unwrap();
        fs::write(
            fragment_dir.join("10-long-polls.toml"),
            "response_header_timeout = 45\n",
        )
        .unwrap();
        fs::write(
            fragment_dir.join("20-local.toml"),
            "response_header_timeout = 60\n",
        )
        .unwrap();
        fs::write(fragment_dir.join("README"), "ignored").unwrap();

        let settings = Settings::load(&Cli {
            config: Some(config_path),
        })
        .unwrap();

        assert_eq!(settings.response_header_timeout, 60);
        assert_eq!(
            settings.ca,
            CaSettings::Builtin {
                dir: dir.path().join("ca")
            }
        );
        assert_eq!(settings.clients, dir.path().join("clients.toml"));
    }

    #[test]
    fn load_rejects_config_fragment_path_that_is_not_directory() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("exfilguard.toml");
        fs::write(&config_path, "").unwrap();
        fs::write(dir.path().join("config.d"), "not a directory").unwrap();

        let error = Settings::load(&Cli {
            config: Some(config_path),
        })
        .unwrap_err();

        assert!(
            error.to_string().contains("is not a directory"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_rejects_removed_persistent_leaf_cache_setting() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("exfilguard.toml");
        fs::write(
            &config_path,
            r#"
	listen = "127.0.0.1:3128"
	clients = "clients.toml"
	policies = "policies.toml"
	cert_cache_dir = "leaf-cache"

	[ca]
	source = "builtin"
	dir = "ca"
"#,
        )
        .unwrap();

        let error = Settings::load(&Cli {
            config: Some(config_path),
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("cert_cache_dir")
                && error.to_string().contains("unknown field"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn test_settings_validation_cache_enabled() {
        let settings = Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            proxy_protocol: ProxyProtocolMode::Off,
            proxy_protocol_allowed_cidrs: None,
            ca: CaSettings::Builtin {
                dir: PathBuf::from("ca"),
            },
            clients: PathBuf::from("clients.toml"),
            policies: PathBuf::from("policies.toml"),
            clients_dir: None,
            policies_dir: None,
            log: LogFormat::Text,
            leaf_ttl: 3600,
            leaf_cache_capacity: 4096,
            leaf_mint_concurrency: 4,
            log_queries: false,
            dns_resolve_timeout: 2,
            upstream_connect_timeout: 5,
            tls_handshake_timeout: 10,
            request_header_timeout: 10,
            request_body_idle_timeout: 30,
            response_header_timeout: 30,
            response_body_idle_timeout: 60,
            request_total_timeout: 0,
            client_keepalive_idle_timeout: 30,
            connect_tunnel_idle_timeout: 60,
            connect_tunnel_max_lifetime: 0,
            upstream_pool_capacity: 32,
            http2_max_concurrent_streams: 100,
            max_request_header_size: 1024,
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

        let mut unlimited = settings.clone();
        unlimited.max_request_body_size = 0;
        assert!(unlimited.validate().is_ok());

        let mut invalid_ca = settings.clone();
        let mut vault = valid_vault_settings(VaultAuth::Proxy {});
        vault.request_timeout = 0;
        invalid_ca.ca = CaSettings::Vault(Box::new(vault));
        assert!(invalid_ca.validate().is_err());

        let mut invalid_leaf_cache = settings.clone();
        invalid_leaf_cache.leaf_cache_capacity = 0;
        assert!(invalid_leaf_cache.validate().is_err());

        let mut invalid_mint_concurrency = settings;
        invalid_mint_concurrency.leaf_mint_concurrency = 0;
        assert!(invalid_mint_concurrency.validate().is_err());
    }

    #[test]
    fn test_settings_validation_cache_invalid_sizes() {
        let mut settings = Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            proxy_protocol: ProxyProtocolMode::Off,
            proxy_protocol_allowed_cidrs: None,
            ca: CaSettings::Builtin {
                dir: PathBuf::from("ca"),
            },
            clients: PathBuf::from("clients.toml"),
            policies: PathBuf::from("policies.toml"),
            clients_dir: None,
            policies_dir: None,
            log: LogFormat::Text,
            leaf_ttl: 3600,
            leaf_cache_capacity: 4096,
            leaf_mint_concurrency: 4,
            log_queries: false,
            dns_resolve_timeout: 2,
            upstream_connect_timeout: 5,
            tls_handshake_timeout: 10,
            request_header_timeout: 10,
            request_body_idle_timeout: 30,
            response_header_timeout: 30,
            response_body_idle_timeout: 60,
            request_total_timeout: 0,
            client_keepalive_idle_timeout: 30,
            connect_tunnel_idle_timeout: 60,
            connect_tunnel_max_lifetime: 0,
            upstream_pool_capacity: 32,
            http2_max_concurrent_streams: 100,
            max_request_header_size: 1024,
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

        settings.cache_total_capacity = 1024;
        settings.cache_max_entry_size = 1025;
        assert!(settings.validate().is_err());
    }

    #[test]
    fn test_settings_validation_cache_disabled_sizes_ignored() {
        let settings = Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            proxy_protocol: ProxyProtocolMode::Off,
            proxy_protocol_allowed_cidrs: None,
            ca: CaSettings::Builtin {
                dir: PathBuf::from("ca"),
            },
            clients: PathBuf::from("clients.toml"),
            policies: PathBuf::from("policies.toml"),
            clients_dir: None,
            policies_dir: None,
            log: LogFormat::Text,
            leaf_ttl: 3600,
            leaf_cache_capacity: 4096,
            leaf_mint_concurrency: 4,
            log_queries: false,
            dns_resolve_timeout: 2,
            upstream_connect_timeout: 5,
            tls_handshake_timeout: 10,
            request_header_timeout: 10,
            request_body_idle_timeout: 30,
            response_header_timeout: 30,
            response_body_idle_timeout: 60,
            request_total_timeout: 0,
            client_keepalive_idle_timeout: 30,
            connect_tunnel_idle_timeout: 60,
            connect_tunnel_max_lifetime: 0,
            upstream_pool_capacity: 32,
            http2_max_concurrent_streams: 100,
            max_request_header_size: 1024,
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

    #[test]
    fn test_settings_validation_proxy_protocol_requires_allowlist() {
        let settings = Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            proxy_protocol: ProxyProtocolMode::Required,
            proxy_protocol_allowed_cidrs: None,
            ca: CaSettings::Builtin {
                dir: PathBuf::from("ca"),
            },
            clients: PathBuf::from("clients.toml"),
            policies: PathBuf::from("policies.toml"),
            clients_dir: None,
            policies_dir: None,
            log: LogFormat::Text,
            leaf_ttl: 3600,
            leaf_cache_capacity: 4096,
            leaf_mint_concurrency: 4,
            log_queries: false,
            dns_resolve_timeout: 2,
            upstream_connect_timeout: 5,
            tls_handshake_timeout: 10,
            request_header_timeout: 10,
            request_body_idle_timeout: 30,
            response_header_timeout: 30,
            response_body_idle_timeout: 60,
            request_total_timeout: 0,
            client_keepalive_idle_timeout: 30,
            connect_tunnel_idle_timeout: 60,
            connect_tunnel_max_lifetime: 0,
            upstream_pool_capacity: 32,
            http2_max_concurrent_streams: 100,
            max_request_header_size: 1024,
            max_response_header_size: 1024,
            max_request_body_size: 1024,
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
        assert!(settings.validate().is_err());
    }
}
