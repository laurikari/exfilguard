pub mod cli;
pub mod config;
pub mod logging;
pub mod metrics;
pub mod policy;
pub mod proxy;
pub mod settings;
pub mod tls;
pub mod util;

use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use rustls::crypto::ring;
use rustls::{RootCertStore, client::ClientConfig};
use rustls_native_certs as native_certs;
use tokio::sync::watch;
use tokio::time::{Duration, sleep};
use tracing::warn;

use crate::{
    policy::matcher::PolicySnapshot,
    proxy::{default_upstream_resolver, permissive_test_upstream_resolver},
    settings::{CaSettings, Settings, VaultAuth},
    tls::{
        ca::CertificateAuthority,
        cache::CertificateCache,
        issuer::TlsIssuer,
        vault::{VaultAuthConfig, VaultCaSource, VaultConfig},
    },
};

pub async fn run(settings: Settings) -> Result<()> {
    run_with_upstream_resolver(settings, default_upstream_resolver()).await
}

#[doc(hidden)]
pub async fn run_for_tests(settings: Settings) -> Result<()> {
    run_with_upstream_resolver(settings, permissive_test_upstream_resolver()).await
}

async fn run_with_upstream_resolver(
    settings: Settings,
    upstream_resolver: Arc<dyn proxy::UpstreamResolver>,
) -> Result<()> {
    settings.validate()?;
    let StartupPreflight {
        policy_snapshot,
        tls_client_configs,
    } = build_startup_preflight(&settings)?;
    let settings = Arc::new(settings);
    let metrics = settings.metrics_listen.map(|addr| {
        let path = "/metrics".to_string();
        let tls = match (&settings.metrics_tls_cert, &settings.metrics_tls_key) {
            (Some(cert), Some(key)) => Some(crate::metrics::MetricsTlsConfig {
                cert_path: cert.clone(),
                key_path: key.clone(),
            }),
            _ => None,
        };
        (addr, path, tls)
    });
    let (ca, ca_source, vault_source) = load_ca(&settings.ca).await?;
    let cert_cache = Arc::new(CertificateCache::new(settings.leaf_cache_capacity)?);
    let tls_issuer = Arc::new(TlsIssuer::new(
        ca.clone(),
        cert_cache.clone(),
        settings.leaf_ttl(),
        settings.leaf_mint_concurrency,
    )?);
    crate::metrics::set_ca_state(
        ca_source,
        ca.root_not_after().unix_timestamp(),
        ca.intermediate_not_after().unix_timestamp(),
        true,
        tls_issuer.generation(),
    );
    if let Some(vault_source) = vault_source {
        vault_source.spawn_renewal(tls_issuer.clone());
    }
    spawn_ca_usability_monitor(tls_issuer.clone());
    let TlsClientConfigs { http1, http2 } = tls_client_configs;
    crate::metrics::mark_policy_reload_success();
    let (policy_tx, policy_rx) = watch::channel(policy_snapshot);
    spawn_runtime_policy_reload_task(settings.clone(), policy_tx);
    let policy_store = proxy::PolicyStore::new(policy_rx);
    let tls_context = Arc::new(proxy::TlsContext::new(tls_issuer, http1, http2));

    let cache = if let Some(cache_dir) = &settings.cache_dir {
        Some(Arc::new(
            proxy::cache::HttpCache::new(
                settings.cache_max_entries,
                cache_dir.clone(),
                settings.cache_max_entry_size,
                settings.cache_total_capacity,
                settings.cache_sweeper_interval(),
                settings.cache_sweeper_batch_size,
            )
            .await?,
        ))
    } else {
        None
    };

    let app = proxy::AppContext::new(settings, policy_store, tls_context, cache)
        .with_upstream_resolver(upstream_resolver);

    if let Some((addr, path, tls)) = metrics {
        tracing::info!(address = %addr, tls = tls.is_some(), "metrics endpoint starting");
        tokio::select! {
            res = crate::metrics::serve(addr, path, tls) => res,
            res = proxy::run(app) => res,
        }
    } else {
        proxy::run(app).await
    }
}

struct StartupPreflight {
    policy_snapshot: PolicySnapshot,
    tls_client_configs: TlsClientConfigs,
}

fn build_startup_preflight(settings: &Settings) -> Result<StartupPreflight> {
    Ok(StartupPreflight {
        policy_snapshot: build_runtime_policy_snapshot(settings)?,
        tls_client_configs: build_tls_client_configs(settings)?,
    })
}

fn spawn_ca_usability_monitor(issuer: Arc<TlsIssuer>) {
    tokio::spawn(async move {
        loop {
            let usable = issuer.current_ca().intermediate_not_after()
                > time::OffsetDateTime::now_utc() + time::Duration::minutes(5);
            crate::metrics::set_ca_issuer_usable(usable);
            sleep(Duration::from_secs(60)).await;
        }
    });
}

async fn load_ca(
    settings: &CaSettings,
) -> Result<(
    Arc<CertificateAuthority>,
    &'static str,
    Option<Arc<VaultCaSource>>,
)> {
    match settings {
        CaSettings::Builtin { dir } => Ok((
            Arc::new(CertificateAuthority::load_builtin(dir)?),
            "builtin",
            None,
        )),
        CaSettings::Files { dir } => Ok((
            Arc::new(CertificateAuthority::load_files(dir)?),
            "files",
            None,
        )),
        CaSettings::Vault(settings) => {
            let auth = match &settings.auth {
                VaultAuth::AppRole {
                    mount,
                    role_id,
                    secret_id_file,
                } => VaultAuthConfig::AppRole {
                    mount: mount.clone(),
                    role_id: role_id.clone(),
                    secret_id_file: secret_id_file.clone(),
                },
                VaultAuth::TokenFile { token_file } => VaultAuthConfig::TokenFile {
                    token_file: token_file.clone(),
                },
                VaultAuth::Proxy {} => VaultAuthConfig::Proxy,
            };
            let source = Arc::new(VaultCaSource::new(VaultConfig {
                address: settings.address.clone(),
                tls_ca_cert: settings.tls_ca_cert.clone(),
                tls_server_name: settings.tls_server_name.clone(),
                namespace: settings.namespace.clone(),
                pki_mount: settings.pki_mount.clone(),
                issuer: settings.issuer.clone(),
                expected_root_certs: settings.expected_root_certs.clone(),
                intermediate_ttl: settings.intermediate_ttl(),
                renewal_threshold: settings.renewal_threshold(),
                request_timeout: settings.request_timeout(),
                tls_client_cert: settings.tls_client_cert.clone(),
                tls_client_key: settings.tls_client_key.clone(),
                auth,
            })?);
            let ca = source
                .issue()
                .await
                .context("failed to initialize Vault-backed CA")?;
            Ok((ca, "vault", Some(source)))
        }
    }
}

/// Reloadable runtime state derived from the configured client/policy files.
///
/// This intentionally excludes startup-owned settings such as listeners,
/// metrics, cache, and TLS/material configuration.
fn build_runtime_policy_snapshot(settings: &Settings) -> Result<PolicySnapshot> {
    let config = settings.load_runtime_config()?;
    let compiled = Arc::new(policy::compile::compile_config(&config)?);
    Ok(PolicySnapshot::new(compiled))
}

struct TlsClientConfigs {
    http1: Arc<ClientConfig>,
    http2: Arc<ClientConfig>,
}

fn build_tls_client_configs(_settings: &Settings) -> Result<TlsClientConfigs> {
    let provider = ring::default_provider();
    let builder = ClientConfig::builder_with_provider(provider.into());
    let builder = builder.with_safe_default_protocol_versions()?;

    let mut root_store = RootCertStore::empty();
    let mut anchors_loaded = 0usize;

    let native = native_certs::load_native_certs();
    if !native.errors.is_empty() {
        for err in &native.errors {
            warn!(error = %err, "failed to load some system trust anchors");
        }
    }
    let (added, ignored) = root_store.add_parsable_certificates(native.certs);
    if ignored > 0 {
        warn!(ignored, "ignored {ignored} invalid system trust anchors");
    }
    if added == 0 {
        warn!("no trust anchors loaded from system locations; outbound TLS verification may fail");
    }
    anchors_loaded += added;

    ensure!(
        anchors_loaded > 0,
        "no trust anchors available; install system certificates or provide a custom trust store"
    );

    let builder = builder.with_root_certificates(Arc::new(root_store));
    let mut http1 = builder.with_no_client_auth();
    http1.alpn_protocols = vec![b"http/1.1".to_vec()];

    let mut http2 = http1.clone();
    http2.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsClientConfigs {
        http1: Arc::new(http1),
        http2: Arc::new(http2),
    })
}

#[cfg(unix)]
fn spawn_runtime_policy_reload_task(
    settings: Arc<Settings>,
    policy_tx: watch::Sender<PolicySnapshot>,
) {
    use tokio::signal::unix::{SignalKind, signal};

    tokio::spawn(async move {
        let mut hup = match signal(SignalKind::hangup()) {
            Ok(signal) => signal,
            Err(err) => {
                tracing::error!(error = %err, "failed to install SIGHUP handler");
                return;
            }
        };

        while hup.recv().await.is_some() {
            tracing::info!("received SIGHUP; reloading runtime policy");
            match build_runtime_policy_snapshot(&settings) {
                Ok(snapshot) => {
                    let client_count = snapshot.client_count();
                    let policy_count = snapshot.policy_count();
                    if let Err(err) = policy_tx.send(snapshot) {
                        tracing::error!(
                            error = %err,
                            "failed to publish reloaded runtime policy"
                        );
                        break;
                    }
                    crate::metrics::mark_policy_reload_success();
                    tracing::info!(client_count, policy_count, "runtime policy reloaded");
                }
                Err(err) => {
                    tracing::error!(error = ?err, "runtime policy reload failed");
                }
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_runtime_policy_reload_task(
    _settings: Arc<Settings>,
    _policy_tx: watch::Sender<PolicySnapshot>,
) {
    tracing::info!("SIGHUP runtime policy reload is not supported on this platform");
}
pub mod io_util;

#[cfg(test)]
mod startup_tests {
    use std::fs;

    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn invalid_policy_does_not_create_builtin_ca_material() -> Result<()> {
        let directory = TempDir::new()?;
        let ca_dir = directory.path().join("ca");
        let clients_path = directory.path().join("clients.toml");
        let policies_path = directory.path().join("policies.toml");
        fs::write(
            &clients_path,
            r#"
[[client]]
name = "fallback"
policies = ["present-policy"]
fallback = true
"#,
        )?;
        fs::write(
            &policies_path,
            r#"
[[policy]]
name = "present-policy"
  [[policy.rule]]
  action = "DENY"
"#,
        )?;

        let settings: Settings = toml::from_str(&format!(
            r#"
listen = "127.0.0.1:0"
clients = {clients_path:?}
policies = {policies_path:?}
ca = {{ source = "builtin", dir = {ca_dir:?} }}
"#,
            clients_path = clients_path.to_string_lossy(),
            policies_path = policies_path.to_string_lossy(),
            ca_dir = ca_dir.to_string_lossy(),
        ))?;

        let err = run_for_tests(settings)
            .await
            .expect_err("invalid policy must fail startup");
        assert!(err.to_string().contains("must set status"), "{err:?}");
        assert!(
            !ca_dir.exists(),
            "policy preflight failure created CA material"
        );
        Ok(())
    }
}
