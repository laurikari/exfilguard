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

use anyhow::{Result, ensure};
use rustls::crypto::ring;
use rustls::{RootCertStore, client::ClientConfig};
use rustls_native_certs as native_certs;
use tokio::sync::watch;
use tracing::warn;

use crate::{
    policy::matcher::PolicySnapshot,
    settings::Settings,
    tls::{ca::CertificateAuthority, cache::CertificateCache, issuer::TlsIssuer},
};

const DEFAULT_CERT_CACHE_CAPACITY: usize = 512;

pub async fn run(settings: Settings) -> Result<()> {
    let settings = Arc::new(settings);
    if let Some(addr) = settings.metrics_listen {
        let path = "/metrics".to_string();
        let tls = match (&settings.metrics_tls_cert, &settings.metrics_tls_key) {
            (Some(cert), Some(key)) => Some(crate::metrics::MetricsTlsConfig {
                cert_path: cert.clone(),
                key_path: key.clone(),
            }),
            _ => None,
        };
        tokio::spawn(async move {
            tracing::info!(address = %addr, tls = tls.is_some(), "metrics endpoint starting");
            if let Err(err) = crate::metrics::serve(addr, path, tls).await {
                tracing::error!(error = %err, "metrics endpoint failed");
            }
        });
    }
    let ca = Arc::new(CertificateAuthority::load_or_generate(&settings.ca_dir)?);
    let cert_cache_dir = settings.cert_cache_dir.clone();
    let cert_cache = Arc::new(CertificateCache::new(
        DEFAULT_CERT_CACHE_CAPACITY,
        cert_cache_dir,
    )?);
    let tls_issuer = Arc::new(TlsIssuer::new(
        ca.clone(),
        cert_cache.clone(),
        settings.leaf_ttl(),
    )?);
    let TlsClientConfigs { http1, http2 } = build_tls_client_configs(&settings)?;
    let snapshot = build_policy_snapshot(&settings)?;
    let (policy_tx, policy_rx) = watch::channel(snapshot.clone());
    spawn_reload_task(settings.clone(), policy_tx);
    let policy_store = proxy::PolicyStore::new(policy_rx);
    let tls_context = Arc::new(proxy::TlsContext::new(ca, tls_issuer, http1, http2));

    let cache = if let Some(cache_dir) = &settings.cache_dir {
        Some(Arc::new(
            proxy::cache::HttpCache::new(
                settings.cache_max_entries,
                cache_dir.clone(),
                settings.cache_max_entry_size,
                settings.cache_total_capacity,
            )
            .await?,
        ))
    } else {
        None
    };

    let app = proxy::AppContext::new(settings, policy_store, tls_context, cache);
    proxy::run(app).await
}

fn build_policy_snapshot(settings: &Settings) -> Result<PolicySnapshot> {
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

    match native_certs::load_native_certs() {
        Ok(certs) => {
            let (added, ignored) = root_store.add_parsable_certificates(certs);
            if ignored > 0 {
                warn!(ignored, "ignored {ignored} invalid system trust anchors");
            }
            if added == 0 {
                warn!(
                    "no trust anchors loaded from system locations; outbound TLS verification may fail"
                );
            }
            anchors_loaded += added;
        }
        Err(err) => {
            warn!(error = %err, "failed to load system trust anchors");
        }
    }

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
fn spawn_reload_task(settings: Arc<Settings>, policy_tx: watch::Sender<PolicySnapshot>) {
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
            tracing::info!("received SIGHUP; reloading configuration");
            match build_policy_snapshot(&settings) {
                Ok(snapshot) => {
                    let client_count = snapshot.compiled.clients.len();
                    let policy_count = snapshot.compiled.policies.len();
                    if let Err(err) = policy_tx.send(snapshot) {
                        tracing::error!(error = %err, "failed to publish reloaded configuration");
                        break;
                    }
                    tracing::info!(client_count, policy_count, "configuration reloaded");
                }
                Err(err) => {
                    tracing::error!(error = ?err, "configuration reload failed");
                }
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_reload_task(_settings: Arc<Settings>, _policy_tx: watch::Sender<PolicySnapshot>) {
    tracing::info!("SIGHUP reload is not supported on this platform");
}
pub mod io_util;
