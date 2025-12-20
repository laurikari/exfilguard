use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::Result;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use exfilguard::{
    cli::LogFormat,
    config,
    policy::{self, matcher::PolicySnapshot},
    proxy::{self, AppContext, PolicyStore},
    settings::Settings,
    tls::{ca::CertificateAuthority, cache::CertificateCache, issuer::TlsIssuer},
};

use rustls::{RootCertStore, client::ClientConfig};

use super::dirs::{TestDirs, write_clients_and_policies};
use super::net::{find_free_port, wait_for_listener};
use super::tls::build_proxy_tls_configs;

const CERT_CACHE_CAPACITY: usize = 512;

fn default_test_settings(listen: SocketAddr, dirs: &TestDirs) -> Settings {
    Settings {
        listen,
        ca_dir: dirs.ca_dir.clone(),
        clients: dirs.clients_path.clone(),
        clients_dir: None,
        policies: dirs.policies_path.clone(),
        policies_dir: None,
        cert_cache_dir: None,
        log: LogFormat::Text,
        leaf_ttl: 3_600,
        log_queries: false,
        client_timeout: 10,
        upstream_connect_timeout: 5,
        upstream_timeout: 10,
        upstream_pool_capacity: 32,
        max_request_header_size: 32 * 1024,
        max_response_header_size: 4096,
        max_request_body_size: 1024 * 1024,
        cache_dir: dirs.cache_dir.clone(),
        cache_max_entry_size: 10 * 1024 * 1024,
        cache_max_entries: 10_000,
        cache_total_capacity: 1024 * 1024 * 1024,
        cache_sweeper_interval: 300,
        cache_sweeper_batch_size: 1000,
        metrics_listen: None,
        metrics_tls_cert: None,
        metrics_tls_key: None,
    }
}

fn build_app_context(
    settings: Arc<Settings>,
    policy_store: PolicyStore,
    ca: Arc<CertificateAuthority>,
    tls_issuer: Arc<TlsIssuer>,
    client_http1: Arc<ClientConfig>,
    client_http2: Arc<ClientConfig>,
    cache: Option<Arc<proxy::cache::HttpCache>>,
) -> AppContext {
    let tls = Arc::new(proxy::TlsContext::new(
        ca,
        tls_issuer,
        client_http1,
        client_http2,
    ));
    AppContext::new(settings, policy_store, tls, cache)
}

pub struct ProxyHarness {
    pub dirs: TestDirs,
    pub addr: SocketAddr,
    pub settings: Arc<Settings>,
    pub ca: Arc<CertificateAuthority>,
    pub cache: Option<Arc<proxy::cache::HttpCache>>,
    _policy_tx: watch::Sender<PolicySnapshot>,
    handle: JoinHandle<()>,
}

impl ProxyHarness {
    pub async fn connect(&self) -> Result<TcpStream> {
        Ok(TcpStream::connect(self.addr).await?)
    }

    pub async fn shutdown(self) {
        self.handle.abort();
        let _ = self.handle.await;
    }
}

pub struct ProxyHarnessBuilder {
    dirs: TestDirs,
    clients: String,
    policies: String,
    proxy_root_store: RootCertStore,
    cache: Option<Arc<proxy::cache::HttpCache>>,
    settings_override: Option<Box<dyn FnOnce(&mut Settings) + Send>>,
}

impl ProxyHarnessBuilder {
    pub fn new(clients: &str, policies: &str) -> Result<Self> {
        Ok(Self::with_dirs(TestDirs::new()?, clients, policies))
    }

    pub fn with_dirs(dirs: TestDirs, clients: &str, policies: &str) -> Self {
        Self {
            dirs,
            clients: clients.to_string(),
            policies: policies.to_string(),
            proxy_root_store: RootCertStore::empty(),
            cache: None,
            settings_override: None,
        }
    }

    pub fn with_cache_dir(mut self) -> Result<Self> {
        self.dirs.enable_cache_dir()?;
        Ok(self)
    }

    pub fn with_cache(mut self, cache: Arc<proxy::cache::HttpCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn with_proxy_root_store(mut self, root_store: RootCertStore) -> Self {
        self.proxy_root_store = root_store;
        self
    }

    pub fn with_settings<F>(mut self, func: F) -> Self
    where
        F: FnOnce(&mut Settings) + Send + 'static,
    {
        self.settings_override = Some(Box::new(func));
        self
    }

    pub async fn spawn(mut self) -> Result<ProxyHarness> {
        write_clients_and_policies(&self.dirs, &self.clients, &self.policies)?;

        let ca = Arc::new(CertificateAuthority::load_or_generate(&self.dirs.ca_dir)?);
        let config_doc = config::load_config(&self.dirs.clients_path, &self.dirs.policies_path)?;
        let compiled = Arc::new(policy::compile::compile_config(&config_doc)?);
        let snapshot = PolicySnapshot::new(compiled);
        let (policy_tx, policy_rx) = watch::channel(snapshot);
        let policy_store = PolicyStore::new(policy_rx);

        let proxy_port = find_free_port()?;
        let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}")
            .parse()
            .expect("valid listen address");

        let mut settings = default_test_settings(proxy_addr, &self.dirs);
        if let Some(override_fn) = self.settings_override.take() {
            override_fn(&mut settings);
        }
        let proxy_addr = settings.listen;
        let settings = Arc::new(settings);

        let cert_cache = Arc::new(CertificateCache::new(
            CERT_CACHE_CAPACITY,
            settings.cert_cache_dir.clone(),
        )?);
        let tls_issuer = Arc::new(TlsIssuer::new(ca.clone(), cert_cache, settings.leaf_ttl())?);

        let (proxy_client_config, proxy_client_h2_config) =
            build_proxy_tls_configs(self.proxy_root_store)?;

        let cache = if let Some(cache) = self.cache.take() {
            Some(cache)
        } else if let Some(cache_dir) = self.dirs.cache_dir.clone() {
            Some(Arc::new(
                proxy::cache::HttpCache::new(
                    settings.cache_max_entries,
                    cache_dir,
                    settings.cache_max_entry_size,
                    settings.cache_total_capacity,
                    StdDuration::from_secs(settings.cache_sweeper_interval),
                    settings.cache_sweeper_batch_size,
                )
                .await?,
            ))
        } else {
            None
        };

        let app = build_app_context(
            settings.clone(),
            policy_store,
            ca.clone(),
            tls_issuer,
            proxy_client_config,
            proxy_client_h2_config,
            cache.clone(),
        );

        let handle = tokio::spawn(async move {
            if let Err(err) = proxy::run(app).await {
                tracing::error!(error = ?err, "proxy run failed");
            }
        });

        wait_for_listener(proxy_addr).await?;

        Ok(ProxyHarness {
            dirs: self.dirs,
            addr: proxy_addr,
            settings,
            ca,
            cache,
            _policy_tx: policy_tx,
            handle,
        })
    }
}
