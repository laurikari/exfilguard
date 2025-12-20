#![allow(clippy::type_complexity)]
#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::{Context, Result, anyhow};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use exfilguard::{
    cli::LogFormat,
    config,
    policy::{self, matcher::PolicySnapshot},
    proxy::{self, AppContext, PolicyStore},
    settings::Settings,
    tls::{ca::CertificateAuthority, cache::CertificateCache, issuer::TlsIssuer},
};

use rustls::{RootCertStore, client::ClientConfig, crypto::ring};

pub const CERT_CACHE_CAPACITY: usize = 512;

pub struct TestDirs {
    _temp: TempDir,
    pub ca_dir: PathBuf,
    pub config_dir: PathBuf,
    pub clients_path: PathBuf,
    pub policies_path: PathBuf,
    pub cache_dir: Option<PathBuf>,
}

impl TestDirs {
    pub fn new() -> Result<Self> {
        let temp = TempDir::new()?;
        let workspace = temp.path();
        let ca_dir = workspace.join("ca");
        let config_dir = workspace.join("config");
        std::fs::create_dir_all(&ca_dir)?;
        std::fs::create_dir_all(&config_dir)?;

        let clients_path = config_dir.join("clients.toml");
        let policies_path = config_dir.join("policies.toml");

        Ok(Self {
            _temp: temp,
            ca_dir,
            config_dir,
            clients_path,
            policies_path,
            cache_dir: None,
        })
    }

    pub fn enable_cache_dir(&mut self) -> Result<&Path> {
        if self.cache_dir.is_none() {
            let cache_dir = self
                .config_dir
                .parent()
                .unwrap_or(Path::new("."))
                .join("http_cache");
            std::fs::create_dir_all(&cache_dir)?;
            self.cache_dir = Some(cache_dir);
        }
        Ok(self.cache_dir.as_deref().expect("cache_dir set"))
    }
}

pub fn write_clients_and_policies(dirs: &TestDirs, clients: &str, policies: &str) -> Result<()> {
    std::fs::write(&dirs.clients_path, clients)?;
    std::fs::write(&dirs.policies_path, policies)?;
    Ok(())
}

pub fn default_test_settings(listen: SocketAddr, dirs: &TestDirs) -> Settings {
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

pub fn find_free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

pub async fn wait_for_listener(addr: SocketAddr) -> Result<()> {
    for _ in 0..50 {
        match timeout(StdDuration::from_millis(50), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                stream.shutdown().await.ok();
                return Ok(());
            }
            _ => sleep(StdDuration::from_millis(50)).await,
        }
    }
    Err(anyhow!("listener {addr} did not become ready"))
}

pub fn build_proxy_tls_configs(
    root_store: RootCertStore,
) -> Result<(Arc<ClientConfig>, Arc<ClientConfig>)> {
    let http1 = build_client_tls(root_store.clone())?;
    let http2 = build_client_tls_h2(root_store)?;
    Ok((http1, http2))
}

pub fn build_client_tls(root_store: RootCertStore) -> Result<Arc<ClientConfig>> {
    build_client_tls_with_protocols(root_store, vec![b"http/1.1".to_vec()])
}

pub fn build_client_tls_h2(root_store: RootCertStore) -> Result<Arc<ClientConfig>> {
    build_client_tls_with_protocols(root_store, vec![b"h2".to_vec(), b"http/1.1".to_vec()])
}

pub fn build_client_tls_with_protocols(
    root_store: RootCertStore,
    protocols: Vec<Vec<u8>>,
) -> Result<Arc<ClientConfig>> {
    let provider = ring::default_provider();
    let builder = ClientConfig::builder_with_provider(provider.into());
    let builder = builder.with_safe_default_protocol_versions()?;
    let builder = builder.with_root_certificates(Arc::new(root_store));
    let mut config = builder.with_no_client_auth();
    config.alpn_protocols = protocols;
    Ok(Arc::new(config))
}

pub fn build_app_context(
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

pub async fn read_http_response<S>(stream: &mut S) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

pub async fn read_response_status(reader: &mut BufReader<TcpStream>) -> Result<u16> {
    let mut line = String::new();
    let bytes = timeout(StdDuration::from_secs(2), reader.read_line(&mut line)).await??;
    if bytes == 0 {
        return Err(anyhow!("connection closed before response status line"));
    }
    let status = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("missing status code in response line"))?
        .parse::<u16>()
        .map_err(|err| anyhow!("invalid status code: {err}"))?;
    loop {
        line.clear();
        let n = timeout(StdDuration::from_secs(2), reader.read_line(&mut line)).await??;
        if n == 0 || line == "\r\n" {
            break;
        }
    }
    Ok(status)
}

pub async fn read_until_double_crlf(stream: &mut TcpStream) -> Result<String> {
    let mut buffer = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let bytes = stream.read(&mut byte).await?;
        if bytes == 0 {
            break;
        }
        buffer.extend_from_slice(&byte);
        if buffer.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(buffer).context("invalid UTF-8 response")
}
