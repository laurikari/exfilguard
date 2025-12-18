use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration as StdDuration,
};

use anyhow::Result;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

use exfilguard::{
    cli::LogFormat,
    config,
    policy::{self, matcher::PolicySnapshot},
    proxy::{self, AppContext, PolicyStore},
    settings::Settings,
    tls::{ca::CertificateAuthority, cache::CertificateCache, issuer::TlsIssuer},
};

use rustls::{RootCertStore, client::ClientConfig, crypto::ring};

const CERT_CACHE_CAPACITY: usize = 512;

fn default_test_settings(
    listen: SocketAddr,
    ca_dir: &Path,
    clients: &Path,
    policies: &Path,
    cache_dir: Option<&Path>,
) -> Settings {
    Settings {
        listen,
        ca_dir: ca_dir.to_path_buf(),
        clients: clients.to_path_buf(),
        clients_dir: None,
        policies: policies.to_path_buf(),
        policies_dir: None,
        cert_cache_dir: None,
        log: LogFormat::Text,
        leaf_ttl: 3_600,
        log_queries: false,
        client_timeout: 10,
        upstream_connect_timeout: 5,
        upstream_timeout: 10,
        upstream_pool_capacity: 32,
        max_header_size: 32 * 1024,
        max_response_header_size: 4096,
        max_body_size: 1024 * 1024,
        cache_dir: cache_dir.map(|p| p.to_path_buf()),
        cache_max_entry_size: 10 * 1024 * 1024,
        cache_max_entries: 10_000,
        cache_total_capacity: 1024 * 1024 * 1024,
        metrics_listen: None,
        metrics_tls_cert: None,
        metrics_tls_key: None,
    }
}

fn find_free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

async fn wait_for_listener(addr: SocketAddr) -> Result<()> {
    let start = std::time::Instant::now();
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if start.elapsed() > StdDuration::from_secs(5) {
            anyhow::bail!("timed out waiting for listener {}", addr);
        }
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }
}

fn build_proxy_tls_configs(
    root_store: RootCertStore,
) -> Result<(Arc<ClientConfig>, Arc<ClientConfig>)> {
    let provider = ring::default_provider();
    let mut http1 = ClientConfig::builder_with_provider(provider.clone().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store.clone())
        .with_no_client_auth();
    http1.alpn_protocols = vec![b"http/1.1".to_vec()];

    let mut http2 = ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    http2.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok((Arc::new(http1), Arc::new(http2)))
}

fn build_app_context(
    settings: Arc<Settings>,
    policy_store: PolicyStore,
    ca: Arc<CertificateAuthority>,
    tls_issuer: Arc<TlsIssuer>,
    proxy_client_config: Arc<ClientConfig>,
    proxy_client_h2_config: Arc<ClientConfig>,
    cache: Option<Arc<exfilguard::proxy::cache::HttpCache>>,
) -> AppContext {
    let tls_context = Arc::new(proxy::TlsContext::new(
        ca,
        tls_issuer,
        proxy_client_config,
        proxy_client_h2_config,
    ));
    AppContext::new(settings, policy_store, tls_context, cache)
}

// Minimal HTTP upstream that counts requests
struct MockUpstream {
    listener: TcpListener,
    requests: Arc<AtomicUsize>,
    headers: String,
}

impl MockUpstream {
    async fn new(headers: &str) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        Ok(Self {
            listener,
            requests: Arc::new(AtomicUsize::new(0)),
            headers: headers.to_string(),
        })
    }

    fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    async fn run(self) -> Result<()> {
        loop {
            let (mut socket, _) = self.listener.accept().await?;
            let requests = self.requests.clone();
            let headers = self.headers.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut data = Vec::new();
                loop {
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    data.extend_from_slice(&buf[..n]);
                    if data.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }

                if data.is_empty() {
                    return;
                }

                requests.fetch_add(1, Ordering::SeqCst);

                let body = "cached-response";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n\r\n{}",
                    body.len(),
                    headers,
                    body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.shutdown().await.ok();
            });
        }
    }
}

async fn read_http_response<S>(stream: &mut S) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

async fn run_cache_bypass_test(upstream_headers: &str, request_headers: &str) -> Result<()> {
    let temp = tempfile::TempDir::new()?;
    let workspace = temp.path();
    let ca_dir = workspace.join("ca");
    let config_dir = workspace.join("config");
    let cache_dir = workspace.join("http_cache");
    std::fs::create_dir_all(&ca_dir)?;
    std::fs::create_dir_all(&config_dir)?;
    std::fs::create_dir_all(&cache_dir)?;

    let upstream = MockUpstream::new(upstream_headers).await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();

    let upstream_task = tokio::spawn(upstream.run());

    let clients_path = config_dir.join("clients.toml");
    let policies_path = config_dir.join("policies.toml");

    std::fs::write(
        &clients_path,
        r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["cache-test"]
catch_all = true
"#,
    )?;

    std::fs::write(
        &policies_path,
        format!(
            r#"[[policy]]
name = "cache-test"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["GET"]
  url_pattern = "http://127.0.0.1:{upstream_port}/**"
  allow_private_connect = true
  [policy.rule.cache]
"#,
        ),
    )?;

    let ca = Arc::new(CertificateAuthority::load_or_generate(&ca_dir)?);
    let config_doc = config::load_config(&clients_path, &policies_path)?;
    let compiled = Arc::new(policy::compile::compile_config(&config_doc)?);
    let snapshot = PolicySnapshot::new(compiled);
    let (_policy_tx, policy_rx) = watch::channel(snapshot);
    let policy_store = PolicyStore::new(policy_rx);

    let proxy_port = find_free_port()?;
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}")
        .parse()
        .expect("valid listen address");
    let settings = Arc::new(default_test_settings(
        proxy_addr,
        &ca_dir,
        &clients_path,
        &policies_path,
        Some(&cache_dir),
    ));

    let cert_cache = Arc::new(CertificateCache::new(CERT_CACHE_CAPACITY, None)?);
    let tls_issuer = Arc::new(TlsIssuer::new(ca.clone(), cert_cache, settings.leaf_ttl())?);
    let (proxy_client_config, proxy_client_h2_config) =
        build_proxy_tls_configs(RootCertStore::empty())?;

    let http_cache = Arc::new(exfilguard::proxy::cache::HttpCache::new(
        100,
        cache_dir.clone(),
        1024 * 1024,
        settings.cache_total_capacity,
    )?);

    let app = build_app_context(
        settings.clone(),
        policy_store,
        ca.clone(),
        tls_issuer,
        proxy_client_config.clone(),
        proxy_client_h2_config.clone(),
        Some(http_cache),
    );

    let proxy_handle = tokio::spawn(async move {
        if let Err(err) = proxy::run(app).await {
            tracing::error!(error = ?err, "proxy run failed");
        }
    });

    wait_for_listener(proxy_addr).await?;

    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/resource HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n{request_headers}Connection: close\r\n\r\n"
    );

    // First Request (Miss)
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.write_all(request.as_bytes()).await?;
    let response = read_http_response(&mut stream).await?;
    assert!(response.contains("cached-response"));
    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        1,
        "Should hit upstream"
    );

    tokio::time::sleep(StdDuration::from_millis(200)).await;

    // Second Request (Should Miss due to bypass)
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.write_all(request.as_bytes()).await?;
    let response = read_http_response(&mut stream).await?;
    assert!(
        response.contains("cached-response"),
        "Unexpected response: {}",
        response
    );
    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        2,
        "Should hit upstream again"
    );

    proxy_handle.abort();
    upstream_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cache_hit_avoids_upstream() -> Result<()> {
    let _ = exfilguard::logging::init_logger(LogFormat::Text);
    let temp = tempfile::TempDir::new()?;
    let workspace = temp.path();
    let ca_dir = workspace.join("ca");
    let config_dir = workspace.join("config");
    let cache_dir = workspace.join("http_cache");
    std::fs::create_dir_all(&ca_dir)?;
    std::fs::create_dir_all(&config_dir)?;
    std::fs::create_dir_all(&cache_dir)?;

    let upstream = MockUpstream::new("Cache-Control: public, max-age=60").await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();

    let upstream_task = tokio::spawn(upstream.run());

    let clients_path = config_dir.join("clients.toml");
    let policies_path = config_dir.join("policies.toml");

    std::fs::write(
        &clients_path,
        r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["cache-test"]
catch_all = true
"#,
    )?;

    std::fs::write(
        &policies_path,
        format!(
            r#"[[policy]]
name = "cache-test"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["GET"]
  url_pattern = "http://127.0.0.1:{upstream_port}/**"
  allow_private_connect = true
  [policy.rule.cache]
"#,
        ),
    )?;

    let ca = Arc::new(CertificateAuthority::load_or_generate(&ca_dir)?);
    let config_doc = config::load_config(&clients_path, &policies_path)?;
    let compiled = Arc::new(policy::compile::compile_config(&config_doc)?);
    let snapshot = PolicySnapshot::new(compiled);
    let (_policy_tx, policy_rx) = watch::channel(snapshot);
    let policy_store = PolicyStore::new(policy_rx);

    let proxy_port = find_free_port()?;
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}")
        .parse()
        .expect("valid listen address");
    let settings = Arc::new(default_test_settings(
        proxy_addr,
        &ca_dir,
        &clients_path,
        &policies_path,
        Some(&cache_dir),
    ));

    let cert_cache = Arc::new(CertificateCache::new(CERT_CACHE_CAPACITY, None)?);
    let tls_issuer = Arc::new(TlsIssuer::new(ca.clone(), cert_cache, settings.leaf_ttl())?);
    let (proxy_client_config, proxy_client_h2_config) =
        build_proxy_tls_configs(RootCertStore::empty())?;

    let http_cache = Arc::new(exfilguard::proxy::cache::HttpCache::new(
        100,
        cache_dir.clone(),
        1024 * 1024,
        settings.cache_total_capacity,
    )?);

    let app = build_app_context(
        settings.clone(),
        policy_store,
        ca.clone(),
        tls_issuer,
        proxy_client_config.clone(),
        proxy_client_h2_config.clone(),
        Some(http_cache),
    );

    let proxy_handle = tokio::spawn(async move {
        if let Err(err) = proxy::run(app).await {
            tracing::error!(error = ?err, "proxy run failed");
        }
    });

    wait_for_listener(proxy_addr).await?;

    // First Request (Miss)
    let mut stream = TcpStream::connect(proxy_addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/resource HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let response = read_http_response(&mut stream).await?;
    assert!(
        response.contains("cached-response"),
        "Unexpected response: {}",
        response
    );
    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        1,
        "Should hit upstream once"
    );

    // Allow cache write to settle
    tokio::time::sleep(StdDuration::from_millis(2000)).await;

    // Second Request (Hit)
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.write_all(request.as_bytes()).await?;
    let response = read_http_response(&mut stream).await?;
    assert!(
        response.contains("cached-response"),
        "Response should contain cached body"
    );
    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        1,
        "Should NOT hit upstream again (cache hit expected)"
    );

    proxy_handle.abort();
    upstream_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cache_bypass_on_no_store() -> Result<()> {
    run_cache_bypass_test("Cache-Control: no-store", "").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cache_bypass_on_no_cache() -> Result<()> {
    run_cache_bypass_test("Cache-Control: no-cache", "").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cache_bypass_on_authorization_header() -> Result<()> {
    run_cache_bypass_test(
        "Cache-Control: public, max-age=60",
        "Authorization: Bearer token\r\n",
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cache_bypass_on_cookie_header() -> Result<()> {
    run_cache_bypass_test(
        "Cache-Control: public, max-age=60",
        "Cookie: session=abc\r\n",
    )
    .await
}
