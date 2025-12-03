use std::{
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration as StdDuration,
};

use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::{sleep, timeout},
};

use exfilguard::{
    cli::LogFormat,
    config,
    policy::{self, matcher::PolicySnapshot},
    proxy::{self, AppContext, PolicyStore},
    settings::Settings,
    tls::{ca::CertificateAuthority, cache::CertificateCache, issuer::TlsIssuer},
};

const CERT_CACHE_CAPACITY: usize = 512;
use rustls::{RootCertStore, client::ClientConfig, crypto::ring};

// --- Helper Functions (Duplicated from bump_integration.rs for isolation) ---

fn default_test_settings(
    listen: SocketAddr,
    ca_dir: &Path,
    clients: &Path,
    policies: &Path,
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
        cache_dir: None,
        cache_max_entry_size: 10 * 1024 * 1024,
        cache_total_capacity: 1024 * 1024 * 1024,
        metrics_listen: None,
        metrics_tls_cert: None,
        metrics_tls_key: None,
    }
}

fn find_free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

async fn wait_for_listener(addr: SocketAddr) -> Result<()> {
    for _ in 0..50 {
        match timeout(StdDuration::from_millis(50), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                stream.shutdown().await.ok();
                return Ok(());
            }
            _ => sleep(StdDuration::from_millis(50)).await,
        }
    }
    Err(anyhow::anyhow!("listener {addr} did not become ready"))
}

fn build_app_context(
    settings: Arc<Settings>,
    policy_store: PolicyStore,
    ca: Arc<CertificateAuthority>,
    tls_issuer: Arc<TlsIssuer>,
    client_http1: Arc<ClientConfig>,
    client_http2: Arc<ClientConfig>,
) -> AppContext {
    let tls = Arc::new(proxy::TlsContext::new(
        ca,
        tls_issuer,
        client_http1,
        client_http2,
    ));
    AppContext::new(settings, policy_store, tls, None)
}

fn build_proxy_tls_configs(
    root_store: RootCertStore,
) -> Result<(Arc<ClientConfig>, Arc<ClientConfig>)> {
    let http1 = build_client_tls(root_store.clone())?;
    // For these tests we don't strictly need h2, but we follow standard setup
    let http2 =
        build_client_tls_with_protocols(root_store, vec![b"h2".to_vec(), b"http/1.1".to_vec()])?;
    Ok((http1, http2))
}

fn build_client_tls(root_store: RootCertStore) -> Result<Arc<ClientConfig>> {
    build_client_tls_with_protocols(root_store, vec![b"http/1.1".to_vec()])
}

fn build_client_tls_with_protocols(
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

// --- Tests ---

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_max_body_size_enforced() -> Result<()> {
    let temp = tempfile::TempDir::new()?;
    let workspace = temp.path();
    let ca_dir = workspace.join("ca");
    let config_dir = workspace.join("config");
    std::fs::create_dir_all(&ca_dir)?;
    std::fs::create_dir_all(&config_dir)?;

    let clients_path = config_dir.join("clients.toml");
    let policies_path = config_dir.join("policies.toml");

    // Setup upstream that just reads everything
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_port = upstream_listener.local_addr()?.port();
    let upstream_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = upstream_listener.accept().await {
            let mut buf = [0u8; 1024];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });

    std::fs::write(
        &clients_path,
        r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-upload"]
catch_all = true
"#,
    )?;

    std::fs::write(
        &policies_path,
        format!(
            r###"[[policy]]
name = "allow-upload"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "http://127.0.0.1:{upstream_port}/**"
  allow_private_connect = true
"###
        ),
    )?;

    let ca = Arc::new(CertificateAuthority::load_or_generate(&ca_dir)?);
    let config_doc = config::load_config(&clients_path, &policies_path)?;
    let compiled = Arc::new(policy::compile::compile_config(&config_doc)?);
    let snapshot = PolicySnapshot::new(compiled);
    let (policy_tx, policy_rx) = watch::channel(snapshot);
    let policy_store = PolicyStore::new(policy_rx);

    let proxy_port = find_free_port()?;
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}")
        .parse()
        .expect("valid listen address");

    // Set max body size to small value (1KB)
    let mut settings = default_test_settings(proxy_addr, &ca_dir, &clients_path, &policies_path);
    settings.max_body_size = 1024;
    let settings = Arc::new(settings);

    let cert_cache = Arc::new(CertificateCache::new(CERT_CACHE_CAPACITY, None)?);
    let tls_issuer = Arc::new(TlsIssuer::new(ca.clone(), cert_cache, settings.leaf_ttl())?);
    let (proxy_client_config, proxy_client_h2_config) =
        build_proxy_tls_configs(RootCertStore::empty())?;

    let app = build_app_context(
        settings.clone(),
        policy_store,
        ca.clone(),
        tls_issuer,
        proxy_client_config.clone(),
        proxy_client_h2_config.clone(),
    );

    let proxy_handle = tokio::spawn(async move {
        if let Err(err) = proxy::run(app).await {
            tracing::error!(error = ?err, "proxy run failed");
        }
    });
    let _policy_tx = policy_tx;

    wait_for_listener(proxy_addr).await?;

    let mut stream = TcpStream::connect(proxy_addr).await?;
    // Send a large body > 1KB
    let body_size = 2048;
    let body = vec![b'A'; body_size];
    let request = format!(
        "POST http://127.0.0.1:{upstream_port}/upload HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nContent-Length: {body_size}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    // We expect the proxy to close the connection or return an error before finishing reading
    // In many implementations, it might return 413 Payload Too Large
    let mut response = String::new();
    stream.read_to_string(&mut response).await.ok();

    // We expect either a 413 or 500/502 depending on how the error is propagated,
    // or just a closed connection. But the upload should definitely NOT succeed (200 OK).
    // The current implementation of `BodySizeTracker` returns `BodyTooLarge` error which typically results in 413 or 502/500 or disconnect.

    if !response.is_empty() {
        assert!(
            !response.contains("200 OK"),
            "Upload should not succeed. Response: {}",
            response
        );
        // Ideally we check for 413
        if response.contains("HTTP/1.1") {
            assert!(
                response.contains("413") || response.contains("500") || response.contains("502"),
                "Expected error status, got: {}",
                response
            );
        }
    }

    stream.shutdown().await.ok();
    proxy_handle.abort();
    let _ = proxy_handle.await;
    upstream_task.abort();
    let _ = upstream_task.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_client_idle_timeout() -> Result<()> {
    let temp = tempfile::TempDir::new()?;
    let workspace = temp.path();
    let ca_dir = workspace.join("ca");
    let config_dir = workspace.join("config");
    std::fs::create_dir_all(&ca_dir)?;
    std::fs::create_dir_all(&config_dir)?;

    let clients_path = config_dir.join("clients.toml");
    let policies_path = config_dir.join("policies.toml");

    // Minimal config
    std::fs::write(
        &clients_path,
        r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["dummy"]
catch_all = true
"#,
    )?;
    std::fs::write(
        &policies_path,
        r#"
[[policy]]
name = "dummy"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "http://dummy/**"
"#,
    )?;

    let ca = Arc::new(CertificateAuthority::load_or_generate(&ca_dir)?);
    let config_doc = config::load_config(&clients_path, &policies_path)?;
    let compiled = Arc::new(policy::compile::compile_config(&config_doc)?);
    let snapshot = PolicySnapshot::new(compiled);
    let (policy_tx, policy_rx) = watch::channel(snapshot);
    let policy_store = PolicyStore::new(policy_rx);

    let proxy_port = find_free_port()?;
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}")
        .parse()
        .expect("valid listen address");

    let mut settings = default_test_settings(proxy_addr, &ca_dir, &clients_path, &policies_path);
    settings.client_timeout = 1; // 1 second timeout
    let settings = Arc::new(settings);

    let cert_cache = Arc::new(CertificateCache::new(CERT_CACHE_CAPACITY, None)?);
    let tls_issuer = Arc::new(TlsIssuer::new(ca.clone(), cert_cache, settings.leaf_ttl())?);
    let (proxy_client_config, proxy_client_h2_config) =
        build_proxy_tls_configs(RootCertStore::empty())?;

    let app = build_app_context(
        settings.clone(),
        policy_store,
        ca.clone(),
        tls_issuer,
        proxy_client_config.clone(),
        proxy_client_h2_config.clone(),
    );

    let proxy_handle = tokio::spawn(async move {
        if let Err(err) = proxy::run(app).await {
            tracing::error!(error = ?err, "proxy run failed");
        }
    });
    let _policy_tx = policy_tx;

    wait_for_listener(proxy_addr).await?;

    let mut stream = TcpStream::connect(proxy_addr).await?;

    // Write nothing. Wait for timeout + buffer.
    sleep(StdDuration::from_secs(2)).await;

    // Try to write. It should fail because connection is closed.
    // Or try to read.
    let res = stream.read(&mut [0u8; 1]).await;
    match res {
        Ok(0) => { /* Connection closed cleanly */ }
        Ok(_) => panic!("Connection should be closed due to timeout"),
        Err(e) if e.kind() == ErrorKind::BrokenPipe || e.kind() == ErrorKind::ConnectionReset => { /* OK */
        }
        Err(e) => panic!("Unexpected error: {:?}", e),
    }

    proxy_handle.abort();
    let _ = proxy_handle.await;

    Ok(())
}
