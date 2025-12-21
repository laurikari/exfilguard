mod support;

use std::{
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration as StdDuration,
};

use anyhow::{Context, Result};
use bytes::Bytes;
use h2::client as h2_client;
use h2::server as h2_server;
use http::{HeaderValue, Method, StatusCode, Uri};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::sleep,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use exfilguard::tls::ca::CertificateAuthority;
use rustls::{
    RootCertStore,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};

use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_default_deny_returns_403() -> Result<()> {
    let dirs = TestDirs::new()?;
    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-listed"]
fallback = true
"#;

    let policies = r#"[[policy]]
name = "allow-listed"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["GET"]
  url_pattern = "http://allowed.test/**"
"#;

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies)
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request = b"GET http://denied.test/resource HTTP/1.1\r\nHost: denied.test\r\nUser-Agent: exfilguard-test\r\nConnection: close\r\n\r\n";
    stream.write_all(request).await?;
    stream.flush().await?;

    let response = read_http_response(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("request blocked by policy"),
        "default deny body missing: {response}"
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_private_ip_blocked_by_default() -> Result<()> {
    let dirs = TestDirs::new()?;
    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-loopback"]
fallback = true
"#;

    let policies = r#"[[policy]]
name = "allow-loopback"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["GET"]
  url_pattern = "http://127.0.0.1/**"
"#;

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies)
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request = b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    stream.write_all(request).await?;
    stream.flush().await?;

    let response = read_http_response(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("request blocked by policy"),
        "expected policy block body, got: {response}"
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_upstream_failure_returns_502() -> Result<()> {
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_port = upstream_listener.local_addr()?.port();
    let upstream_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = upstream_listener.accept().await {
            let _ = stream.shutdown().await;
        }
    });

    let dirs = TestDirs::new()?;
    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-local"]
fallback = true
"#;

    let policies = format!(
        r#"[[policy]]
name = "allow-local"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["GET"]
  url_pattern = "http://127.0.0.1:{upstream_port}/**"
  allow_private_upstream = true
"#,
    );

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies.as_str())
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/oops HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nUser-Agent: exfilguard-test\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let response = read_http_response(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 502"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("upstream request failed"),
        "missing upstream failure body: {response}"
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_splice_stays_open_past_timeout() -> Result<()> {
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_port = upstream_listener.local_addr()?.port();
    let upstream_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = upstream_listener.accept().await {
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        }
    });

    let dirs = TestDirs::new()?;
    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["connect-splice"]
fallback = true
"#;

    let policies = format!(
        r#"[[policy]]
name = "connect-splice"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["CONNECT"]
  inspect_payload = false
  allow_private_upstream = true
  url_pattern = "https://127.0.0.1:{upstream_port}/**"
"#,
    );

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies.as_str())
        .with_settings(|settings| {
            settings.upstream_connect_timeout = 1;
            settings.upstream_timeout = 1;
            settings.upstream_pool_capacity = 4;
        })
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: keep-alive\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let response = read_until_double_crlf(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected CONNECT response: {response}"
    );

    sleep(StdDuration::from_millis(1500)).await;

    let payload = b"splice-test";
    stream.write_all(payload).await?;
    stream.flush().await?;
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await?;
    assert_eq!(echoed.as_slice(), payload);

    stream.shutdown().await.ok();
    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_private_ip_allowed_with_flag() -> Result<()> {
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_port = upstream_listener.local_addr()?.port();
    let upstream_task = tokio::spawn(async move {
        let (mut socket, _) = upstream_listener.accept().await?;
        read_until_double_crlf(&mut socket).await?;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            .await
            .context("failed to write upstream response")?;
        socket.shutdown().await.ok();
        Ok::<(), anyhow::Error>(())
    });

    let dirs = TestDirs::new()?;
    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-loopback"]
fallback = true
"#;

    let policies = format!(
        r#"[[policy]]
name = "allow-loopback"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["GET"]
  url_pattern = "http://127.0.0.1:{upstream_port}/**"
  allow_private_upstream = true
"#
    );

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies.as_str())
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let response = read_http_response(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("hello"),
        "expected upstream body to be relayed: {response}"
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;

    upstream_task.await??;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_explicit_deny_returns_configured_status() -> Result<()> {
    let dirs = TestDirs::new()?;
    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["egress"]
fallback = true
"#;

    let policies = r#"[[policy]]
name = "egress"
  [[policy.rule]]
  action = "DENY"
  status = 470
  reason = "Policy Blocked"
  body = "Blocked by policy\n"
  url_pattern = "http://blocked.test/**"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "http://allowed.test/**"
"#;

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies)
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request =
        b"GET http://blocked.test/ HTTP/1.1\r\nHost: blocked.test\r\nConnection: close\r\n\r\n";
    stream.write_all(request).await?;
    stream.flush().await?;

    let response = read_http_response(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 470 Policy Blocked"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("Blocked by policy"),
        "missing configured body: {response}"
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_default_deny_returns_403() -> Result<()> {
    let dirs = TestDirs::new()?;
    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-listed"]
fallback = true
"#;

    let policies = r#"[[policy]]
name = "allow-listed"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "https://allowed.test/**"
"#;

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies)
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let connect_request =
        b"CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test:443\r\nProxy-Connection: close\r\n\r\n";
    stream.write_all(connect_request).await?;
    stream.flush().await?;

    let response = read_http_response(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "unexpected CONNECT deny response: {response}"
    );
    assert!(
        response.contains("request blocked by policy"),
        "default CONNECT deny body missing: {response}"
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_hostname_private_resolution_is_blocked() -> Result<()> {
    let dirs = TestDirs::new()?;
    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["connect"]
fallback = true
"#;

    let target_port = find_free_port()?;
    let policies_doc = format!(
        r#"[[policy]]
name = "connect"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["CONNECT"]
  url_pattern = "https://localhost:{port}/**"
  inspect_payload = false
"#,
        port = target_port
    );

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies_doc.as_str())
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request = format!(
        "CONNECT localhost:{target_port} HTTP/1.1\r\nHost: localhost:{target_port}\r\nUser-Agent: exfilguard-test\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let response = read_http_response(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("CONNECT to private networks is not allowed"),
        "expected private network denial message, got: {response}"
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_splice_relays_payload() -> Result<()> {
    const CLIENT_PAYLOAD: &[u8] = b"client->upstream";
    const UPSTREAM_PAYLOAD: &[u8] = b"upstream->client";

    let dirs = TestDirs::new()?;
    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-splice"]
fallback = true
"#;

    let policies = r#"[[policy]]
name = "allow-splice"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["CONNECT"]
  url_pattern = "https://localhost/**"
  inspect_payload = false
  allow_private_upstream = true
"#;
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut socket, _) = upstream_listener.accept().await.context("accept failed")?;
        let mut buffer = vec![0u8; CLIENT_PAYLOAD.len()];
        socket
            .read_exact(&mut buffer)
            .await
            .context("failed reading payload from proxy")?;
        if buffer != CLIENT_PAYLOAD {
            anyhow::bail!(
                "unexpected client payload: expected {:?}, got {:?}",
                CLIENT_PAYLOAD,
                buffer
            );
        }
        socket
            .write_all(UPSTREAM_PAYLOAD)
            .await
            .context("failed writing upstream payload")?;
        socket.shutdown().await.ok();
        Ok::<(), anyhow::Error>(())
    });

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies)
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let connect_request = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nProxy-Connection: keep-alive\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    );
    stream.write_all(connect_request.as_bytes()).await?;
    stream.flush().await?;

    let response = read_http_response(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected CONNECT establish response: {response}"
    );

    stream.write_all(CLIENT_PAYLOAD).await?;
    stream.flush().await?;

    let mut received = vec![0u8; UPSTREAM_PAYLOAD.len()];
    stream
        .read_exact(&mut received)
        .await
        .context("failed reading upstream payload during pass-through")?;
    assert_eq!(received, UPSTREAM_PAYLOAD);

    stream.shutdown().await.ok();

    upstream_task.await.expect("upstream task join failure")?;
    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_blocks_private_ip_targets() -> Result<()> {
    let dirs = TestDirs::new()?;
    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-listed"]
fallback = true
"#;

    let policies = r#"[[policy]]
name = "allow-listed"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "https://example.com/**"
"#;

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies)
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request =
        b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\nProxy-Connection: close\r\n\r\n";
    stream.write_all(request).await?;
    stream.flush().await?;

    let response = read_http_response(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "unexpected private IP response: {response}"
    );
    assert!(
        response.contains("CONNECT to private networks is not allowed"),
        "missing private network warning body: {response}"
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_keepalive_reuses_upstream_connections() -> Result<()> {
    let upstream_host = "localhost";
    let dirs = TestDirs::new()?;
    let workspace = dirs.config_dir.parent().expect("temp workspace directory");
    let cert_cache_dir = workspace.join("cert_cache");
    std::fs::create_dir_all(&cert_cache_dir)?;

    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-http"]
fallback = true
"#;

    let policies = format!(
        r#"[[policy]]
name = "allow-http"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "http://{host}/**"
  allow_private_upstream = true
"#,
        host = upstream_host
    );

    let accept_count = Arc::new(AtomicUsize::new(0));
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let accept_counter = accept_count.clone();
    let upstream_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => break,
                accept = upstream_listener.accept() => {
                    let (stream, peer) = match accept {
                        Ok(pair) => pair,
                        Err(err) => return Err(anyhow::anyhow!("upstream accept error: {err}")),
                    };
                    accept_counter.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        if let Err(err) = serve_http_keepalive(stream, peer).await {
                            tracing::warn!(error = %err, "http upstream handler error");
                        }
                    });
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let cert_cache_path = cert_cache_dir.clone();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies.as_str())
        .with_settings(move |settings| {
            settings.cert_cache_dir = Some(cert_cache_path.clone());
        })
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request_one = format!(
        "GET http://{host}:{port}/first HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: exfilguard-test\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    stream.write_all(request_one.as_bytes()).await?;
    stream.flush().await?;
    let response_one = read_http_response(&mut stream).await?;
    assert!(
        response_one.starts_with("HTTP/1.1 200"),
        "unexpected first response: {response_one}"
    );
    assert!(
        response_one.contains("first"),
        "first response body missing path: {response_one}"
    );

    let request_two = format!(
        "GET http://{host}:{port}/second HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: exfilguard-test\r\nProxy-Connection: close\r\nConnection: close\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    stream.write_all(request_two.as_bytes()).await?;
    stream.flush().await?;
    let response_two = read_http_response(&mut stream).await?;
    assert!(
        response_two.starts_with("HTTP/1.1 200"),
        "unexpected second response: {response_two}"
    );
    assert!(
        response_two.contains("second"),
        "second response body missing path: {response_two}"
    );

    stream.shutdown().await.ok();

    assert_eq!(
        accept_count.load(Ordering::SeqCst),
        1,
        "expected upstream connection reuse"
    );

    let _ = shutdown_tx.send(());
    upstream_task
        .await
        .expect("upstream task join failed")
        .expect("upstream task error");

    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_keepalive_reuses_upstream_connections() -> Result<()> {
    let upstream_host = "localhost";
    let dirs = TestDirs::new()?;
    let workspace = dirs.config_dir.parent().expect("temp workspace directory");
    let cert_cache_dir = workspace.join("cert_cache");
    std::fs::create_dir_all(&cert_cache_dir)?;

    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-bump"]
fallback = true
"#;

    let policies = format!(
        r#"[[policy]]
name = "allow-bump"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "https://{host}/**"
  allow_private_upstream = true
"#,
        host = upstream_host
    );

    let ca = Arc::new(CertificateAuthority::load_or_generate(&dirs.ca_dir)?);
    let upstream_config = build_upstream_tls_config(&ca, upstream_host)?;

    let accept_count = Arc::new(AtomicUsize::new(0));
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let accept_counter = accept_count.clone();
    let upstream_task = {
        let upstream_config = upstream_config.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => break,
                    accept = upstream_listener.accept() => {
                        let (stream, peer) = match accept {
                            Ok(pair) => pair,
                            Err(err) => return Err(anyhow::anyhow!("upstream accept error: {err}")),
                        };
                        accept_counter.fetch_add(1, Ordering::SeqCst);
                        let acceptor = TlsAcceptor::from(upstream_config.clone());
                        tokio::spawn(async move {
                            if let Err(err) = serve_tls_keepalive(stream, acceptor, peer).await {
                                tracing::warn!(error = %err, "tls upstream handler error");
                            }
                        });
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        })
    };

    let mut proxy_root_store = RootCertStore::empty();
    let (added_proxy, _) = proxy_root_store.add_parsable_certificates([ca.root_certificate_der()]);
    assert!(added_proxy > 0, "expected CA root to be trusted by proxy");
    let cert_cache_path = cert_cache_dir.clone();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies.as_str())
        .with_proxy_root_store(proxy_root_store)
        .with_settings(move |settings| {
            settings.cert_cache_dir = Some(cert_cache_path.clone());
        })
        .spawn()
        .await?;

    let mut client_root_store = RootCertStore::empty();
    let (added_client, _) =
        client_root_store.add_parsable_certificates([ca.root_certificate_der()]);
    assert!(added_client > 0, "expected CA root to be trusted by client");
    let client_tls_config = build_client_tls(client_root_store)?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let connect_request = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    stream.write_all(connect_request.as_bytes()).await?;
    stream.flush().await?;

    let connect_response = read_until_double_crlf(&mut stream).await?;
    assert!(
        connect_response.starts_with("HTTP/1.1 200"),
        "unexpected CONNECT response: {connect_response}"
    );

    let connector = TlsConnector::from(client_tls_config);
    let server_name = ServerName::try_from(upstream_host).unwrap();
    let mut tls_stream = connector.connect(server_name, stream).await?;

    let request_one = format!(
        "GET /first HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: exfilguard-test\r\nConnection: keep-alive\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    tls_stream.write_all(request_one.as_bytes()).await?;
    tls_stream.flush().await?;
    let response_one = read_http_response(&mut tls_stream).await?;
    assert!(
        response_one.starts_with("HTTP/1.1 200"),
        "unexpected first bumped response: {response_one}"
    );
    assert!(
        response_one.contains("first"),
        "first bumped response body missing path: {response_one}"
    );

    let request_two = format!(
        "GET /second HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: exfilguard-test\r\nConnection: close\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    tls_stream.write_all(request_two.as_bytes()).await?;
    tls_stream.flush().await?;
    let response_two = read_http_response(&mut tls_stream).await?;
    assert!(
        response_two.starts_with("HTTP/1.1 200"),
        "unexpected second bumped response: {response_two}"
    );
    assert!(
        response_two.contains("second"),
        "second bumped response body missing path: {response_two}"
    );

    tls_stream.shutdown().await.ok();

    let accepts = accept_count.load(Ordering::SeqCst);
    assert!(
        accepts <= 2,
        "expected upstream TLS connection reuse (saw {accepts} accepts)"
    );

    let _ = shutdown_tx.send(());
    upstream_task
        .await
        .expect("upstream task join failed")
        .expect("upstream task error");

    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_relays_https_response() -> Result<()> {
    let upstream_host = "localhost";
    let dirs = TestDirs::new()?;
    let workspace = dirs.config_dir.parent().expect("temp workspace directory");
    let cert_cache_dir = workspace.join("cert_cache");
    std::fs::create_dir_all(&cert_cache_dir)?;

    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-searchkit"]
fallback = true
"#;

    let policies = format!(
        r#"[[policy]]
name = "allow-searchkit"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "https://{host}/privacy-policy/"
  allow_private_upstream = true
"#,
        host = upstream_host
    );

    let ca = Arc::new(CertificateAuthority::load_or_generate(&dirs.ca_dir)?);
    let upstream_config = build_upstream_tls_config(&ca, upstream_host)?;

    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let upstream_task = {
        let upstream_config = upstream_config.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => break,
                    accept = upstream_listener.accept() => {
                        let (stream, peer) = match accept {
                            Ok(pair) => pair,
                            Err(err) => {
                                return Err(anyhow::anyhow!("upstream accept error: {err}"));
                            }
                        };
                        let acceptor = TlsAcceptor::from(upstream_config.clone());
                        tokio::spawn(async move {
                            if let Err(err) = serve_redirect(stream, acceptor, peer).await {
                                tracing::warn!(error = %err, "upstream handler error");
                            }
                        });
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        })
    };

    let mut proxy_root_store = RootCertStore::empty();
    let (added_proxy, _) = proxy_root_store.add_parsable_certificates([ca.root_certificate_der()]);
    assert!(added_proxy > 0, "expected CA root to be trusted by proxy");
    let cert_cache_path = cert_cache_dir.clone();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies.as_str())
        .with_proxy_root_store(proxy_root_store)
        .with_settings(move |settings| {
            settings.cert_cache_dir = Some(cert_cache_path.clone());
        })
        .spawn()
        .await?;

    let mut root_store = RootCertStore::empty();
    let (added_client, _) = root_store.add_parsable_certificates([ca.root_certificate_der()]);
    assert!(added_client > 0, "expected CA root to be trusted by client");
    let client_tls_config = build_client_tls(root_store)?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let connect_request = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    stream.write_all(connect_request.as_bytes()).await?;

    let connect_response = read_until_double_crlf(&mut stream).await?;
    assert!(
        connect_response.starts_with("HTTP/1.1 200"),
        "unexpected CONNECT response: {connect_response}"
    );

    let connector = TlsConnector::from(client_tls_config);
    let server_name = ServerName::try_from(upstream_host).unwrap();
    let mut tls_stream = connector.connect(server_name, stream).await?;

    let request = format!(
        "GET /privacy-policy/ HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: exfilguard-test\r\nConnection: close\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    tls_stream.write_all(request.as_bytes()).await?;
    tls_stream.flush().await?;

    let mut response_bytes = Vec::new();
    loop {
        let mut chunk = [0u8; 1024];
        match tls_stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                response_bytes.extend_from_slice(&chunk[..n]);
                if response_bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(err) => {
                if !response_bytes.is_empty()
                    && (err.kind() == ErrorKind::UnexpectedEof
                        || err
                            .to_string()
                            .contains("peer closed connection without sending TLS close_notify"))
                {
                    break;
                }
                return Err(err.into());
            }
        }
    }
    let response_text = String::from_utf8_lossy(&response_bytes);
    assert!(
        response_text.starts_with("HTTP/1.1 301"),
        "expected 301 response, got {response_text}"
    );
    assert!(
        response_text.contains("Location: https://www.searchkit.com/"),
        "location header missing: {response_text}"
    );

    // Cleanup
    let _ = shutdown_tx.send(());
    upstream_task
        .await
        .expect("upstream task join failed")
        .expect("upstream task error");

    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_prefers_http1_when_upstream_http1_only() -> Result<()> {
    let upstream_host = "localhost";
    let dirs = TestDirs::new()?;
    let workspace = dirs.config_dir.parent().expect("temp workspace directory");
    let cert_cache_dir = workspace.join("cert_cache");
    std::fs::create_dir_all(&cert_cache_dir)?;

    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-http1-only"]
fallback = true
"#;

    let policies = format!(
        r#"[[policy]]
name = "allow-http1-only"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "https://{host}/**"
  allow_private_upstream = true
"#,
        host = upstream_host
    );

    let ca = Arc::new(CertificateAuthority::load_or_generate(&dirs.ca_dir)?);
    let upstream_config = build_upstream_tls_config(&ca, upstream_host)?;

    let accept_count = Arc::new(AtomicUsize::new(0));
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let accept_counter = accept_count.clone();
    let upstream_task = {
        let upstream_config = upstream_config.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => break,
                    accept = upstream_listener.accept() => {
                        let (stream, peer) = match accept {
                            Ok(pair) => pair,
                            Err(err) => return Err(anyhow::anyhow!("upstream accept error: {err}")),
                        };
                        accept_counter.fetch_add(1, Ordering::SeqCst);
                        let acceptor = TlsAcceptor::from(upstream_config.clone());
                        tokio::spawn(async move {
                            if let Err(err) = serve_tls_keepalive(stream, acceptor, peer).await {
                                tracing::warn!(error = %err, "tls upstream handler error");
                            }
                        });
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        })
    };

    let mut proxy_root_store = RootCertStore::empty();
    let (added_proxy, _) = proxy_root_store.add_parsable_certificates([ca.root_certificate_der()]);
    assert!(added_proxy > 0, "expected CA root to be trusted by proxy");
    let cert_cache_path = cert_cache_dir.clone();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies.as_str())
        .with_proxy_root_store(proxy_root_store)
        .with_settings(move |settings| {
            settings.cert_cache_dir = Some(cert_cache_path.clone());
        })
        .spawn()
        .await?;

    let mut client_root_store = RootCertStore::empty();
    let (added_client, _) =
        client_root_store.add_parsable_certificates([ca.root_certificate_der()]);
    assert!(added_client > 0, "expected CA root to be trusted by client");
    let client_tls_config = build_client_tls_h2(client_root_store)?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let connect_request = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    stream.write_all(connect_request.as_bytes()).await?;
    stream.flush().await?;

    let connect_response = read_until_double_crlf(&mut stream).await?;
    assert!(
        connect_response.starts_with("HTTP/1.1 200"),
        "unexpected CONNECT response: {connect_response}"
    );

    let connector = TlsConnector::from(client_tls_config);
    let server_name = ServerName::try_from(upstream_host).unwrap();
    let mut tls_stream = connector.connect(server_name, stream).await?;

    let negotiated = tls_stream.get_ref().1.alpn_protocol();
    assert_eq!(
        negotiated,
        Some(&b"http/1.1"[..]),
        "proxy should prefer HTTP/1.1 when upstream does not support HTTP/2"
    );

    let request = format!(
        "GET /fallback HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: exfilguard-test\r\nConnection: close\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    tls_stream.write_all(request.as_bytes()).await?;
    tls_stream.flush().await?;
    let response = read_http_response(&mut tls_stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected fallback response: {response}"
    );
    assert!(
        response.contains("/fallback"),
        "fallback response body missing path: {response}"
    );

    tls_stream.shutdown().await.ok();

    let _ = shutdown_tx.send(());
    upstream_task
        .await
        .expect("upstream task join failed")
        .expect("upstream task error");

    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_supports_http2() -> Result<()> {
    let upstream_host = "localhost";
    let dirs = TestDirs::new()?;
    let workspace = dirs.config_dir.parent().expect("temp workspace directory");
    let cert_cache_dir = workspace.join("cert_cache");
    std::fs::create_dir_all(&cert_cache_dir)?;

    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-h2"]
fallback = true
"#;

    let policies = format!(
        r#"[[policy]]
name = "allow-h2"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "https://{host}/**"
  allow_private_upstream = true
"#,
        host = upstream_host
    );

    let ca = Arc::new(CertificateAuthority::load_or_generate(&dirs.ca_dir)?);
    let upstream_config = build_upstream_h2_tls_config(&ca, upstream_host)?;

    let accept_count = Arc::new(AtomicUsize::new(0));
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let accept_counter = accept_count.clone();
    let upstream_task = {
        let upstream_config = upstream_config.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => break,
                    accept = upstream_listener.accept() => {
                        let (stream, peer) = match accept {
                            Ok(pair) => pair,
                            Err(err) => return Err(anyhow::anyhow!("upstream accept error: {err}")),
                        };
                        accept_counter.fetch_add(1, Ordering::SeqCst);
                        let acceptor = TlsAcceptor::from(upstream_config.clone());
                        tokio::spawn(async move {
                            if let Err(err) = serve_tls_h2(stream, acceptor, peer).await {
                                tracing::warn!(error = %err, "tls h2 upstream handler error");
                            }
                        });
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        })
    };

    let mut proxy_root_store = RootCertStore::empty();
    let (added_proxy, _) = proxy_root_store.add_parsable_certificates([ca.root_certificate_der()]);
    assert!(added_proxy > 0, "expected CA root to be trusted by proxy");
    let cert_cache_path = cert_cache_dir.clone();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies.as_str())
        .with_proxy_root_store(proxy_root_store)
        .with_settings(move |settings| {
            settings.cert_cache_dir = Some(cert_cache_path.clone());
        })
        .spawn()
        .await?;

    let mut client_root_store = RootCertStore::empty();
    let (added_client, _) =
        client_root_store.add_parsable_certificates([ca.root_certificate_der()]);
    assert!(added_client > 0, "expected CA root to be trusted by client");
    let client_tls_config = build_client_tls_h2(client_root_store)?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let connect_request = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    stream.write_all(connect_request.as_bytes()).await?;
    stream.flush().await?;

    let connect_response = read_until_double_crlf(&mut stream).await?;
    assert!(
        connect_response.starts_with("HTTP/1.1 200"),
        "unexpected CONNECT response: {connect_response}"
    );

    let connector = TlsConnector::from(client_tls_config);
    let server_name = ServerName::try_from(upstream_host).unwrap();
    let tls_stream = connector.connect(server_name, stream).await?;

    let (mut client, connection) = h2_client::handshake(tls_stream)
        .await
        .context("failed to negotiate HTTP/2 with proxy")?;
    let h2_task = tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::warn!(error = %err, "downstream HTTP/2 connection ended");
        }
    });

    let authority = format!("{}:{}", upstream_host, upstream_addr.port());

    let first_uri = Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query("/h2/first")
        .build()?;
    let mut first_builder = http::Request::builder().method(Method::GET).uri(first_uri);
    first_builder
        .headers_mut()
        .expect("headers before body")
        .insert(
            http::header::USER_AGENT,
            HeaderValue::from_static("exfilguard-test"),
        );
    let first_request = first_builder.body(())?;

    let (first_response_fut, _first_stream) = client
        .send_request(first_request, true)
        .context("failed to send first HTTP/2 request")?;
    let first_response = first_response_fut
        .await
        .context("failed to receive first HTTP/2 response")?;
    assert_eq!(first_response.status(), StatusCode::OK);
    let mut first_body = first_response.into_body();
    let mut first_bytes = Vec::new();
    while let Some(frame) = first_body.data().await {
        let chunk = frame.context("failed to read first HTTP/2 response chunk")?;
        first_bytes.extend_from_slice(&chunk);
    }
    let first_text = String::from_utf8(first_bytes)?;
    assert_eq!(first_text, "/h2/first");

    let second_uri = Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query("/h2/second")
        .build()?;
    let mut second_builder = http::Request::builder().method(Method::GET).uri(second_uri);
    second_builder
        .headers_mut()
        .expect("headers before body")
        .insert(
            http::header::USER_AGENT,
            HeaderValue::from_static("exfilguard-test"),
        );
    let second_request = second_builder.body(())?;

    let (second_response_fut, _second_stream) = client
        .send_request(second_request, true)
        .context("failed to send second HTTP/2 request")?;
    let second_response = second_response_fut
        .await
        .context("failed to receive second HTTP/2 response")?;
    assert_eq!(second_response.status(), StatusCode::OK);
    let mut second_body = second_response.into_body();
    let mut second_bytes = Vec::new();
    while let Some(frame) = second_body.data().await {
        let chunk = frame.context("failed to read second HTTP/2 response chunk")?;
        second_bytes.extend_from_slice(&chunk);
    }
    let second_text = String::from_utf8(second_bytes)?;
    assert_eq!(second_text, "/h2/second");

    drop(client);
    h2_task.abort();
    let _ = h2_task.await;

    assert_eq!(
        accept_count.load(Ordering::SeqCst),
        1,
        "expected upstream HTTP/2 connection reuse"
    );

    let _ = shutdown_tx.send(());
    upstream_task
        .await
        .expect("upstream task join failed")
        .expect("upstream task error");

    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_policy_denied() -> Result<()> {
    let upstream_host = "localhost";
    let dirs = TestDirs::new()?;
    let workspace = dirs.config_dir.parent().expect("temp workspace directory");
    let cert_cache_dir = workspace.join("cert_cache");
    std::fs::create_dir_all(&cert_cache_dir)?;

    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["h2-policy"]
fallback = true
"#;

    let policies = format!(
        r#"[[policy]]
name = "h2-policy"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["CONNECT"]
  url_pattern = "https://{host}/**"
  allow_private_upstream = true

  [[policy.rule]]
  action = "DENY"
  methods = ["GET"]
  url_pattern = "https://{host}/blocked/**"
  status = 451
  body = "blocked by policy"
"#,
        host = upstream_host
    );

    let ca = Arc::new(CertificateAuthority::load_or_generate(&dirs.ca_dir)?);
    let upstream_config = build_upstream_h2_tls_config(&ca, upstream_host)?;

    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let upstream_task = {
        let upstream_config = upstream_config.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => break,
                    accept = upstream_listener.accept() => {
                        let (stream, peer) = accept.context("upstream accept failed")?;
                        let acceptor = TlsAcceptor::from(upstream_config.clone());
                        tokio::spawn(async move {
                            if let Err(err) = serve_tls_h2(stream, acceptor, peer).await {
                                tracing::warn!(error = %err, "tls h2 upstream handler error");
                            }
                        });
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        })
    };

    let mut proxy_root_store = RootCertStore::empty();
    let (added_proxy, _) = proxy_root_store.add_parsable_certificates([ca.root_certificate_der()]);
    assert!(added_proxy > 0, "expected CA root to be trusted by proxy");
    let cert_cache_path = cert_cache_dir.clone();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies.as_str())
        .with_proxy_root_store(proxy_root_store)
        .with_settings(move |settings| {
            settings.cert_cache_dir = Some(cert_cache_path.clone());
        })
        .spawn()
        .await?;

    let mut client_root_store = RootCertStore::empty();
    let (added_client, _) =
        client_root_store.add_parsable_certificates([ca.root_certificate_der()]);
    assert!(added_client > 0, "expected CA root to be trusted by client");
    let client_tls_config = build_client_tls_h2(client_root_store)?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let connect_request = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    stream.write_all(connect_request.as_bytes()).await?;
    stream.flush().await?;

    let connect_response = read_until_double_crlf(&mut stream).await?;
    assert!(
        connect_response.starts_with("HTTP/1.1 200"),
        "unexpected CONNECT response: {connect_response}"
    );

    let connector = TlsConnector::from(client_tls_config);
    let server_name = ServerName::try_from(upstream_host).unwrap();
    let tls_stream = connector.connect(server_name, stream).await?;

    let (mut client, connection) = h2_client::handshake(tls_stream)
        .await
        .context("failed to negotiate HTTP/2 with proxy")?;
    let h2_task = tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::warn!(error = %err, "downstream HTTP/2 connection ended");
        }
    });

    let authority = format!("{}:{}", upstream_host, upstream_addr.port());

    let deny_uri = Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query("/blocked/resource")
        .build()?;
    let deny_request = http::Request::builder()
        .method(Method::GET)
        .uri(deny_uri)
        .body(())?;
    let (deny_response_fut, _) = client
        .send_request(deny_request, true)
        .context("failed to send denied HTTP/2 request")?;
    let deny_response = deny_response_fut
        .await
        .context("failed to receive denied HTTP/2 response")?;
    assert_eq!(deny_response.status(), StatusCode::from_u16(451)?);
    let mut deny_body = deny_response.into_body();
    let mut deny_bytes = Vec::new();
    while let Some(frame) = deny_body.data().await {
        let chunk = frame.context("failed to read denied HTTP/2 response chunk")?;
        deny_bytes.extend_from_slice(&chunk);
    }
    assert_eq!(String::from_utf8(deny_bytes)?, "blocked by policy");

    let default_uri = Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query("/unmatched")
        .build()?;
    let default_request = http::Request::builder()
        .method(Method::GET)
        .uri(default_uri)
        .body(())?;
    let (default_response_fut, _) = client
        .send_request(default_request, true)
        .context("failed to send default-deny HTTP/2 request")?;
    let default_response = default_response_fut
        .await
        .context("failed to receive default-deny HTTP/2 response")?;
    assert_eq!(default_response.status(), StatusCode::FORBIDDEN);
    let mut default_body = default_response.into_body();
    let mut default_bytes = Vec::new();
    while let Some(frame) = default_body.data().await {
        let chunk = frame.context("failed to read default-deny HTTP/2 response chunk")?;
        default_bytes.extend_from_slice(&chunk);
    }
    assert_eq!(
        String::from_utf8(default_bytes)?,
        "request blocked by policy"
    );

    drop(client);
    h2_task.abort();
    let _ = h2_task.await;

    let _ = shutdown_tx.send(());
    upstream_task
        .await
        .expect("upstream task join failed")
        .expect("upstream task error");

    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_ipv6_loopback_denied() -> Result<()> {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};

    let dirs = TestDirs::new()?;
    let workspace = dirs.config_dir.parent().expect("temp workspace directory");
    let cert_cache_dir = workspace.join("cert_cache");
    std::fs::create_dir_all(&cert_cache_dir)?;

    let clients = std::fs::read_to_string("tests/data/clients/ipv6.toml")?;
    let policies = std::fs::read_to_string("tests/data/policies/ipv6.toml")?;

    let cert_cache_path = cert_cache_dir.clone();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients.as_str(), policies.as_str())
        .with_settings(move |settings| {
            let port = settings.listen.port();
            settings.listen = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
            settings.cert_cache_dir = Some(cert_cache_path.clone());
            settings.log_queries = true;
        })
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request = b"GET http://[::1]/secret HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n\r\n";
    stream.write_all(request).await?;
    stream.flush().await?;

    let response = read_http_response(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 451"),
        "expected 451 deny response, got: {response}"
    );
    assert!(
        response.contains("loopback denied"),
        "deny body missing: {response}"
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;
    Ok(())
}

async fn serve_http_keepalive(mut stream: TcpStream, _peer: SocketAddr) -> Result<()> {
    loop {
        let request_bytes = read_request(&mut stream).await?;
        if request_bytes.is_empty() {
            break;
        }
        let request = String::from_utf8(request_bytes)?;
        let path = request_path(&request);
        let close = request.to_ascii_lowercase().contains("connection: close");
        let body = path.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n{}",
            body.len(),
            if close { "close" } else { "keep-alive" },
            body
        );
        stream
            .write_all(response.as_bytes())
            .await
            .context("failed to write HTTP upstream response")?;
        stream
            .flush()
            .await
            .context("failed to flush HTTP upstream response")?;
        if close {
            break;
        }
    }
    stream
        .shutdown()
        .await
        .context("failed to shutdown HTTP upstream stream")?;
    Ok(())
}

async fn serve_tls_keepalive(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    _peer: SocketAddr,
) -> Result<()> {
    let mut tls = acceptor
        .accept(stream)
        .await
        .context("tls handshake with proxy failed")?;
    loop {
        let request_bytes = read_request(&mut tls).await?;
        if request_bytes.is_empty() {
            break;
        }
        let request = String::from_utf8(request_bytes)?;
        let path = request_path(&request);
        let close = request.to_ascii_lowercase().contains("connection: close");
        let body = path.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n{}",
            body.len(),
            if close { "close" } else { "keep-alive" },
            body
        );
        tls.write_all(response.as_bytes())
            .await
            .context("failed to write TLS upstream response")?;
        tls.flush()
            .await
            .context("failed to flush TLS upstream response")?;
        if close {
            break;
        }
    }
    tls.shutdown()
        .await
        .context("failed to shutdown TLS upstream stream")?;
    Ok(())
}

async fn serve_tls_h2(stream: TcpStream, acceptor: TlsAcceptor, _peer: SocketAddr) -> Result<()> {
    let tls = acceptor
        .accept(stream)
        .await
        .context("tls handshake with proxy failed")?;
    let mut connection = h2_server::handshake(tls)
        .await
        .context("failed to establish HTTP/2 handshake with proxy")?;

    while let Some(result) = connection.accept().await {
        let (request, mut respond) = result.context("failed to accept HTTP/2 request")?;
        let path = request.uri().path().to_string();
        let mut builder = http::Response::builder().status(StatusCode::OK);
        {
            let headers = builder
                .headers_mut()
                .expect("headers available before body");
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
        }
        let response = builder
            .body(())
            .map_err(|err| anyhow::anyhow!("failed to build HTTP/2 response: {err}"))?;
        let mut send = respond
            .send_response(response, path.is_empty())
            .context("failed to send HTTP/2 response headers")?;
        if !path.is_empty() {
            send.send_data(Bytes::copy_from_slice(path.as_bytes()), true)
                .context("failed to send HTTP/2 response body")?;
        }
    }

    Ok(())
}

async fn read_http_response<S>(stream: &mut S) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let read = stream
            .read(&mut byte)
            .await
            .context("failed to read response byte")?;
        if read == 0 {
            return Err(anyhow::anyhow!("response closed before headers completed"));
        }
        head.extend_from_slice(&byte[..read]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head_str = String::from_utf8(head.clone())?;
    let content_length = extract_content_length(&head_str)?;
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream
            .read_exact(&mut body)
            .await
            .context("failed to read response body")?;
    }
    head.extend_from_slice(&body);
    Ok(String::from_utf8(head)?)
}

async fn read_request<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let read = stream
            .read(&mut byte)
            .await
            .context("failed to read request byte")?;
        if read == 0 {
            return Ok(buffer);
        }
        buffer.extend_from_slice(&byte[..read]);
        if buffer.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    Ok(buffer)
}

fn request_path(request: &str) -> &str {
    request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
}

fn extract_content_length(head: &str) -> Result<usize> {
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            return value
                .trim()
                .parse::<usize>()
                .context("invalid Content-Length header");
        }
    }
    Ok(0)
}

async fn serve_redirect(stream: TcpStream, acceptor: TlsAcceptor, _peer: SocketAddr) -> Result<()> {
    let mut tls = acceptor
        .accept(stream)
        .await
        .context("tls handshake with client failed")?;

    // Consume the incoming HTTP request headers from the proxy.
    let mut request_buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let read = tls
            .read(&mut byte)
            .await
            .context("failed to read request from proxy")?;
        if read == 0 {
            break;
        }
        request_buf.extend_from_slice(&byte[..read]);
        if request_buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let response = b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.searchkit.com/\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    tls.write_all(response)
        .await
        .context("failed to write upstream response")?;
    tls.shutdown()
        .await
        .context("failed to shutdown upstream TLS")?;
    Ok(())
}

fn build_upstream_tls_config(
    ca: &CertificateAuthority,
    host: &str,
) -> Result<Arc<rustls::ServerConfig>> {
    build_upstream_tls_config_with_alpn(ca, host, vec![b"http/1.1".to_vec()])
}

fn build_upstream_h2_tls_config(
    ca: &CertificateAuthority,
    host: &str,
) -> Result<Arc<rustls::ServerConfig>> {
    build_upstream_tls_config_with_alpn(ca, host, vec![b"h2".to_vec()])
}

fn build_upstream_tls_config_with_alpn(
    ca: &CertificateAuthority,
    host: &str,
    protocols: Vec<Vec<u8>>,
) -> Result<Arc<rustls::ServerConfig>> {
    let minted = ca.mint_leaf(&[host], StdDuration::from_secs(3600))?;
    let provider = ring::default_provider();
    let builder = rustls::ServerConfig::builder_with_provider(provider.into());
    let builder = builder.with_safe_default_protocol_versions()?;
    let builder = builder.with_no_client_auth();
    let chain: Vec<_> = minted
        .chain_der
        .iter()
        .map(|bytes| CertificateDer::from(bytes.clone()))
        .collect();
    let key_der = PrivateKeyDer::try_from(minted.private_key_der.to_vec())
        .map_err(|err| anyhow::anyhow!("invalid upstream private key: {err}"))?;
    let mut config = builder.with_single_cert(chain, key_der)?;
    config.alpn_protocols = protocols;
    Ok(Arc::new(config))
}
