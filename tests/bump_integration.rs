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
use http::{HeaderValue, Method, StatusCode, Uri};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::{sleep, timeout},
};

use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_default_deny_returns_403() -> Result<()> {
    let log_capture = LogCapture::new("info").await;
    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-listed"])
        .policy(
            PolicySpec::new("allow-listed")
                .rule(RuleSpec::allow(&["GET"], "http://allowed.test/**")),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let mut client = ProxyClient::connect(harness.addr).await?;
    let request = b"GET http://denied.test/resource HTTP/1.1\r\nHost: denied.test\r\nUser-Agent: exfilguard-test\r\nConnection: close\r\n\r\n";
    client.send(request).await?;

    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("request blocked by policy"),
        "default deny body missing: {response}"
    );
    let logs = log_capture.text();
    assert!(
        logs.contains("no matching policy decision; default deny"),
        "expected default deny log entry, got: {logs}"
    );

    client.shutdown().await;
    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_private_ip_blocked_by_default() -> Result<()> {
    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-loopback"])
        .policy(
            PolicySpec::new("allow-loopback")
                .rule(RuleSpec::allow(&["GET"], "http://127.0.0.1/**")),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let mut client = ProxyClient::connect(harness.addr).await?;
    let request = b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    client.send(request).await?;

    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("request blocked by policy"),
        "expected policy block body, got: {response}"
    );

    client.shutdown().await;
    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_upstream_failure_returns_502() -> Result<()> {
    let upstream = TestUpstream::close().await?;
    let upstream_port = upstream.port();

    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-local"])
        .policy(
            PolicySpec::new("allow-local").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
                    .allow_private_upstream(true),
            ),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let mut client = ProxyClient::connect(harness.addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/oops HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nUser-Agent: exfilguard-test\r\nConnection: close\r\n\r\n"
    );
    client.send(request.as_bytes()).await?;

    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 502"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("upstream request failed"),
        "missing upstream failure body: {response}"
    );

    client.shutdown().await;
    harness.shutdown().await;
    drop(upstream);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_splice_stays_open_past_timeout() -> Result<()> {
    let upstream = TestUpstream::echo().await?;
    let upstream_port = upstream.port();

    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["connect-splice"])
        .policy(
            PolicySpec::new("connect-splice").rule(
                RuleSpec::allow(
                    &["CONNECT"],
                    format!("https://127.0.0.1:{upstream_port}/**"),
                )
                .inspect_payload(false)
                .allow_private_upstream(true),
            ),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(|settings| {
            settings.upstream_connect_timeout = 1;
            settings.response_body_idle_timeout = 1;
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
    drop(upstream);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_splice_max_lifetime_closes_without_http_response() -> Result<()> {
    let upstream = TestUpstream::echo().await?;
    let upstream_port = upstream.port();

    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["connect-splice"])
        .policy(
            PolicySpec::new("connect-splice").rule(
                RuleSpec::allow(
                    &["CONNECT"],
                    format!("https://127.0.0.1:{upstream_port}/**"),
                )
                .inspect_payload(false)
                .allow_private_upstream(true),
            ),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(|settings| {
            settings.connect_tunnel_idle_timeout = 60;
            settings.connect_tunnel_max_lifetime = 1;
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

    sleep(StdDuration::from_secs(2)).await;

    let mut buf = [0u8; 64];
    let read = timeout(StdDuration::from_secs(2), stream.read(&mut buf)).await??;
    assert!(
        read == 0,
        "expected tunnel to close without extra response, got: {}",
        String::from_utf8_lossy(&buf[..read])
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;
    drop(upstream);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_private_ip_allowed_with_flag() -> Result<()> {
    let upstream = TestUpstream::http_ok("hello").await?;
    let upstream_port = upstream.port();

    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-loopback"])
        .policy(
            PolicySpec::new("allow-loopback").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
                    .allow_private_upstream(true),
            ),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let mut client = ProxyClient::connect(harness.addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    client.send(request.as_bytes()).await?;

    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("hello"),
        "expected upstream body to be relayed: {response}"
    );

    client.shutdown().await;
    harness.shutdown().await;
    drop(upstream);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_explicit_deny_returns_configured_status() -> Result<()> {
    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["egress"])
        .policy(
            PolicySpec::new("egress")
                .rule(
                    RuleSpec::deny(&["ANY"], "http://blocked.test/**")
                        .status(470)
                        .reason("Policy Blocked")
                        .body("Blocked by policy\n"),
                )
                .rule(RuleSpec::allow_any("http://allowed.test/**")),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let mut client = ProxyClient::connect(harness.addr).await?;
    let request =
        b"GET http://blocked.test/ HTTP/1.1\r\nHost: blocked.test\r\nConnection: close\r\n\r\n";
    client.send(request).await?;

    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 470 Policy Blocked"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("Blocked by policy"),
        "missing configured body: {response}"
    );

    client.shutdown().await;
    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_default_deny_returns_403() -> Result<()> {
    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-listed"])
        .policy(
            PolicySpec::new("allow-listed").rule(RuleSpec::allow_any("https://allowed.test/**")),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
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
    let target_port = find_free_port()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["connect"])
        .policy(
            PolicySpec::new("connect").rule(
                RuleSpec::allow(&["CONNECT"], format!("https://localhost:{target_port}/**"))
                    .inspect_payload(false),
            ),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
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
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-splice"])
        .policy(
            PolicySpec::new("allow-splice").rule(
                RuleSpec::allow(&["CONNECT"], "https://localhost/**")
                    .inspect_payload(false)
                    .allow_private_upstream(true),
            ),
        )
        .render();
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

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
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
    let log_capture = LogCapture::new("info").await;
    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-listed"])
        .policy(PolicySpec::new("allow-listed").rule(RuleSpec::allow_any("https://example.com/**")))
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
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
    let logs = log_capture.text();
    assert!(
        logs.contains("CONNECT target is private network; blocking"),
        "expected private CONNECT block log entry, got: {logs}"
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

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-http"])
        .policy(PolicySpec::new("allow-http").rule(
            RuleSpec::allow_any(format!("http://{upstream_host}/**")).allow_private_upstream(true),
        ))
        .render();

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
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
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
    let policy_name = "allow-bump";
    let policy = PolicySpec::new(policy_name).rule(
        RuleSpec::allow_any(format!("https://{upstream_host}/**")).allow_private_upstream(true),
    );
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .upstream_mode(UpstreamMode::Http1Keepalive),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.http1_client();

    let request_one = format!(
        "GET /first HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: exfilguard-test\r\nConnection: keep-alive\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    client.send(request_one.as_bytes()).await?;
    let response_one = client.read_response_with_length().await?;
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
    client.send(request_two.as_bytes()).await?;
    let response_two = client.read_response_with_length().await?;
    assert!(
        response_two.starts_with("HTTP/1.1 200"),
        "unexpected second bumped response: {response_two}"
    );
    assert!(
        response_two.contains("second"),
        "second bumped response body missing path: {response_two}"
    );

    client.stream_mut().shutdown().await.ok();

    let accepts = fixture.accept_count();
    assert!(
        accepts <= 2,
        "expected upstream TLS connection reuse (saw {accepts} accepts)"
    );

    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_relays_https_response() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-searchkit";
    let policy = PolicySpec::new(policy_name).rule(
        RuleSpec::allow_any(format!("https://{upstream_host}/privacy-policy/"))
            .allow_private_upstream(true),
    );
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .upstream_mode(UpstreamMode::Http1Redirect),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.http1_client();

    let request = format!(
        "GET /privacy-policy/ HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: exfilguard-test\r\nConnection: close\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    client.send(request.as_bytes()).await?;

    let mut response_bytes = Vec::new();
    loop {
        let mut chunk = [0u8; 1024];
        match client.stream_mut().read(&mut chunk).await {
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

    client.stream_mut().shutdown().await.ok();
    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_rejects_absolute_form_targets() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-bump";
    let policy = PolicySpec::new(policy_name).rule(
        RuleSpec::allow_any(format!("https://{upstream_host}/**")).allow_private_upstream(true),
    );
    let mut fixture =
        BumpedTlsFixture::new(BumpedTlsOptions::new(upstream_host, policy_name, policy)).await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.http1_client();
    let request = format!(
        "GET http://{host}:{port}/absolute HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    client.send(request.as_bytes()).await?;

    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "unexpected bumped response: {response}"
    );
    assert!(
        response.contains("invalid request target"),
        "expected target rejection body, got: {response}"
    );

    client.stream_mut().shutdown().await.ok();
    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_prefers_http1_when_upstream_http1_only() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-http1-only";
    let policy = PolicySpec::new(policy_name).rule(
        RuleSpec::allow_any(format!("https://{upstream_host}/**")).allow_private_upstream(true),
    );
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2)
            .upstream_mode(UpstreamMode::Http1Keepalive),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.http1_client();

    let negotiated = client.stream().get_ref().1.alpn_protocol();
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
    client.send(request.as_bytes()).await?;
    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected fallback response: {response}"
    );
    assert!(
        response.contains("/fallback"),
        "fallback response body missing path: {response}"
    );

    client.stream_mut().shutdown().await.ok();
    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_supports_http2() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2";
    let policy = PolicySpec::new(policy_name).rule(
        RuleSpec::allow_any(format!("https://{upstream_host}/**")).allow_private_upstream(true),
    );
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2)
            .upstream_mode(UpstreamMode::Http2),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.h2_client().await?;

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

    let (first_status, first_text) = client.request_text(first_request).await?;
    assert_eq!(first_status, StatusCode::OK);
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

    let (second_status, second_text) = client.request_text(second_request).await?;
    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(second_text, "/h2/second");

    client.shutdown().await;

    assert_eq!(
        fixture.accept_count(),
        1,
        "expected upstream HTTP/2 connection reuse"
    );

    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_policy_denied() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "h2-policy";
    let policy = PolicySpec::new(policy_name)
        .rule(
            RuleSpec::allow(&["CONNECT"], format!("https://{upstream_host}/**"))
                .allow_private_upstream(true),
        )
        .rule(
            RuleSpec::deny(&["GET"], format!("https://{upstream_host}/blocked/**"))
                .status(451)
                .body("blocked by policy"),
        );
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2)
            .upstream_mode(UpstreamMode::Http2),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.h2_client().await?;

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
    let (deny_status, deny_body) = client.request_text(deny_request).await?;
    assert_eq!(deny_status, StatusCode::from_u16(451)?);
    assert_eq!(deny_body, "blocked by policy");

    let default_uri = Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query("/unmatched")
        .build()?;
    let default_request = http::Request::builder()
        .method(Method::GET)
        .uri(default_uri)
        .body(())?;
    let (default_status, default_body) = client.request_text(default_request).await?;
    assert_eq!(default_status, StatusCode::FORBIDDEN);
    assert_eq!(default_body, "request blocked by policy");

    client.shutdown().await;

    fixture.shutdown().await;

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
