mod support;

use std::{
    io::ErrorKind,
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration as StdDuration,
};

use anyhow::{Result, bail};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

use support::*;

// --- Tests ---

async fn wait_for_metric(sample: &str) -> Result<()> {
    for _ in 0..100 {
        let metrics = String::from_utf8(exfilguard::metrics::gather())?;
        if metrics.lines().any(|line| line == sample) {
            return Ok(());
        }
        sleep(StdDuration::from_millis(10)).await;
    }
    bail!("timed out waiting for metric sample: {sample}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_client_connection_limit_rejects_and_recovers() -> Result<()> {
    let dirs = TestDirs::new()?;
    let client_name = "connection-limit-client";
    let (clients, policies) = TestConfigBuilder::new()
        .fallback_client_with_max_connections(client_name, &["deny"], 1)
        .policy(
            PolicySpec::new("deny")
                .rule(RuleSpec::deny(&["ANY"], "http://example.com/**").status(403)),
        )
        .render();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let inactive_sample =
        format!("downstream_connections_active_by_client{{client=\"{client_name}\"}} 0");
    wait_for_metric(&inactive_sample).await?;

    let partial_request = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n";
    let mut first = TcpStream::connect(harness.addr).await?;
    first.write_all(partial_request).await?;
    first.flush().await?;
    let active_sample =
        format!("downstream_connections_active_by_client{{client=\"{client_name}\"}} 1");
    wait_for_metric(&active_sample).await?;

    let mut second = TcpStream::connect(harness.addr).await?;
    let mut byte = [0u8; 1];
    match timeout(StdDuration::from_secs(1), second.read(&mut byte)).await? {
        Ok(0) => {}
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
            ) => {}
        other => panic!("limited connection was not closed immediately: {other:?}"),
    }

    wait_for_metric(&format!(
        "downstream_connection_rejections_total{{client=\"{client_name}\"}} 1"
    ))
    .await?;

    drop(first);
    wait_for_metric(&inactive_sample).await?;

    let mut replacement = TcpStream::connect(harness.addr).await?;
    replacement.write_all(partial_request).await?;
    replacement.flush().await?;
    wait_for_metric(&active_sample).await?;

    replacement.shutdown().await.ok();
    second.shutdown().await.ok();
    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_max_request_body_size_enforced() -> Result<()> {
    let dirs = TestDirs::new()?;

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

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-upload"])
        .policy(
            PolicySpec::new("allow-upload").rule(RuleSpec::allow_any(format!(
                "http://127.0.0.1:{upstream_port}/**"
            ))),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(|settings| settings.max_request_body_size = 1024)
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    // Send a large body > 1KB
    let body_size = 2048;
    let body = vec![b'A'; body_size];
    let request = format!(
        "POST http://127.0.0.1:{upstream_port}/upload HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nContent-Length: {body_size}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    let response = timeout(
        StdDuration::from_secs(2),
        read_http_response_with_length(&mut stream),
    )
    .await??;
    assert!(
        response.starts_with("HTTP/1.1 413"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("request body exceeds configured limit"),
        "missing limit body: {response}"
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn response_header_timeout_returns_gateway_timeout_without_total_timeout() -> Result<()> {
    let dirs = TestDirs::new()?;
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_port = upstream_listener.local_addr()?.port();
    let upstream_task = tokio::spawn(async move {
        if let Ok((_stream, _)) = upstream_listener.accept().await {
            sleep(StdDuration::from_secs(3)).await;
        }
    });

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-timeout"])
        .policy(PolicySpec::new("allow-timeout").rule(RuleSpec::allow(
            &["GET"],
            format!("http://127.0.0.1:{upstream_port}/**"),
        )))
        .render();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(|settings| {
            settings.response_header_timeout = 1;
            settings.request_total_timeout = 0;
        })
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/slow HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let response = timeout(
        StdDuration::from_secs(2),
        read_http_response_with_length(&mut stream),
    )
    .await??;
    assert!(
        response.starts_with("HTTP/1.1 504"),
        "unexpected response: {response}"
    );
    assert!(response.contains("request timed out"));

    stream.shutdown().await.ok();
    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_total_timeout_triggers_during_body() -> Result<()> {
    let dirs = TestDirs::new()?;

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
        }
    });

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-upload"])
        .policy(
            PolicySpec::new("allow-upload").rule(RuleSpec::allow_any(format!(
                "http://127.0.0.1:{upstream_port}/**"
            ))),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(|settings| {
            settings.request_total_timeout = 1;
            settings.request_body_idle_timeout = 10;
        })
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let body_size = 10;
    let request = format!(
        "POST http://127.0.0.1:{upstream_port}/upload HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nContent-Length: {body_size}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(b"A").await?;
    stream.flush().await?;

    sleep(StdDuration::from_secs(2)).await;

    let response = timeout(
        StdDuration::from_secs(2),
        read_http_response_with_length(&mut stream),
    )
    .await??;
    assert!(
        response.starts_with("HTTP/1.1 504"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("request timed out"),
        "missing timeout body: {response}"
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_total_timeout_caps_upstream_tls_setup() -> Result<()> {
    let dirs = TestDirs::new()?;

    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_port = upstream_listener.local_addr()?.port();
    let upstream_task = tokio::spawn(async move {
        if let Ok((_stream, _)) = upstream_listener.accept().await {
            sleep(StdDuration::from_secs(10)).await;
        }
    });

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-tls"])
        .policy(PolicySpec::new("allow-tls").rule(RuleSpec::allow(
            &["GET"],
            format!("https://127.0.0.1:{upstream_port}/**"),
        )))
        .render();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(|settings| {
            settings.request_total_timeout = 1;
            settings.tls_handshake_timeout = 10;
        })
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request = format!(
        "GET https://127.0.0.1:{upstream_port}/slow HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let response = timeout(
        StdDuration::from_secs(3),
        read_http_response_with_length(&mut stream),
    )
    .await??;
    assert!(
        response.starts_with("HTTP/1.1 504"),
        "unexpected response: {response}"
    );
    assert!(response.contains("request timed out"));

    stream.shutdown().await.ok();
    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_total_timeout_starts_after_complete_request_head() -> Result<()> {
    let dirs = TestDirs::new()?;

    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_port = upstream_listener.local_addr()?.port();
    let upstream_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = upstream_listener.accept().await {
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        }
    });

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-slow-head"])
        .policy(PolicySpec::new("allow-slow-head").rule(RuleSpec::allow(
            &["GET"],
            format!("http://127.0.0.1:{upstream_port}/**"),
        )))
        .render();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(|settings| {
            settings.request_total_timeout = 1;
            settings.request_header_timeout = 5;
        })
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let partial = format!(
        "GET http://127.0.0.1:{upstream_port}/slow-head HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n"
    );
    stream.write_all(partial.as_bytes()).await?;
    stream.flush().await?;
    sleep(StdDuration::from_secs(2)).await;
    stream.write_all(b"Connection: close\r\n\r\n").await?;
    stream.flush().await?;

    let response = timeout(
        StdDuration::from_secs(3),
        read_http_response_with_length(&mut stream),
    )
    .await??;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn early_http1_errors_redact_queries_when_logging_is_disabled() -> Result<()> {
    const SECRET: &str = "m16-query-secret-sentinel";

    let log_capture = LogCapture::new("info").await;
    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow"])
        .policy(PolicySpec::new("allow").rule(RuleSpec::allow_any("http://example.com/**")))
        .render();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(|settings| {
            settings.log_queries = false;
            settings.max_request_body_size = 1;
        })
        .spawn()
        .await?;

    let cases = [
        (
            format!(
                "POST http://example.com/expect?secret={SECRET} HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nExpect: custom\r\nConnection: close\r\n\r\n"
            ),
            "HTTP/1.1 417",
        ),
        (
            format!(
                "POST http://example.com/oversized?secret={SECRET} HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\nConnection: close\r\n\r\n"
            ),
            "HTTP/1.1 413",
        ),
        (
            format!(
                "GET http://[malformed?secret={SECRET} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            ),
            "HTTP/1.1 400",
        ),
    ];

    for (request, expected_status) in cases {
        let mut stream = TcpStream::connect(harness.addr).await?;
        stream.write_all(request.as_bytes()).await?;
        let response = read_http_response_with_length(&mut stream).await?;
        assert!(
            response.starts_with(expected_status),
            "unexpected response: {response}"
        );
    }

    harness.shutdown().await;
    let logs = log_capture.text();
    assert!(!logs.contains(SECRET), "query leaked into logs: {logs}");
    for redacted in [
        "http://example.com/expect",
        "http://example.com/oversized",
        "http://[malformed",
    ] {
        assert!(
            logs.contains(redacted),
            "missing redacted target {redacted:?}: {logs}"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn early_http1_errors_log_queries_only_when_enabled() -> Result<()> {
    const SECRET: &str = "m16-opt-in-query-sentinel";

    let log_capture = LogCapture::new("info").await;
    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow"])
        .policy(PolicySpec::new("allow").rule(RuleSpec::allow_any("http://example.com/**")))
        .render();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(|settings| settings.log_queries = true)
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request = format!(
        "POST http://example.com/invalid?secret={SECRET} HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nExpect: custom\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let response = read_http_response_with_length(&mut stream).await?;
    assert!(response.starts_with("HTTP/1.1 417"));

    harness.shutdown().await;
    let logs = log_capture.text();
    assert!(
        logs.contains(SECRET),
        "explicit query logging omitted query: {logs}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn head_response_body_does_not_poison_keepalive() -> Result<()> {
    let dirs = TestDirs::new()?;

    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_port = upstream_listener.local_addr()?.port();
    let upstream_connections = Arc::new(AtomicUsize::new(0));
    let upstream_connections_clone = upstream_connections.clone();

    let upstream_task = tokio::spawn(async move {
        loop {
            let (stream, _) = match upstream_listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            upstream_connections_clone.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                loop {
                    line.clear();
                    let bytes = match reader.read_line(&mut line).await {
                        Ok(bytes) => bytes,
                        Err(_) => break,
                    };
                    if bytes == 0 {
                        break;
                    }
                    let method = line.split_whitespace().next().unwrap_or("").to_string();
                    loop {
                        line.clear();
                        let n = match reader.read_line(&mut line).await {
                            Ok(n) => n,
                            Err(_) => return,
                        };
                        if n == 0 || line == "\r\n" {
                            break;
                        }
                    }

                    let response = match method.as_str() {
                        "HEAD" => b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" as &[u8],
                        "GET" => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                        _ => b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n",
                    };

                    if reader.get_mut().write_all(response).await.is_err() {
                        break;
                    }
                    if reader.get_mut().flush().await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow"])
        .policy(PolicySpec::new("allow").rule(RuleSpec::allow_any(format!(
            "http://127.0.0.1:{upstream_port}/**"
        ))))
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let client = TcpStream::connect(harness.addr).await?;
    let mut reader = BufReader::new(client);

    let head_request = format!(
        "HEAD http://127.0.0.1:{upstream_port}/probe HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    reader.get_mut().write_all(head_request.as_bytes()).await?;
    reader.get_mut().flush().await?;
    let status = read_response_status(&mut reader).await?;
    assert_eq!(status, 200);

    let get_request = format!(
        "GET http://127.0.0.1:{upstream_port}/data HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    reader.get_mut().write_all(get_request.as_bytes()).await?;
    reader.get_mut().flush().await?;
    let status = read_response_status(&mut reader).await?;
    assert_eq!(status, 200);

    drop(reader);

    for _ in 0..50 {
        if upstream_connections.load(Ordering::SeqCst) >= 2 {
            break;
        }
        sleep(StdDuration::from_millis(50)).await;
    }
    assert!(
        upstream_connections.load(Ordering::SeqCst) >= 2,
        "expected separate upstream connections for HEAD and GET"
    );

    upstream_task.abort();
    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unframed_reset_content_does_not_poison_upstream_pool() -> Result<()> {
    let dirs = TestDirs::new()?;

    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_port = upstream_listener.local_addr()?.port();
    let upstream_connections = Arc::new(AtomicUsize::new(0));
    let upstream_requests = Arc::new(AtomicUsize::new(0));
    let upstream_connections_clone = upstream_connections.clone();
    let upstream_requests_clone = upstream_requests.clone();

    let upstream_task = tokio::spawn(async move {
        loop {
            let (stream, _) = match upstream_listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            upstream_connections_clone.fetch_add(1, Ordering::SeqCst);
            let upstream_requests = upstream_requests_clone.clone();
            tokio::spawn(async move {
                let mut stream = stream;
                loop {
                    match read_until_double_crlf(&mut stream).await {
                        Ok(request) if !request.is_empty() => {}
                        Ok(_) | Err(_) => break,
                    }
                    let request_number = upstream_requests.fetch_add(1, Ordering::SeqCst);
                    let response = if request_number == 0 {
                        b"HTTP/1.1 205 Reset Content\r\n\r\nhello" as &[u8]
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                    };
                    if stream.write_all(response).await.is_err() || stream.flush().await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow"])
        .policy(PolicySpec::new("allow").rule(RuleSpec::allow_any(format!(
            "http://127.0.0.1:{upstream_port}/**"
        ))))
        .render();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let mut first = BufReader::new(TcpStream::connect(harness.addr).await?);
    let first_request = format!(
        "GET http://127.0.0.1:{upstream_port}/reset HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    first.get_mut().write_all(first_request.as_bytes()).await?;
    first.get_mut().flush().await?;
    assert_eq!(read_response_status(&mut first).await?, 205);
    drop(first);

    let mut second = BufReader::new(TcpStream::connect(harness.addr).await?);
    let second_request = format!(
        "GET http://127.0.0.1:{upstream_port}/data HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    second
        .get_mut()
        .write_all(second_request.as_bytes())
        .await?;
    second.get_mut().flush().await?;
    assert_eq!(read_response_status(&mut second).await?, 200);

    assert_eq!(upstream_requests.load(Ordering::SeqCst), 2);
    assert!(
        upstream_connections.load(Ordering::SeqCst) >= 2,
        "unframed 205 connection was returned to the upstream pool"
    );

    upstream_task.abort();
    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_client_idle_timeout() -> Result<()> {
    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["dummy"])
        .policy(PolicySpec::new("dummy").rule(RuleSpec::allow_any("http://dummy/**")))
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(|settings| settings.client_keepalive_idle_timeout = 1)
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;

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

    harness.shutdown().await;

    Ok(())
}
