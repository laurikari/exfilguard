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

use anyhow::Result;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

use support::*;

// --- Tests ---

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

    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-upload"]
fallback = true
"#;

    let policies = format!(
        r###"[[policy]]
name = "allow-upload"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "http://127.0.0.1:{upstream_port}/**"
  allow_private_upstream = true
"###
    );

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies.as_str())
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

    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow-upload"]
fallback = true
"#;

    let policies = format!(
        r###"[[policy]]
name = "allow-upload"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "http://127.0.0.1:{upstream_port}/**"
  allow_private_upstream = true
"###
    );

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies.as_str())
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

    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["allow"]
fallback = true
"#;

    let policies = format!(
        r###"[[policy]]
name = "allow"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "http://127.0.0.1:{upstream_port}/**"
  allow_private_upstream = true
"###
    );

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies.as_str())
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
async fn test_client_idle_timeout() -> Result<()> {
    let dirs = TestDirs::new()?;
    let clients = r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
policies = ["dummy"]
fallback = true
"#;
    let policies = r#"
[[policy]]
name = "dummy"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "http://dummy/**"
"#;

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients, policies)
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
