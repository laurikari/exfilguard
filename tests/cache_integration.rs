mod support;

use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration as StdDuration,
};

use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use support::*;

// Minimal HTTP upstream that counts requests
struct MockUpstream {
    listener: TcpListener,
    requests: Arc<AtomicUsize>,
    headers: String,
    body: String,
    delay: Option<StdDuration>,
}

impl MockUpstream {
    async fn new(headers: &str) -> Result<Self> {
        Self::new_with_delay(headers, None).await
    }

    async fn new_with_delay(headers: &str, delay: Option<StdDuration>) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        Ok(Self {
            listener,
            requests: Arc::new(AtomicUsize::new(0)),
            headers: headers.to_string(),
            body: "cached-response".to_string(),
            delay,
        })
    }

    fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    async fn run(self) -> Result<()> {
        let delay = self.delay;
        let body = self.body;
        loop {
            let (mut socket, _) = self.listener.accept().await?;
            let requests = self.requests.clone();
            let headers = self.headers.clone();
            let body = body.clone();
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

                let response_head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n\r\n",
                    body.len(),
                    headers
                );
                socket.write_all(response_head.as_bytes()).await.unwrap();
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }
                socket.write_all(body.as_bytes()).await.unwrap();
                socket.shutdown().await.ok();
            });
        }
    }
}

async fn run_cache_bypass_test(upstream_headers: &str, request_headers: &str) -> Result<()> {
    let upstream = MockUpstream::new(upstream_headers).await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();

    let upstream_task = tokio::spawn(upstream.run());

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["cache-test"])
        .policy(
            PolicySpec::new("cache-test").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
                    .allow_private_upstream(true)
                    .cache_enabled(),
            ),
        )
        .render();

    let mut dirs = TestDirs::new()?;
    dirs.enable_cache_dir()?;

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/resource HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n{request_headers}Connection: close\r\n\r\n"
    );

    // First Request (Miss)
    let mut stream = TcpStream::connect(harness.addr).await?;
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
    let mut stream = TcpStream::connect(harness.addr).await?;
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

    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cache_hit_avoids_upstream() -> Result<()> {
    let upstream = MockUpstream::new("Cache-Control: public, max-age=60").await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();

    let upstream_task = tokio::spawn(upstream.run());

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["cache-test"])
        .policy(
            PolicySpec::new("cache-test").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
                    .allow_private_upstream(true)
                    .cache_enabled(),
            ),
        )
        .render();

    let mut dirs = TestDirs::new()?;
    dirs.enable_cache_dir()?;

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    // First Request (Miss)
    let mut stream = TcpStream::connect(harness.addr).await?;
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
    let mut stream = TcpStream::connect(harness.addr).await?;
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

    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cache_hit_keeps_connection_open() -> Result<()> {
    let upstream = MockUpstream::new("Cache-Control: public, max-age=60").await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();

    let upstream_task = tokio::spawn(upstream.run());

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["cache-test"])
        .policy(
            PolicySpec::new("cache-test").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
                    .allow_private_upstream(true)
                    .cache_enabled(),
            ),
        )
        .render();

    let mut dirs = TestDirs::new()?;
    dirs.enable_cache_dir()?;

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/resource HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );

    // Warm the cache on a throwaway connection.
    let mut stream = TcpStream::connect(harness.addr).await?;
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

    tokio::time::sleep(StdDuration::from_millis(2000)).await;

    // Cache hit should keep the downstream connection open.
    let keepalive_request = format!(
        "GET http://127.0.0.1:{upstream_port}/resource HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: keep-alive\r\n\r\n"
    );
    let mut stream = TcpStream::connect(harness.addr).await?;
    stream.write_all(keepalive_request.as_bytes()).await?;
    let response_one = read_http_response_with_length(&mut stream).await?;
    assert!(response_one.contains("cached-response"));

    stream.write_all(keepalive_request.as_bytes()).await?;
    let response_two = read_http_response_with_length(&mut stream).await?;
    assert!(response_two.contains("cached-response"));

    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        1,
        "Cache hits should avoid upstream and keep the connection open"
    );

    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cache_write_failure_does_not_abort_response() -> Result<()> {
    let log_capture = LogCapture::new("info").await;

    let upstream = MockUpstream::new_with_delay(
        "Cache-Control: public, max-age=60",
        Some(StdDuration::from_millis(200)),
    )
    .await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();

    let upstream_task = tokio::spawn(upstream.run());

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["cache-test"])
        .policy(
            PolicySpec::new("cache-test").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
                    .allow_private_upstream(true)
                    .cache_enabled(),
            ),
        )
        .render();

    let mut dirs = TestDirs::new()?;
    dirs.enable_cache_dir()?;

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let cache_version_dir = harness
        .dirs
        .cache_dir
        .as_ref()
        .expect("cache dir enabled")
        .join("v1");

    let readonly_marker = Arc::new(AtomicUsize::new(0));
    let watcher_dir = cache_version_dir.clone();
    let watcher_marker = readonly_marker.clone();
    let watcher = tokio::spawn(async move {
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > StdDuration::from_secs(2) {
                break;
            }
            if let Ok(entries) = std::fs::read_dir(&watcher_dir) {
                for entry in entries {
                    let entry = entry?;
                    let name = entry.file_name();
                    if name.to_string_lossy().starts_with("tmp_") {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let mut perms = std::fs::metadata(&watcher_dir)?.permissions();
                            perms.set_mode(0o500);
                            std::fs::set_permissions(&watcher_dir, perms)?;
                            watcher_marker.store(1, Ordering::SeqCst);
                        }
                        break;
                    }
                }
            }
            if watcher_marker.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        Ok::<(), anyhow::Error>(())
    });

    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/resource HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );

    let mut stream = TcpStream::connect(harness.addr).await?;
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

    watcher.await??;
    assert_eq!(
        readonly_marker.load(Ordering::SeqCst),
        1,
        "Expected cache directory to be made read-only"
    );

    tokio::time::sleep(StdDuration::from_millis(200)).await;

    let mut stream = TcpStream::connect(harness.addr).await?;
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
        "Cache write failure should not create a usable entry"
    );
    let logs = log_capture.text();
    assert!(
        logs.contains("failed to finalize cache entry")
            || logs.contains("failed to open cache write stream"),
        "expected cache write failure to be logged, got: {logs}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&cache_version_dir)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&cache_version_dir, perms)?;
    }

    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;

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
