mod support;

use std::{
    net::Ipv4Addr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration as StdDuration,
};

use anyhow::Result;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

use support::*;

fn response_header_values<'a>(response: &'a str, name: &str) -> Vec<&'a str> {
    response
        .split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .collect()
}

// Minimal HTTP upstream that counts requests
struct MockUpstream {
    listener: TcpListener,
    requests: Arc<AtomicUsize>,
    headers: String,
    body: String,
    delay: Option<StdDuration>,
    raw_response: Option<String>,
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
            raw_response: None,
        })
    }

    async fn new_raw(raw_response: &str) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        Ok(Self {
            listener,
            requests: Arc::new(AtomicUsize::new(0)),
            headers: String::new(),
            body: String::new(),
            delay: None,
            raw_response: Some(raw_response.to_string()),
        })
    }

    fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    async fn run(self) -> Result<()> {
        let delay = self.delay;
        let body = self.body;
        let raw_response = self.raw_response;
        loop {
            let (mut socket, _) = self.listener.accept().await?;
            let requests = self.requests.clone();
            let headers = self.headers.clone();
            let body = body.clone();
            let raw_response = raw_response.clone();
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

                if let Some(raw_response) = raw_response {
                    socket.write_all(raw_response.as_bytes()).await.unwrap();
                    socket.shutdown().await.ok();
                    return;
                }

                let additional_headers = if headers.is_empty() {
                    String::new()
                } else {
                    format!("{headers}\r\n")
                };
                let response_head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{additional_headers}\r\n",
                    body.len()
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

struct BodyEchoUpstream {
    listener: TcpListener,
    requests: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl BodyEchoUpstream {
    async fn new() -> Result<Self> {
        Ok(Self {
            listener: TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?,
            requests: Arc::new(AtomicUsize::new(0)),
            bodies: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    async fn run(self) -> Result<()> {
        loop {
            let (socket, _) = self.listener.accept().await?;
            let requests = self.requests.clone();
            let bodies = self.bodies.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(socket);
                loop {
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).await.unwrap_or(0) == 0 {
                        return;
                    }

                    let mut content_length = 0usize;
                    let mut connection_close = false;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                            return;
                        }
                        if line == "\r\n" {
                            break;
                        }
                        let Some((name, value)) = line.split_once(':') else {
                            return;
                        };
                        if name.eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse().unwrap();
                        } else if name.eq_ignore_ascii_case("connection")
                            && value.trim().eq_ignore_ascii_case("close")
                        {
                            connection_close = true;
                        }
                    }

                    let mut body = vec![0u8; content_length];
                    reader.read_exact(&mut body).await.unwrap();
                    requests.fetch_add(1, Ordering::SeqCst);
                    bodies.lock().unwrap().push(body.clone());

                    let response_body = format!("origin:{}", String::from_utf8_lossy(&body));
                    let connection = if connection_close {
                        "close"
                    } else {
                        "keep-alive"
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nCache-Control: public, max-age=60\r\nConnection: {connection}\r\n\r\n{response_body}",
                        response_body.len()
                    );
                    reader
                        .get_mut()
                        .write_all(response.as_bytes())
                        .await
                        .unwrap();
                    reader.get_mut().flush().await.unwrap();

                    if connection_close {
                        reader.get_mut().shutdown().await.ok();
                        return;
                    }
                }
            });
        }
    }
}

async fn spawn_body_cache_harness(upstream_port: u16) -> Result<ProxyHarness> {
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["cache-test"])
        .policy(
            PolicySpec::new("cache-test").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
                    .cache_enabled(),
            ),
        )
        .render();

    let mut dirs = TestDirs::new()?;
    dirs.enable_cache_dir()?;
    ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await
}

fn fixed_body_request(upstream_port: u16, path: &str, body: &str, close: bool) -> String {
    let connection = if close { "close" } else { "keep-alive" };
    format!(
        "GET http://127.0.0.1:{upstream_port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n{body}",
        body.len()
    )
}

fn bodyless_request(upstream_port: u16, path: &str, close: bool) -> String {
    let connection = if close { "close" } else { "keep-alive" };
    format!(
        "GET http://127.0.0.1:{upstream_port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: {connection}\r\n\r\n"
    )
}

async fn run_conditional_cache_bypass_test(
    conditional_name: &str,
    matching_value: &str,
    nonmatching_value: &str,
    response_validator: &str,
) -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_port = listener.local_addr()?.port();
    let request_counter = Arc::new(AtomicUsize::new(0));
    let counter = request_counter.clone();
    let conditional_name_owned = conditional_name.to_ascii_lowercase();
    let matching_value_owned = matching_value.to_string();
    let response_validator_owned = response_validator.to_string();
    let upstream_task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await?;
            let counter = counter.clone();
            let conditional_name = conditional_name_owned.clone();
            let matching_value = matching_value_owned.clone();
            let response_validator = response_validator_owned.clone();
            tokio::spawn(async move {
                let mut data = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let read = socket.read(&mut buf).await.unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    data.extend_from_slice(&buf[..read]);
                    if data.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }

                counter.fetch_add(1, Ordering::SeqCst);
                let request = String::from_utf8_lossy(&data);
                let condition = request.lines().skip(1).find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case(&conditional_name)
                        .then(|| value.trim().to_string())
                });
                let response = if condition.as_deref() == Some(matching_value.as_str()) {
                    format!(
                        "HTTP/1.1 304 Not Modified\r\n{response_validator}\r\nConnection: close\r\n\r\n"
                    )
                } else {
                    let body = if condition.is_some() {
                        "conditional-full"
                    } else {
                        "initial"
                    };
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nCache-Control: public, max-age=60\r\n{response_validator}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.shutdown().await.ok();
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["cache-test"])
        .policy(
            PolicySpec::new("cache-test").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
                    .cache_enabled(),
            ),
        )
        .render();
    let mut dirs = TestDirs::new()?;
    dirs.enable_cache_dir()?;
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let request = |conditional: Option<&str>| {
        let conditional = conditional
            .map(|value| format!("{conditional_name}: {value}\r\n"))
            .unwrap_or_default();
        format!(
            "GET http://127.0.0.1:{upstream_port}/conditional HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n{conditional}Connection: close\r\n\r\n"
        )
    };

    let mut stream = TcpStream::connect(harness.addr).await?;
    stream.write_all(request(None).as_bytes()).await?;
    let warm = read_http_response(&mut stream).await?;
    assert!(warm.contains("initial"));

    let mut stream = TcpStream::connect(harness.addr).await?;
    stream
        .write_all(request(Some(matching_value)).as_bytes())
        .await?;
    let not_modified = read_http_response(&mut stream).await?;
    assert!(
        not_modified.starts_with("HTTP/1.1 304"),
        "conditional request should reach the origin: {not_modified:?}"
    );

    let mut stream = TcpStream::connect(harness.addr).await?;
    stream
        .write_all(request(Some(nonmatching_value)).as_bytes())
        .await?;
    let full = read_http_response(&mut stream).await?;
    assert!(full.contains("conditional-full"));

    let mut stream = TcpStream::connect(harness.addr).await?;
    stream.write_all(request(None).as_bytes()).await?;
    let cached = read_http_response(&mut stream).await?;
    assert!(
        cached.contains("initial"),
        "conditional full response must not replace cached entry: {cached:?}"
    );
    assert_eq!(request_counter.load(Ordering::SeqCst), 3);

    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
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

async fn run_forced_freshness_test(upstream_headers: &str, expect_cache_hit: bool) -> Result<()> {
    let upstream = MockUpstream::new(upstream_headers).await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();
    let upstream_task = tokio::spawn(upstream.run());

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["cache-test"])
        .policy(
            PolicySpec::new("cache-test").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
                    .cache_force_duration(60),
            ),
        )
        .render();
    let mut dirs = TestDirs::new()?;
    dirs.enable_cache_dir()?;
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let request = bodyless_request(upstream_port, "/forced", true);
    for _ in 0..2 {
        let mut stream = TcpStream::connect(harness.addr).await?;
        stream.write_all(request.as_bytes()).await?;
        let response = read_http_response(&mut stream).await?;
        assert!(
            response.contains("cached-response"),
            "unexpected response for {upstream_headers:?}: {response:?}"
        );
        tokio::time::sleep(StdDuration::from_millis(200)).await;
    }

    let expected_requests = if expect_cache_hit { 1 } else { 2 };
    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        expected_requests,
        "unexpected forced-cache behavior for upstream headers {upstream_headers:?}"
    );

    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forced_freshness_is_only_an_absent_metadata_fallback() -> Result<()> {
    run_forced_freshness_test("", true).await?;
    run_forced_freshness_test("Age: 61", false).await?;
    run_forced_freshness_test("Cache-Control: max-age=0", false).await?;
    run_forced_freshness_test("Cache-Control: public, max-age=invalid", false).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn if_none_match_bypasses_cache_lookup_and_storage() -> Result<()> {
    run_conditional_cache_bypass_test("If-None-Match", "\"v1\"", "\"other\"", "ETag: \"v1\"").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn if_modified_since_bypasses_cache_lookup_and_storage() -> Result<()> {
    run_conditional_cache_bypass_test(
        "If-Modified-Since",
        "Sun, 06 Nov 1994 08:49:37 GMT",
        "Sun, 06 Nov 1994 08:49:36 GMT",
        "Last-Modified: Sun, 06 Nov 1994 08:49:37 GMT",
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn existing_age_can_exhaust_origin_freshness() -> Result<()> {
    let upstream = MockUpstream::new("Cache-Control: public, max-age=60\r\nAge: 59").await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();
    let upstream_task = tokio::spawn(upstream.run());

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["cache-test"])
        .policy(
            PolicySpec::new("cache-test").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
                    .cache_enabled(),
            ),
        )
        .render();
    let mut dirs = TestDirs::new()?;
    dirs.enable_cache_dir()?;
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;
    let request = bodyless_request(upstream_port, "/aged", true);

    for _ in 0..2 {
        let mut stream = TcpStream::connect(harness.addr).await?;
        stream.write_all(request.as_bytes()).await?;
        assert!(
            read_http_response(&mut stream)
                .await?
                .contains("cached-response")
        );
        tokio::time::sleep(StdDuration::from_millis(1_100)).await;
    }
    assert_eq!(request_counter.load(Ordering::SeqCst), 2);

    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn body_transfer_time_consumes_freshness() -> Result<()> {
    let upstream = MockUpstream::new_with_delay(
        "Cache-Control: public, max-age=1",
        Some(StdDuration::from_millis(1_100)),
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
                    .cache_enabled(),
            ),
        )
        .render();
    let mut dirs = TestDirs::new()?;
    dirs.enable_cache_dir()?;
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;
    let request = bodyless_request(upstream_port, "/slow", true);

    for _ in 0..2 {
        let mut stream = TcpStream::connect(harness.addr).await?;
        stream.write_all(request.as_bytes()).await?;
        assert!(
            read_http_response(&mut stream)
                .await?
                .contains("cached-response")
        );
    }
    assert_eq!(request_counter.load(Ordering::SeqCst), 2);

    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_vary_values_do_not_cross_cache_representations() -> Result<()> {
    let upstream =
        MockUpstream::new("Cache-Control: public, max-age=60\r\nVary: X-Variant").await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();
    let upstream_task = tokio::spawn(upstream.run());

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["cache-test"])
        .policy(
            PolicySpec::new("cache-test").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
                    .cache_enabled(),
            ),
        )
        .render();
    let mut dirs = TestDirs::new()?;
    dirs.enable_cache_dir()?;
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let repeated = format!(
        "GET http://127.0.0.1:{upstream_port}/vary HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nX-Variant: common\r\nX-Variant: secret\r\nConnection: close\r\n\r\n"
    );
    let mut stream = TcpStream::connect(harness.addr).await?;
    stream.write_all(repeated.as_bytes()).await?;
    let response = read_http_response(&mut stream).await?;
    assert!(response.contains("cached-response"));
    assert_eq!(request_counter.load(Ordering::SeqCst), 1);

    tokio::time::sleep(StdDuration::from_millis(200)).await;

    let first_only = format!(
        "GET http://127.0.0.1:{upstream_port}/vary HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nX-Variant: common\r\nConnection: close\r\n\r\n"
    );
    let mut stream = TcpStream::connect(harness.addr).await?;
    stream.write_all(first_only.as_bytes()).await?;
    let response = read_http_response(&mut stream).await?;
    assert!(response.contains("cached-response"));
    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        2,
        "request sharing only the first Vary value must miss"
    );

    tokio::time::sleep(StdDuration::from_millis(200)).await;

    let mut stream = TcpStream::connect(harness.addr).await?;
    stream.write_all(first_only.as_bytes()).await?;
    let response = read_http_response(&mut stream).await?;
    assert!(response.contains("cached-response"));
    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        2,
        "the exact single-value representation should now hit"
    );

    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixed_body_requests_do_not_populate_cache_or_share_variants() -> Result<()> {
    let upstream = BodyEchoUpstream::new().await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();
    let received_bodies = upstream.bodies.clone();
    let upstream_task = tokio::spawn(upstream.run());
    let harness = spawn_body_cache_harness(upstream_port).await?;

    for body in ["alpha", "bravo"] {
        let mut stream = TcpStream::connect(harness.addr).await?;
        stream
            .write_all(fixed_body_request(upstream_port, "/variant", body, true).as_bytes())
            .await?;
        let response = read_http_response(&mut stream).await?;
        assert!(
            response.contains(&format!("origin:{body}")),
            "body variant was not forwarded independently: {response}"
        );
    }

    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        2,
        "each body-bearing request must reach the origin"
    );

    // A later bodyless request should populate a fresh entry, proving neither
    // body-bearing response was stored under the bodyless cache key.
    let bodyless = bodyless_request(upstream_port, "/variant", true);
    let mut stream = TcpStream::connect(harness.addr).await?;
    stream.write_all(bodyless.as_bytes()).await?;
    let response = read_http_response(&mut stream).await?;
    assert!(response.contains("origin:"));
    assert_eq!(request_counter.load(Ordering::SeqCst), 3);

    tokio::time::sleep(StdDuration::from_millis(200)).await;

    let mut stream = TcpStream::connect(harness.addr).await?;
    stream.write_all(bodyless.as_bytes()).await?;
    let response = read_http_response(&mut stream).await?;
    assert!(response.contains("origin:"));
    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        3,
        "the bodyless response should be cacheable"
    );
    assert_eq!(
        *received_bodies.lock().unwrap(),
        vec![b"alpha".to_vec(), b"bravo".to_vec(), Vec::new()]
    );

    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixed_body_bypasses_existing_hit_and_preserves_pipeline() -> Result<()> {
    let upstream = BodyEchoUpstream::new().await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();
    let upstream_task = tokio::spawn(upstream.run());
    let harness = spawn_body_cache_harness(upstream_port).await?;

    let bodyless_close = bodyless_request(upstream_port, "/pipelined", true);
    let mut warm_stream = TcpStream::connect(harness.addr).await?;
    warm_stream.write_all(bodyless_close.as_bytes()).await?;
    let warm_response = read_http_response(&mut warm_stream).await?;
    assert!(warm_response.contains("origin:"));
    assert_eq!(request_counter.load(Ordering::SeqCst), 1);

    tokio::time::sleep(StdDuration::from_millis(200)).await;

    let body_request = fixed_body_request(upstream_port, "/pipelined", "BODY", false);
    let following_request = bodyless_request(upstream_port, "/pipelined", true);
    let mut stream = TcpStream::connect(harness.addr).await?;
    stream
        .write_all(format!("{body_request}{following_request}").as_bytes())
        .await?;

    let first = read_http_response_with_length(&mut stream).await?;
    assert!(
        first.contains("origin:BODY"),
        "body-bearing request incorrectly used the existing cache hit: {first}"
    );
    let second = read_http_response_with_length(&mut stream).await?;
    assert!(
        second.contains("origin:"),
        "following pipelined request was not parsed cleanly: {second}"
    );
    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        2,
        "only the warmup and body-bearing request should reach the origin"
    );

    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expect_continue_body_request_bypasses_existing_hit() -> Result<()> {
    let upstream = BodyEchoUpstream::new().await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();
    let upstream_task = tokio::spawn(upstream.run());
    let harness = spawn_body_cache_harness(upstream_port).await?;

    let bodyless = bodyless_request(upstream_port, "/expect", true);
    let mut warm_stream = TcpStream::connect(harness.addr).await?;
    warm_stream.write_all(bodyless.as_bytes()).await?;
    let warm_response = read_http_response(&mut warm_stream).await?;
    assert!(warm_response.contains("origin:"));
    tokio::time::sleep(StdDuration::from_millis(200)).await;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request_head = format!(
        "GET http://127.0.0.1:{upstream_port}/expect HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nContent-Length: 4\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request_head.as_bytes()).await?;
    let interim = read_until_double_crlf(&mut stream).await?;
    assert!(
        interim.starts_with("HTTP/1.1 100 Continue"),
        "cache hit incorrectly replaced the continue handshake: {interim}"
    );

    stream.write_all(b"BODY").await?;
    let response = read_http_response(&mut stream).await?;
    assert!(
        response.contains("origin:BODY"),
        "body was not forwarded after 100 Continue: {response}"
    );
    assert_eq!(request_counter.load(Ordering::SeqCst), 2);

    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_origin_ttl_is_capped_and_cache_hits() -> Result<()> {
    let upstream = MockUpstream::new("Cache-Control: public, max-age=18446744073709551615").await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();

    let upstream_task = tokio::spawn(upstream.run());

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["cache-test"])
        .policy(
            PolicySpec::new("cache-test").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
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
async fn test_chunked_response_with_trailers_is_not_cached() -> Result<()> {
    let raw_response = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Cache-Control: public, max-age=60\r\n",
        "Connection: close\r\n",
        "\r\n",
        "f\r\ncached-response\r\n",
        "0\r\n",
        "Set-Cookie: session=abc\r\n",
        "\r\n",
    );
    let upstream = MockUpstream::new_raw(raw_response).await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();

    let upstream_task = tokio::spawn(upstream.run());

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["cache-test"])
        .policy(
            PolicySpec::new("cache-test").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
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

    let mut stream = TcpStream::connect(harness.addr).await?;
    stream.write_all(request.as_bytes()).await?;
    let response = read_http_response(&mut stream).await?;
    assert!(
        response.contains("cached-response"),
        "Unexpected response: {}",
        response
    );
    assert!(
        response.contains("Set-Cookie: session=abc"),
        "Response trailers should still be forwarded"
    );
    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        1,
        "Should hit upstream once"
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
        "Trailer-bearing response should not be served from cache"
    );

    harness.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunked_response_cache_hit_uses_canonical_payload() -> Result<()> {
    let raw_response = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Cache-Control: public, max-age=60\r\n",
        "Connection: close\r\n",
        "\r\n",
        "6;extension=yes\r\n",
        "cached\r\n",
        "9\r\n",
        "-response\r\n",
        "0\r\n",
        "\r\n",
    );
    let upstream = MockUpstream::new_raw(raw_response).await?;
    let upstream_port = upstream.port();
    let request_counter = upstream.requests.clone();
    let upstream_task = tokio::spawn(upstream.run());

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["cache-test"])
        .policy(
            PolicySpec::new("cache-test").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
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

    let mut first_stream = TcpStream::connect(harness.addr).await?;
    first_stream.write_all(request.as_bytes()).await?;
    let first = read_http_response(&mut first_stream).await?;
    assert_eq!(
        response_header_values(&first, "transfer-encoding"),
        ["chunked"]
    );
    assert!(first.ends_with("6;extension=yes\r\ncached\r\n9\r\n-response\r\n0\r\n\r\n"));

    tokio::time::sleep(StdDuration::from_millis(200)).await;
    let mut second_stream = TcpStream::connect(harness.addr).await?;
    second_stream.write_all(request.as_bytes()).await?;
    let second = read_http_response(&mut second_stream).await?;
    assert!(response_header_values(&second, "transfer-encoding").is_empty());
    assert_eq!(response_header_values(&second, "content-length"), ["15"]);
    assert!(second.ends_with("\r\n\r\ncached-response"), "{second:?}");
    assert_eq!(request_counter.load(Ordering::SeqCst), 1);

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
    let ages = response_header_values(&response_one, "Age");
    assert_eq!(ages.len(), 1);
    assert!(ages[0].parse::<u64>()? >= 2);

    stream.write_all(keepalive_request.as_bytes()).await?;
    let response_two = read_http_response_with_length(&mut stream).await?;
    assert!(response_two.contains("cached-response"));
    assert_eq!(response_header_values(&response_two, "Age").len(), 1);

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
        .join("v5");

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
