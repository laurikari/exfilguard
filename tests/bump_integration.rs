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
use http::{HeaderValue, Method, StatusCode, Uri};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::{sleep, timeout},
};

use support::*;

const CONNECT_ESTABLISHED_RESPONSE: &str =
    "HTTP/1.1 200 Connection Established\r\nProxy-Agent: exfilguard\r\n\r\n";

async fn capture_tls_client_hello(host: &str) -> Result<Vec<u8>> {
    let config = build_client_tls(rustls::RootCertStore::empty())?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())?;
    let (client_io, mut capture_io) = tokio::io::duplex(16 * 1024);
    let handshake = tokio::spawn(async move { connector.connect(server_name, client_io).await });

    let mut header = [0u8; 5];
    timeout(
        StdDuration::from_secs(1),
        capture_io.read_exact(&mut header),
    )
    .await??;
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut record = Vec::with_capacity(5 + record_len);
    record.extend_from_slice(&header);
    record.resize(5 + record_len, 0);
    timeout(
        StdDuration::from_secs(1),
        capture_io.read_exact(&mut record[5..]),
    )
    .await??;

    handshake.abort();
    let _ = handshake.await;
    Ok(record)
}

async fn read_tunnel_tail(stream: &mut TcpStream) -> Result<Vec<u8>> {
    timeout(StdDuration::from_secs(3), async {
        let mut tail = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => return Ok(tail),
                Ok(read) => tail.extend_from_slice(&buffer[..read]),
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::ConnectionReset
                            | ErrorKind::BrokenPipe
                            | ErrorKind::UnexpectedEof
                    ) =>
                {
                    return Ok(tail);
                }
                Err(err) => return Err(err.into()),
            }
        }
    })
    .await
    .context("tunnel did not close after terminal relay condition")?
}

fn log_field_value(line: &str, field: &str) -> Option<String> {
    let needle = format!("{field}=");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    } else {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

async fn wait_for_bumped_upstream_requests(
    fixture: &BumpedTlsFixture,
    expected: usize,
) -> Result<()> {
    timeout(StdDuration::from_secs(2), async {
        while fixture.request_count() < expected {
            sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .with_context(|| format!("timed out waiting for {expected} upstream HTTP/2 requests"))?;
    Ok(())
}

fn bumped_h2_request(authority: &str, method: Method, path: &str) -> Result<http::Request<()>> {
    Ok(http::Request::builder()
        .method(method)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority)
                .path_and_query(path)
                .build()?,
        )
        .body(())?)
}

async fn proxy_response_for_raw_upstream_response(upstream_response: Vec<u8>) -> Result<String> {
    let upstream = TestUpstream::http_response(upstream_response).await?;
    let upstream_port = upstream.port();
    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-local"])
        .policy(PolicySpec::new("allow-local").rule(RuleSpec::allow(
            &["GET"],
            format!("http://127.0.0.1:{upstream_port}/**"),
        )))
        .render();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let mut client = ProxyClient::connect(harness.addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/status HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    client.send(request.as_bytes()).await?;
    let response = client.read_response().await?;

    client.shutdown().await;
    harness.shutdown().await;
    drop(upstream);
    Ok(response)
}

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
        .with_private_test_upstreams(false)
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
    let log_capture = LogCapture::new("info").await;
    let upstream = TestUpstream::close().await?;
    let upstream_port = upstream.port();

    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-local"])
        .policy(PolicySpec::new("allow-local").rule(RuleSpec::allow(
            &["GET"],
            format!("http://127.0.0.1:{upstream_port}/**"),
        )))
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
        response.contains("upstream closed connection")
            || response.contains("upstream request failed"),
        "missing upstream failure body: {response}"
    );

    client.shutdown().await;
    harness.shutdown().await;
    drop(upstream);

    let logs = log_capture.text();
    assert!(
        logs.contains("error_reason=\"upstream_closed\"")
            || logs.contains("error_reason=\"upstream_failed\""),
        "expected upstream failure access log entry, got: {logs}"
    );
    let access_line = logs
        .lines()
        .find(|line| {
            line.contains("target=\"access_log\"")
                && line.contains("host=\"127.0.0.1\"")
                && line.contains("path=\"/oops\"")
                && (line.contains("error_reason=\"upstream_closed\"")
                    || line.contains("error_reason=\"upstream_failed\""))
        })
        .expect("upstream failure access log line should exist");
    let access_request_id =
        log_field_value(access_line, "request_id").expect("access log request_id missing");
    let request_id_needle = format!("request_id=\"{access_request_id}\"");
    let forward_line = logs
        .lines()
        .find(|line| {
            line.contains(&request_id_needle)
                && (line.contains("upstream closed connection before response headers")
                    || line.contains("upstream request failed"))
        })
        .expect("matching forward error warning line should exist");
    let forward_request_id =
        log_field_value(forward_line, "request_id").expect("forward_error request_id missing");
    assert_eq!(
        access_request_id, forward_request_id,
        "forward_error and access log request IDs should match; logs: {logs}"
    );
    assert!(
        forward_line.contains("method=GET") || forward_line.contains("method=\"GET\""),
        "forward_error should include method, got: {forward_line}"
    );
    assert!(
        forward_line.contains("host=127.0.0.1") || forward_line.contains("host=\"127.0.0.1\""),
        "forward_error should include host, got: {forward_line}"
    );
    assert!(
        forward_line.contains("path=/oops") || forward_line.contains("path=\"/oops\""),
        "forward_error should include path, got: {forward_line}"
    );
    assert!(
        access_line.contains("error_detail="),
        "access log should include forward error detail, got: {access_line}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_invalid_header_value_returns_400() -> Result<()> {
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
    let request = b"GET http://allowed.test/resource HTTP/1.1\r\nHost: allowed.test\r\nX-Test: ok\rX-Evil: 1\r\nConnection: close\r\n\r\n";
    client.send(request).await?;

    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("invalid request"),
        "expected invalid request body, got: {response}"
    );

    client.shutdown().await;
    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ambiguous_http1_request_whitespace_returns_400() -> Result<()> {
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

    let cases: &[(&str, &[u8])] = &[
        (
            "tab request separator",
            b"GET\thttp://allowed.test/resource HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n",
        ),
        (
            "repeated request separator",
            b"GET  http://allowed.test/resource HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n",
        ),
        (
            "leading header whitespace",
            b"GET http://allowed.test/resource HTTP/1.1\r\n Host: allowed.test\r\nConnection: close\r\n\r\n",
        ),
        (
            "whitespace before header colon",
            b"GET http://allowed.test/resource HTTP/1.1\r\nHost : allowed.test\r\nConnection: close\r\n\r\n",
        ),
    ];

    for (case, request) in cases {
        let mut client = ProxyClient::connect(harness.addr).await?;
        client.send(request).await?;
        let response = client.read_response().await?;
        assert!(
            response.starts_with("HTTP/1.1 400"),
            "{case} was not rejected as a bad request: {response}"
        );
        assert!(
            response.contains("invalid request"),
            "{case} produced an unexpected error body: {response}"
        );
        client.shutdown().await;
    }

    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_invalid_upstream_header_value_returns_502() -> Result<()> {
    let upstream = TestUpstream::http_response(
        b"HTTP/1.1 200 OK\r\nX-Test: ok\rX-Evil: 1\r\nConnection: close\r\n\r\n".to_vec(),
    )
    .await?;
    let upstream_port = upstream.port();

    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-local"])
        .policy(PolicySpec::new("allow-local").rule(RuleSpec::allow(
            &["GET"],
            format!("http://127.0.0.1:{upstream_port}/**"),
        )))
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let mut client = ProxyClient::connect(harness.addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/oops HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    client.send(request.as_bytes()).await?;

    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 502"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("upstream request failed"),
        "expected upstream failure body, got: {response}"
    );

    client.shutdown().await;
    harness.shutdown().await;
    drop(upstream);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_upstream_status_lines_are_rejected_before_forwarding() -> Result<()> {
    let cases = [
        (
            "embedded bare CR",
            b"HTTP/1.1 200 OK\rInjected: yes\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
        ),
        (
            "bare LF terminator",
            b"HTTP/1.1 200 OK\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ),
    ];

    for (case, upstream_response) in cases {
        let response = proxy_response_for_raw_upstream_response(upstream_response).await?;
        assert!(
            response.starts_with("HTTP/1.1 502"),
            "{case} reached the downstream client: {response:?}"
        );
        assert_eq!(
            response.matches("HTTP/1.1 ").count(),
            1,
            "{case} produced more than one downstream response: {response:?}"
        );
        assert!(
            !response.contains("200 OK") && !response.contains("Injected"),
            "{case} leaked origin status-line bytes downstream: {response:?}"
        );
        assert!(
            response.contains("upstream request failed"),
            "{case} did not produce the standard upstream failure response: {response:?}"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_upstream_header_line_endings_are_rejected_before_forwarding() -> Result<()> {
    let cases = [
        (
            "bare LF header line",
            b"HTTP/1.1 200 OK\r\nX-Test: value\nContent-Length: 0\r\n\r\n".to_vec(),
        ),
        (
            "extra CR before header LF",
            b"HTTP/1.1 200 OK\r\nX-Test: value\r\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ),
        (
            "bare LF header terminator",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\n".to_vec(),
        ),
    ];

    for (case, upstream_response) in cases {
        let response = proxy_response_for_raw_upstream_response(upstream_response).await?;
        assert!(
            response.starts_with("HTTP/1.1 502"),
            "{case} reached the downstream client: {response:?}"
        );
        assert_eq!(
            response.matches("HTTP/1.1 ").count(),
            1,
            "{case} produced more than one downstream response: {response:?}"
        );
        assert!(
            !response.contains("200 OK") && !response.contains("X-Test"),
            "{case} leaked origin header bytes downstream: {response:?}"
        );
        assert!(
            response.contains("upstream request failed"),
            "{case} did not produce the standard upstream failure response: {response:?}"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_accepts_zero_length_no_content_for_get_and_delete() -> Result<()> {
    for method in ["GET", "DELETE"] {
        let mut fixture = no_content_fixture(false).await?;
        let response = request_no_content_path(&mut fixture, method, "/zero").await?;
        assert_empty_no_content(&response);
        assert!(response.contains("ETag: \"kept\""), "{response}");
        assert!(response.contains("Connection: close"), "{response}");
        let mut trailing = Vec::new();
        timeout(
            StdDuration::from_secs(2),
            fixture.tls_stream_mut().read_to_end(&mut trailing),
        )
        .await??;
        assert!(
            trailing.is_empty(),
            "unexpected response body: {trailing:?}"
        );
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_rejects_unsafe_no_content_framing() -> Result<()> {
    for path in ["/nonzero", "/chunked", "/both"] {
        for method in ["GET", "DELETE"] {
            let mut fixture = no_content_fixture(false).await?;
            let response = request_no_content_path(&mut fixture, method, path).await?;
            assert!(response.starts_with("HTTP/1.1 502"), "{path}: {response}");
            assert!(!response.contains("204 No Content"), "{path}: {response}");
            fixture.shutdown().await;
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_conforming_no_content_preserves_keepalive() -> Result<()> {
    let mut fixture = no_content_fixture(false).await?;
    let response = request_no_content_path(&mut fixture, "GET", "/plain").await?;
    assert_empty_no_content(&response);
    assert!(!response.to_ascii_lowercase().contains("connection: close"));
    let connections = fixture.accept_count();
    let response = request_no_content_path(&mut fixture, "GET", "/after").await?;
    assert!(response.ends_with("\r\n\r\nreal"), "{response}");
    assert_eq!(fixture.accept_count(), connections);
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_zero_length_no_content_does_not_poison_next_response() -> Result<()> {
    let mut fixture = no_content_fixture(false).await?;
    let response = request_no_content_path(&mut fixture, "DELETE", "/poison").await?;
    assert_empty_no_content(&response);
    let mut trailing = Vec::new();
    timeout(
        StdDuration::from_secs(2),
        fixture.tls_stream_mut().read_to_end(&mut trailing),
    )
    .await??;
    assert!(
        trailing.is_empty(),
        "injected response escaped: {trailing:?}"
    );
    let connections = fixture.accept_count();
    fixture.reconnect(ClientProtocols::Http1).await?;
    let response = request_no_content_path(&mut fixture, "GET", "/after").await?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("\r\n\r\nreal"), "{response}");
    assert!(!response.contains("poison"), "{response}");
    assert!(fixture.accept_count() > connections);
    assert_eq!(fixture.request_count(), 2);
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_caches_normalized_no_content() -> Result<()> {
    let mut fixture = no_content_fixture(true).await?;
    let response = request_no_content_path(&mut fixture, "GET", "/zero").await?;
    assert_empty_no_content(&response);
    // Wait for completion of the cache write and retirement of the connection.
    let mut trailing = Vec::new();
    timeout(
        StdDuration::from_secs(2),
        fixture.tls_stream_mut().read_to_end(&mut trailing),
    )
    .await??;
    assert!(trailing.is_empty());
    let uri: Uri = format!("https://localhost:{}/zero", fixture.upstream_addr().port()).parse()?;
    let cached = fixture
        .cache()
        .lookup(&Method::GET, &uri, &http::HeaderMap::new())
        .await
        .context("204 was not cached")?;
    assert_eq!(cached.status, StatusCode::NO_CONTENT);
    assert_eq!(cached.content_length, 0);
    assert!(!cached.headers.contains_key(http::header::CONTENT_LENGTH));
    fixture.reconnect(ClientProtocols::Http1).await?;
    let response = request_no_content_path(&mut fixture, "GET", "/zero").await?;
    assert_empty_no_content(&response);
    assert_eq!(
        fixture.request_count(),
        1,
        "second response was not a cache hit"
    );
    fixture.shutdown().await;
    Ok(())
}

async fn no_content_fixture(cache: bool) -> Result<BumpedTlsFixture> {
    let rule = RuleSpec::allow(&["GET", "DELETE"], "https://localhost/**");
    let policy =
        PolicySpec::new("allow-no-content").rule(if cache { rule.cache_enabled() } else { rule });
    let mut options = BumpedTlsOptions::new("localhost", "allow-no-content", policy)
        .upstream_mode(UpstreamMode::Http1NoContent);
    if cache {
        options = options.with_cache();
    }
    BumpedTlsFixture::new(options).await
}

async fn request_no_content_path(
    fixture: &mut BumpedTlsFixture,
    method: &str,
    path: &str,
) -> Result<String> {
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
        fixture.upstream_addr().port()
    );
    let mut client = fixture.http1_client();
    client.send(request).await?;
    client.read_response_with_length().await
}

fn assert_empty_no_content(response: &str) {
    assert!(
        response.starts_with("HTTP/1.1 204 No Content\r\n"),
        "{response}"
    );
    assert!(
        !response.to_ascii_lowercase().contains("content-length"),
        "{response}"
    );
    assert!(
        !response.to_ascii_lowercase().contains("transfer-encoding"),
        "{response}"
    );
    assert!(response.ends_with("\r\n\r\n"), "{response}");
    assert_eq!(response.matches("HTTP/1.1 ").count(), 1, "{response}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forbidden_no_content_framing_is_rejected_before_forwarding() -> Result<()> {
    let cases = [
        (
            "204 with Content-Length",
            b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
        ),
        (
            "204 with Transfer-Encoding",
            b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
                .to_vec(),
        ),
        (
            "205 with nonzero Content-Length",
            b"HTTP/1.1 205 Reset Content\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
        ),
        (
            "205 with Transfer-Encoding",
            b"HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec(),
        ),
    ];

    for (case, upstream_response) in cases {
        let response = proxy_response_for_raw_upstream_response(upstream_response).await?;
        assert!(
            response.starts_with("HTTP/1.1 502"),
            "{case} reached the downstream client: {response:?}"
        );
        assert_eq!(
            response.matches("HTTP/1.1 ").count(),
            1,
            "{case} produced more than one downstream response: {response:?}"
        );
        assert!(
            !response.contains("204 No Content") && !response.contains("205 Reset Content"),
            "{case} leaked the invalid origin response downstream: {response:?}"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unusual_valid_upstream_reason_phrase_is_forwarded() -> Result<()> {
    let status_line = "HTTP/1.1 299 Odd\tReason !~é";
    let response = proxy_response_for_raw_upstream_response(
        format!("{status_line}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK").into_bytes(),
    )
    .await?;

    assert!(
        response.starts_with(&format!("{status_line}\r\n")),
        "valid reason phrase was rejected or rewritten: {response:?}"
    );
    assert!(response.ends_with("\r\n\r\nOK"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_invalid_chunk_size_line_returns_400() -> Result<()> {
    let upstream = TestUpstream::http_ok("unexpected").await?;
    let upstream_port = upstream.port();

    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-local"])
        .policy(PolicySpec::new("allow-local").rule(RuleSpec::allow(
            &["POST"],
            format!("http://127.0.0.1:{upstream_port}/**"),
        )))
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let mut client = ProxyClient::connect(harness.addr).await?;
    let request = format!(
        "POST http://127.0.0.1:{upstream_port}/upload HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\nx\r\n0\r\n\r\n"
    );
    client.send(request.as_bytes()).await?;

    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("invalid request body"),
        "expected invalid request body response, got: {response}"
    );

    client.shutdown().await;
    harness.shutdown().await;
    drop(upstream);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_valid_signed_chunk_extension_is_forwarded_unchanged() -> Result<()> {
    let chunked_body = b"5;chunk-signature=abc123\r\nhello\r\n0\r\n\r\n".to_vec();
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let expected_body_len = chunked_body.len();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await?;
        let request_head = read_request(&mut stream).await?;
        let request_head = String::from_utf8(request_head)?;
        anyhow::ensure!(
            request_head
                .to_ascii_lowercase()
                .contains("transfer-encoding: chunked"),
            "upstream request did not retain chunked framing: {request_head}"
        );

        let mut body = vec![0u8; expected_body_len];
        stream.read_exact(&mut body).await?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await?;
        stream.flush().await?;
        stream.shutdown().await.ok();
        Ok::<Vec<u8>, anyhow::Error>(body)
    });

    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-local"])
        .policy(PolicySpec::new("allow-local").rule(RuleSpec::allow(
            &["POST"],
            format!("http://127.0.0.1:{}/**", upstream_addr.port()),
        )))
        .render();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let mut client = ProxyClient::connect(harness.addr).await?;
    let request_head = format!(
        "POST http://127.0.0.1:{port}/upload HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        port = upstream_addr.port()
    );
    let mut request = request_head.into_bytes();
    request.extend_from_slice(&chunked_body);
    client.send(&request).await?;

    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );
    let forwarded_body = upstream_task.await.expect("upstream task join failed")?;
    assert_eq!(forwarded_body, chunked_body);

    client.shutdown().await;
    harness.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_invalid_upstream_chunk_closes_started_response_without_502() -> Result<()> {
    let log_capture = LogCapture::new("info").await;
    let upstream = TestUpstream::http_response(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\nx\r\n0\r\n\r\n"
            .to_vec(),
    )
    .await?;
    let upstream_port = upstream.port();

    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-local"])
        .policy(PolicySpec::new("allow-local").rule(RuleSpec::allow(
            &["GET"],
            format!("http://127.0.0.1:{upstream_port}/**"),
        )))
        .render();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let mut client = ProxyClient::connect(harness.addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/bad-body HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    client.send(request.as_bytes()).await?;

    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "origin response head should have been forwarded: {response}"
    );
    assert_eq!(
        response.matches("HTTP/1.1 ").count(),
        1,
        "proxy must not append a second response after forwarding the origin status: {response}"
    );
    assert!(
        !response.contains("502 Bad Gateway"),
        "proxy appended a 502 to an already-started response: {response}"
    );

    client.shutdown().await;
    harness.shutdown().await;
    drop(upstream);

    let logs = log_capture.text();
    assert!(
        logs.contains("error_reason=\"response_body_failed\"")
            || logs.contains("error_reason=response_body_failed"),
        "expected response-body failure access log, got: {logs}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_truncated_fixed_body_closes_started_response_without_502() -> Result<()> {
    let upstream = TestUpstream::http_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nshort".to_vec(),
    )
    .await?;
    let upstream_port = upstream.port();

    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-local"])
        .policy(PolicySpec::new("allow-local").rule(RuleSpec::allow(
            &["GET"],
            format!("http://127.0.0.1:{upstream_port}/**"),
        )))
        .render();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let mut client = ProxyClient::connect(harness.addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/truncated HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    client.send(request.as_bytes()).await?;

    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "origin response head should have been forwarded: {response}"
    );
    assert_eq!(
        response.matches("HTTP/1.1 ").count(),
        1,
        "proxy appended a second response after the truncated body: {response}"
    );
    assert!(
        !response.contains("502 Bad Gateway"),
        "proxy appended a 502 to the truncated response: {response}"
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
                .https_mode("tunnel"),
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
                .https_mode("tunnel"),
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
    assert_eq!(response, CONNECT_ESTABLISHED_RESPONSE);

    sleep(StdDuration::from_secs(2)).await;

    let tail = read_tunnel_tail(&mut stream).await?;
    assert!(
        tail.is_empty(),
        "proxy injected bytes after CONNECT max lifetime: {}",
        String::from_utf8_lossy(&tail)
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;
    drop(upstream);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_splice_idle_timeout_closes_without_http_response() -> Result<()> {
    let log_capture = LogCapture::new("info").await;
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
                .https_mode("tunnel"),
            ),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(|settings| {
            settings.connect_tunnel_idle_timeout = 1;
            settings.connect_tunnel_max_lifetime = 0;
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
    assert_eq!(response, CONNECT_ESTABLISHED_RESPONSE);

    let tail = read_tunnel_tail(&mut stream).await?;
    assert!(
        tail.is_empty(),
        "proxy injected an HTTP response after CONNECT idle timeout: {}",
        String::from_utf8_lossy(&tail)
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;
    drop(upstream);

    let logs = log_capture.text();
    let error_log = logs
        .lines()
        .find(|line| line.contains("tunnel_relay_failed") && line.contains("decision="))
        .with_context(|| format!("missing committed tunnel error log: {logs}"))?;
    assert_eq!(log_field_value(error_log, "status").as_deref(), Some("200"));
    assert_eq!(
        log_field_value(error_log, "decision").as_deref(),
        Some("ERROR")
    );
    assert_eq!(
        log_field_value(error_log, "error_reason").as_deref(),
        Some("tunnel_relay_failed")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_splice_upstream_reset_does_not_append_http_response() -> Result<()> {
    const UPSTREAM_PAYLOAD: &[u8] = b"tunnel bytes before reset";

    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let (reset_tx, reset_rx) = oneshot::channel::<()>();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.context("accept failed")?;
        stream
            .write_all(UPSTREAM_PAYLOAD)
            .await
            .context("failed to write pre-reset tunnel payload")?;
        stream.flush().await?;
        reset_rx.await.context("reset signal sender dropped")?;
        stream.set_zero_linger()?;
        drop(stream);
        Ok::<(), anyhow::Error>(())
    });

    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["connect-splice"])
        .policy(
            PolicySpec::new("connect-splice").rule(
                RuleSpec::allow(
                    &["CONNECT"],
                    format!("https://127.0.0.1:{}/**", upstream_addr.port()),
                )
                .https_mode("tunnel"),
            ),
        )
        .render();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(|settings| settings.connect_tunnel_idle_timeout = 30)
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request = format!(
        "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: keep-alive\r\n\r\n",
        port = upstream_addr.port()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let response = read_until_double_crlf(&mut stream).await?;
    assert_eq!(response, CONNECT_ESTABLISHED_RESPONSE);
    let mut payload = vec![0u8; UPSTREAM_PAYLOAD.len()];
    stream.read_exact(&mut payload).await?;
    assert_eq!(payload, UPSTREAM_PAYLOAD);

    reset_tx
        .send(())
        .expect("upstream reset receiver available");
    upstream_task.await.context("upstream task join failed")??;
    let tail = read_tunnel_tail(&mut stream).await?;
    assert!(
        tail.is_empty(),
        "proxy injected an HTTP response after upstream reset: {}",
        String::from_utf8_lossy(&tail)
    );

    stream.shutdown().await.ok();
    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_loopback_upstream_relays_response() -> Result<()> {
    let upstream = TestUpstream::http_ok("hello").await?;
    let upstream_port = upstream.port();

    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-loopback"])
        .policy(PolicySpec::new("allow-loopback").rule(RuleSpec::allow(
            &["GET"],
            format!("http://127.0.0.1:{upstream_port}/**"),
        )))
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
async fn connect_inspect_deny_does_not_authorize_transport_preflight() -> Result<()> {
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["deny-only"])
        .policy(
            PolicySpec::new("deny-only").rule(
                RuleSpec::deny(&["ANY"], format!("https://*:{}/**", upstream_addr.port()))
                    .status(470)
                    .body("inner request denied"),
            ),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;
    let mut client = ProxyClient::connect(harness.addr).await?;
    let request = format!(
        "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n",
        port = upstream_addr.port()
    );
    client.send(request).await?;

    let response = client.read_headers().await?;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "deny-only inspect rule authorized CONNECT preflight: {response}"
    );
    assert!(
        timeout(StdDuration::from_millis(100), upstream_listener.accept())
            .await
            .is_err(),
        "deny-only inspect rule caused an upstream connection"
    );

    client.shutdown().await;
    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_equivalent_ipv6_spelling_hits_ordered_deny() -> Result<()> {
    let dirs = TestDirs::new()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["ipv6"])
        .policy(
            PolicySpec::new("ipv6")
                .rule(
                    RuleSpec::deny(&["CONNECT"], "https://[2001:0DB8:0:0:0:0:0:10]:443/**")
                        .https_mode("tunnel")
                        .status(451)
                        .body("IPv6 target denied"),
                )
                .rule(RuleSpec::allow(&["CONNECT"], "https://*/**").https_mode("tunnel")),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request = b"CONNECT [2001:db8::10]:443 HTTP/1.1\r\nHost: [2001:db8::10]:443\r\nConnection: close\r\n\r\n";
    stream.write_all(request).await?;
    stream.flush().await?;

    let response = read_http_response(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 451"),
        "equivalent IPv6 spelling bypassed ordered deny: {response}"
    );
    assert!(response.contains("IPv6 target denied"));

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
                    .https_mode("tunnel"),
            ),
        )
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_private_test_upstreams(false)
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
async fn connect_bumped_private_resolution_is_blocked() -> Result<()> {
    let dirs = TestDirs::new()?;
    let target_port = find_free_port()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["bump"])
        .policy(PolicySpec::new("bump").rule(RuleSpec::allow(
            &["GET"],
            format!("https://localhost:{target_port}/**"),
        )))
        .render();

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_private_test_upstreams(false)
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
async fn connect_splice_preserves_pipelined_payload() -> Result<()> {
    const CLIENT_PAYLOAD: &[u8] = b"client->upstream";
    const UPSTREAM_PAYLOAD: &[u8] = b"upstream->client";

    let dirs = TestDirs::new()?;
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-splice"])
        .policy(
            PolicySpec::new("allow-splice")
                .rule(RuleSpec::allow(&["CONNECT"], "https://localhost/**").https_mode("tunnel"))
                .bind_host_port("localhost", upstream_addr.port()),
        )
        .render();
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
    let mut pipelined = connect_request.into_bytes();
    pipelined.extend_from_slice(CLIENT_PAYLOAD);
    stream.write_all(&pipelined).await?;
    stream.flush().await?;

    let response = read_http_response(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected CONNECT establish response: {response}"
    );

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
        .with_private_test_upstreams(false)
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
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-http"])
        .policy(
            PolicySpec::new("allow-http")
                .rule(RuleSpec::allow_any(format!("http://{upstream_host}/**")))
                .bind_host_port(upstream_host, upstream_addr.port()),
        )
        .render();

    let accept_count = Arc::new(AtomicUsize::new(0));
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

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
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
async fn connection_close_cannot_be_overridden_or_pooled() -> Result<()> {
    let upstream_host = "localhost";
    let dirs = TestDirs::new()?;
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-http"])
        .policy(
            PolicySpec::new("allow-http")
                .rule(RuleSpec::allow_any(format!("http://{upstream_host}/**")))
                .bind_host_port(upstream_host, upstream_addr.port()),
        )
        .render();

    let accept_count = Arc::new(AtomicUsize::new(0));
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
                        if let Err(err) = serve_http_mixed_connection_headers(stream, peer).await {
                            tracing::warn!(error = %err, "mixed Connection upstream handler error");
                        }
                    });
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    for path in ["first", "second"] {
        let mut stream = TcpStream::connect(harness.addr).await?;
        let request = format!(
            "GET http://{host}:{port}/{path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: keep-alive\r\n\r\n",
            host = upstream_host,
            port = upstream_addr.port(),
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let response = read_http_response(&mut stream).await?;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "unexpected {path} response: {response}"
        );
        assert!(
            response.contains("Connection: close"),
            "mixed Connection fields did not force downstream close: {response}"
        );
        assert!(
            response.ends_with(path),
            "{path} response body missing path: {response}"
        );
        stream.shutdown().await.ok();
    }

    assert_eq!(
        accept_count.load(Ordering::SeqCst),
        2,
        "an upstream connection carrying Connection: close must not be pooled"
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
async fn http_keepalive_retries_stale_upstream_connection() -> Result<()> {
    let upstream_host = "localhost";
    let dirs = TestDirs::new()?;
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-http"])
        .policy(
            PolicySpec::new("allow-http")
                .rule(RuleSpec::allow_any(format!("http://{upstream_host}/**")))
                .bind_host_port(upstream_host, upstream_addr.port()),
        )
        .render();

    let accept_count = Arc::new(AtomicUsize::new(0));
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
                        if let Err(err) = serve_http_stale_keepalive(stream, peer).await {
                            tracing::warn!(error = %err, "stale keepalive upstream handler error");
                        }
                    });
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
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
        2,
        "expected the proxy to reconnect after a stale keep-alive upstream socket"
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
async fn http_keepalive_does_not_retry_ambiguous_empty_post() -> Result<()> {
    let upstream_host = "localhost";
    let dirs = TestDirs::new()?;
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;

    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow-http"])
        .policy(
            PolicySpec::new("allow-http")
                .rule(RuleSpec::allow_any(format!("http://{upstream_host}/**")))
                .bind_host_port(upstream_host, upstream_addr.port()),
        )
        .render();

    let accept_count = Arc::new(AtomicUsize::new(0));
    let action_count = Arc::new(AtomicUsize::new(0));
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let accept_counter = accept_count.clone();
    let action_counter = action_count.clone();
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
                    let action_counter = action_counter.clone();
                    tokio::spawn(async move {
                        if let Err(err) =
                            serve_http_ambiguous_empty_post(stream, peer, action_counter).await
                        {
                            tracing::warn!(
                                error = %err,
                                "ambiguous POST upstream handler error"
                            );
                        }
                    });
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let warm_request = format!(
        "GET http://{host}:{port}/warm HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: exfilguard-test\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    stream.write_all(warm_request.as_bytes()).await?;
    stream.flush().await?;
    let warm_response = read_http_response(&mut stream).await?;
    assert!(
        warm_response.starts_with("HTTP/1.1 200"),
        "unexpected warm-up response: {warm_response}"
    );

    let post_request = format!(
        "POST http://{host}:{port}/action HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: exfilguard-test\r\nContent-Length: 0\r\nProxy-Connection: close\r\nConnection: close\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    stream.write_all(post_request.as_bytes()).await?;
    stream.flush().await?;
    let post_response = read_http_response(&mut stream).await?;
    assert!(
        post_response.starts_with("HTTP/1.1 502"),
        "expected ambiguous upstream failure, got: {post_response}"
    );

    assert_eq!(
        action_count.load(Ordering::SeqCst),
        1,
        "the origin-side POST action must not be replayed"
    );
    assert_eq!(
        accept_count.load(Ordering::SeqCst),
        1,
        "a non-idempotent request must not be retried on a fresh connection"
    );

    stream.shutdown().await.ok();
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
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
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
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow_any(format!(
        "https://{upstream_host}/privacy-policy/"
    )));
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
async fn connect_bump_preserves_pipelined_client_hello() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-pipelined-client-hello";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .upstream_mode(UpstreamMode::Http1Redirect),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();

    let mut initial_client = fixture.take_tls_stream();
    initial_client.shutdown().await.ok();

    let client_hello = capture_tls_client_hello(upstream_host).await?;
    let mut stream = TcpStream::connect(fixture.proxy_addr()).await?;
    let connect_request = format!(
        "CONNECT {upstream_host}:{port} HTTP/1.1\r\nHost: {upstream_host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n",
        port = upstream_addr.port()
    );
    let mut pipelined = connect_request.into_bytes();
    pipelined.extend_from_slice(&client_hello);
    stream.write_all(&pipelined).await?;
    stream.flush().await?;

    let response = read_until_double_crlf(&mut stream).await?;
    assert_eq!(response, CONNECT_ESTABLISHED_RESPONSE);

    let mut server_record_header = [0u8; 5];
    timeout(
        StdDuration::from_secs(3),
        stream.read_exact(&mut server_record_header),
    )
    .await??;
    assert_eq!(
        server_record_header[0], 22,
        "proxy did not process the pipelined TLS ClientHello"
    );

    stream.shutdown().await.ok();
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_allows_large_streamed_upload_with_default_unlimited_body_size() -> Result<()>
{
    let upstream_host = "localhost";
    let policy_name = "allow-large-upload";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["PUT"],
        format!("https://{upstream_host}/upload/**"),
    ));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .upstream_mode(UpstreamMode::Http1Inspect),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.http1_client();

    let body_size = 64 * 1024 * 1024 + 1;
    let request = format!(
        "PUT /upload/layer HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: exfilguard-test\r\nContent-Length: {body_size}\r\nConnection: close\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    client.send(request.as_bytes()).await?;

    let chunk = vec![b'x'; 64 * 1024];
    let mut remaining = body_size;
    while remaining > 0 {
        let to_write = remaining.min(chunk.len());
        client.stream_mut().write_all(&chunk[..to_write]).await?;
        remaining -= to_write;
    }
    client.stream_mut().flush().await?;

    let response = timeout(
        StdDuration::from_secs(30),
        client.read_response_with_length(),
    )
    .await??;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected bumped response: {response}"
    );
    assert!(
        response.contains("path=/upload/layer"),
        "expected upstream path echo, got: {response}"
    );
    assert!(
        response.contains(&format!("content-length={body_size}")),
        "expected upstream content-length echo, got: {response}"
    );
    assert!(
        response.contains(&format!("body-len={body_size}")),
        "expected full upstream body length echo, got: {response}"
    );

    client.stream_mut().shutdown().await.ok();
    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_rejects_invalid_host_ports() -> Result<()> {
    for port in ["wat", "65536", "+443", ""] {
        let policy =
            PolicySpec::new("invalid-port").rule(RuleSpec::allow_any("https://localhost/**"));
        let mut fixture =
            BumpedTlsFixture::new(BumpedTlsOptions::new("localhost", "invalid-port", policy))
                .await?;
        let mut client = fixture.http1_client();
        client
            .send(format!(
                "GET / HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n"
            ))
            .await?;
        let response = client.read_response().await?;
        assert!(response.starts_with("HTTP/1.1 400"), "{port}: {response}");
        assert_eq!(fixture.request_count(), 0);
        fixture.shutdown().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_rejects_absolute_form_targets() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-bump";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
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
async fn connect_bump_uses_canonical_policy_path_and_forwards_raw_target() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-canonical-path";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow_any(format!(
        "https://{upstream_host}/canonical/**"
    )));
    let mut fixture =
        BumpedTlsFixture::new(BumpedTlsOptions::new(upstream_host, policy_name, policy)).await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.http1_client();
    let request = format!(
        "GET /alias/../c%61nonical/report?sig=abc HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    client.send(request.as_bytes()).await?;

    let response = client.read_response_with_length().await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected bumped response: {response}"
    );
    assert!(
        response.contains("/alias/../c%61nonical/report?sig=abc"),
        "expected upstream to see raw request target, got: {response}"
    );

    client.stream_mut().shutdown().await.ok();
    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http1_accepts_npm_encoded_slash_without_rewriting_target() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-npm-scoped-package";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["GET"],
        format!("https://{upstream_host}/@scope%2Fpackage"),
    ));
    let mut fixture =
        BumpedTlsFixture::new(BumpedTlsOptions::new(upstream_host, policy_name, policy)).await?;
    let upstream_addr = fixture.upstream_addr();
    let authority = format!("{upstream_host}:{}", upstream_addr.port());
    let mut client = fixture.http1_client();

    let encoded_request =
        format!("GET /@scope%2fpackage?write=true HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    client.send(encoded_request).await?;
    let encoded_response = client.read_response_with_length().await?;
    assert!(
        encoded_response.starts_with("HTTP/1.1 200"),
        "lowercase encoded slash did not match the canonical policy pattern: {encoded_response}"
    );
    let (_, encoded_body) = encoded_response
        .split_once("\r\n\r\n")
        .context("encoded-slash response missing head terminator")?;
    assert_eq!(
        encoded_body, "/@scope%2fpackage?write=true",
        "upstream did not receive the original npm request target"
    );

    let literal_request = format!(
        "GET /@scope/package?write=true HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    );
    client.send(literal_request).await?;
    let literal_response = client.read_response_with_length().await?;
    assert!(
        literal_response.starts_with("HTTP/1.1 403"),
        "literal slash unexpectedly matched the encoded-slash rule: {literal_response}"
    );

    client.stream_mut().shutdown().await.ok();
    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http1_encoded_unreserved_hits_ordered_deny() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "deny-canonical-admin";
    let policy = PolicySpec::new(policy_name)
        .rule(
            RuleSpec::deny(&["GET"], format!("https://{upstream_host}/admin/**"))
                .status(451)
                .body("canonical path denied"),
        )
        .rule(RuleSpec::allow(
            &["GET"],
            format!("https://{upstream_host}/**"),
        ));
    let mut fixture =
        BumpedTlsFixture::new(BumpedTlsOptions::new(upstream_host, policy_name, policy)).await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.http1_client();
    let request = format!(
        "GET /%61dmin/export HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    client.send(request.as_bytes()).await?;

    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 451"),
        "encoded admin path bypassed ordered deny: {response}"
    );
    assert!(
        response.contains("canonical path denied"),
        "unexpected deny response: {response}"
    );

    client.stream_mut().shutdown().await.ok();
    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_blocks_dot_segment_policy_bypass() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-prefix-only";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow_any(format!(
        "https://{upstream_host}/alias/**"
    )));
    let mut fixture =
        BumpedTlsFixture::new(BumpedTlsOptions::new(upstream_host, policy_name, policy)).await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.http1_client();
    let request = format!(
        "GET /alias/../secret HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port()
    );
    client.send(request.as_bytes()).await?;

    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "unexpected bumped response: {response}"
    );
    assert!(
        response.contains("request blocked by policy"),
        "expected policy denial body, got: {response}"
    );

    client.stream_mut().shutdown().await.ok();
    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_prefers_http1_when_upstream_http1_only() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-http1-only";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
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
async fn connect_bump_rejects_h2_only_client_when_upstream_http1_only() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-http1-only";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http1)
            .upstream_mode(UpstreamMode::Http1Keepalive),
    )
    .await?;

    let _handshake_error = fixture
        .reconnect(ClientProtocols::Http2Only)
        .await
        .expect_err("H2-only client must not negotiate against an HTTP/1-only path");

    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http1_closes_unused_http2_probe() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "close-unused-h2-probe";
    let policy = PolicySpec::new(policy_name)
        .rule(
            RuleSpec::deny(
                &["GET"],
                format!("https://{upstream_host}/downstream-still-open"),
            )
            .status(451)
            .body("downstream session remained open"),
        )
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http1)
            .upstream_mode(UpstreamMode::Http2),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();

    fixture
        .wait_for_upstream_close(StdDuration::from_secs(2))
        .await?;

    let mut client = fixture.http1_client();
    assert_eq!(
        client.stream().get_ref().1.alpn_protocol(),
        Some(&b"http/1.1"[..])
    );
    let request = format!(
        "GET /downstream-still-open HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n",
        host = upstream_host,
        port = upstream_addr.port(),
    );
    client.send(request).await?;
    let response = client.read_response().await?;
    assert!(response.starts_with("HTTP/1.1 451"), "{response}");
    assert!(
        response.contains("downstream session remained open"),
        "{response}"
    );
    client.stream_mut().shutdown().await.ok();

    assert_eq!(
        fixture.accept_count(),
        1,
        "the denied request must not open another origin connection"
    );
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_supports_http2() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
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
async fn connect_bump_http2_client_reset_preserves_other_streams() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2-client-reset";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2StreamIsolation),
    )
    .await?;
    let authority = format!("{}:{}", upstream_host, fixture.upstream_addr().port());
    let mut client = fixture.h2_client().await?;

    let (cancelled_response, mut cancelled_body) = client.start_request_with_open_body(
        bumped_h2_request(&authority, Method::PUT, "/client-reset")?,
    )?;
    wait_for_bumped_upstream_requests(&fixture, 1).await?;

    let survivor_response =
        client.start_request(bumped_h2_request(&authority, Method::GET, "/survivor")?)?;
    wait_for_bumped_upstream_requests(&fixture, 2).await?;

    cancelled_body.send_reset(h2::Reason::CANCEL);
    let reset_error = timeout(StdDuration::from_secs(2), cancelled_response)
        .await
        .context("timed out waiting for cancelled downstream HTTP/2 stream")?
        .expect_err("cancelled downstream HTTP/2 stream returned a response");
    assert!(reset_error.is_reset());

    let release_response = client.start_request(bumped_h2_request(
        &authority,
        Method::GET,
        "/release-after-client-reset",
    )?)?;
    let release_response = timeout(StdDuration::from_secs(2), release_response)
        .await
        .context("timed out waiting for release HTTP/2 response")??;
    assert_eq!(release_response.status(), StatusCode::OK);
    assert_eq!(
        BumpedH2Client::read_body(release_response.into_body()).await?,
        "/release-after-client-reset"
    );

    let survivor_response = timeout(StdDuration::from_secs(2), survivor_response)
        .await
        .context("timed out waiting for surviving HTTP/2 stream")??;
    assert_eq!(survivor_response.status(), StatusCode::OK);
    assert_eq!(
        BumpedH2Client::read_body(survivor_response.into_body()).await?,
        "/survivor"
    );
    assert_eq!(fixture.accept_count(), 1);

    client.shutdown().await;
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_origin_reset_preserves_other_streams() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2-origin-reset";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2StreamIsolation),
    )
    .await?;
    let authority = format!("{}:{}", upstream_host, fixture.upstream_addr().port());
    let mut client = fixture.h2_client().await?;

    let survivor_response =
        client.start_request(bumped_h2_request(&authority, Method::GET, "/survivor")?)?;
    wait_for_bumped_upstream_requests(&fixture, 1).await?;

    let reset_response =
        client.start_request(bumped_h2_request(&authority, Method::GET, "/origin-reset")?)?;
    let reset_error = timeout(StdDuration::from_secs(2), reset_response)
        .await
        .context("timed out waiting for origin HTTP/2 stream reset")?
        .expect_err("origin-reset HTTP/2 stream returned a response");
    assert!(reset_error.is_reset());

    let release_response =
        client.start_request(bumped_h2_request(&authority, Method::GET, "/release")?)?;
    let release_response = timeout(StdDuration::from_secs(2), release_response)
        .await
        .context("timed out waiting for release HTTP/2 response")??;
    assert_eq!(release_response.status(), StatusCode::OK);
    assert_eq!(
        BumpedH2Client::read_body(release_response.into_body()).await?,
        "/release"
    );

    let survivor_response = timeout(StdDuration::from_secs(2), survivor_response)
        .await
        .context("timed out waiting for surviving HTTP/2 stream")??;
    assert_eq!(survivor_response.status(), StatusCode::OK);
    assert_eq!(
        BumpedH2Client::read_body(survivor_response.into_body()).await?,
        "/survivor"
    );
    assert_eq!(fixture.accept_count(), 1);

    client.shutdown().await;
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_cache_miss_then_hit() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "cache-h2";
    let policy = PolicySpec::new(policy_name).rule(
        RuleSpec::allow(&["GET"], format!("https://{upstream_host}/**")).cache_force_duration(60),
    );
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2CacheInspect)
            .with_cache(),
    )
    .await?;
    let authority = format!("{}:{}", upstream_host, fixture.upstream_addr().port());
    let mut client = fixture.h2_client().await?;

    let uri = Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query("/h2/cached")
        .build()?;
    let first = http::Request::builder()
        .method(Method::GET)
        .uri(uri.clone())
        .body(())?;
    let (first_status, first_body) = client.request_text(first).await?;
    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(first_body, "request=1\npath=/h2/cached\nbody=");

    sleep(StdDuration::from_millis(50)).await;
    let second = http::Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(())?;
    let (second_status, second_body) = client.request_text(second).await?;
    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(second_body, first_body);
    assert_eq!(
        fixture.request_count(),
        1,
        "the second request should be served without an upstream HTTP/2 stream"
    );

    client.shutdown().await;
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bumped_cache_reuses_http1_chunk_payload_for_http2() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "cache-cross-protocol-h1-h2";
    let policy = PolicySpec::new(policy_name).rule(
        RuleSpec::allow(&["GET"], format!("https://{upstream_host}/**")).cache_force_duration(60),
    );
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http1)
            .upstream_mode(UpstreamMode::DualProtocolCacheInspect)
            .with_cache(),
    )
    .await?;
    let authority = format!("{}:{}", upstream_host, fixture.upstream_addr().port());
    let expected_body = "request=1\npath=/cross/h1-to-h2\nprotocol=http/1.1";

    {
        let mut client = fixture.http1_client();
        let request = format!(
            "GET /cross/h1-to-h2 HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        );
        client.send(request).await?;
        let response = client.read_response().await?;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(
            response
                .to_ascii_lowercase()
                .contains("transfer-encoding: chunked"),
            "origin response was not relayed with chunk framing: {response}"
        );
    }
    assert_eq!(fixture.request_count(), 1);

    sleep(StdDuration::from_millis(50)).await;
    fixture.reconnect(ClientProtocols::Http2Preferred).await?;
    let mut client = fixture.h2_client().await?;
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/cross/h1-to-h2")
                .build()?,
        )
        .body(())?;
    let (status, body) = client.request_text(request).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body, expected_body,
        "cached body retained HTTP/1 chunk framing"
    );
    assert_eq!(
        fixture.request_count(),
        1,
        "HTTP/2 request should reuse the HTTP/1-populated cache entry"
    );

    client.shutdown().await;
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bumped_cache_reuses_http2_payload_for_fixed_http1_response() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "cache-cross-protocol-h2-h1";
    let policy = PolicySpec::new(policy_name).rule(
        RuleSpec::allow(&["GET"], format!("https://{upstream_host}/**")).cache_force_duration(60),
    );
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::DualProtocolCacheInspect)
            .with_cache(),
    )
    .await?;
    let authority = format!("{}:{}", upstream_host, fixture.upstream_addr().port());
    let expected_body = "request=1\npath=/cross/h2-to-h1\nprotocol=h2";
    let uri = Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query("/cross/h2-to-h1")
        .build()?;

    let mut h2_client = fixture.h2_client().await?;
    let first = http::Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(())?;
    let (status, body) = h2_client.request_text(first).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, expected_body);
    assert_eq!(fixture.request_count(), 1);
    h2_client.shutdown().await;

    sleep(StdDuration::from_millis(50)).await;
    fixture.reconnect(ClientProtocols::Http1).await?;
    let mut client = fixture.http1_client();
    let request =
        format!("GET /cross/h2-to-h1 HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    client.send(request).await?;
    let response = client.read_response_with_length().await?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .context("cached HTTP/1 response missing head terminator")?;
    assert!(head.starts_with("HTTP/1.1 200"));
    assert!(
        !head.to_ascii_lowercase().contains("transfer-encoding"),
        "cached H2 payload should use fixed HTTP/1 framing: {head}"
    );
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("content-length: {}", expected_body.len())),
        "cached HTTP/1 response has wrong content length: {head}"
    );
    assert_eq!(body, expected_body);
    assert_eq!(
        fixture.request_count(),
        1,
        "HTTP/1 request should reuse the HTTP/2-populated cache entry"
    );

    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_body_requests_bypass_cache() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "cache-h2-bodyless-only";
    let policy = PolicySpec::new(policy_name).rule(
        RuleSpec::allow(&["GET"], format!("https://{upstream_host}/**")).cache_force_duration(60),
    );
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2CacheInspect)
            .with_cache(),
    )
    .await?;
    let authority = format!("{}:{}", upstream_host, fixture.upstream_addr().port());
    let uri = Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query("/h2/body")
        .build()?;
    let mut client = fixture.h2_client().await?;

    for (sequence, body) in [(1, "first"), (2, "second")] {
        let request = http::Request::builder()
            .method(Method::GET)
            .uri(uri.clone())
            .header(http::header::CONTENT_LENGTH, body.len())
            .body(())?;
        let (status, response_body) = client
            .request_text_with_body(request, Bytes::copy_from_slice(body.as_bytes()))
            .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response_body,
            format!("request={sequence}\npath=/h2/body\nbody={body}")
        );
    }

    let first_bodyless = http::Request::builder()
        .method(Method::GET)
        .uri(uri.clone())
        .body(())?;
    let (status, cached_body) = client.request_text(first_bodyless).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cached_body, "request=3\npath=/h2/body\nbody=");

    sleep(StdDuration::from_millis(50)).await;
    let second_bodyless = http::Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(())?;
    let (status, second_bodyless_body) = client.request_text(second_bodyless).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second_bodyless_body, cached_body);
    assert_eq!(
        fixture.request_count(),
        3,
        "body-bearing requests should bypass lookup and storage"
    );

    client.shutdown().await;
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_forwards_early_response_while_upload_is_active() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2-full-duplex";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["GET", "PUT"],
        format!("https://{upstream_host}/**"),
    ));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2EarlyResponse)
            .with_settings(|settings| {
                settings.request_body_idle_timeout = 1;
                settings.response_header_timeout = 2;
            }),
    )
    .await?;
    let authority = format!("{}:{}", upstream_host, fixture.upstream_addr().port());
    let mut client = fixture.h2_client().await?;

    let duplex_body = Bytes::from(vec![b'd'; 256 * 1024]);
    let duplex_request = http::Request::builder()
        .method(Method::PUT)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/duplex")
                .build()?,
        )
        .header(http::header::CONTENT_LENGTH, duplex_body.len())
        .body(())?;
    let (status, response_body) = timeout(
        StdDuration::from_secs(3),
        client.request_text_with_body(duplex_request, duplex_body.clone()),
    )
    .await
    .context("duplex HTTP/2 exchange timed out")?
    .context("duplex HTTP/2 exchange failed")?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response_body, format!("received={}", duplex_body.len()));

    let rejected_body = Bytes::from(vec![b'r'; 512 * 1024]);
    let rejected_request = http::Request::builder()
        .method(Method::PUT)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/early")
                .build()?,
        )
        .header(http::header::CONTENT_LENGTH, rejected_body.len())
        .body(())?;
    let (status, response_body) = timeout(
        StdDuration::from_secs(3),
        client.request_text_with_body(rejected_request, rejected_body),
    )
    .await
    .context("early HTTP/2 response timed out")?
    .context("early HTTP/2 response failed")?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response_body, "rejected");

    let after_request = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/after")
                .build()?,
        )
        .body(())?;
    let (status, response_body) = timeout(
        StdDuration::from_secs(3),
        client.request_text(after_request),
    )
    .await
    .context("follow-up HTTP/2 request timed out")?
    .context("follow-up HTTP/2 request failed")?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response_body, "/after");
    assert_eq!(fixture.accept_count(), 1, "upstream H2 connection was lost");

    let truncated_request = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/truncated")
                .build()?,
        )
        .body(())?;
    let truncated = timeout(
        StdDuration::from_secs(3),
        client.request_text(truncated_request),
    )
    .await
    .context("truncated HTTP/2 response timed out")?;
    assert!(
        truncated.is_err(),
        "NO_ERROR reset completed an ordinary truncated response"
    );

    client.shutdown().await;
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_rejects_declared_oversize_before_upstream_stream() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "limit-h2-declared-body";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["GET", "PUT"],
        format!("https://{upstream_host}/**"),
    ));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2CacheInspect)
            .with_settings(|settings| {
                settings.max_request_body_size = 1024;
                settings.request_body_idle_timeout = 5;
            }),
    )
    .await?;
    let authority = format!("{}:{}", upstream_host, fixture.upstream_addr().port());
    let mut client = fixture.h2_client().await?;

    let oversized_request = http::Request::builder()
        .method(Method::PUT)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/oversized")
                .build()?,
        )
        .header(http::header::CONTENT_LENGTH, 1025)
        .body(())?;
    let (response, upload) = client.start_request_with_open_body(oversized_request)?;
    let response = timeout(StdDuration::from_secs(1), response)
        .await
        .context("declared-oversize request was not rejected promptly")??;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        fixture.request_count(),
        0,
        "origin observed a stream for a known-oversize request"
    );
    drop(response);
    drop(upload);

    let follow_up = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/after-oversize")
                .build()?,
        )
        .body(())?;
    let (status, body) = timeout(StdDuration::from_secs(3), client.request_text(follow_up))
        .await
        .context("follow-up request timed out")??;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "request=1\npath=/after-oversize\nbody=");
    assert_eq!(fixture.request_count(), 1);
    assert_eq!(fixture.accept_count(), 1);

    client.shutdown().await;
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_invalid_request_path_returns_400() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2-invalid";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.h2_client().await?;

    let authority = format!("{}:{}", upstream_host, upstream_addr.port());
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/safe/%2e%2e/blocked")
                .build()?,
        )
        .body(())?;
    let (status, text) = client.request_text(request).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(text, "invalid request");

    client.shutdown().await;
    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_encoded_unreserved_hits_ordered_deny() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "deny-h2-canonical-admin";
    let policy = PolicySpec::new(policy_name)
        .rule(
            RuleSpec::deny(&["GET"], format!("https://{upstream_host}/admin/**"))
                .status(451)
                .body("canonical path denied"),
        )
        .rule(RuleSpec::allow(
            &["GET"],
            format!("https://{upstream_host}/**"),
        ));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.h2_client().await?;

    let authority = format!("{}:{}", upstream_host, upstream_addr.port());
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/%61dmin/export")
                .build()?,
        )
        .body(())?;
    let (status, text) = client.request_text(request).await?;
    assert_eq!(status, StatusCode::from_u16(451)?);
    assert_eq!(text, "canonical path denied");

    client.shutdown().await;
    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_accepts_npm_encoded_slash_as_distinct_path_data() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2-npm-scoped-package";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["GET"],
        format!("https://{upstream_host}/@scope%2Fpackage"),
    ));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2),
    )
    .await?;
    let authority = format!("{}:{}", upstream_host, fixture.upstream_addr().port());
    let mut client = fixture.h2_client().await?;

    let encoded_request = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/@scope%2fpackage")
                .build()?,
        )
        .body(())?;
    let (encoded_status, encoded_body) = client.request_text(encoded_request).await?;
    assert_eq!(encoded_status, StatusCode::OK);
    assert_eq!(
        encoded_body, "/@scope%2fpackage",
        "HTTP/2 upstream did not receive the original encoded path"
    );

    let literal_request = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/@scope/package")
                .build()?,
        )
        .body(())?;
    let (literal_status, literal_body) = client.request_text(literal_request).await?;
    assert_eq!(literal_status, StatusCode::FORBIDDEN);
    assert_eq!(literal_body, "request blocked by policy");

    client.shutdown().await;
    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_closes_request_idle_session() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2-idle";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2)
            .with_settings(|settings| settings.client_keepalive_idle_timeout = 1),
    )
    .await?;
    let mut client = fixture.h2_client().await?;

    client.wait_closed(StdDuration::from_secs(2)).await?;
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_closes_incomplete_request_headers_when_idle() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2-incomplete";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2)
            .with_settings(|settings| settings.client_keepalive_idle_timeout = 1),
    )
    .await?;
    let mut stream = fixture.take_tls_stream();

    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await?;
    stream.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await?;
    stream.write_all(&[0, 0, 1, 1, 0, 0, 0, 0, 1, 0x82]).await?;
    stream.flush().await?;

    timeout(StdDuration::from_secs(2), async {
        let mut buffer = [0_u8; 1024];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => return Ok::<(), std::io::Error>(()),
                Ok(_) => {}
                Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(()),
                Err(err) => return Err(err),
            }
        }
    })
    .await
    .context("incomplete HTTP/2 headers were not closed by idle timeout")??;

    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_does_not_apply_connection_idle_timeout_to_active_stream() -> Result<()>
{
    let upstream_host = "localhost";
    let policy_name = "allow-h2-active";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2NoResponse)
            .with_settings(|settings| {
                settings.client_keepalive_idle_timeout = 1;
                settings.response_header_timeout = 3;
            }),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.h2_client().await?;
    let authority = format!("{}:{}", upstream_host, upstream_addr.port());
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/h2/active")
                .build()?,
        )
        .body(())?;
    let response = client.start_request(request)?;

    sleep(StdDuration::from_millis(1_500)).await;
    assert!(
        !client.is_closed(),
        "active HTTP/2 stream was closed by connection-idle timeout"
    );

    drop(response);
    client.shutdown().await;
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_closes_downstream_after_upstream_close() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2-reconnect";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2SingleUse),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.h2_client().await?;

    let authority = format!("{}:{}", upstream_host, upstream_addr.port());

    let first_request = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/h2/first")
                .build()?,
        )
        .body(())?;
    let (first_status, first_text) = client.request_text(first_request).await?;
    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(first_text, "/h2/first");

    client.wait_closed(StdDuration::from_secs(1)).await?;

    client.shutdown().await;

    assert_eq!(
        fixture.accept_count(),
        1,
        "expected downstream HTTP/2 session to close after upstream close"
    );

    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_disconnects_when_upstream_closes_before_response() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2-close-before-response";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2CloseBeforeResponse),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.h2_client().await?;

    let authority = format!("{}:{}", upstream_host, upstream_addr.port());
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/h2/broken")
                .build()?,
        )
        .body(())?;

    let _ = client
        .request_text(request)
        .await
        .expect_err("expected downstream disconnect after upstream closed before response");
    client.wait_closed(StdDuration::from_secs(1)).await?;
    client.shutdown().await;

    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_response_header_timeout_preserves_session() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2-timeout";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2NoResponse)
            .with_settings(|settings| {
                settings.response_header_timeout = 1;
            }),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.h2_client().await?;

    let authority = format!("{}:{}", upstream_host, upstream_addr.port());
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/h2/timeout")
                .build()?,
        )
        .body(())?;

    let (status, body) = timeout(StdDuration::from_secs(2), client.request_text(request)).await??;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(body, "request timed out");

    let follow_up = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/h2/after-timeout")
                .build()?,
        )
        .body(())?;
    let (status, body) =
        timeout(StdDuration::from_secs(2), client.request_text(follow_up)).await??;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "/h2/after-timeout");
    assert_eq!(
        fixture.accept_count(),
        1,
        "upstream H2 session was replaced"
    );

    client.shutdown().await;

    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_total_timeout_returns_504_before_response() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2-total-timeout-head";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2NoResponse)
            .with_settings(|settings| {
                settings.request_total_timeout = 2;
                settings.response_header_timeout = 10;
            }),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.h2_client().await?;

    let authority = format!("{}:{}", upstream_host, upstream_addr.port());
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/h2/total-timeout")
                .build()?,
        )
        .body(())?;

    let (status, body) = timeout(StdDuration::from_secs(3), client.request_text(request)).await??;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(body, "request timed out");

    client.shutdown().await;
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_total_timeout_applies_to_response_body() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2-total-timeout-body";
    let policy = PolicySpec::new(policy_name)
        .rule(RuleSpec::allow_any(format!("https://{upstream_host}/**")));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2HeadersThenStallBody)
            .with_settings(|settings| {
                settings.request_total_timeout = 2;
                settings.response_body_idle_timeout = 10;
            }),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.h2_client().await?;

    let authority = format!("{}:{}", upstream_host, upstream_addr.port());
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query("/h2/slow-body")
                .build()?,
        )
        .body(())?;

    let response = timeout(StdDuration::from_secs(2), client.request(request)).await??;
    assert_eq!(response.status(), StatusCode::OK);

    let result = timeout(
        StdDuration::from_secs(3),
        BumpedH2Client::read_body(response.into_body()),
    )
    .await;
    match result {
        Ok(Err(_)) => {}
        Ok(Ok(body)) => {
            panic!("expected HTTP/2 body relay to fail on total timeout, got {body:?}");
        }
        Err(_) => panic!("HTTP/2 response body relay ignored request_total_timeout"),
    }

    client.shutdown().await;
    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_cache_timeout_resets_only_affected_stream() -> Result<()> {
    const BODY_SIZE: usize = 16 * 1024 * 1024;

    let upstream_host = "localhost";
    let policy_name = "allow-h2-cache-timeout";
    let policy = PolicySpec::new(policy_name).rule(
        RuleSpec::allow(&["GET"], format!("https://{upstream_host}/**")).cache_force_duration(60),
    );
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2CacheInspect)
            .with_cache()
            .with_settings(|settings| {
                settings.request_total_timeout = 2;
                settings.response_body_idle_timeout = 10;
                settings.cache_max_entry_size = 20 * 1024 * 1024;
            }),
    )
    .await?;
    let authority = format!("{}:{}", upstream_host, fixture.upstream_addr().port());
    let large_uri = Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query("/h2/large-cache-hit")
        .build()?;
    fixture
        .cache()
        .store(
            &Method::GET,
            &large_uri,
            &http::HeaderMap::new(),
            StatusCode::OK,
            &http::HeaderMap::new(),
            &vec![b'x'; BODY_SIZE],
            StdDuration::from_secs(60),
        )
        .await?;

    let mut client = fixture.h2_client().await?;
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(large_uri)
        .body(())?;
    let response = timeout(StdDuration::from_secs(2), client.request(request)).await??;
    assert_eq!(response.status(), StatusCode::OK);

    sleep(StdDuration::from_secs(3)).await;
    let body_result = timeout(
        StdDuration::from_secs(2),
        BumpedH2Client::read_body(response.into_body()),
    )
    .await?;
    assert!(
        body_result.is_err(),
        "timed-out cache stream completed successfully"
    );

    let after_uri = Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query("/h2/after-cache-timeout")
        .build()?;
    let after = http::Request::builder()
        .method(Method::GET)
        .uri(after_uri)
        .body(())?;
    let (status, body) = timeout(StdDuration::from_secs(3), client.request_text(after)).await??;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "request=1\npath=/h2/after-cache-timeout\nbody=");
    assert_eq!(fixture.request_count(), 1);

    client.shutdown().await;
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_preserves_content_length_for_body_requests() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "allow-h2-put";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["PUT"],
        format!("https://{upstream_host}/upload/**"),
    ));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2Inspect),
    )
    .await?;
    let upstream_addr = fixture.upstream_addr();
    let mut client = fixture.h2_client().await?;

    let authority = format!("{}:{}", upstream_host, upstream_addr.port());
    let body = Bytes::from_static(b"hello world");
    let content_length = body.len();
    let uri = Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query("/upload/object")
        .build()?;
    let mut builder = http::Request::builder().method(Method::PUT).uri(uri);
    let headers = builder.headers_mut().expect("headers before body");
    headers.insert(
        http::header::USER_AGENT,
        HeaderValue::from_static("exfilguard-test"),
    );
    headers.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&content_length.to_string())?,
    );
    let request = builder.body(())?;

    let (status, response_body) = client.request_text_with_body(request, body.clone()).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response_body.contains(&format!("content-length={content_length}")),
        "expected upstream content-length echo, got: {response_body}"
    );
    assert!(
        response_body.contains(&format!("body-len={content_length}")),
        "expected upstream body length echo, got: {response_body}"
    );
    assert!(
        response_body.contains("body=hello world"),
        "expected upstream body echo, got: {response_body}"
    );

    client.shutdown().await;
    fixture.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_policy_denied() -> Result<()> {
    let upstream_host = "localhost";
    let policy_name = "h2-policy";
    let policy = PolicySpec::new(policy_name)
        .rule(
            RuleSpec::deny(&["GET"], format!("https://{upstream_host}/blocked/**"))
                .status(451)
                .reason("Policy Blocked")
                .body("blocked by policy"),
        )
        .rule(RuleSpec::allow(
            &["GET"],
            format!("https://{upstream_host}/allowed/**"),
        ));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new(upstream_host, policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
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

    let clients = std::fs::read_to_string("tests/data/clients/ipv6.toml")?;
    let policies = std::fs::read_to_string("tests/data/policies/ipv6.toml")?;

    let harness = ProxyHarnessBuilder::with_dirs(dirs, clients.as_str(), policies.as_str())
        .with_private_test_upstreams(false)
        .with_settings(move |settings| {
            let port = settings.listen.port();
            settings.listen = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
            settings.log_queries = true;
        })
        .spawn()
        .await?;

    let mut stream = TcpStream::connect(harness.addr).await?;
    let request = b"GET http://[0:0:0:0:0:0:0:1]/secret HTTP/1.1\r\nHost: [0:0:0:0:0:0:0:1]\r\nConnection: close\r\n\r\n";
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

async fn serve_http_mixed_connection_headers(
    mut stream: TcpStream,
    _peer: SocketAddr,
) -> Result<()> {
    loop {
        let request_bytes = read_request(&mut stream).await?;
        if request_bytes.is_empty() {
            break;
        }
        let request = String::from_utf8(request_bytes)?;
        let body = request_path(&request);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .await
            .context("failed to write mixed Connection response")?;
        stream
            .flush()
            .await
            .context("failed to flush mixed Connection response")?;
    }
    stream
        .shutdown()
        .await
        .context("failed to shutdown mixed Connection upstream stream")?;
    Ok(())
}

async fn serve_http_stale_keepalive(mut stream: TcpStream, _peer: SocketAddr) -> Result<()> {
    let request_bytes = read_request(&mut stream).await?;
    if request_bytes.is_empty() {
        stream
            .shutdown()
            .await
            .context("failed to shutdown empty stale keepalive stream")?;
        return Ok(());
    }

    let request = String::from_utf8(request_bytes)?;
    let path = request_path(&request);
    let body = path.to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("failed to write stale keepalive HTTP response")?;
    stream
        .flush()
        .await
        .context("failed to flush stale keepalive HTTP response")?;
    stream
        .shutdown()
        .await
        .context("failed to shutdown stale keepalive upstream stream")?;
    Ok(())
}

async fn serve_http_ambiguous_empty_post(
    mut stream: TcpStream,
    _peer: SocketAddr,
    action_count: Arc<AtomicUsize>,
) -> Result<()> {
    loop {
        let request_bytes = read_request(&mut stream).await?;
        if request_bytes.is_empty() {
            break;
        }

        let request = String::from_utf8(request_bytes)?;
        if request.starts_with("POST ") && request_path(&request) == "/action" {
            action_count.fetch_add(1, Ordering::SeqCst);
            stream
                .shutdown()
                .await
                .context("failed to close after processing ambiguous POST")?;
            return Ok(());
        }

        let body = request_path(&request).to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .await
            .context("failed to write ambiguous POST warm-up response")?;
        stream
            .flush()
            .await
            .context("failed to flush ambiguous POST warm-up response")?;
    }

    stream
        .shutdown()
        .await
        .context("failed to shutdown ambiguous POST upstream stream")?;
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
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_rejects_truncated_response_during_upload() -> Result<()> {
    let policy_name = "review-truncated-upload";
    let policy =
        PolicySpec::new(policy_name).rule(RuleSpec::allow(&["PUT"], "https://localhost/**"));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new("localhost", policy_name, policy)
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2EarlyResponse)
            .with_settings(|settings| {
                settings.request_body_idle_timeout = 5;
                settings.response_header_timeout = 2;
            }),
    )
    .await?;
    let authority = format!("localhost:{}", fixture.upstream_addr().port());
    let mut client = fixture.h2_client().await?;
    let request = http::Request::builder()
        .method(Method::PUT)
        .uri(format!("https://{authority}/truncated"))
        .body(())?;
    // Retain the upload handle without sending END_STREAM, guaranteeing the
    // upstream response arrives while the request upload remains active.
    let (response, upload) = client.start_request_with_open_body(request)?;
    let outcome = timeout(StdDuration::from_secs(3), async {
        let response = response.await.context("response head")?;
        let status = response.status();
        let body = BumpedH2Client::read_body(response.into_body()).await?;
        Ok::<_, anyhow::Error>((status, body))
    })
    .await
    .context("waiting for truncated response")?;
    drop(upload);
    client.shutdown().await;
    fixture.shutdown().await;
    assert!(
        outcome.is_err(),
        "Origin sent RST_STREAM(NO_ERROR) without END_STREAM, but proxy completed response: {outcome:?}"
    );
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_bump_http2_bounds_unacknowledged_graceful_shutdown() -> Result<()> {
    let policy =
        PolicySpec::new("review-close").rule(RuleSpec::allow(&["GET"], "https://localhost/**"));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new("localhost", "review-close", policy)
            .client_protocols(ClientProtocols::Http2Only)
            .upstream_mode(UpstreamMode::Http2SingleUse)
            .with_settings(|settings| settings.client_keepalive_idle_timeout = 1),
    )
    .await?;
    let authority = format!("localhost:{}", fixture.upstream_addr().port());
    let mut tls = fixture.take_tls_stream();
    // A minimal ordinary GET, using HPACK static entries and a literal authority.
    let mut headers = vec![0x82, 0x87, 0x84, 0x01, authority.len() as u8];
    headers.extend_from_slice(authority.as_bytes());
    tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await?;
    tls.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await?;
    tls.write_all(&[0, 0, headers.len() as u8, 1, 5, 0, 0, 0, 1])
        .await?;
    tls.write_all(&headers).await?;
    tls.flush().await?;
    let mut saw_shutdown_ping = false;
    let mut saw_goaway = false;
    let outcome = tokio::time::timeout(StdDuration::from_secs(3), async {
        loop {
            let mut frame = [0u8; 9];
            if let Err(err) = tls.read_exact(&mut frame).await {
                return err;
            }
            let len = (usize::from(frame[0]) << 16)
                | (usize::from(frame[1]) << 8)
                | usize::from(frame[2]);
            let mut payload = vec![0; len];
            if let Err(err) = tls.read_exact(&mut payload).await {
                return err;
            }
            if frame[3] == 4 && frame[4] & 1 == 0 {
                tls.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await.unwrap();
                tls.flush().await.unwrap();
            }
            saw_shutdown_ping |= frame[3] == 6 && frame[4] & 1 == 0;
            saw_goaway |= frame[3] == 7;
            // Simulate a client that receives frames but no longer answers PING.
        }
    })
    .await;
    fixture
        .wait_for_upstream_close(StdDuration::from_secs(1))
        .await?;
    drop(tls);
    fixture.shutdown().await;
    assert!(
        saw_shutdown_ping && saw_goaway,
        "shutdown exchange was not reached"
    );
    assert!(
        outcome.is_ok(),
        "connection remained open for 3s despite 1s idle timeout after origin closed"
    );
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bumped_cache_mutations_invalidate_across_http_versions() -> Result<()> {
    for first_h2 in [false, true] {
        let policy = PolicySpec::new("cache-mutations")
            .rule(RuleSpec::allow(&["GET"], "https://localhost/**").cache_force_duration(60))
            .rule(RuleSpec::allow(&["DELETE"], "https://localhost/**"));
        let protocol = |h2| {
            if h2 {
                ClientProtocols::Http2Only
            } else {
                ClientProtocols::Http1
            }
        };
        let mut fixture = BumpedTlsFixture::new(
            BumpedTlsOptions::new("localhost", "cache-mutations", policy)
                .client_protocols(protocol(first_h2))
                .upstream_mode(UpstreamMode::DualProtocolCacheInspect)
                .with_cache(),
        )
        .await?;
        let authority = format!("localhost:{}", fixture.upstream_addr().port());
        let uri: Uri = format!("https://{authority}/resource").parse()?;
        for (index, (method, h2)) in [
            (Method::GET, first_h2),
            (Method::DELETE, !first_h2),
            (Method::GET, !first_h2),
        ]
        .into_iter()
        .enumerate()
        {
            if index != 0 {
                fixture.reconnect(protocol(h2)).await?;
            }
            if h2 {
                let mut client = fixture.h2_client().await?;
                let request = http::Request::builder()
                    .method(method)
                    .uri(uri.clone())
                    .body(())?;
                let (status, _) = client.request_text(request).await?;
                assert_eq!(status, StatusCode::OK);
                client.shutdown().await;
            } else {
                let mut client = fixture.http1_client();
                client.send(format!("{method} /resource HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")).await?;
                assert!(client.read_response().await?.starts_with("HTTP/1.1 200"));
            }
            assert_eq!(
                fixture.request_count(),
                index + 1,
                "phase {index}, first_h2={first_h2}"
            );
            if index == 0 {
                let cache = fixture.cache();
                timeout(StdDuration::from_secs(3), async {
                    while cache
                        .lookup(&Method::GET, &uri, &http::HeaderMap::new())
                        .await
                        .is_none()
                    {
                        tokio::task::yield_now().await;
                    }
                })
                .await?;
            }
        }
        fixture.shutdown().await;
    }
    Ok(())
}
