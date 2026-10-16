mod support;

use std::{io::ErrorKind, time::Duration};

use anyhow::{Context, Result};
use http::{HeaderMap, Method, StatusCode, Uri};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    time::{sleep, timeout},
};

use support::*;

async fn read_closed_response(stream: &mut (impl AsyncRead + Unpin)) -> Result<String> {
    timeout(Duration::from_secs(2), async {
        let mut response = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buffer[..n]),
                Err(error) if error.kind() == ErrorKind::ConnectionReset => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(String::from_utf8(response)?)
    })
    .await
    .context("proxy did not close the rejected connection")?
}

fn assert_upgrade_response(response: &str) {
    assert!(
        response.starts_with("HTTP/1.1 501 Not Implemented\r\n"),
        "{response}"
    );
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(head.contains("Connection: close\r\n"), "{response}");
    assert_eq!(body, "HTTP/1.1 Upgrade is not supported by ExfilGuard\r\n");
    assert!(head.contains(&format!("Content-Length: {}\r\n", body.len())));
}

async fn upgrade_log(logs: &LogCapture, path: &str) -> Result<String> {
    timeout(Duration::from_secs(2), async {
        loop {
            if let Some(line) = logs.text().lines().find(|line| {
                line.contains("error_reason=\"upgrade_unsupported\"") && line.contains(path)
            }) {
                return line.to_string();
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .context("missing upgrade rejection access log")
}

#[tokio::test]
async fn plain_upgrade_requests_are_rejected_before_forwarding() -> Result<()> {
    let logs = LogCapture::new("info").await;
    let upstream = TestUpstream::http_ok("ordinary response").await?;
    let authority = upstream.addr().to_string();
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow"])
        .policy(
            PolicySpec::new("allow").rule(RuleSpec::allow_any(format!("http://{authority}/**"))),
        )
        .render();
    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .spawn()
        .await?;
    let cases = [
        ("Upgrade: websocket\r\nConnection: Upgrade\r\n", ""),
        (
            "cOnNeCtIoN: keep-alive, uPgRaDe\r\nuPgRaDe: websocket\r\n",
            "",
        ),
        ("Upgrade: h2c\r\n", ""),
        ("Upgrade:\r\n", ""),
        ("Connection: upgrade\r\n", ""),
        (
            "Upgrade: websocket\r\nExpect: 100-continue\r\nContent-Length: 4\r\n",
            "",
        ),
        (
            "Upgrade: websocket\r\nContent-Length: 4\r\n",
            "bodyGET /second HTTP/1.1\r\nHost: example.test\r\n\r\n",
        ),
    ];
    for (index, (headers, tail)) in cases.iter().enumerate() {
        let path = format!("/plain-upgrade-{index}");
        let request = format!(
            "GET http://{authority}{path}?hidden=query HTTP/1.1\r\nHost: {authority}\r\n{headers}\r\n{tail}"
        );
        let mut client = harness.connect().await?;
        client.write_all(request.as_bytes()).await?;
        assert_upgrade_response(&read_closed_response(&mut client).await?);
        let log = upgrade_log(&logs, &path).await?;
        for field in [
            "status=501",
            "decision=\"ERROR\"",
            "method=\"GET\"",
            "client=\"default\"",
        ] {
            assert!(log.contains(field), "{log}");
        }
        assert!(!log.contains("hidden=query"), "{log}");
        assert!(!log.contains("policy="), "{log}");
        assert!(!log.contains("rule="), "{log}");
    }
    assert_eq!(upstream.accept_count(), 0);

    let mut client = harness.connect().await?;
    client.write_all(format!("GET http://{authority}/ordinary HTTP/1.1\r\nHost: {authority}\r\nSec-WebSocket-Key: fixture\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\n\r\n").as_bytes()).await?;
    assert!(
        read_closed_response(&mut client)
            .await?
            .starts_with("HTTP/1.1 200")
    );
    assert_eq!(upstream.accept_count(), 1);
    harness.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn inspected_upgrade_is_rejected_before_cache_or_upstream_request() -> Result<()> {
    let logs = LogCapture::new("info").await;
    let policy = PolicySpec::new("allow")
        .rule(RuleSpec::allow_any("https://localhost/**").cache_force_duration(60));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new("localhost", "allow", policy)
            .upstream_mode(UpstreamMode::DualProtocolCacheInspect)
            .with_cache(),
    )
    .await?;
    let authority = format!("localhost:{}", fixture.upstream_addr().port());
    let uri: Uri = format!("https://{authority}/tls-upgrade?hidden=query").parse()?;
    fixture
        .cache()
        .store(
            &Method::GET,
            &uri,
            &HeaderMap::new(),
            StatusCode::OK,
            &HeaderMap::new(),
            b"cached ordinary response",
            Duration::from_secs(60),
        )
        .await?;
    let mut client = fixture.http1_client();
    client.send(format!("GET /tls-upgrade?hidden=query HTTP/1.1\r\nHost: {authority}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nGET /second HTTP/1.1\r\nHost: {authority}\r\n\r\n")).await?;
    assert_upgrade_response(&read_closed_response(client.stream_mut()).await?);
    let log = upgrade_log(&logs, "/tls-upgrade").await?;
    for field in [
        "status=501",
        "decision=\"ERROR\"",
        "scheme=\"https\"",
        "effective_mode=\"bump\"",
        "outer_method=\"CONNECT\"",
        "inner_method=\"GET\"",
        "session_id=",
    ] {
        assert!(log.contains(field), "{log}");
    }
    assert!(!log.contains("hidden=query"), "{log}");
    assert_eq!(
        fixture.accept_count(),
        1,
        "only CONNECT preflight should connect upstream"
    );
    assert_eq!(fixture.request_count(), 0);
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn connect_rejects_upgrade_headers_but_tunnel_bytes_remain_opaque() -> Result<()> {
    let upstream = TestUpstream::echo().await?;
    let authority = upstream.addr().to_string();
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["tunnel"])
        .policy(PolicySpec::new("tunnel").rule(
            RuleSpec::allow(&["CONNECT"], format!("https://{authority}/**")).https_mode("tunnel"),
        ))
        .render();
    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .spawn()
        .await?;
    let mut client = harness.connect().await?;
    client
        .write_all(
            format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUpgrade: websocket\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    assert_upgrade_response(&read_closed_response(&mut client).await?);
    assert_eq!(upstream.accept_count(), 0);

    let mut client = harness.connect().await?;
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let response = timeout(Duration::from_secs(2), read_until_double_crlf(&mut client)).await??;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let bytes = b"GET / HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    client.write_all(bytes).await?;
    let mut echoed = vec![0; bytes.len()];
    timeout(Duration::from_secs(2), client.read_exact(&mut echoed)).await??;
    assert_eq!(echoed, bytes);
    harness.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn malformed_upgrade_request_still_returns_400() -> Result<()> {
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow"])
        .policy(PolicySpec::new("allow").rule(RuleSpec::allow_any("http://example.test/**")))
        .render();
    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .spawn()
        .await?;
    let mut client = harness.connect().await?;
    client.write_all(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nConnection: close\r\n\r\n").await?;
    assert!(
        read_closed_response(&mut client)
            .await?
            .starts_with("HTTP/1.1 400")
    );
    harness.shutdown().await;
    Ok(())
}
