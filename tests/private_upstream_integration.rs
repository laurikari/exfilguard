mod support;

use std::time::Duration;

use anyhow::Result;
use http::{Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

use support::*;

const ADDRESS_BLOCK: &str = "upstream address blocked (private_address)";

#[tokio::test]
async fn legacy_ipv4_cannot_evade_a_literal_deny_before_a_broad_allow() -> Result<()> {
    let origin = TestUpstream::http_ok("should not be reached").await?;
    let port = origin.port();
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["numeric"])
        .policy(
            PolicySpec::new("numeric")
                .rule(
                    RuleSpec::deny(&["CONNECT"], format!("https://127.0.0.1:{port}/**"))
                        .status(403)
                        .https_mode("tunnel"),
                )
                .rule(
                    RuleSpec::allow(&["CONNECT"], format!("https://*:{port}/**"))
                        .https_mode("tunnel"),
                )
                .rule(RuleSpec::deny(&["GET"], format!("http://127.0.0.1:{port}/**")).status(403))
                .rule(RuleSpec::allow(&["GET"], format!("http://*:{port}/**"))),
        )
        .render();
    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .with_private_test_upstreams(false)
        .with_settings(|settings| {
            settings.allow_private_upstream_cidrs = vec!["127.0.0.1/32".parse().unwrap()]
        })
        .spawn()
        .await?;
    for host in [
        "127.0.0.1",
        "127.1",
        "127.0.1",
        "0177.0.0.1",
        "0x7f000001",
        "2130706433",
        "0x7f.1",
        "127.1.",
    ] {
        let authority = format!("{host}:{port}");
        let status = if host == "127.0.0.1" { 403 } else { 400 };
        for (method, target) in [
            ("GET", "/probe".to_string()),
            ("GET", format!("http://{authority}/probe")),
            ("CONNECT", authority.clone()),
        ] {
            let mut client = harness.connect().await?;
            client.write_all(format!(
                "{method} {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
            ).as_bytes()).await?;
            let response =
                timeout(Duration::from_secs(2), read_http_response(&mut client)).await??;
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}")),
                "{method} {target}: {response}"
            );
        }
    }
    assert_eq!(origin.accept_count(), 0);
    harness.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn non_public_destinations_are_blocked_across_proxy_modes() -> Result<()> {
    for authority in [
        "[fec0::1]:8443",
        "[4000::1]:8443",
        "[2001:1000::1]:8443",
        "192.88.99.1:8443",
    ] {
        for (method, target, rule) in [
            (
                "GET",
                format!("http://{authority}/probe"),
                RuleSpec::allow(&["GET"], format!("http://{authority}/**")),
            ),
            (
                "CONNECT",
                authority.to_owned(),
                RuleSpec::allow(&["CONNECT"], format!("https://{authority}/**"))
                    .https_mode("tunnel"),
            ),
            (
                "CONNECT",
                authority.to_owned(),
                RuleSpec::allow(&["GET"], format!("https://{authority}/**")),
            ),
        ] {
            let (clients, policies) = TestConfigBuilder::new()
                .default_client(&["allowed"])
                .policy(PolicySpec::new("allowed").rule(rule))
                .render();
            let harness = ProxyHarnessBuilder::new(&clients, &policies)?
                .with_private_test_upstreams(false)
                .spawn()
                .await?;
            let mut client = harness.connect().await?;
            client
                .write_all(
                    format!(
                        "{method} {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            let response =
                timeout(Duration::from_secs(2), read_http_response(&mut client)).await??;
            assert!(response.starts_with("HTTP/1.1 403"), "{response}");
            assert!(response.contains(ADDRESS_BLOCK), "{response}");
            harness.shutdown().await;
        }
    }
    Ok(())
}

async fn access_log(
    logs: &LogCapture,
    client_port: u16,
    method: &str,
    status: u16,
) -> Result<String> {
    Ok(timeout(Duration::from_secs(2), async {
        loop {
            if let Some(line) = logs.text().lines().find(|line| {
                line.contains(&format!(" method=\"{method}\""))
                    && line
                        .split_whitespace()
                        .any(|field| field == format!("client_port={client_port}"))
                    && line.contains(&format!("status={status}"))
            }) {
                return line.to_string();
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?)
}

#[tokio::test]
async fn http_private_exception_still_requires_request_policy() -> Result<()> {
    for (cidr, path, status) in [
        (None, "/allowed", 403),
        (Some("127.0.0.2/32"), "/allowed", 403),
        (Some("127.0.0.1/32"), "/allowed", 200),
        (Some("127.0.0.1/32"), "/denied", 403),
    ] {
        let logs = LogCapture::new("info").await;
        let upstream = TestUpstream::http_ok("internal service").await?;
        let authority = upstream.addr().to_string();
        let (clients, policies) = TestConfigBuilder::new()
            .default_client(&["internal"])
            .policy(PolicySpec::new("internal").rule(RuleSpec::allow(
                &["GET"],
                format!("http://{authority}/allowed"),
            )))
            .render();
        let harness = ProxyHarnessBuilder::new(&clients, &policies)?
            .with_private_test_upstreams(false)
            .with_settings(move |settings| {
                settings.allow_private_upstream_cidrs =
                    cidr.into_iter().map(|net| net.parse().unwrap()).collect();
            })
            .spawn()
            .await?;
        let mut client = harness.connect().await?;
        client.write_all(format!(
            "GET http://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        ).as_bytes()).await?;
        let response = timeout(Duration::from_secs(2), read_http_response(&mut client)).await??;
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{response}"
        );
        let log = access_log(&logs, client.local_addr()?.port(), "GET", status).await?;
        if path == "/denied" {
            assert!(response.contains("request blocked by policy"), "{response}");
            assert!(!log.contains("private_address"), "{log}");
        } else {
            assert!(log.contains("client=\"default\""), "{log}");
            assert!(log.contains("policy=\"internal\""), "{log}");
            assert!(log.contains("rule="), "{log}");
            if status == 403 {
                assert!(response.contains(ADDRESS_BLOCK), "{response}");
                assert!(log.contains("error_reason=\"private_address\""), "{log}");
            } else {
                assert!(response.contains("internal service"), "{response}");
                assert!(log.contains("decision=\"ALLOW\""), "{log}");
            }
        }
        assert_eq!(upstream.accept_count(), usize::from(status == 200));
        harness.shutdown().await;
    }
    Ok(())
}

#[tokio::test]
async fn connect_private_exceptions_and_resolution_logs() -> Result<()> {
    for inspect in [false, true] {
        let logs = LogCapture::new("info").await;
        let upstream = TestUpstream::echo().await?;
        let authority = format!("localhost:{}", upstream.port());
        let rule = if inspect {
            RuleSpec::allow(&["GET"], format!("https://{authority}/**"))
        } else {
            RuleSpec::allow(&["CONNECT"], format!("https://{authority}/**")).https_mode("tunnel")
        };
        let (clients, policies) = TestConfigBuilder::new()
            .default_client(&["internal"])
            .policy(PolicySpec::new("internal").rule(rule))
            .render();
        let harness = ProxyHarnessBuilder::new(&clients, &policies)?
            .with_private_test_upstreams(false)
            .spawn()
            .await?;
        let mut client = harness.connect().await?;
        client
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await?;
        let response = timeout(Duration::from_secs(2), read_http_response(&mut client)).await??;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(response.contains(ADDRESS_BLOCK), "{response}");
        let log = access_log(&logs, client.local_addr()?.port(), "CONNECT", 403).await?;
        for field in [
            "client=\"default\"",
            "decision=\"DENY\"",
            "error_reason=\"private_address\"",
        ] {
            assert!(log.contains(field), "{log}");
        }
        if inspect {
            assert!(log.contains("effective_mode=\"bump\""), "{log}");
            assert!(log.contains("transport=\"tls_bump_preflight\""), "{log}");
            assert!(!log.contains("policy="), "{log}");
            assert!(!log.contains("rule="), "{log}");
        } else {
            assert!(log.contains("effective_mode=\"tunnel\""), "{log}");
            assert!(log.contains("policy=\"internal\""), "{log}");
            assert!(log.contains("rule="), "{log}");
        }
        assert_eq!(upstream.accept_count(), 0);
        harness.shutdown().await;
    }
    Ok(())
}

#[tokio::test]
async fn connect_exception_allows_tunnel_only_with_matching_policy() -> Result<()> {
    for permitted in [false, true] {
        let logs = LogCapture::new("info").await;
        let upstream = TestUpstream::echo().await?;
        let authority = upstream.addr().to_string();
        let target = if permitted {
            authority.clone()
        } else {
            "example.test:443".to_string()
        };
        let (clients, policies) = TestConfigBuilder::new()
            .default_client(&["internal"])
            .policy(PolicySpec::new("internal").rule(
                RuleSpec::allow(&["CONNECT"], format!("https://{target}/**")).https_mode("tunnel"),
            ))
            .render();
        let harness = ProxyHarnessBuilder::new(&clients, &policies)?
            .with_private_test_upstreams(false)
            .with_settings(|settings| {
                settings.allow_private_upstream_cidrs = vec!["127.0.0.1/32".parse().unwrap()]
            })
            .spawn()
            .await?;
        let mut client = harness.connect().await?;
        client
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await?;
        if permitted {
            let response =
                timeout(Duration::from_secs(2), read_until_double_crlf(&mut client)).await??;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            client.write_all(b"internal tunnel").await?;
            let mut echoed = [0; 15];
            timeout(Duration::from_secs(2), client.read_exact(&mut echoed)).await??;
            assert_eq!(&echoed, b"internal tunnel");
            client.shutdown().await?;
            let log = access_log(&logs, client.local_addr()?.port(), "CONNECT", 200).await?;
            assert!(log.contains("policy=\"internal\""), "{log}");
            assert!(log.contains("effective_mode=\"tunnel\""), "{log}");
        } else {
            let response =
                timeout(Duration::from_secs(2), read_http_response(&mut client)).await??;
            assert!(response.starts_with("HTTP/1.1 403"), "{response}");
            assert!(response.contains("request blocked by policy"), "{response}");
            let log = access_log(&logs, client.local_addr()?.port(), "CONNECT", 403).await?;
            assert!(!log.contains("private_address"), "{log}");
        }
        assert_eq!(upstream.accept_count(), usize::from(permitted));
        harness.shutdown().await;
    }
    Ok(())
}

#[tokio::test]
async fn inspected_private_exception_preserves_http1_and_http2_policy() -> Result<()> {
    for http2 in [false, true] {
        let policy = PolicySpec::new("internal")
            .rule(RuleSpec::allow(&["GET"], "https://localhost/allowed"));
        let mut fixture = BumpedTlsFixture::new(
            BumpedTlsOptions::new("localhost", "internal", policy)
                .with_private_test_upstreams(false)
                .with_settings(|settings| {
                    settings.allow_private_upstream_cidrs = vec!["127.0.0.1/32".parse().unwrap()]
                })
                .client_protocols(if http2 {
                    ClientProtocols::Http2Only
                } else {
                    ClientProtocols::Http1
                })
                .upstream_mode(UpstreamMode::DualProtocolCacheInspect),
        )
        .await?;
        let authority = format!("localhost:{}", fixture.upstream_addr().port());
        if http2 {
            let mut client = fixture.h2_client().await?;
            for (path, status) in [
                ("/denied", StatusCode::FORBIDDEN),
                ("/allowed", StatusCode::OK),
            ] {
                let request = Request::builder()
                    .uri(format!("https://{authority}{path}"))
                    .body(())?;
                let (actual, body) = client.request_text(request).await?;
                assert_eq!(actual, status);
                if status == StatusCode::FORBIDDEN {
                    assert_eq!(body, "request blocked by policy");
                }
            }
            client.shutdown().await;
        } else {
            for (path, status) in [("/allowed", 200), ("/denied", 403)] {
                if status == 403 {
                    fixture.reconnect(ClientProtocols::Http1).await?;
                }
                let mut client = fixture.http1_client();
                client
                    .send(format!(
                        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
                    ))
                    .await?;
                let response = timeout(Duration::from_secs(2), client.read_response()).await??;
                assert!(
                    response.starts_with(&format!("HTTP/1.1 {status}")),
                    "{response}"
                );
            }
        }
        assert_eq!(
            fixture.request_count(),
            1,
            "denied request must not reach the upstream"
        );
        fixture.shutdown().await;
    }
    Ok(())
}
