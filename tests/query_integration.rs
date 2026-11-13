mod support;

use anyhow::Result;
use http::{Method, StatusCode};

use support::*;

#[tokio::test]
async fn cache_trace_does_not_disclose_redacted_queries() -> Result<()> {
    let logs = LogCapture::new("info,exfilguard::proxy::cache=trace").await;
    let origin = TestUpstream::http_response(
        b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=600\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ).await?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["cache"])
        .policy(
            PolicySpec::new("cache").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{}/**", origin.port()))
                    .cache_enabled(),
            ),
        )
        .render();
    let mut dirs = TestDirs::new()?;
    dirs.enable_cache_dir()?;
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(|settings| settings.log_queries = false)
        .spawn()
        .await?;
    let mut client = ProxyClient::connect(harness.addr).await?;
    client.send(format!(
        "GET http://127.0.0.1:{port}/resource?token=cache-query-secret HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n",
        port = origin.port(),
    )).await?;
    assert!(client.read_response().await?.starts_with("HTTP/1.1 200"));
    let output = logs.wait_for("stored cache entry").await?;
    assert!(output.contains("entry_id="), "{output}");
    assert!(!output.contains("cache-query-secret"), "{output}");
    client.shutdown().await;
    harness.shutdown().await;
    Ok(())
}

fn query_policy() -> PolicySpec {
    PolicySpec::new("queries")
        .rule(RuleSpec::allow(
            &["GET"],
            "https://localhost/download?file=allowed.md",
        ))
        .rule(RuleSpec::allow(
            &["GET"],
            "https://localhost/literal?x=*&plus=+&escape=%2f&again=?",
        ))
        .rule(RuleSpec::allow(&["GET"], "https://localhost/empty?"))
        .rule(RuleSpec::allow(&["GET"], "https://localhost/absent").query_present(false))
        .rule(RuleSpec::allow(&["GET"], "https://localhost/present").query_present(true))
        .rule(RuleSpec::allow(&["GET"], "https://localhost/legacy"))
        .rule(RuleSpec::deny(&["GET"], "https://localhost/ordered?deny=yes").status(403))
        .rule(RuleSpec::allow(&["GET"], "https://localhost/ordered"))
}

const CASES: &[(&str, bool)] = &[
    ("/download?file=allowed.md", true),
    ("/%64ownload?file=allowed.md", true),
    ("/download?file=private.md", false),
    ("/download?file=allowed.md&extra=value", false),
    ("/download?file=allowed.md&file=private.md", false),
    ("/download?file=%61llowed.md", false),
    ("/download", false),
    ("/literal?x=*&plus=+&escape=%2f&again=?", true),
    ("/literal?x=other&plus=+&escape=%2f&again=?", false),
    ("/literal?x=*&plus=%20&escape=%2f&again=?", false),
    ("/literal?x=*&plus=+&escape=%2F&again=?", false),
    ("/empty?", true),
    ("/empty", false),
    ("/empty?value", false),
    ("/absent", true),
    ("/absent?", false),
    ("/absent?value", false),
    ("/present", false),
    ("/present?", true),
    ("/present?value", true),
    ("/legacy", true),
    ("/legacy?value", true),
    ("/ordered?deny=yes", false),
    ("/ordered?deny=no", true),
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inspected_http1_matches_literal_queries_and_preserves_targets() -> Result<()> {
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new("localhost", "queries", query_policy())
            .upstream_mode(UpstreamMode::Http1Inspect),
    )
    .await?;
    let authority = format!("localhost:{}", fixture.upstream_addr().port());
    let mut allowed_targets = Vec::new();
    for absolute in [false, true] {
        for &(path, allowed) in CASES {
            fixture.reconnect(ClientProtocols::Http1).await?;
            let target = if absolute {
                format!("https://{authority}{path}")
            } else {
                path.to_string()
            };
            let mut client = fixture.http1_client();
            client
                .send(format!(
                    "GET {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
                ))
                .await?;
            let response = client.read_response_with_length().await?;
            let expected = if allowed { "200" } else { "403" };
            assert!(
                response.starts_with(&format!("HTTP/1.1 {expected}")),
                "{target}: {response}"
            );
            if allowed {
                allowed_targets.push(format!("GET {path} HTTP/1.1\r\n"));
            }
        }
    }
    let captured = fixture.captured_requests();
    assert_eq!(captured.len(), allowed_targets.len());
    for (request, expected) in captured.iter().zip(allowed_targets) {
        assert!(request.head.starts_with(&expected), "{}", request.head);
    }
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inspected_http2_matches_literal_queries_and_preserves_targets() -> Result<()> {
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new("localhost", "queries", query_policy())
            .client_protocols(ClientProtocols::Http2Preferred)
            .upstream_mode(UpstreamMode::Http2Inspect),
    )
    .await?;
    let authority = format!("localhost:{}", fixture.upstream_addr().port());
    let mut client = fixture.h2_client().await?;
    for &(path, allowed) in CASES {
        let request = http::Request::builder()
            .method(Method::GET)
            .uri(format!("https://{authority}{path}"))
            .body(())?;
        let (status, body) = client.request_text(request).await?;
        assert_eq!(
            status,
            if allowed {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            },
            "{path}: {body}"
        );
        if allowed {
            assert!(
                body.contains(&format!("path={path}\n")),
                "upstream request target changed: {body}"
            );
        }
    }
    client.shutdown().await;
    fixture.shutdown().await;
    Ok(())
}
