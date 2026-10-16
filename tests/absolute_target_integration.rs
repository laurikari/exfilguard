mod support;

use std::time::Duration;

use anyhow::Result;
use http::{HeaderMap, Method, StatusCode, Uri};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, time::timeout};

use support::*;

// Test-only SigV4 signing with fixed credentials and time. Compare the complete
// origin-visible request against the signed input, including Host and payload.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    assert!(key.len() <= 64);
    let mut inner = [0x36; 64];
    let mut outer = [0x5c; 64];
    for (index, byte) in key.iter().enumerate() {
        inner[index] ^= byte;
        outer[index] ^= byte;
    }
    let mut hash = Sha256::new();
    hash.update(inner);
    hash.update(data);
    let digest = hash.finalize();
    let mut hash = Sha256::new();
    hash.update(outer);
    hash.update(digest);
    hash.finalize().into()
}

fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn signed_headers(method: &str, authority: &str, path: &str, query: &str, body: &[u8]) -> String {
    let body_hash = sha256_hex(body);
    let date = "20260923T000000Z";
    let scope = "20260923/test-region/s3/aws4_request";
    let signed = "host;x-amz-content-sha256;x-amz-date";
    let canonical = format!(
        "{method}\n{path}\n{query}\nhost:{authority}\nx-amz-content-sha256:{body_hash}\nx-amz-date:{date}\n\n{signed}\n{body_hash}"
    );
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
        sha256_hex(canonical)
    );
    let mut key = hmac_sha256(b"AWS4test-secret", b"20260923");
    for component in ["test-region", "s3", "aws4_request"] {
        key = hmac_sha256(&key, component.as_bytes());
    }
    let signature = hmac_sha256(&key, to_sign.as_bytes());
    let signature: String = signature.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "X-Amz-Date: {date}\r\nX-Amz-Content-Sha256: {body_hash}\r\nAuthorization: AWS4-HMAC-SHA256 Credential=test-key/{scope}, SignedHeaders={signed}, Signature={signature}\r\n"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn absolute_https_preserves_signed_requests_and_origin_form() -> Result<()> {
    let policy = PolicySpec::new("signed")
        .rule(RuleSpec::allow(&["HEAD"], "https://localhost/"))
        .rule(RuleSpec::allow(
            &["PUT", "GET", "DELETE"],
            "https://localhost/objects/**",
        ));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new("localhost", "signed", policy)
            .upstream_mode(UpstreamMode::Http1Inspect),
    )
    .await?;
    // Deliberately retain a different spelling from the canonical CONNECT host.
    let authority = format!("LOCALHOST:{}", fixture.upstream_addr().port());
    let mut expected = Vec::new();
    for absolute in [true, false] {
        for method in ["HEAD", "PUT", "GET", "DELETE"] {
            let (path, canonical_path, canonical_query) = if method == "HEAD" {
                ("/", "/", "")
            } else {
                (
                    "/objects/a%20b/%252F?z=last&a=%2F&empty=",
                    "/objects/a%20b/%252F",
                    "a=%2F&empty=&z=last",
                )
            };
            let body = if method == "PUT" {
                b"signed object\0payload".as_slice()
            } else {
                b""
            };
            let headers = signed_headers(method, &authority, canonical_path, canonical_query, body);
            let length = if body.is_empty() {
                String::new()
            } else {
                format!("Content-Length: {}\r\n", body.len())
            };
            let target = if absolute {
                format!("https://{authority}{path}")
            } else {
                path.to_string()
            };
            let head =
                format!("{method} {target} HTTP/1.1\r\nHost: {authority}\r\n{headers}{length}\r\n");
            let mut request = head.into_bytes();
            request.extend_from_slice(body);
            let mut client = fixture.http1_client();
            client.send(request).await?;
            let response = client.read_response_with_length().await?;
            assert!(response.starts_with("HTTP/1.1 200"), "{method}: {response}");
            let body_hash: [u8; 32] = Sha256::digest(body).into();
            expected.push((
                format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\n{headers}{length}\r\n"),
                body_hash,
            ));
        }
    }
    let captured = fixture.captured_requests();
    assert_eq!(captured.len(), expected.len());
    for (request, (head, body_hash)) in captured.iter().zip(expected) {
        assert_eq!(request.head, head, "signed request head changed in transit");
        assert_eq!(
            request.body_sha256, body_hash,
            "signed payload changed in transit"
        );
    }
    fixture.shutdown().await;
    Ok(())
}

async fn cache_response(fixture: &BumpedTlsFixture, uri: &str) -> Result<()> {
    fixture
        .cache()
        .store(
            &Method::GET,
            &uri.parse::<Uri>()?,
            &HeaderMap::new(),
            StatusCode::OK,
            &HeaderMap::new(),
            b"cached",
            Duration::from_secs(60),
        )
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn absolute_https_rejects_invalid_targets_before_cache_or_forwarding() -> Result<()> {
    let decoy = TcpListener::bind("127.0.0.1:0").await?;
    let policy = PolicySpec::new("bound")
        .rule(RuleSpec::allow_all_destinations(&["GET"]).cache_force_duration(60));
    let mut fixture =
        BumpedTlsFixture::new(BumpedTlsOptions::new("localhost", "bound", policy).with_cache())
            .await?;
    let authority = format!("localhost:{}", fixture.upstream_addr().port());
    let other_host = format!("127.0.0.1:{}", fixture.upstream_addr().port());
    let other_port = format!("localhost:{}", decoy.local_addr()?.port());
    for destination in [
        format!("http://{authority}/cached"),
        format!("https://{other_host}/cached"),
        format!("https://{other_port}/cached"),
    ] {
        cache_response(&fixture, &destination).await?;
    }
    cache_response(&fixture, &format!("https://{authority}/cached")).await?;
    for target in [format!("https://{authority}/cached"), "/cached".into()] {
        let mut client = fixture.http1_client();
        client
            .send(format!(
                "GET {target} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
            ))
            .await?;
        let response = client.read_response_with_length().await?;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert_eq!(response.split_once("\r\n\r\n").unwrap().1, "cached");
    }
    assert_eq!(
        fixture.request_count(),
        0,
        "matching request did not use cache"
    );
    let cases = [
        (
            format!("https://{other_host}/uncached"),
            Some(other_host.clone()),
            421,
        ),
        (
            format!("https://{other_port}/uncached"),
            Some(other_port.clone()),
            421,
        ),
        (
            format!("http://{authority}/uncached"),
            Some(authority.clone()),
            421,
        ),
        (
            format!("ftp://{authority}/uncached"),
            Some(authority.clone()),
            400,
        ),
        (
            format!("https://{authority}/cached"),
            Some(format!("{authority}\r\nHost: {authority}")),
            400,
        ),
        (
            format!("http://{authority}/cached"),
            Some(authority.clone()),
            421,
        ),
        (
            format!("https://{other_host}/cached"),
            Some(other_host.clone()),
            421,
        ),
        (
            format!("https://{other_port}/cached"),
            Some(other_port.clone()),
            421,
        ),
        ("/cached".into(), Some(other_host.clone()), 421),
        (format!("https://{authority}/cached"), Some(other_host), 400),
        (format!("https://{authority}/cached"), Some(other_port), 400),
        (format!("https://{authority}/cached"), None, 400),
        (
            format!("https://{authority}/cached"),
            Some("localhost:wat".into()),
            400,
        ),
        (
            format!("https://user@{authority}/cached"),
            Some(authority.clone()),
            400,
        ),
        (
            format!("https://{authority}/cached#fragment"),
            Some(authority.clone()),
            400,
        ),
        (
            format!("https://{authority}/%2e%2e/cached"),
            Some(authority.clone()),
            400,
        ),
        (
            format!("https://{authority}/a%5cb"),
            Some(authority.clone()),
            400,
        ),
    ];
    for (index, (target, host, status)) in cases.into_iter().enumerate() {
        if index > 0 {
            fixture.reconnect(ClientProtocols::Http1).await?;
        }
        // Establish a reusable upstream connection before each rejection.
        let mut client = fixture.http1_client();
        client
            .send(format!(
                "GET /warm/{index} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
            ))
            .await?;
        assert!(
            client
                .read_response_with_length()
                .await?
                .starts_with("HTTP/1.1 200")
        );
        let before = fixture.request_count();
        let connections = fixture.accept_count();
        let host = host
            .map(|value| format!("Host: {value}\r\n"))
            .unwrap_or_default();
        let mut client = fixture.http1_client();
        client
            .send(format!("GET {target} HTTP/1.1\r\n{host}\r\n"))
            .await?;
        let response = client.read_response().await?;
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{target}: {response}"
        );
        assert_eq!(
            fixture.request_count(),
            before,
            "rejected request reached upstream"
        );
        assert_eq!(
            fixture.accept_count(),
            connections,
            "rejected request opened upstream connection"
        );
    }
    assert!(
        timeout(Duration::from_millis(20), decoy.accept())
            .await
            .is_err()
    );
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn absolute_https_uses_canonical_method_path_policy() -> Result<()> {
    let policy = PolicySpec::new("paths")
        .rule(RuleSpec::deny(&["GET"], "https://localhost/objects/private/**").status(403))
        .rule(RuleSpec::allow(&["GET"], "https://localhost/objects/**"));
    let mut fixture =
        BumpedTlsFixture::new(BumpedTlsOptions::new("localhost", "paths", policy)).await?;
    let authority = format!("localhost:{}", fixture.upstream_addr().port());
    for (index, (method, path, status)) in [
        ("GET", "/alias/../objects/a%2fb?z=%252f&x=+&x=%20", 200),
        ("GET", "/objects/pr%69vate/secret", 403),
        ("DELETE", "/objects/allowed", 403),
        ("GET", "/elsewhere", 403),
    ]
    .into_iter()
    .enumerate()
    {
        if index > 0 {
            fixture.reconnect(ClientProtocols::Http1).await?;
        }
        let before = fixture.request_count();
        let mut client = fixture.http1_client();
        client.send(format!("{method} https://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")).await?;
        let response = client.read_response().await?;
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{response}"
        );
        if status == 200 {
            assert_eq!(response.split_once("\r\n\r\n").unwrap().1, path);
        } else {
            assert_eq!(fixture.request_count(), before);
        }
    }
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inspected_http2_checks_binding_before_cache_and_keeps_other_streams_usable() -> Result<()>
{
    let policy = PolicySpec::new("h2-bound")
        .rule(RuleSpec::allow_all_destinations(&["GET"]).cache_force_duration(60));
    let mut fixture = BumpedTlsFixture::new(
        BumpedTlsOptions::new("localhost", "h2-bound", policy)
            .client_protocols(ClientProtocols::Http2Only)
            .upstream_mode(UpstreamMode::Http2CacheInspect)
            .with_cache(),
    )
    .await?;
    let port = fixture.upstream_addr().port();
    let good = format!("https://localhost:{port}/cached");
    cache_response(&fixture, &good).await?;
    let mut client = fixture.h2_client().await?;
    for uri in [
        format!("http://localhost:{port}/cached"),
        format!("https://127.0.0.1:{port}/cached"),
        "https://localhost:0/cached".into(),
    ] {
        cache_response(&fixture, &uri).await?;
        let request = http::Request::builder().uri(uri).body(())?;
        let (status, _) = client.request_text(request).await?;
        assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    }
    let conflicting = http::Request::builder()
        .uri(&good)
        .header("host", "other.invalid")
        .body(())?;
    assert_eq!(
        client.request_text(conflicting).await?.0,
        StatusCode::BAD_REQUEST
    );
    let request = http::Request::builder().uri(&good).body(())?;
    assert_eq!(
        client.request_text(request).await?,
        (StatusCode::OK, "cached".into())
    );
    assert_eq!(fixture.request_count(), 0);
    client.shutdown().await;
    fixture.shutdown().await;
    Ok(())
}
