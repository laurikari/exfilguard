mod support;

#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Result;

use exfilguard::settings::ProxyProtocolMode;
use ipnet::IpNet;
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_protocol_allows_forwarded_client() -> Result<()> {
    let upstream = TestUpstream::http_ok("ok").await?;
    let upstream_port = upstream.port();

    let (clients, policies) = TestConfigBuilder::new()
        .client_ip("lb", "203.0.113.10", &["allow-proxy"])
        .fallback_client("fallback", &["deny-all"])
        .policy(
            PolicySpec::new("allow-proxy").rule(RuleSpec::allow_any(format!(
                "http://127.0.0.1:{upstream_port}/**"
            ))),
        )
        .policy(PolicySpec::new("deny-all").rule(
            RuleSpec::deny(&["ANY"], format!("http://127.0.0.1:{upstream_port}/**")).status(403),
        ))
        .render();

    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .with_settings(|settings| {
            settings.proxy_protocol = ProxyProtocolMode::Required;
            settings.proxy_protocol_allowed_cidrs =
                Some(vec!["127.0.0.1/32".parse::<IpNet>().unwrap()]);
        })
        .spawn()
        .await?;

    let mut client = ProxyClient::connect(harness.addr).await?;
    let proxy_line = "PROXY TCP4 203.0.113.10 192.0.2.1 5555 3128\r\n";
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    client.send(proxy_line).await?;
    client.send(request).await?;
    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );

    harness.shutdown().await;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_protocol_ipv4_cidr_allows_mapped_dual_stack_peer() -> Result<()> {
    let upstream = TestUpstream::http_ok("ok").await?;
    let upstream_port = upstream.port();
    let proxy_port = find_free_port()?;

    let (clients, policies) = TestConfigBuilder::new()
        .client_ip("lb", "203.0.113.10", &["allow-proxy"])
        .fallback_client("fallback", &["deny-all"])
        .policy(
            PolicySpec::new("allow-proxy").rule(RuleSpec::allow_any(format!(
                "http://127.0.0.1:{upstream_port}/**"
            ))),
        )
        .policy(PolicySpec::new("deny-all").rule(
            RuleSpec::deny(&["ANY"], format!("http://127.0.0.1:{upstream_port}/**")).status(403),
        ))
        .render();

    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .with_settings(move |settings| {
            settings.listen = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), proxy_port);
            settings.proxy_protocol = ProxyProtocolMode::Required;
            settings.proxy_protocol_allowed_cidrs =
                Some(vec!["127.0.0.1/32".parse::<IpNet>().unwrap()]);
        })
        .spawn()
        .await?;

    let ipv4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy_port);
    let mut client = ProxyClient::connect(ipv4_addr).await?;
    client
        .send("PROXY TCP4 203.0.113.10 192.0.2.1 5555 3128\r\n")
        .await?;
    client
        .send(&format!(
            "GET http://127.0.0.1:{upstream_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
        ))
        .await?;
    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );

    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_protocol_optional_allows_untrusted_direct_peer() -> Result<()> {
    let upstream = TestUpstream::http_ok("ok").await?;
    let upstream_port = upstream.port();

    let (clients, policies) = TestConfigBuilder::new()
        .fallback_client("local", &["allow-local"])
        .policy(
            PolicySpec::new("allow-local").rule(RuleSpec::allow_any(format!(
                "http://127.0.0.1:{upstream_port}/**"
            ))),
        )
        .render();

    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .with_settings(|settings| {
            settings.proxy_protocol = ProxyProtocolMode::Optional;
            settings.proxy_protocol_allowed_cidrs =
                Some(vec!["198.51.100.0/24".parse::<IpNet>().unwrap()]);
        })
        .spawn()
        .await?;

    let mut client = ProxyClient::connect(harness.addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    client.send(request).await?;
    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );

    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_protocol_required_rejects_untrusted_direct_peer() -> Result<()> {
    let upstream = TestUpstream::http_ok("ok").await?;
    let upstream_port = upstream.port();

    let (clients, policies) = TestConfigBuilder::new()
        .fallback_client("local", &["allow-local"])
        .policy(
            PolicySpec::new("allow-local").rule(RuleSpec::allow_any(format!(
                "http://127.0.0.1:{upstream_port}/**"
            ))),
        )
        .render();

    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .with_settings(|settings| {
            settings.proxy_protocol = ProxyProtocolMode::Required;
            settings.proxy_protocol_allowed_cidrs =
                Some(vec!["198.51.100.0/24".parse::<IpNet>().unwrap()]);
        })
        .spawn()
        .await?;

    let mut client = ProxyClient::connect(harness.addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    match async {
        client.send(request).await?;
        client.read_response().await
    }
    .await
    {
        Ok(response) => {
            assert!(
                response.is_empty(),
                "expected connection to close without HTTP response, got: {response}"
            );
        }
        Err(err) => {
            let detail = err.to_string();
            assert!(
                detail.contains("Connection reset by peer")
                    || detail.contains("Broken pipe")
                    || detail.contains("not connected"),
                "unexpected error while probing rejected connection: {detail}"
            );
        }
    }

    harness.shutdown().await;
    Ok(())
}
