mod support;

use anyhow::Result;

use exfilguard::settings::ProxyProtocolMode;
use ipnet::IpNet;
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_protocol_allows_forwarded_client() -> Result<()> {
    let upstream = TestUpstream::http_ok("ok").await?;
    let upstream_port = upstream.port();

    let (clients, policies) = TestConfigBuilder::new()
        .client_ip("lb", "203.0.113.10", &["allow-proxy"], false)
        .client_cidr("fallback", "0.0.0.0/0", &["deny-all"], true)
        .policy(
            PolicySpec::new("allow-proxy").rule(
                RuleSpec::allow_any(format!("http://127.0.0.1:{upstream_port}/**"))
                    .allow_private_upstream(true),
            ),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_protocol_allowlist_skips_untrusted_peer() -> Result<()> {
    let upstream = TestUpstream::http_ok("ok").await?;
    let upstream_port = upstream.port();

    let (clients, policies) = TestConfigBuilder::new()
        .client_ip("local", "127.0.0.1", &["allow-local"], true)
        .policy(
            PolicySpec::new("allow-local").rule(
                RuleSpec::allow_any(format!("http://127.0.0.1:{upstream_port}/**"))
                    .allow_private_upstream(true),
            ),
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
    client.send(request).await?;
    let response = client.read_response().await?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );

    harness.shutdown().await;
    Ok(())
}
