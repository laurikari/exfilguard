mod support;

use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use bytes::Bytes;
use exfilguard::{settings::ProxyProtocolMode, tls::ca::CertificateAuthority};
use rustls::{RootCertStore, pki_types::ServerName};
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

async fn wait_for_handshake_connections(count: usize) -> Result<()> {
    let expected =
        format!("downstream_connections_active_by_client{{client=\"handshake-test\"}} {count}");
    timeout(Duration::from_secs(3), async {
        loop {
            if String::from_utf8(exfilguard::metrics::gather())?
                .lines()
                .any(|line| line == expected)
            {
                return Ok::<_, anyhow::Error>(());
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?
}

#[tokio::test]
async fn tls_proxy_forwards_http_and_connect_payloads() -> Result<()> {
    let upstream = TestUpstream::http_ok("through TLS").await?;
    let echo = TestUpstream::echo().await?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["allow"])
        .policy(
            PolicySpec::new("allow")
                .rule(
                    RuleSpec::allow(&["CONNECT"], format!("https://{}/**", echo.addr()))
                        .https_mode("tunnel"),
                )
                .rule(RuleSpec::allow(
                    &["GET"],
                    format!("http://{}/**", upstream.addr()),
                )),
        )
        .render();
    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .with_tls_proxy()
        .spawn()
        .await?;
    let mut client = harness.connect_tls().await?;
    assert_eq!(
        client.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    client
        .write_all(
            format!(
                "GET http://{}/ HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                upstream.addr(),
                upstream.addr()
            )
            .as_bytes(),
        )
        .await?;
    let response = timeout(Duration::from_secs(3), read_http_response(&mut client)).await??;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("through TLS"));

    let mut tunnel = harness.connect_tls().await?;
    tunnel
        .write_all(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\nprefetched payload",
                echo.addr(),
                echo.addr()
            )
            .as_bytes(),
        )
        .await?;
    assert!(
        read_until_double_crlf(&mut tunnel)
            .await?
            .starts_with("HTTP/1.1 200")
    );
    let mut payload = [0; 18];
    timeout(Duration::from_secs(3), tunnel.read_exact(&mut payload)).await??;
    assert_eq!(&payload, b"prefetched payload");
    tunnel.shutdown().await?;
    harness.shutdown().await;
    Ok(())
}

async fn tls_upstream(
    ca: &CertificateAuthority,
    h2: bool,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let config = if h2 {
        build_upstream_h2_tls_config(ca, "localhost")?
    } else {
        build_upstream_tls_config(ca, "localhost")?
    };
    let acceptor = TlsAcceptor::from(config);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                if h2 {
                    let Ok(mut connection) = h2::server::handshake(tls).await else {
                        return;
                    };
                    while let Some(Ok((request, mut respond))) = connection.accept().await {
                        let body = format!(
                            "{}\nhost={}",
                            request.uri().path_and_query().unwrap(),
                            request.headers().contains_key("host")
                        );
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        if let Ok(mut send) = respond.send_response(response, false) {
                            let _ = send.send_data(Bytes::from(body), true);
                        }
                    }
                } else if let Ok(head) = read_until_double_crlf(&mut tls).await {
                    if head.is_empty() {
                        return;
                    }
                    let body = head.lines().next().unwrap();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tls.write_all(response.as_bytes()).await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    Ok((addr, task))
}

#[tokio::test]
async fn inspected_http1_and_http2_work_inside_tls_proxy_connections() -> Result<()> {
    for h2 in [false, true] {
        let dirs = TestDirs::new()?;
        let ca = CertificateAuthority::load_builtin(&dirs.ca_dir)?;
        let (upstream, task) = tls_upstream(&ca, h2).await?;
        let mut roots = RootCertStore::empty();
        roots.add(ca.root_certificate_der())?;
        let (clients, policies) = TestConfigBuilder::new()
            .default_client(&["inspect"])
            .policy(PolicySpec::new("inspect").rule(RuleSpec::allow(
                &["GET"],
                format!("https://localhost:{}/**", upstream.port()),
            )))
            .render();
        let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
            .with_proxy_root_store(roots.clone())
            .with_tls_proxy()
            .spawn()
            .await?;
        let mut outer = harness.connect_tls().await?;
        outer
            .write_all(
                format!(
                    "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
                    upstream.port(),
                    upstream.port()
                )
                .as_bytes(),
            )
            .await?;
        assert!(
            read_until_double_crlf(&mut outer)
                .await?
                .starts_with("HTTP/1.1 200")
        );
        let config = if h2 {
            build_client_tls_h2_only(roots)?
        } else {
            build_client_tls(roots)?
        };
        let mut inner = TlsConnector::from(config)
            .connect(ServerName::try_from("localhost")?, outer)
            .await?;
        if h2 {
            let (mut sender, connection) = h2::client::handshake(inner).await?;
            let driver = tokio::spawn(connection);
            let request = http::Request::builder()
                .uri(format!(
                    "https://localhost:{}/signed%2Fpath?q=%2f",
                    upstream.port()
                ))
                .body(())?;
            let (response, _) = sender.send_request(request, true)?;
            let mut body = response.await?.into_body();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk?;
                body.flow_control().release_capacity(chunk.len())?;
                bytes.extend_from_slice(&chunk);
            }
            assert_eq!(bytes, b"/signed%2Fpath?q=%2f\nhost=false");
            driver.abort();
        } else {
            inner.write_all(format!("GET /signed%2Fpath?q=%2f HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n", upstream.port()).as_bytes()).await?;
            let response = read_http_response_with_length(&mut inner).await?;
            assert!(
                response.ends_with("GET /signed%2Fpath?q=%2f HTTP/1.1"),
                "{response}"
            );
        }
        harness.shutdown().await;
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn tls_validation_and_handshake_failures_release_client_capacity() -> Result<()> {
    let (clients, policies) = TestConfigBuilder::new()
        .fallback_client_with_max_connections("handshake-test", &["deny"], 1)
        .policy(PolicySpec::new("deny").rule(RuleSpec::deny(&["ANY"], "http://**/**").status(403)))
        .render();
    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .with_tls_proxy()
        .with_settings(|s| s.tls_handshake_timeout = 1)
        .spawn()
        .await?;
    wait_for_handshake_connections(0).await?;
    let stalled = harness.connect().await?;
    wait_for_handshake_connections(1).await?;
    assert!(harness.connect_tls().await.is_err());
    let mut byte = [0];
    let mut stalled = stalled;
    assert!(matches!(
        timeout(Duration::from_secs(2), stalled.read(&mut byte)).await?,
        Ok(0) | Err(_)
    ));
    drop(stalled);
    wait_for_handshake_connections(0).await?;
    for (roots, name) in [
        (RootCertStore::empty(), "localhost"),
        (harness.proxy_tls_roots.clone(), "wrong.example"),
    ] {
        let connector = TlsConnector::from(build_client_tls(roots)?);
        assert!(
            connector
                .connect(ServerName::try_from(name)?, harness.connect().await?)
                .await
                .is_err()
        );
        wait_for_handshake_connections(0).await?;
    }
    let mut plain = harness.connect().await?;
    plain
        .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await?;
    match timeout(Duration::from_secs(2), plain.read(&mut byte)).await? {
        Ok(0) | Err(_) => {}
        Ok(_) => assert_eq!(byte[0], 0x15, "expected a TLS alert record"),
    }
    drop(plain);
    wait_for_handshake_connections(0).await?;
    let config = build_client_tls_with_protocols(harness.proxy_tls_roots.clone(), vec![])?;
    let mut valid = TlsConnector::from(config)
        .connect(ServerName::try_from("localhost")?, harness.connect().await?)
        .await?;
    assert!(valid.get_ref().1.alpn_protocol().is_none());
    valid
        .write_all(
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await?;
    assert!(
        read_http_response(&mut valid)
            .await?
            .starts_with("HTTP/1.1 403")
    );
    harness.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn trusted_proxy_protocol_is_read_before_tls() -> Result<()> {
    let upstream = TestUpstream::http_ok("forwarded client").await?;
    let (clients, policies) = TestConfigBuilder::new()
        .client_ip("forwarded", "203.0.113.10", &["allow"])
        .default_client(&["deny"])
        .policy(PolicySpec::new("deny").rule(RuleSpec::deny(&["ANY"], "http://**/**").status(403)))
        .policy(PolicySpec::new("allow").rule(RuleSpec::allow_any(format!(
            "http://{}/**",
            upstream.addr()
        ))))
        .render();
    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .with_tls_proxy()
        .with_settings(|s| {
            s.proxy_protocol = ProxyProtocolMode::Required;
            s.proxy_protocol_allowed_cidrs = Some(vec!["127.0.0.1/32".parse().unwrap()]);
        })
        .spawn()
        .await?;
    let mut v2 = b"\r\n\r\n\0\r\nQUIT\n\x21\x11\0\x0c".to_vec();
    v2.extend_from_slice(&[203, 0, 113, 10, 127, 0, 0, 1, 0x30, 0x39, 0x0c, 0x38]);
    for header in [
        b"PROXY TCP4 203.0.113.10 127.0.0.1 12345 3128\r\n".to_vec(),
        v2,
    ] {
        let mut tcp = harness.connect().await?;
        tcp.write_all(&header).await?;
        let connector = TlsConnector::from(build_client_tls(harness.proxy_tls_roots.clone())?);
        let mut tls = connector
            .connect(ServerName::try_from("localhost")?, tcp)
            .await?;
        tls.write_all(
            format!(
                "GET http://{}/ HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                upstream.addr(),
                upstream.addr()
            )
            .as_bytes(),
        )
        .await?;
        assert!(
            read_http_response(&mut tls)
                .await?
                .ends_with("forwarded client")
        );
    }
    harness.shutdown().await;
    Ok(())
}
