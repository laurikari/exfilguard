mod support;

use std::{net::SocketAddr, time::Duration};

use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use exfilguard::{config, tls::ca::CertificateAuthority};
use rustls::{RootCertStore, pki_types::ServerName};
use support::*;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const PASSWORD: &str = "correctbatteryhorsestapler";
const HASH: &str = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";

fn basic(user: &str, password: &str) -> String {
    format!(
        "Proxy-Authorization: Basic {}\r\n",
        STANDARD.encode(format!("{user}:{password}"))
    )
}

fn password_client(name: &str, cidr: &str, policy: &str) -> String {
    format!(
        "\n[[client]]\nname='{name}'\ncidr='{cidr}'\npassword_hash='{HASH}'\npolicies=['{policy}']\nmax_connections=1\n"
    )
}

fn configuration(origin: SocketAddr) -> (String, String) {
    let (mut clients, policies) = TestConfigBuilder::new()
        .fallback_client("node", &["packages"])
        .policy(PolicySpec::new("packages").rule(RuleSpec::allow(
            &["GET"],
            format!("http://{origin}/ubuntu/**"),
        )))
        .policy(PolicySpec::new("alice-policy").rule(RuleSpec::allow(
            &["GET"],
            format!("http://{origin}/alice/**"),
        )))
        .policy(
            PolicySpec::new("bob-policy")
                .rule(RuleSpec::allow(&["GET"], format!("http://{origin}/bob/**"))),
        )
        .render();
    clients.push_str(&password_client("alice", "127.0.0.0/8", "alice-policy"));
    clients.push_str(&password_client("bob", "127.0.0.0/8", "bob-policy"));
    clients.push_str(&password_client("remote", "192.0.2.0/24", "bob-policy"));
    (clients, policies)
}

async fn request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    origin: SocketAddr,
    path: &str,
    credentials: &str,
) -> Result<String> {
    stream.write_all(format!("GET http://{origin}{path} HTTP/1.1\r\nHost: {origin}\r\n{credentials}Connection: keep-alive\r\n\r\n").as_bytes()).await?;
    timeout(
        Duration::from_secs(5),
        read_http_response_with_length(stream),
    )
    .await?
}

#[tokio::test]
async fn anonymous_and_password_policies_are_separate() -> Result<()> {
    let logs = LogCapture::new("info").await;
    let origin = TestUpstream::http_response(
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\norigin",
    )
    .await?;
    let (clients, policies) = configuration(origin.addr());
    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .with_tls_proxy()
        .spawn()
        .await?;

    for (path, credentials, status) in [
        ("/ubuntu/package", String::new(), "200"),
        ("/alice/api", String::new(), "407"),
        (
            "/ubuntu/package",
            basic("alice", "incorrect-password"),
            "407",
        ),
        ("/ubuntu/package", basic("unknown", PASSWORD), "407"),
        ("/ubuntu/package", basic("remote", PASSWORD), "407"),
        (
            "/ubuntu/package",
            "Proxy-Authorization: Basic !!!\r\n".into(),
            "407",
        ),
        (
            "/ubuntu/package",
            format!("{}{}", basic("alice", PASSWORD), basic("alice", PASSWORD)),
            "407",
        ),
        ("/ubuntu/package", basic("alice", PASSWORD), "403"),
        ("/bob/api", basic("bob", PASSWORD), "200"),
    ] {
        let mut stream = harness.connect_tls().await?;
        let response = request(&mut stream, origin.addr(), path, &credentials).await?;
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{path}: {response}"
        );
        if status == "407" {
            assert!(response.contains("Proxy-Authenticate: Basic realm=\"exfilguard\""));
        }
    }
    let mut alice = harness.connect_tls().await?;
    for credentials in [
        basic("alice", PASSWORD),
        String::new(),
        basic("alice", PASSWORD),
    ] {
        assert!(
            request(&mut alice, origin.addr(), "/alice/api", &credentials)
                .await?
                .starts_with("HTTP/1.1 200")
        );
    }
    assert!(
        request(
            &mut alice,
            origin.addr(),
            "/bob/api",
            &basic("bob", PASSWORD)
        )
        .await?
        .starts_with("HTTP/1.1 407")
    );
    let text = logs.wait_for("proxy_authentication").await?;
    assert!(!text.contains(PASSWORD));
    assert!(!text.contains(HASH));
    assert!(!text.contains(&STANDARD.encode(format!("alice:{PASSWORD}"))));
    harness.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn admission_limits_apply_to_the_selected_identity() -> Result<()> {
    let origin = TestUpstream::http_response(
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\norigin",
    )
    .await?;
    let (clients, policies) = configuration(origin.addr());
    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .with_tls_proxy()
        .spawn()
        .await?;
    let mut alice = harness.connect_tls().await?;
    assert!(
        request(
            &mut alice,
            origin.addr(),
            "/alice/api",
            &basic("alice", PASSWORD)
        )
        .await?
        .starts_with("HTTP/1.1 200")
    );
    let mut excess = harness.connect_tls().await?;
    assert!(
        request(
            &mut excess,
            origin.addr(),
            "/alice/api",
            &basic("alice", PASSWORD)
        )
        .await?
        .starts_with("HTTP/1.1 503")
    );
    let mut bob = harness.connect_tls().await?;
    assert!(
        request(&mut bob, origin.addr(), "/bob/api", &basic("bob", PASSWORD))
            .await?
            .starts_with("HTTP/1.1 200")
    );
    let mut anonymous = harness.connect_tls().await?;
    assert!(
        request(&mut anonymous, origin.addr(), "/ubuntu/package", "")
            .await?
            .starts_with("HTTP/1.1 200")
    );
    drop(alice);
    timeout(Duration::from_secs(3), async {
        loop {
            let mut stream = harness.connect_tls().await?;
            if request(
                &mut stream,
                origin.addr(),
                "/alice/api",
                &basic("alice", PASSWORD),
            )
            .await?
            .starts_with("HTTP/1.1 200")
            {
                break Ok::<_, anyhow::Error>(());
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    harness.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn pending_limit_covers_tls_connections_without_request_headers() -> Result<()> {
    let origin = TestUpstream::http_response(
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\norigin",
    )
    .await?;
    let (clients, policies) = configuration(origin.addr());
    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .with_settings(|settings| settings.authentication.max_pending_connections = 1)
        .with_tls_proxy()
        .spawn()
        .await?;
    let first = timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(stream) = harness.connect_tls().await {
                break stream;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert!(harness.connect_tls().await.is_err());
    drop(first);
    timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(mut stream) = harness.connect_tls().await {
                assert!(
                    request(
                        &mut stream,
                        origin.addr(),
                        "/alice/api",
                        &basic("alice", PASSWORD)
                    )
                    .await?
                    .starts_with("HTTP/1.1 200")
                );
                break Ok::<_, anyhow::Error>(());
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    harness.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn reload_revokes_credentials_but_preserves_policy_only_sessions() -> Result<()> {
    for change in ["hash", "remove", "source"] {
        let origin = TestUpstream::http_response(
            "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\norigin",
        )
        .await?;
        let (clients, policies) = configuration(origin.addr());
        let harness = ProxyHarnessBuilder::new(&clients, &policies)?
            .with_tls_proxy()
            .spawn()
            .await?;
        let mut stream = harness.connect_tls().await?;
        assert!(
            request(
                &mut stream,
                origin.addr(),
                "/alice/api",
                &basic("alice", PASSWORD)
            )
            .await?
            .starts_with("HTTP/1.1 200")
        );
        let denied = policies.replace("/alice/**", "/different/**");
        harness.reload(&clients, &denied)?;
        assert!(
            request(&mut stream, origin.addr(), "/alice/api", "")
                .await?
                .starts_with("HTTP/1.1 403")
        );
        // Policy denial closes HTTP/1; establish another authenticated session.
        harness.reload(&clients, &policies)?;
        let mut stream = harness.connect_tls().await?;
        assert!(
            request(
                &mut stream,
                origin.addr(),
                "/alice/api",
                &basic("alice", PASSWORD)
            )
            .await?
            .starts_with("HTTP/1.1 200")
        );
        assert!(
            harness
                .reload(&clients.replace(HASH, "invalid-hash"), &policies)
                .is_err()
        );
        assert!(
            request(&mut stream, origin.addr(), "/alice/api", "")
                .await?
                .starts_with("HTTP/1.1 200")
        );
        let changed = match change {
            "hash" => clients.replacen(HASH, &bcrypt::non_truncating_hash("new-password", 4)?, 1),
            "source" => clients.replacen("127.0.0.0/8", "198.51.100.0/24", 1),
            _ => clients.replace(&password_client("alice", "127.0.0.0/8", "alice-policy"), ""),
        };
        harness.reload(&changed, &policies)?;
        let mut byte = [0];
        let result = timeout(Duration::from_secs(3), stream.read(&mut byte)).await?;
        assert!(
            matches!(result, Ok(0) | Err(_)),
            "session not revoked: {change}"
        );
        harness.shutdown().await;
    }
    Ok(())
}

#[tokio::test]
async fn password_clients_require_tls_and_validate_selector_classes() -> Result<()> {
    let origin = TestUpstream::http_response(
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\norigin",
    )
    .await?;
    let (clients, policies) = configuration(origin.addr());
    let error = ProxyHarnessBuilder::new(&clients, &policies)?
        .spawn()
        .await
        .err()
        .expect("TLS required");
    assert!(error.to_string().contains("require [proxy_tls]"));
    let dirs = TestDirs::new()?;
    for (extra, allowed) in [
        (
            "[[client]]\nname='node-net'\ncidr='127.0.0.0/8'\npolicies=['packages']\n",
            true,
        ),
        (
            "[[client]]\nname='lease'\ncidr='127.0.0.0/8'\npolicies=['packages']\nauthorization_service='central'\n",
            true,
        ),
        (
            "[[client]]\nname='lease'\ncidr='127.0.0.0/8'\npolicies=['packages']\nauthorization_service='central'\n[[client]]\nname='lease2'\nip='127.0.0.1'\npolicies=['packages']\nauthorization_service='central'\n",
            false,
        ),
        (
            "[[client]]\nname='node1'\ncidr='127.0.0.0/8'\npolicies=['packages']\n[[client]]\nname='node2'\nip='127.0.0.1'\npolicies=['packages']\n",
            false,
        ),
    ] {
        write_clients_and_policies(&dirs, &format!("{clients}\n{extra}"), &policies)?;
        assert_eq!(
            config::load_config(&dirs.clients_path, &dirs.policies_path).is_ok(),
            allowed
        );
    }
    for invalid in [
        clients.replacen("name='alice'", "name='a:b'", 1),
        clients.replacen("name='alice'", "name='bob'", 1),
        clients.replacen(
            "password_hash=",
            "authorization_service='central'\npassword_hash=",
            1,
        ),
        clients.replacen(HASH, "$1$unsupported$hash", 1),
        clients.replacen("cidr='127.0.0.0/8'", "", 1),
    ] {
        write_clients_and_policies(&dirs, &invalid, &policies)?;
        let error = config::load_config(&dirs.clients_path, &dirs.policies_path).unwrap_err();
        assert!(!format!("{error:#}").contains(HASH));
    }
    // TOML source excerpts may contain hashes even when another field is invalid.
    write_clients_and_policies(
        &dirs,
        &clients.replacen(HASH, &format!("{HASH}' invalid='value"), 1),
        &policies,
    )?;
    let error = config::load_config(&dirs.clients_path, &dirs.policies_path).unwrap_err();
    assert!(!format!("{error:#}").contains(HASH));
    for field in ["max_pending_connections", "max_concurrent_verifications"] {
        let builder = ProxyHarnessBuilder::new(&clients, &policies)?
            .with_tls_proxy()
            .with_settings(move |settings| {
                if field == "max_pending_connections" {
                    settings.authentication.max_pending_connections = 0;
                } else {
                    settings.authentication.max_concurrent_verifications = 0;
                }
            });
        assert!(builder.spawn().await.is_err(), "{field}");
    }
    Ok(())
}

#[tokio::test]
async fn password_tunnel_is_revoked_on_reload() -> Result<()> {
    let echo = TestUpstream::echo().await?;
    let (_, policies) = TestConfigBuilder::new()
        .policy(PolicySpec::new("deny").rule(RuleSpec::deny(&["ANY"], "http://**/**").status(403)))
        .policy(
            PolicySpec::new("tunnel").rule(
                RuleSpec::allow(&["CONNECT"], format!("https://{}/**", echo.addr()))
                    .https_mode("tunnel"),
            ),
        )
        .render();
    let clients = format!(
        "{}\n[[client]]\nname='node'\nfallback=true\npolicies=['deny']\n",
        password_client("alice", "127.0.0.0/8", "tunnel")
    );
    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .with_tls_proxy()
        .spawn()
        .await?;
    let mut stream = harness.connect_tls().await?;
    stream
        .write_all(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n{}\r\npayload",
                echo.addr(),
                echo.addr(),
                basic("alice", PASSWORD)
            )
            .as_bytes(),
        )
        .await?;
    assert!(
        read_until_double_crlf(&mut stream)
            .await?
            .starts_with("HTTP/1.1 200")
    );
    let mut payload = [0; 7];
    timeout(Duration::from_secs(3), stream.read_exact(&mut payload)).await??;
    assert_eq!(&payload, b"payload");
    let changed = clients.replace(HASH, &bcrypt::non_truncating_hash("new-password", 4)?);
    harness.reload(&changed, &policies)?;
    let mut byte = [0];
    assert!(matches!(
        timeout(Duration::from_secs(3), stream.read(&mut byte)).await?,
        Ok(0) | Err(_)
    ));
    harness.shutdown().await;
    Ok(())
}

async fn authenticated_tls_origin(
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
                            "{}\nauth={}",
                            request.uri().path(),
                            request.headers().contains_key("proxy-authorization")
                        );
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        if let Ok(mut send) = respond.send_response(response, false) {
                            let _ = send.send_data(Bytes::from(body), true);
                        }
                    }
                } else {
                    while let Ok(head) = read_until_double_crlf(&mut tls).await {
                        if head.is_empty() {
                            break;
                        }
                        let body = format!(
                            "{}\nauth={}",
                            head.lines().next().unwrap(),
                            head.to_ascii_lowercase().contains("proxy-authorization:")
                        );
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        );
                        if tls.write_all(response.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });
    Ok((addr, task))
}

#[tokio::test]
async fn password_identity_survives_inspected_http1_and_http2() -> Result<()> {
    for h2 in [false, true] {
        let dirs = TestDirs::new()?;
        let ca = CertificateAuthority::load_builtin(&dirs.ca_dir)?;
        let (origin, origin_task) = authenticated_tls_origin(&ca, h2).await?;
        let mut roots = RootCertStore::empty();
        roots.add(ca.root_certificate_der())?;
        let (_, policies) = TestConfigBuilder::new()
            .policy(
                PolicySpec::new("deny").rule(RuleSpec::deny(&["ANY"], "http://**/**").status(403)),
            )
            .policy(PolicySpec::new("inspect").rule(RuleSpec::allow(
                &["GET"],
                format!("https://localhost:{}/alice/**", origin.port()),
            )))
            .render();
        let clients = format!(
            "{}\n[[client]]\nname='node'\nfallback=true\npolicies=['deny']\n",
            password_client("alice", "127.0.0.0/8", "inspect")
        );
        let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
            .with_proxy_root_store(roots.clone())
            .with_tls_proxy()
            .spawn()
            .await?;
        // An authenticated policy denial is 403, including CONNECT preflight.
        let mut denied = harness.connect_tls().await?;
        denied
            .write_all(
                format!(
                    "CONNECT other.example:443 HTTP/1.1\r\nHost: other.example:443\r\n{}\r\n",
                    basic("alice", PASSWORD)
                )
                .as_bytes(),
            )
            .await?;
        assert!(
            read_http_response_with_length(&mut denied)
                .await?
                .starts_with("HTTP/1.1 403")
        );
        drop(denied);
        let mut outer = harness.connect_tls().await?;
        outer
            .write_all(
                format!(
                    "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n{}\r\n",
                    origin.port(),
                    origin.port(),
                    basic("alice", PASSWORD)
                )
                .as_bytes(),
            )
            .await?;
        let response = read_until_double_crlf(&mut outer).await?;
        ensure!(response.starts_with("HTTP/1.1 200"), "{response}");
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
            for (credentials, expected) in [
                (None, 200),
                (Some(PASSWORD), 200),
                (Some("wrong"), 407),
                (None, 200),
            ] {
                let mut builder = http::Request::builder()
                    .uri(format!("https://localhost:{}/alice/api", origin.port()));
                if let Some(password) = credentials {
                    builder = builder.header(
                        "proxy-authorization",
                        format!("Basic {}", STANDARD.encode(format!("alice:{password}"))),
                    );
                }
                let (response, _) = sender.send_request(builder.body(())?, true)?;
                let response = timeout(Duration::from_secs(5), response).await??;
                assert_eq!(response.status().as_u16(), expected);
                let mut body = response.into_body();
                let mut bytes = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk?;
                    body.flow_control().release_capacity(chunk.len())?;
                    bytes.extend_from_slice(&chunk);
                }
                if expected == 200 {
                    assert_eq!(bytes, b"/alice/api\nauth=false");
                }
            }
            // Revocation must also terminate an idle multiplexed connection.
            harness.reload(
                &clients.replace(HASH, &bcrypt::non_truncating_hash("new-password", 4)?),
                &policies,
            )?;
            let _ = timeout(Duration::from_secs(3), driver).await?;
        } else {
            for credentials in [String::new(), basic("alice", PASSWORD)] {
                inner
                    .write_all(
                        format!(
                            "GET /alice/api HTTP/1.1\r\nHost: localhost:{}\r\n{credentials}\r\n",
                            origin.port()
                        )
                        .as_bytes(),
                    )
                    .await?;
                let response = timeout(
                    Duration::from_secs(5),
                    read_http_response_with_length(&mut inner),
                )
                .await??;
                assert!(response.starts_with("HTTP/1.1 200"), "{response}");
                assert!(response.ends_with("auth=false"), "{response}");
            }
            inner
                .write_all(
                    format!(
                        "GET /alice/api HTTP/1.1\r\nHost: localhost:{}\r\n{}\r\n",
                        origin.port(),
                        basic("alice", "wrong")
                    )
                    .as_bytes(),
                )
                .await?;
            assert!(
                read_http_response_with_length(&mut inner)
                    .await?
                    .starts_with("HTTP/1.1 407")
            );
        }
        harness.shutdown().await;
        origin_task.abort();
    }
    Ok(())
}
