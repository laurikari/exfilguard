mod cache;
mod forward;
mod handler;
mod parse;
mod respond;

use std::time::Instant;

use http::Method;

use crate::config::Scheme;

use super::codec::Http1HeaderAccumulator;

pub use parse::handle_non_connect;
pub use respond::{respond_with_access_log, shutdown_stream};

pub enum ClientDisposition {
    Continue,
    Close,
}

pub struct RequestContext {
    pub method: Method,
    pub target: String,
    pub headers: Http1HeaderAccumulator,
    pub request_line_bytes: usize,
    pub header_bytes: usize,
    pub start: Instant,
    pub fallback_scheme: Scheme,
    pub snapshot: crate::policy::matcher::PolicySnapshot,
    pub authorization_token: Option<std::sync::Arc<crate::authorization::AuthorizationToken>>,
    pub client_name: Option<std::sync::Arc<str>>,
}

impl RequestContext {
    pub fn total_request_bytes(&self) -> u64 {
        (self.request_line_bytes + self.header_bytes) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cli::LogFormat,
        config,
        config::Scheme,
        policy::{self, matcher::PolicySnapshot},
        proxy::{self, PolicyStore, http::upstream::UpstreamPool},
        settings::{CaSettings, ProxyProtocolMode, Settings},
        tls::{ca::CertificateAuthority, cache::CertificateCache, issuer::TlsIssuer},
    };
    use anyhow::Result;
    use http::Method;
    use rustls::{RootCertStore, client::ClientConfig, crypto::ring};
    use std::{net::SocketAddr, sync::Arc, time::Instant};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, BufReader};
    use tokio::sync::watch;

    async fn build_test_app(temp: &TempDir) -> Result<proxy::AppContext> {
        let workspace = temp.path();
        let ca_dir = workspace.join("ca");
        let config_dir = workspace.join("config");
        std::fs::create_dir_all(&config_dir)?;

        let clients_path = config_dir.join("clients.toml");
        let policies_path = config_dir.join("policies.toml");

        std::fs::write(
            &clients_path,
            r#"[[client]]
name = "default"
policies = ["allow"]
fallback = true
"#,
        )?;

        std::fs::write(
            &policies_path,
            r#"[[policy]]
name = "allow"
  [[policy.rule]]
  action = "ALLOW"
"#,
        )?;

        let settings = Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            max_connections: 4096,
            proxy_tls: None,
            authentication: Default::default(),
            proxy_protocol: ProxyProtocolMode::Off,
            proxy_protocol_allowed_cidrs: None,
            allow_private_upstream_cidrs: Vec::new(),
            proxy_protocol_max_pending_connections: 1024,
            vault: None,
            ca: CaSettings::Builtin {
                dir: ca_dir.clone(),
            },
            clients: clients_path.clone(),
            clients_dir: None,
            policies: policies_path.clone(),
            policies_dir: None,
            authorization: None,
            log: LogFormat::Text,
            leaf_ttl: 3600,
            leaf_cache_capacity: 4,
            leaf_mint_concurrency: 2,
            log_queries: false,
            dns_resolve_timeout: 1,
            upstream_connect_timeout: 1,
            tls_handshake_timeout: 1,
            request_header_timeout: 1,
            request_body_idle_timeout: 1,
            response_header_timeout: 1,
            response_body_idle_timeout: 1,
            request_total_timeout: 0,
            client_keepalive_idle_timeout: 1,
            connect_tunnel_idle_timeout: 1,
            connect_tunnel_max_lifetime: 0,
            upstream_pool_capacity: 4,
            http2_max_concurrent_streams: 100,
            http2_stream_window_size: 32 * 1024 * 1024,
            http2_connection_window_size: 64 * 1024 * 1024,
            http2_receive_window_budget: None,
            max_request_header_size: 4096,
            max_response_header_size: 4096,
            max_request_body_size: 1024 * 1024,
            cache_dir: None,
            cache_max_entry_size: 10 * 1024 * 1024,
            cache_max_entries: 10_000,
            cache_total_capacity: 1024 * 1024 * 1024,
            cache_sweeper_interval: 300,
            cache_sweeper_batch_size: 1000,
            metrics_listen: None,
            metrics_tls_cert: None,
            metrics_tls_key: None,
        };

        let ca = Arc::new(CertificateAuthority::load_builtin(&ca_dir)?);
        let cert_cache = Arc::new(CertificateCache::new(settings.leaf_cache_capacity)?);
        let tls_issuer = Arc::new(TlsIssuer::new(
            ca.clone(),
            cert_cache,
            settings.leaf_ttl(),
            settings.leaf_mint_concurrency,
        )?);
        let config_doc = config::load_config(&clients_path, &policies_path)?;
        let compiled = Arc::new(policy::compile::compile_config(&config_doc)?);
        let snapshot = PolicySnapshot::new(compiled);
        let (_tx, rx) = watch::channel(snapshot);
        let policy_store = PolicyStore::new(rx);
        let tls_client_config = Arc::new(build_test_client_config());
        let tls_client_h2_config = Arc::new(build_test_client_config_h2());
        let tls_context = Arc::new(proxy::TlsContext::new(
            tls_issuer,
            tls_client_config,
            tls_client_h2_config,
        ));

        proxy::AppContext::new(Arc::new(settings), policy_store, tls_context, None).await
    }

    fn build_test_client_config() -> ClientConfig {
        build_test_client_config_with_alpn(vec![b"http/1.1".to_vec()])
    }

    fn build_test_client_config_h2() -> ClientConfig {
        build_test_client_config_with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
    }

    fn build_test_client_config_with_alpn(protocols: Vec<Vec<u8>>) -> ClientConfig {
        let provider = ring::default_provider();
        let builder = ClientConfig::builder_with_provider(provider.into());
        let builder = builder.with_safe_default_protocol_versions().unwrap();
        let root_store = Arc::new(RootCertStore::empty());
        let mut config = builder
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = protocols;
        config
    }

    #[tokio::test]
    async fn shadowed_inspection_allows_are_rejected_before_resolution() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        use crate::authentication::ConnectionSession;
        use crate::proxy::resolver::{FilteredAddresses, UpstreamResolver};
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;
        use tokio::time::timeout;

        struct RecordingResolver {
            calls: AtomicUsize,
            upstream: SocketAddr,
        }

        #[async_trait::async_trait]
        impl UpstreamResolver for RecordingResolver {
            async fn resolve_filtered(
                &self,
                _host: &str,
                _port: u16,
                _timeout: Duration,
                _context: &'static str,
            ) -> Result<FilteredAddresses> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(FilteredAddresses {
                    allowed: vec![self.upstream],
                    filtered_private: 0,
                })
            }
        }

        std::fs::create_dir_all("/tmp/exfilguard")?;
        let temp = tempfile::Builder::new()
            .prefix("preflight-")
            .tempdir_in("/tmp/exfilguard")?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let resolver = Arc::new(RecordingResolver {
            calls: AtomicUsize::new(0),
            upstream: listener.local_addr()?,
        });
        let mut app = build_test_app(&temp)
            .await?
            .with_upstream_resolver(resolver.clone());
        let port = resolver.upstream.port();
        for split_policies in [false, true] {
            for methods in ["ANY", "GET"] {
                let client_policies = if split_policies {
                    r#"["deny", "allow"]"#
                } else {
                    r#"["allow"]"#
                };
                std::fs::write(
                    &app.settings.clients,
                    format!(
                        "[[client]]\nname = \"default\"\nfallback = true\npolicies = {client_policies}\n"
                    ),
                )?;
                let denied = format!(
                    r#"
[[policy.rule]]
action = "DENY"
status = 470
methods = ["{methods}"]
url_pattern = "https://*.example.test:{port}/**"
"#
                );
                let allowed = format!(
                    r#"
[[policy.rule]]
action = "ALLOW"
methods = ["GET"]
url_pattern = "https://*.example.test:{port}/safe"
"#
                );
                let policies = if split_policies {
                    format!(
                        "[[policy]]\nname = \"deny\"\n{denied}\n[[policy]]\nname = \"allow\"\n{allowed}"
                    )
                } else {
                    format!("[[policy]]\nname = \"allow\"\n{denied}\n{allowed}")
                };
                std::fs::write(&app.settings.policies, policies)?;
                let compiled =
                    policy::compile::compile_config(&app.settings.load_runtime_config()?)?;
                let (_tx, rx) = watch::channel(PolicySnapshot::new(Arc::new(compiled)));
                app.policies = PolicyStore::new(rx);

                let authority = format!("secret.example.test:{port}");
                for (request_line, expected_status) in [
                    (format!("GET https://{authority}/safe HTTP/1.1"), 470),
                    (format!("CONNECT {authority} HTTP/1.1"), 403),
                ] {
                    let (mut client, server) = tokio::io::duplex(4096);
                    let task = tokio::spawn(proxy::http::handle_http(
                        server,
                        "127.0.0.1:12345".parse()?,
                        app.clone(),
                        ConnectionSession::new(None),
                    ));
                    client
                        .write_all(
                            format!(
                                "{request_line}\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
                            )
                            .as_bytes(),
                        )
                        .await?;
                    client.shutdown().await?;
                    let mut response = String::new();
                    timeout(Duration::from_secs(5), client.read_to_string(&mut response)).await??;
                    task.await??;
                    assert!(
                        response.starts_with(&format!("HTTP/1.1 {expected_status}")),
                        "{response}"
                    );
                    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0, "{request_line}");
                }
            }
        }
        assert!(
            timeout(Duration::from_millis(10), listener.accept())
                .await
                .is_err(),
            "shadowed allow caused an upstream connection"
        );
        Ok(())
    }

    #[tokio::test]
    async fn parse_errors_return_bad_request() -> Result<()> {
        let temp = TempDir::new()?;
        let app = build_test_app(&temp).await?;
        let (client_side, server_side) = tokio::io::duplex(1024);
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut reader = BufReader::new(server_side);
        let mut upstream_pool = UpstreamPool::new(app.settings.upstream_pool_capacity_nonzero());
        let mut headers = Http1HeaderAccumulator::new(1024);
        headers.push_line("User-Agent: test\r\n")?;
        headers.push_line("\r\n")?;
        let header_bytes = headers.total_bytes();
        let ctx = RequestContext {
            method: Method::GET,
            target: "/".to_string(),
            headers,
            request_line_bytes: 16,
            header_bytes,
            start: Instant::now(),
            fallback_scheme: Scheme::Http,
            snapshot: app.policies.snapshot(),
            authorization_token: None,
            client_name: None,
        };

        let result =
            handle_non_connect(&mut reader, peer, &app, &mut upstream_pool, ctx, None, None)
                .await?;
        assert!(matches!(result, ClientDisposition::Close));

        drop(reader);
        let mut buf = Vec::new();
        let mut client_side = client_side;
        client_side.read_to_end(&mut buf).await?;
        let body = String::from_utf8_lossy(&buf);
        assert!(body.starts_with("HTTP/1.1 400"));
        assert!(body.contains("invalid request target"));
        Ok(())
    }

    #[tokio::test]
    async fn unsupported_expect_header_returns_417() -> Result<()> {
        let temp = TempDir::new()?;
        let app = build_test_app(&temp).await?;
        let (mut client_side, server_side) = tokio::io::duplex(1024);
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut reader = BufReader::new(server_side);
        let mut upstream_pool = UpstreamPool::new(app.settings.upstream_pool_capacity_nonzero());

        let mut headers = Http1HeaderAccumulator::new(1024);
        headers.push_line("Host: example.com\r\n")?;
        headers.push_line("Expect: custom\r\n")?;
        headers.push_line("Content-Length: 10\r\n")?;
        headers.push_line("\r\n")?;
        let header_bytes = headers.total_bytes();
        let ctx = RequestContext {
            method: Method::POST,
            target: "/".to_string(),
            headers,
            request_line_bytes: 18,
            header_bytes,
            start: Instant::now(),
            fallback_scheme: Scheme::Http,
            snapshot: app.policies.snapshot(),
            authorization_token: None,
            client_name: None,
        };

        let result =
            handle_non_connect(&mut reader, peer, &app, &mut upstream_pool, ctx, None, None)
                .await?;
        assert!(matches!(result, ClientDisposition::Close));

        drop(reader);
        let mut buf = Vec::new();
        client_side.read_to_end(&mut buf).await?;
        let body = String::from_utf8_lossy(&buf);
        assert!(body.starts_with("HTTP/1.1 417"));
        assert!(body.contains("expectation failed"));
        Ok(())
    }

    #[tokio::test]
    async fn oversized_content_length_returns_413() -> Result<()> {
        let temp = TempDir::new()?;
        let app = build_test_app(&temp).await?;
        let (mut client_side, server_side) = tokio::io::duplex(1024);
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut reader = BufReader::new(server_side);
        let mut upstream_pool = UpstreamPool::new(app.settings.upstream_pool_capacity_nonzero());
        let oversized = app.settings.max_request_body_size + 1;

        let mut headers = Http1HeaderAccumulator::new(1024);
        headers.push_line("Host: example.com\r\n")?;
        headers.push_line(&format!("Content-Length: {oversized}\r\n"))?;
        headers.push_line("\r\n")?;
        let header_bytes = headers.total_bytes();
        let ctx = RequestContext {
            method: Method::POST,
            target: "/".to_string(),
            headers,
            request_line_bytes: 18,
            header_bytes,
            start: Instant::now(),
            fallback_scheme: Scheme::Http,
            snapshot: app.policies.snapshot(),
            authorization_token: None,
            client_name: None,
        };

        let result =
            handle_non_connect(&mut reader, peer, &app, &mut upstream_pool, ctx, None, None)
                .await?;
        assert!(matches!(result, ClientDisposition::Close));

        drop(reader);
        let mut buf = Vec::new();
        client_side.read_to_end(&mut buf).await?;
        let body = String::from_utf8_lossy(&buf);
        assert!(body.starts_with("HTTP/1.1 413"));
        assert!(body.contains("request body exceeds configured limit"));
        Ok(())
    }
}
