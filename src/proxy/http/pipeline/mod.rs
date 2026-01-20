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
pub use respond::{respond_with_access_log, send_response, shutdown_stream};

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
        settings::{ProxyProtocolMode, Settings},
        tls::{ca::CertificateAuthority, cache::CertificateCache, issuer::TlsIssuer},
    };
    use anyhow::Result;
    use http::Method;
    use rustls::{RootCertStore, client::ClientConfig, crypto::ring};
    use std::{net::SocketAddr, sync::Arc, time::Instant};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, BufReader};
    use tokio::sync::watch;

    fn build_test_app(temp: &TempDir) -> Result<proxy::AppContext> {
        let workspace = temp.path();
        let ca_dir = workspace.join("ca");
        let config_dir = workspace.join("config");
        std::fs::create_dir_all(&ca_dir)?;
        std::fs::create_dir_all(&config_dir)?;

        let clients_path = config_dir.join("clients.toml");
        let policies_path = config_dir.join("policies.toml");

        std::fs::write(
            &clients_path,
            r#"[[client]]
name = "default"
cidr = "0.0.0.0/0"
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
            proxy_protocol: ProxyProtocolMode::Off,
            proxy_protocol_allowed_cidrs: None,
            ca_dir: ca_dir.clone(),
            clients: clients_path.clone(),
            clients_dir: None,
            policies: policies_path.clone(),
            policies_dir: None,
            cert_cache_dir: None,
            log: LogFormat::Text,
            leaf_ttl: 3600,
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

        let ca = Arc::new(CertificateAuthority::load_or_generate(&ca_dir)?);
        let cert_cache = Arc::new(CertificateCache::new(4, None)?);
        let tls_issuer = Arc::new(TlsIssuer::new(ca.clone(), cert_cache, settings.leaf_ttl())?);
        let config_doc = config::load_config(&clients_path, &policies_path)?;
        let compiled = Arc::new(policy::compile::compile_config(&config_doc)?);
        let snapshot = PolicySnapshot::new(compiled);
        let (_tx, rx) = watch::channel(snapshot);
        let policy_store = PolicyStore::new(rx);
        let tls_client_config = Arc::new(build_test_client_config());
        let tls_client_h2_config = Arc::new(build_test_client_config_h2());
        let tls_context = Arc::new(proxy::TlsContext::new(
            ca,
            tls_issuer,
            tls_client_config,
            tls_client_h2_config,
        ));

        Ok(proxy::AppContext::new(
            Arc::new(settings),
            policy_store,
            tls_context,
            None,
        ))
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
    async fn parse_errors_return_bad_request() -> Result<()> {
        let temp = TempDir::new()?;
        let app = build_test_app(&temp)?;
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
        };

        let result =
            handle_non_connect(&mut reader, peer, &app, &mut upstream_pool, ctx, None).await?;
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
        let app = build_test_app(&temp)?;
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
        };

        let result =
            handle_non_connect(&mut reader, peer, &app, &mut upstream_pool, ctx, None).await?;
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
        let app = build_test_app(&temp)?;
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
        };

        let result =
            handle_non_connect(&mut reader, peer, &app, &mut upstream_pool, ctx, None).await?;
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
