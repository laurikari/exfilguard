use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Result;
use http::{Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::{debug, warn};

use async_trait::async_trait;

use crate::io_util::{copy_with_write_timeout, write_all_with_timeout};
use crate::{
    config::Scheme,
    logging::AccessLogBuilder,
    proxy::{
        AppContext,
        allow_log::{AllowLogStats, log_allow_success},
        connect::ResolvedTarget,
        forward_limits::AllowLogTracker,
        policy_eval::{self, AllowDecision, PolicyLogConfig, RequestLogContext},
        policy_response::{self, ForwardErrorSpec},
        request::{ParsedRequest, parse_http1_request, scheme_name},
        request_pipeline::{self, RequestHandler},
    },
    util::timeout_with_context,
};

use super::body::BodyPlan;
use super::codec::{ConnectionDirective, HeaderAccumulator, encode_cached_response};
use super::forward::{
    ForwardResult, ForwardTimeouts, determine_response_body_plan, forward_to_upstream,
};
use super::upstream::UpstreamPool;
use crate::proxy::cache::CacheLookupOutcome;

pub enum ClientDisposition {
    Continue,
    Close,
}

pub struct RequestContext {
    pub method: Method,
    pub target: String,
    pub headers: HeaderAccumulator,
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

pub async fn handle_non_connect<S>(
    reader: &mut BufReader<S>,
    peer: SocketAddr,
    app: &AppContext,
    upstream_pool: &mut UpstreamPool,
    ctx: RequestContext,
    connect_binding: Option<&ResolvedTarget>,
) -> Result<ClientDisposition>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let total_request_bytes = ctx.total_request_bytes();
    let RequestContext {
        method,
        target,
        headers,
        request_line_bytes: _,
        header_bytes: _,
        start,
        fallback_scheme,
    } = ctx;
    let request_body_timeout = app.settings.request_body_idle_timeout();
    let response_header_timeout = app.settings.response_header_timeout();
    let response_body_timeout = app.settings.response_body_idle_timeout();
    let request_total_timeout = app.settings.request_total_timeout();
    let content_length = match headers.content_length() {
        Ok(value) => value,
        Err(err) => {
            warn!(peer = %peer, error = %err, "invalid content-length header");
            let stream = reader.get_mut();
            respond_with_access_log(
                stream,
                StatusCode::BAD_REQUEST,
                None,
                b"invalid Content-Length header\r\n",
                response_body_timeout,
                total_request_bytes,
                start.elapsed(),
                AccessLogBuilder::new(peer)
                    .method(method.as_str())
                    .scheme(scheme_name(fallback_scheme))
                    .host(headers.host().unwrap_or(""))
                    .path(target.clone())
                    .decision("ERROR"),
            )
            .await?;
            return Ok(ClientDisposition::Close);
        }
    };

    let expect_continue = match headers.expect_continue() {
        Ok(value) => value,
        Err(err) => {
            warn!(peer = %peer, error = %err, "unsupported Expect header");
            respond_with_access_log(
                reader.get_mut(),
                StatusCode::EXPECTATION_FAILED,
                None,
                b"expectation failed\r\n",
                response_body_timeout,
                total_request_bytes,
                start.elapsed(),
                AccessLogBuilder::new(peer)
                    .method(method.as_str())
                    .scheme(scheme_name(fallback_scheme))
                    .host(headers.host().unwrap_or(""))
                    .path(target.clone())
                    .decision("ERROR"),
            )
            .await?;
            return Ok(ClientDisposition::Close);
        }
    };

    if !headers.is_chunked()
        && let Some(length) = content_length
        && length > app.settings.max_request_body_size
    {
        warn!(
            peer = %peer,
            length,
            max = app.settings.max_request_body_size,
            "request body exceeds limit"
        );
        respond_with_access_log(
            reader.get_mut(),
            StatusCode::PAYLOAD_TOO_LARGE,
            None,
            b"request body exceeds configured limit\r\n",
            response_body_timeout,
            total_request_bytes,
            start.elapsed(),
            AccessLogBuilder::new(peer)
                .method(method.as_str())
                .scheme(scheme_name(fallback_scheme))
                .host(headers.host().unwrap_or(""))
                .path(target.clone())
                .decision("DENY"),
        )
        .await?;
        return Ok(ClientDisposition::Close);
    }

    let body_plan = if headers.is_chunked() {
        BodyPlan::Chunked
    } else {
        match content_length {
            Some(length) if length > 0 => BodyPlan::Fixed(length),
            _ => BodyPlan::Empty,
        }
    };
    let parsed = match parse_http1_request(method.clone(), &target, headers.host(), fallback_scheme)
    {
        Ok(parsed) => parsed,
        Err(err) => {
            warn!(peer = %peer, error = ?err, "failed to parse HTTP request target");
            respond_with_access_log(
                reader.get_mut(),
                StatusCode::BAD_REQUEST,
                None,
                b"invalid request target\r\n",
                response_body_timeout,
                total_request_bytes,
                start.elapsed(),
                AccessLogBuilder::new(peer)
                    .method(method.as_str())
                    .scheme(scheme_name(fallback_scheme))
                    .host(headers.host().unwrap_or(""))
                    .path(target)
                    .decision("ERROR"),
            )
            .await?;
            return Ok(ClientDisposition::Close);
        }
    };
    let snapshot = app.policies.snapshot();
    let log_tracker = AllowLogTracker::new(total_request_bytes, start);
    let mut handler = Http1RequestHandler {
        reader,
        upstream_pool,
        app,
        connect_binding,
        headers,
        body_plan,
        log_tracker,
        peer,
        request_body_timeout,
        response_header_timeout,
        response_body_timeout,
        request_start: start,
        request_total_timeout,
        parsed: &parsed,
        expect_continue,
    };
    request_pipeline::process_request(
        peer,
        &parsed,
        &snapshot,
        app.settings.log_queries,
        PolicyLogConfig::http1(),
        &mut handler,
    )
    .await
}

struct Http1RequestHandler<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    reader: &'a mut BufReader<S>,
    upstream_pool: &'a mut UpstreamPool,
    app: &'a AppContext,
    connect_binding: Option<&'a ResolvedTarget>,
    headers: HeaderAccumulator,
    body_plan: BodyPlan,
    log_tracker: AllowLogTracker,
    peer: SocketAddr,
    request_body_timeout: Duration,
    response_header_timeout: Duration,
    response_body_timeout: Duration,
    request_start: Instant,
    request_total_timeout: Option<Duration>,
    parsed: &'a ParsedRequest,
    expect_continue: bool,
}

#[async_trait]
impl<'a, S> RequestHandler for Http1RequestHandler<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    type Output = ClientDisposition;

    async fn on_allow(&mut self, outcome: policy_eval::AllowOutcome<'_>) -> Result<Self::Output> {
        let policy_eval::AllowOutcome { decision, log } = outcome;

        // Try Cache Lookup
        let mut cache_lookup = Some("bypass");
        if let (Some(_cache_config), Some(cache)) = (&decision.cache, &self.app.cache) {
            match cache.lookup_for_request(self.parsed, &self.headers).await {
                Ok(CacheLookupOutcome::Hit(hit)) => {
                    // Serve from cache
                    let client_stream = self.reader.get_mut();
                    let hit = *hit;
                    let cached = hit.cached;
                    let head = hit.head;

                    let body_plan =
                        determine_response_body_plan(&self.parsed.method, cached.status, &head);
                    let should_close = self.headers.wants_connection_close()
                        || matches!(body_plan, super::forward::ResponseBodyPlan::UntilClose);
                    let override_connection = if should_close {
                        Some(ConnectionDirective::Close)
                    } else {
                        None
                    };
                    let encoded_head = encode_cached_response(
                        &head.status_line,
                        &cached.headers,
                        body_plan,
                        head.content_length,
                        override_connection,
                    );
                    write_all_with_timeout(
                        client_stream,
                        &encoded_head,
                        self.response_body_timeout,
                        "writing cached response head",
                    )
                    .await?;

                    let mut copied = 0u64;
                    if !matches!(body_plan, super::forward::ResponseBodyPlan::Empty) {
                        let mut file = tokio::fs::File::open(&cached.body_path).await?;
                        copied = copy_with_write_timeout(
                            &mut file,
                            client_stream,
                            self.response_body_timeout,
                            "writing cached response body",
                        )
                        .await?;
                    }

                    if should_close {
                        shutdown_stream(client_stream, self.response_body_timeout).await?;
                    }

                    // Log Cache Hit
                    let log_builder = log
                        .access_log_builder()
                        .decision("CACHE_HIT")
                        .client(decision.client.as_ref())
                        .status(cached.status)
                        .bytes(self.log_tracker.base_bytes(), copied)
                        .cache_lookup("hit")
                        .cache_store("bypassed");

                    // Add policy info
                    let log_builder = log_builder
                        .policy(decision.policy.as_ref())
                        .rule(decision.rule.as_ref())
                        .inspect_payload(decision.inspect_payload);

                    log_builder.log();

                    return Ok(if should_close {
                        ClientDisposition::Close
                    } else {
                        ClientDisposition::Continue
                    });
                }
                Ok(CacheLookupOutcome::Miss) => {
                    cache_lookup = Some("miss");
                }
                Ok(CacheLookupOutcome::Bypass) => {}
                Err(err) => {
                    debug!(
                        peer = %self.peer,
                        error = %err,
                        "skipping cache lookup due to URI build failure"
                    );
                }
            }
        }

        let forward_result = self.forward_request(&decision).await;
        let handled = policy_response::handle_forward_result(
            &decision,
            log.clone(),
            forward_result,
            self.peer,
            &self.parsed.host,
        )
        .await?;
        match handled {
            policy_response::ForwardOutcome::Completed(success) => {
                let stats = self.build_allow_log_stats(&success);
                log_allow_success(
                    log,
                    &decision,
                    stats,
                    cache_lookup,
                    Some(success.stats.cache_store.as_str()),
                );
                self.handle_forward_success(success).await
            }
            policy_response::ForwardOutcome::Responded(ctx) => {
                self.respond_forward_error(ctx.spec, ctx.log, ctx.decision)
                    .await
            }
        }
    }

    async fn on_deny(&mut self, outcome: policy_eval::DenyOutcome<'_>) -> Result<Self::Output> {
        self.handle_deny(outcome).await
    }

    async fn on_default_deny(
        &mut self,
        outcome: policy_eval::DefaultDenyOutcome<'_>,
    ) -> Result<Self::Output> {
        self.handle_default_deny(outcome).await
    }
}

impl<'a, S> Http1RequestHandler<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn forward_request(&mut self, decision: &AllowDecision) -> Result<ForwardResult> {
        forward_to_upstream(
            self.reader,
            self.upstream_pool,
            self.parsed,
            &self.headers,
            self.body_plan,
            self.connect_binding,
            &ForwardTimeouts {
                connect: self.app.settings.upstream_connect_timeout(),
                request_io: self.request_body_timeout,
                response_header: self.response_header_timeout,
                response_io: self.response_body_timeout,
            },
            self.request_start,
            self.request_total_timeout,
            self.expect_continue,
            decision,
            self.peer,
            self.app.settings.max_request_body_size,
            self.app,
        )
        .await
    }

    fn build_allow_log_stats(&mut self, success: &ForwardResult) -> AllowLogStats {
        self.log_tracker
            .add_client_bytes(success.stats.client_body_bytes);
        self.log_tracker.build_allow_log_stats(
            success.stats.status,
            success.stats.bytes_to_client,
            success.upstream_addr,
            success.reused_existing,
        )
    }

    async fn handle_forward_success(
        &mut self,
        success: ForwardResult,
    ) -> Result<ClientDisposition> {
        if success.client_close {
            shutdown_stream(self.reader.get_mut(), self.response_body_timeout).await?;
            Ok(ClientDisposition::Close)
        } else {
            Ok(ClientDisposition::Continue)
        }
    }

    async fn respond_forward_error(
        &mut self,
        spec: ForwardErrorSpec,
        log: RequestLogContext<'_>,
        decision: AllowDecision,
    ) -> Result<ClientDisposition> {
        self.send_forward_error_response(spec, log, decision).await
    }

    async fn send_forward_error_response(
        &mut self,
        spec: ForwardErrorSpec,
        log: RequestLogContext<'_>,
        decision: AllowDecision,
    ) -> Result<ClientDisposition> {
        if spec.extra_client_bytes > 0 {
            self.log_tracker.add_client_bytes(spec.extra_client_bytes);
        }
        respond_with_access_log(
            self.reader.get_mut(),
            spec.status,
            None,
            spec.body_http1,
            self.response_body_timeout,
            self.log_tracker.current_bytes(),
            self.log_tracker.elapsed(),
            policy_response::forward_error_log_builder(log.access_log_builder(), &decision, &spec),
        )
        .await?;
        Ok(ClientDisposition::Close)
    }

    async fn handle_deny(
        &mut self,
        outcome: policy_eval::DenyOutcome<'_>,
    ) -> Result<ClientDisposition> {
        let deny = outcome.decision;
        let log = outcome.log;
        let response = policy_response::build_policy_deny_response(&log, &deny);
        respond_with_access_log(
            self.reader.get_mut(),
            response.spec.status,
            response.spec.reason,
            response.spec.body_http1,
            self.response_body_timeout,
            self.log_tracker.base_bytes(),
            self.log_tracker.elapsed(),
            response.log_builder,
        )
        .await?;
        Ok(ClientDisposition::Close)
    }

    async fn handle_default_deny(
        &mut self,
        outcome: policy_eval::DefaultDenyOutcome<'_>,
    ) -> Result<ClientDisposition> {
        let log = outcome.log;
        let response = policy_response::build_default_deny_response(&log);
        respond_with_access_log(
            self.reader.get_mut(),
            response.spec.status,
            response.spec.reason,
            response.spec.body_http1,
            self.response_body_timeout,
            self.log_tracker.base_bytes(),
            self.log_tracker.elapsed(),
            response.log_builder,
        )
        .await?;
        Ok(ClientDisposition::Close)
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn respond_with_access_log<S>(
    stream: &mut S,
    status: StatusCode,
    reason: Option<&str>,
    body: &[u8],
    timeout_dur: Duration,
    bytes_in: u64,
    elapsed: Duration,
    log_builder: AccessLogBuilder,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let bytes_out = send_response(stream, status, reason, body, timeout_dur).await?;
    shutdown_stream(stream, timeout_dur).await?;
    log_builder
        .status(status)
        .bytes(bytes_in, bytes_out as u64)
        .elapsed(elapsed)
        .log();
    Ok(())
}

pub async fn send_response<S>(
    stream: &mut S,
    status: StatusCode,
    reason: Option<&str>,
    body: &[u8],
    timeout_dur: Duration,
) -> Result<usize>
where
    S: AsyncWrite + Unpin,
{
    let reason_text = reason
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("Unknown"));
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
        status.as_u16(),
        reason_text,
        body.len()
    );
    write_all_with_timeout(
        stream,
        header.as_bytes(),
        timeout_dur,
        "writing response header",
    )
    .await?;
    let mut written = header.len();
    if !body.is_empty() {
        write_all_with_timeout(stream, body, timeout_dur, "writing response body").await?;
        written += body.len();
    }
    Ok(written)
}

pub async fn shutdown_stream<S>(stream: &mut S, timeout_dur: Duration) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    timeout_with_context(
        timeout_dur,
        stream.shutdown(),
        "shutting down client stream",
    )
    .await
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
        settings::Settings,
        tls::{ca::CertificateAuthority, cache::CertificateCache, issuer::TlsIssuer},
    };
    use anyhow::Result;
    use http::Method;
    use rustls::{RootCertStore, client::ClientConfig, crypto::ring};
    use std::{net::SocketAddr, sync::Arc};
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
        let mut headers = HeaderAccumulator::new(1024);
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

        let mut headers = HeaderAccumulator::new(1024);
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
}
