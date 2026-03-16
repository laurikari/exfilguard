use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use http::StatusCode;
use tokio::net::TcpStream;
use tracing::{Level, warn};
use uuid::Uuid;

use crate::{
    logging::AccessLogBuilder,
    proxy::{
        AppContext,
        forward_error::{classify_forward_error, log_forward_error},
        http::respond_with_access_log,
        policy_eval::{AllowDecision, DenyDecision, RequestLogContext},
        policy_response::{self, ForwardErrorSpec, ForwardOutcome},
        request::{EffectiveMode, RequestFlowContext},
    },
    util::is_private_ip,
};

use super::{
    bump::handle_bump,
    resolve::{ResolvedTarget, resolve_connect_target},
    splice::{ConnectTunnelTimeout, handle_splice},
    target::ConnectTarget,
};

/// Manages the state and lifecycle of a CONNECT tunnel.
///
/// A session is responsible for:
/// 1. Resolving the upstream target (with DNS and private-IP checks).
/// 2. Executing the "Decision Path":
///    - Tunnel mode: Raw byte streaming for explicit CONNECT tunnel rules.
///    - Bump mode: TLS interception after a transport-only preflight.
pub struct ConnectSession {
    peer: SocketAddr,
    parsed: ConnectTarget,
    literal_ip: Option<IpAddr>,
    target: String,
    session_id: Arc<str>,
    bytes_in: u64,
    start: Instant,
    response_timeout: Duration,
}

impl ConnectSession {
    pub fn new(
        peer: SocketAddr,
        target: String,
        parsed: ConnectTarget,
        bytes_in: u64,
        start: Instant,
        response_timeout: Duration,
    ) -> Self {
        let literal_ip = parsed.host.parse::<IpAddr>().ok();
        Self {
            peer,
            parsed,
            literal_ip,
            target,
            session_id: Arc::<str>::from(Uuid::new_v4().to_string()),
            bytes_in,
            start,
            response_timeout,
        }
    }

    pub fn parsed(&self) -> &ConnectTarget {
        &self.parsed
    }

    pub fn original_target(&self) -> &str {
        &self.target
    }

    pub fn bump_flow_context(&self) -> RequestFlowContext {
        RequestFlowContext {
            session_id: self.session_id.clone(),
            outer_method: Arc::<str>::from("CONNECT"),
            effective_mode: EffectiveMode::Bump,
        }
    }

    pub async fn process_tunnel_allow(
        &mut self,
        stream: TcpStream,
        allow: AllowDecision,
        log: RequestLogContext<'_>,
        app: &AppContext,
    ) -> Result<()> {
        let resolve_timeout = app.settings.dns_resolve_timeout();
        let resolved = match resolve_connect_target(
            &self.parsed,
            resolve_timeout,
            app.settings.allow_test_upstreams,
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(err) => {
                let mut stream = stream;
                self.respond_resolution_error(&mut stream, err, |builder| {
                    builder
                        .client(allow.client.as_ref())
                        .policy(allow.policy.as_ref())
                        .rule(allow.rule.as_ref())
                        .effective_mode("tunnel")
                })
                .await?;
                return Ok(());
            }
        };

        self.handle_splice_path(stream, allow, log, resolved, app)
            .await
    }

    pub async fn process_tls_bump_preflight(
        &mut self,
        stream: TcpStream,
        client: Arc<str>,
        log: RequestLogContext<'_>,
        app: &AppContext,
    ) -> Result<()> {
        let resolve_timeout = app.settings.dns_resolve_timeout();
        let resolved = match resolve_connect_target(
            &self.parsed,
            resolve_timeout,
            app.settings.allow_test_upstreams,
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(err) => {
                let mut stream = stream;
                self.respond_resolution_error(&mut stream, err, |builder| {
                    builder
                        .client(client.as_ref())
                        .effective_mode("bump")
                        .transport("tls_bump_preflight")
                })
                .await?;
                return Ok(());
            }
        };

        self.handle_bump_preflight_path(stream, client, log, resolved, app)
            .await
    }

    pub async fn respond_policy_deny(
        &self,
        stream: &mut TcpStream,
        deny: &DenyDecision,
    ) -> Result<()> {
        let spec = policy_response::policy_deny_spec(deny);
        self.respond_with_builder(
            stream,
            spec.status,
            spec.reason,
            spec.body_http1,
            "DENY",
            |builder| {
                policy_response::decorate_policy_deny_log(builder.effective_mode("tunnel"), deny)
            },
        )
        .await
    }

    pub async fn respond_default_denial(&self, stream: &mut TcpStream) -> Result<()> {
        if self.literal_ip.is_some_and(is_private_ip) {
            warn!(
                peer = %self.peer,
                host = %self.parsed.host,
                port = self.parsed.port,
                "CONNECT target is private network; blocking"
            );
            self.respond_with_builder(
                stream,
                StatusCode::FORBIDDEN,
                None,
                b"CONNECT to private networks is not allowed\r\n",
                "DENY",
                |builder| builder,
            )
            .await
        } else {
            warn!(
                peer = %self.peer,
                host = %self.parsed.host,
                port = self.parsed.port,
                "no matching CONNECT tunnel policy or TLS bump preflight; default deny"
            );
            let spec = policy_response::default_deny_spec();
            self.respond_with_builder(
                stream,
                spec.status,
                spec.reason,
                spec.body_http1,
                "DENY",
                policy_response::decorate_default_deny_log,
            )
            .await
        }
    }

    async fn run_splice(
        &mut self,
        stream: &mut TcpStream,
        resolved: &ResolvedTarget,
        allow: &AllowDecision,
        app: &AppContext,
    ) -> Result<()> {
        let stats = handle_splice(stream, &self.parsed, resolved, app).await?;
        self.bytes_in = self.bytes_in.saturating_add(stats.client_stream_bytes);
        self.access_log_builder()
            .status(StatusCode::OK)
            .decision("ALLOW")
            .client(allow.client.as_ref())
            .policy(allow.policy.as_ref())
            .rule(allow.rule.as_ref())
            .effective_mode("tunnel")
            .bytes(
                self.bytes_in,
                stats.handshake_bytes + stats.upstream_stream_bytes,
            )
            .elapsed(self.start.elapsed())
            .upstream_addr(stats.upstream_addr.to_string())
            .upstream_reused(false)
            .log();
        Ok(())
    }

    async fn run_bump(
        &mut self,
        stream: TcpStream,
        resolved: ResolvedTarget,
        client: &str,
        app: &AppContext,
    ) -> Result<()> {
        let bump_stats = handle_bump(
            stream,
            &self.parsed,
            resolved,
            app,
            self.peer,
            self.bump_flow_context(),
        )
        .await?;
        self.access_log_builder()
            .status(StatusCode::OK)
            .decision("ALLOW")
            .client(client)
            .effective_mode("bump")
            .transport("tls_bump_preflight")
            .bytes(self.bytes_in, bump_stats.handshake_bytes)
            .elapsed(self.start.elapsed())
            .log_with_level(Level::DEBUG);
        Ok(())
    }

    async fn handle_splice_path(
        &mut self,
        stream: TcpStream,
        allow: AllowDecision,
        log: RequestLogContext<'_>,
        resolved: ResolvedTarget,
        app: &AppContext,
    ) -> Result<()> {
        let mut stream_holder = Some(stream);
        let splice_result = self
            .run_splice(
                stream_holder.as_mut().expect("CONNECT stream present"),
                &resolved,
                &allow,
                app,
            )
            .await;
        if let Err(err) = splice_result.as_ref()
            && err.downcast_ref::<ConnectTunnelTimeout>().is_some()
        {
            warn!(
                peer = %self.peer,
                host = %self.parsed.host,
                port = self.parsed.port,
                "CONNECT tunnel exceeded max lifetime"
            );
            self.access_log_builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .decision("ERROR")
                .client(allow.client.as_ref())
                .policy(allow.policy.as_ref())
                .rule(allow.rule.as_ref())
                .effective_mode("tunnel")
                .bytes(self.bytes_in, 0)
                .elapsed(self.start.elapsed())
                .upstream_reused(false)
                .log();
            return Ok(());
        }
        let stream_for_error = stream_holder;
        match policy_response::handle_forward_result(
            &allow,
            log,
            splice_result,
            self.peer,
            &self.parsed.host,
        )
        .await?
        {
            ForwardOutcome::Completed(()) => Ok(()),
            ForwardOutcome::Responded(ctx) => {
                if let Some(mut stream) = stream_for_error {
                    self.respond_forward_error(
                        &mut stream,
                        ctx.spec,
                        ctx.log,
                        ctx.decision,
                        &ctx.error_detail,
                    )
                    .await?;
                }
                Ok(())
            }
        }
    }

    async fn handle_bump_preflight_path(
        &mut self,
        stream: TcpStream,
        client: Arc<str>,
        _log: RequestLogContext<'_>,
        resolved: ResolvedTarget,
        app: &AppContext,
    ) -> Result<()> {
        let bump_result = self.run_bump(stream, resolved, client.as_ref(), app).await;
        match bump_result {
            Ok(()) => Ok(()),
            Err(err) => {
                let kind = classify_forward_error(&err);
                crate::metrics::record_upstream_error(kind.as_metric_label());
                log_forward_error(&kind, self.peer, &self.parsed.host, &err);
                self.log_bump_preflight_error(
                    policy_response::forward_error_spec(&kind),
                    client.as_ref(),
                    &err.to_string(),
                )
                .await
            }
        }
    }

    async fn respond_forward_error(
        &mut self,
        stream: &mut TcpStream,
        spec: ForwardErrorSpec,
        log: RequestLogContext<'_>,
        allow: AllowDecision,
        error_detail: &str,
    ) -> Result<()> {
        if spec.extra_client_bytes > 0 {
            self.bytes_in = self.bytes_in.saturating_add(spec.extra_client_bytes);
        }
        respond_with_access_log(
            stream,
            spec.status,
            None,
            spec.body_http1,
            self.response_timeout,
            self.bytes_in,
            self.start.elapsed(),
            policy_response::forward_error_log_builder(
                log.access_log_builder(),
                &allow,
                &spec,
                error_detail,
            ),
        )
        .await
    }

    async fn log_bump_preflight_error(
        &mut self,
        spec: ForwardErrorSpec,
        client: &str,
        error_detail: &str,
    ) -> Result<()> {
        if spec.extra_client_bytes > 0 {
            self.bytes_in = self.bytes_in.saturating_add(spec.extra_client_bytes);
        }
        self.access_log_builder()
            .status(spec.status)
            .decision(spec.decision)
            .client(client)
            .effective_mode("bump")
            .transport("tls_bump_preflight")
            .error_reason(spec.log_reason)
            .error_detail(error_detail)
            .bytes(self.bytes_in, 0)
            .elapsed(self.start.elapsed())
            .log_with_level(Level::DEBUG);
        Ok(())
    }

    async fn respond_resolution_error<F>(
        &self,
        stream: &mut TcpStream,
        err: anyhow::Error,
        build: F,
    ) -> Result<()>
    where
        F: FnOnce(AccessLogBuilder) -> AccessLogBuilder,
    {
        if err
            .downcast_ref::<crate::proxy::resolver::PrivateAddressError>()
            .is_some()
        {
            warn!(
                peer = %self.peer,
                host = %self.parsed.host,
                port = self.parsed.port,
                "CONNECT target resolved to private network; blocking"
            );
            self.respond_with_builder(
                stream,
                StatusCode::FORBIDDEN,
                None,
                b"CONNECT to private networks is not allowed\r\n",
                "DENY",
                build,
            )
            .await
        } else {
            warn!(
                peer = %self.peer,
                host = %self.parsed.host,
                port = self.parsed.port,
                error = %err,
                "failed to resolve CONNECT target"
            );
            self.respond_with_builder(
                stream,
                StatusCode::BAD_GATEWAY,
                None,
                b"failed to resolve CONNECT target\r\n",
                "ERROR",
                build,
            )
            .await
        }
    }

    fn access_log_builder(&self) -> AccessLogBuilder {
        AccessLogBuilder::for_connect(self.peer, self.parsed.host.clone(), self.target.clone())
            .session_id(self.session_id.as_ref())
    }

    async fn respond_with_builder<F>(
        &self,
        stream: &mut TcpStream,
        status: StatusCode,
        reason: Option<&str>,
        body: &[u8],
        decision: &str,
        build: F,
    ) -> Result<()>
    where
        F: FnOnce(AccessLogBuilder) -> AccessLogBuilder,
    {
        respond_with_access_log(
            stream,
            status,
            reason,
            body,
            self.response_timeout,
            self.bytes_in,
            self.start.elapsed(),
            build(self.access_log_builder()).decision(decision),
        )
        .await
    }
}
