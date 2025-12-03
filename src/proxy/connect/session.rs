use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::Result;
use http::StatusCode;
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::{
    logging::AccessLogBuilder,
    proxy::{
        AppContext,
        http::respond_with_access_log,
        policy_eval::{AllowDecision, DenyDecision, RequestLogContext},
        policy_response::{self, ForwardErrorSpec, ForwardOutcome},
    },
    util::is_private_ip,
};

use super::{
    bump::handle_bump,
    resolve::{ResolvedTarget, resolve_connect_target},
    splice::handle_splice,
    target::ConnectTarget,
};

pub struct ConnectSession {
    peer: SocketAddr,
    parsed: ConnectTarget,
    literal_ip: Option<IpAddr>,
    target: String,
    bytes_in: u64,
    start: Instant,
    client_timeout: Duration,
}

impl ConnectSession {
    pub fn new(
        peer: SocketAddr,
        target: String,
        parsed: ConnectTarget,
        bytes_in: u64,
        start: Instant,
        client_timeout: Duration,
    ) -> Self {
        let literal_ip = parsed.host.parse::<IpAddr>().ok();
        Self {
            peer,
            parsed,
            literal_ip,
            target,
            bytes_in,
            start,
            client_timeout,
        }
    }

    pub fn parsed(&self) -> &ConnectTarget {
        &self.parsed
    }

    pub fn original_target(&self) -> &str {
        &self.target
    }

    pub async fn process_allow(
        &mut self,
        stream: TcpStream,
        allow: AllowDecision,
        log: RequestLogContext<'_>,
        app: &AppContext,
    ) -> Result<()> {
        log_allow(&self.peer, &self.parsed, &allow);

        let resolve_timeout = app.settings.upstream_connect_timeout();
        let resolved = match resolve_connect_target(
            &self.parsed,
            resolve_timeout,
            allow.allow_private_connect,
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(err) => {
                let mut stream = stream;
                self.respond_resolution_error(&mut stream, &allow, err)
                    .await?;
                return Ok(());
            }
        };

        if allow.inspect_payload {
            self.handle_bump_path(stream, allow, log, resolved, app)
                .await
        } else {
            self.handle_splice_path(stream, allow, log, resolved, app)
                .await
        }
    }

    pub async fn respond_policy_deny(
        &self,
        stream: &mut TcpStream,
        deny: &DenyDecision,
    ) -> Result<()> {
        info!(
            peer = %self.peer,
            client = %deny.client,
            policy = %deny.policy,
            rule = %deny.rule,
            host = %self.parsed.host,
            port = self.parsed.port,
            status = deny.status.as_u16(),
            "policy deny decision (CONNECT)"
        );
        let spec = policy_response::policy_deny_spec(deny);
        self.respond_with_builder(
            stream,
            spec.status,
            spec.reason,
            spec.body_http1,
            "DENY",
            |builder| policy_response::decorate_policy_deny_log(builder, deny),
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
                "no matching policy decision for CONNECT; default deny"
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
            .inspect_payload(false)
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
        allow: &AllowDecision,
        app: &AppContext,
    ) -> Result<()> {
        let bump_stats = handle_bump(stream, &self.parsed, resolved, app, self.peer).await?;
        self.access_log_builder()
            .status(StatusCode::OK)
            .decision("ALLOW")
            .client(allow.client.as_ref())
            .policy(allow.policy.as_ref())
            .rule(allow.rule.as_ref())
            .inspect_payload(true)
            .bytes(self.bytes_in, bump_stats.handshake_bytes)
            .elapsed(self.start.elapsed())
            .log();
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
                    self.respond_forward_error(&mut stream, ctx.spec, ctx.log, ctx.decision)
                        .await?;
                }
                Ok(())
            }
        }
    }

    async fn handle_bump_path(
        &mut self,
        stream: TcpStream,
        allow: AllowDecision,
        log: RequestLogContext<'_>,
        resolved: ResolvedTarget,
        app: &AppContext,
    ) -> Result<()> {
        let bump_result = self.run_bump(stream, resolved, &allow, app).await;
        match policy_response::handle_forward_result(
            &allow,
            log,
            bump_result,
            self.peer,
            &self.parsed.host,
        )
        .await?
        {
            ForwardOutcome::Completed(()) => Ok(()),
            ForwardOutcome::Responded(ctx) => {
                self.log_forward_error(ctx.spec, ctx.log, ctx.decision)
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
    ) -> Result<()> {
        if spec.extra_client_bytes > 0 {
            self.bytes_in = self.bytes_in.saturating_add(spec.extra_client_bytes);
        }
        respond_with_access_log(
            stream,
            spec.status,
            None,
            spec.body_http1,
            self.client_timeout,
            self.bytes_in,
            self.start.elapsed(),
            policy_response::forward_error_log_builder(log.access_log_builder(), &allow, &spec),
        )
        .await
    }

    async fn log_forward_error(
        &mut self,
        spec: ForwardErrorSpec,
        log: RequestLogContext<'_>,
        allow: AllowDecision,
    ) -> Result<()> {
        if spec.extra_client_bytes > 0 {
            self.bytes_in = self.bytes_in.saturating_add(spec.extra_client_bytes);
        }
        policy_response::forward_error_log_builder(log.access_log_builder(), &allow, &spec)
            .status(spec.status)
            .bytes(self.bytes_in, 0)
            .elapsed(self.start.elapsed())
            .log();
        Ok(())
    }

    async fn respond_resolution_error(
        &self,
        stream: &mut TcpStream,
        allow: &AllowDecision,
        err: anyhow::Error,
    ) -> Result<()> {
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
                |builder| {
                    builder
                        .client(allow.client.as_ref())
                        .policy(allow.policy.as_ref())
                        .rule(allow.rule.as_ref())
                },
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
                |builder| {
                    builder
                        .client(allow.client.as_ref())
                        .policy(allow.policy.as_ref())
                        .rule(allow.rule.as_ref())
                },
            )
            .await
        }
    }

    fn access_log_builder(&self) -> AccessLogBuilder {
        AccessLogBuilder::for_connect(self.peer, self.parsed.host.clone(), self.target.clone())
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
            self.client_timeout,
            self.bytes_in,
            self.start.elapsed(),
            build(self.access_log_builder()).decision(decision),
        )
        .await
    }
}

fn log_allow(peer: &SocketAddr, target: &ConnectTarget, allow: &AllowDecision) {
    if allow.inspect_payload {
        info!(
            peer = %peer,
            client = %allow.client,
            policy = %allow.policy,
            rule = %allow.rule,
            host = %target.host,
            port = target.port,
            "policy allow decision (CONNECT bump)"
        );
    } else {
        info!(
            peer = %peer,
            client = %allow.client,
            policy = %allow.policy,
            rule = %allow.rule,
            host = %target.host,
            port = target.port,
            "policy allow decision (CONNECT pass-through)"
        );
    }
}
