use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use h2::server::{self, SendResponse};
use http;
use tokio::{net::TcpStream, sync::Mutex, task::JoinSet};
use tokio_rustls::server::TlsStream;
use tracing::warn;

use crate::{
    policy::matcher::PolicySnapshot,
    proxy::{
        AppContext,
        allow_log::{AllowLogStats, log_allow_success},
        connect::ResolvedTarget,
        forward_limits::AllowLogTracker,
        policy_eval::{self, AllowDecision, PolicyLogConfig, RequestLogContext},
        policy_response::{self, ForwardErrorSpec},
        request_pipeline::{self, RequestHandler},
    },
};
use async_trait::async_trait;

use super::{
    forward::{forward_request_to_upstream, send_error_response},
    request::{SanitizedRequest, reject_expect_header, sanitize_request},
    upstream::{Http2Upstream, PrimedHttp2Upstream},
};

pub async fn serve_bumped_http2(
    stream: TlsStream<TcpStream>,
    peer: SocketAddr,
    app: AppContext,
    connect_binding: Option<ResolvedTarget>,
    primed_upstream: Option<PrimedHttp2Upstream>,
) -> Result<()> {
    let mut service =
        Http2BumpService::new(stream, peer, app, connect_binding, primed_upstream).await?;
    service.run().await
}

struct Http2BumpService {
    peer: SocketAddr,
    app: AppContext,
    connection: server::Connection<TlsStream<TcpStream>, Bytes>,
    upstream: Arc<Mutex<Http2Upstream>>,
}

impl Http2BumpService {
    async fn new(
        stream: TlsStream<TcpStream>,
        peer: SocketAddr,
        app: AppContext,
        connect_binding: Option<ResolvedTarget>,
        primed_upstream: Option<PrimedHttp2Upstream>,
    ) -> Result<Self> {
        let connection = server::handshake(stream)
            .await
            .context("failed to handshake HTTP/2 with downstream client")?;
        let upstream = Http2Upstream::new(app.clone(), connect_binding, primed_upstream);
        Ok(Self {
            peer,
            app,
            connection,
            upstream: Arc::new(Mutex::new(upstream)),
        })
    }

    async fn run(&mut self) -> Result<()> {
        let mut tasks = JoinSet::new();
        while let Some(result) = self.connection.accept().await {
            match result {
                Ok((request, respond)) => {
                    let peer = self.peer;
                    let app = self.app.clone();
                    let upstream = self.upstream.clone();
                    tasks.spawn(async move {
                        if let Err(err) =
                            process_downstream_request(request, respond, peer, app, upstream).await
                        {
                            warn!(
                                peer = %peer,
                                error = %err,
                                "HTTP/2 downstream request handling failed"
                            );
                        }
                    });
                }
                Err(err) => {
                    warn!(
                        peer = %self.peer,
                        error = %err,
                        "failed to accept HTTP/2 request from downstream"
                    );
                    break;
                }
            }
        }
        while tasks.join_next().await.is_some() {}
        let mut upstream = self.upstream.lock().await;
        upstream.shutdown().await;
        Ok(())
    }
}

async fn process_downstream_request(
    request: http::Request<h2::RecvStream>,
    respond: SendResponse<Bytes>,
    peer: SocketAddr,
    app: AppContext,
    upstream: Arc<Mutex<Http2Upstream>>,
) -> Result<()> {
    if let Err(err) = reject_expect_header(request.headers()) {
        warn!(
            peer = %peer,
            error = %err,
            "HTTP/2 request contained unsupported Expect header"
        );
        let mut respond = respond;
        send_error_response(
            &mut respond,
            http::StatusCode::EXPECTATION_FAILED,
            "expectation failed",
        )
        .await?;
        return Ok(());
    }

    let ctx = DownstreamRequestCtx::new(request, respond, peer, &app)?;
    ctx.handle(upstream).await
}

struct DownstreamRequestCtx {
    peer: SocketAddr,
    meta: SanitizedRequest,
    body: h2::RecvStream,
    respond: SendResponse<Bytes>,
    snapshot: PolicySnapshot,
    client_timeout: Duration,
    upstream_timeout: Duration,
    max_request_body_size: usize,
    max_response_header_bytes: usize,
    log_queries: bool,
    log_tracker: AllowLogTracker,
}

impl DownstreamRequestCtx {
    fn new(
        request: http::Request<h2::RecvStream>,
        respond: SendResponse<Bytes>,
        peer: SocketAddr,
        app: &AppContext,
    ) -> Result<Self> {
        let start = Instant::now();
        let snapshot = app.policies.snapshot();
        let max_header_size = app.settings.max_header_size;
        let (meta, body) = sanitize_request(request, max_header_size)
            .context("failed to sanitize HTTP/2 request")?;
        let log_queries = app.settings.log_queries;
        let request_base = meta.request_line_bytes + meta.header_bytes as u64;
        Ok(Self {
            peer,
            meta,
            body,
            respond,
            snapshot,
            client_timeout: app.settings.client_timeout(),
            upstream_timeout: app.settings.upstream_timeout(),
            max_request_body_size: app.settings.max_request_body_size,
            max_response_header_bytes: app.settings.max_response_header_size,
            log_queries,
            log_tracker: AllowLogTracker::new(request_base, start),
        })
    }

    async fn handle(self, upstream: Arc<Mutex<Http2Upstream>>) -> Result<()> {
        let peer = self.peer;
        let log_queries = self.log_queries;
        let snapshot = self.snapshot.clone();
        let parsed_for_policy = self.meta.parsed.clone();
        let mut handler = Http2RequestHandler {
            ctx: self,
            upstream,
        };
        request_pipeline::process_request(
            peer,
            &parsed_for_policy,
            &snapshot,
            log_queries,
            PolicyLogConfig::http2_connect_bump(),
            &mut handler,
        )
        .await
    }

    async fn handle_deny(&mut self, deny: policy_eval::DenyOutcome<'_>) -> Result<()> {
        let policy_eval::DenyOutcome { decision, log } = deny;
        let response = policy_response::build_policy_deny_response(&log, &decision);
        send_error_response(
            &mut self.respond,
            response.spec.status,
            response.spec.body_http2,
        )
        .await?;
        response
            .log_builder
            .status(response.spec.status)
            .bytes(
                self.log_tracker.base_bytes(),
                response.spec.body_http2.len() as u64,
            )
            .elapsed(self.log_tracker.elapsed())
            .log();
        Ok(())
    }

    async fn handle_default_deny(
        &mut self,
        outcome: policy_eval::DefaultDenyOutcome<'_>,
    ) -> Result<()> {
        let policy_eval::DefaultDenyOutcome { log } = outcome;
        let response = policy_response::build_default_deny_response(&log);
        send_error_response(
            &mut self.respond,
            response.spec.status,
            response.spec.body_http2,
        )
        .await?;
        response
            .log_builder
            .status(response.spec.status)
            .bytes(
                self.log_tracker.base_bytes(),
                response.spec.body_http2.len() as u64,
            )
            .elapsed(self.log_tracker.elapsed())
            .log();
        Ok(())
    }

    async fn respond_forward_error(
        &mut self,
        spec: ForwardErrorSpec,
        log: RequestLogContext<'_>,
        decision: AllowDecision,
    ) -> Result<()> {
        send_error_response(&mut self.respond, spec.status, spec.body_http2).await?;
        self.log_tracker.add_client_bytes(spec.extra_client_bytes);
        policy_response::forward_error_log_builder(log.access_log_builder(), &decision, &spec)
            .bytes(self.log_tracker.current_bytes(), 0)
            .elapsed(self.log_tracker.elapsed())
            .log();
        Ok(())
    }
}

struct Http2RequestHandler {
    ctx: DownstreamRequestCtx,
    upstream: Arc<Mutex<Http2Upstream>>,
}

impl Http2RequestHandler {
    async fn forward_request(
        &mut self,
        decision: &AllowDecision,
    ) -> Result<super::forward::ForwardOutcome> {
        let forward_meta = self.ctx.meta.clone();
        let checkout = {
            let mut upstream = self.upstream.lock().await;
            upstream
                .checkout_sender(decision.allow_private_connect, &forward_meta.parsed)
                .await?
        };
        forward_request_to_upstream(
            checkout,
            forward_meta,
            &mut self.ctx.body,
            &mut self.ctx.respond,
            self.ctx.client_timeout,
            self.ctx.upstream_timeout,
            self.ctx.max_request_body_size,
            self.ctx.max_response_header_bytes,
        )
        .await
    }

    fn build_allow_log_stats(&mut self, success: &super::forward::ForwardOutcome) -> AllowLogStats {
        self.ctx
            .log_tracker
            .add_client_bytes(success.client_body_bytes());
        self.ctx.log_tracker.build_allow_log_stats(
            success.status(),
            success.bytes_to_client(),
            success.upstream_addr(),
            success.upstream_reused(),
        )
    }

    async fn handle_forward_success(
        &mut self,
        _success: super::forward::ForwardOutcome,
    ) -> Result<()> {
        Ok(())
    }

    async fn respond_forward_error(
        &mut self,
        spec: ForwardErrorSpec,
        log: RequestLogContext<'_>,
        decision: AllowDecision,
    ) -> Result<()> {
        self.ctx.respond_forward_error(spec, log, decision).await
    }
}

#[async_trait]
impl RequestHandler for Http2RequestHandler {
    type Output = ();

    async fn on_allow(&mut self, outcome: policy_eval::AllowOutcome<'_>) -> Result<Self::Output> {
        let policy_eval::AllowOutcome { decision, log } = outcome;
        let forward_result = self.forward_request(&decision).await;
        let handled = policy_response::handle_forward_result(
            &decision,
            log.clone(),
            forward_result,
            self.ctx.peer,
            &self.ctx.meta.parsed.host,
        )
        .await?;
        match handled {
            policy_response::ForwardOutcome::Completed(success) => {
                let stats = self.build_allow_log_stats(&success);
                log_allow_success(log, &decision, stats, None, None);
                self.handle_forward_success(success).await
            }
            policy_response::ForwardOutcome::Responded(ctx) => {
                self.respond_forward_error(ctx.spec, ctx.log, ctx.decision)
                    .await
            }
        }
    }

    async fn on_deny(&mut self, outcome: policy_eval::DenyOutcome<'_>) -> Result<Self::Output> {
        self.ctx.handle_deny(outcome).await
    }

    async fn on_default_deny(
        &mut self,
        outcome: policy_eval::DefaultDenyOutcome<'_>,
    ) -> Result<Self::Output> {
        self.ctx.handle_default_deny(outcome).await
    }
}
