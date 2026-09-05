use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::future::poll_fn;
use h2::server::{self, SendResponse};
use http;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, Semaphore, watch},
    task::JoinSet,
    time::{sleep, timeout},
};
use tokio_rustls::server::TlsStream;
use tracing::warn;

use crate::{
    authorization::{BodyAccess, BufferedBody, FinalizedProtocol, FinalizedRequestV1},
    policy::matcher::PolicySnapshot,
    proxy::{
        AppContext,
        allow_log::{AllowLogStats, log_allow_success},
        cache::HttpCache,
        connect::ResolvedTarget,
        forward_error::{ForwardErrorKind, classify_forward_error, log_forward_error},
        forward_limits::{
            AllowLogTracker, RequestDeadline, ResponseProgress, validate_declared_body_size,
        },
        policy_eval::{self, AllowDecision, PolicyLogConfig, RequestLogContext},
        policy_response::{self, ForwardErrorSpec},
        request::RequestFlowContext,
        request_pipeline::{self, RequestHandler},
    },
};
use async_trait::async_trait;

use super::{
    cache::{CacheEvaluation, CacheMiss, evaluate_cache, send_cached_response},
    forward::{
        buffer_request_body, forward_finalized_request_to_upstream, forward_request_to_upstream,
        send_error_response,
    },
    request::{SanitizedRequest, reject_expect_header, sanitize_request},
    upstream::{Http2Upstream, PrimedHttp2Upstream},
};

pub async fn serve_bumped_http2<S>(
    stream: TlsStream<S>,
    peer: SocketAddr,
    app: AppContext,
    connect_binding: ResolvedTarget,
    primed_upstream: Option<PrimedHttp2Upstream>,
    flow_context: RequestFlowContext,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut service = Http2BumpService::new(
        stream,
        peer,
        app,
        connect_binding,
        primed_upstream,
        flow_context,
    )
    .await?;
    service.run().await
}

struct Http2BumpService<S> {
    peer: SocketAddr,
    app: AppContext,
    connection: server::Connection<TlsStream<S>, Bytes>,
    upstream: Arc<Mutex<Http2Upstream>>,
    upstream_closed: watch::Receiver<bool>,
    flow_context: RequestFlowContext,
    request_slots: Arc<Semaphore>,
}

impl<S> Http2BumpService<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn new(
        stream: TlsStream<S>,
        peer: SocketAddr,
        app: AppContext,
        connect_binding: ResolvedTarget,
        primed_upstream: Option<PrimedHttp2Upstream>,
        flow_context: RequestFlowContext,
    ) -> Result<Self> {
        let connection = handshake_downstream(
            stream,
            app.settings.max_request_header_size,
            app.settings.http2_max_concurrent_streams,
            app.settings.request_header_timeout(),
        )
        .await?;
        let upstream = Http2Upstream::new(app.clone(), connect_binding, primed_upstream);
        let upstream_closed = upstream.closed_receiver();
        let request_slots = Arc::new(Semaphore::new(
            app.settings.http2_max_concurrent_streams_usize(),
        ));
        Ok(Self {
            peer,
            app,
            connection,
            upstream: Arc::new(Mutex::new(upstream)),
            upstream_closed,
            flow_context,
            request_slots,
        })
    }

    async fn run(&mut self) -> Result<()> {
        let mut tasks = JoinSet::new();
        let keepalive_timeout = self.app.settings.client_keepalive_idle_timeout();
        loop {
            tokio::select! {
                biased;
                result = self.upstream_closed.changed() => {
                    match result {
                        Ok(()) if *self.upstream_closed.borrow() => {
                            warn!(
                                peer = %self.peer,
                                "closing downstream HTTP/2 session after upstream connection closed"
                            );
                            self.connection.graceful_shutdown();
                            if let Err(err) = poll_fn(|cx| self.connection.poll_closed(cx)).await {
                                warn!(
                                    peer = %self.peer,
                                    error = %err,
                                    "failed to close downstream HTTP/2 connection after upstream shutdown"
                                );
                            }
                            break;
                        }
                        Ok(()) => continue,
                        Err(_) => break,
                    }
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(result) = result {
                        log_stream_task_completion(self.peer, result);
                    }
                }
                result = self.connection.accept() => {
                    let Some(result) = result else {
                        break;
                    };
                    match result {
                        Ok((request, respond)) => {
                            let peer = self.peer;
                            let app = self.app.clone();
                            let upstream = self.upstream.clone();
                            let flow_context = self.flow_context.clone();
                            let permit = self
                                .request_slots
                                .clone()
                                .acquire_owned()
                                .await
                                .expect("HTTP/2 request semaphore should remain open");
                            tasks.spawn(async move {
                                let _permit = permit;
                                if let Err(err) =
                                    process_downstream_request(
                                        request,
                                        respond,
                                        peer,
                                        app,
                                        upstream,
                                        flow_context,
                                    )
                                    .await
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
                _ = sleep(keepalive_timeout), if tasks.is_empty() => {
                    tracing::debug!(
                        peer = %self.peer,
                        "closing idle downstream HTTP/2 session"
                    );
                    break;
                }
            }
        }
        while let Some(result) = tasks.join_next().await {
            log_stream_task_completion(self.peer, result);
        }
        let mut upstream = self.upstream.lock().await;
        upstream.shutdown().await;
        Ok(())
    }
}

async fn handshake_downstream<T>(
    stream: T,
    max_header_size: usize,
    max_concurrent_streams: u32,
    setup_timeout: Duration,
) -> Result<server::Connection<T, Bytes>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut builder = server::Builder::new();
    builder
        .max_header_list_size(max_header_size.min(u32::MAX as usize) as u32)
        .max_concurrent_streams(max_concurrent_streams);
    timeout(setup_timeout, builder.handshake(stream))
        .await
        .context("timed out waiting for downstream HTTP/2 connection preface")?
        .context("failed to handshake HTTP/2 with downstream client")
}

fn log_stream_task_completion(peer: SocketAddr, result: Result<(), tokio::task::JoinError>) {
    if let Err(err) = result {
        warn!(
            peer = %peer,
            error = %err,
            "HTTP/2 downstream request task failed"
        );
    }
}

async fn process_downstream_request(
    request: http::Request<h2::RecvStream>,
    respond: SendResponse<Bytes>,
    peer: SocketAddr,
    app: AppContext,
    upstream: Arc<Mutex<Http2Upstream>>,
    flow_context: RequestFlowContext,
) -> Result<()> {
    let _stream_guard = crate::metrics::track_http2_stream();
    let start = Instant::now();

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
            None,
        )
        .await?;
        return Ok(());
    }

    let snapshot = app.policies.snapshot();
    // Inner requests inherit the CONNECT token, but must not replace it or
    // hide malformed/duplicate authentication headers during sanitization.
    let authorization_token = app.authorization.as_ref().and_then(|authorization| {
        let bound = flow_context.authorization_token.as_ref()?;
        authorization
            .bind_token(
                request
                    .headers()
                    .get_all(http::header::PROXY_AUTHORIZATION)
                    .iter()
                    .map(http::HeaderValue::as_bytes),
                Some(bound),
            )
            .ok()
    });
    let flow_context = RequestFlowContext {
        authorization_token,
        ..flow_context
    };
    let max_request_header_size = app.settings.max_request_header_size;
    let (meta, body) = match sanitize_request(request, max_request_header_size, &flow_context) {
        Ok(result) => result,
        Err(err) => {
            warn!(
                peer = %peer,
                error = %err,
                "failed to sanitize HTTP/2 request"
            );
            let mut respond = respond;
            send_error_response(
                &mut respond,
                http::StatusCode::BAD_REQUEST,
                "invalid request",
                None,
            )
            .await?;
            return Ok(());
        }
    };
    let ctx = DownstreamRequestCtx::new(meta, body, respond, peer, snapshot, start, &app);
    ctx.handle(upstream).await
}

struct DownstreamRequestCtx {
    peer: SocketAddr,
    meta: SanitizedRequest,
    body: h2::RecvStream,
    respond: SendResponse<Bytes>,
    snapshot: PolicySnapshot,
    request_body_timeout: Duration,
    response_header_timeout: Duration,
    response_body_timeout: Duration,
    request_deadline: RequestDeadline,
    response_progress: ResponseProgress,
    max_request_body_size: usize,
    max_request_header_bytes: usize,
    max_response_header_bytes: usize,
    log_queries: bool,
    cache: Option<Arc<HttpCache>>,
    log_tracker: AllowLogTracker,
    authorization: Option<Arc<crate::authorization::AuthorizationServices>>,
    authorization_token: Option<Arc<crate::authorization::AuthorizationToken>>,
}

impl DownstreamRequestCtx {
    fn new(
        meta: SanitizedRequest,
        body: h2::RecvStream,
        respond: SendResponse<Bytes>,
        peer: SocketAddr,
        snapshot: PolicySnapshot,
        start: Instant,
        app: &AppContext,
    ) -> Self {
        let log_queries = app.settings.log_queries;
        let request_base = meta.request_line_bytes + meta.header_bytes as u64;
        let authorization_token = meta
            .parsed
            .flow_context()
            .and_then(|flow| flow.authorization_token.clone());
        Self {
            peer,
            meta,
            body,
            respond,
            snapshot,
            request_body_timeout: app.settings.request_body_idle_timeout(),
            response_header_timeout: app.settings.response_header_timeout(),
            response_body_timeout: app.settings.response_body_idle_timeout(),
            request_deadline: RequestDeadline::new(start, app.settings.request_total_timeout()),
            response_progress: ResponseProgress::default(),
            max_request_body_size: app.settings.max_request_body_size,
            max_request_header_bytes: app.settings.max_request_header_size,
            max_response_header_bytes: app.settings.max_response_header_size,
            log_queries,
            cache: app.cache.clone(),
            log_tracker: AllowLogTracker::new(request_base, start),
            authorization: app.authorization.clone(),
            authorization_token,
        }
    }

    async fn handle(self, upstream: Arc<Mutex<Http2Upstream>>) -> Result<()> {
        let peer = self.peer;
        let log_queries = self.log_queries;
        let snapshot = self.snapshot.clone();
        let parsed_for_policy = self.meta.parsed.clone();
        let authorization = self.authorization.clone();
        let authorization_token = self.authorization_token.clone();
        let mut handler = Http2RequestHandler {
            ctx: self,
            upstream,
        };
        request_pipeline::process_request(
            peer,
            &parsed_for_policy,
            &snapshot,
            authorization
                .as_deref()
                .map(|authorization| (authorization, authorization_token.as_ref())),
            handler.ctx.request_deadline.instant(),
            log_queries,
            PolicyLogConfig::http1(),
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
            None,
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
            None,
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
        decision: &AllowDecision,
        error_detail: &str,
    ) -> Result<()> {
        send_error_response(&mut self.respond, spec.status, spec.body_http2, None).await?;
        self.log_tracker
            .record_client_body_bytes(spec.extra_client_bytes);
        policy_response::forward_error_log_builder(
            log.access_log_builder(),
            decision,
            &spec,
            error_detail,
        )
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

enum AllowedRequestResult {
    CacheHit {
        status: http::StatusCode,
        bytes_out: u64,
    },
    Forwarded {
        success: super::forward::ForwardOutcome,
        cache_lookup: &'static str,
    },
}

impl Http2RequestHandler {
    fn should_disconnect_on_forward_error(kind: &ForwardErrorKind<'_>) -> bool {
        !matches!(
            kind,
            ForwardErrorKind::Http2StreamReset
                | ForwardErrorKind::InvalidRequestBody(_)
                | ForwardErrorKind::BodyTooLarge(_)
                | ForwardErrorKind::CredentialPreparationFailed
                | ForwardErrorKind::CredentialRequestRejected(_)
                | ForwardErrorKind::PrivateAddress(_)
                | ForwardErrorKind::RequestTimeout
                | ForwardErrorKind::ClientBodyIdleTimeout
                | ForwardErrorKind::MisdirectedRequest(_)
        )
    }

    fn forward_error_decision(kind: &ForwardErrorKind<'_>) -> &'static str {
        match kind {
            ForwardErrorKind::BodyTooLarge(_) | ForwardErrorKind::PrivateAddress(_) => "DENY",
            ForwardErrorKind::CredentialRequestRejected(_) => "DENY",
            ForwardErrorKind::ResponseAlreadyStarted(_)
            | ForwardErrorKind::Http2StreamReset
            | ForwardErrorKind::RequestTimeout
            | ForwardErrorKind::ClientBodyIdleTimeout
            | ForwardErrorKind::CredentialPreparationFailed
            | ForwardErrorKind::InvalidRequestBody(_)
            | ForwardErrorKind::MisdirectedRequest(_)
            | ForwardErrorKind::UpstreamClosed
            | ForwardErrorKind::Other => "ERROR",
        }
    }

    async fn forward_request(
        &mut self,
        decision: &AllowDecision,
        cache_miss: Option<Box<CacheMiss>>,
    ) -> Result<super::forward::ForwardOutcome> {
        let forward_meta = self.ctx.meta.clone();
        if let Some(credential) = decision
            .authorization
            .as_ref()
            .and_then(|authorization| authorization.credential.as_ref())
        {
            if credential.body_access == BodyAccess::None
                && (!self.ctx.body.is_end_stream()
                    || self.ctx.meta.content_length.unwrap_or(0) != 0)
            {
                return Err(
                    crate::proxy::forward_error::CredentialRequestRejected::body_not_allowed()
                        .into(),
                );
            }
            {
                let upstream = self.upstream.lock().await;
                upstream.validate_request_target(&forward_meta.parsed)?;
            }
            let buffered_body = if self.ctx.body.is_end_stream() {
                None
            } else {
                let authorization = self
                    .ctx
                    .authorization
                    .as_ref()
                    .expect("credential decision requires authorization services");
                let max_body_size =
                    authorization.buffered_body_limit(self.ctx.max_request_body_size);
                let buffer_limit =
                    credential_body_buffer_limit(self.ctx.meta.content_length, max_body_size)?;
                let permit = authorization.reserve_buffered_body(buffer_limit).await?;
                let (bytes, wire_bytes) = buffer_request_body(
                    &mut self.ctx.body,
                    self.ctx.request_body_timeout,
                    self.ctx.request_deadline.instant(),
                    buffer_limit,
                )
                .await?;
                Some(BufferedBody::new(bytes, wire_bytes, permit))
            };
            let client_body_bytes = buffered_body.as_ref().map_or(0, BufferedBody::wire_bytes);
            self.ctx
                .log_tracker
                .record_client_body_bytes(client_body_bytes);
            let mut finalized = FinalizedRequestV1::new(
                &forward_meta.parsed,
                forward_meta.forward_headers,
                forward_meta.content_length,
                buffered_body,
                credential.protected_headers.clone(),
                FinalizedProtocol::Http2,
                self.ctx.max_request_header_bytes,
            )
            .map_err(crate::proxy::forward_error::credential_finalization_failed)?;
            self.ctx
                .authorization
                .as_ref()
                .expect("credential decision requires authorization services")
                .prepare_headers(
                    credential,
                    &mut finalized,
                    self.ctx.peer,
                    self.ctx.max_request_header_bytes,
                )
                .await
                .map_err(crate::proxy::forward_error::credential_preparation_failed)?;
            let checkout = {
                let mut upstream = self.upstream.lock().await;
                upstream.checkout_sender(&forward_meta.parsed).await?
            };
            return forward_finalized_request_to_upstream(
                checkout,
                finalized,
                &mut self.ctx.respond,
                self.ctx.request_body_timeout,
                self.ctx.response_header_timeout,
                self.ctx.response_body_timeout,
                self.ctx.request_deadline,
                &self.ctx.response_progress,
                self.ctx.max_response_header_bytes,
            )
            .await;
        }
        let checkout = {
            let mut upstream = self.upstream.lock().await;
            upstream.checkout_sender(&forward_meta.parsed).await?
        };
        forward_request_to_upstream(
            checkout,
            forward_meta,
            &mut self.ctx.body,
            &mut self.ctx.respond,
            self.ctx.request_body_timeout,
            self.ctx.response_header_timeout,
            self.ctx.response_body_timeout,
            self.ctx.request_deadline,
            &self.ctx.response_progress,
            self.ctx.max_request_body_size,
            self.ctx.max_request_header_bytes,
            self.ctx.max_response_header_bytes,
            cache_miss,
        )
        .await
    }

    fn build_allow_log_stats(&mut self, success: &super::forward::ForwardOutcome) -> AllowLogStats {
        self.ctx
            .log_tracker
            .record_client_body_bytes(success.client_body_bytes());
        self.ctx.log_tracker.build_allow_log_stats(
            success.status(),
            success.bytes_to_client(),
            success.upstream_addr(),
            success.upstream_reused(),
        )
    }

    async fn handle_forward_error(
        &mut self,
        decision: &AllowDecision,
        log: RequestLogContext<'_>,
        err: anyhow::Error,
    ) -> Result<()> {
        let kind = classify_forward_error(&err);
        let should_disconnect = Self::should_disconnect_on_forward_error(&kind);
        let error_detail = err.to_string();

        crate::metrics::record_upstream_error(kind.as_metric_label());
        log_forward_error(&kind, &log, &err);

        if matches!(
            kind,
            ForwardErrorKind::ResponseAlreadyStarted(_) | ForwardErrorKind::Http2StreamReset
        ) {
            // Dropping the affected H2 stream resets it. Other multiplexed streams and the
            // shared upstream session remain usable.
            self.log_disconnect_forward_error(decision, log, &kind, &error_detail);
            Ok(())
        } else if should_disconnect {
            {
                let mut upstream = self.upstream.lock().await;
                upstream.terminate_session().await;
            }
            self.log_disconnect_forward_error(decision, log, &kind, &error_detail);
            Ok(())
        } else {
            let spec = policy_response::forward_error_spec(&kind);
            self.ctx
                .respond_forward_error(spec, log, decision, &error_detail)
                .await
        }
    }

    fn log_disconnect_forward_error(
        &mut self,
        decision: &AllowDecision,
        log: RequestLogContext<'_>,
        kind: &ForwardErrorKind<'_>,
        error_detail: &str,
    ) {
        log.access_log_builder()
            .client(decision.client.as_ref())
            .decision(Self::forward_error_decision(kind))
            .policy(decision.policy.as_ref())
            .rule(decision.rule.as_ref())
            .error_reason(kind.as_metric_label())
            .error_detail(error_detail)
            .bytes(self.ctx.log_tracker.current_bytes(), 0)
            .elapsed(self.ctx.log_tracker.elapsed())
            .log();
    }
}

fn credential_body_buffer_limit(declared: Option<usize>, maximum: usize) -> Result<usize> {
    validate_declared_body_size(declared, maximum)?;
    Ok(declared.unwrap_or(maximum))
}

#[async_trait]
impl RequestHandler for Http2RequestHandler {
    type Output = ();

    async fn on_allow(&mut self, outcome: policy_eval::AllowOutcome<'_>) -> Result<Self::Output> {
        let policy_eval::AllowOutcome { decision, log } = outcome;

        let deadline = self.ctx.request_deadline;
        let progress = self.ctx.response_progress.clone();
        let result = deadline
            .run(&progress, async {
                validate_declared_body_size(
                    self.ctx.meta.content_length,
                    self.ctx.max_request_body_size,
                )?;
                let cache_evaluation = evaluate_cache(
                    &self.ctx.meta,
                    self.ctx.body.is_end_stream(),
                    &decision,
                    self.ctx.cache.as_ref(),
                    self.ctx.peer,
                )
                .await;
                let (cache_lookup, cache_miss) = match cache_evaluation {
                    CacheEvaluation::Hit(cached) => {
                        let (status, bytes_out) = send_cached_response(
                            &mut self.ctx.respond,
                            &self.ctx.meta.parsed.method,
                            *cached,
                            self.ctx.response_body_timeout,
                            self.ctx.request_deadline,
                            &self.ctx.response_progress,
                            self.ctx.max_response_header_bytes,
                        )
                        .await?;
                        return Ok(AllowedRequestResult::CacheHit { status, bytes_out });
                    }
                    CacheEvaluation::Miss(miss) => ("miss", Some(miss)),
                    CacheEvaluation::Bypass => ("bypass", None),
                };

                let success = self.forward_request(&decision, cache_miss).await?;
                Ok(AllowedRequestResult::Forwarded {
                    success,
                    cache_lookup,
                })
            })
            .await;

        match result {
            Ok(AllowedRequestResult::CacheHit { status, bytes_out }) => {
                log.access_log_builder()
                    .decision("CACHE_HIT")
                    .client(decision.client.as_ref())
                    .policy(decision.policy.as_ref())
                    .rule(decision.rule.as_ref())
                    .status(status)
                    .bytes(self.ctx.log_tracker.base_bytes(), bytes_out)
                    .elapsed(self.ctx.log_tracker.elapsed())
                    .cache_lookup("hit")
                    .cache_store("bypassed")
                    .log();
                Ok(())
            }
            Ok(AllowedRequestResult::Forwarded {
                success,
                cache_lookup,
            }) => {
                let stats = self.build_allow_log_stats(&success);
                log_allow_success(
                    log,
                    &decision,
                    stats,
                    Some(cache_lookup),
                    Some(success.cache_store()),
                );
                Ok(())
            }
            Err(err) => self.handle_forward_error(&decision, log, err).await,
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

    async fn on_auth_deny(&mut self, log: RequestLogContext<'_>) -> Result<Self::Output> {
        send_error_response(
            &mut self.ctx.respond,
            http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "proxy authentication required",
            Some("ExfilGuard"),
        )
        .await?;
        log.access_log_builder()
            .status(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            .decision("DENY")
            .error_reason("proxy_authentication")
            .bytes(
                self.ctx.log_tracker.base_bytes(),
                "proxy authentication required".len() as u64,
            )
            .elapsed(self.ctx.log_tracker.elapsed())
            .log();
        Ok(())
    }

    async fn on_authorization_service_error(
        &mut self,
        log: RequestLogContext<'_>,
    ) -> Result<Self::Output> {
        send_error_response(
            &mut self.ctx.respond,
            http::StatusCode::BAD_GATEWAY,
            "authorization service failed",
            None,
        )
        .await?;
        log.access_log_builder()
            .status(http::StatusCode::BAD_GATEWAY)
            .decision("ERROR")
            .error_reason("authorization_service_failed")
            .bytes(
                self.ctx.log_tracker.base_bytes(),
                "authorization service failed".len() as u64,
            )
            .elapsed(self.ctx.log_tracker.elapsed())
            .log();
        Ok(())
    }

    async fn on_request_timeout(&mut self, log: RequestLogContext<'_>) -> Result<Self::Output> {
        send_error_response(
            &mut self.ctx.respond,
            http::StatusCode::GATEWAY_TIMEOUT,
            "request timed out",
            None,
        )
        .await?;
        log.access_log_builder()
            .status(http::StatusCode::GATEWAY_TIMEOUT)
            .decision("ERROR")
            .error_reason("request_timeout")
            .bytes(
                self.ctx.log_tracker.base_bytes(),
                "request timed out".len() as u64,
            )
            .elapsed(self.ctx.log_tracker.elapsed())
            .log();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use tokio::sync::mpsc;

    #[tokio::test(start_paused = true)]
    async fn downstream_handshake_times_out_without_connection_preface() {
        let (_client, server) = duplex(1024);
        let task = tokio::spawn(handshake_downstream(
            server,
            32 * 1024,
            100,
            Duration::from_secs(1),
        ));
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(1)).await;
        let error = task.await.unwrap().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("timed out waiting for downstream HTTP/2 connection preface"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn completed_stream_tasks_are_reaped_while_accept_source_remains_open() {
        let mut tasks = JoinSet::new();
        for _ in 0..256 {
            tasks.spawn(async {});
        }
        assert_eq!(tasks.len(), 256);

        let (accept_source, mut accepted) = mpsc::unbounded_channel::<()>();
        let peer = "127.0.0.1:3128".parse().unwrap();
        while !tasks.is_empty() {
            tokio::select! {
                biased;
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(result) = result {
                        log_stream_task_completion(peer, result);
                    }
                }
                value = accepted.recv() => {
                    panic!("open idle accept source unexpectedly completed: {value:?}");
                }
            }
        }

        assert_eq!(tasks.len(), 0);
        assert!(!accept_source.is_closed());
    }

    #[test]
    fn credential_body_buffer_uses_declared_size() {
        assert_eq!(credential_body_buffer_limit(Some(7), 1024).unwrap(), 7);
        assert_eq!(credential_body_buffer_limit(None, 1024).unwrap(), 1024);
        assert!(credential_body_buffer_limit(Some(1025), 1024).is_err());
    }
}
