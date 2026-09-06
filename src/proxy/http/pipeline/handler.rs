use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};

use async_trait::async_trait;

use crate::proxy::{
    AppContext,
    allow_log::log_allow_success,
    connect::ResolvedTarget,
    forward_error::{ForwardErrorKind, classify_forward_error, log_forward_error},
    forward_limits::{AllowLogTracker, RequestDeadline, ResponseProgress},
    policy_eval, policy_response,
    request::ParsedRequest,
    request_pipeline::RequestHandler,
};

use super::ClientDisposition;
use super::cache::{CacheEvaluation, evaluate_cache};
use super::forward::{
    build_allow_log_stats, forward_request, handle_forward_success, respond_forward_error,
};
use super::respond::shutdown_stream;

use super::super::body::BodyPlan;
use super::super::codec::Http1HeaderAccumulator;
use super::super::upstream::UpstreamPool;

enum AllowedRequestResult {
    CacheHit(ClientDisposition),
    Forwarded {
        result: super::super::forward::ForwardResult,
        cache_lookup: Option<&'static str>,
    },
}

pub(super) struct Http1RequestHandler<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub(super) reader: &'a mut BufReader<S>,
    pub(super) upstream_pool: &'a mut UpstreamPool,
    pub(super) app: &'a AppContext,
    pub(super) connect_binding: Option<&'a ResolvedTarget>,
    pub(super) headers: Http1HeaderAccumulator,
    pub(super) body_plan: BodyPlan,
    pub(super) log_tracker: AllowLogTracker,
    pub(super) peer: SocketAddr,
    pub(super) request_body_timeout: Duration,
    pub(super) response_header_timeout: Duration,
    pub(super) response_body_timeout: Duration,
    pub(super) request_deadline: RequestDeadline,
    pub(super) response_progress: ResponseProgress,
    pub(super) parsed: &'a ParsedRequest,
    pub(super) expect_continue: bool,
}

#[async_trait]
impl<'a, S> RequestHandler for Http1RequestHandler<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    type Output = ClientDisposition;

    async fn on_allow(&mut self, outcome: policy_eval::AllowOutcome<'_>) -> Result<Self::Output> {
        let policy_eval::AllowOutcome { decision, log } = outcome;

        let deadline = self.request_deadline;
        let progress = self.response_progress.clone();
        let allowed_result = deadline
            .run(&progress, async {
                let cache_lookup = match evaluate_cache(self, &decision, &log).await? {
                    CacheEvaluation::Hit(disposition) => {
                        return Ok(AllowedRequestResult::CacheHit(disposition));
                    }
                    CacheEvaluation::Miss => Some("miss"),
                    CacheEvaluation::Bypass => Some("bypass"),
                };

                let result = forward_request(self, &decision).await?;
                Ok(AllowedRequestResult::Forwarded {
                    result,
                    cache_lookup,
                })
            })
            .await;

        let (success, cache_lookup) = match allowed_result {
            Ok(AllowedRequestResult::CacheHit(disposition)) => return Ok(disposition),
            Ok(AllowedRequestResult::Forwarded {
                result,
                cache_lookup,
            }) => (result, cache_lookup),
            Err(err) => {
                let kind = classify_forward_error(&err);
                if let ForwardErrorKind::ResponseAlreadyStarted(_) = &kind {
                    crate::metrics::record_upstream_error(kind.as_metric_label());
                    log_forward_error(&kind, &log, &err);
                    let error_detail = err.to_string();
                    let shutdown_result =
                        shutdown_stream(self.reader.get_mut(), self.response_body_timeout).await;
                    policy_response::forward_disconnect_log_builder(
                        log.access_log_builder(),
                        &decision,
                        &kind,
                        &error_detail,
                        &self.log_tracker,
                    )
                    .log();
                    shutdown_result?;
                    return Ok(ClientDisposition::Close);
                }
                let handled = policy_response::handle_forward_result::<
                    super::super::forward::ForwardResult,
                >(&decision, log.clone(), Err(err))
                .await?;
                match handled {
                    policy_response::ForwardOutcome::Responded(ctx) => {
                        return respond_forward_error(
                            self,
                            ctx.spec,
                            ctx.log,
                            ctx.decision,
                            &ctx.error_detail,
                        )
                        .await;
                    }
                    policy_response::ForwardOutcome::Completed(_) => unreachable!(),
                }
            }
        };

        let stats = build_allow_log_stats(self, &success);
        log_allow_success(
            log,
            &decision,
            stats,
            cache_lookup,
            Some(success.stats.cache_store.as_str()),
        );
        handle_forward_success(self, success).await
    }

    async fn on_deny(&mut self, outcome: policy_eval::DenyOutcome<'_>) -> Result<Self::Output> {
        let deny = outcome.decision;
        let log = outcome.log;
        let response = policy_response::build_policy_deny_response(&log, &deny);
        super::respond::respond_with_access_log(
            self.reader.get_mut(),
            response.spec.status,
            response.spec.reason,
            response.spec.body_http1,
            None,
            self.response_body_timeout,
            self.log_tracker.base_bytes(),
            self.log_tracker.elapsed(),
            response.log_builder,
        )
        .await?;
        Ok(ClientDisposition::Close)
    }

    async fn on_default_deny(
        &mut self,
        outcome: policy_eval::DefaultDenyOutcome<'_>,
    ) -> Result<Self::Output> {
        let log = outcome.log;
        let response = policy_response::build_default_deny_response(&log);
        super::respond::respond_with_access_log(
            self.reader.get_mut(),
            response.spec.status,
            response.spec.reason,
            response.spec.body_http1,
            None,
            self.response_body_timeout,
            self.log_tracker.base_bytes(),
            self.log_tracker.elapsed(),
            response.log_builder,
        )
        .await?;
        Ok(ClientDisposition::Close)
    }

    async fn on_auth_deny(
        &mut self,
        log: policy_eval::RequestLogContext<'_>,
    ) -> Result<Self::Output> {
        super::respond::respond_with_access_log(
            self.reader.get_mut(),
            http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            None,
            b"proxy authentication required\r\n",
            Some("ExfilGuard"),
            self.response_body_timeout,
            self.log_tracker.base_bytes(),
            self.log_tracker.elapsed(),
            log.access_log_builder()
                .status(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .decision("DENY")
                .error_reason("proxy_authentication"),
        )
        .await?;
        Ok(ClientDisposition::Close)
    }

    async fn on_authorization_service_error(
        &mut self,
        log: policy_eval::RequestLogContext<'_>,
    ) -> Result<Self::Output> {
        super::respond::respond_with_access_log(
            self.reader.get_mut(),
            http::StatusCode::BAD_GATEWAY,
            None,
            b"authorization service failed\r\n",
            None,
            self.response_body_timeout,
            self.log_tracker.base_bytes(),
            self.log_tracker.elapsed(),
            log.access_log_builder()
                .status(http::StatusCode::BAD_GATEWAY)
                .decision("ERROR")
                .error_reason("authorization_service_failed"),
        )
        .await?;
        Ok(ClientDisposition::Close)
    }

    async fn on_request_timeout(
        &mut self,
        log: policy_eval::RequestLogContext<'_>,
    ) -> Result<Self::Output> {
        super::respond::respond_with_access_log(
            self.reader.get_mut(),
            http::StatusCode::GATEWAY_TIMEOUT,
            None,
            b"request timed out\r\n",
            None,
            self.response_body_timeout,
            self.log_tracker.base_bytes(),
            self.log_tracker.elapsed(),
            log.access_log_builder()
                .status(http::StatusCode::GATEWAY_TIMEOUT)
                .decision("ERROR")
                .error_reason("request_timeout"),
        )
        .await?;
        Ok(ClientDisposition::Close)
    }
}
