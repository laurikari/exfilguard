use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};

use async_trait::async_trait;

use crate::proxy::{
    AppContext, allow_log::log_allow_success, connect::ResolvedTarget,
    forward_limits::AllowLogTracker, policy_eval, policy_response, request::ParsedRequest,
    request_pipeline::RequestHandler,
};

use super::ClientDisposition;
use super::cache::{CacheEvaluation, evaluate_cache};
use super::forward::{
    build_allow_log_stats, forward_request, handle_forward_success, respond_forward_error,
};

use super::super::body::BodyPlan;
use super::super::codec::Http1HeaderAccumulator;
use super::super::upstream::UpstreamPool;

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
    pub(super) request_start: Instant,
    pub(super) request_total_timeout: Option<Duration>,
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

        let cache_lookup = match evaluate_cache(self, &decision, &log).await? {
            CacheEvaluation::Hit(disposition) => return Ok(disposition),
            CacheEvaluation::Miss => Some("miss"),
            CacheEvaluation::Bypass => Some("bypass"),
        };

        let forward_result = forward_request(self, &decision).await;
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
            policy_response::ForwardOutcome::Responded(ctx) => {
                respond_forward_error(self, ctx.spec, ctx.log, ctx.decision, &ctx.error_detail)
                    .await
            }
        }
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
            self.response_body_timeout,
            self.log_tracker.base_bytes(),
            self.log_tracker.elapsed(),
            response.log_builder,
        )
        .await?;
        Ok(ClientDisposition::Close)
    }
}
