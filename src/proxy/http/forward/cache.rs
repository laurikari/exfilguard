use std::net::SocketAddr;
use std::time::Instant;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tracing::{debug, warn};

use crate::io_util::{BestEffortWriter, TeeWriter};
use crate::proxy::AppContext;
use crate::proxy::cache::{
    CacheFinishOutcome, CacheResponseTiming, CacheSkipReason, CacheStorePlan, CacheWritePlan,
    CacheWriter, build_cache_request_context, plan_cache_write,
};
use crate::proxy::policy_eval::AllowDecision;
use crate::proxy::request::ParsedRequest;

use super::super::body::BodyPlan;
use super::super::codec::{Http1HeaderAccumulator, Http1ResponseHead};
use super::response::{ResponseBodyPlan, relay_body};
use super::{CacheStoreResult, ForwardTimeouts};

pub(super) enum CacheWriteState {
    Bypass,
    Skip,
    Store(Box<CacheStoreContext>),
}

pub(super) struct CacheStoreContext {
    writer: CacheWriter,
    plan: CacheStorePlan,
    status: http::StatusCode,
}

pub(super) struct CacheResponse<'a> {
    pub head: &'a Http1ResponseHead,
    pub timing: CacheResponseTiming,
}

pub(super) async fn prepare_cache_write(
    decision: &AllowDecision,
    app: &AppContext,
    request: &ParsedRequest,
    headers: &Http1HeaderAccumulator,
    request_body_plan: BodyPlan,
    response: CacheResponse<'_>,
    peer: SocketAddr,
) -> CacheWriteState {
    let CacheResponse { head, timing } = response;
    if !request_body_plan.is_definitely_empty() {
        return CacheWriteState::Bypass;
    }

    let cache_config = match decision.cache.as_ref() {
        Some(config) => config,
        None => return CacheWriteState::Bypass,
    };
    let cache = match app.cache.as_ref() {
        Some(cache) => cache,
        None => return CacheWriteState::Bypass,
    };

    let cache_request = match build_cache_request_context(request, headers) {
        Ok(context) => Some(context),
        Err(err) => {
            debug!(
                peer = %peer,
                error = %err,
                "skipping cache store due to URI build failure"
            );
            None
        }
    };
    let response_headers = head.header_map();
    let plan = plan_cache_write(
        &request.method,
        cache_request,
        head.status,
        response_headers,
        cache_config.force_cache_duration,
        headers.has_sensitive_cache_headers(),
        timing,
    );

    match plan {
        CacheWritePlan::Bypass => CacheWriteState::Bypass,
        CacheWritePlan::Skip(reason) => {
            if matches!(reason, CacheSkipReason::ResponseSetCookie) {
                warn!(
                    peer = %peer,
                    host = %request.host,
                    "skipping cache store due to Set-Cookie response header"
                );
            } else if matches!(reason, CacheSkipReason::UnrepresentableTtl) {
                warn!(
                    peer = %peer,
                    host = %request.host,
                    "skipping cache store because expiration time is not representable"
                );
            }
            CacheWriteState::Skip
        }
        CacheWritePlan::Store(plan) => {
            let stream = cache
                .open_stream(
                    &request.method,
                    &plan.request.uri,
                    &plan.request.headers,
                    &plan.response_headers,
                )
                .await;
            match stream {
                Ok(Some(writer)) => CacheWriteState::Store(Box::new(CacheStoreContext {
                    writer,
                    plan: *plan,
                    status: head.status,
                })),
                Ok(None) => CacheWriteState::Skip,
                Err(err) => {
                    warn!(
                        peer = %peer,
                        host = %request.host,
                        error = %err,
                        "failed to open cache write stream"
                    );
                    crate::metrics::record_cache_store_error();
                    CacheWriteState::Skip
                }
            }
        }
    }
}

impl CacheWriteState {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn relay_body<S, C>(
        self,
        upstream_reader: &mut BufReader<S>,
        client: &mut C,
        response_body_plan: ResponseBodyPlan,
        timeouts: &ForwardTimeouts,
        upstream_peer: SocketAddr,
        total_deadline: Option<Instant>,
        max_response_trailer_bytes: usize,
        peer: SocketAddr,
        request: &ParsedRequest,
    ) -> Result<(u64, CacheStoreResult)>
    where
        S: AsyncRead + Unpin,
        C: AsyncWrite + Unpin,
    {
        match self {
            CacheWriteState::Bypass => {
                let bytes = relay_body(
                    upstream_reader,
                    client,
                    response_body_plan,
                    timeouts,
                    upstream_peer,
                    total_deadline,
                    max_response_trailer_bytes,
                )
                .await?;
                Ok((bytes.bytes, CacheStoreResult::Bypassed))
            }
            CacheWriteState::Skip => {
                let bytes = relay_body(
                    upstream_reader,
                    client,
                    response_body_plan,
                    timeouts,
                    upstream_peer,
                    total_deadline,
                    max_response_trailer_bytes,
                )
                .await?;
                Ok((bytes.bytes, CacheStoreResult::Skipped))
            }
            CacheWriteState::Store(ctx) => {
                let CacheStoreContext {
                    mut writer,
                    plan,
                    status,
                } = *ctx;
                let mut best_effort = BestEffortWriter::new(&mut writer);
                let bytes = {
                    let mut tee = TeeWriter::new(client, &mut best_effort);
                    relay_body(
                        upstream_reader,
                        &mut tee,
                        response_body_plan,
                        timeouts,
                        upstream_peer,
                        total_deadline,
                        max_response_trailer_bytes,
                    )
                    .await?
                };

                let cache_error = best_effort.take_error();
                let cache_failed = cache_error.is_some();
                let discarded_for_trailers = bytes.had_trailers;
                drop(best_effort);
                if let Some(err) = cache_error.as_ref() {
                    warn!(
                        peer = %peer,
                        host = %request.host,
                        error = %err,
                        "cache write failed"
                    );
                    crate::metrics::record_cache_store_error();
                    writer.discard();
                }
                if discarded_for_trailers {
                    writer.discard();
                }

                let CacheStorePlan {
                    response_headers,
                    timing,
                    ..
                } = plan;
                let finish_result = writer.finish(status, response_headers, timing).await;

                let cache_store = match finish_result {
                    Ok(outcome) => {
                        if outcome == CacheFinishOutcome::Stored
                            && !cache_failed
                            && !discarded_for_trailers
                        {
                            crate::metrics::record_cache_store();
                            CacheStoreResult::Stored
                        } else {
                            CacheStoreResult::Skipped
                        }
                    }
                    Err(err) => {
                        warn!(
                            peer = %peer,
                            host = %request.host,
                            error = %err,
                            "failed to finalize cache entry"
                        );
                        crate::metrics::record_cache_store_error();
                        CacheStoreResult::Skipped
                    }
                };

                Ok((bytes.bytes, cache_store))
            }
        }
    }
}
