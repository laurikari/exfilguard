use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use crate::io_util::{copy_with_write_timeout, write_all_with_timeout};
use crate::proxy::{
    cache::CacheLookupOutcome,
    policy_eval::{AllowDecision, RequestLogContext},
};

use super::ClientDisposition;
use super::handler::Http1RequestHandler;
use super::respond::shutdown_stream;

use super::super::codec::{ConnectionOverride, encode_cached_http1_response};
use super::super::forward::{ResponseBodyPlan, determine_response_body_plan};

pub(super) enum CacheEvaluation {
    Hit(ClientDisposition),
    Miss,
    Bypass,
}

pub(super) async fn evaluate_cache<S>(
    handler: &mut Http1RequestHandler<'_, S>,
    decision: &AllowDecision,
    log: &RequestLogContext<'_>,
) -> Result<CacheEvaluation>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let cache = match (&decision.cache, &handler.app.cache) {
        (Some(_cache_config), Some(cache)) => cache,
        _ => return Ok(CacheEvaluation::Bypass),
    };

    match cache
        .lookup_for_request(handler.parsed, &handler.headers)
        .await
    {
        Ok(CacheLookupOutcome::Hit(hit)) => {
            let client_stream = handler.reader.get_mut();
            let hit = *hit;
            let cached = hit.cached;
            let head = hit.head;

            let body_plan =
                determine_response_body_plan(&handler.parsed.method, cached.status, &head);
            let should_close = handler.headers.wants_connection_close()
                || matches!(body_plan, ResponseBodyPlan::UntilClose);
            let override_connection = if should_close {
                Some(ConnectionOverride::Close)
            } else {
                None
            };
            let encoded_head = encode_cached_http1_response(
                &head.status_line,
                &cached.headers,
                body_plan,
                head.content_length,
                override_connection,
            );
            write_all_with_timeout(
                client_stream,
                &encoded_head,
                handler.response_body_timeout,
                "writing cached response head",
            )
            .await?;

            let mut copied = 0u64;
            if !matches!(body_plan, ResponseBodyPlan::Empty) {
                let mut file = tokio::fs::File::open(&cached.body_path).await?;
                copied = copy_with_write_timeout(
                    &mut file,
                    client_stream,
                    handler.response_body_timeout,
                    "writing cached response body",
                )
                .await?;
            }

            if should_close {
                shutdown_stream(client_stream, handler.response_body_timeout).await?;
            }

            let log_builder = log
                .access_log_builder()
                .decision("CACHE_HIT")
                .client(decision.client.as_ref())
                .status(cached.status)
                .bytes(handler.log_tracker.base_bytes(), copied)
                .cache_lookup("hit")
                .cache_store("bypassed");

            let log_builder = log_builder
                .policy(decision.policy.as_ref())
                .rule(decision.rule.as_ref())
                .inspect_payload(decision.inspect_payload);

            log_builder.log();

            Ok(CacheEvaluation::Hit(if should_close {
                ClientDisposition::Close
            } else {
                ClientDisposition::Continue
            }))
        }
        Ok(CacheLookupOutcome::Miss) => Ok(CacheEvaluation::Miss),
        Ok(CacheLookupOutcome::Bypass) => Ok(CacheEvaluation::Bypass),
        Err(err) => {
            debug!(
                peer = %handler.peer,
                error = %err,
                "skipping cache lookup due to URI build failure"
            );
            Ok(CacheEvaluation::Bypass)
        }
    }
}
