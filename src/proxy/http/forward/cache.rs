use std::net::SocketAddr;
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::io_util::PayloadCopy;
use crate::proxy::AppContext;
use crate::proxy::cache::{
    CacheFinishOutcome, CacheResponseTiming, CacheSkipReason, CacheStorePlan, CacheWritePlan,
    CacheWriter, build_http1_cache_request_context, plan_cache_write,
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
    pub generation: Option<u64>,
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
    let CacheResponse {
        head,
        timing,
        generation,
    } = response;
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

    let cache_request = match build_http1_cache_request_context(request, headers) {
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
    if head.transfer_encoding_present && !has_exact_chunked_transfer_encoding(&response_headers) {
        return CacheWriteState::Skip;
    }
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
            let Some(generation) = generation else {
                return CacheWriteState::Bypass;
            };
            let stream = timeout(
                app.settings.response_body_idle_timeout(),
                cache.open_stream(
                    &request.method,
                    &plan.request.uri,
                    &plan.request.headers,
                    &plan.response_headers,
                    generation,
                ),
            )
            .await
            .context("timed out opening cache write stream")
            .and_then(|result| result);
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

fn has_exact_chunked_transfer_encoding(headers: &http::HeaderMap) -> bool {
    let mut codings = headers
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim);
    matches!(codings.next(), Some(coding) if coding.eq_ignore_ascii_case("chunked"))
        && codings.next().is_none()
}

fn strip_hop_by_hop_response_headers(headers: &mut http::HeaderMap) {
    let connection_tokens = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .filter_map(|token| http::header::HeaderName::from_bytes(token.as_bytes()).ok())
        .collect::<Vec<_>>();

    for token in connection_tokens {
        headers.remove(token);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
    ] {
        headers.remove(name);
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
                    None,
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
                    None,
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
                let mut best_effort = PayloadCopy::best_effort(&mut writer);
                let bytes = relay_body(
                    upstream_reader,
                    client,
                    Some(&mut best_effort),
                    response_body_plan,
                    timeouts,
                    upstream_peer,
                    total_deadline,
                    max_response_trailer_bytes,
                )
                .await?;

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
                    writer.discard_in_background();
                }
                if discarded_for_trailers {
                    writer.discard_in_background();
                }

                let CacheStorePlan {
                    mut response_headers,
                    timing,
                    ..
                } = plan;
                strip_hop_by_hop_response_headers(&mut response_headers);
                if matches!(response_body_plan, ResponseBodyPlan::Chunked) {
                    response_headers.remove(http::header::CONTENT_LENGTH);
                }
                writer.defer_cleanup();
                let finish_result = if cache_failed || discarded_for_trailers {
                    Ok(CacheFinishOutcome::Skipped)
                } else {
                    timeout(
                        timeouts.response_io,
                        writer.finish(status, response_headers, timing),
                    )
                    .await
                    .context("timed out finalizing cache entry")
                    .and_then(|result| result)
                };

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

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};

    use super::{has_exact_chunked_transfer_encoding, strip_hop_by_hop_response_headers};

    #[test]
    fn canonical_chunk_storage_requires_only_chunked_transfer_coding() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        assert!(has_exact_chunked_transfer_encoding(&headers));

        headers.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("gzip, chunked"),
        );
        assert!(!has_exact_chunked_transfer_encoding(&headers));
    }

    #[test]
    fn canonical_metadata_drops_connection_scoped_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("Keep-Alive, X-Private"),
        );
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("x-private", HeaderValue::from_static("secret"));
        headers.insert("x-end-to-end", HeaderValue::from_static("preserved"));

        strip_hop_by_hop_response_headers(&mut headers);

        assert!(!headers.contains_key(http::header::CONNECTION));
        assert!(!headers.contains_key("keep-alive"));
        assert!(!headers.contains_key("x-private"));
        assert_eq!(headers["x-end-to-end"], "preserved");
    }
}
