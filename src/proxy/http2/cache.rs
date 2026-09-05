use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use h2::server::SendResponse;
use http::{HeaderMap, Method, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::proxy::cache::{
    CacheFinishOutcome, CacheLookupOutcome, CacheRequestContext, CacheResponseTiming,
    CacheStorePlan, CacheWritePlan, CacheWriter, CachedResponse, HttpCache,
    build_cache_request_context, plan_cache_write,
};
use crate::proxy::forward_limits::HeaderBudget;
use crate::proxy::headers::response_header_should_skip;
use crate::proxy::policy_eval::AllowDecision;

use super::forward::{send_data_with_backpressure, with_total_deadline};
use super::request::SanitizedRequest;

const HEADER_PADDING: usize = 4;

pub(super) enum CacheEvaluation {
    Hit(Box<CachedResponse>),
    Miss(Box<CacheMiss>),
    Bypass,
}

pub(super) struct CacheMiss {
    cache: Arc<HttpCache>,
    request: CacheRequestContext,
    force_cache_duration: Option<std::time::Duration>,
    generation: u64,
}

pub(super) async fn evaluate_cache(
    meta: &SanitizedRequest,
    request_end_stream: bool,
    decision: &AllowDecision,
    cache: Option<&Arc<HttpCache>>,
    peer: SocketAddr,
) -> CacheEvaluation {
    if !request_end_stream || meta.content_length.is_some_and(|length| length != 0) {
        return CacheEvaluation::Bypass;
    }
    let (Some(config), Some(cache)) = (decision.cache.as_ref(), cache) else {
        return CacheEvaluation::Bypass;
    };
    let headers = meta.forward_header_map();
    let request = match build_cache_request_context(&meta.parsed, &headers) {
        Ok(request) => request,
        Err(err) => {
            debug!(
                peer = %peer,
                error = %err,
                "skipping HTTP/2 cache lookup due to URI build failure"
            );
            return CacheEvaluation::Bypass;
        }
    };

    let generation = cache.generation();
    match cache.lookup_for_header_map(&meta.parsed, &headers).await {
        Ok(CacheLookupOutcome::Hit(cached)) => CacheEvaluation::Hit(cached),
        Ok(CacheLookupOutcome::Miss) => CacheEvaluation::Miss(Box::new(CacheMiss {
            cache: cache.clone(),
            generation,
            request,
            force_cache_duration: config.force_cache_duration,
        })),
        Ok(CacheLookupOutcome::Bypass) => CacheEvaluation::Bypass,
        Err(err) => {
            debug!(
                peer = %peer,
                error = %err,
                "skipping HTTP/2 cache lookup due to URI build failure"
            );
            CacheEvaluation::Bypass
        }
    }
}

pub(super) struct CacheWriteState {
    state: CacheWriteKind,
}

enum CacheWriteKind {
    Bypassed,
    Skipped,
    Store(Box<CacheWriteContext>),
}

struct CacheWriteContext {
    writer: CacheWriter,
    plan: CacheStorePlan,
    status: StatusCode,
    failed: bool,
}

impl CacheWriteState {
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare(
        miss: Option<Box<CacheMiss>>,
        method: &Method,
        status: StatusCode,
        response_headers: HeaderMap,
        response_time: SystemTime,
        response_delay: std::time::Duration,
        peer: SocketAddr,
        cache_io_timeout: Duration,
    ) -> Self {
        let Some(miss) = miss else {
            return Self {
                state: CacheWriteKind::Bypassed,
            };
        };
        let plan = plan_cache_write(
            method,
            Some(miss.request),
            status,
            response_headers,
            miss.force_cache_duration,
            false,
            CacheResponseTiming {
                response_time,
                response_delay,
            },
        );
        let CacheWritePlan::Store(plan) = plan else {
            return Self {
                state: match plan {
                    CacheWritePlan::Bypass => CacheWriteKind::Bypassed,
                    CacheWritePlan::Skip(_) => CacheWriteKind::Skipped,
                    CacheWritePlan::Store(_) => unreachable!(),
                },
            };
        };

        let open = miss.cache.open_stream(
            method,
            &plan.request.uri,
            &plan.request.headers,
            &plan.response_headers,
            miss.generation,
        );
        match timeout(cache_io_timeout, open).await {
            Err(_) => {
                warn!(peer = %peer, "timed out opening HTTP/2 cache write stream");
                crate::metrics::record_cache_store_error();
                Self {
                    state: CacheWriteKind::Skipped,
                }
            }
            Ok(Ok(Some(writer))) => Self {
                state: CacheWriteKind::Store(Box::new(CacheWriteContext {
                    writer,
                    plan: *plan,
                    status,
                    failed: false,
                })),
            },
            Ok(Ok(None)) => Self {
                state: CacheWriteKind::Skipped,
            },
            Ok(Err(err)) => {
                warn!(peer = %peer, error = %err, "failed to open HTTP/2 cache write stream");
                crate::metrics::record_cache_store_error();
                Self {
                    state: CacheWriteKind::Skipped,
                }
            }
        }
    }

    pub async fn write(&mut self, chunk: &[u8], peer: SocketAddr, cache_io_timeout: Duration) {
        let CacheWriteKind::Store(context) = &mut self.state else {
            return;
        };
        if context.failed {
            return;
        }
        match timeout(cache_io_timeout, context.writer.write_all(chunk)).await {
            Ok(Ok(())) => return,
            Ok(Err(err)) => {
                warn!(peer = %peer, error = %err, "HTTP/2 cache write failed");
            }
            Err(_) => {
                warn!(peer = %peer, "HTTP/2 cache write timed out");
            }
        }
        crate::metrics::record_cache_store_error();
        context.writer.discard_in_background();
        context.failed = true;
    }

    pub fn discard(&mut self) {
        if let CacheWriteKind::Store(context) = &mut self.state {
            context.writer.discard_in_background();
        }
    }

    pub async fn finish(self, peer: SocketAddr, cache_io_timeout: Duration) -> &'static str {
        match self.state {
            CacheWriteKind::Bypassed => "bypassed",
            CacheWriteKind::Skipped => "skipped",
            CacheWriteKind::Store(context) => {
                let CacheWriteContext {
                    mut writer,
                    plan,
                    status,
                    failed,
                } = *context;
                writer.defer_cleanup();
                let finish = writer.finish(status, plan.response_headers, plan.timing);
                let result = timeout(cache_io_timeout, finish).await;
                match result {
                    Ok(Ok(CacheFinishOutcome::Stored)) if !failed => {
                        crate::metrics::record_cache_store();
                        "stored"
                    }
                    Ok(Ok(_)) => "skipped",
                    Ok(Err(err)) => {
                        warn!(peer = %peer, error = %err, "failed to finalize HTTP/2 cache entry");
                        crate::metrics::record_cache_store_error();
                        "skipped"
                    }
                    Err(_) => {
                        warn!(peer = %peer, "timed out finalizing HTTP/2 cache entry");
                        crate::metrics::record_cache_store_error();
                        "skipped"
                    }
                }
            }
        }
    }
}

pub(super) async fn send_cached_response(
    respond: &mut SendResponse<Bytes>,
    method: &Method,
    mut cached: CachedResponse,
    response_body_timeout: std::time::Duration,
    request_deadline: crate::proxy::forward_limits::RequestDeadline,
    response_progress: &crate::proxy::forward_limits::ResponseProgress,
    max_response_header_bytes: usize,
) -> Result<(StatusCode, u64)> {
    let status = cached.status;
    let has_body = method != Method::HEAD
        && !matches!(
            status,
            StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
        );
    let mut headers = canonical_h2_headers(&cached.headers, max_response_header_bytes)?;
    if status == StatusCode::NO_CONTENT {
        headers.remove(http::header::CONTENT_LENGTH);
    } else if has_body {
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_str(&cached.content_length.to_string())
                .expect("cached body length is a valid Content-Length"),
        );
    }
    let header_bytes = header_bytes(&headers, max_response_header_bytes)? as u64;
    let end_stream = !has_body || cached.content_length == 0;
    let mut builder = http::Response::builder().status(status);
    *builder
        .headers_mut()
        .expect("headers available before response body") = headers;
    let response = builder
        .body(())
        .map_err(|err| anyhow!("failed to build cached HTTP/2 response: {err}"))?;
    let mut send = respond
        .send_response(response, end_stream)
        .context("failed to send cached HTTP/2 response headers")?;
    response_progress.mark_started(status, header_bytes);
    if end_stream {
        response_progress.mark_complete();
        return Ok((status, header_bytes));
    }

    let total_deadline = request_deadline.instant();
    let mut remaining = cached.content_length;
    let mut buffer = vec![0u8; 8192];
    while remaining > 0 {
        let to_read = remaining.min(buffer.len() as u64) as usize;
        let read = with_total_deadline(total_deadline, async {
            tokio::time::timeout(
                response_body_timeout,
                cached.body.read(&mut buffer[..to_read]),
            )
            .await
            .map_err(|_| anyhow!("timed out reading cached HTTP/2 response body"))?
            .context("failed to read cached HTTP/2 response body")
        })
        .await?;
        if read == 0 {
            return Err(anyhow!("cached response body ended early"));
        }
        remaining -= read as u64;
        send_data_with_backpressure(
            &mut send,
            Bytes::copy_from_slice(&buffer[..read]),
            response_body_timeout,
            total_deadline,
            "sending cached HTTP/2 response body",
        )
        .await?;
        response_progress.add_bytes(read as u64);
    }
    send.send_data(Bytes::new(), true)
        .context("failed to finish cached HTTP/2 response body")?;
    response_progress.mark_complete();
    Ok((status, header_bytes + cached.content_length))
}

fn canonical_h2_headers(headers: &HeaderMap, max_bytes: usize) -> Result<HeaderMap> {
    let mut connection_tokens = std::collections::HashSet::new();
    for value in headers.get_all(http::header::CONNECTION) {
        if let Ok(value) = value.to_str() {
            connection_tokens.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|token| !token.is_empty())
                    .map(str::to_ascii_lowercase),
            );
        }
    }
    let mut result = HeaderMap::new();
    let mut budget =
        HeaderBudget::new(max_bytes, "cached response headers exceed configured limit")?;
    for (name, value) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        if response_header_should_skip(&lower, &connection_tokens) {
            continue;
        }
        budget.record(name.as_str().len() + value.as_bytes().len() + HEADER_PADDING)?;
        result.append(name.clone(), value.clone());
    }
    Ok(result)
}

fn header_bytes(headers: &HeaderMap, max_bytes: usize) -> Result<usize> {
    let mut budget =
        HeaderBudget::new(max_bytes, "cached response headers exceed configured limit")?;
    for (name, value) in headers {
        budget.record(name.as_str().len() + value.as_bytes().len() + HEADER_PADDING)?;
    }
    Ok(budget.used())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use anyhow::Result;
    use http::{HeaderMap, Method, StatusCode, Uri};
    use tempfile::TempDir;

    use crate::proxy::cache::{CacheRequestContext, CacheTiming};

    use super::*;

    async fn stalled_cache_write() -> Result<(TempDir, CacheWriteState)> {
        let dir = TempDir::new()?;
        let cache =
            HttpCache::new(1, dir.path().join("cache"), 1024, 1024, Duration::ZERO, 0).await?;
        let uri = Uri::from_static("http://example.com/cache-timeout");
        let request_headers = HeaderMap::new();
        let response_headers = HeaderMap::new();
        let mut writer = cache
            .open_stream(
                &Method::GET,
                &uri,
                &request_headers,
                &response_headers,
                cache.generation(),
            )
            .await?
            .expect("cache stream should be available");
        writer.stall_file_operations();
        let plan = CacheStorePlan {
            request: CacheRequestContext {
                uri,
                headers: request_headers,
                bypass: false,
            },
            response_headers,
            timing: CacheTiming {
                response_time: SystemTime::now(),
                corrected_initial_age: Duration::ZERO,
                freshness_lifetime: Duration::from_secs(60),
            },
        };
        let state = CacheWriteState {
            state: CacheWriteKind::Store(Box::new(CacheWriteContext {
                writer,
                plan,
                status: StatusCode::OK,
                failed: false,
            })),
        };
        Ok((dir, state))
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_cache_body_write_times_out_and_skips_storage() -> Result<()> {
        let (_dir, mut state) = stalled_cache_write().await?;
        let peer = "127.0.0.1:1234".parse()?;

        state.write(b"body", peer, Duration::from_secs(1)).await;

        assert_eq!(state.finish(peer, Duration::from_secs(1)).await, "skipped");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_cache_finalization_times_out_and_releases_stream() -> Result<()> {
        let (_dir, state) = stalled_cache_write().await?;
        let peer = "127.0.0.1:1234".parse()?;

        assert_eq!(state.finish(peer, Duration::from_secs(1)).await, "skipped");
        Ok(())
    }
}
