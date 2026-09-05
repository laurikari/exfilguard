use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result};
use http::{Method, StatusCode, Uri};
use tokio::fs as async_fs;

use super::{CacheKey, CacheState, HttpCache};

/// Cancellation or I/O failure must never leave stale entries available.
struct InvalidationGuard<'a> {
    state: &'a CacheState,
    completed: bool,
}

impl Drop for InvalidationGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.state.disabled.store(true, Ordering::Release);
            crate::metrics::record_cache_store_error();
            tracing::warn!(
                "cache invalidation interrupted; caching disabled until restart; clear cache storage before restarting"
            );
        }
    }
}

impl HttpCache {
    /// Mutations invalidate even when the matching rule does not enable caching.
    pub(crate) async fn invalidate_after_response(
        &self,
        request: &crate::proxy::request::ParsedRequest,
        status: StatusCode,
        io_timeout: Duration,
    ) {
        if self.state.disabled.load(Ordering::Acquire)
            || request.method.is_safe()
            || !(status.is_success() || status.is_redirection())
        {
            return;
        }
        let mut guard = InvalidationGuard {
            state: &self.state,
            completed: false,
        };
        let result = match request.cache_uri() {
            Ok(uri) => tokio::time::timeout(io_timeout, self.invalidate(&uri))
                .await
                .context("cache invalidation timed out")
                .and_then(|result| result),
            Err(err) => Err(err),
        };
        if let Err(err) = result {
            // Failure to invalidate must not leave stale cache hits usable.
            // Forward the successful mutation, but stop using this cache.
            tracing::warn!(error = %err, "cache invalidation failed");
        } else {
            guard.completed = true;
        }
    }

    async fn invalidate(&self, uri: &Uri) -> Result<()> {
        let _publish_guard = self.state.publish_lock.lock().await;
        self.state.generation.fetch_add(1, Ordering::AcqRel);
        for method in [Method::GET, Method::HEAD] {
            let key = CacheKey::new(&method, uri);
            let removed = {
                let mut index = self.state.index.lock();
                let removed = index.remove_by_key(key.key_base());
                CacheState::update_cache_metrics(&index);
                removed
            };
            // Remove metadata even when its entry has already left the index.
            match async_fs::remove_file(self.state.store.meta_path(key.entry_id())).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
            if let Some(entry) = removed {
                let _ = async_fs::remove_file(self.state.store.body_path(&entry.body_id)).await;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Scheme;
    use crate::proxy::cache::{CacheFinishOutcome, CacheTiming};
    use crate::proxy::request::parse_http1_request;
    use http::HeaderMap;
    use std::time::SystemTime;
    use tempfile::TempDir;
    use tokio::io::AsyncWriteExt;

    async fn cache(dir: &TempDir) -> HttpCache {
        HttpCache::new(
            16,
            dir.path().to_path_buf(),
            65536,
            1048576,
            Duration::from_secs(3600),
            16,
        )
        .await
        .unwrap()
    }

    async fn store(cache: &HttpCache, method: &Method, uri: &Uri) {
        cache
            .store(
                method,
                uri,
                &HeaderMap::new(),
                StatusCode::OK,
                &HeaderMap::new(),
                b"original",
                Duration::from_secs(300),
            )
            .await
            .unwrap();
    }

    fn mutation(method: Method) -> crate::proxy::request::ParsedRequest {
        parse_http1_request(method, "http://example.com:80/resource", None, Scheme::Http).unwrap()
    }

    #[tokio::test]
    async fn invalidation_only_follows_successful_unsafe_responses() {
        let dir = TempDir::new().unwrap();
        let cache = cache(&dir).await;
        let uri = mutation(Method::DELETE).cache_uri().unwrap();
        for method in [
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::TRACE,
            Method::DELETE,
            Method::PUT,
            Method::POST,
            Method::from_bytes(b"UPDATE").unwrap(),
        ] {
            for status in [
                StatusCode::OK,
                StatusCode::NO_CONTENT,
                StatusCode::SEE_OTHER,
                StatusCode::BAD_REQUEST,
                StatusCode::INTERNAL_SERVER_ERROR,
            ] {
                store(&cache, &Method::GET, &uri).await;
                store(&cache, &Method::HEAD, &uri).await;
                let generation = cache.generation();
                cache
                    .invalidate_after_response(
                        &mutation(method.clone()),
                        status,
                        Duration::from_secs(1),
                    )
                    .await;
                let invalidated =
                    !method.is_safe() && (status.is_success() || status.is_redirection());
                for cached_method in [Method::GET, Method::HEAD] {
                    assert_eq!(
                        cache
                            .lookup(&cached_method, &uri, &HeaderMap::new())
                            .await
                            .is_none(),
                        invalidated,
                        "{method} {status}"
                    );
                }
                assert_eq!(cache.generation() != generation, invalidated);
            }
        }
    }

    #[tokio::test]
    async fn invalidation_blocks_old_fills_and_survives_restart() {
        let dir = TempDir::new().unwrap();
        let cache = cache(&dir).await;
        let request = mutation(Method::DELETE);
        let uri = request.cache_uri().unwrap();
        let unrelated: Uri = "http://example.com:80/unrelated".parse().unwrap();
        let filling: Uri = "http://example.com:80/filling".parse().unwrap();
        store(&cache, &Method::GET, &uri).await;
        store(&cache, &Method::HEAD, &uri).await;
        store(&cache, &Method::GET, &unrelated).await;
        let generation = cache.generation();
        let headers = HeaderMap::new();
        let mut old = cache
            .open_stream(&Method::GET, &uri, &headers, &headers, generation)
            .await
            .unwrap()
            .unwrap();
        let mut other = cache
            .open_stream(&Method::GET, &filling, &headers, &headers, generation)
            .await
            .unwrap()
            .unwrap();
        old.write_all(b"stale").await.unwrap();
        other.write_all(b"unrelated fill").await.unwrap();
        cache
            .invalidate_after_response(&request, StatusCode::NO_CONTENT, Duration::from_secs(1))
            .await;
        for writer in [old, other] {
            let timing = CacheTiming {
                response_time: SystemTime::now(),
                corrected_initial_age: Duration::ZERO,
                freshness_lifetime: Duration::from_secs(300),
            };
            assert_eq!(
                writer
                    .finish(StatusCode::OK, headers.clone(), timing)
                    .await
                    .unwrap(),
                CacheFinishOutcome::Skipped
            );
        }
        assert!(
            cache
                .open_stream(&Method::GET, &uri, &headers, &headers, generation)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            cache
                .lookup(&Method::GET, &unrelated, &headers)
                .await
                .is_some()
        );
        drop(cache);
        let rebuilt = self::cache(&dir).await;
        for method in [Method::GET, Method::HEAD] {
            assert!(rebuilt.lookup(&method, &uri, &headers).await.is_none());
        }
        assert!(
            rebuilt
                .lookup(&Method::GET, &unrelated, &headers)
                .await
                .is_some()
        );
        store(&rebuilt, &Method::GET, &uri).await;
        assert!(rebuilt.lookup(&Method::GET, &uri, &headers).await.is_some());
    }

    #[tokio::test]
    async fn invalidation_ignores_vary_request_headers() {
        let dir = TempDir::new().unwrap();
        let cache = cache(&dir).await;
        let request = mutation(Method::PUT);
        let uri = request.cache_uri().unwrap();
        for language in ["en", "fi"] {
            let mut headers = HeaderMap::new();
            headers.insert("accept-language", language.parse().unwrap());
            let mut response = HeaderMap::new();
            response.insert("vary", "accept-language".parse().unwrap());
            cache
                .store(
                    &Method::GET,
                    &uri,
                    &headers,
                    StatusCode::OK,
                    &response,
                    b"variant",
                    Duration::from_secs(300),
                )
                .await
                .unwrap();
            assert!(cache.lookup(&Method::GET, &uri, &headers).await.is_some());
            cache
                .invalidate_after_response(&request, StatusCode::NO_CONTENT, Duration::from_secs(1))
                .await;
            assert!(cache.lookup(&Method::GET, &uri, &headers).await.is_none());
        }
    }

    #[tokio::test]
    async fn failed_metadata_removal_disables_cache() {
        let dir = TempDir::new().unwrap();
        let cache = cache(&dir).await;
        let request = mutation(Method::DELETE);
        let uri = request.cache_uri().unwrap();
        store(&cache, &Method::GET, &uri).await;
        let key = CacheKey::new(&Method::GET, &uri);
        let metadata = cache.state.store.meta_path(key.entry_id());
        async_fs::remove_file(&metadata).await.unwrap();
        async_fs::create_dir(&metadata).await.unwrap();
        cache
            .invalidate_after_response(&request, StatusCode::NO_CONTENT, Duration::from_secs(1))
            .await;
        assert!(cache.state.disabled.load(Ordering::Acquire));
        assert!(
            cache
                .lookup(&Method::GET, &uri, &HeaderMap::new())
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn interrupted_invalidation_disables_cache_hits_and_fills() {
        for cancel in [false, true] {
            let dir = TempDir::new().unwrap();
            let cache = cache(&dir).await;
            let request = mutation(Method::DELETE);
            let uri = request.cache_uri().unwrap();
            store(&cache, &Method::GET, &uri).await;
            let lock = cache.state.publish_lock.lock().await;
            if cancel {
                let mut invalidation = Box::pin(cache.invalidate_after_response(
                    &request,
                    StatusCode::NO_CONTENT,
                    Duration::from_secs(1),
                ));
                assert!(futures::poll!(invalidation.as_mut()).is_pending());
                drop(invalidation);
            } else {
                cache
                    .invalidate_after_response(
                        &request,
                        StatusCode::NO_CONTENT,
                        Duration::from_millis(10),
                    )
                    .await;
            }
            drop(lock);
            assert!(
                cache
                    .lookup(&Method::GET, &uri, &HeaderMap::new())
                    .await
                    .is_none()
            );
            assert!(
                cache
                    .open_stream(
                        &Method::GET,
                        &uri,
                        &HeaderMap::new(),
                        &HeaderMap::new(),
                        cache.generation()
                    )
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}
