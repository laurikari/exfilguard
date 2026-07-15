#[cfg(test)]
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::{Result, anyhow, ensure};
use http::{HeaderMap, Method, StatusCode, Uri};
use parking_lot::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::{fs as async_fs, task};
use tracing::trace;

#[cfg(test)]
use crate::config::MAX_CACHE_TTL_SECONDS;

mod admission;
mod entry;
mod index;
mod key;
mod lookup;
mod maintenance;
mod reader;
mod request;
mod store;
mod writer;

pub(crate) use admission::{
    CacheResponseTiming, CacheSkipReason, CacheStorePlan, CacheTiming, CacheWritePlan,
    plan_cache_write,
};
use entry::{CacheEntry, PersistedEntry};
use index::CacheIndex;
use key::{CacheKey, VaryKey};
pub(crate) use lookup::{CacheLookupOutcome, Http1CacheLookupOutcome};
#[cfg(test)]
use maintenance::cache_version_dir;
use maintenance::{prepare_versioned_cache_dir, spawn_cache_dir_cleanup, spawn_cache_sweeper};
use reader::CacheReader;
pub(crate) use request::{
    CacheRequestContext, build_cache_request_context, build_http1_cache_request_context,
};
use store::CacheStore;
pub(crate) use writer::{CacheFinishOutcome, CacheWriter};

#[derive(Debug)]
pub struct CachedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body_path: PathBuf,
    pub(crate) body: async_fs::File,
    pub content_length: u64,
}

#[derive(Clone)]
pub struct HttpCache {
    state: Arc<CacheState>,
}

#[derive(Debug)]
struct CacheState {
    index: Mutex<CacheIndex>,
    publish_lock: tokio::sync::Mutex<()>,
    store: CacheStore,
    max_entry_size: u64,
    max_bytes: u64,
    in_flight_bytes: AtomicU64,
    next_id: AtomicU64,
}

#[derive(Debug, Default)]
struct SweepStats {
    inspected: usize,
    removed: u64,
    bytes_reclaimed: u64,
}

impl HttpCache {
    pub async fn new(
        capacity: usize,
        disk_dir: PathBuf,
        max_entry_size: u64,
        max_bytes: u64,
        sweeper_interval: Duration,
        sweeper_batch_size: usize,
    ) -> Result<Self> {
        ensure!(
            max_entry_size <= max_bytes,
            "cache max entry size ({max_entry_size}) must not exceed total capacity ({max_bytes})"
        );
        let cache_root = disk_dir;
        let (disk_dir, cleanup_dirs) = prepare_versioned_cache_dir(&cache_root).await?;

        let capacity = std::num::NonZeroUsize::new(capacity)
            .ok_or_else(|| anyhow!("cache capacity must be greater than zero"))?;
        let index = CacheIndex::new(capacity, max_bytes);
        let store = CacheStore::new(disk_dir.clone());
        let state = Arc::new(CacheState {
            index: Mutex::new(index),
            publish_lock: tokio::sync::Mutex::new(()),
            store,
            max_entry_size,
            max_bytes,
            in_flight_bytes: AtomicU64::new(0),
            next_id: AtomicU64::new(1),
        });
        spawn_cache_dir_cleanup(cleanup_dirs);
        let rebuild = {
            let state = state.clone();
            task::spawn_blocking(move || state.rebuild_from_disk())
        };
        rebuild
            .await
            .map_err(|err| anyhow!("cache rebuild task failed: {err}"))??;

        spawn_cache_sweeper(state.clone(), sweeper_interval, sweeper_batch_size);
        Ok(Self { state })
    }

    pub async fn lookup(
        &self,
        method: &Method,
        uri: &Uri,
        req_headers: &HeaderMap,
    ) -> Option<CachedResponse> {
        CacheReader::new(self.state.clone())
            .lookup(method, uri, req_headers)
            .await
    }

    pub(crate) async fn open_stream(
        &self,
        method: &Method,
        uri: &Uri,
        req_headers: &HeaderMap,
        resp_headers: &HeaderMap,
    ) -> Result<Option<CacheWriter>> {
        let cache_key = CacheKey::new(method, uri);
        let vary = match VaryKey::from_response(resp_headers, req_headers) {
            Some(map) => map,
            None => {
                trace!("skipping cache due to Vary header limits");
                return Ok(None);
            }
        };

        // Use a random temp file name
        let temp_name = format!("tmp_{}", uuid::Uuid::new_v4());
        let temp_path = self.state.store.temp_path(&temp_name);

        let mut options = async_fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let file = options.open(&temp_path).await?;

        Ok(Some(CacheWriter::new(
            file,
            temp_path,
            self.state.clone(),
            cache_key,
            vary,
        )))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn store(
        &self,
        method: &Method,
        uri: &Uri,
        req_headers: &HeaderMap,
        status: StatusCode,
        headers: &HeaderMap,
        body: &[u8],
        ttl: Duration,
    ) -> Result<()> {
        let response_time = SystemTime::now();
        if let Some(mut stream) = self.open_stream(method, uri, req_headers, headers).await? {
            stream.write_all(body).await?;
            let timing = CacheTiming {
                response_time,
                corrected_initial_age: Duration::ZERO,
                freshness_lifetime: ttl,
            };
            if stream.finish(status, headers.clone(), timing).await? == CacheFinishOutcome::Stored {
                crate::metrics::record_cache_store();
            }
        }
        Ok(())
    }
}

impl CacheState {
    fn update_cache_metrics(index: &CacheIndex) {
        crate::metrics::set_cache_usage(index.len(), index.bytes_in_use());
    }

    fn body_path(&self, body_id: &str) -> PathBuf {
        self.store.body_path(body_id)
    }

    fn meta_path(&self, entry_id: &str) -> PathBuf {
        self.store.meta_path(entry_id)
    }

    fn next_entry_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn try_reserve_in_flight(&self, bytes: u64) -> bool {
        if bytes == 0 {
            return true;
        }
        self.in_flight_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|total| *total <= self.max_entry_size)
            })
            .is_ok()
    }

    fn release_in_flight(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let released =
            self.in_flight_bytes
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_sub(bytes)
                });
        debug_assert!(released.is_ok(), "cache in-flight accounting underflow");
    }

    #[cfg(test)]
    fn in_flight_bytes(&self) -> u64 {
        self.in_flight_bytes.load(Ordering::Acquire)
    }

    fn remove_entry_if_id_matches(&self, key_base: &str, entry_id: u64) -> Option<CacheEntry> {
        let mut guard = self.index.lock();
        let removed = guard.remove_if_id_matches(key_base, entry_id);
        Self::update_cache_metrics(&guard);
        removed
    }

    fn remove_entry_by_key_base(&self, key_base: &str) {
        let mut guard = self.index.lock();
        guard.remove_by_key(key_base);
        Self::update_cache_metrics(&guard);
    }

    async fn write_metadata_async(&self, entry_id: &str, entry: &PersistedEntry) -> Result<()> {
        self.store.write_metadata_async(entry_id, entry).await
    }

    fn publish_lock(&self) -> &tokio::sync::Mutex<()> {
        &self.publish_lock
    }

    fn insert_entry(&self, key_base: String, entry: CacheEntry) -> Vec<CacheEntry> {
        let mut guard = self.index.lock();
        let evicted = guard.insert(key_base, entry);
        Self::update_cache_metrics(&guard);
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::TempDir;

    fn build_uri(host: &str, port: u16, path: &str) -> Uri {
        http::Uri::builder()
            .scheme("http")
            .authority(format!("{host}:{port}").as_str())
            .path_and_query(path)
            .build()
            .expect("build test uri")
    }

    const TEST_SWEEPER_INTERVAL: Duration = Duration::from_secs(3600);
    const TEST_SWEEPER_BATCH_SIZE: usize = 128;

    fn now_unix_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time is after the Unix epoch")
            .as_millis() as u64
    }

    async fn build_cache(
        capacity: usize,
        dir: PathBuf,
        max_entry_size: u64,
        max_bytes: u64,
    ) -> Result<HttpCache> {
        HttpCache::new(
            capacity,
            dir,
            max_entry_size,
            max_bytes,
            TEST_SWEEPER_INTERVAL,
            TEST_SWEEPER_BATCH_SIZE,
        )
        .await
    }

    fn cache_entry_paths(
        cache: &HttpCache,
        method: &Method,
        uri: &Uri,
    ) -> Result<(PathBuf, PathBuf)> {
        let key_id = CacheKey::new(method, uri).entry_id().to_string();
        let meta_path = cache.state.meta_path(&key_id);
        let persisted: PersistedEntry = serde_json::from_slice(&fs::read(&meta_path)?)?;
        let body_path = cache.state.body_path(&persisted.body_id);
        Ok((body_path, meta_path))
    }

    #[tokio::test]
    async fn test_cache_lifecycle() -> Result<()> {
        let dir = TempDir::new()?;
        let cache =
            build_cache(10, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/test");
        let req_headers = HeaderMap::new();
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("content-type", "text/plain".parse()?);

        let body = b"hello world";

        // Store
        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                body,
                Duration::from_secs(60),
            )
            .await?;

        // Lookup Hit
        let hit = cache.lookup(&method, &uri, &req_headers).await;
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.content_length, body.len() as u64);
        assert_eq!(hit.headers.get(http::header::AGE).unwrap(), "0");

        // Verify body on disk
        let disk_body = fs::read(hit.body_path)?;
        assert_eq!(disk_body, body);

        Ok(())
    }

    #[tokio::test]
    async fn rejects_entry_limit_above_total_capacity() -> Result<()> {
        let dir = TempDir::new()?;
        let result = build_cache(10, dir.path().to_path_buf(), 1025, 1024).await;
        assert!(result.is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cache_files_use_restrictive_permissions() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new()?;
        let cache =
            build_cache(10, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/perm");
        let req_headers = HeaderMap::new();
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("content-type", "text/plain".parse()?);

        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"payload",
                Duration::from_secs(60),
            )
            .await?;

        let hit = cache.lookup(&method, &uri, &req_headers).await.unwrap();
        let body_mode = fs::metadata(&hit.body_path)?.permissions().mode() & 0o777;
        assert_eq!(body_mode, 0o600);

        let entry_id = CacheKey::new(&method, &uri).entry_id().to_string();
        let meta_path = cache.state.meta_path(&entry_id);
        let meta_mode = fs::metadata(&meta_path)?.permissions().mode() & 0o777;
        assert_eq!(meta_mode, 0o600);
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_expiration() -> Result<()> {
        let dir = TempDir::new()?;
        let cache =
            build_cache(10, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/expired");
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();

        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"data",
                Duration::from_secs(0),
            )
            .await?;

        std::thread::sleep(Duration::from_millis(10));

        // Lookup Miss
        let miss = cache.lookup(&method, &uri, &req_headers).await;
        assert!(miss.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_expired_entries_cleanup_disk() -> Result<()> {
        let dir = TempDir::new()?;
        let cache =
            build_cache(10, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/expired-cleanup");
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();
        let body = b"expired-data";

        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                body,
                Duration::from_secs(1),
            )
            .await?;

        let (body_path, meta_path) = cache_entry_paths(&cache, &method, &uri)?;

        assert!(body_path.exists(), "expected cached body to exist");
        assert!(meta_path.exists(), "expected cached metadata to exist");

        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let miss = cache.lookup(&method, &uri, &req_headers).await;
        assert!(miss.is_none());

        assert!(!body_path.exists(), "expired body should be removed");
        assert!(!meta_path.exists(), "expired metadata should be removed");

        Ok(())
    }

    #[tokio::test]
    async fn test_cache_eviction_deletes_file() -> Result<()> {
        let dir = TempDir::new()?;
        // Capacity 2
        let cache = build_cache(2, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();
        let method = Method::GET;

        // 1. Store Item A
        let uri_a = build_uri("example.com", 80, "/item-a");
        cache
            .store(
                &method,
                &uri_a,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"A",
                Duration::from_secs(60),
            )
            .await?;
        let hit_a = cache.lookup(&method, &uri_a, &req_headers).await.unwrap();
        assert!(hit_a.body_path.exists());

        // 2. Store Item B
        let uri_b = build_uri("example.com", 80, "/item-b");
        cache
            .store(
                &method,
                &uri_b,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"B",
                Duration::from_secs(60),
            )
            .await?;
        let hit_b = cache.lookup(&method, &uri_b, &req_headers).await.unwrap();
        assert!(hit_b.body_path.exists());

        // 3. Store Item C -> Should evict A (LRU)
        let uri_c = build_uri("example.com", 80, "/item-c");
        cache
            .store(
                &method,
                &uri_c,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"C",
                Duration::from_secs(60),
            )
            .await?;

        // Assertions
        // A should be gone from index
        assert!(cache.lookup(&method, &uri_a, &req_headers).await.is_none());
        // A's file should be deleted
        assert!(!hit_a.body_path.exists(), "Evicted file should be deleted");

        // B and C should exist
        assert!(cache.lookup(&method, &uri_b, &req_headers).await.is_some());
        assert!(hit_b.body_path.exists());

        let hit_c = cache.lookup(&method, &uri_c, &req_headers).await.unwrap();

        assert!(hit_c.body_path.exists());

        Ok(())
    }

    #[tokio::test]
    async fn rebuild_restores_persisted_entries() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let cache = build_cache(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/persist");
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();

        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"persisted",
                Duration::from_secs(60),
            )
            .await?;

        drop(cache);

        let rebuilt = build_cache(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;
        let hit = rebuilt
            .lookup(&method, &uri, &req_headers)
            .await
            .expect("entry should be restored from disk");
        let body = fs::read(hit.body_path)?;
        assert_eq!(body, b"persisted");
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_preserves_non_utf8_response_header_values() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/opaque-header");
        let req_headers = HeaderMap::new();
        let header_name = http::header::HeaderName::from_static("x-opaque");
        let opaque_value = http::HeaderValue::from_bytes(b"\x80opaque")?;
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(header_name.clone(), opaque_value.clone());

        let cache = build_cache(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;
        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"persisted",
                Duration::from_secs(60),
            )
            .await?;
        drop(cache);

        let rebuilt = build_cache(4, disk_dir, 1024 * 1024, 1024 * 1024 * 10).await?;
        let hit = rebuilt
            .lookup(&method, &uri, &req_headers)
            .await
            .expect("entry with an opaque HTTP/2 header should survive rebuild");
        assert_eq!(hit.headers.get(header_name), Some(&opaque_value));
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_drops_entry_with_invalid_persisted_header() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/invalid-persisted-header");
        let req_headers = HeaderMap::new();

        let cache = build_cache(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;
        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &HeaderMap::new(),
                b"persisted",
                Duration::from_secs(60),
            )
            .await?;
        let (body_path, meta_path) = cache_entry_paths(&cache, &method, &uri)?;
        let mut persisted: PersistedEntry = serde_json::from_slice(&fs::read(&meta_path)?)?;
        persisted
            .headers
            .push(("x-corrupt".to_string(), b"embedded\rreturn".to_vec()));
        fs::write(&meta_path, serde_json::to_vec(&persisted)?)?;
        drop(cache);

        let rebuilt = build_cache(4, disk_dir, 1024 * 1024, 1024 * 1024 * 10).await?;
        assert!(rebuilt.lookup(&method, &uri, &req_headers).await.is_none());
        assert!(!meta_path.exists(), "invalid metadata should be removed");
        assert!(!body_path.exists(), "invalid entry body should be removed");
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_restores_age_timeline_and_hits_replace_origin_age() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let cache = build_cache(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;
        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/persisted-age");
        let req_headers = HeaderMap::new();
        let mut resp_headers = HeaderMap::new();
        resp_headers.append(http::header::AGE, "2".parse()?);
        resp_headers.append(http::header::AGE, "3".parse()?);

        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"persisted",
                Duration::from_secs(60),
            )
            .await?;
        let (_, meta_path) = cache_entry_paths(&cache, &method, &uri)?;
        drop(cache);

        let mut persisted: PersistedEntry = serde_json::from_slice(&fs::read(&meta_path)?)?;
        persisted.corrected_initial_age_millis = 7_000;
        persisted.expires_at_unix_millis = persisted.response_time_unix_millis + 53_000;
        fs::write(&meta_path, serde_json::to_vec(&persisted)?)?;

        let rebuilt = build_cache(4, disk_dir, 1024 * 1024, 1024 * 1024 * 10).await?;
        let hit = rebuilt
            .lookup(&method, &uri, &req_headers)
            .await
            .expect("entry should be restored from disk");
        let ages = hit.headers.get_all(http::header::AGE);
        assert_eq!(ages.iter().count(), 1);
        let age: u64 = ages.iter().next().unwrap().to_str()?.parse()?;
        assert!((7..10).contains(&age), "unexpected restored age {age}");
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_replacements_keep_headers_and_body_together() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let cache = build_cache(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;
        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/replace");
        let req_headers = HeaderMap::new();
        let mut headers_a = HeaderMap::new();
        headers_a.insert("x-variant", "a".parse()?);
        let mut headers_b = HeaderMap::new();
        headers_b.insert("x-variant", "b".parse()?);

        let store_a = cache.store(
            &method,
            &uri,
            &req_headers,
            StatusCode::OK,
            &headers_a,
            b"body-a",
            Duration::from_secs(60),
        );
        let store_b = cache.store(
            &method,
            &uri,
            &req_headers,
            StatusCode::OK,
            &headers_b,
            b"body-b",
            Duration::from_secs(60),
        );
        let (result_a, result_b) = tokio::join!(store_a, store_b);
        result_a?;
        result_b?;

        let assert_consistent = |hit: CachedResponse| -> Result<()> {
            let variant = hit
                .headers
                .get("x-variant")
                .and_then(|value| value.to_str().ok());
            let body = fs::read(hit.body_path)?;
            assert!(
                matches!(
                    (variant, body.as_slice()),
                    (Some("a"), b"body-a") | (Some("b"), b"body-b")
                ),
                "cache metadata and body must come from the same writer"
            );
            Ok(())
        };

        assert_consistent(
            cache
                .lookup(&method, &uri, &req_headers)
                .await
                .expect("replacement should remain live"),
        )?;
        drop(cache);

        let rebuilt = build_cache(4, disk_dir, 1024 * 1024, 1024 * 1024 * 10).await?;
        assert_consistent(
            rebuilt
                .lookup(&method, &uri, &req_headers)
                .await
                .expect("replacement should survive rebuild"),
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_keeps_distinct_entries_with_same_body() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let cache = build_cache(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri_a = build_uri("example.com", 80, "/same-body-a");
        let uri_b = build_uri("example.com", 80, "/same-body-b");
        let req_headers = HeaderMap::new();
        let body = b"identical";

        let mut resp_headers_a = HeaderMap::new();
        resp_headers_a.insert("x-variant", "a".parse()?);
        let mut resp_headers_b = HeaderMap::new();
        resp_headers_b.insert("x-variant", "b".parse()?);

        cache
            .store(
                &method,
                &uri_a,
                &req_headers,
                StatusCode::OK,
                &resp_headers_a,
                body,
                Duration::from_secs(60),
            )
            .await?;
        cache
            .store(
                &method,
                &uri_b,
                &req_headers,
                StatusCode::OK,
                &resp_headers_b,
                body,
                Duration::from_secs(60),
            )
            .await?;

        drop(cache);

        let rebuilt = build_cache(4, disk_dir, 1024 * 1024, 1024 * 1024 * 10).await?;
        let hit_a = rebuilt
            .lookup(&method, &uri_a, &req_headers)
            .await
            .expect("entry A should be restored from disk");
        let hit_b = rebuilt
            .lookup(&method, &uri_b, &req_headers)
            .await
            .expect("entry B should be restored from disk");

        let header_a = hit_a
            .headers
            .get("x-variant")
            .and_then(|value| value.to_str().ok());
        let header_b = hit_b
            .headers
            .get("x-variant")
            .and_then(|value| value.to_str().ok());
        assert_eq!(header_a, Some("a"));
        assert_eq!(header_b, Some("b"));
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_drops_entries_with_corrupted_body() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let cache = build_cache(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/corrupt");
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();

        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"body",
                Duration::from_secs(60),
            )
            .await?;

        // Corrupt the body on disk
        if let Some(hit) = cache.lookup(&method, &uri, &req_headers).await {
            fs::write(hit.body_path, b"tampered")?;
        }

        drop(cache);

        let rebuilt = build_cache(4, disk_dir, 1024 * 1024, 1024 * 1024 * 10).await?;
        assert!(
            rebuilt.lookup(&method, &uri, &req_headers).await.is_none(),
            "corrupted body should cause entry to be dropped"
        );
        Ok(())
    }

    #[tokio::test]
    async fn live_lookup_rejects_body_size_mismatch() -> Result<()> {
        let dir = TempDir::new()?;
        let cache = build_cache(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/tampered-size");
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();

        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"body",
                Duration::from_secs(60),
            )
            .await?;

        let hit = cache.lookup(&method, &uri, &req_headers).await.unwrap();
        fs::write(&hit.body_path, b"tampered-body")?;

        assert!(
            cache.lookup(&method, &uri, &req_headers).await.is_none(),
            "tampered body size should invalidate live cache entry"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_lookup_rejects_symlinked_body() -> Result<()> {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new()?;
        let cache = build_cache(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/tampered-link");
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();

        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"body",
                Duration::from_secs(60),
            )
            .await?;

        let hit = cache.lookup(&method, &uri, &req_headers).await.unwrap();
        let replacement = dir.path().join("replacement-body");
        fs::write(&replacement, b"replacement")?;
        fs::remove_file(&hit.body_path)?;
        symlink(&replacement, &hit.body_path)?;

        assert!(
            cache.lookup(&method, &uri, &req_headers).await.is_none(),
            "symlinked body should invalidate live cache entry"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_drops_invalid_content_hash_metadata() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let key_base = "GET::http://example.com:80/".to_string();
        let entry_id = CacheKey::entry_id_for_key(&key_base);
        let versioned_dir = cache_version_dir(&disk_dir);
        let shard_dir = versioned_dir.join(&entry_id[0..2]).join(&entry_id[2..4]);
        fs::create_dir_all(&shard_dir)?;
        let meta_path = shard_dir.join(format!("{entry_id}.meta"));
        let persisted = PersistedEntry {
            key_base,
            body_id: format!("{}{}", &entry_id[..4], "0".repeat(60)),
            status: 200,
            headers: Vec::new(),
            vary_headers: Vec::new(),
            response_time_unix_millis: now_unix_millis(),
            corrected_initial_age_millis: 0,
            expires_at_unix_millis: now_unix_millis() + 60_000,
            content_hash: "abc".to_string(),
            content_length: 0,
        };
        let data = serde_json::to_vec(&persisted)?;
        fs::write(&meta_path, data)?;

        let _rebuilt = build_cache(4, disk_dir, 1024 * 1024, 1024 * 1024 * 10).await?;
        assert!(
            !meta_path.exists(),
            "invalid cache metadata should be removed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_drops_invalid_timing_metadata() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let key_base = "GET::http://example.com:80/unrepresentable".to_string();
        let entry_id = CacheKey::entry_id_for_key(&key_base);
        let versioned_dir = cache_version_dir(&disk_dir);
        let shard_dir = versioned_dir.join(&entry_id[0..2]).join(&entry_id[2..4]);
        fs::create_dir_all(&shard_dir)?;
        let meta_path = shard_dir.join(format!("{entry_id}.meta"));
        let persisted = PersistedEntry {
            key_base,
            body_id: format!("{}{}", &entry_id[..4], "0".repeat(60)),
            status: 200,
            headers: Vec::new(),
            vary_headers: Vec::new(),
            response_time_unix_millis: now_unix_millis(),
            corrected_initial_age_millis: 0,
            expires_at_unix_millis: u64::MAX,
            content_hash: "0".repeat(64),
            content_length: 0,
        };
        fs::write(&meta_path, serde_json::to_vec(&persisted)?)?;

        let _rebuilt = build_cache(4, disk_dir, 1024 * 1024, 1024 * 1024 * 10).await?;
        assert!(!meta_path.exists());
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_prunes_expired_entries() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let versioned_dir = cache_version_dir(&disk_dir);
        let cache = build_cache(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/expired-persisted");
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();

        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"expired",
                Duration::from_secs(1),
            )
            .await?;

        tokio::time::sleep(Duration::from_millis(1_100)).await;
        drop(cache);

        let rebuilt = build_cache(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;
        assert!(
            rebuilt.lookup(&method, &uri, &req_headers).await.is_none(),
            "expired entry should be pruned during rebuild"
        );
        let file_count = fs::read_dir(&versioned_dir)?
            .filter_map(|entry| entry.ok())
            .flat_map(|entry| {
                if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                    fs::read_dir(entry.path())
                        .map(|iter| iter.filter_map(|e| e.ok()).collect::<Vec<_>>())
                        .unwrap_or_default()
                } else {
                    vec![entry]
                }
            })
            .filter(|entry| entry.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .count();
        assert_eq!(file_count, 0, "disk cache should be empty of files");
        Ok(())
    }

    #[tokio::test]
    async fn uses_versioned_cache_dir_and_cleans_old_versions() -> Result<()> {
        let dir = TempDir::new()?;
        let old_dir = dir.path().join("v4");
        fs::create_dir_all(&old_dir)?;
        fs::write(old_dir.join("old"), b"data")?;

        let cache = build_cache(4, dir.path().to_path_buf(), 1024, 1024 * 10).await?;
        let active_dir = cache_version_dir(dir.path());
        assert_eq!(cache.state.store.disk_dir(), active_dir);
        assert!(!old_dir.exists(), "old cache version should be tombstoned");

        let active_name = active_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        assert_eq!(active_name, "v6");
        let mut cleaned = false;
        for _ in 0..10 {
            let dirs = fs::read_dir(dir.path())?
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
                .filter_map(|entry| entry.file_name().to_str().map(|name| name.to_string()))
                .collect::<Vec<_>>();
            if dirs.len() == 1 && dirs[0] == active_name {
                cleaned = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(cleaned, "old cache dir should be cleaned asynchronously");
        Ok(())
    }

    #[tokio::test]
    async fn sweeper_removes_expired_entries() -> Result<()> {
        let dir = TempDir::new()?;
        let cache =
            build_cache(10, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/sweep-expired");
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();

        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"sweep",
                Duration::from_secs(1),
            )
            .await?;

        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let (body_path, _) = cache_entry_paths(&cache, &method, &uri)?;
        assert!(body_path.exists(), "expected cached body to exist");

        let stats = cache.state.sweep_expired_entries(10).await?;
        assert_eq!(stats.removed, 1);
        assert!(!body_path.exists(), "expired body should be removed");
        if let Some(shard_dir) = body_path.parent()
            && shard_dir.exists()
        {
            assert_eq!(
                fs::read_dir(shard_dir)?.count(),
                0,
                "empty shard dir should be pruned"
            );
        }
        assert!(cache.lookup(&method, &uri, &req_headers).await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn sweeper_removes_invalid_timing_metadata() -> Result<()> {
        let dir = TempDir::new()?;
        let cache =
            build_cache(10, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;
        let key_base = "GET::http://example.com:80/sweep-invalid-expiry".to_string();
        let entry_id = CacheKey::entry_id_for_key(&key_base);
        let body_id = format!("{}{}", &entry_id[..4], "0".repeat(60));
        let body_path = cache.state.body_path(&body_id);
        fs::create_dir_all(body_path.parent().expect("body shard"))?;
        fs::write(&body_path, b"body")?;
        let meta_path = cache.state.meta_path(&entry_id);
        let persisted = PersistedEntry {
            key_base,
            body_id,
            status: 200,
            headers: Vec::new(),
            vary_headers: Vec::new(),
            response_time_unix_millis: now_unix_millis(),
            corrected_initial_age_millis: 0,
            expires_at_unix_millis: u64::MAX,
            content_hash: blake3::hash(b"body").to_hex().to_string(),
            content_length: 4,
        };
        fs::write(&meta_path, serde_json::to_vec(&persisted)?)?;

        let stats = cache.state.sweep_expired_entries(10).await?;
        assert_eq!(stats.removed, 1);
        assert!(!meta_path.exists());
        assert!(!body_path.exists());
        Ok(())
    }

    #[tokio::test]
    async fn test_vary_mismatch() -> Result<()> {
        let dir = TempDir::new()?;

        let cache =
            build_cache(10, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;

        let uri = build_uri("example.com", 80, "/vary");

        let mut req_headers_1 = HeaderMap::new();

        req_headers_1.insert("user-agent", "mobile".parse()?);

        let mut resp_headers = HeaderMap::new();

        resp_headers.insert("vary", "User-Agent".parse()?);

        // Store for Mobile

        cache
            .store(
                &method,
                &uri,
                &req_headers_1,
                StatusCode::OK,
                &resp_headers,
                b"mobile content",
                Duration::from_secs(60),
            )
            .await?;

        // Hit for Mobile

        assert!(cache.lookup(&method, &uri, &req_headers_1).await.is_some());

        // Miss for Desktop

        let mut req_headers_2 = HeaderMap::new();

        req_headers_2.insert("user-agent", "desktop".parse()?);

        assert!(cache.lookup(&method, &uri, &req_headers_2).await.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn persisted_vary_preserves_complete_ordered_values() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/vary-persisted");
        let name = http::header::HeaderName::from_static("x-variant");
        let secret = http::HeaderValue::from_bytes(b"\x80secret")?;

        let mut stored_headers = HeaderMap::new();
        stored_headers.append(name.clone(), "common".parse()?);
        stored_headers.append(name.clone(), secret.clone());
        let mut response_headers = HeaderMap::new();
        response_headers.insert(http::header::VARY, "X-Variant".parse()?);

        let cache = build_cache(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;
        cache
            .store(
                &method,
                &uri,
                &stored_headers,
                StatusCode::OK,
                &response_headers,
                b"secret representation",
                Duration::from_secs(MAX_CACHE_TTL_SECONDS),
            )
            .await?;
        drop(cache);

        let rebuilt = build_cache(4, disk_dir, 1024 * 1024, 1024 * 1024 * 10).await?;
        assert!(
            rebuilt
                .lookup(&method, &uri, &stored_headers)
                .await
                .is_some(),
            "exact repeated values should survive cache rebuild"
        );

        let mut first_only = HeaderMap::new();
        first_only.append(name.clone(), "common".parse()?);
        assert!(
            rebuilt.lookup(&method, &uri, &first_only).await.is_none(),
            "persisted key must not match only its first value"
        );

        let mut reversed = HeaderMap::new();
        reversed.append(name.clone(), secret);
        reversed.append(name, "common".parse()?);
        assert!(
            rebuilt.lookup(&method, &uri, &reversed).await.is_none(),
            "persisted key must preserve value order"
        );
        Ok(())
    }

    #[tokio::test]
    async fn skips_cache_when_vary_header_missing_from_request() -> Result<()> {
        let dir = TempDir::new()?;
        let cache = build_cache(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/vary-missing");

        // Request does NOT include Accept-Language
        let req_headers = HeaderMap::new();

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(http::header::VARY, "Accept-Language".parse()?);

        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"body",
                Duration::from_secs(60),
            )
            .await?;

        assert!(
            cache.lookup(&method, &uri, &req_headers).await.is_none(),
            "cache should be skipped when request lacks header named in Vary"
        );
        let versioned_dir = cache_version_dir(dir.path());
        assert_eq!(
            fs::read_dir(&versioned_dir)?.count(),
            0,
            "cache directory should remain empty when entry is skipped"
        );
        Ok(())
    }

    #[tokio::test]
    async fn skips_cache_when_vary_star_present() -> Result<()> {
        let dir = TempDir::new()?;
        let cache = build_cache(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/vary-star");

        let req_headers = HeaderMap::new();
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(http::header::VARY, "*".parse()?);

        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"body",
                Duration::from_secs(60),
            )
            .await?;

        assert!(
            cache.lookup(&method, &uri, &req_headers).await.is_none(),
            "Vary:* responses must not be cached"
        );
        let versioned_dir = cache_version_dir(dir.path());
        assert_eq!(
            fs::read_dir(&versioned_dir)?.count(),
            0,
            "cache directory should remain empty when Vary:* skips caching"
        );
        Ok(())
    }

    #[tokio::test]
    async fn cache_keys_include_scheme_and_authority() -> Result<()> {
        let dir = TempDir::new()?;
        let cache = build_cache(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();
        let method = Method::GET;

        let uri_a = build_uri("alpha.example.com", 80, "/shared");
        cache
            .store(
                &method,
                &uri_a,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"alpha",
                Duration::from_secs(30),
            )
            .await?;

        // Different host with same path must not hit cache
        let uri_b = build_uri("beta.example.com", 80, "/shared");
        assert!(
            cache.lookup(&method, &uri_b, &req_headers).await.is_none(),
            "cache should not mix hosts for identical paths"
        );

        // Original host still hits
        assert!(cache.lookup(&method, &uri_a, &req_headers).await.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn enforces_total_capacity_and_evicts_lru() -> Result<()> {
        let dir = TempDir::new()?;
        // Total and per-entry caps are 6 bytes; each individual entry fits.
        let cache = build_cache(4, dir.path().to_path_buf(), 6, 6).await?;
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();
        let method = Method::GET;

        // Store first entry of 4 bytes
        let uri_a = build_uri("example.com", 80, "/a");
        cache
            .store(
                &method,
                &uri_a,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"aaaa",
                Duration::from_secs(60),
            )
            .await?;
        let hit_a = cache.lookup(&method, &uri_a, &req_headers).await.unwrap();
        assert!(hit_a.body_path.exists());

        // Store second entry of 4 bytes -> should evict first to stay under 6 bytes
        let uri_b = build_uri("example.com", 80, "/b");
        cache
            .store(
                &method,
                &uri_b,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"bbbb",
                Duration::from_secs(60),
            )
            .await?;

        assert!(cache.lookup(&method, &uri_a, &req_headers).await.is_none());
        assert!(!hit_a.body_path.exists());
        assert!(cache.lookup(&method, &uri_b, &req_headers).await.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn skips_entry_bigger_than_total_capacity() -> Result<()> {
        let dir = TempDir::new()?;
        let cache = build_cache(2, dir.path().to_path_buf(), 2, 2).await?;
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();
        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/too-big");

        cache
            .store(
                &method,
                &uri,
                &req_headers,
                StatusCode::OK,
                &resp_headers,
                b"data",
                Duration::from_secs(60),
            )
            .await?;

        assert!(cache.lookup(&method, &uri, &req_headers).await.is_none());
        // temp should have been cleaned; cache dir should remain empty
        let versioned_dir = cache_version_dir(dir.path());
        assert_eq!(fs::read_dir(&versioned_dir)?.count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn clears_stale_disk_on_startup() -> Result<()> {
        let dir = TempDir::new()?;
        let versioned_dir = cache_version_dir(dir.path());

        // Write stray temp file and a hashed body shard
        fs::create_dir_all(&versioned_dir)?;
        let tmp = versioned_dir.join("tmp_orphan");
        fs::write(&tmp, b"junk")?;
        let shard_dir = versioned_dir.join("aa").join("bb");
        fs::create_dir_all(&shard_dir)?;
        let body_path = shard_dir.join("aabbcc");
        fs::write(&body_path, b"data")?;

        let cache = build_cache(4, dir.path().to_path_buf(), 1024, 1024 * 10).await?;

        // All stray files/directories should be removed and counters reset
        assert_eq!(fs::read_dir(&versioned_dir)?.count(), 0);
        let index = cache.state.index.lock();
        assert_eq!(index.bytes_in_use(), 0);
        assert_eq!(index.len(), 0);
        drop(index);
        Ok(())
    }

    #[tokio::test]
    async fn skips_cache_when_vary_header_count_too_high() -> Result<()> {
        let dir = TempDir::new()?;
        let cache = build_cache(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/vary-limit");
        let mut req_headers = HeaderMap::new();
        for name in ["a", "b", "c", "d", "e", "f", "g", "h", "i"] {
            req_headers.insert(name, "v".parse().unwrap());
        }
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(
            http::header::VARY,
            "a, b, c, d, e, f, g, h, i".parse().unwrap(),
        );

        let stream = cache
            .open_stream(&method, &uri, &req_headers, &resp_headers)
            .await?;
        assert!(stream.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn skips_cache_when_vary_value_bytes_too_large() -> Result<()> {
        let dir = TempDir::new()?;
        let cache = build_cache(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/vary-bytes");
        let mut req_headers = HeaderMap::new();
        let large_value = "x".repeat(super::key::MAX_VARY_BYTES + 1);
        req_headers.insert("user-agent", large_value.parse().unwrap());
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(http::header::VARY, "User-Agent".parse().unwrap());

        let stream = cache
            .open_stream(&method, &uri, &req_headers, &resp_headers)
            .await?;
        assert!(stream.is_none());
        Ok(())
    }
}
