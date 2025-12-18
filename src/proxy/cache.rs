use std::fs;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow};
use blake3::Hasher;
use http::{HeaderMap, Method, StatusCode, Uri};
use lru::LruCache;
use parking_lot::Mutex;
use tokio::fs::File as AsyncFile;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::{trace, warn};

const MAX_VARY_HEADERS: usize = 8;
const MAX_VARY_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body_path: PathBuf,
    pub content_length: u64,
}

#[derive(Clone)]
pub struct HttpCache {
    state: Arc<CacheState>,
}

#[derive(Debug)]
struct CacheState {
    inner: Mutex<CacheInner>,
    disk_dir: PathBuf,
    max_entry_size: u64,
    max_bytes: u64,
}

#[derive(Debug)]
struct CacheInner {
    lru: LruCache<String, CacheEntry>,
    bytes_in_use: u64,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub vary_headers: HeaderMap,
    pub expires_at: SystemTime,
    pub body_hash: String,
    pub content_length: u64,
}

pub struct CacheStream {
    file: AsyncFile,
    hasher: Hasher,
    temp_path: PathBuf,
    state: Arc<CacheState>,
    current_size: u64,
    key_base: String,
    vary_headers: HeaderMap,
    discard: bool,
}

impl HttpCache {
    pub fn new(
        capacity: usize,
        disk_dir: PathBuf,
        max_entry_size: u64,
        max_bytes: u64,
    ) -> Result<Self> {
        fs::create_dir_all(&disk_dir)
            .with_context(|| format!("failed to create cache dir {}", disk_dir.display()))?;

        let capacity = std::num::NonZeroUsize::new(capacity)
            .ok_or_else(|| anyhow!("cache capacity must be greater than zero"))?;
        let cache = LruCache::new(capacity);
        let state = Arc::new(CacheState {
            inner: Mutex::new(CacheInner {
                lru: cache,
                bytes_in_use: 0,
            }),
            disk_dir,
            max_entry_size,
            max_bytes,
        });
        state.rebuild_from_disk()?;

        Ok(Self { state })
    }

    pub fn lookup(
        &self,
        method: &Method,
        uri: &Uri,
        req_headers: &HeaderMap,
    ) -> Option<CachedResponse> {
        let key_base = format!("{}::{}", method, uri);

        let mut guard = self.state.inner.lock();
        let inner = &mut *guard;

        if let Some(entry) = inner.lru.get(&key_base) {
            if SystemTime::now() > entry.expires_at {
                trace!("cache entry expired");
                if let Some(removed) = inner.lru.pop(&key_base) {
                    inner.bytes_in_use = inner.bytes_in_use.saturating_sub(removed.content_length);
                }
                crate::metrics::record_cache_lookup(false);
                return None;
            }

            if !self.vary_matches(&entry.vary_headers, req_headers) {
                trace!("cache entry vary mismatch");
                crate::metrics::record_cache_lookup(false);
                return None;
            }

            let body_path = self.get_body_path(&entry.body_hash);
            if !body_path.exists() {
                warn!("cache body missing on disk: {}", body_path.display());
                if let Some(removed) = inner.lru.pop(&key_base) {
                    inner.bytes_in_use = inner.bytes_in_use.saturating_sub(removed.content_length);
                }
                crate::metrics::record_cache_lookup(false);
                return None;
            }

            crate::metrics::record_cache_lookup(true);
            return Some(CachedResponse {
                status: entry.status,
                headers: entry.headers.clone(),
                body_path,
                content_length: entry.content_length,
            });
        }

        crate::metrics::record_cache_lookup(false);
        None
    }

    pub async fn open_stream(
        &self,
        method: &Method,
        uri: &Uri,
        req_headers: &HeaderMap,
        resp_headers: &HeaderMap,
    ) -> Result<Option<CacheStream>> {
        let key_base = format!("{}::{}", method, uri);
        let vary_headers = match self.extract_vary_headers(resp_headers, req_headers) {
            Some(map) => map,
            None => {
                trace!("skipping cache due to Vary header limits");
                return Ok(None);
            }
        };

        // Use a random temp file name
        let temp_name = format!("tmp_{}", uuid::Uuid::new_v4());
        let temp_path = self.state.disk_dir.join(&temp_name);

        let file = AsyncFile::create(&temp_path).await?;

        Ok(Some(CacheStream {
            file,
            hasher: Hasher::new(),
            temp_path,
            state: self.state.clone(),
            current_size: 0,
            key_base,
            vary_headers,
            discard: false,
        }))
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
        if let Some(mut stream) = self.open_stream(method, uri, req_headers, headers).await? {
            stream.write_all(body).await?;
            stream.finish(status, headers.clone(), ttl).await?;
            crate::metrics::record_cache_store();
        }
        Ok(())
    }

    fn get_body_path(&self, hash: &str) -> PathBuf {
        self.state.body_path(hash)
    }

    fn extract_vary_headers(
        &self,
        resp_headers: &HeaderMap,
        req_headers: &HeaderMap,
    ) -> Option<HeaderMap> {
        let mut vary_map = HeaderMap::new();
        let mut vary_bytes = 0usize;
        for value in resp_headers.get_all(http::header::VARY) {
            if let Ok(s) = value.to_str() {
                for header_name in s.split(',') {
                    let header_name = header_name.trim();
                    if header_name == "*" {
                        continue; // Cannot cache Vary: *
                    }
                    if let Ok(hdr) = http::header::HeaderName::from_bytes(header_name.as_bytes())
                        && let Some(req_val) = req_headers.get(&hdr)
                    {
                        if vary_map.len() + 1 > MAX_VARY_HEADERS {
                            return None;
                        }
                        let added_bytes = hdr.as_str().len() + req_val.as_bytes().len();
                        if vary_bytes.saturating_add(added_bytes) > MAX_VARY_BYTES {
                            return None;
                        }
                        vary_bytes += added_bytes;
                        vary_map.insert(hdr, req_val.clone());
                    }
                }
            }
        }
        Some(vary_map)
    }

    fn vary_matches(&self, stored_vary: &HeaderMap, req_headers: &HeaderMap) -> bool {
        for (name, value) in stored_vary.iter() {
            if let Some(req_value) = req_headers.get(name) {
                if req_value != value {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }
}

impl CacheState {
    fn body_path(&self, hash: &str) -> PathBuf {
        let (first, remainder) = hash.split_at(2);
        let (second, _) = remainder.split_at(2);
        self.disk_dir.join(first).join(second).join(hash)
    }

    fn rebuild_from_disk(&self) -> Result<()> {
        self.clean_dir(&self.disk_dir)?;
        let mut guard = self.inner.lock();
        guard.bytes_in_use = 0;
        guard.lru.clear();
        Ok(())
    }

    fn clean_dir(&self, dir: &Path) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                fs::remove_dir_all(&path).ok();
            } else {
                fs::remove_file(&path).ok();
            }
        }
        Ok(())
    }

    fn insert_entry(&self, key_base: String, entry: CacheEntry) -> Vec<CacheEntry> {
        let mut evicted = Vec::new();
        let mut guard = self.inner.lock();
        let inner = &mut *guard;

        inner.bytes_in_use = inner.bytes_in_use.saturating_add(entry.content_length);

        if let Some((_key, removed)) = inner.lru.push(key_base, entry) {
            inner.bytes_in_use = inner.bytes_in_use.saturating_sub(removed.content_length);
            evicted.push(removed);
        }

        while inner.bytes_in_use > self.max_bytes {
            if let Some((_key, removed)) = inner.lru.pop_lru() {
                inner.bytes_in_use = inner.bytes_in_use.saturating_sub(removed.content_length);
                evicted.push(removed);
            } else {
                break;
            }
        }

        evicted
    }
}

impl CacheStream {
    pub async fn finish(
        mut self,
        status: StatusCode,
        headers: HeaderMap,
        ttl: Duration,
    ) -> Result<()> {
        self.file.flush().await?;

        if self.discard {
            // Delete temp file
            tokio::fs::remove_file(&self.temp_path).await.ok();
            return Ok(());
        }

        if self.current_size > self.state.max_bytes {
            tokio::fs::remove_file(&self.temp_path).await.ok();
            return Ok(());
        }

        let hash = self.hasher.finalize();
        let body_hash = hash.to_hex().to_string();

        // Construct final path
        let (first, remainder) = body_hash.split_at(2);
        let (second, _) = remainder.split_at(2);
        let shard_dir = self.state.disk_dir.join(first).join(second);
        let final_path = shard_dir.join(&body_hash);

        // Move temp file to final path
        if !final_path.exists() {
            tokio::fs::create_dir_all(&shard_dir).await?;
            tokio::fs::rename(&self.temp_path, &final_path).await?;
        } else {
            // Already exists, just delete temp
            tokio::fs::remove_file(&self.temp_path).await?;
        }

        let entry = CacheEntry {
            status,
            headers,
            vary_headers: self.vary_headers.clone(),
            expires_at: SystemTime::now() + ttl,
            body_hash,
            content_length: self.current_size,
        };

        let evicted = self.state.insert_entry(self.key_base.clone(), entry);
        trace!("stored cache entry for {}", self.key_base);

        for evicted_entry in evicted {
            crate::metrics::record_cache_eviction();
            let path = self.state.body_path(&evicted_entry.body_hash);

            trace!("removing evicted cache file: {}", path.display());
            if let Err(e) = tokio::fs::remove_file(path).await {
                warn!("failed to remove evicted cache file: {}", e);
            }
        }

        Ok(())
    }
}

impl AsyncWrite for CacheStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.discard {
            return Poll::Ready(Ok(buf.len()));
        }

        // Check size limit
        if self.current_size + buf.len() as u64 > self.state.max_entry_size {
            self.discard = true;
            return Poll::Ready(Ok(buf.len()));
        }

        // Write to hasher
        self.hasher.update(buf);
        self.current_size += buf.len() as u64;

        // Write to file
        Pin::new(&mut self.file).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.file).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.file).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn build_uri(host: &str, port: u16, path: &str) -> Uri {
        http::Uri::builder()
            .scheme("http")
            .authority(format!("{host}:{port}").as_str())
            .path_and_query(path)
            .build()
            .expect("build test uri")
    }

    #[tokio::test]
    async fn test_cache_lifecycle() -> Result<()> {
        let dir = TempDir::new()?;
        let cache = HttpCache::new(10, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10)?;

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
        let hit = cache.lookup(&method, &uri, &req_headers);
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.content_length, body.len() as u64);

        // Verify body on disk
        let disk_body = fs::read(hit.body_path)?;
        assert_eq!(disk_body, body);

        Ok(())
    }

    #[tokio::test]
    async fn test_cache_expiration() -> Result<()> {
        let dir = TempDir::new()?;
        let cache = HttpCache::new(10, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10)?;

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
        let miss = cache.lookup(&method, &uri, &req_headers);
        assert!(miss.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_cache_eviction_deletes_file() -> Result<()> {
        let dir = TempDir::new()?;
        // Capacity 2
        let cache = HttpCache::new(2, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10)?;
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
        let hit_a = cache.lookup(&method, &uri_a, &req_headers).unwrap();
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
        let hit_b = cache.lookup(&method, &uri_b, &req_headers).unwrap();
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
        assert!(cache.lookup(&method, &uri_a, &req_headers).is_none());
        // A's file should be deleted
        assert!(!hit_a.body_path.exists(), "Evicted file should be deleted");

        // B and C should exist
        assert!(cache.lookup(&method, &uri_b, &req_headers).is_some());
        assert!(hit_b.body_path.exists());

        let hit_c = cache.lookup(&method, &uri_c, &req_headers).unwrap();

        assert!(hit_c.body_path.exists());

        Ok(())
    }

    #[tokio::test]
    async fn test_vary_mismatch() -> Result<()> {
        let dir = TempDir::new()?;

        let cache = HttpCache::new(10, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10)?;

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

        assert!(cache.lookup(&method, &uri, &req_headers_1).is_some());

        // Miss for Desktop

        let mut req_headers_2 = HeaderMap::new();

        req_headers_2.insert("user-agent", "desktop".parse()?);

        assert!(cache.lookup(&method, &uri, &req_headers_2).is_none());

        Ok(())
    }

    #[tokio::test]
    async fn cache_keys_include_scheme_and_authority() -> Result<()> {
        let dir = TempDir::new()?;
        let cache = HttpCache::new(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10)?;
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
            cache.lookup(&method, &uri_b, &req_headers).is_none(),
            "cache should not mix hosts for identical paths"
        );

        // Original host still hits
        assert!(cache.lookup(&method, &uri_a, &req_headers).is_some());

        Ok(())
    }

    #[tokio::test]
    async fn enforces_total_capacity_and_evicts_lru() -> Result<()> {
        let dir = TempDir::new()?;
        // Total cap of 6 bytes, entry cap large enough to not trigger first.
        let cache = HttpCache::new(4, dir.path().to_path_buf(), 1024, 6)?;
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
        let hit_a = cache.lookup(&method, &uri_a, &req_headers).unwrap();
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

        assert!(cache.lookup(&method, &uri_a, &req_headers).is_none());
        assert!(!hit_a.body_path.exists());
        assert!(cache.lookup(&method, &uri_b, &req_headers).is_some());

        Ok(())
    }

    #[tokio::test]
    async fn skips_entry_bigger_than_total_capacity() -> Result<()> {
        let dir = TempDir::new()?;
        let cache = HttpCache::new(2, dir.path().to_path_buf(), 1024, 2)?;
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

        assert!(cache.lookup(&method, &uri, &req_headers).is_none());
        // temp should have been cleaned; cache dir should remain empty
        assert_eq!(fs::read_dir(dir.path())?.count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn clears_stale_disk_on_startup() -> Result<()> {
        let dir = TempDir::new()?;

        // Write stray temp file and a hashed body shard
        let tmp = dir.path().join("tmp_orphan");
        fs::write(&tmp, b"junk")?;
        let shard_dir = dir.path().join("aa").join("bb");
        fs::create_dir_all(&shard_dir)?;
        let body_path = shard_dir.join("aabbcc");
        fs::write(&body_path, b"data")?;

        let cache = HttpCache::new(4, dir.path().to_path_buf(), 1024, 1024 * 10)?;

        // All stray files/directories should be removed and counters reset
        assert_eq!(fs::read_dir(dir.path())?.count(), 0);
        let inner = cache.state.inner.lock();
        assert_eq!(inner.bytes_in_use, 0);
        assert_eq!(inner.lru.len(), 0);
        drop(inner);
        Ok(())
    }

    #[tokio::test]
    async fn skips_cache_when_vary_header_count_too_high() -> Result<()> {
        let dir = TempDir::new()?;
        let cache = HttpCache::new(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10)?;

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
        let cache = HttpCache::new(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10)?;

        let method = Method::GET;
        let uri = build_uri("example.com", 80, "/vary-bytes");
        let mut req_headers = HeaderMap::new();
        let large_value = "x".repeat(MAX_VARY_BYTES + 1);
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
