use std::fs::{self};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use blake3::Hasher;
use http::{HeaderMap, Method, StatusCode, Uri};
use lru::LruCache;
use parking_lot::Mutex;
use tokio::fs::File as AsyncFile;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::{trace, warn};

#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body_path: PathBuf,
    pub content_length: u64,
}

#[derive(Clone)]
pub struct HttpCache {
    inner: Arc<Mutex<LruCache<String, CacheEntry>>>,
    disk_dir: PathBuf,
    max_entry_size: u64,
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
    disk_dir: PathBuf,
    max_entry_size: u64,
    current_size: u64,
    inner: Arc<Mutex<LruCache<String, CacheEntry>>>,
    key_base: String,
    vary_headers: HeaderMap,
    discard: bool,
}

impl HttpCache {
    pub fn new(capacity: usize, disk_dir: PathBuf, max_entry_size: u64) -> Result<Self> {
        fs::create_dir_all(&disk_dir)
            .with_context(|| format!("failed to create cache dir {}", disk_dir.display()))?;

        let cache = LruCache::new(std::num::NonZeroUsize::new(capacity).unwrap());

        Ok(Self {
            inner: Arc::new(Mutex::new(cache)),
            disk_dir,
            max_entry_size,
        })
    }

    pub fn lookup(
        &self,
        method: &Method,
        uri: &Uri,
        req_headers: &HeaderMap,
    ) -> Option<CachedResponse> {
        let key_base = format!("{}::{}", method, uri);

        let mut cache = self.inner.lock();

        if let Some(entry) = cache.get(&key_base) {
            if SystemTime::now() > entry.expires_at {
                trace!("cache entry expired");
                cache.pop(&key_base);
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
                cache.pop(&key_base);
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
    ) -> Result<CacheStream> {
        let key_base = format!("{}::{}", method, uri);
        let vary_headers = self.extract_vary_headers(resp_headers, req_headers);

        // Use a random temp file name
        let temp_name = format!("tmp_{}", uuid::Uuid::new_v4());
        let temp_path = self.disk_dir.join(&temp_name);

        let file = AsyncFile::create(&temp_path).await?;

        Ok(CacheStream {
            file,
            hasher: Hasher::new(),
            temp_path,
            disk_dir: self.disk_dir.clone(),
            max_entry_size: self.max_entry_size,
            current_size: 0,
            inner: self.inner.clone(),
            key_base,
            vary_headers,
            discard: false,
        })
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
        let mut stream = self.open_stream(method, uri, req_headers, headers).await?;
        stream.write_all(body).await?;
        stream.finish(status, headers.clone(), ttl).await?;
        crate::metrics::record_cache_store();
        Ok(())
    }

    fn get_body_path(&self, hash: &str) -> PathBuf {
        let (first, remainder) = hash.split_at(2);
        let (second, _) = remainder.split_at(2);
        self.disk_dir.join(first).join(second).join(hash)
    }

    fn extract_vary_headers(&self, resp_headers: &HeaderMap, req_headers: &HeaderMap) -> HeaderMap {
        let mut vary_map = HeaderMap::new();
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
                        vary_map.insert(hdr, req_val.clone());
                    }
                }
            }
        }
        vary_map
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

        let hash = self.hasher.finalize();
        let body_hash = hash.to_hex().to_string();

        // Construct final path
        let (first, remainder) = body_hash.split_at(2);
        let (second, _) = remainder.split_at(2);
        let shard_dir = self.disk_dir.join(first).join(second);
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

        let evicted = self.inner.lock().push(self.key_base.clone(), entry.clone());
        trace!("stored cache entry for {}", self.key_base);

        if let Some((_key, evicted_entry)) = evicted
            && evicted_entry.body_hash != entry.body_hash
        {
            crate::metrics::record_cache_eviction();
            let hash = evicted_entry.body_hash;
            let (first, remainder) = hash.split_at(2);
            let (second, _) = remainder.split_at(2);
            let path = self.disk_dir.join(first).join(second).join(&hash);

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
        if self.current_size + buf.len() as u64 > self.max_entry_size {
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

    #[tokio::test]
    async fn test_cache_lifecycle() -> Result<()> {
        let dir = TempDir::new()?;
        let cache = HttpCache::new(10, dir.path().to_path_buf(), 1024 * 1024)?;

        let method = Method::GET;
        let uri = "/test".parse::<Uri>()?;
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
        let cache = HttpCache::new(10, dir.path().to_path_buf(), 1024 * 1024)?;

        let method = Method::GET;
        let uri = "/expired".parse::<Uri>()?;
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();

        // Store with 0 TTL (effectively expired immediately for test logic,
        // though strictly SystemTime might be equal. Let's use a small check)
        // Actually, let's inject a time or just wait. Waiting 1ms is risky in CI.
        // Better: SystemTime is not mockable easily here.
        // We rely on logic: expires_at = now + 0.
        // lookup checks if now > expires_at.
        // If we set TTL to 0, it expires instantly or very soon.

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
        let cache = HttpCache::new(2, dir.path().to_path_buf(), 1024 * 1024)?;
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();
        let method = Method::GET;

        // 1. Store Item A
        let uri_a = "/item-a".parse::<Uri>()?;
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
        let uri_b = "/item-b".parse::<Uri>()?;
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
        let uri_c = "/item-c".parse::<Uri>()?;
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

        let cache = HttpCache::new(10, dir.path().to_path_buf(), 1024 * 1024)?;

        let method = Method::GET;

        let uri = "/vary".parse::<Uri>()?;

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
}
