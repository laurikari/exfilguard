use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow};
use blake3::Hasher;
use http::{HeaderMap, Method, StatusCode, Uri};
use lru::LruCache;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::fs::File as AsyncFile;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::{fs as async_fs, task};
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
    next_id: AtomicU64,
}

#[derive(Debug)]
struct CacheInner {
    lru: LruCache<String, CacheEntry>,
    bytes_in_use: u64,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    pub id: u64,
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub vary_headers: HeaderMap,
    pub expires_at: SystemTime,
    pub body_hash: String,
    pub content_length: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedEntry {
    key_base: String,
    status: u16,
    headers: Vec<(String, String)>,
    vary_headers: Vec<(String, String)>,
    expires_at: u64,
    body_hash: String,
    content_length: u64,
}

fn to_headermap(items: &[(String, String)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in items {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::try_from(name.as_str()),
            http::HeaderValue::from_str(value),
        ) {
            map.append(name, value);
        }
    }
    map
}

fn headermap_to_vec(map: &HeaderMap) -> Vec<(String, String)> {
    let mut items = Vec::new();
    for (name, value) in map.iter() {
        if let Ok(value_str) = value.to_str() {
            items.push((name.as_str().to_string(), value_str.to_string()));
        }
    }
    items
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
    pub async fn new(
        capacity: usize,
        disk_dir: PathBuf,
        max_entry_size: u64,
        max_bytes: u64,
    ) -> Result<Self> {
        async_fs::create_dir_all(&disk_dir)
            .await
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
            next_id: AtomicU64::new(1),
        });
        let rebuild = {
            let state = state.clone();
            task::spawn_blocking(move || state.rebuild_from_disk())
        };
        rebuild
            .await
            .map_err(|err| anyhow!("cache rebuild task failed: {err}"))??;

        Ok(Self { state })
    }

    pub async fn lookup(
        &self,
        method: &Method,
        uri: &Uri,
        req_headers: &HeaderMap,
    ) -> Option<CachedResponse> {
        let key_base = format!("{}::{}", method, uri);

        let entry = {
            let mut guard = self.state.inner.lock();
            guard.lru.get(&key_base).cloned()
        };

        let entry = match entry {
            Some(entry) => entry,
            None => {
                crate::metrics::record_cache_lookup(false);
                return None;
            }
        };

        if SystemTime::now() > entry.expires_at {
            trace!("cache entry expired");
            if self.state.remove_entry_if_id_matches(&key_base, entry.id) {
                self.state
                    .remove_entry_files_for_hash_async(&entry.body_hash)
                    .await;
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
        if let Err(err) = async_fs::metadata(&body_path).await {
            warn!(
                error = %err,
                path = %body_path.display(),
                "cache body missing on disk"
            );
            if self.state.remove_entry_if_id_matches(&key_base, entry.id) {
                self.state
                    .remove_entry_files_for_hash_async(&entry.body_hash)
                    .await;
            }
            crate::metrics::record_cache_lookup(false);
            return None;
        }

        crate::metrics::record_cache_lookup(true);
        Some(CachedResponse {
            status: entry.status,
            headers: entry.headers.clone(),
            body_path,
            content_length: entry.content_length,
        })
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
                        // RFC: Vary:* response is not cacheable.
                        return None;
                    }
                    if let Ok(hdr) = http::header::HeaderName::from_bytes(header_name.as_bytes()) {
                        let req_val = match req_headers.get(&hdr) {
                            Some(val) => val,
                            None => {
                                // If the request didn't supply a header named in Vary, the
                                // response representation cannot be cached safely.
                                return None;
                            }
                        };
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

    fn meta_path(&self, hash: &str) -> PathBuf {
        let mut path = self.body_path(hash);
        path.set_extension("meta");
        path
    }

    fn next_entry_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn remove_entry_if_id_matches(&self, key_base: &str, entry_id: u64) -> bool {
        let mut guard = self.inner.lock();
        let inner = &mut *guard;
        let matches = inner
            .lru
            .get(key_base)
            .map(|entry| entry.id == entry_id)
            .unwrap_or(false);
        if matches && let Some(removed) = inner.lru.pop(key_base) {
            inner.bytes_in_use = inner.bytes_in_use.saturating_sub(removed.content_length);
            return true;
        }
        false
    }

    fn rebuild_from_disk(&self) -> Result<()> {
        self.remove_temp_files()?;
        let mut guard = self.inner.lock();
        guard.bytes_in_use = 0;
        guard.lru.clear();
        drop(guard);

        if !self.disk_dir.exists() {
            return Ok(());
        }

        for shard1 in fs::read_dir(&self.disk_dir)? {
            let shard1 = shard1?;
            if !shard1.file_type()?.is_dir() {
                continue;
            }
            for shard2 in fs::read_dir(shard1.path())? {
                let shard2 = shard2?;
                if !shard2.file_type()?.is_dir() {
                    continue;
                }
                let mut meta_files = Vec::new();
                let mut other_files = Vec::new();
                for entry in fs::read_dir(shard2.path())? {
                    let entry = entry?;
                    let path = entry.path();
                    if entry.file_type()?.is_file() {
                        if path.extension().and_then(|ext| ext.to_str()) == Some("meta") {
                            meta_files.push(path);
                        } else {
                            other_files.push(path);
                        }
                    }
                }

                let mut live_hashes = HashSet::new();
                for meta in meta_files {
                    if let Some(hash) = self.restore_entry_from_meta(&meta)? {
                        live_hashes.insert(hash);
                    }
                }

                for path in other_files {
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|s| s.to_string());
                    let keep = name
                        .as_ref()
                        .map(|n| live_hashes.contains(n))
                        .unwrap_or(false);
                    if !keep {
                        fs::remove_file(&path).ok();
                    }
                }

                if fs::read_dir(shard2.path())?.next().is_none() {
                    fs::remove_dir_all(shard2.path()).ok();
                }
            }
            if fs::read_dir(shard1.path())?.next().is_none() {
                fs::remove_dir_all(shard1.path()).ok();
            }
        }
        Ok(())
    }

    fn remove_temp_files(&self) -> Result<()> {
        if !self.disk_dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&self.disk_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file()
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|name| name.starts_with("tmp_"))
                    .unwrap_or(false)
            {
                fs::remove_file(&path).ok();
            }
        }
        Ok(())
    }

    fn restore_entry_from_meta(&self, meta_path: &Path) -> Result<Option<String>> {
        let data = match fs::read(meta_path) {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(
                    "failed to read cache metadata {}: {}",
                    meta_path.display(),
                    err
                );
                return Ok(None);
            }
        };

        let persisted: PersistedEntry = match serde_json::from_slice(&data) {
            Ok(value) => value,
            Err(err) => {
                warn!(
                    "failed to parse cache metadata {}: {}",
                    meta_path.display(),
                    err
                );
                self.remove_entry_files_from_meta(meta_path);
                return Ok(None);
            }
        };

        if !Self::valid_body_hash(&persisted.body_hash) {
            warn!(
                "cache metadata {} has invalid body hash; removing entry",
                meta_path.display()
            );
            fs::remove_file(meta_path).ok();
            return Ok(None);
        }

        // Basic validation
        let expires_at = SystemTime::UNIX_EPOCH + Duration::from_secs(persisted.expires_at);
        if SystemTime::now() > expires_at {
            self.remove_entry_files_from_meta(meta_path);
            return Ok(None);
        }

        let body_path = self.body_path(&persisted.body_hash);
        if !body_path.exists() {
            self.remove_entry_files_from_meta(meta_path);
            return Ok(None);
        }

        if !self.body_hash_matches(&body_path, &persisted.body_hash) {
            warn!(
                "cache body hash mismatch for {}; removing entry",
                body_path.display()
            );
            self.remove_entry_files_from_meta(meta_path);
            return Ok(None);
        }

        if persisted.content_length > self.max_entry_size {
            self.remove_entry_files_from_meta(meta_path);
            return Ok(None);
        }
        if persisted.content_length > self.max_bytes {
            self.remove_entry_files_from_meta(meta_path);
            return Ok(None);
        }

        let headers = to_headermap(&persisted.headers);
        let vary_headers = to_headermap(&persisted.vary_headers);

        let entry = CacheEntry {
            id: self.next_entry_id(),
            status: StatusCode::from_u16(persisted.status).unwrap_or(StatusCode::OK),
            headers,
            vary_headers,
            expires_at,
            body_hash: persisted.body_hash.clone(),
            content_length: persisted.content_length,
        };

        let evicted = self.insert_entry(persisted.key_base.clone(), entry);
        self.remove_evicted_files(evicted);
        Ok(Some(persisted.body_hash))
    }

    fn body_hash_matches(&self, path: &Path, expected_hex: &str) -> bool {
        let mut file = match fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut hasher = Hasher::new();
        let mut buf = [0u8; 8192];
        loop {
            match std::io::Read::read(&mut file, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    hasher.update(&buf[..n]);
                }
                Err(_) => return false,
            }
        }
        hasher.finalize().to_hex().to_string() == expected_hex
    }

    fn remove_entry_files_from_meta(&self, meta_path: &Path) {
        if let Some(stem) = meta_path.file_stem().and_then(|s| s.to_str()) {
            let body_path = self.body_path(stem);
            fs::remove_file(body_path).ok();
        }
        fs::remove_file(meta_path).ok();
    }

    fn remove_evicted_files(&self, evicted: Vec<CacheEntry>) {
        for evicted_entry in evicted {
            crate::metrics::record_cache_eviction();
            let path = self.body_path(&evicted_entry.body_hash);
            let meta = self.meta_path(&evicted_entry.body_hash);
            trace!("removing evicted cache file: {}", path.display());
            if let Err(e) = fs::remove_file(path) {
                warn!("failed to remove evicted cache file: {}", e);
            }
            fs::remove_file(meta).ok();
        }
    }

    fn valid_body_hash(value: &str) -> bool {
        value.len() == 64 && value.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
    }

    async fn remove_entry_files_from_meta_async(&self, meta_path: &Path) {
        if let Some(stem) = meta_path.file_stem().and_then(|s| s.to_str()) {
            let body_path = self.body_path(stem);
            let _ = async_fs::remove_file(&body_path).await;
        }
        let _ = async_fs::remove_file(meta_path).await;
    }

    async fn remove_entry_files_for_hash_async(&self, body_hash: &str) {
        let meta_path = self.meta_path(body_hash);
        self.remove_entry_files_from_meta_async(&meta_path).await;
    }

    async fn remove_evicted_files_async(&self, evicted: Vec<CacheEntry>) {
        for evicted_entry in evicted {
            crate::metrics::record_cache_eviction();
            let path = self.body_path(&evicted_entry.body_hash);
            let meta = self.meta_path(&evicted_entry.body_hash);
            trace!("removing evicted cache file: {}", path.display());
            if let Err(e) = async_fs::remove_file(&path).await {
                warn!("failed to remove evicted cache file: {}", e);
            }
            let _ = async_fs::remove_file(&meta).await;
        }
    }

    async fn write_metadata_async(&self, entry: &PersistedEntry) -> Result<()> {
        let meta_path = self.meta_path(&entry.body_hash);
        if let Some(parent) = meta_path.parent() {
            async_fs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed to create cache shard {}", parent.display()))?;
        }
        let data = serde_json::to_vec(entry)?;
        async_fs::write(&meta_path, data)
            .await
            .with_context(|| format!("failed to write cache metadata {}", meta_path.display()))?;
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
            async_fs::remove_file(&self.temp_path).await.ok();
            return Ok(());
        }

        if self.current_size > self.state.max_bytes {
            async_fs::remove_file(&self.temp_path).await.ok();
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
        if async_fs::metadata(&final_path).await.is_err() {
            async_fs::create_dir_all(&shard_dir).await?;
            async_fs::rename(&self.temp_path, &final_path).await?;
        } else {
            // Already exists, just delete temp
            async_fs::remove_file(&self.temp_path).await?;
        }

        let entry = CacheEntry {
            id: self.state.next_entry_id(),
            status,
            headers,
            vary_headers: self.vary_headers.clone(),
            expires_at: SystemTime::now() + ttl,
            body_hash,
            content_length: self.current_size,
        };

        let persisted = PersistedEntry {
            key_base: self.key_base.clone(),
            status: status.as_u16(),
            headers: headermap_to_vec(&entry.headers),
            vary_headers: headermap_to_vec(&entry.vary_headers),
            expires_at: entry
                .expires_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            body_hash: entry.body_hash.clone(),
            content_length: entry.content_length,
        };

        if let Err(err) = self.state.write_metadata_async(&persisted).await {
            warn!("failed to write cache metadata: {}", err);
            async_fs::remove_file(&self.state.meta_path(&entry.body_hash))
                .await
                .ok();
            async_fs::remove_file(self.state.body_path(&entry.body_hash))
                .await
                .ok();
            return Ok(());
        }

        let evicted = self.state.insert_entry(self.key_base.clone(), entry);
        trace!("stored cache entry for {}", self.key_base);

        self.state.remove_evicted_files_async(evicted).await;

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
        let cache =
            HttpCache::new(10, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

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

        // Verify body on disk
        let disk_body = fs::read(hit.body_path)?;
        assert_eq!(disk_body, body);

        Ok(())
    }

    #[tokio::test]
    async fn test_cache_expiration() -> Result<()> {
        let dir = TempDir::new()?;
        let cache =
            HttpCache::new(10, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

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
            HttpCache::new(10, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

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
                Duration::from_secs(0),
            )
            .await?;

        let body_hash = blake3::hash(body).to_hex().to_string();
        let (first, remainder) = body_hash.split_at(2);
        let (second, _) = remainder.split_at(2);
        let body_path = dir.path().join(first).join(second).join(&body_hash);
        let mut meta_path = body_path.clone();
        meta_path.set_extension("meta");

        assert!(body_path.exists(), "expected cached body to exist");
        assert!(meta_path.exists(), "expected cached metadata to exist");

        std::thread::sleep(Duration::from_millis(5));
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
        let cache =
            HttpCache::new(2, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;
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
        let cache = HttpCache::new(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;

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

        let rebuilt = HttpCache::new(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;
        let hit = rebuilt
            .lookup(&method, &uri, &req_headers)
            .await
            .expect("entry should be restored from disk");
        let body = fs::read(hit.body_path)?;
        assert_eq!(body, b"persisted");
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_drops_entries_with_corrupted_body() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let cache = HttpCache::new(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;

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

        let rebuilt = HttpCache::new(4, disk_dir, 1024 * 1024, 1024 * 1024 * 10).await?;
        assert!(
            rebuilt.lookup(&method, &uri, &req_headers).await.is_none(),
            "corrupted body should cause entry to be dropped"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_drops_invalid_body_hash_metadata() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let shard_dir = disk_dir.join("aa").join("bb");
        fs::create_dir_all(&shard_dir)?;
        let meta_path = shard_dir.join("broken.meta");
        let persisted = PersistedEntry {
            key_base: "GET::http://example.com:80/".to_string(),
            status: 200,
            headers: Vec::new(),
            vary_headers: Vec::new(),
            expires_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs()
                + 60,
            body_hash: "abc".to_string(),
            content_length: 0,
        };
        let data = serde_json::to_vec(&persisted)?;
        fs::write(&meta_path, data)?;

        let _rebuilt = HttpCache::new(4, disk_dir, 1024 * 1024, 1024 * 1024 * 10).await?;
        assert!(
            !meta_path.exists(),
            "invalid cache metadata should be removed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_prunes_expired_entries() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let cache = HttpCache::new(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;

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
                Duration::from_secs(0),
            )
            .await?;

        std::thread::sleep(Duration::from_millis(10));
        drop(cache);

        let rebuilt = HttpCache::new(4, disk_dir.clone(), 1024 * 1024, 1024 * 1024 * 10).await?;
        assert!(
            rebuilt.lookup(&method, &uri, &req_headers).await.is_none(),
            "expired entry should be pruned during rebuild"
        );
        let file_count = fs::read_dir(&disk_dir)?
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
    async fn test_vary_mismatch() -> Result<()> {
        let dir = TempDir::new()?;

        let cache =
            HttpCache::new(10, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

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
    async fn skips_cache_when_vary_header_missing_from_request() -> Result<()> {
        let dir = TempDir::new()?;
        let cache =
            HttpCache::new(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

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
        assert_eq!(
            fs::read_dir(dir.path())?.count(),
            0,
            "cache directory should remain empty when entry is skipped"
        );
        Ok(())
    }

    #[tokio::test]
    async fn skips_cache_when_vary_star_present() -> Result<()> {
        let dir = TempDir::new()?;
        let cache =
            HttpCache::new(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

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
        assert_eq!(
            fs::read_dir(dir.path())?.count(),
            0,
            "cache directory should remain empty when Vary:* skips caching"
        );
        Ok(())
    }

    #[tokio::test]
    async fn cache_keys_include_scheme_and_authority() -> Result<()> {
        let dir = TempDir::new()?;
        let cache =
            HttpCache::new(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;
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
        // Total cap of 6 bytes, entry cap large enough to not trigger first.
        let cache = HttpCache::new(4, dir.path().to_path_buf(), 1024, 6).await?;
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
        let cache = HttpCache::new(2, dir.path().to_path_buf(), 1024, 2).await?;
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

        let cache = HttpCache::new(4, dir.path().to_path_buf(), 1024, 1024 * 10).await?;

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
        let cache =
            HttpCache::new(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

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
        let cache =
            HttpCache::new(4, dir.path().to_path_buf(), 1024 * 1024, 1024 * 1024 * 10).await?;

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
