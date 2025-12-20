use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
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
const CACHE_LAYOUT_VERSION: u32 = 1;
const CACHE_VERSION_PREFIX: &str = "v";
const CACHE_TOMBSTONE_PREFIX: &str = "tombstone-";

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

#[derive(Debug, Default)]
struct SweepStats {
    inspected: usize,
    removed: u64,
    bytes_reclaimed: u64,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    pub id: u64,
    pub entry_id: String,
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub vary_headers: HeaderMap,
    pub expires_at: SystemTime,
    pub content_hash: String,
    pub content_length: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedEntry {
    key_base: String,
    status: u16,
    headers: Vec<(String, String)>,
    vary_headers: Vec<(String, String)>,
    expires_at: u64,
    content_hash: String,
    content_length: u64,
}

fn entry_id_for_key(key_base: &str) -> String {
    blake3::hash(key_base.as_bytes()).to_hex().to_string()
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

fn cache_version_dir(root: &Path) -> PathBuf {
    root.join(format!("{CACHE_VERSION_PREFIX}{CACHE_LAYOUT_VERSION}"))
}

fn parse_cache_version(name: &str) -> Option<u32> {
    let version = name.strip_prefix(CACHE_VERSION_PREFIX)?;
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    version.parse().ok()
}

fn tombstone_dir_name(version_name: &str) -> String {
    format!(
        "{CACHE_TOMBSTONE_PREFIX}{version_name}-{}",
        uuid::Uuid::new_v4()
    )
}

async fn prepare_versioned_cache_dir(root: &Path) -> Result<(PathBuf, Vec<PathBuf>)> {
    async_fs::create_dir_all(root)
        .await
        .with_context(|| format!("failed to create cache root {}", root.display()))?;

    let active_name = format!("{CACHE_VERSION_PREFIX}{CACHE_LAYOUT_VERSION}");
    let active_dir = cache_version_dir(root);
    async_fs::create_dir_all(&active_dir)
        .await
        .with_context(|| format!("failed to create cache dir {}", active_dir.display()))?;

    let mut cleanup_dirs = Vec::new();
    let mut entries = match async_fs::read_dir(root).await {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Ok((active_dir, cleanup_dirs));
        }
        Err(err) => return Err(err.into()),
    };

    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == active_name {
            continue;
        }
        if name_str.starts_with(CACHE_TOMBSTONE_PREFIX) {
            cleanup_dirs.push(entry.path());
            continue;
        }
        if parse_cache_version(&name_str).is_some() {
            let tombstone_path = root.join(tombstone_dir_name(&name_str));
            if let Err(err) = async_fs::rename(entry.path(), &tombstone_path).await {
                warn!(
                    error = %err,
                    path = %entry.path().display(),
                    "failed to tombstone old cache dir"
                );
                continue;
            }
            cleanup_dirs.push(tombstone_path);
        }
    }

    Ok((active_dir, cleanup_dirs))
}

fn spawn_cache_dir_cleanup(dirs: Vec<PathBuf>) {
    for dir in dirs {
        tokio::spawn(async move {
            match async_fs::remove_dir_all(&dir).await {
                Ok(()) => crate::metrics::record_cache_cleanup_dir(),
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => {
                    warn!(
                        error = %err,
                        path = %dir.display(),
                        "failed to remove old cache dir"
                    );
                }
            }
        });
    }
}

fn spawn_cache_sweeper(state: Arc<CacheState>, interval: Duration, batch_size: usize) {
    if interval.is_zero() || batch_size == 0 {
        return;
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match state.sweep_expired_entries(batch_size).await {
                Ok(stats) => {
                    crate::metrics::record_cache_sweep_run();
                    crate::metrics::record_cache_sweep_removed(
                        stats.removed,
                        stats.bytes_reclaimed,
                    );
                }
                Err(err) => {
                    warn!(error = %err, "cache sweep failed");
                }
            }
        }
    });
}

pub struct CacheStream {
    file: AsyncFile,
    hasher: Hasher,
    temp_path: PathBuf,
    state: Arc<CacheState>,
    current_size: u64,
    key_base: String,
    entry_id: String,
    vary_headers: HeaderMap,
    discard: bool,
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
        let cache_root = disk_dir;
        let (disk_dir, cleanup_dirs) = prepare_versioned_cache_dir(&cache_root).await?;

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
                    .remove_entry_files_for_entry_id_async(&entry.entry_id)
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

        let body_path = self.get_body_path(&entry.entry_id);
        if let Err(err) = async_fs::metadata(&body_path).await {
            warn!(
                error = %err,
                path = %body_path.display(),
                "cache body missing on disk"
            );
            if self.state.remove_entry_if_id_matches(&key_base, entry.id) {
                self.state
                    .remove_entry_files_for_entry_id_async(&entry.entry_id)
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
        let entry_id = entry_id_for_key(&key_base);
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

        let mut options = async_fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let file = options.open(&temp_path).await?;

        Ok(Some(CacheStream {
            file,
            hasher: Hasher::new(),
            temp_path,
            state: self.state.clone(),
            current_size: 0,
            key_base,
            entry_id,
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

    fn get_body_path(&self, entry_id: &str) -> PathBuf {
        self.state.body_path(entry_id)
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
    fn body_path(&self, entry_id: &str) -> PathBuf {
        let (first, remainder) = entry_id.split_at(2);
        let (second, _) = remainder.split_at(2);
        self.disk_dir.join(first).join(second).join(entry_id)
    }

    fn meta_path(&self, entry_id: &str) -> PathBuf {
        let mut path = self.body_path(entry_id);
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

    fn remove_entry_by_key_base(&self, key_base: &str) {
        let mut guard = self.inner.lock();
        if let Some(removed) = guard.lru.pop(key_base) {
            guard.bytes_in_use = guard.bytes_in_use.saturating_sub(removed.content_length);
        }
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

        let entry_id = entry_id_for_key(&persisted.key_base);
        let file_stem = meta_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if entry_id != file_stem {
            warn!(
                expected = entry_id,
                actual = file_stem,
                "cache metadata key mismatch; removing entry"
            );
            self.remove_entry_files_from_meta(meta_path);
            return Ok(None);
        }

        if !Self::valid_content_hash(&persisted.content_hash) {
            warn!(
                "cache metadata {} has invalid content hash; removing entry",
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

        let body_path = self.body_path(&entry_id);
        if !body_path.exists() {
            self.remove_entry_files_from_meta(meta_path);
            return Ok(None);
        }

        if !self.content_hash_matches(&body_path, &persisted.content_hash) {
            warn!(
                "cache content hash mismatch for {}; removing entry",
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
            entry_id: entry_id.clone(),
            content_hash: persisted.content_hash.clone(),
            content_length: persisted.content_length,
        };

        let evicted = self.insert_entry(persisted.key_base.clone(), entry);
        self.remove_evicted_files(evicted);
        Ok(Some(entry_id))
    }

    fn content_hash_matches(&self, path: &Path, expected_hex: &str) -> bool {
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
            let path = self.body_path(&evicted_entry.entry_id);
            let meta = self.meta_path(&evicted_entry.entry_id);
            trace!("removing evicted cache file: {}", path.display());
            if let Err(e) = fs::remove_file(path) {
                warn!("failed to remove evicted cache file: {}", e);
            }
            fs::remove_file(meta).ok();
        }
    }

    fn valid_content_hash(value: &str) -> bool {
        value.len() == 64 && value.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
    }

    async fn remove_entry_files_from_meta_async(&self, meta_path: &Path) {
        if let Some(stem) = meta_path.file_stem().and_then(|s| s.to_str()) {
            let body_path = self.body_path(stem);
            let _ = async_fs::remove_file(&body_path).await;
        }
        let _ = async_fs::remove_file(meta_path).await;
    }

    async fn remove_entry_files_for_entry_id_async(&self, entry_id: &str) {
        let meta_path = self.meta_path(entry_id);
        self.remove_entry_files_from_meta_async(&meta_path).await;
    }

    async fn dir_is_empty(path: &Path) -> bool {
        let mut entries = match async_fs::read_dir(path).await {
            Ok(entries) => entries,
            Err(_) => return false,
        };
        match entries.next_entry().await {
            Ok(None) => true,
            Ok(Some(_)) => false,
            Err(_) => false,
        }
    }

    async fn prune_empty_shards(&self, entry_id: &str) {
        let body_path = self.body_path(entry_id);
        let shard2 = match body_path.parent() {
            Some(path) => path.to_path_buf(),
            None => return,
        };
        if Self::dir_is_empty(&shard2).await {
            let _ = async_fs::remove_dir(&shard2).await;
        }
        let shard1 = match shard2.parent() {
            Some(path) => path.to_path_buf(),
            None => return,
        };
        if shard1 == self.disk_dir {
            return;
        }
        if Self::dir_is_empty(&shard1).await {
            let _ = async_fs::remove_dir(&shard1).await;
        }
    }

    async fn sweep_expired_entries(&self, batch_size: usize) -> Result<SweepStats> {
        let mut stats = SweepStats::default();
        if batch_size == 0 {
            return Ok(stats);
        }
        let now = SystemTime::now();
        let mut shard1_entries = match async_fs::read_dir(&self.disk_dir).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(stats),
            Err(err) => return Err(err.into()),
        };

        'outer: while let Some(shard1) = shard1_entries.next_entry().await? {
            if !shard1.file_type().await?.is_dir() {
                continue;
            }
            let mut shard2_entries = match async_fs::read_dir(shard1.path()).await {
                Ok(entries) => entries,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => return Err(err.into()),
            };
            while let Some(shard2) = shard2_entries.next_entry().await? {
                if !shard2.file_type().await?.is_dir() {
                    continue;
                }
                let mut entries = match async_fs::read_dir(shard2.path()).await {
                    Ok(entries) => entries,
                    Err(err) if err.kind() == ErrorKind::NotFound => continue,
                    Err(err) => return Err(err.into()),
                };
                while let Some(entry) = entries.next_entry().await? {
                    if stats.inspected >= batch_size {
                        break 'outer;
                    }
                    let file_type = entry.file_type().await?;
                    if !file_type.is_file() {
                        continue;
                    }
                    let path = entry.path();
                    if path.extension().and_then(|ext| ext.to_str()) != Some("meta") {
                        continue;
                    }
                    stats.inspected += 1;
                    let data = match async_fs::read(&path).await {
                        Ok(data) => data,
                        Err(err) if err.kind() == ErrorKind::NotFound => continue,
                        Err(err) => return Err(err.into()),
                    };
                    let persisted: PersistedEntry = match serde_json::from_slice(&data) {
                        Ok(value) => value,
                        Err(_) => continue,
                    };
                    let expires_at =
                        SystemTime::UNIX_EPOCH + Duration::from_secs(persisted.expires_at);
                    if now <= expires_at {
                        continue;
                    }
                    self.remove_entry_by_key_base(&persisted.key_base);
                    self.remove_entry_files_from_meta_async(&path).await;
                    if let Some(entry_id) = path.file_stem().and_then(|s| s.to_str()) {
                        self.prune_empty_shards(entry_id).await;
                    }
                    stats.removed += 1;
                    stats.bytes_reclaimed = stats
                        .bytes_reclaimed
                        .saturating_add(persisted.content_length);
                }
            }
        }

        Ok(stats)
    }

    async fn remove_evicted_files_async(&self, evicted: Vec<CacheEntry>) {
        for evicted_entry in evicted {
            crate::metrics::record_cache_eviction();
            let path = self.body_path(&evicted_entry.entry_id);
            let meta = self.meta_path(&evicted_entry.entry_id);
            trace!("removing evicted cache file: {}", path.display());
            if let Err(e) = async_fs::remove_file(&path).await {
                warn!("failed to remove evicted cache file: {}", e);
            }
            let _ = async_fs::remove_file(&meta).await;
        }
    }

    async fn write_metadata_async(&self, entry_id: &str, entry: &PersistedEntry) -> Result<()> {
        let meta_path = self.meta_path(entry_id);
        if let Some(parent) = meta_path.parent() {
            async_fs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed to create cache shard {}", parent.display()))?;
        }
        let data = serde_json::to_vec(entry)?;
        let mut options = async_fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut file = options
            .open(&meta_path)
            .await
            .with_context(|| format!("failed to write cache metadata {}", meta_path.display()))?;
        file.write_all(&data).await?;
        file.flush().await?;
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
    pub fn discard(&mut self) {
        self.discard = true;
    }

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
        let content_hash = hash.to_hex().to_string();
        let final_path = self.state.body_path(&self.entry_id);
        let shard_dir = final_path
            .parent()
            .map(|path| path.to_path_buf())
            .ok_or_else(|| anyhow!("cache entry path missing parent"))?;

        // Move temp file to final path
        async_fs::create_dir_all(&shard_dir).await?;
        let _ = async_fs::remove_file(&final_path).await;
        async_fs::rename(&self.temp_path, &final_path).await?;

        let entry = CacheEntry {
            id: self.state.next_entry_id(),
            status,
            headers,
            vary_headers: self.vary_headers.clone(),
            expires_at: SystemTime::now() + ttl,
            entry_id: self.entry_id.clone(),
            content_hash,
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
            content_hash: entry.content_hash.clone(),
            content_length: entry.content_length,
        };

        if let Err(err) = self
            .state
            .write_metadata_async(&self.entry_id, &persisted)
            .await
        {
            warn!("failed to write cache metadata: {}", err);
            async_fs::remove_file(&self.state.meta_path(&entry.entry_id))
                .await
                .ok();
            async_fs::remove_file(self.state.body_path(&entry.entry_id))
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

    const TEST_SWEEPER_INTERVAL: Duration = Duration::from_secs(3600);
    const TEST_SWEEPER_BATCH_SIZE: usize = 128;

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

        // Verify body on disk
        let disk_body = fs::read(hit.body_path)?;
        assert_eq!(disk_body, body);

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

        let entry_id = entry_id_for_key(&format!("{}::{}", method, uri));
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
                Duration::from_secs(0),
            )
            .await?;

        let key_base = format!("{}::{}", method, uri);
        let entry_id = entry_id_for_key(&key_base);
        let (first, remainder) = entry_id.split_at(2);
        let (second, _) = remainder.split_at(2);
        let body_path = cache
            .state
            .disk_dir
            .join(first)
            .join(second)
            .join(&entry_id);
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
    async fn rebuild_drops_invalid_content_hash_metadata() -> Result<()> {
        let dir = TempDir::new()?;
        let disk_dir = dir.path().to_path_buf();
        let key_base = "GET::http://example.com:80/".to_string();
        let entry_id = entry_id_for_key(&key_base);
        let versioned_dir = cache_version_dir(&disk_dir);
        let shard_dir = versioned_dir.join(&entry_id[0..2]).join(&entry_id[2..4]);
        fs::create_dir_all(&shard_dir)?;
        let meta_path = shard_dir.join(format!("{entry_id}.meta"));
        let persisted = PersistedEntry {
            key_base,
            status: 200,
            headers: Vec::new(),
            vary_headers: Vec::new(),
            expires_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs()
                + 60,
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
                Duration::from_secs(0),
            )
            .await?;

        std::thread::sleep(Duration::from_millis(10));
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
        let old_dir = dir.path().join("v0");
        fs::create_dir_all(&old_dir)?;
        fs::write(old_dir.join("old"), b"data")?;

        let cache = build_cache(4, dir.path().to_path_buf(), 1024, 1024 * 10).await?;
        let active_dir = cache_version_dir(dir.path());
        assert_eq!(cache.state.disk_dir, active_dir);
        assert!(!old_dir.exists(), "old cache version should be tombstoned");

        let active_name = active_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
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
                Duration::from_secs(0),
            )
            .await?;

        std::thread::sleep(Duration::from_millis(5));
        let key_base = format!("{}::{}", method, uri);
        let entry_id = entry_id_for_key(&key_base);
        let body_path = cache.state.body_path(&entry_id);
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
        // Total cap of 6 bytes, entry cap large enough to not trigger first.
        let cache = build_cache(4, dir.path().to_path_buf(), 1024, 6).await?;
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
        let cache = build_cache(2, dir.path().to_path_buf(), 1024, 2).await?;
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
        let inner = cache.state.inner.lock();
        assert_eq!(inner.bytes_in_use, 0);
        assert_eq!(inner.lru.len(), 0);
        drop(inner);
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
