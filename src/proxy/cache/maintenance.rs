use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use tokio::fs as async_fs;
use tracing::{trace, warn};

use super::{CacheEntry, CacheKey, CacheState, PersistedEntry, SweepStats, VaryKey, to_headermap};

const CACHE_LAYOUT_VERSION: u32 = 1;
const CACHE_VERSION_PREFIX: &str = "v";
const CACHE_TOMBSTONE_PREFIX: &str = "tombstone-";

pub(super) fn cache_version_dir(root: &Path) -> PathBuf {
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

pub(super) async fn prepare_versioned_cache_dir(root: &Path) -> Result<(PathBuf, Vec<PathBuf>)> {
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

pub(super) fn spawn_cache_dir_cleanup(dirs: Vec<PathBuf>) {
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

pub(super) fn spawn_cache_sweeper(state: Arc<CacheState>, interval: Duration, batch_size: usize) {
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

impl CacheState {
    pub(super) fn rebuild_from_disk(&self) -> Result<()> {
        self.store.remove_temp_files()?;
        let mut guard = self.index.lock();
        guard.reset();
        drop(guard);

        if !self.store.disk_dir().exists() {
            return Ok(());
        }

        for shard1 in fs::read_dir(self.store.disk_dir())? {
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

        let key = CacheKey::from_key_base(persisted.key_base.clone());
        let entry_id = key.entry_id();
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

        let body_path = self.body_path(entry_id);
        if !body_path.exists() {
            self.remove_entry_files_from_meta(meta_path);
            return Ok(None);
        }

        if !self
            .store
            .content_hash_matches(&body_path, &persisted.content_hash)
        {
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
        let vary = VaryKey::new(vary_headers);

        let entry = CacheEntry {
            id: self.next_entry_id(),
            status: http::StatusCode::from_u16(persisted.status).unwrap_or(http::StatusCode::OK),
            headers,
            vary,
            expires_at,
            entry_id: entry_id.to_string(),
            content_hash: persisted.content_hash.clone(),
            content_length: persisted.content_length,
        };

        let evicted = self.insert_entry(key.key_base().to_string(), entry);
        self.remove_evicted_files(evicted);
        Ok(Some(entry_id.to_string()))
    }

    fn remove_entry_files_from_meta(&self, meta_path: &Path) {
        self.store.remove_entry_files_from_meta(meta_path);
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
        self.store
            .remove_entry_files_from_meta_async(meta_path)
            .await;
    }

    pub(super) async fn remove_entry_files_for_entry_id_async(&self, entry_id: &str) {
        self.store
            .remove_entry_files_for_entry_id_async(entry_id)
            .await;
    }

    async fn prune_empty_shards(&self, entry_id: &str) {
        self.store.prune_empty_shards(entry_id).await;
    }

    pub(super) async fn sweep_expired_entries(&self, batch_size: usize) -> Result<SweepStats> {
        let mut stats = SweepStats::default();
        if batch_size == 0 {
            return Ok(stats);
        }
        let now = SystemTime::now();
        let mut shard1_entries = match async_fs::read_dir(self.store.disk_dir()).await {
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

    pub(super) async fn remove_evicted_files_async(&self, evicted: Vec<CacheEntry>) {
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
}
