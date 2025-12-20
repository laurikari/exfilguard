use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use blake3::Hasher;
use tokio::fs as async_fs;
use tokio::io::AsyncWriteExt;

use super::PersistedEntry;

#[derive(Debug, Clone)]
pub(super) struct CacheStore {
    disk_dir: PathBuf,
}

impl CacheStore {
    pub(super) fn new(disk_dir: PathBuf) -> Self {
        Self { disk_dir }
    }

    pub(super) fn disk_dir(&self) -> &Path {
        &self.disk_dir
    }

    pub(super) fn body_path(&self, entry_id: &str) -> PathBuf {
        let (first, remainder) = entry_id.split_at(2);
        let (second, _) = remainder.split_at(2);
        self.disk_dir.join(first).join(second).join(entry_id)
    }

    pub(super) fn meta_path(&self, entry_id: &str) -> PathBuf {
        let mut path = self.body_path(entry_id);
        path.set_extension("meta");
        path
    }

    pub(super) fn temp_path(&self, name: &str) -> PathBuf {
        self.disk_dir.join(name)
    }

    pub(super) fn remove_temp_files(&self) -> Result<()> {
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

    pub(super) fn content_hash_matches(&self, path: &Path, expected_hex: &str) -> bool {
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

    pub(super) fn remove_entry_files_from_meta(&self, meta_path: &Path) {
        if let Some(stem) = meta_path.file_stem().and_then(|s| s.to_str()) {
            let body_path = self.body_path(stem);
            fs::remove_file(body_path).ok();
        }
        fs::remove_file(meta_path).ok();
    }

    pub(super) async fn remove_entry_files_from_meta_async(&self, meta_path: &Path) {
        if let Some(stem) = meta_path.file_stem().and_then(|s| s.to_str()) {
            let body_path = self.body_path(stem);
            let _ = async_fs::remove_file(&body_path).await;
        }
        let _ = async_fs::remove_file(meta_path).await;
    }

    pub(super) async fn remove_entry_files_for_entry_id_async(&self, entry_id: &str) {
        let meta_path = self.meta_path(entry_id);
        self.remove_entry_files_from_meta_async(&meta_path).await;
    }

    pub(super) async fn dir_is_empty(path: &Path) -> bool {
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

    pub(super) async fn prune_empty_shards(&self, entry_id: &str) {
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

    pub(super) async fn write_metadata_async(
        &self,
        entry_id: &str,
        entry: &PersistedEntry,
    ) -> Result<()> {
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
}
