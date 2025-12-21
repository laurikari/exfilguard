use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, SystemTime};

use anyhow::{Result, anyhow};
use blake3::Hasher;
use http::{HeaderMap, StatusCode};
use tokio::fs as async_fs;
use tokio::fs::File as AsyncFile;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::{trace, warn};

use super::{CacheEntry, CacheKey, CacheState, VaryKey};

pub(crate) struct CacheWriter {
    file: AsyncFile,
    hasher: Hasher,
    temp_path: std::path::PathBuf,
    state: Arc<CacheState>,
    current_size: u64,
    key: CacheKey,
    vary: VaryKey,
    discard: bool,
    finished: bool,
}

impl CacheWriter {
    pub(super) fn new(
        file: AsyncFile,
        temp_path: std::path::PathBuf,
        state: Arc<CacheState>,
        key: CacheKey,
        vary: VaryKey,
    ) -> Self {
        Self {
            file,
            hasher: Hasher::new(),
            temp_path,
            state,
            current_size: 0,
            key,
            vary,
            discard: false,
            finished: false,
        }
    }

    pub(crate) fn discard(&mut self) {
        self.discard = true;
    }

    pub(crate) async fn finish(
        mut self,
        status: StatusCode,
        headers: HeaderMap,
        ttl: Duration,
    ) -> Result<()> {
        self.file.flush().await?;

        if self.discard {
            // Delete temp file
            async_fs::remove_file(&self.temp_path).await.ok();
            self.finished = true;
            return Ok(());
        }

        if self.current_size > self.state.max_bytes {
            async_fs::remove_file(&self.temp_path).await.ok();
            self.finished = true;
            return Ok(());
        }

        let hash = self.hasher.finalize();
        let content_hash = hash.to_hex().to_string();
        let final_path = self.state.body_path(self.key.entry_id());
        let shard_dir = final_path
            .parent()
            .map(|path| path.to_path_buf())
            .ok_or_else(|| anyhow!("cache entry path missing parent"))?;

        // Move temp file to final path
        async_fs::create_dir_all(&shard_dir).await?;
        async_fs::rename(&self.temp_path, &final_path).await?;

        let entry = CacheEntry {
            id: self.state.next_entry_id(),
            status,
            headers,
            vary: self.vary.clone(),
            expires_at: SystemTime::now() + ttl,
            entry_id: self.key.entry_id().to_string(),
            content_hash,
            content_length: self.current_size,
        };

        let persisted = entry.to_persisted(self.key.key_base());

        if let Err(err) = self
            .state
            .write_metadata_async(self.key.entry_id(), &persisted)
            .await
        {
            warn!("failed to write cache metadata: {}", err);
            async_fs::remove_file(&self.state.meta_path(&entry.entry_id))
                .await
                .ok();
            async_fs::remove_file(self.state.body_path(&entry.entry_id))
                .await
                .ok();
            self.finished = true;
            return Ok(());
        }

        let evicted = self
            .state
            .insert_entry(self.key.key_base().to_string(), entry);
        trace!("stored cache entry for {}", self.key.key_base());

        self.state.remove_evicted_files_async(evicted).await;

        self.finished = true;
        Ok(())
    }
}

impl AsyncWrite for CacheWriter {
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

impl Drop for CacheWriter {
    fn drop(&mut self) {
        if self.finished {
            return;
        }

        let temp_path = self.temp_path.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = async_fs::remove_file(temp_path).await;
            });
        } else {
            let _ = std::fs::remove_file(&temp_path);
        }
    }
}
