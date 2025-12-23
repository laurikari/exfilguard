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

enum CacheWriterFile {
    File(AsyncFile),
    #[cfg(test)]
    Partial(PartialWrite<AsyncFile>),
}

impl CacheWriterFile {
    fn new(file: AsyncFile) -> Self {
        Self::File(file)
    }

    #[cfg(test)]
    fn new_partial(file: AsyncFile, max_write: usize) -> Self {
        Self::Partial(PartialWrite::new(file, max_write))
    }
}

impl AsyncWrite for CacheWriterFile {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            CacheWriterFile::File(file) => Pin::new(file).poll_write(cx, buf),
            #[cfg(test)]
            CacheWriterFile::Partial(file) => Pin::new(file).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            CacheWriterFile::File(file) => Pin::new(file).poll_flush(cx),
            #[cfg(test)]
            CacheWriterFile::Partial(file) => Pin::new(file).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            CacheWriterFile::File(file) => Pin::new(file).poll_shutdown(cx),
            #[cfg(test)]
            CacheWriterFile::Partial(file) => Pin::new(file).poll_shutdown(cx),
        }
    }
}

impl Unpin for CacheWriterFile {}

#[cfg(test)]
struct PartialWrite<W> {
    inner: W,
    max_write: usize,
}

#[cfg(test)]
impl<W> PartialWrite<W> {
    fn new(inner: W, max_write: usize) -> Self {
        Self { inner, max_write }
    }
}

#[cfg(test)]
impl<W> AsyncWrite for PartialWrite<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let limit = self.max_write.min(buf.len());
        Pin::new(&mut self.inner).poll_write(cx, &buf[..limit])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
impl<W: Unpin> Unpin for PartialWrite<W> {}

pub(crate) struct CacheWriter {
    file: CacheWriterFile,
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
            file: CacheWriterFile::new(file),
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

    #[cfg(test)]
    pub(super) fn new_with_partial_write(
        file: AsyncFile,
        temp_path: std::path::PathBuf,
        state: Arc<CacheState>,
        key: CacheKey,
        vary: VaryKey,
        max_write: usize,
    ) -> Self {
        Self {
            file: CacheWriterFile::new_partial(file, max_write),
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

        // Check size limit before writing to avoid partial cache entries.
        if self.current_size + buf.len() as u64 > self.state.max_entry_size {
            self.discard = true;
            return Poll::Ready(Ok(buf.len()));
        }

        // Write to file, then update hash/size with bytes actually written.
        match Pin::new(&mut self.file).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    self.hasher.update(&buf[..written]);
                    self.current_size = self.current_size.saturating_add(written as u64);
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
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

#[cfg(test)]
mod tests {
    use super::super::entry::PersistedEntry;
    use super::super::{CacheIndex, CacheStore};
    use super::*;
    use http::{HeaderMap, Method, StatusCode, Uri};
    use parking_lot::Mutex;
    use std::num::NonZeroUsize;
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;
    use tempfile::TempDir;

    fn build_state(dir: &TempDir) -> Arc<CacheState> {
        let capacity = NonZeroUsize::new(8).expect("nonzero capacity");
        let index = CacheIndex::new(capacity, 1024 * 1024);
        let store = CacheStore::new(dir.path().to_path_buf());
        Arc::new(CacheState {
            index: Mutex::new(index),
            store,
            max_entry_size: 1024 * 1024,
            max_bytes: 1024 * 1024,
            next_id: AtomicU64::new(1),
        })
    }

    fn build_uri() -> Uri {
        Uri::builder()
            .scheme("http")
            .authority("example.com:80")
            .path_and_query("/test")
            .build()
            .expect("build uri")
    }

    #[tokio::test]
    async fn cache_writer_tracks_partial_writes() -> Result<()> {
        let dir = TempDir::new()?;
        let state = build_state(&dir);
        let key = CacheKey::new(&Method::GET, &build_uri());
        let temp_path = state.store.temp_path("tmp_partial_write");

        let mut options = async_fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        let file = options.open(&temp_path).await?;

        let vary = VaryKey::new(HeaderMap::new());
        let mut writer = CacheWriter::new_with_partial_write(
            file,
            temp_path.clone(),
            state.clone(),
            key.clone(),
            vary,
            3,
        );

        let body = b"partial write cache payload";
        writer.write_all(body).await?;
        writer
            .finish(StatusCode::OK, HeaderMap::new(), Duration::from_secs(30))
            .await?;

        let meta_path = state.meta_path(key.entry_id());
        let meta_bytes = async_fs::read(&meta_path).await?;
        let persisted: PersistedEntry = serde_json::from_slice(&meta_bytes)?;

        assert_eq!(persisted.content_length, body.len() as u64);
        assert_eq!(
            persisted.content_hash,
            blake3::hash(body).to_hex().to_string()
        );

        let body_path = state.body_path(key.entry_id());
        let stored = async_fs::read(&body_path).await?;
        assert_eq!(stored, body);

        Ok(())
    }
}
