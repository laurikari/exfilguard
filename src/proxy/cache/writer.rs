use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::SystemTime;

use anyhow::{Context, Result, anyhow};
use blake3::Hasher;
use http::{HeaderMap, StatusCode};
use tokio::fs as async_fs;
use tokio::fs::File as AsyncFile;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::OwnedMutexGuard;
use tracing::{trace, warn};

use super::{CacheEntry, CacheKey, CacheState, CacheTiming, VaryKey};

enum CacheWriterFile {
    File(AsyncFile),
    #[cfg(test)]
    Partial(PartialWrite<AsyncFile>),
    #[cfg(test)]
    Pending,
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
            #[cfg(test)]
            CacheWriterFile::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            CacheWriterFile::File(file) => Pin::new(file).poll_flush(cx),
            #[cfg(test)]
            CacheWriterFile::Partial(file) => Pin::new(file).poll_flush(cx),
            #[cfg(test)]
            CacheWriterFile::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            CacheWriterFile::File(file) => Pin::new(file).poll_shutdown(cx),
            #[cfg(test)]
            CacheWriterFile::Partial(file) => Pin::new(file).poll_shutdown(cx),
            #[cfg(test)]
            CacheWriterFile::Pending => Poll::Pending,
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
    file: Option<CacheWriterFile>,
    hasher: Hasher,
    temp_path: std::path::PathBuf,
    state: Arc<CacheState>,
    current_size: u64,
    key: CacheKey,
    vary: VaryKey,
    reserved_bytes: u64,
    pending_reservation: u64,
    discard: bool,
    deferred_cleanup: bool,
    committed: bool,
    finished: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheFinishOutcome {
    Stored,
    Skipped,
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
            file: Some(CacheWriterFile::new(file)),
            hasher: Hasher::new(),
            temp_path,
            state,
            current_size: 0,
            key,
            vary,
            reserved_bytes: 0,
            pending_reservation: 0,
            discard: false,
            deferred_cleanup: false,
            committed: false,
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
            file: Some(CacheWriterFile::new_partial(file, max_write)),
            hasher: Hasher::new(),
            temp_path,
            state,
            current_size: 0,
            key,
            vary,
            reserved_bytes: 0,
            pending_reservation: 0,
            discard: false,
            deferred_cleanup: false,
            committed: false,
            finished: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn stall_file_operations(&mut self) {
        self.file = Some(CacheWriterFile::Pending);
    }

    pub(crate) fn discard(&mut self) {
        if self.discard {
            return;
        }
        self.discard = true;
        self.file.take();
        let _ = std::fs::remove_file(&self.temp_path);
        self.release_reserved_bytes();
    }

    pub(crate) fn discard_in_background(&mut self) {
        if self.discard {
            return;
        }
        self.discard = true;
        self.deferred_cleanup = true;
        self.file.take();
        remove_file_in_background(self.temp_path.clone());
        self.release_reserved_bytes();
    }

    pub(crate) fn defer_cleanup(&mut self) {
        self.deferred_cleanup = true;
    }

    fn release_reserved_bytes(&mut self) {
        self.state.release_in_flight(self.reserved_bytes);
        self.reserved_bytes = 0;
        self.pending_reservation = 0;
    }

    pub(crate) async fn finish(
        self,
        status: StatusCode,
        headers: HeaderMap,
        timing: CacheTiming,
    ) -> Result<CacheFinishOutcome> {
        // Waiting remains cancellable by the request's cache timeout. Only
        // the lock holder may outlive its caller, so a stalled publication
        // cannot accumulate detached tasks (including zero-byte fills).
        let publish_guard = self.state.publish_lock().clone().lock_owned().await;
        // Once admitted, retain ownership through filesystem operations and
        // their accounting/cleanup updates even if the caller stops waiting.
        tokio::spawn(self.finish_owned(status, headers, timing, publish_guard))
            .await
            .context("cache publication task failed")?
    }

    async fn finish_owned(
        mut self,
        status: StatusCode,
        headers: HeaderMap,
        timing: CacheTiming,
        _publish_guard: OwnedMutexGuard<()>,
    ) -> Result<CacheFinishOutcome> {
        if let Some(file) = self.file.as_mut() {
            file.flush().await?;
        }

        if self.discard {
            self.finished = true;
            return Ok(CacheFinishOutcome::Skipped);
        }

        if self.current_size > self.state.max_bytes {
            self.discard();
            self.finished = true;
            return Ok(CacheFinishOutcome::Skipped);
        }

        let Some(expires_at) = timing.expires_at() else {
            warn!("skipping cache entry with unrepresentable expiration time");
            self.discard();
            self.finished = true;
            return Ok(CacheFinishOutcome::Skipped);
        };
        if SystemTime::now() >= expires_at {
            self.discard();
            self.finished = true;
            return Ok(CacheFinishOutcome::Skipped);
        }

        let hash = self.hasher.finalize();
        let content_hash = hash.to_hex().to_string();
        let key_id = self.key.entry_id().to_string();
        let random_id = blake3::hash(uuid::Uuid::new_v4().as_bytes())
            .to_hex()
            .to_string();
        let body_id = format!("{}{}", &key_id[..4], &random_id[4..]);
        let final_path = self.state.body_path(&body_id);
        let shard_dir = final_path
            .parent()
            .map(|path| path.to_path_buf())
            .ok_or_else(|| anyhow!("cache entry path missing parent"))?;

        // Move temp file to final path
        async_fs::create_dir_all(&shard_dir).await?;
        async_fs::rename(&self.temp_path, &final_path).await?;
        self.temp_path = final_path.clone();

        let entry = CacheEntry {
            id: self.state.next_entry_id(),
            key_id: key_id.clone(),
            body_id: body_id.clone(),
            status,
            headers,
            vary: self.vary.clone(),
            response_time: timing.response_time,
            corrected_initial_age: timing.corrected_initial_age,
            expires_at,
            content_hash,
            content_length: self.current_size,
        };

        let persisted = entry.to_persisted(self.key.key_base());

        if let Err(err) = self.state.write_metadata_async(&key_id, &persisted).await {
            warn!("failed to write cache metadata: {}", err);
            async_fs::remove_file(self.state.body_path(&body_id))
                .await
                .ok();
            self.release_reserved_bytes();
            self.finished = true;
            return Ok(CacheFinishOutcome::Skipped);
        }

        let evicted = self
            .state
            .insert_entry(self.key.key_base().to_string(), entry);
        self.committed = true;
        trace!("stored cache entry for {}", self.key.key_base());

        self.state
            .remove_evicted_files_async(evicted, &key_id)
            .await;

        self.release_reserved_bytes();
        self.finished = true;
        Ok(CacheFinishOutcome::Stored)
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
        let requested = buf.len() as u64;
        if self
            .current_size
            .checked_add(requested)
            .is_none_or(|size| size > self.state.max_entry_size)
        {
            self.discard();
            return Poll::Ready(Ok(buf.len()));
        }
        if self.pending_reservation == 0 {
            if !self.state.try_reserve_in_flight(requested) {
                self.discard();
                return Poll::Ready(Ok(buf.len()));
            }
            self.reserved_bytes = self.reserved_bytes.saturating_add(requested);
            self.pending_reservation = requested;
        } else if self.pending_reservation != requested {
            // The previous asynchronous file operation was abandoned by its
            // caller. Drop this cache fill rather than attribute its result to
            // a different buffer.
            self.discard();
            return Poll::Ready(Ok(buf.len()));
        }

        // Write to file, then update hash/size with bytes actually written.
        let result = Pin::new(self.file.as_mut().expect("active cache writer has a file"))
            .poll_write(cx, buf);
        match result {
            Poll::Ready(Ok(written)) => {
                let written = written as u64;
                let unwritten = self.pending_reservation - written;
                self.state.release_in_flight(unwritten);
                self.reserved_bytes -= unwritten;
                self.pending_reservation = 0;
                if written > 0 {
                    self.hasher.update(&buf[..written as usize]);
                    self.current_size = self.current_size.saturating_add(written);
                }
                Poll::Ready(Ok(written as usize))
            }
            Poll::Ready(Err(err)) => {
                self.state.release_in_flight(self.pending_reservation);
                self.reserved_bytes -= self.pending_reservation;
                self.pending_reservation = 0;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.file.as_mut() {
            Some(file) => Pin::new(file).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.file.as_mut() {
            Some(file) => Pin::new(file).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl Drop for CacheWriter {
    fn drop(&mut self) {
        if self.finished {
            self.release_reserved_bytes();
            return;
        }

        self.file.take();
        if !self.committed {
            if self.deferred_cleanup {
                remove_file_in_background(self.temp_path.clone());
            } else {
                let _ = std::fs::remove_file(&self.temp_path);
            }
        }
        self.release_reserved_bytes();
    }
}

fn remove_file_in_background(path: std::path::PathBuf) {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        drop(runtime.spawn(async move {
            let _ = async_fs::remove_file(path).await;
        }));
    } else {
        let _ = std::fs::remove_file(path);
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
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    fn build_state(dir: &TempDir) -> Arc<CacheState> {
        build_state_with_max_entry_size(dir, 1024 * 1024)
    }

    fn build_state_with_max_entry_size(dir: &TempDir, max_entry_size: u64) -> Arc<CacheState> {
        let capacity = NonZeroUsize::new(8).expect("nonzero capacity");
        let index = CacheIndex::new(capacity, 1024 * 1024);
        let store = CacheStore::new(dir.path().to_path_buf());
        Arc::new(CacheState {
            index: Mutex::new(index),
            publish_lock: Arc::new(tokio::sync::Mutex::new(())),
            store,
            max_entry_size,
            max_bytes: 1024 * 1024,
            in_flight_bytes: AtomicU64::new(0),
            next_id: AtomicU64::new(1),
            sweep_offset: std::sync::atomic::AtomicUsize::new(0),
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
        let response_time = SystemTime::now();
        writer
            .finish(
                StatusCode::OK,
                HeaderMap::new(),
                CacheTiming {
                    response_time,
                    corrected_initial_age: Duration::ZERO,
                    freshness_lifetime: Duration::from_secs(30),
                },
            )
            .await?;

        let meta_path = state.meta_path(key.entry_id());
        let meta_bytes = async_fs::read(&meta_path).await?;
        let persisted: PersistedEntry = serde_json::from_slice(&meta_bytes)?;

        assert_eq!(persisted.content_length, body.len() as u64);
        assert_eq!(
            persisted.content_hash,
            blake3::hash(body).to_hex().to_string()
        );

        let body_path = state.body_path(&persisted.body_id);
        let stored = async_fs::read(&body_path).await?;
        assert_eq!(stored, body);

        Ok(())
    }

    #[tokio::test]
    async fn cache_writer_discards_unrepresentable_expiration() -> Result<()> {
        let dir = TempDir::new()?;
        let state = build_state(&dir);
        let key = CacheKey::new(&Method::GET, &build_uri());
        let temp_path = state.store.temp_path("tmp_unrepresentable_ttl");

        let mut options = async_fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        let file = options.open(&temp_path).await?;
        let mut writer = CacheWriter::new(
            file,
            temp_path.clone(),
            state.clone(),
            key.clone(),
            VaryKey::new(HeaderMap::new()),
        );
        writer.write_all(b"body").await?;
        writer
            .finish(
                StatusCode::OK,
                HeaderMap::new(),
                CacheTiming {
                    response_time: SystemTime::now(),
                    corrected_initial_age: Duration::ZERO,
                    freshness_lifetime: Duration::MAX,
                },
            )
            .await?;

        assert!(!temp_path.exists());
        assert!(!state.meta_path(key.entry_id()).exists());
        Ok(())
    }

    #[tokio::test]
    async fn cache_writer_discards_entry_that_expired_while_streaming() -> Result<()> {
        let dir = TempDir::new()?;
        let state = build_state(&dir);
        let key = CacheKey::new(&Method::GET, &build_uri());
        let temp_path = state.store.temp_path("tmp_expired_while_streaming");

        let mut options = async_fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        let file = options.open(&temp_path).await?;
        let mut writer = CacheWriter::new(
            file,
            temp_path.clone(),
            state.clone(),
            key.clone(),
            VaryKey::new(HeaderMap::new()),
        );
        writer.write_all(b"body").await?;
        let outcome = writer
            .finish(
                StatusCode::OK,
                HeaderMap::new(),
                CacheTiming {
                    response_time: SystemTime::now() - Duration::from_secs(31),
                    corrected_initial_age: Duration::ZERO,
                    freshness_lifetime: Duration::from_secs(30),
                },
            )
            .await?;

        assert_eq!(outcome, CacheFinishOutcome::Skipped);
        assert!(!temp_path.exists());
        assert!(!state.meta_path(key.entry_id()).exists());
        Ok(())
    }

    #[tokio::test]
    async fn aggregate_in_flight_budget_discards_only_competing_fill() -> Result<()> {
        let dir = TempDir::new()?;
        let state = build_state_with_max_entry_size(&dir, 8);
        let key_a = CacheKey::new(&Method::GET, &build_uri());
        let key_b = CacheKey::new(&Method::GET, &"http://example.com:80/other".parse::<Uri>()?);
        let path_a = state.store.temp_path("tmp_budget_a");
        let path_b = state.store.temp_path("tmp_budget_b");
        let mut writer_a = CacheWriter::new(
            async_fs::File::create(&path_a).await?,
            path_a.clone(),
            state.clone(),
            key_a,
            VaryKey::new(HeaderMap::new()),
        );
        let mut writer_b = CacheWriter::new(
            async_fs::File::create(&path_b).await?,
            path_b.clone(),
            state.clone(),
            key_b,
            VaryKey::new(HeaderMap::new()),
        );

        writer_a.write_all(b"aaaaaa").await?;
        assert_eq!(state.in_flight_bytes(), 6);
        writer_b.write_all(b"bbbb").await?;

        assert_eq!(state.in_flight_bytes(), 6);
        assert!(path_a.exists());
        assert!(!path_b.exists());
        assert_eq!(
            writer_b
                .finish(
                    StatusCode::OK,
                    HeaderMap::new(),
                    CacheTiming {
                        response_time: SystemTime::now(),
                        corrected_initial_age: Duration::ZERO,
                        freshness_lifetime: Duration::from_secs(30),
                    },
                )
                .await?,
            CacheFinishOutcome::Skipped
        );

        drop(writer_a);
        assert_eq!(state.in_flight_bytes(), 0);
        assert!(!path_a.exists());
        Ok(())
    }

    #[tokio::test]
    async fn crossing_entry_limit_removes_partial_file_immediately() -> Result<()> {
        let dir = TempDir::new()?;
        let state = build_state_with_max_entry_size(&dir, 8);
        let key = CacheKey::new(&Method::GET, &build_uri());
        let temp_path = state.store.temp_path("tmp_entry_limit");
        let mut writer = CacheWriter::new(
            async_fs::File::create(&temp_path).await?,
            temp_path.clone(),
            state.clone(),
            key,
            VaryKey::new(HeaderMap::new()),
        );

        writer.write_all(b"aaaaaa").await?;
        assert_eq!(state.in_flight_bytes(), 6);
        writer.flush().await?;
        assert_eq!(std::fs::metadata(&temp_path)?.len(), 6);

        writer.write_all(b"bbbb").await?;
        assert_eq!(state.in_flight_bytes(), 0);
        assert!(!temp_path.exists());
        Ok(())
    }
}
