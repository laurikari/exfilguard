use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use http::{HeaderMap, Method, StatusCode, Uri};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;

use super::{CacheKey, CacheTiming, HttpCache};

// With one blocking worker, holding it makes filesystem completion explicit
// without depending on disk speed. Drop releases it even if an assertion fails.
struct FileWorkerGate(Option<std::sync::mpsc::Sender<()>>);

impl FileWorkerGate {
    async fn hold() -> Self {
        let (release, wait) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            let _ = wait.recv();
        });
        ready.await.unwrap();
        Self(Some(release))
    }
}

impl Drop for FileWorkerGate {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.send(());
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap()
}

async fn cache(dir: &TempDir) -> Result<HttpCache> {
    HttpCache::new(8, dir.path().to_path_buf(), 1024, 8192, Duration::ZERO, 0).await
}

fn files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                dirs.push(entry.path());
            } else {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    files
}

#[test]
fn timed_out_creation_removes_the_late_file() -> Result<()> {
    runtime().block_on(async {
        let dir = TempDir::new()?;
        let cache = cache(&dir).await?;
        let uri: Uri = "http://example.com/test".parse()?;
        let headers = HeaderMap::new();
        let gate = FileWorkerGate::hold().await;
        let result = tokio::time::timeout(
            Duration::from_millis(10),
            cache.open_stream(&Method::GET, &uri, &headers, &headers),
        )
        .await;
        assert!(result.is_err());
        drop(gate);
        // The creation job, including destruction of its abandoned result,
        // finishes before this next job on the same worker.
        tokio::task::spawn_blocking(|| {}).await?;
        assert!(files(dir.path()).is_empty());
        Ok(())
    })
}

#[test]
fn timed_out_publication_waiters_do_not_accumulate() -> Result<()> {
    runtime().block_on(async {
        let dir = TempDir::new()?;
        let cache = cache(&dir).await?;
        let uri: Uri = "http://example.com/test".parse()?;
        let headers = HeaderMap::new();
        // Model an earlier publication stalled while holding the shared lock.
        let guard = cache.state.publish_lock().lock().await;
        for body in [b"".as_slice(), b"response body".as_slice()] {
            for _ in 0..8 {
                let mut writer = cache
                    .open_stream(&Method::GET, &uri, &headers, &headers)
                    .await?
                    .unwrap();
                writer.write_all(body).await?;
                writer.flush().await?;
                writer.defer_cleanup();
                let result = tokio::time::timeout(
                    Duration::from_millis(10),
                    writer.finish(
                        StatusCode::OK,
                        headers.clone(),
                        CacheTiming {
                            response_time: SystemTime::now(),
                            corrected_initial_age: Duration::ZERO,
                            freshness_lifetime: Duration::from_secs(30),
                        },
                    ),
                )
                .await;
                assert!(result.is_err());
                // Let deferred cleanup finish while publication remains blocked.
                tokio::task::yield_now().await;
                tokio::task::spawn_blocking(|| {}).await?;
                assert!(files(dir.path()).is_empty());
                assert_eq!(cache.state.in_flight_bytes.load(Ordering::SeqCst), 0);
                assert_eq!(std::sync::Arc::strong_count(&cache.state), 1);
            }
        }
        drop(guard);
        assert!(cache.lookup(&Method::GET, &uri, &headers).await.is_none());
        Ok(())
    })
}

#[test]
fn timed_out_publication_retains_ownership_until_stored_or_cleaned_up() -> Result<()> {
    for fail in [false, true] {
        runtime().block_on(async {
            let dir = TempDir::new()?;
            let cache = cache(&dir).await?;
            let uri: Uri = "http://example.com/test".parse()?;
            let headers = HeaderMap::new();
            let mut writer = cache
                .open_stream(&Method::GET, &uri, &headers, &headers)
                .await?
                .unwrap();
            let body = b"response body";
            writer.write_all(body).await?;
            writer.flush().await?;
            writer.defer_cleanup();
            let blocker = cache
                .state
                .store
                .disk_dir()
                .join(&CacheKey::new(&Method::GET, &uri).entry_id()[..2]);
            if fail {
                // A file where publication needs a shard directory forces a
                // filesystem error after the caller has already timed out.
                std::fs::write(&blocker, b"not a directory")?;
            }
            let gate = FileWorkerGate::hold().await;
            let result = tokio::time::timeout(
                Duration::from_millis(10),
                writer.finish(
                    StatusCode::OK,
                    headers.clone(),
                    CacheTiming {
                        response_time: SystemTime::now(),
                        corrected_initial_age: Duration::ZERO,
                        freshness_lifetime: Duration::from_secs(30),
                    },
                ),
            )
            .await;
            assert!(result.is_err());
            assert_eq!(
                cache.state.in_flight_bytes.load(Ordering::SeqCst),
                body.len() as u64,
                "publication must retain its staging reservation after timeout"
            );
            drop(gate);
            tokio::time::timeout(Duration::from_secs(3), async {
                while cache.state.in_flight_bytes.load(Ordering::SeqCst) != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            // Drain deferred cleanup as well as the publication itself.
            tokio::task::yield_now().await;
            tokio::task::spawn_blocking(|| {}).await?;
            let cached = cache.lookup(&Method::GET, &uri, &headers).await;
            if fail {
                assert!(cached.is_none());
                assert_eq!(files(dir.path()), vec![blocker]);
            } else {
                let cached = cached.expect("publication should finish after timeout");
                assert_eq!(std::fs::read(&cached.body_path)?, body);
                assert_eq!(files(dir.path()).len(), 2, "only body and metadata remain");
            }
            Ok::<_, anyhow::Error>(())
        })?;
    }
    Ok(())
}
