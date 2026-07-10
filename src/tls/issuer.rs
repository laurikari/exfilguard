use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration as StdDuration;

use anyhow::{Context, Result, anyhow, ensure};
use parking_lot::Mutex;
use rustls::sign::CertifiedKey;
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

use super::{ca::CertificateAuthority, cache::CertificateCache};

type KeyLock = AsyncMutex<()>;
type FlightMap = Mutex<HashMap<String, Weak<KeyLock>>>;

/// Issues and memory-caches leaf certificates for inbound TLS handshakes.
#[derive(Clone)]
pub struct TlsIssuer {
    ca: Arc<CertificateAuthority>,
    cache: Arc<CertificateCache>,
    ttl: StdDuration,
    mint_permits: Arc<Semaphore>,
    flights: Arc<FlightMap>,
}

struct FlightRegistration {
    key: String,
    lock: Arc<KeyLock>,
    flights: Arc<FlightMap>,
}

impl FlightRegistration {
    fn acquire(key: String, flights: Arc<FlightMap>) -> Self {
        let lock = {
            let mut entries = flights.lock();
            if let Some(lock) = entries.get(&key).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(KeyLock::new(()));
                entries.insert(key.clone(), Arc::downgrade(&lock));
                lock
            }
        };
        Self { key, lock, flights }
    }
}

impl Drop for FlightRegistration {
    fn drop(&mut self) {
        let mut entries = self.flights.lock();
        if Arc::strong_count(&self.lock) == 1
            && entries
                .get(&self.key)
                .is_some_and(|entry| Weak::ptr_eq(entry, &Arc::downgrade(&self.lock)))
        {
            entries.remove(&self.key);
        }
    }
}

impl TlsIssuer {
    pub fn new(
        ca: Arc<CertificateAuthority>,
        cache: Arc<CertificateCache>,
        ttl: StdDuration,
        mint_concurrency: usize,
    ) -> Result<Self> {
        ensure!(ttl > StdDuration::from_secs(0), "leaf ttl must be positive");
        ensure!(
            mint_concurrency > 0,
            "leaf mint concurrency must be greater than zero"
        );
        Ok(Self {
            ca,
            cache,
            ttl,
            mint_permits: Arc::new(Semaphore::new(mint_concurrency)),
            flights: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Returns a `CertifiedKey` covering the provided hostnames.
    /// `names` must contain at least one entry (the SNI hostname), with additional SANs optional.
    pub async fn issue(&self, names: &[&str]) -> Result<Arc<CertifiedKey>> {
        ensure!(!names.is_empty(), "at least one hostname required");
        let key = cache_key(names);
        if let Some(cached) = self.cache.get(&key) {
            return Ok(cached);
        }

        let flight = FlightRegistration::acquire(key.clone(), self.flights.clone());
        let _key_guard = flight.lock.lock().await;
        if let Some(cached) = self.cache.get(&key) {
            return Ok(cached);
        }

        let ca = self.ca.clone();
        let ttl = self.ttl;
        let owned_names: Vec<String> = names.iter().map(|name| (*name).to_string()).collect();
        let minted = run_blocking_limited(self.mint_permits.clone(), move || {
            let names: Vec<&str> = owned_names.iter().map(String::as_str).collect();
            ca.mint_leaf(&names, ttl)
        })
        .await?;
        Ok(self.cache.insert(key, minted))
    }
}

async fn run_blocking_limited<T, F>(permits: Arc<Semaphore>, task: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let permit = permits
        .acquire_owned()
        .await
        .map_err(|_| anyhow!("leaf mint admission closed"))?;
    tokio::task::spawn_blocking(move || run_with_permit(permit, task))
        .await
        .context("leaf mint worker failed")?
}

fn run_with_permit<T, F>(_permit: OwnedSemaphorePermit, task: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    task()
}

fn cache_key(names: &[&str]) -> String {
    if names.len() == 1 {
        return names[0].to_ascii_lowercase();
    }
    let mut items: Vec<String> = names.iter().map(|name| name.to_ascii_lowercase()).collect();
    items.sort();
    items.dedup();
    items.join("|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{ca::CertificateAuthority, cache::CertificateCache};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;
    use tokio::sync::Barrier;

    fn issuer(capacity: usize, mint_concurrency: usize) -> Result<TlsIssuer> {
        let ca_dir = TempDir::new()?;
        let ca = Arc::new(CertificateAuthority::load_or_generate(ca_dir.path())?);
        let cache = Arc::new(CertificateCache::new(capacity)?);
        TlsIssuer::new(ca, cache, StdDuration::from_secs(3600), mint_concurrency)
    }

    #[tokio::test]
    async fn issues_and_caches_single_name() -> Result<()> {
        let issuer = issuer(16, 2)?;
        let first = issuer.issue(&["example.com"]).await?;
        let second = issuer.issue(&["example.com"]).await?;
        assert!(Arc::ptr_eq(&first, &second));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_same_name_requests_share_one_leaf() -> Result<()> {
        let issuer = issuer(16, 4)?;
        let barrier = Arc::new(Barrier::new(33));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let issuer = issuer.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                issuer.issue(&["same.example"]).await
            }));
        }
        barrier.wait().await;

        let mut issued = Vec::new();
        for task in tasks {
            issued.push(task.await??);
        }
        for key in &issued[1..] {
            assert!(Arc::ptr_eq(&issued[0], key));
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn blocking_work_respects_global_concurrency() -> Result<()> {
        let permits = Arc::new(Semaphore::new(2));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();

        for _ in 0..12 {
            let permits = permits.clone();
            let active = active.clone();
            let maximum = maximum.clone();
            tasks.push(tokio::spawn(async move {
                run_blocking_limited(permits, move || {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(current, Ordering::SeqCst);
                    std::thread::sleep(StdDuration::from_millis(10));
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
            }));
        }
        for task in tasks {
            task.await??;
        }

        assert_eq!(maximum.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_admission_wait_recovers_permit() -> Result<()> {
        let permits = Arc::new(Semaphore::new(1));
        let active = Arc::new(AtomicUsize::new(0));
        let first_active = active.clone();
        let first = tokio::spawn(run_blocking_limited(permits.clone(), move || {
            first_active.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(StdDuration::from_millis(100));
            first_active.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }));
        while active.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }

        let waiting = run_blocking_limited(permits.clone(), || Ok(()));
        assert!(
            tokio::time::timeout(StdDuration::from_millis(10), waiting)
                .await
                .is_err()
        );
        first.await??;

        run_blocking_limited(permits, || Ok(())).await?;
        assert_eq!(active.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_empty_names() {
        let issuer = issuer(16, 2).unwrap();
        let err = issuer.issue(&[]).await.unwrap_err();
        assert!(err.to_string().contains("hostname"));
    }

    #[test]
    fn rejects_invalid_limits() {
        let ca_dir = TempDir::new().unwrap();
        let ca = Arc::new(CertificateAuthority::load_or_generate(ca_dir.path()).unwrap());
        let cache = Arc::new(CertificateCache::new(16).unwrap());
        let err = TlsIssuer::new(ca, cache, StdDuration::from_secs(3600), 0)
            .err()
            .expect("zero concurrency must fail");
        assert!(err.to_string().contains("greater than zero"));
    }
}
