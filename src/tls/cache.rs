use std::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use lru::LruCache;
use parking_lot::Mutex;
use rustls::sign::CertifiedKey;
use time::OffsetDateTime;
use tracing::trace;

use super::ca::MintedLeaf;

#[derive(Clone)]
pub struct CertificateCache {
    inner: Arc<Mutex<LruCache<String, CachedEntry>>>,
}

struct CachedEntry {
    key: Arc<CertifiedKey>,
    expires_at: OffsetDateTime,
}

impl CertificateCache {
    pub fn new(capacity: usize) -> Result<Self> {
        let capacity = NonZeroUsize::new(capacity)
            .ok_or_else(|| anyhow!("leaf cache capacity must be greater than zero"))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(LruCache::new(capacity))),
        })
    }

    pub fn get(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        let mut cache = self.inner.lock();
        let now = OffsetDateTime::now_utc();
        let mut expired = false;
        let key = match cache.get(name) {
            Some(entry) if entry.expires_at > now => Some(entry.key.clone()),
            Some(_) => {
                expired = true;
                None
            }
            None => None,
        };
        if expired {
            cache.pop(name);
        }
        if key.is_some() {
            trace!(name, "leaf certificate cache hit");
        }
        key
    }

    pub fn insert(&self, name: String, minted: MintedLeaf) -> Arc<CertifiedKey> {
        let key = minted.certified_key.clone();
        self.inner.lock().put(
            name,
            CachedEntry {
                key: key.clone(),
                expires_at: minted.expires_at,
            },
        );
        key
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ca::CertificateAuthority;
    use std::time::Duration;
    use tempfile::TempDir;

    fn mint(ca: &CertificateAuthority, name: &str) -> Result<MintedLeaf> {
        ca.mint_leaf(&[name], Duration::from_secs(3600))
    }

    #[test]
    fn cache_hits_memory() -> Result<()> {
        let dir = TempDir::new()?;
        let ca = CertificateAuthority::load_or_generate(dir.path())?;
        let cache = CertificateCache::new(16)?;
        let name = "example.com";

        assert!(cache.get(name).is_none());
        let inserted = cache.insert(name.to_string(), mint(&ca, name)?);
        let cached = cache.get(name).expect("cached leaf");
        assert!(Arc::ptr_eq(&inserted, &cached));
        Ok(())
    }

    #[test]
    fn cache_evicts_least_recently_used_entry() -> Result<()> {
        let dir = TempDir::new()?;
        let ca = CertificateAuthority::load_or_generate(dir.path())?;
        let cache = CertificateCache::new(2)?;

        cache.insert("one.example".to_string(), mint(&ca, "one.example")?);
        cache.insert("two.example".to_string(), mint(&ca, "two.example")?);
        assert!(cache.get("one.example").is_some());
        cache.insert("three.example".to_string(), mint(&ca, "three.example")?);

        assert!(cache.get("one.example").is_some());
        assert!(cache.get("two.example").is_none());
        assert!(cache.get("three.example").is_some());
        assert_eq!(cache.len(), 2);
        Ok(())
    }

    #[test]
    fn cache_removes_expired_entry() -> Result<()> {
        let dir = TempDir::new()?;
        let ca = CertificateAuthority::load_or_generate(dir.path())?;
        let cache = CertificateCache::new(2)?;
        let mut minted = mint(&ca, "expired.example")?;
        minted.expires_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        cache.insert("expired.example".to_string(), minted);

        assert!(cache.get("expired.example").is_none());
        assert_eq!(cache.len(), 0);
        Ok(())
    }

    #[test]
    fn cache_rejects_zero_capacity() {
        let err = CertificateCache::new(0).err().expect("zero must fail");
        assert!(err.to_string().contains("greater than zero"));
    }
}
