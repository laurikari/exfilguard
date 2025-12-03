use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::num::NonZeroUsize;
// Windows support is out of scope; use the Unix-specific OpenOptions extension
// to manage on-disk key permissions.
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use lru::LruCache;
use parking_lot::Mutex;
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use time::OffsetDateTime;
use tracing::{trace, warn};
use zeroize::Zeroizing;

use super::ca::MintedLeaf;

#[derive(Clone)]
pub struct CertificateCache {
    inner: Arc<Mutex<LruCache<String, CachedEntry>>>,
    disk_dir: Option<PathBuf>,
}

struct CachedEntry {
    key: Arc<CertifiedKey>,
    expires_at: OffsetDateTime,
}

impl CertificateCache {
    pub fn new(capacity: usize, disk_dir: Option<PathBuf>) -> Result<Self> {
        let capacity = NonZeroUsize::new(capacity)
            .ok_or_else(|| anyhow!("certificate cache capacity must be greater than zero"))?;
        if let Some(dir) = disk_dir.as_ref() {
            fs::create_dir_all(dir).with_context(|| {
                format!("failed to create certificate cache dir {}", dir.display())
            })?;
        }
        let cache = LruCache::new(capacity);
        Ok(Self {
            inner: Arc::new(Mutex::new(cache)),
            disk_dir,
        })
    }

    pub fn get_or_mint<F>(&self, name: &str, mint: F) -> Result<Arc<CertifiedKey>>
    where
        F: FnOnce() -> Result<MintedLeaf>,
    {
        if let Some(key) = self.get_from_memory(name) {
            trace!(name, "cache hit (memory)");
            return Ok(key);
        }

        if let Some(entry) = self.load_from_disk(name)? {
            trace!(name, "cache hit (disk)");
            let key = entry.key.clone();
            self.insert_memory(name, entry);
            return Ok(key);
        }

        trace!(name, "cache miss; minting new leaf certificate");
        let minted = mint()?;
        if let Some(paths) = self.disk_paths(name)
            && let Err(err) = persist_to_disk(&paths, name, &minted)
        {
            warn!(name, error = %err, "failed to persist leaf certificate to disk");
        }
        let entry = CachedEntry {
            key: minted.certified_key.clone(),
            expires_at: minted.expires_at,
        };
        let key = entry.key.clone();
        self.insert_memory(name, entry);
        Ok(key)
    }

    fn get_from_memory(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        let mut cache = self.inner.lock();
        let now = OffsetDateTime::now_utc();
        let mut remove = false;
        let result = match cache.get_mut(name) {
            Some(entry) if entry.expires_at > now => Some(entry.key.clone()),
            Some(_) => {
                remove = true;
                None
            }
            None => None,
        };
        if remove {
            cache.pop(name);
        }
        result
    }

    fn insert_memory(&self, name: &str, entry: CachedEntry) {
        let mut cache = self.inner.lock();
        cache.put(name.to_string(), entry);
    }

    fn load_from_disk(&self, name: &str) -> Result<Option<CachedEntry>> {
        let Some(paths) = self.disk_paths(name) else {
            return Ok(None);
        };

        let meta_text = match fs::read_to_string(&paths.meta) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                warn!(
                    name,
                    error = %err,
                    "failed to read certificate cache metadata; purging entry"
                );
                let _ = remove_disk_entry(&paths);
                return Ok(None);
            }
        };

        let meta = match parse_meta(&meta_text) {
            Ok(meta) => meta,
            Err(err) => {
                warn!(name, error = %err, "failed to parse certificate cache metadata; purging entry");
                let _ = remove_disk_entry(&paths);
                return Ok(None);
            }
        };
        if meta.host != name {
            warn!(
                name,
                disk_host = meta.host,
                "cache metadata host mismatch; purging entry"
            );
            let _ = remove_disk_entry(&paths);
            return Ok(None);
        }

        let expires_at = meta.expires_at;
        let now = OffsetDateTime::now_utc();
        if expires_at <= now {
            trace!(name, "cached certificate expired on disk; removing");
            let _ = remove_disk_entry(&paths);
            return Ok(None);
        }

        let chain_bytes = match read_chain_file(&paths.chain) {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(name, error = %err, "failed to read cached certificate chain; purging entry");
                let _ = remove_disk_entry(&paths);
                return Ok(None);
            }
        };

        let private_key = match fs::read(&paths.key) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(err) => {
                warn!(
                    name,
                    error = %err,
                    "failed to read cached private key; purging entry"
                );
                let _ = remove_disk_entry(&paths);
                return Ok(None);
            }
        };

        let key_der = match PrivateKeyDer::try_from(private_key.to_vec()) {
            Ok(key) => key,
            Err(err) => {
                warn!(
                    name,
                    error = %err,
                    "failed to parse cached private key; purging entry"
                );
                let _ = remove_disk_entry(&paths);
                return Ok(None);
            }
        };

        let cert_chain: Vec<_> = chain_bytes.into_iter().map(CertificateDer::from).collect();

        let provider = ring::default_provider();
        let certified_key = CertifiedKey::from_der(cert_chain, key_der, &provider)
            .map_err(|err| anyhow!("failed to rebuild cached certified key: {err}"))?;

        Ok(Some(CachedEntry {
            key: Arc::new(certified_key),
            expires_at,
        }))
    }

    fn disk_paths(&self, name: &str) -> Option<DiskPaths> {
        let base = self.disk_dir.as_ref()?;
        let HashedLocation { shard_path, hex } = hashed_name(name);
        let dir = base.join(&shard_path);
        Some(DiskPaths {
            dir: dir.clone(),
            chain: dir.join(format!("{hex}.chain")),
            key: dir.join(format!("{hex}.key")),
            meta: dir.join(format!("{hex}.meta")),
        })
    }
}

struct DiskPaths {
    dir: PathBuf,
    chain: PathBuf,
    key: PathBuf,
    meta: PathBuf,
}

fn persist_to_disk(paths: &DiskPaths, host: &str, minted: &MintedLeaf) -> Result<()> {
    fs::create_dir_all(&paths.dir).with_context(|| {
        format!(
            "failed to create certificate cache shard directory {}",
            paths.dir.display()
        )
    })?;
    write_chain_file(&paths.chain, &minted.chain_der)?;
    write_private_key(&paths.key, minted.private_key_der.as_slice())?;
    write_meta(&paths.meta, host, minted.expires_at)?;
    Ok(())
}

fn write_chain_file(path: &Path, chain: &[Vec<u8>]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to write certificate chain {}", path.display()))?;
    let count: u32 = chain
        .len()
        .try_into()
        .map_err(|_| anyhow!("certificate chain too large to persist"))?;
    file.write_all(&count.to_be_bytes())?;
    for cert in chain {
        let len: u32 = cert
            .len()
            .try_into()
            .map_err(|_| anyhow!("certificate entry too large to persist"))?;
        file.write_all(&len.to_be_bytes())?;
        file.write_all(cert)?;
    }
    file.flush()?;
    Ok(())
}

fn read_chain_file(path: &Path) -> Result<Vec<Vec<u8>>> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open cached certificate chain {}", path.display()))?;
    let mut count_buf = [0u8; 4];
    file.read_exact(&mut count_buf)?;
    let count = u32::from_be_bytes(count_buf);
    let mut chain = Vec::with_capacity(count as usize);
    for _ in 0..count {
        file.read_exact(&mut count_buf)?;
        let len = u32::from_be_bytes(count_buf) as usize;
        let mut cert = vec![0u8; len];
        file.read_exact(&mut cert)?;
        chain.push(cert);
    }
    Ok(chain)
}

fn write_private_key(path: &Path, key: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    options.mode(0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to write cached key {}", path.display()))?;
    file.write_all(key)?;
    file.flush()?;
    Ok(())
}

fn write_meta(path: &Path, host: &str, expires_at: OffsetDateTime) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    options.mode(0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to write cache metadata {}", path.display()))?;
    let content = format!(
        "version=2\nhost={}\nexpires_at={}\n",
        host,
        expires_at.unix_timestamp()
    );
    file.write_all(content.as_bytes())?;
    file.flush()?;
    Ok(())
}

struct MetaInfo {
    host: String,
    expires_at: OffsetDateTime,
}

fn parse_meta(meta: &str) -> Result<MetaInfo> {
    let mut host: Option<String> = None;
    let mut expires: Option<i64> = None;
    for line in meta.lines() {
        if let Some(value) = line.strip_prefix("host=") {
            host = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("expires_at=") {
            let ts: i64 = value
                .parse()
                .map_err(|err| anyhow!("invalid expiration timestamp: {err}"))?;
            expires = Some(ts);
        }
    }
    let host = host.ok_or_else(|| anyhow!("cache metadata missing host"))?;
    let expires = expires.ok_or_else(|| anyhow!("cache metadata missing expiration"))?;
    let expires_at = OffsetDateTime::from_unix_timestamp(expires).map_err(|err| anyhow!(err))?;
    Ok(MetaInfo { host, expires_at })
}

fn remove_disk_entry(paths: &DiskPaths) -> Result<()> {
    let _ = fs::remove_file(&paths.chain);
    let _ = fs::remove_file(&paths.key);
    let _ = fs::remove_file(&paths.meta);
    let _ = fs::remove_dir(&paths.dir);
    if let Some(parent) = paths.dir.parent() {
        let _ = fs::remove_dir(parent);
        if let Some(grand) = parent.parent() {
            let _ = fs::remove_dir(grand);
        }
    }
    Ok(())
}

struct HashedLocation {
    shard_path: PathBuf,
    hex: String,
}

fn hashed_name(name: &str) -> HashedLocation {
    let digest = blake3::hash(name.as_bytes());
    let hex = digest.to_hex().to_string();
    let (first, remainder) = hex.split_at(2);
    let (second, _) = remainder.split_at(2);
    let mut shard_path = PathBuf::new();
    shard_path.push(first);
    shard_path.push(second);
    HashedLocation { shard_path, hex }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ca::CertificateAuthority;
    use std::time::Duration as StdDuration;
    use tempfile::TempDir;
    use time::Duration;

    #[test]
    fn cache_hits_memory() -> Result<()> {
        let dir = TempDir::new()?;
        let ca = CertificateAuthority::load_or_generate(dir.path())?;
        let cache = CertificateCache::new(16, None)?;
        let name = "example.com";
        let ttl = StdDuration::from_secs(3600);
        let key = cache.get_or_mint(name, || ca.mint_leaf(&[name], ttl))?;
        let key2 = cache.get_or_mint(name, || ca.mint_leaf(&[name], ttl))?;
        assert_eq!(key.cert.len(), key2.cert.len());
        for (first, second) in key.cert.iter().zip(key2.cert.iter()) {
            assert_eq!(first.as_ref(), second.as_ref());
        }
        Ok(())
    }

    #[test]
    fn cache_persists_to_disk() -> Result<()> {
        let ca_dir = TempDir::new()?;
        let cache_dir = TempDir::new()?;
        let ca = CertificateAuthority::load_or_generate(ca_dir.path())?;
        let cache = CertificateCache::new(16, Some(cache_dir.path().to_path_buf()))?;
        let name = "persist.example";
        let ttl = StdDuration::from_secs(3600);

        let key = cache.get_or_mint(name, || ca.mint_leaf(&[name], ttl))?;
        drop(cache);

        let cache = CertificateCache::new(16, Some(cache_dir.path().to_path_buf()))?;
        let key2 = cache.get_or_mint(name, || ca.mint_leaf(&[name], ttl))?;
        assert_eq!(key.cert.len(), key2.cert.len());
        for (first, second) in key.cert.iter().zip(key2.cert.iter()) {
            assert_eq!(first.as_ref(), second.as_ref());
        }
        Ok(())
    }

    #[test]
    fn cache_ignores_expired_disk_entries() -> Result<()> {
        let ca_dir = TempDir::new()?;
        let cache_dir = TempDir::new()?;
        let ca = CertificateAuthority::load_or_generate(ca_dir.path())?;
        let cache = CertificateCache::new(16, Some(cache_dir.path().to_path_buf()))?;
        let name = "expired.example";
        let ttl = StdDuration::from_secs(1);

        let _ = cache.get_or_mint(name, || ca.mint_leaf(&[name], ttl))?;

        // Manually overwrite metadata to simulate expiration in the past.
        if let Some(paths) = cache.disk_paths(name) {
            write_meta(
                &paths.meta,
                name,
                OffsetDateTime::now_utc() - Duration::hours(1),
            )?;
        }

        let key = cache.get_or_mint(name, || ca.mint_leaf(&[name], StdDuration::from_secs(2)))?;
        let key2 = cache.get_or_mint(name, || ca.mint_leaf(&[name], StdDuration::from_secs(2)))?;
        assert!(Arc::ptr_eq(&key, &key2));
        Ok(())
    }

    #[test]
    fn cache_rejects_host_mismatch() -> Result<()> {
        let ca_dir = TempDir::new()?;
        let cache_dir = TempDir::new()?;
        let ca = CertificateAuthority::load_or_generate(ca_dir.path())?;
        let cache = CertificateCache::new(16, Some(cache_dir.path().to_path_buf()))?;
        let name = "host-mismatch.example";
        let ttl = StdDuration::from_secs(3600);

        let _ = cache.get_or_mint(name, || ca.mint_leaf(&[name], ttl))?;
        drop(cache);

        let cache = CertificateCache::new(16, Some(cache_dir.path().to_path_buf()))?;
        if let Some(paths) = cache.disk_paths(name) {
            write_meta(
                &paths.meta,
                "other.example",
                OffsetDateTime::now_utc() + Duration::hours(1),
            )?;
        }
        drop(cache);

        let cache = CertificateCache::new(16, Some(cache_dir.path().to_path_buf()))?;
        let _ = cache.get_or_mint(name, || ca.mint_leaf(&[name], ttl))?;
        if let Some(paths) = cache.disk_paths(name) {
            let meta = std::fs::read_to_string(&paths.meta)?;
            let parsed = parse_meta(&meta)?;
            assert_eq!(parsed.host, name);
        } else {
            panic!("expected cache metadata to exist");
        }
        Ok(())
    }
}
