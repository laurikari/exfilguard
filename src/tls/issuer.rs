use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::{Result, ensure};
use rustls::sign::CertifiedKey;

use super::{ca::CertificateAuthority, cache::CertificateCache};

/// Issues (and caches) leaf certificates for inbound TLS handshakes.
#[derive(Clone)]
pub struct TlsIssuer {
    ca: Arc<CertificateAuthority>,
    cache: Arc<CertificateCache>,
    ttl: StdDuration,
}

impl TlsIssuer {
    pub fn new(
        ca: Arc<CertificateAuthority>,
        cache: Arc<CertificateCache>,
        ttl: StdDuration,
    ) -> Result<Self> {
        ensure!(ttl > StdDuration::from_secs(0), "leaf ttl must be positive");
        Ok(Self { ca, cache, ttl })
    }

    /// Returns a `CertifiedKey` covering the provided hostnames.
    /// `names` must contain at least one entry (the SNI hostname), with additional SANs optional.
    pub fn issue(&self, names: &[&str]) -> Result<Arc<CertifiedKey>> {
        ensure!(!names.is_empty(), "at least one hostname required");
        let key = cache_key(names);
        self.cache
            .get_or_mint(&key, || self.ca.mint_leaf(names, self.ttl))
    }
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
    use std::time::Duration as StdDuration;
    use tempfile::TempDir;

    #[test]
    fn issues_and_caches_single_name() -> Result<()> {
        let ca_dir = TempDir::new()?;
        let ca = Arc::new(CertificateAuthority::load_or_generate(ca_dir.path())?);
        let cache = Arc::new(CertificateCache::new(16, None)?);
        let issuer = TlsIssuer::new(ca, cache, StdDuration::from_secs(3600))?;

        let first = issuer.issue(&["example.com"])?;
        let second = issuer.issue(&["example.com"])?;
        assert!(Arc::ptr_eq(&first, &second));
        Ok(())
    }

    #[test]
    fn multi_name_key_is_order_insensitive() -> Result<()> {
        let ca_dir = TempDir::new()?;
        let ca = Arc::new(CertificateAuthority::load_or_generate(ca_dir.path())?);
        let cache = Arc::new(CertificateCache::new(16, None)?);
        let issuer = TlsIssuer::new(ca, cache, StdDuration::from_secs(3600))?;

        let first = issuer.issue(&["a.example", "b.example"])?;
        let second = issuer.issue(&["b.example", "a.example"])?;
        assert!(Arc::ptr_eq(&first, &second));
        Ok(())
    }

    #[test]
    fn rejects_empty_names() {
        let ca_dir = TempDir::new().unwrap();
        let ca = Arc::new(CertificateAuthority::load_or_generate(ca_dir.path()).unwrap());
        let cache = Arc::new(CertificateCache::new(16, None).unwrap());
        let issuer = TlsIssuer::new(ca, cache, StdDuration::from_secs(3600)).unwrap();
        let err = issuer.issue(&[]).unwrap_err();
        assert!(err.to_string().contains("hostname"));
    }
}
