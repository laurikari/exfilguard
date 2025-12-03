use std::convert::TryInto;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write};
// ExfilGuard only targets Unix-like hosts, so we rely on the Unix-specific
// OpenOptions extension traits to enforce filesystem permissions.
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use rand::{RngCore, rngs::OsRng};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SerialNumber,
};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use time::{Duration, OffsetDateTime};
use tracing::info;
use zeroize::Zeroizing;

const ROOT_CERT_FILE: &str = "root.crt";
const ROOT_KEY_FILE: &str = "root.key";
const INTERMEDIATE_CERT_FILE: &str = "intermediate.crt";
const INTERMEDIATE_KEY_FILE: &str = "intermediate.key";
const ROOT_VALIDITY_YEARS: i64 = 10;
const INTERMEDIATE_VALIDITY_YEARS: i64 = 1;

/// Handles lifecycle management for the root and intermediate certificate authority.
#[derive(Clone)]
pub struct CertificateAuthority {
    root_cert: Arc<Vec<u8>>,
    intermediate_cert: Arc<Vec<u8>>,
    intermediate_key: Arc<KeyPair>,
    intermediate_params: Arc<CertificateParams>,
}

impl CertificateAuthority {
    /// Load existing CA material from `ca_dir`, generating a new root and intermediate if none
    /// exists yet. When generating, the material is written to disk before being returned.
    pub fn load_or_generate<P: AsRef<Path>>(ca_dir: P) -> Result<Self> {
        let ca_dir = ca_dir.as_ref();
        fs::create_dir_all(ca_dir)
            .with_context(|| format!("failed to create CA directory {}", ca_dir.display()))?;

        let paths = CaPaths::new(ca_dir);
        let existing = [
            paths.root_cert.exists(),
            paths.root_key.exists(),
            paths.intermediate_cert.exists(),
            paths.intermediate_key.exists(),
        ];
        let present = existing.iter().filter(|present| **present).count();

        match present {
            0 => Self::generate(&paths),
            4 => Self::load_existing(&paths),
            _ => bail!(
                "incomplete CA material detected in {}; expected {}, {}, {}, {}",
                ca_dir.display(),
                ROOT_CERT_FILE,
                ROOT_KEY_FILE,
                INTERMEDIATE_CERT_FILE,
                INTERMEDIATE_KEY_FILE
            ),
        }
    }

    fn generate(paths: &CaPaths) -> Result<Self> {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|err| anyhow!("failed to generate root key: {err}"))?;
        let root_params = build_root_params();
        let root_cert = root_params
            .self_signed(&root_key)
            .map_err(|err| anyhow!("failed to self-sign root certificate: {err}"))?;

        let intermediate_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|err| anyhow!("failed to generate intermediate key: {err}"))?;
        let intermediate_params = build_intermediate_params();
        let root_issuer = rcgen::Issuer::from_params(&root_params, &root_key);
        let intermediate_cert =
            sign_certificate(&intermediate_params, &intermediate_key, &root_issuer)?;

        let root_cert_pem = root_cert.pem();
        let root_key_pem = Zeroizing::new(root_key.serialize_pem());
        let intermediate_cert_pem = intermediate_cert.pem();
        let intermediate_key_pem = Zeroizing::new(intermediate_key.serialize_pem());

        write_pem_file(&paths.root_cert, &root_cert_pem, false)?;
        write_pem_file(&paths.root_key, root_key_pem.as_str(), true)?;
        write_pem_file(&paths.intermediate_cert, &intermediate_cert_pem, false)?;
        write_pem_file(&paths.intermediate_key, intermediate_key_pem.as_str(), true)?;

        // Drop root key as soon as we've finished persisting it.
        drop(root_key);

        let root_der = root_cert.der().as_ref().to_vec();
        let intermediate_der = intermediate_cert.der().as_ref().to_vec();
        info!(
            directory = %paths.dir.display(),
            "generated new certificate authority material"
        );
        Self::from_material(
            root_der,
            intermediate_der,
            intermediate_params,
            intermediate_key,
        )
    }

    fn load_existing(paths: &CaPaths) -> Result<Self> {
        let root_der = read_certificate_der(&paths.root_cert)?;
        // Validate that the root key exists; we intentionally do not load it into memory.
        if !paths.root_key.exists() {
            bail!("expected root key at {}", paths.root_key.display());
        }

        let intermediate_der = read_certificate_der(&paths.intermediate_cert)?;
        let intermediate_params = build_intermediate_params();
        let intermediate_key_pem = Zeroizing::new(
            fs::read_to_string(&paths.intermediate_key).with_context(|| {
                format!(
                    "failed to read intermediate key from {}",
                    paths.intermediate_key.display()
                )
            })?,
        );
        let intermediate_key = KeyPair::from_pem(intermediate_key_pem.as_ref())
            .map_err(|err| anyhow!("failed to parse intermediate key: {err}"))?;

        info!(
            directory = %paths.dir.display(),
            "loaded existing certificate authority material"
        );
        Self::from_material(
            root_der,
            intermediate_der,
            intermediate_params,
            intermediate_key,
        )
    }

    fn from_material(
        root_der: Vec<u8>,
        intermediate_der: Vec<u8>,
        intermediate_params: CertificateParams,
        intermediate_key: KeyPair,
    ) -> Result<Self> {
        ensure_key_matches_cert(&intermediate_der, &intermediate_key)?;
        Ok(Self {
            root_cert: Arc::new(root_der),
            intermediate_cert: Arc::new(intermediate_der),
            intermediate_key: Arc::new(intermediate_key),
            intermediate_params: Arc::new(intermediate_params),
        })
    }

    /// Returns the intermediate signing key. Intended for internal use by TLS minting code.
    #[allow(dead_code)]
    pub(crate) fn signing_key(&self) -> Arc<KeyPair> {
        self.intermediate_key.clone()
    }

    /// Returns the DER-encoded root certificate.
    pub fn root_certificate_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.root_cert.as_ref().clone())
    }

    /// Returns the DER-encoded intermediate certificate.
    pub fn intermediate_certificate_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.intermediate_cert.as_ref().clone())
    }

    /// Returns the certificate chain to present to clients. The leaf certificate is expected
    /// to be prepended by the caller.
    pub fn certificate_chain(&self) -> Vec<CertificateDer<'static>> {
        let _ = &self.intermediate_key;
        vec![
            self.intermediate_certificate_der(),
            self.root_certificate_der(),
        ]
    }

    /// Mint a new leaf certificate for the provided subject names with the requested validity.
    /// The returned value includes the full chain and private key bytes for persistence.
    pub fn mint_leaf(&self, names: &[&str], ttl: StdDuration) -> Result<MintedLeaf> {
        ensure!(!names.is_empty(), "at least one subject name is required");
        ensure!(ttl > StdDuration::from_secs(0), "leaf ttl must be positive");
        let (leaf_params, expires_at) = build_leaf_params(names, ttl)?;
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|err| anyhow!("failed to generate leaf key: {err}"))?;
        let issuer =
            rcgen::Issuer::from_params(self.intermediate_params.as_ref(), &*self.intermediate_key);
        let leaf_cert = sign_certificate(&leaf_params, &leaf_key, &issuer)?;

        let private_key_der = Zeroizing::new(leaf_key.serialize_der());
        let key_der = PrivateKeyDer::try_from(private_key_der.to_vec())
            .map_err(|err| anyhow!("failed to parse generated leaf key: {err}"))?;

        let leaf_der = leaf_cert.der().as_ref().to_vec();
        let mut chain_der = Vec::with_capacity(1 + self.certificate_chain().len());
        chain_der.push(leaf_der);
        for cert in self.certificate_chain() {
            chain_der.push(cert.as_ref().to_vec());
        }

        let cert_chain_for_rustls: Vec<_> = chain_der
            .iter()
            .map(|bytes| CertificateDer::from(bytes.clone()))
            .collect();

        let provider = ring::default_provider();
        let certified_key = CertifiedKey::from_der(cert_chain_for_rustls, key_der, &provider)
            .map_err(|err| anyhow!("failed to build certified key: {err}"))?;

        Ok(MintedLeaf {
            certified_key: Arc::new(certified_key),
            chain_der,
            private_key_der,
            expires_at,
        })
    }
}

fn build_root_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(random_serial());
    params.distinguished_name = distinguished_name("ExfilGuard Root CA");
    set_validity(&mut params, ROOT_VALIDITY_YEARS);
    params
}

fn build_intermediate_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.use_authority_key_identifier_extension = true;
    params.serial_number = Some(random_serial());
    params.distinguished_name = distinguished_name("ExfilGuard Intermediate CA");
    set_validity(&mut params, INTERMEDIATE_VALIDITY_YEARS);
    params
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

fn set_validity(params: &mut CertificateParams, years: i64) {
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(years * 365);
}

fn random_serial() -> SerialNumber {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    // Ensure the serial number is treated as positive and non-zero.
    bytes[0] &= 0x7F;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[bytes.len() - 1] = 1;
    }
    SerialNumber::from(bytes.to_vec())
}

fn write_pem_file(path: &Path, contents: &str, private: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mode = if private { 0o600 } else { 0o644 };
    options.mode(mode);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to flush {}", path.display()))?;
    Ok(())
}

fn read_certificate_der(path: &Path) -> Result<Vec<u8>> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read certificate {}", path.display()))?;
    let mut cursor = Cursor::new(bytes);
    let mut certs = rustls_pemfile::certs(&mut cursor);
    match certs.next() {
        Some(Ok(cert)) => {
            if certs.next().is_some() {
                bail!(
                    "multiple certificates found in {}; expected a single PEM section",
                    path.display()
                );
            }
            Ok(cert.as_ref().to_vec())
        }
        Some(Err(err)) => {
            Err(err).with_context(|| format!("failed to parse certificate at {}", path.display()))
        }
        None => bail!("no certificate found in {}", path.display()),
    }
}

fn ensure_key_matches_cert(cert_der: &[u8], key: &KeyPair) -> Result<()> {
    let provider = ring::default_provider();
    let key_der = PrivateKeyDer::try_from(key.serialize_der())
        .map_err(|err| anyhow!("failed to parse private key DER: {err}"))?;
    let cert = CertificateDer::from(cert_der.to_vec());
    CertifiedKey::from_der(vec![cert], key_der, &provider)
        .map_err(|err| anyhow!("intermediate key does not match certificate: {err}"))?;
    Ok(())
}

fn sign_certificate(
    params: &CertificateParams,
    subject_key: &KeyPair,
    issuer: &rcgen::Issuer<'_, impl rcgen::SigningKey>,
) -> Result<Certificate> {
    params
        .signed_by(subject_key, issuer)
        .map_err(|err| anyhow!("failed to sign certificate: {err}"))
}

fn build_leaf_params(
    names: &[&str],
    ttl: StdDuration,
) -> Result<(CertificateParams, OffsetDateTime)> {
    let subject_alt_names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
    let mut params = CertificateParams::new(subject_alt_names)
        .map_err(|err| anyhow!("invalid subject names: {err}"))?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    params.serial_number = Some(random_serial());
    if let Some(primary) = names.first() {
        params.distinguished_name = distinguished_name(primary);
    }

    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::minutes(5);
    let ttl_duration = std_duration_to_time(ttl)?;
    params.not_after = now
        .checked_add(ttl_duration)
        .ok_or_else(|| anyhow!("leaf TTL exceeds supported range"))?;
    let expires_at = params.not_after;

    Ok((params, expires_at))
}

fn std_duration_to_time(ttl: StdDuration) -> Result<Duration> {
    let seconds = ttl
        .as_secs()
        .try_into()
        .map_err(|_| anyhow!("leaf TTL seconds exceed supported range"))?;
    let mut duration = Duration::seconds(seconds);
    let nanos = ttl.subsec_nanos();
    if nanos > 0 {
        duration = duration
            .checked_add(Duration::nanoseconds(nanos as i64))
            .ok_or_else(|| anyhow!("leaf TTL nanoseconds exceed supported range"))?;
    }
    Ok(duration)
}

pub struct MintedLeaf {
    pub certified_key: Arc<CertifiedKey>,
    pub chain_der: Vec<Vec<u8>>,
    pub private_key_der: Zeroizing<Vec<u8>>,
    pub expires_at: OffsetDateTime,
}

struct CaPaths<'a> {
    dir: &'a Path,
    root_cert: PathBuf,
    root_key: PathBuf,
    intermediate_cert: PathBuf,
    intermediate_key: PathBuf,
}

impl<'a> CaPaths<'a> {
    fn new(dir: &'a Path) -> Self {
        Self {
            dir,
            root_cert: dir.join(ROOT_CERT_FILE),
            root_key: dir.join(ROOT_KEY_FILE),
            intermediate_cert: dir.join(INTERMEDIATE_CERT_FILE),
            intermediate_key: dir.join(INTERMEDIATE_KEY_FILE),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::fs;
    use std::time::Duration as StdDuration;
    use tempfile::TempDir;

    #[test]
    fn generates_new_material_when_missing() -> Result<()> {
        let dir = TempDir::new()?;
        let ca = CertificateAuthority::load_or_generate(dir.path())?;
        assert!(dir.path().join(ROOT_CERT_FILE).exists());
        assert!(dir.path().join(ROOT_KEY_FILE).exists());
        assert!(dir.path().join(INTERMEDIATE_CERT_FILE).exists());
        assert!(dir.path().join(INTERMEDIATE_KEY_FILE).exists());

        let chain = ca.certificate_chain();
        assert_eq!(chain.len(), 2);
        assert!(!chain[0].as_ref().is_empty());
        assert!(!chain[1].as_ref().is_empty());
        assert!(!ca.signing_key().serialize_der().is_empty());
        Ok(())
    }

    #[test]
    fn reuses_existing_material() -> Result<()> {
        let dir = TempDir::new()?;
        let ca_first = CertificateAuthority::load_or_generate(dir.path())?;
        let root_first = ca_first.root_certificate_der().as_ref().to_vec();
        let intermediate_first = ca_first.intermediate_certificate_der().as_ref().to_vec();
        let key_first = ca_first.signing_key().serialize_der();
        drop(ca_first);

        let ca_second = CertificateAuthority::load_or_generate(dir.path())?;
        assert_eq!(
            root_first,
            ca_second.root_certificate_der().as_ref().to_vec()
        );
        assert_eq!(
            intermediate_first,
            ca_second.intermediate_certificate_der().as_ref().to_vec()
        );
        assert_eq!(key_first, ca_second.signing_key().serialize_der());
        Ok(())
    }

    #[test]
    fn errors_on_partial_material() -> Result<()> {
        let dir = TempDir::new()?;
        let root_path = dir.path().join(ROOT_CERT_FILE);
        fs::write(&root_path, "dummy root cert")?;
        match CertificateAuthority::load_or_generate(dir.path()) {
            Ok(_) => panic!("expected error when CA material is incomplete"),
            Err(err) => assert!(
                err.to_string().contains("incomplete CA material"),
                "{err:?}"
            ),
        }
        Ok(())
    }

    #[test]
    fn mint_leaf_produces_certified_key() -> Result<()> {
        let dir = TempDir::new()?;
        let ca = CertificateAuthority::load_or_generate(dir.path())?;
        let minted = ca.mint_leaf(&["leaf.example"], StdDuration::from_secs(3600))?;
        assert_eq!(minted.chain_der.len(), 3);
        assert!(!minted.certified_key.cert.is_empty());
        assert!(!minted.private_key_der.is_empty());
        assert!(minted.expires_at > OffsetDateTime::now_utc());
        Ok(())
    }
}
