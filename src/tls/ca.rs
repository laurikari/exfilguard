use std::convert::TryInto;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{Read, Write};
// ExfilGuard only targets Unix-like hosts, so we rely on the Unix-specific
// OpenOptions extension traits to enforce filesystem permissions.
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use nix::fcntl::{Flock, FlockArg};
use nix::libc::O_NOFOLLOW;
use nix::unistd::geteuid;
use rand::{TryRng, rngs::SysRng};
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
const PENDING_GENERATION_DIR: &str = ".exfilguard-ca.pending";
const GENERATION_READY_FILE: &str = "ready";
const GENERATION_READY_CONTENTS: &str = "exfilguard-ca-generation-v1\n";
const ROOT_VALIDITY_YEARS: i64 = 10;
const LEAF_ISSUER_EXPIRY_MARGIN: Duration = Duration::minutes(5);

/// Handles lifecycle management for the root and intermediate certificate authority.
#[derive(Clone)]
pub struct CertificateAuthority {
    certificate_chain: Arc<Vec<Vec<u8>>>,
    intermediate_key: Arc<KeyPair>,
    root_not_after: OffsetDateTime,
    intermediate_not_after: OffsetDateTime,
}

impl CertificateAuthority {
    /// Load or initialize ExfilGuard's built-in CA hierarchy.
    pub fn load_builtin<P: AsRef<Path>>(ca_dir: P) -> Result<Self> {
        Self::load_from_directory(ca_dir.as_ref(), true)
    }

    pub fn load_files<P: AsRef<Path>>(ca_dir: P) -> Result<Self> {
        Self::load_from_directory(ca_dir.as_ref(), false)
    }

    fn load_from_directory(ca_dir: &Path, allow_generation: bool) -> Result<Self> {
        if allow_generation {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(ca_dir)
                .with_context(|| format!("failed to create CA directory {}", ca_dir.display()))?;
        }

        let expected_uid = geteuid().as_raw();
        validate_ca_directory(ca_dir, expected_uid)?;

        // Serialize built-in generation and recovery without persisting a lock
        // file alongside the documented CA material. flock(2) on the directory
        // is sufficient because all participating ExfilGuard processes take it.
        let _generation_lock = if allow_generation {
            Some(lock_ca_directory(ca_dir)?)
        } else {
            None
        };

        let paths = CaPaths::new(ca_dir);
        let pending_generation = ca_dir.join(PENDING_GENERATION_DIR);
        if allow_generation {
            recover_pending_generation(&paths, expected_uid)?;
        } else if path_exists_no_follow(&pending_generation)? {
            bail!(
                "unfinished built-in CA generation found at {}; start once with source = \"builtin\" to recover it, or remove it after verifying the externally managed CA material",
                pending_generation.display()
            );
        }

        let has_root_cert = path_exists_no_follow(&paths.root_cert)?;
        let has_root_key = path_exists_no_follow(&paths.root_key)?;
        let has_intermediate_cert = path_exists_no_follow(&paths.intermediate_cert)?;
        let has_intermediate_key = path_exists_no_follow(&paths.intermediate_key)?;

        for (path, kind, present) in [
            (&paths.root_cert, CaFileKind::Certificate, has_root_cert),
            (&paths.root_key, CaFileKind::PrivateKey, has_root_key),
            (
                &paths.intermediate_cert,
                CaFileKind::Certificate,
                has_intermediate_cert,
            ),
            (
                &paths.intermediate_key,
                CaFileKind::PrivateKey,
                has_intermediate_key,
            ),
        ] {
            if present {
                validate_ca_file(path, kind, expected_uid)?;
            }
        }

        if has_root_key {
            bail!(
                "obsolete {} found in {}; ExfilGuard never loads a root private key; move it to offline storage or remove the invalid compatibility copy",
                ROOT_KEY_FILE,
                ca_dir.display()
            );
        }

        match (
            has_root_cert,
            has_root_key,
            has_intermediate_cert,
            has_intermediate_key,
        ) {
            (false, false, false, false) if allow_generation => Self::generate(&paths),
            (false, false, false, false) => bail!(
                "files CA source requires {}, {}, and {} in {}",
                ROOT_CERT_FILE,
                INTERMEDIATE_CERT_FILE,
                INTERMEDIATE_KEY_FILE,
                ca_dir.display()
            ),
            (true, false, true, true) => Self::load_existing(&paths),
            _ => bail!(
                "incomplete CA material detected in {}; expected exactly {}, {}, and {}; {} is forbidden",
                ca_dir.display(),
                ROOT_CERT_FILE,
                INTERMEDIATE_CERT_FILE,
                INTERMEDIATE_KEY_FILE,
                ROOT_KEY_FILE
            ),
        }
    }

    fn generate(paths: &CaPaths) -> Result<Self> {
        Self::generate_with_hook(paths, |_| Ok(()))
    }

    fn generate_with_hook(
        paths: &CaPaths,
        mut after_step: impl FnMut(GenerationStep) -> Result<()>,
    ) -> Result<Self> {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|err| anyhow!("failed to generate root key: {err}"))?;
        let now = OffsetDateTime::now_utc();
        let not_before = now - Duration::days(1);
        let not_after = now + Duration::days(ROOT_VALIDITY_YEARS * 365);
        let root_params = build_root_params(not_before, not_after)?;
        let root_cert = root_params
            .self_signed(&root_key)
            .map_err(|err| anyhow!("failed to self-sign root certificate: {err}"))?;

        let intermediate_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|err| anyhow!("failed to generate intermediate key: {err}"))?;
        let intermediate_params = build_intermediate_params(not_before, not_after)?;
        let root_issuer = rcgen::Issuer::from_params(&root_params, &root_key);
        let intermediate_cert =
            sign_certificate(&intermediate_params, &intermediate_key, &root_issuer)?;

        let root_cert_pem = root_cert.pem();
        let intermediate_cert_pem = intermediate_cert.pem();
        let intermediate_key_pem = Zeroizing::new(intermediate_key.serialize_pem());

        let pending_dir = paths.dir.join(PENDING_GENERATION_DIR);
        DirBuilder::new()
            .mode(0o700)
            .create(&pending_dir)
            .with_context(|| {
                format!(
                    "failed to create pending CA generation {}",
                    pending_dir.display()
                )
            })?;
        sync_directory(paths.dir)?;
        after_step(GenerationStep::PendingDirectoryCreated)?;

        let pending_paths = CaPaths::new(&pending_dir);
        write_pem_file(&pending_paths.root_cert, &root_cert_pem, false)?;
        after_step(GenerationStep::RootCertificateStaged)?;
        write_pem_file(
            &pending_paths.intermediate_cert,
            &intermediate_cert_pem,
            false,
        )?;
        after_step(GenerationStep::IntermediateCertificateStaged)?;
        write_pem_file(
            &pending_paths.intermediate_key,
            intermediate_key_pem.as_str(),
            true,
        )?;
        after_step(GenerationStep::IntermediateKeyStaged)?;
        // The marker may become durable only after every prerequisite filename
        // is durable; file fsync alone does not persist its directory entry.
        sync_directory(&pending_dir)?;
        after_step(GenerationStep::StagedFilesSynced)?;
        write_pem_file(
            &pending_dir.join(GENERATION_READY_FILE),
            GENERATION_READY_CONTENTS,
            true,
        )?;
        after_step(GenerationStep::ReadyMarkerStaged)?;
        sync_directory(&pending_dir)?;
        after_step(GenerationStep::ReadyMarkerSynced)?;

        publish_pending_generation(paths, &pending_paths, &mut after_step)?;

        let expected_uid = geteuid().as_raw();
        for (path, kind) in [
            (&paths.root_cert, CaFileKind::Certificate),
            (&paths.intermediate_cert, CaFileKind::Certificate),
            (&paths.intermediate_key, CaFileKind::PrivateKey),
        ] {
            validate_ca_file(path, kind, expected_uid)?;
        }

        discard_pending_generation(&pending_dir)?;
        sync_directory(paths.dir)?;
        after_step(GenerationStep::PendingGenerationRemoved)?;

        // The built-in root key is intentionally never persisted.
        drop(root_key);

        let root_der = root_cert.der().as_ref().to_vec();
        let intermediate_der = intermediate_cert.der().as_ref().to_vec();
        info!(
            directory = %paths.dir.display(),
            "generated new certificate authority material"
        );
        Self::from_material(root_der, intermediate_der, intermediate_key)
    }

    fn load_existing(paths: &CaPaths) -> Result<Self> {
        let authority = Self::from_existing_material(paths)?;

        info!(
            directory = %paths.dir.display(),
            "loaded existing certificate authority material"
        );
        Ok(authority)
    }

    fn from_existing_material(paths: &CaPaths) -> Result<Self> {
        let root_der = read_certificate_der(&paths.root_cert)?;
        let intermediate_der = read_certificate_der(&paths.intermediate_cert)?;
        let intermediate_key_pem = read_private_key_pem(&paths.intermediate_key)?;
        let intermediate_key = KeyPair::from_pem(intermediate_key_pem.as_ref())
            .map_err(|err| anyhow!("failed to parse intermediate key: {err}"))?;

        Self::from_material(root_der, intermediate_der, intermediate_key)
    }

    pub(crate) fn from_material(
        root_der: Vec<u8>,
        intermediate_der: Vec<u8>,
        intermediate_key: KeyPair,
    ) -> Result<Self> {
        Self::from_chain(vec![intermediate_der, root_der], intermediate_key)
    }

    pub(crate) fn from_chain(
        certificate_chain: Vec<Vec<u8>>,
        intermediate_key: KeyPair,
    ) -> Result<Self> {
        let now = OffsetDateTime::now_utc();
        let chain_refs: Vec<&[u8]> = certificate_chain.iter().map(Vec::as_slice).collect();
        let validity =
            super::validation::validate_ca_hierarchy(&chain_refs, &intermediate_key, now)?;
        ensure!(
            validity.intermediate_not_after > now + LEAF_ISSUER_EXPIRY_MARGIN,
            "intermediate certificate has too little remaining validity to issue a leaf"
        );
        Ok(Self {
            certificate_chain: Arc::new(certificate_chain),
            intermediate_key: Arc::new(intermediate_key),
            root_not_after: validity.root_not_after,
            intermediate_not_after: validity.intermediate_not_after,
        })
    }

    /// Returns the intermediate signing key. Intended for internal use by TLS minting code.
    #[allow(dead_code)]
    pub(crate) fn signing_key(&self) -> Arc<KeyPair> {
        self.intermediate_key.clone()
    }

    /// Returns the DER-encoded root certificate.
    pub fn root_certificate_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(
            self.certificate_chain
                .last()
                .expect("validated CA chain is nonempty")
                .clone(),
        )
    }

    /// Returns the DER-encoded intermediate certificate.
    pub fn intermediate_certificate_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(
            self.certificate_chain
                .first()
                .expect("validated CA chain is nonempty")
                .clone(),
        )
    }

    pub fn root_not_after(&self) -> OffsetDateTime {
        self.root_not_after
    }

    pub fn intermediate_not_after(&self) -> OffsetDateTime {
        self.intermediate_not_after
    }

    /// Returns the certificate chain to present to clients. The leaf certificate is expected
    /// to be prepended by the caller.
    pub fn certificate_chain(&self) -> Vec<CertificateDer<'static>> {
        self.certificate_chain
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect()
    }

    /// Mint a new leaf certificate for the provided subject names with the requested validity.
    /// The returned value includes the in-memory rustls key plus raw material for test fixtures.
    pub fn mint_leaf(&self, names: &[&str], ttl: StdDuration) -> Result<MintedLeaf> {
        ensure!(!names.is_empty(), "at least one subject name is required");
        ensure!(ttl > StdDuration::from_secs(0), "leaf ttl must be positive");
        let issuer_not_after = self.root_not_after.min(self.intermediate_not_after);
        let (leaf_params, expires_at) = build_leaf_params(names, ttl, issuer_not_after)?;
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|err| anyhow!("failed to generate leaf key: {err}"))?;
        let intermediate_cert = self.intermediate_certificate_der();
        let issuer = rcgen::Issuer::from_ca_cert_der(&intermediate_cert, &*self.intermediate_key)
            .map_err(|err| anyhow!("failed to parse intermediate certificate: {err}"))?;
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

fn build_root_params(
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<CertificateParams> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(random_serial()?);
    params.distinguished_name = distinguished_name("ExfilGuard Root CA");
    params.not_before = not_before;
    params.not_after = not_after;
    Ok(params)
}

fn build_intermediate_params(
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<CertificateParams> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.use_authority_key_identifier_extension = true;
    params.serial_number = Some(random_serial()?);
    params.distinguished_name = distinguished_name("ExfilGuard Intermediate CA");
    params.not_before = not_before;
    params.not_after = not_after;
    Ok(params)
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

fn random_serial() -> Result<SerialNumber> {
    let mut bytes = [0u8; 16];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|err| anyhow!("failed to generate certificate serial number: {err}"))?;
    // Ensure the serial number is treated as positive and non-zero.
    bytes[0] &= 0x7F;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[bytes.len() - 1] = 1;
    }
    Ok(SerialNumber::from(bytes.to_vec()))
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationStep {
    PendingDirectoryCreated,
    RootCertificateStaged,
    IntermediateCertificateStaged,
    IntermediateKeyStaged,
    StagedFilesSynced,
    ReadyMarkerStaged,
    ReadyMarkerSynced,
    RootCertificatePublished,
    IntermediateCertificatePublished,
    IntermediateKeyPublished,
    PublishedDirectorySynced,
    PendingGenerationRemoved,
}

fn lock_ca_directory(path: &Path) -> Result<Flock<File>> {
    let directory = File::open(path)
        .with_context(|| format!("failed to open CA directory {} for locking", path.display()))?;
    Flock::lock(directory, FlockArg::LockExclusive).map_err(|(_, err)| {
        anyhow!(
            "failed to lock CA directory {} for generation: {err}",
            path.display()
        )
    })
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("failed to open directory {} for syncing", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync directory {}", path.display()))
}

fn recover_pending_generation(paths: &CaPaths, expected_uid: u32) -> Result<()> {
    let pending_dir = paths.dir.join(PENDING_GENERATION_DIR);
    if !path_exists_no_follow(&pending_dir)? {
        return Ok(());
    }

    validate_ca_directory(&pending_dir, expected_uid)?;
    let ready_path = pending_dir.join(GENERATION_READY_FILE);
    if !path_exists_no_follow(&ready_path)?
        || !generation_marker_is_ready(&ready_path, expected_uid)?
    {
        discard_pending_generation(&pending_dir)?;
        sync_directory(paths.dir)?;
        return Ok(());
    }

    let pending_paths = CaPaths::new(&pending_dir);
    validate_pending_generation(&pending_paths, expected_uid)?;
    publish_pending_generation(paths, &pending_paths, &mut |_| Ok(()))?;
    discard_pending_generation(&pending_dir)?;
    sync_directory(paths.dir)?;
    Ok(())
}

fn validate_pending_generation(paths: &CaPaths, expected_uid: u32) -> Result<()> {
    validate_ca_directory(paths.dir, expected_uid)?;
    ensure!(
        !path_exists_no_follow(&paths.root_key)?,
        "pending CA generation {} unexpectedly contains {}; ExfilGuard never persists a root private key",
        paths.dir.display(),
        ROOT_KEY_FILE
    );
    for (path, kind) in [
        (&paths.root_cert, CaFileKind::Certificate),
        (&paths.intermediate_cert, CaFileKind::Certificate),
        (&paths.intermediate_key, CaFileKind::PrivateKey),
    ] {
        validate_ca_file(path, kind, expected_uid).with_context(|| {
            format!(
                "pending CA generation {} is incomplete or unsafe",
                paths.dir.display()
            )
        })?;
    }

    let ready_path = paths.dir.join(GENERATION_READY_FILE);
    ensure!(
        generation_marker_is_ready(&ready_path, expected_uid)?,
        "pending CA generation marker {} is incomplete",
        ready_path.display()
    );

    // Do not publish a durable but unusable hierarchy. The staged key and
    // certificates must pass the same cryptographic validation as live files.
    CertificateAuthority::from_existing_material(paths)?;
    Ok(())
}

fn generation_marker_is_ready(path: &Path, expected_uid: u32) -> Result<bool> {
    let mut ready_file = open_validated_ca_file(path, CaFileKind::TransactionMarker, expected_uid)?;
    let ready_metadata = ready_file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if ready_metadata.len() != GENERATION_READY_CONTENTS.len() as u64 {
        return Ok(false);
    }
    let mut contents = Vec::with_capacity(GENERATION_READY_CONTENTS.len());
    ready_file
        .read_to_end(&mut contents)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(contents == GENERATION_READY_CONTENTS.as_bytes())
}

fn publish_pending_generation(
    final_paths: &CaPaths,
    pending_paths: &CaPaths,
    after_step: &mut impl FnMut(GenerationStep) -> Result<()>,
) -> Result<()> {
    let expected_uid = geteuid().as_raw();
    validate_pending_generation(pending_paths, expected_uid)?;

    for (source, destination, kind, step) in [
        (
            &pending_paths.root_cert,
            &final_paths.root_cert,
            CaFileKind::Certificate,
            GenerationStep::RootCertificatePublished,
        ),
        (
            &pending_paths.intermediate_cert,
            &final_paths.intermediate_cert,
            CaFileKind::Certificate,
            GenerationStep::IntermediateCertificatePublished,
        ),
        (
            &pending_paths.intermediate_key,
            &final_paths.intermediate_key,
            CaFileKind::PrivateKey,
            GenerationStep::IntermediateKeyPublished,
        ),
    ] {
        if path_exists_no_follow(destination)? {
            validate_ca_file(destination, kind, expected_uid)?;
            let source_metadata = fs::metadata(source)
                .with_context(|| format!("failed to inspect {}", source.display()))?;
            let destination_metadata = fs::metadata(destination)
                .with_context(|| format!("failed to inspect {}", destination.display()))?;
            ensure!(
                source_metadata.dev() == destination_metadata.dev()
                    && source_metadata.ino() == destination_metadata.ino(),
                "cannot recover pending CA generation because {} contains different material",
                destination.display()
            );
            continue;
        }

        fs::hard_link(source, destination).with_context(|| {
            format!(
                "failed to publish pending CA file {} as {}",
                source.display(),
                destination.display()
            )
        })?;
        after_step(step)?;
    }

    sync_directory(final_paths.dir)?;
    after_step(GenerationStep::PublishedDirectorySynced)?;
    Ok(())
}

fn discard_pending_generation(path: &Path) -> Result<()> {
    let allowed_names = [
        GENERATION_READY_FILE,
        ROOT_CERT_FILE,
        INTERMEDIATE_CERT_FILE,
        INTERMEDIATE_KEY_FILE,
    ];
    for entry in fs::read_dir(path)
        .with_context(|| format!("failed to inspect pending CA generation {}", path.display()))?
    {
        let entry = entry.with_context(|| {
            format!("failed to inspect pending CA generation {}", path.display())
        })?;
        let name = entry.file_name();
        ensure!(
            allowed_names.iter().any(|allowed| name == *allowed),
            "pending CA generation {} contains unrecognized entry {:?}; refusing to remove it",
            path.display(),
            name
        );
        let metadata = fs::symlink_metadata(entry.path())
            .with_context(|| format!("failed to inspect {}", entry.path().display()))?;
        ensure!(
            !metadata.is_dir(),
            "pending CA generation entry {} is a directory; refusing to remove it",
            entry.path().display()
        );
    }

    // Remove and durably forget the commit marker first. If cleanup is
    // interrupted, recovery can then recognize the remainder as disposable
    // staging rather than complete material that still needs publishing.
    let ready_path = path.join(GENERATION_READY_FILE);
    if path_exists_no_follow(&ready_path)? {
        fs::remove_file(&ready_path)
            .with_context(|| format!("failed to remove {}", ready_path.display()))?;
        sync_directory(path)?;
    }
    for name in [
        ROOT_CERT_FILE,
        INTERMEDIATE_CERT_FILE,
        INTERMEDIATE_KEY_FILE,
    ] {
        let entry = path.join(name);
        if path_exists_no_follow(&entry)? {
            fs::remove_file(&entry)
                .with_context(|| format!("failed to remove {}", entry.display()))?;
        }
    }
    sync_directory(path)?;
    fs::remove_dir(path)
        .with_context(|| format!("failed to remove pending CA generation {}", path.display()))?;
    Ok(())
}

#[derive(Clone, Copy)]
enum CaFileKind {
    Certificate,
    PrivateKey,
    TransactionMarker,
}

fn path_exists_no_follow(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn validate_ca_directory(path: &Path, expected_uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect CA directory {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "CA directory {} must not be a symlink; replace it with a real directory owned by UID {}",
            path.display(),
            expected_uid
        );
    }
    ensure!(
        metadata.is_dir(),
        "CA directory {} is not a directory",
        path.display()
    );
    ensure!(
        metadata.uid() == expected_uid,
        "CA directory {} is owned by UID {}, but ExfilGuard runs as UID {}; run `chown {} {}`",
        path.display(),
        metadata.uid(),
        expected_uid,
        expected_uid,
        path.display()
    );

    let mode = metadata.mode() & 0o7777;
    ensure!(
        matches!(mode, 0o500 | 0o700),
        "CA directory {} has mode {:04o}; expected 0500 or 0700; run `chmod 0700 {}`",
        path.display(),
        mode,
        path.display()
    );
    Ok(())
}

fn validate_ca_file(path: &Path, kind: CaFileKind, expected_uid: u32) -> Result<()> {
    open_validated_ca_file(path, kind, expected_uid)?;
    Ok(())
}

fn open_validated_ca_file(path: &Path, kind: CaFileKind, expected_uid: u32) -> Result<File> {
    let link_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect CA file {}", path.display()))?;
    if link_metadata.file_type().is_symlink() {
        bail!(
            "CA file {} must not be a symlink; install a regular file owned by UID {}",
            path.display(),
            expected_uid
        );
    }
    validate_ca_file_metadata(path, &link_metadata, kind, expected_uid)?;

    // O_NOFOLLOW closes the race where the final path is replaced with a symlink
    // between the metadata check and open. The owner-only CA directory prevents
    // other users from replacing entries after its validation.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to securely open CA file {}", path.display()))?;
    let opened_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect open CA file {}", path.display()))?;
    validate_ca_file_metadata(path, &opened_metadata, kind, expected_uid)?;
    Ok(file)
}

fn validate_ca_file_metadata(
    path: &Path,
    metadata: &Metadata,
    kind: CaFileKind,
    expected_uid: u32,
) -> Result<()> {
    ensure!(
        metadata.file_type().is_file(),
        "CA file {} is not a regular file",
        path.display()
    );
    ensure!(
        metadata.uid() == expected_uid,
        "CA file {} is owned by UID {}, but ExfilGuard runs as UID {}; run `chown {} {}`",
        path.display(),
        metadata.uid(),
        expected_uid,
        expected_uid,
        path.display()
    );

    let mode = metadata.mode() & 0o7777;
    match kind {
        CaFileKind::PrivateKey => ensure!(
            matches!(mode, 0o400 | 0o600),
            "CA private key {} has mode {:04o}; expected 0400 or 0600; run `chmod 0600 {}`",
            path.display(),
            mode,
            path.display()
        ),
        CaFileKind::Certificate => ensure!(
            mode & 0o400 != 0 && mode & 0o7133 == 0,
            "CA certificate {} has unsafe mode {:04o}; it must be owner-readable, non-executable, and not group/world-writable; run `chmod 0644 {}`",
            path.display(),
            mode,
            path.display()
        ),
        CaFileKind::TransactionMarker => ensure!(
            matches!(mode, 0o400 | 0o600),
            "CA transaction marker {} has mode {:04o}; expected 0400 or 0600",
            path.display(),
            mode
        ),
    }
    Ok(())
}

fn open_ca_file(path: &Path, kind: CaFileKind) -> Result<File> {
    open_validated_ca_file(path, kind, geteuid().as_raw())
}

fn read_certificate_der(path: &Path) -> Result<Vec<u8>> {
    let mut file = open_ca_file(path, CaFileKind::Certificate)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed to read certificate {}", path.display()))?;
    let certificates = super::validation::parse_strict_certificate_pem_bundle(
        &bytes,
        &format!("certificate {}", path.display()),
    )?;
    ensure!(
        certificates.len() == 1,
        "multiple certificates found in {}; expected a single PEM section",
        path.display()
    );
    Ok(certificates.into_iter().next().expect("length checked"))
}

fn read_private_key_pem(path: &Path) -> Result<Zeroizing<String>> {
    let mut file = open_ca_file(path, CaFileKind::PrivateKey)?;
    let mut pem = Zeroizing::new(String::new());
    file.read_to_string(&mut pem)
        .with_context(|| format!("failed to read intermediate key from {}", path.display()))?;
    Ok(pem)
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
    issuer_not_after: OffsetDateTime,
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
    params.serial_number = Some(random_serial()?);
    if let Some(primary) = names.first() {
        params.distinguished_name = distinguished_name(primary);
    }

    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::minutes(5);
    let ttl_duration = std_duration_to_time(ttl)?;
    let requested_not_after = now
        .checked_add(ttl_duration)
        .ok_or_else(|| anyhow!("leaf TTL exceeds supported range"))?;
    let latest_not_after = issuer_not_after - LEAF_ISSUER_EXPIRY_MARGIN;
    ensure!(
        latest_not_after > now,
        "CA intermediate is too close to expiry to mint a leaf certificate"
    );
    params.not_after = requested_not_after.min(latest_not_after);
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
    use rcgen::SanType;
    use std::fs;
    use std::net::IpAddr;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration as StdDuration;
    use tempfile::TempDir;
    use x509_parser::parse_x509_certificate;

    fn secure_ca_temp_dir() -> Result<TempDir> {
        let dir = TempDir::new()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        Ok(dir)
    }

    fn test_validity() -> (OffsetDateTime, OffsetDateTime) {
        let now = OffsetDateTime::now_utc();
        (now - Duration::days(1), now + Duration::days(365))
    }

    #[test]
    fn generates_new_material_when_missing() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        let ca = CertificateAuthority::load_builtin(dir.path())?;
        assert!(dir.path().join(ROOT_CERT_FILE).exists());
        assert!(!dir.path().join(ROOT_KEY_FILE).exists());
        assert!(dir.path().join(INTERMEDIATE_CERT_FILE).exists());
        assert!(dir.path().join(INTERMEDIATE_KEY_FILE).exists());

        let chain = ca.certificate_chain();
        assert_eq!(chain.len(), 2);
        assert!(!chain[0].as_ref().is_empty());
        assert!(!chain[1].as_ref().is_empty());
        assert!(!ca.signing_key().serialize_der().is_empty());
        let remaining = ca.intermediate_not_after() - OffsetDateTime::now_utc();
        assert!(remaining > Duration::days(9 * 365));
        assert_eq!(ca.root_not_after(), ca.intermediate_not_after());
        Ok(())
    }

    #[test]
    fn reuses_existing_material() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        let ca_first = CertificateAuthority::load_builtin(dir.path())?;
        let root_first = ca_first.root_certificate_der().as_ref().to_vec();
        let intermediate_first = ca_first.intermediate_certificate_der().as_ref().to_vec();
        let key_first = ca_first.signing_key().serialize_der();
        drop(ca_first);

        let ca_second = CertificateAuthority::load_builtin(dir.path())?;
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
    fn concurrent_builtin_initialization_publishes_one_generation() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        let directory = Arc::new(dir.path().to_path_buf());
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let directory = directory.clone();
            let barrier = barrier.clone();
            workers.push(thread::spawn(move || {
                barrier.wait();
                CertificateAuthority::load_builtin(directory.as_ref())
            }));
        }
        barrier.wait();

        let first = workers
            .remove(0)
            .join()
            .expect("first CA initializer panicked")?;
        let second = workers
            .remove(0)
            .join()
            .expect("second CA initializer panicked")?;
        assert_eq!(
            first.root_certificate_der().as_ref(),
            second.root_certificate_der().as_ref()
        );
        assert!(!dir.path().join(PENDING_GENERATION_DIR).exists());
        Ok(())
    }

    #[test]
    fn builtin_generation_recovers_after_every_persistence_step() -> Result<()> {
        let steps = [
            GenerationStep::PendingDirectoryCreated,
            GenerationStep::RootCertificateStaged,
            GenerationStep::IntermediateCertificateStaged,
            GenerationStep::IntermediateKeyStaged,
            GenerationStep::StagedFilesSynced,
            GenerationStep::ReadyMarkerStaged,
            GenerationStep::ReadyMarkerSynced,
            GenerationStep::RootCertificatePublished,
            GenerationStep::IntermediateCertificatePublished,
            GenerationStep::IntermediateKeyPublished,
            GenerationStep::PublishedDirectorySynced,
            GenerationStep::PendingGenerationRemoved,
        ];

        for failed_step in steps {
            let dir = secure_ca_temp_dir()?;
            let paths = CaPaths::new(dir.path());
            let mut injected = false;
            let error = CertificateAuthority::generate_with_hook(&paths, |completed_step| {
                if completed_step == failed_step && !injected {
                    injected = true;
                    bail!("injected failure after {completed_step:?}");
                }
                Ok(())
            })
            .err()
            .expect("the selected persistence step must fail");
            assert!(injected, "step {failed_step:?} was not reached: {error:?}");

            let recovered = CertificateAuthority::load_builtin(dir.path())?;
            assert!(!dir.path().join(PENDING_GENERATION_DIR).exists());
            assert!(dir.path().join(ROOT_CERT_FILE).is_file());
            assert!(dir.path().join(INTERMEDIATE_CERT_FILE).is_file());
            assert!(dir.path().join(INTERMEDIATE_KEY_FILE).is_file());
            recovered.mint_leaf(&["recovered.example"], StdDuration::from_secs(60))?;
        }
        Ok(())
    }

    #[test]
    fn builtin_generation_recovers_after_interrupted_cleanup() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        let paths = CaPaths::new(dir.path());
        let error = CertificateAuthority::generate_with_hook(&paths, |completed_step| {
            if completed_step == GenerationStep::PublishedDirectorySynced {
                bail!("leave a durable published generation pending cleanup");
            }
            Ok(())
        })
        .err()
        .expect("failure should leave the pending generation in place");
        assert!(error.to_string().contains("durable published generation"));

        let pending_dir = dir.path().join(PENDING_GENERATION_DIR);
        fs::remove_file(pending_dir.join(GENERATION_READY_FILE))?;
        fs::remove_file(pending_dir.join(ROOT_CERT_FILE))?;

        CertificateAuthority::load_builtin(dir.path())?;
        assert!(!pending_dir.exists());
        assert!(dir.path().join(ROOT_CERT_FILE).is_file());
        assert!(dir.path().join(INTERMEDIATE_CERT_FILE).is_file());
        assert!(dir.path().join(INTERMEDIATE_KEY_FILE).is_file());
        Ok(())
    }

    #[test]
    fn builtin_generation_discards_an_incompletely_written_ready_marker() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        let pending_dir = dir.path().join(PENDING_GENERATION_DIR);
        DirBuilder::new().mode(0o700).create(&pending_dir)?;
        write_pem_file(&pending_dir.join(ROOT_CERT_FILE), "partial", false)?;
        write_pem_file(&pending_dir.join(GENERATION_READY_FILE), "", true)?;

        CertificateAuthority::load_builtin(dir.path())?;
        assert!(!pending_dir.exists());
        assert!(dir.path().join(ROOT_CERT_FILE).is_file());
        assert!(dir.path().join(INTERMEDIATE_CERT_FILE).is_file());
        assert!(dir.path().join(INTERMEDIATE_KEY_FILE).is_file());
        Ok(())
    }

    #[test]
    fn builtin_recovery_never_overwrites_different_final_material() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        let paths = CaPaths::new(dir.path());
        CertificateAuthority::generate_with_hook(&paths, |completed_step| {
            if completed_step == GenerationStep::ReadyMarkerSynced {
                bail!("leave a complete staged generation");
            }
            Ok(())
        })
        .err()
        .expect("generation should stop before publication");

        let final_root = dir.path().join(ROOT_CERT_FILE);
        write_pem_file(&final_root, "operator material", false)?;
        let err = CertificateAuthority::load_builtin(dir.path())
            .err()
            .expect("recovery must reject conflicting final material");
        assert!(err.to_string().contains("different material"), "{err:?}");
        assert_eq!(fs::read_to_string(final_root)?, "operator material");
        assert!(dir.path().join(PENDING_GENERATION_DIR).exists());
        Ok(())
    }

    #[test]
    fn leaf_issuer_matches_loaded_intermediate_subject() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|err| anyhow!("failed to generate root key: {err}"))?;
        let (not_before, not_after) = test_validity();
        let root_params = build_root_params(not_before, not_after)?;
        let root_cert = root_params
            .self_signed(&root_key)
            .map_err(|err| anyhow!("failed to self-sign root certificate: {err}"))?;

        let intermediate_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|err| anyhow!("failed to generate intermediate key: {err}"))?;
        let mut intermediate_params = build_intermediate_params(not_before, not_after)?;
        intermediate_params.distinguished_name = distinguished_name("Corp Intermediate CA");
        let root_issuer = rcgen::Issuer::from_params(&root_params, &root_key);
        let intermediate_cert =
            sign_certificate(&intermediate_params, &intermediate_key, &root_issuer)?;

        write_pem_file(&dir.path().join(ROOT_CERT_FILE), &root_cert.pem(), false)?;
        write_pem_file(
            &dir.path().join(INTERMEDIATE_CERT_FILE),
            &intermediate_cert.pem(),
            false,
        )?;
        write_pem_file(
            &dir.path().join(INTERMEDIATE_KEY_FILE),
            &intermediate_key.serialize_pem(),
            true,
        )?;

        let ca = CertificateAuthority::load_builtin(dir.path())?;
        let minted = ca.mint_leaf(&["leaf.example"], StdDuration::from_secs(3600))?;
        let leaf_der = &minted.chain_der[0];
        let (_, leaf_cert) = parse_x509_certificate(leaf_der)
            .map_err(|err| anyhow!("failed to parse leaf certificate: {err}"))?;
        let intermediate_der = ca.intermediate_certificate_der();
        let (_, intermediate_cert) = parse_x509_certificate(intermediate_der.as_ref())
            .map_err(|err| anyhow!("failed to parse intermediate certificate: {err}"))?;

        assert_eq!(
            leaf_cert.tbs_certificate.issuer,
            intermediate_cert.tbs_certificate.subject
        );
        Ok(())
    }

    #[test]
    fn errors_on_partial_material() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        let root_path = dir.path().join(ROOT_CERT_FILE);
        fs::write(&root_path, "dummy root cert")?;
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o644))?;
        match CertificateAuthority::load_builtin(dir.path()) {
            Ok(_) => panic!("expected error when CA material is incomplete"),
            Err(err) => assert!(
                err.to_string().contains("incomplete CA material"),
                "{err:?}"
            ),
        }
        Ok(())
    }

    #[test]
    fn files_source_loads_without_root_key() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|err| anyhow!("failed to generate root key: {err}"))?;
        let (not_before, not_after) = test_validity();
        let root_params = build_root_params(not_before, not_after)?;
        let root_cert = root_params
            .self_signed(&root_key)
            .map_err(|err| anyhow!("failed to self-sign root certificate: {err}"))?;

        let intermediate_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|err| anyhow!("failed to generate intermediate key: {err}"))?;
        let intermediate_params = build_intermediate_params(not_before, not_after)?;
        let root_issuer = rcgen::Issuer::from_params(&root_params, &root_key);
        let intermediate_cert =
            sign_certificate(&intermediate_params, &intermediate_key, &root_issuer)?;

        write_pem_file(&dir.path().join(ROOT_CERT_FILE), &root_cert.pem(), false)?;
        write_pem_file(
            &dir.path().join(INTERMEDIATE_CERT_FILE),
            &intermediate_cert.pem(),
            false,
        )?;
        write_pem_file(
            &dir.path().join(INTERMEDIATE_KEY_FILE),
            &intermediate_key.serialize_pem(),
            true,
        )?;

        let ca = CertificateAuthority::load_files(dir.path())?;
        assert!(!ca.intermediate_certificate_der().as_ref().is_empty());
        Ok(())
    }

    #[test]
    fn files_source_rejects_empty_directory() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        let err = CertificateAuthority::load_files(dir.path())
            .err()
            .expect("files source must not generate a CA");
        assert!(
            err.to_string().contains("files CA source requires"),
            "{err:?}"
        );
        Ok(())
    }

    #[test]
    fn files_source_does_not_recover_builtin_generation() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        let pending_dir = dir.path().join(PENDING_GENERATION_DIR);
        DirBuilder::new().mode(0o700).create(&pending_dir)?;

        let err = CertificateAuthority::load_files(dir.path())
            .err()
            .expect("files source must not mutate a built-in transaction");
        assert!(
            err.to_string()
                .contains("unfinished built-in CA generation"),
            "{err:?}"
        );
        assert!(pending_dir.exists());
        Ok(())
    }

    #[test]
    fn files_source_does_not_create_a_missing_directory() -> Result<()> {
        let parent = secure_ca_temp_dir()?;
        let ca_dir = parent.path().join("missing");
        assert!(CertificateAuthority::load_files(&ca_dir).is_err());
        assert!(!ca_dir.exists());
        Ok(())
    }

    #[test]
    fn rejects_obsolete_root_key() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        CertificateAuthority::load_builtin(dir.path())?;
        write_pem_file(&dir.path().join(ROOT_KEY_FILE), "obsolete", true)?;

        let err = CertificateAuthority::load_builtin(dir.path())
            .err()
            .expect("root private key must be rejected");
        assert!(err.to_string().contains("obsolete root.key"), "{err:?}");
        Ok(())
    }

    #[test]
    fn rejects_symlinked_ca_directory() -> Result<()> {
        let parent = TempDir::new()?;
        let real_dir = parent.path().join("real-ca");
        CertificateAuthority::load_builtin(&real_dir)?;
        let linked_dir = parent.path().join("linked-ca");
        symlink(&real_dir, &linked_dir)?;

        let err = CertificateAuthority::load_builtin(&linked_dir)
            .err()
            .expect("symlinked CA directory should be rejected");
        assert!(err.to_string().contains("must not be a symlink"), "{err:?}");
        Ok(())
    }

    #[test]
    fn rejects_symlinked_ca_keys() -> Result<()> {
        for key_name in [ROOT_KEY_FILE, INTERMEDIATE_KEY_FILE] {
            let dir = secure_ca_temp_dir()?;
            CertificateAuthority::load_builtin(dir.path())?;
            let key_path = dir.path().join(key_name);
            let real_path = dir.path().join(format!("{key_name}.real"));
            if key_name == ROOT_KEY_FILE {
                write_pem_file(&real_path, "obsolete", true)?;
            } else {
                fs::rename(&key_path, &real_path)?;
            }
            symlink(&real_path, &key_path)?;

            let err = CertificateAuthority::load_builtin(dir.path())
                .err()
                .expect("symlinked CA key should be rejected");
            assert!(err.to_string().contains("must not be a symlink"), "{err:?}");
        }
        Ok(())
    }

    #[test]
    fn rejects_permissive_ca_directory() -> Result<()> {
        let dir = TempDir::new()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750))?;

        let err = CertificateAuthority::load_builtin(dir.path())
            .err()
            .expect("permissive CA directory should be rejected");
        assert!(err.to_string().contains("expected 0500 or 0700"), "{err:?}");
        Ok(())
    }

    #[test]
    fn rejects_permissive_ca_key() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        CertificateAuthority::load_builtin(dir.path())?;
        let key_path = dir.path().join(INTERMEDIATE_KEY_FILE);
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o640))?;

        let err = CertificateAuthority::load_builtin(dir.path())
            .err()
            .expect("group-readable CA key should be rejected");
        assert!(err.to_string().contains("expected 0400 or 0600"), "{err:?}");
        Ok(())
    }

    #[test]
    fn accepts_read_only_owner_ca_material() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        CertificateAuthority::load_builtin(dir.path())?;
        fs::set_permissions(
            dir.path().join(INTERMEDIATE_KEY_FILE),
            fs::Permissions::from_mode(0o400),
        )?;
        for cert_name in [ROOT_CERT_FILE, INTERMEDIATE_CERT_FILE] {
            fs::set_permissions(
                dir.path().join(cert_name),
                fs::Permissions::from_mode(0o444),
            )?;
        }
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500))?;

        let result = CertificateAuthority::load_builtin(dir.path());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        result?;
        Ok(())
    }

    #[test]
    fn rejects_non_regular_ca_key() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        CertificateAuthority::load_builtin(dir.path())?;
        let key_path = dir.path().join(INTERMEDIATE_KEY_FILE);
        fs::remove_file(&key_path)?;
        fs::create_dir(&key_path)?;

        let err = CertificateAuthority::load_builtin(dir.path())
            .err()
            .expect("non-regular CA key should be rejected");
        assert!(err.to_string().contains("not a regular file"), "{err:?}");
        Ok(())
    }

    #[test]
    fn rejects_ca_material_owned_by_another_uid() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        CertificateAuthority::load_builtin(dir.path())?;
        let key_path = dir.path().join(INTERMEDIATE_KEY_FILE);
        let metadata = fs::metadata(&key_path)?;
        let other_uid = if metadata.uid() == u32::MAX {
            metadata.uid() - 1
        } else {
            metadata.uid() + 1
        };

        let err =
            validate_ca_file_metadata(&key_path, &metadata, CaFileKind::PrivateKey, other_uid)
                .expect_err("foreign-owned CA key should be rejected");
        assert!(err.to_string().contains("is owned by UID"), "{err:?}");
        Ok(())
    }

    #[test]
    fn rejects_group_writable_ca_certificate() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        CertificateAuthority::load_builtin(dir.path())?;
        let cert_path = dir.path().join(ROOT_CERT_FILE);
        fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o664))?;

        let err = CertificateAuthority::load_builtin(dir.path())
            .err()
            .expect("group-writable CA certificate should be rejected");
        assert!(err.to_string().contains("unsafe mode"), "{err:?}");
        Ok(())
    }

    #[test]
    fn mint_leaf_produces_certified_key() -> Result<()> {
        let dir = secure_ca_temp_dir()?;
        let ca = CertificateAuthority::load_builtin(dir.path())?;
        let minted = ca.mint_leaf(&["leaf.example"], StdDuration::from_secs(3600))?;
        assert_eq!(minted.chain_der.len(), 3);
        assert!(!minted.certified_key.cert.is_empty());
        assert!(!minted.private_key_der.is_empty());
        assert!(minted.expires_at > OffsetDateTime::now_utc());
        Ok(())
    }

    #[test]
    fn leaf_params_use_ip_san_for_literals() -> Result<()> {
        let ttl = StdDuration::from_secs(60);
        for literal in ["192.0.2.1", "2001:db8::1"] {
            let issuer_not_after = OffsetDateTime::now_utc() + Duration::days(1);
            let (params, _) = build_leaf_params(&[literal], ttl, issuer_not_after)?;
            assert_eq!(params.subject_alt_names.len(), 1);
            match &params.subject_alt_names[0] {
                SanType::IpAddress(ip) => {
                    assert_eq!(ip, &literal.parse::<IpAddr>().unwrap());
                }
                other => panic!("expected IP SAN for {literal}, got {other:?}"),
            }
        }
        Ok(())
    }

    #[test]
    fn leaf_validity_is_capped_before_issuer_expiry() -> Result<()> {
        let issuer_not_after = OffsetDateTime::now_utc() + Duration::minutes(30);
        let (_, expires_at) = build_leaf_params(
            &["leaf.example"],
            StdDuration::from_secs(60 * 60),
            issuer_not_after,
        )?;
        assert_eq!(expires_at, issuer_not_after - LEAF_ISSUER_EXPIRY_MARGIN);
        Ok(())
    }
}
