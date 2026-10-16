use std::fs::{File, Metadata, OpenOptions};
use std::future::Future;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use nix::libc::O_NOFOLLOW;
use nix::unistd::geteuid;
use rand::{TryRng, rngs::SysRng};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use reqwest::{Client, StatusCode, Url, redirect::Policy};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use time::OffsetDateTime;
use tokio::time::sleep;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use super::{ca::CertificateAuthority, issuer::TlsIssuer};

const MAX_VAULT_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_CREDENTIAL_BYTES: u64 = 16 * 1024;
pub(crate) const INITIAL_RETRY_DELAY: StdDuration = StdDuration::from_secs(5);
pub(crate) const MAX_RETRY_DELAY: StdDuration = StdDuration::from_secs(15 * 60);
const MAX_RENEWAL_SCHEDULE_SLEEP: StdDuration = StdDuration::from_secs(60 * 60);

#[derive(Clone, Debug)]
pub(crate) enum VaultAuthConfig {
    AppRole {
        mount: String,
        role_id: String,
        secret_id_file: PathBuf,
    },
    TokenFile {
        token_file: PathBuf,
    },
    Proxy,
}

#[derive(Clone, Debug)]
pub(crate) struct VaultConfig {
    pub address: String,
    pub tls_ca_cert: Option<PathBuf>,
    pub tls_server_name: Option<String>,
    pub namespace: Option<String>,
    pub pki_mount: String,
    pub expected_root_certs: PathBuf,
    pub request_timeout: StdDuration,
    pub tls_client_cert: Option<PathBuf>,
    pub tls_client_key: Option<PathBuf>,
    pub auth: VaultAuthConfig,
}

#[derive(Clone)]
pub(crate) struct VaultClient {
    client: Client,
    base_url: Url,
    namespace: Option<String>,
    pki_mount: String,
    expected_roots: Arc<Vec<Vec<u8>>>,
    auth: VaultAuthConfig,
}

#[derive(Clone, Debug)]
pub(crate) struct VaultCaConfig {
    pub issuer: String,
    pub intermediate_ttl: StdDuration,
    pub renewal_threshold: StdDuration,
}

#[derive(Clone)]
pub(crate) struct VaultCaSource {
    vault: Arc<VaultClient>,
    issuer: String,
    intermediate_ttl: StdDuration,
    renewal_threshold: StdDuration,
}

#[derive(Debug)]
struct VaultFailure {
    kind: &'static str,
    message: String,
}

impl std::fmt::Display for VaultFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for VaultFailure {}

fn vault_failure(kind: &'static str, error: impl std::fmt::Display) -> anyhow::Error {
    VaultFailure {
        kind,
        message: error.to_string(),
    }
    .into()
}

pub(crate) fn failure_kind(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<VaultFailure>()
        .map_or("other", |failure| failure.kind)
}

#[derive(Serialize)]
struct AppRoleLoginRequest<'a> {
    role_id: &'a str,
    secret_id: &'a str,
}

#[derive(Deserialize)]
struct AppRoleLoginResponse {
    auth: AppRoleAuth,
}

#[derive(Deserialize)]
struct AppRoleAuth {
    client_token: String,
}

#[derive(Serialize)]
struct SignIntermediateRequest<'a> {
    csr: &'a str,
    common_name: &'static str,
    exclude_cn_from_sans: bool,
    format: &'static str,
    max_path_length: u8,
    remove_roots_from_chain: bool,
    ttl: String,
}

#[derive(Deserialize)]
struct SignIntermediateResponse {
    data: SignedCertificate,
}

#[derive(Deserialize)]
struct SignedCertificate {
    certificate: String,
    issuing_ca: String,
    #[serde(default)]
    ca_chain: Vec<String>,
}

#[derive(Serialize)]
struct SignClientCertificateRequest<'a> {
    csr: &'a str,
    common_name: &'a str,
    exclude_cn_from_sans: bool,
    format: &'static str,
    remove_roots_from_chain: bool,
}

#[derive(Deserialize)]
struct SignClientCertificateResponse {
    data: SignedCertificate,
}

struct ParsedSignedChain {
    der: Vec<Vec<u8>>,
    pem: Vec<String>,
}

pub(crate) struct VaultClientCertificate {
    pub identity_pem: Zeroizing<Vec<u8>>,
    pub validity: super::validation::ClientCertificateValidity,
}

#[derive(Deserialize)]
struct VaultErrors {
    #[serde(default)]
    errors: Vec<String>,
}

impl VaultClient {
    pub(crate) fn new(config: VaultConfig) -> Result<Self> {
        let mut base_url = Url::parse(&config.address).context("invalid Vault address")?;
        ensure!(
            matches!(base_url.scheme(), "http" | "https"),
            "Vault address must use http or https"
        );
        if base_url.scheme() == "http" {
            let loopback = base_url
                .host_str()
                .and_then(|host| host.parse::<IpAddr>().ok())
                .is_some_and(|address| address.is_loopback());
            ensure!(
                loopback,
                "plaintext Vault HTTP is allowed only on a loopback IP address"
            );
            ensure!(
                config.tls_ca_cert.is_none()
                    && config.tls_server_name.is_none()
                    && config.tls_client_cert.is_none()
                    && config.tls_client_key.is_none(),
                "Vault TLS settings cannot be used with a plaintext loopback address"
            );
        }
        ensure!(
            base_url.username().is_empty() && base_url.password().is_none(),
            "Vault address must not contain credentials"
        );
        ensure!(
            base_url.query().is_none() && base_url.fragment().is_none(),
            "Vault address must not contain a query or fragment"
        );
        base_url.set_path("/");

        let mut builder = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(config.request_timeout)
            .user_agent(concat!("exfilguard/", env!("CARGO_PKG_VERSION")));

        if let Some(server_name) = &config.tls_server_name {
            let original_host = base_url
                .host_str()
                .ok_or_else(|| anyhow!("Vault address has no host"))?
                .to_string();
            let port = base_url
                .port_or_known_default()
                .ok_or_else(|| anyhow!("Vault address has no port"))?;
            if original_host != *server_name {
                let address = original_host.parse::<IpAddr>().map_err(|_| {
                    anyhow!(
                        "tls_server_name may differ from vault.address only when the address host is an IP literal"
                    )
                })?;
                base_url
                    .set_host(Some(server_name))
                    .map_err(|_| anyhow!("invalid Vault TLS server name"))?;
                builder = builder.resolve(server_name, SocketAddr::new(address, port));
            }
        }

        if let Some(ca_path) = &config.tls_ca_cert {
            for cert in read_public_certificate_bundle(ca_path)? {
                builder = builder.tls_certs_merge([reqwest::Certificate::from_der(&cert)
                    .context("failed to add Vault TLS trust certificate")?]);
            }
        }

        if let (Some(cert_path), Some(key_path)) = (&config.tls_client_cert, &config.tls_client_key)
        {
            let mut identity = Zeroizing::new(read_public_file(cert_path)?);
            identity.extend_from_slice(&read_secret_bytes(key_path)?);
            builder = builder.identity(
                reqwest::Identity::from_pem(&identity)
                    .context("failed to parse Vault TLS client identity")?,
            );
        }

        let expected_roots = read_public_certificate_bundle(&config.expected_root_certs)?;
        ensure!(
            !expected_roots.is_empty(),
            "expected_root_certs contains no certificates"
        );

        let auth = match config.auth {
            VaultAuthConfig::AppRole {
                mount,
                role_id,
                secret_id_file,
            } => VaultAuthConfig::AppRole {
                mount: validate_api_path(&mount, "Vault AppRole mount")?,
                role_id,
                secret_id_file,
            },
            other => other,
        };
        if let Some(namespace) = &config.namespace {
            reqwest::header::HeaderValue::from_str(namespace)
                .context("Vault namespace is not a valid HTTP header value")?;
        }

        Ok(Self {
            client: builder
                .build()
                .context("failed to build Vault HTTP client")?,
            base_url,
            namespace: config.namespace,
            pki_mount: validate_api_path(&config.pki_mount, "Vault PKI mount")?,
            expected_roots: Arc::new(expected_roots),
            auth,
        })
    }

    async fn authenticate(&self) -> Result<Option<Zeroizing<String>>> {
        match &self.auth {
            VaultAuthConfig::AppRole {
                mount,
                role_id,
                secret_id_file,
            } => {
                let secret_id = read_secret_value(secret_id_file)
                    .map_err(|err| vault_failure("authentication", err))?;
                let url = api_url(&self.base_url, &["auth", mount, "login"])?;
                let body = AppRoleLoginRequest {
                    role_id,
                    secret_id: secret_id.as_str(),
                };
                let response: AppRoleLoginResponse = self
                    .post_json(url, None, &body)
                    .await
                    .map_err(|err| vault_failure("authentication", err))?;
                let client_token = Zeroizing::new(response.auth.client_token);
                validate_secret_value(&client_token, "Vault token")
                    .map_err(|err| vault_failure("authentication", err))?;
                Ok(Some(client_token))
            }
            VaultAuthConfig::TokenFile { token_file } => Ok(Some(
                read_secret_value(token_file)
                    .map_err(|err| vault_failure("authentication", err))?,
            )),
            VaultAuthConfig::Proxy => Ok(None),
        }
    }

    async fn post_json<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        url: Url,
        token: Option<&str>,
        body: &T,
    ) -> Result<R> {
        let mut request = self
            .client
            .post(url)
            .header("X-Vault-Request", "true")
            .json(body);
        if let Some(namespace) = &self.namespace {
            request = request.header("X-Vault-Namespace", namespace);
        }
        if let Some(token) = token {
            request = request.header("X-Vault-Token", token);
        }
        let response = request.send().await.context("Vault request failed")?;
        let status = response.status();
        let bytes = read_limited_response(response).await?;
        if status != StatusCode::OK {
            let message = serde_json::from_slice::<VaultErrors>(&bytes)
                .ok()
                .map(|body| body.errors.join("; "))
                .filter(|message| !message.is_empty())
                .unwrap_or_else(|| format!("HTTP {status}"));
            bail!("Vault returned {status}: {message}");
        }
        serde_json::from_slice(&bytes).context("failed to parse Vault response")
    }

    pub(crate) async fn issue_client_certificate(
        &self,
        role: &str,
        common_name: &str,
    ) -> Result<VaultClientCertificate> {
        let role = validate_single_api_segment(role, "Vault PKI role")?;
        let common_name = common_name.to_string();
        let csr_name = common_name.clone();
        let (key, csr) = tokio::task::spawn_blocking(move || build_client_csr(&csr_name))
            .await
            .context("client certificate CSR worker failed")??;
        let token = self.authenticate().await?;
        let mut segments: Vec<&str> = self.pki_mount.split('/').collect();
        segments.extend(["sign", role.as_str()]);
        let url = api_url(&self.base_url, &segments)?;
        let body = SignClientCertificateRequest {
            csr: &csr,
            common_name: &common_name,
            exclude_cn_from_sans: true,
            format: "pem",
            remove_roots_from_chain: false,
        };
        let response: SignClientCertificateResponse = self
            .post_json(url, token.as_deref().map(|value| value.as_str()), &body)
            .await
            .map_err(|err| vault_failure("signing", err))?;
        drop(token);

        let chain = self
            .parse_signed_chain(response.data, "Vault client certificate")
            .map_err(|err| vault_failure("validation", err))?;
        let chain_refs: Vec<&[u8]> = chain.der.iter().map(Vec::as_slice).collect();
        let validity = super::validation::validate_client_certificate_chain(
            &chain_refs,
            &key,
            &common_name,
            OffsetDateTime::now_utc(),
        )
        .map_err(|err| vault_failure("validation", err))?;

        let mut identity_pem = Zeroizing::new(Vec::new());
        let identity_certificate_count = chain.pem.len() - 1;
        for certificate in chain.pem.into_iter().take(identity_certificate_count) {
            identity_pem.extend_from_slice(certificate.trim().as_bytes());
            identity_pem.push(b'\n');
        }
        identity_pem.extend_from_slice(key.serialize_pem().as_bytes());
        Ok(VaultClientCertificate {
            identity_pem,
            validity,
        })
    }

    fn parse_signed_chain(
        &self,
        signed: SignedCertificate,
        leaf_name: &str,
    ) -> Result<ParsedSignedChain> {
        let leaf_der = parse_single_certificate(signed.certificate.as_bytes(), leaf_name)?;
        let issuing_ca_der =
            parse_single_certificate(signed.issuing_ca.as_bytes(), "Vault issuing certificate")?;
        let (mut parent_der, mut parent_pem) = if signed.ca_chain.is_empty() {
            (vec![issuing_ca_der.clone()], vec![signed.issuing_ca])
        } else {
            let der = signed
                .ca_chain
                .iter()
                .enumerate()
                .map(|(index, certificate)| {
                    parse_single_certificate(
                        certificate.as_bytes(),
                        &format!("Vault CA chain certificate {index}"),
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            (der, signed.ca_chain)
        };
        if parent_der.first() == Some(&leaf_der) {
            parent_der.remove(0);
            parent_pem.remove(0);
        }
        ensure!(
            parent_der.first() == Some(&issuing_ca_der),
            "Vault ca_chain does not begin with issuing_ca"
        );
        for (index, certificate) in parent_der.iter().enumerate() {
            ensure!(
                !parent_der[..index].contains(certificate),
                "Vault ca_chain contains a duplicate certificate"
            );
        }
        let pinned_root = parent_der.last().expect("parent chain is nonempty");
        ensure!(
            self.expected_roots
                .iter()
                .any(|expected| expected == pinned_root),
            "Vault returned a certificate chained to an unpinned root"
        );

        let mut der = Vec::with_capacity(parent_der.len() + 1);
        der.push(leaf_der);
        der.append(&mut parent_der);
        let mut pem = Vec::with_capacity(parent_pem.len() + 1);
        pem.push(signed.certificate);
        pem.append(&mut parent_pem);
        Ok(ParsedSignedChain { der, pem })
    }
}

impl VaultCaSource {
    pub(crate) fn new(vault: Arc<VaultClient>, config: VaultCaConfig) -> Result<Self> {
        let issuer = validate_api_path(&config.issuer, "Vault issuer")?;
        ensure!(
            !issuer.contains('/'),
            "Vault issuer must be one path segment"
        );
        Ok(Self {
            vault,
            issuer,
            intermediate_ttl: config.intermediate_ttl,
            renewal_threshold: config.renewal_threshold,
        })
    }

    pub(crate) async fn issue(&self) -> Result<Arc<CertificateAuthority>> {
        let (key, csr) = tokio::task::spawn_blocking(build_intermediate_csr)
            .await
            .context("intermediate CSR worker failed")??;
        let token = self.vault.authenticate().await?;
        let url = self.sign_intermediate_url()?;
        let ttl = format!("{}s", self.intermediate_ttl.as_secs());
        let body = SignIntermediateRequest {
            csr: &csr,
            common_name: "ExfilGuard Intermediate CA",
            exclude_cn_from_sans: true,
            format: "pem",
            max_path_length: 0,
            remove_roots_from_chain: false,
            ttl,
        };
        let response: SignIntermediateResponse = self
            .vault
            .post_json(url, token.as_deref().map(|value| value.as_str()), &body)
            .await
            .map_err(|err| vault_failure("signing", err))?;
        drop(token);

        let chain = self
            .vault
            .parse_signed_chain(response.data, "Vault intermediate certificate")
            .map_err(|err| vault_failure("validation", err))?;
        let ca = CertificateAuthority::from_chain(chain.der, key)
            .map_err(|err| vault_failure("validation", err))?;
        let remaining = ca.intermediate_not_after() - OffsetDateTime::now_utc();
        let threshold = time::Duration::try_from(self.renewal_threshold)
            .map_err(|_| anyhow!("Vault renewal threshold is too large"))?;
        if remaining <= threshold {
            return Err(vault_failure(
                "validation",
                "Vault intermediate expires too soon for the configured renewal threshold",
            ));
        }
        Ok(Arc::new(ca))
    }

    pub(crate) fn spawn_renewal(self: Arc<Self>, issuer: Arc<TlsIssuer>) {
        tokio::spawn(async move {
            self.renewal_loop(issuer).await;
        });
    }

    async fn renewal_loop(&self, issuer: Arc<TlsIssuer>) {
        let mut retry_delay = INITIAL_RETRY_DELAY;
        loop {
            let threshold =
                time::Duration::try_from(self.renewal_threshold).unwrap_or(time::Duration::days(1));
            let waited_for_schedule = wait_until_renewal_with(
                || issuer.current_ca().intermediate_not_after(),
                threshold,
                OffsetDateTime::now_utc,
                sleep,
            )
            .await;
            if waited_for_schedule {
                // A normally scheduled attempt starts fresh. An overdue retry retains its backoff.
                retry_delay = INITIAL_RETRY_DELAY;
            }

            match self.renew_once(&issuer).await {
                Ok(generation) => {
                    crate::metrics::record_ca_vault_renewal("success", "none");
                    info!(generation, "renewed Vault-backed CA intermediate");
                    retry_delay = INITIAL_RETRY_DELAY;
                    continue;
                }
                Err(err) => {
                    let kind = failure_kind(&err);
                    crate::metrics::record_ca_vault_renewal("failure", kind);
                    if kind == "generation" {
                        error!(error = %err, "failed to publish renewed CA generation");
                    } else {
                        warn!(reason = kind, error = %err, "Vault CA renewal failed");
                    }
                }
            }

            let usable = issuer.current_ca().intermediate_not_after()
                > OffsetDateTime::now_utc() + time::Duration::minutes(5);
            crate::metrics::set_ca_issuer_usable(usable);
            sleep(with_jitter(retry_delay)).await;
            retry_delay = retry_delay.saturating_mul(2).min(MAX_RETRY_DELAY);
        }
    }

    async fn renew_once(&self, issuer: &TlsIssuer) -> Result<u64> {
        let ca = self.issue().await?;
        let root_not_after = ca.root_not_after().unix_timestamp();
        let intermediate_not_after = ca.intermediate_not_after().unix_timestamp();
        let generation = issuer
            .replace_ca(ca)
            .map_err(|err| vault_failure("generation", err))?;
        crate::metrics::set_ca_state(
            "vault",
            root_not_after,
            intermediate_not_after,
            true,
            generation,
        );
        Ok(generation)
    }

    fn sign_intermediate_url(&self) -> Result<Url> {
        let mut segments: Vec<&str> = self.vault.pki_mount.split('/').collect();
        segments.extend(["issuer", self.issuer.as_str(), "sign-intermediate"]);
        api_url(&self.vault.base_url, &segments)
    }
}

pub(crate) async fn wait_until_renewal_due(
    not_after: OffsetDateTime,
    threshold: time::Duration,
) -> bool {
    wait_until_renewal_with(|| not_after, threshold, OffsetDateTime::now_utc, sleep).await
}

async fn wait_until_renewal_with<NotAfter, Now, SleepFor, SleepFuture>(
    mut intermediate_not_after: NotAfter,
    threshold: time::Duration,
    mut now: Now,
    mut sleep_for: SleepFor,
) -> bool
where
    NotAfter: FnMut() -> OffsetDateTime,
    Now: FnMut() -> OffsetDateTime,
    SleepFor: FnMut(StdDuration) -> SleepFuture,
    SleepFuture: Future<Output = ()>,
{
    let mut slept = false;
    loop {
        let renew_at = intermediate_not_after() - threshold;
        let remaining = renew_at - now();
        if remaining <= time::Duration::ZERO {
            return slept;
        }
        let wait = StdDuration::try_from(remaining)
            .unwrap_or(MAX_RENEWAL_SCHEDULE_SLEEP)
            .min(MAX_RENEWAL_SCHEDULE_SLEEP);
        sleep_for(wait).await;
        slept = true;
    }
}

pub(crate) fn with_jitter(delay: StdDuration) -> StdDuration {
    let sample = SysRng.try_next_u64().unwrap_or(500) % 501;
    delay.mul_f64(0.75 + sample as f64 / 1000.0)
}

fn build_intermediate_csr() -> Result<(KeyPair, String)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|err| anyhow!("failed to generate Vault intermediate key: {err}"))?;
    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "ExfilGuard Intermediate CA");
    params.distinguished_name = name;
    let csr = params
        .serialize_request(&key)
        .map_err(|err| anyhow!("failed to generate Vault intermediate CSR: {err}"))?
        .pem()
        .map_err(|err| anyhow!("failed to encode Vault intermediate CSR: {err}"))?;
    Ok((key, csr))
}

fn build_client_csr(common_name: &str) -> Result<(KeyPair, String)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|err| anyhow!("failed to generate Vault client key: {err}"))?;
    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    params.distinguished_name = name;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let csr = params
        .serialize_request(&key)
        .map_err(|err| anyhow!("failed to generate Vault client CSR: {err}"))?
        .pem()
        .map_err(|err| anyhow!("failed to encode Vault client CSR: {err}"))?;
    Ok((key, csr))
}

fn validate_single_api_segment(value: &str, name: &str) -> Result<String> {
    let value = validate_api_path(value, name)?;
    ensure!(!value.contains('/'), "{name} must be one path segment");
    Ok(value)
}

fn validate_api_path(value: &str, name: &str) -> Result<String> {
    let trimmed = value.trim_matches('/');
    ensure!(!trimmed.is_empty(), "{name} must not be empty");
    for segment in trimmed.split('/') {
        ensure!(
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "{name} contains an unsafe path segment"
        );
    }
    Ok(trimmed.to_string())
}

fn api_url(base: &Url, segments: &[&str]) -> Result<Url> {
    let mut url = base.clone();
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| anyhow!("Vault address cannot be a base URL"))?;
        path.clear().push("v1");
        for segment in segments {
            for part in segment.split('/') {
                ensure!(!part.is_empty(), "Vault API path contains an empty segment");
                path.push(part);
            }
        }
    }
    Ok(url)
}

async fn read_limited_response(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_VAULT_RESPONSE_BYTES as u64)
    {
        bail!("Vault response exceeded {MAX_VAULT_RESPONSE_BYTES} bytes");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read Vault response")?
    {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_VAULT_RESPONSE_BYTES,
            "Vault response exceeded {MAX_VAULT_RESPONSE_BYTES} bytes"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn read_secret_value(path: &Path) -> Result<Zeroizing<String>> {
    let mut file = open_checked_file(path, true)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        metadata.len() <= MAX_CREDENTIAL_BYTES,
        "Vault credential {} is too large",
        path.display()
    );
    let mut value = Zeroizing::new(String::with_capacity(metadata.len() as usize));
    file.read_to_string(&mut value)
        .with_context(|| format!("Vault credential {} is not UTF-8", path.display()))?;
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    } else if value.ends_with('\r') {
        value.pop();
    }
    validate_secret_value(&value, &format!("Vault credential {}", path.display()))?;
    Ok(value)
}

fn validate_secret_value(value: &str, name: &str) -> Result<()> {
    ensure!(!value.is_empty(), "{name} is empty");
    ensure!(
        value.len() <= MAX_CREDENTIAL_BYTES as usize,
        "{name} is too large"
    );
    ensure!(
        !value
            .bytes()
            .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n')),
        "{name} contains an embedded newline or NUL"
    );
    ensure!(
        value.trim() == value,
        "{name} contains surrounding whitespace"
    );
    Ok(())
}

pub(crate) fn read_secret_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = open_checked_file(path, true)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        metadata.len() <= MAX_CREDENTIAL_BYTES,
        "secret file {} is too large",
        path.display()
    );
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(bytes)
}

fn read_public_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = open_checked_file(path, false)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(bytes)
}

pub(crate) fn read_public_certificate_bundle(path: &Path) -> Result<Vec<Vec<u8>>> {
    let bytes = read_public_file(path)?;
    super::validation::parse_strict_certificate_pem_bundle(
        &bytes,
        &format!("certificate bundle {}", path.display()),
    )
}

fn parse_single_certificate(bytes: &[u8], name: &str) -> Result<Vec<u8>> {
    let mut certificates = super::validation::parse_strict_certificate_pem_bundle(bytes, name)?;
    ensure!(
        certificates.len() == 1,
        "{name} contains more than one certificate"
    );
    Ok(certificates.pop().expect("length checked"))
}

fn open_checked_file(path: &Path, secret: bool) -> Result<File> {
    let link_metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        !link_metadata.file_type().is_symlink(),
        "{} must not be a symlink",
        path.display()
    );
    validate_checked_metadata(path, &link_metadata, secret)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to securely open {}", path.display()))?;
    validate_checked_metadata(path, &file.metadata()?, secret)?;
    Ok(file)
}

fn validate_checked_metadata(path: &Path, metadata: &Metadata, secret: bool) -> Result<()> {
    ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        path.display()
    );
    let expected_uid = geteuid().as_raw();
    if secret {
        ensure!(
            metadata.uid() == expected_uid,
            "secret file {} must be owned by UID {}",
            path.display(),
            expected_uid
        );
        let mode = metadata.mode() & 0o7777;
        ensure!(
            matches!(mode, 0o400 | 0o600),
            "secret file {} has mode {:04o}; expected 0400 or 0600",
            path.display(),
            mode
        );
    } else {
        ensure!(
            matches!(metadata.uid(), 0) || metadata.uid() == expected_uid,
            "public trust file {} must be owned by root or UID {}",
            path.display(),
            expected_uid
        );
        let mode = metadata.mode() & 0o7777;
        ensure!(
            mode & 0o400 != 0 && mode & 0o7133 == 0,
            "public trust file {} has unsafe mode {:04o}",
            path.display(),
            mode
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    use std::rc::Rc;

    use rcgen::{BasicConstraints, CertificateSigningRequestParams, IsCa, Issuer, KeyUsagePurpose};
    use serde_json::{Value, json};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::tls::cache::CertificateCache;

    fn initial_issuer(directory: &TempDir) -> Arc<TlsIssuer> {
        let ca = Arc::new(
            CertificateAuthority::load_builtin(directory.path().join("initial-ca")).unwrap(),
        );
        let cache = Arc::new(CertificateCache::new(16).unwrap());
        Arc::new(TlsIssuer::new(ca, cache, StdDuration::from_secs(3600), 2).unwrap())
    }

    struct RawRequest {
        method: String,
        target: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    async fn read_request(stream: &mut TcpStream) -> RawRequest {
        let mut bytes = Vec::new();
        let header_end = loop {
            if let Some(offset) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break offset + 4;
            }
            let mut buffer = [0_u8; 4096];
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0, "connection closed before request headers");
            bytes.extend_from_slice(&buffer[..read]);
        };

        let head = std::str::from_utf8(&bytes[..header_end]).unwrap();
        let mut lines = head.split("\r\n");
        let mut request_line = lines.next().unwrap().split_ascii_whitespace();
        let method = request_line.next().unwrap().to_string();
        let target = request_line.next().unwrap().to_string();
        assert_eq!(request_line.next(), Some("HTTP/1.1"));
        let headers: HashMap<_, _> = lines
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (name, value) = line.split_once(':').unwrap();
                (name.to_ascii_lowercase(), value.trim().to_string())
            })
            .collect();
        let content_length = headers
            .get("content-length")
            .map(|value| value.parse::<usize>().unwrap())
            .unwrap_or_default();
        while bytes.len() < header_end + content_length {
            let mut buffer = [0_u8; 4096];
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0, "connection closed before request body");
            bytes.extend_from_slice(&buffer[..read]);
        }

        RawRequest {
            method,
            target,
            headers,
            body: bytes[header_end..header_end + content_length].to_vec(),
        }
    }

    async fn respond_json(stream: &mut TcpStream, body: Value) {
        let body = serde_json::to_vec(&body).unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
    }

    fn ca_params(common_name: &str, path_length: u8, lifetime_days: i64) -> CertificateParams {
        let now = OffsetDateTime::now_utc();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, common_name);
        let mut params = CertificateParams::default();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(lifetime_days);
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_length));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
    }

    fn generate_root(common_name: &str) -> (String, Vec<u8>, Issuer<'static, KeyPair>) {
        let params = ca_params(common_name, 1, 90);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let certificate = params.self_signed(&key).unwrap();
        let pem = certificate.pem();
        let der = certificate.der().as_ref().to_vec();
        (pem, der, Issuer::new(params, key))
    }

    fn generate_vault_signing_hierarchy()
    -> (String, Vec<u8>, String, Vec<u8>, Issuer<'static, KeyPair>) {
        let root_params = ca_params("Pinned Root", 2, 90);
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::from_params(&root_params, &root_key);

        let signer_params = ca_params("Vault Signing Issuer", 1, 60);
        let signer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let signer_cert = signer_params.signed_by(&signer_key, &root_issuer).unwrap();
        (
            root_cert.pem(),
            root_cert.der().as_ref().to_vec(),
            signer_cert.pem(),
            signer_cert.der().as_ref().to_vec(),
            Issuer::new(signer_params, signer_key),
        )
    }

    async fn spawn_fake_vault(
        issuing_ca_pem: String,
        ca_chain: Vec<String>,
        signing_issuer: Issuer<'static, KeyPair>,
        include_issued_intermediate_in_chain: bool,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut login_stream, _) = listener.accept().await.unwrap();
            let login = read_request(&mut login_stream).await;
            assert_eq!(login.method, "POST");
            assert_eq!(login.target, "/v1/auth/team-approle/login");
            assert_eq!(login.headers.get("x-vault-request").unwrap(), "true");
            assert_eq!(login.headers.get("x-vault-namespace").unwrap(), "team-a");
            assert!(!login.headers.contains_key("x-vault-token"));
            assert_eq!(
                serde_json::from_slice::<Value>(&login.body).unwrap(),
                json!({"role_id": "test-role", "secret_id": "test-secret"})
            );
            respond_json(
                &mut login_stream,
                json!({"auth": {"client_token": "one-use-token"}}),
            )
            .await;

            let (mut sign_stream, _) = listener.accept().await.unwrap();
            let sign = read_request(&mut sign_stream).await;
            assert_eq!(sign.method, "POST");
            assert_eq!(
                sign.target,
                "/v1/team/pki/issuer/selected-issuer/sign-intermediate"
            );
            assert_eq!(sign.headers.get("x-vault-request").unwrap(), "true");
            assert_eq!(sign.headers.get("x-vault-namespace").unwrap(), "team-a");
            assert_eq!(sign.headers.get("x-vault-token").unwrap(), "one-use-token");

            let body: Value = serde_json::from_slice(&sign.body).unwrap();
            assert_eq!(body["common_name"], "ExfilGuard Intermediate CA");
            assert_eq!(body["exclude_cn_from_sans"], true);
            assert_eq!(body["format"], "pem");
            assert_eq!(body["max_path_length"], 0);
            assert_eq!(body["remove_roots_from_chain"], false);
            assert_eq!(body["ttl"], "2592000s");

            let mut request = CertificateSigningRequestParams::from_pem(
                body["csr"].as_str().expect("CSR must be a string"),
            )
            .unwrap();
            let now = OffsetDateTime::now_utc();
            request.params.not_before = now - time::Duration::hours(1);
            request.params.not_after = now + time::Duration::days(30);
            request.params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            request.params.key_usages =
                vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let intermediate = request.signed_by(&signing_issuer).unwrap();
            let intermediate_pem = intermediate.pem();
            let mut ca_chain = ca_chain;
            if include_issued_intermediate_in_chain {
                ca_chain.insert(0, intermediate_pem.clone());
            }
            respond_json(
                &mut sign_stream,
                json!({
                    "data": {
                        "certificate": intermediate_pem,
                        "issuing_ca": issuing_ca_pem,
                        "ca_chain": ca_chain,
                    }
                }),
            )
            .await;
        });
        (address, server)
    }

    async fn spawn_fake_vault_client_signer(
        issuing_ca_pem: String,
        ca_chain: Vec<String>,
        signing_issuer: Issuer<'static, KeyPair>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut login_stream, _) = listener.accept().await.unwrap();
            let login = read_request(&mut login_stream).await;
            assert_eq!(login.target, "/v1/auth/team-approle/login");
            respond_json(
                &mut login_stream,
                json!({"auth": {"client_token": "one-use-token"}}),
            )
            .await;

            let (mut sign_stream, _) = listener.accept().await.unwrap();
            let sign = read_request(&mut sign_stream).await;
            assert_eq!(sign.target, "/v1/team/pki/sign/authorization-client");
            assert_eq!(sign.headers.get("x-vault-token").unwrap(), "one-use-token");
            let body: Value = serde_json::from_slice(&sign.body).unwrap();
            assert_eq!(body["common_name"], "exfilguard-production");
            assert_eq!(body["exclude_cn_from_sans"], true);
            assert_eq!(body["format"], "pem");
            assert_eq!(body["remove_roots_from_chain"], false);

            let mut request = CertificateSigningRequestParams::from_pem(
                body["csr"].as_str().expect("CSR must be a string"),
            )
            .unwrap();
            let now = OffsetDateTime::now_utc();
            request.params.not_before = now - time::Duration::minutes(1);
            request.params.not_after = now + time::Duration::hours(12);
            request.params.is_ca = IsCa::NoCa;
            request.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            request.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let certificate = request.signed_by(&signing_issuer).unwrap();
            respond_json(
                &mut sign_stream,
                json!({
                    "data": {
                        "certificate": certificate.pem(),
                        "issuing_ca": issuing_ca_pem,
                        "ca_chain": ca_chain,
                    }
                }),
            )
            .await;
        });
        (address, server)
    }

    fn write_file(directory: &TempDir, name: &str, contents: &[u8]) -> PathBuf {
        let path = directory.path().join(name);
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn vault_config(address: String, roots: PathBuf, secret_id_file: PathBuf) -> VaultConfig {
        VaultConfig {
            address,
            tls_ca_cert: None,
            tls_server_name: None,
            namespace: Some("team-a".to_string()),
            pki_mount: "team/pki".to_string(),
            expected_root_certs: roots,
            request_timeout: StdDuration::from_secs(5),
            tls_client_cert: None,
            tls_client_key: None,
            auth: VaultAuthConfig::AppRole {
                mount: "team-approle".to_string(),
                role_id: "test-role".to_string(),
                secret_id_file,
            },
        }
    }

    fn vault_ca_config() -> VaultCaConfig {
        VaultCaConfig {
            issuer: "selected-issuer".to_string(),
            intermediate_ttl: StdDuration::from_secs(30 * 24 * 60 * 60),
            renewal_threshold: StdDuration::from_secs(7 * 24 * 60 * 60),
        }
    }

    fn vault_ca_source(
        address: String,
        roots: PathBuf,
        secret_id_file: PathBuf,
    ) -> Result<VaultCaSource> {
        let vault = Arc::new(VaultClient::new(vault_config(
            address,
            roots,
            secret_id_file,
        ))?);
        VaultCaSource::new(vault, vault_ca_config())
    }

    #[tokio::test]
    async fn renewal_schedule_caps_sleep_and_rechecks_after_wall_clock_jump() {
        let start = OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap();
        let clock = Rc::new(Cell::new(start));
        let sleeps = Rc::new(RefCell::new(Vec::new()));
        let sleep_clock = clock.clone();
        let recorded_sleeps = sleeps.clone();

        wait_until_renewal_with(
            || start + time::Duration::hours(4),
            time::Duration::hours(1),
            {
                let clock = clock.clone();
                move || clock.get()
            },
            move |duration| {
                let clock = sleep_clock.clone();
                let sleeps = recorded_sleeps.clone();
                async move {
                    sleeps.borrow_mut().push(duration);
                    clock.set(start + time::Duration::hours(3));
                }
            },
        )
        .await;

        assert_eq!(sleeps.borrow().as_slice(), &[MAX_RENEWAL_SCHEDULE_SLEEP]);
    }

    #[tokio::test]
    async fn renewal_schedule_repeats_bounded_sleeps_until_threshold() {
        let start = OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap();
        let clock = Rc::new(Cell::new(start));
        let sleeps = Rc::new(RefCell::new(Vec::new()));
        let sleep_clock = clock.clone();
        let recorded_sleeps = sleeps.clone();

        wait_until_renewal_with(
            || start + time::Duration::hours(4),
            time::Duration::hours(1),
            {
                let clock = clock.clone();
                move || clock.get()
            },
            move |duration| {
                let clock = sleep_clock.clone();
                let sleeps = recorded_sleeps.clone();
                async move {
                    sleeps.borrow_mut().push(duration);
                    clock.set(clock.get() + time::Duration::try_from(duration).unwrap());
                }
            },
        )
        .await;

        assert_eq!(
            sleeps.borrow().as_slice(),
            &[
                MAX_RENEWAL_SCHEDULE_SLEEP,
                MAX_RENEWAL_SCHEDULE_SLEEP,
                MAX_RENEWAL_SCHEDULE_SLEEP,
            ]
        );
    }

    #[tokio::test]
    async fn renewal_schedule_reports_when_renewal_is_already_due() {
        let now = OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap();

        let slept = wait_until_renewal_with(
            || now + time::Duration::hours(1),
            time::Duration::hours(1),
            || now,
            |_| async { panic!("already-due renewal must not sleep") },
        )
        .await;

        assert!(!slept);
    }

    #[test]
    fn validates_api_paths() {
        assert_eq!(validate_api_path("team/pki", "mount").unwrap(), "team/pki");
        for invalid in ["", "/", "pki//nested", "pki/../root", "pki?bad"] {
            assert!(validate_api_path(invalid, "mount").is_err(), "{invalid}");
        }
    }

    #[test]
    fn constructs_encoded_api_urls() {
        let base = Url::parse("https://vault.example/ignored").unwrap();
        let url = api_url(
            &base,
            &["pki", "issuer", "issuer name", "sign-intermediate"],
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://vault.example/v1/pki/issuer/issuer%20name/sign-intermediate"
        );
    }

    #[test]
    fn rejects_ambiguous_secret_values() {
        assert!(validate_secret_value("token", "token").is_ok());
        for invalid in ["", " token", "token ", "a\nb", "a\0b"] {
            assert!(
                validate_secret_value(invalid, "token").is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn secret_file_reader_rejects_permissive_and_symlinked_keys() {
        let directory = TempDir::new().unwrap();
        let key = write_file(&directory, "client.key", b"private key");
        assert_eq!(read_secret_bytes(&key).unwrap().as_slice(), b"private key");

        std::fs::set_permissions(&key, Permissions::from_mode(0o644)).unwrap();
        assert!(read_secret_bytes(&key).is_err());
        std::fs::set_permissions(&key, Permissions::from_mode(0o600)).unwrap();

        let link = directory.path().join("client-link.key");
        std::os::unix::fs::symlink(&key, &link).unwrap();
        assert!(read_secret_bytes(&link).is_err());
    }

    #[test]
    fn rejects_plaintext_remote_vault_address() {
        let config = vault_config(
            "http://192.0.2.10:8200".to_string(),
            PathBuf::from("unused-roots.pem"),
            PathBuf::from("unused-secret-id"),
        );
        let error = match VaultClient::new(config) {
            Ok(_) => panic!("remote plaintext Vault must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("loopback"), "{error:#}");
    }

    #[tokio::test]
    async fn approle_renewal_swaps_in_the_selected_issuer_chain() {
        let directory = TempDir::new().unwrap();
        let (root_pem, root_der, signer_pem, signer_der, signer_issuer) =
            generate_vault_signing_hierarchy();
        let roots = write_file(&directory, "roots.pem", root_pem.as_bytes());
        let secret_id = write_file(&directory, "secret-id", b"test-secret\n");
        let (address, server) = spawn_fake_vault(
            signer_pem.clone(),
            vec![signer_pem, root_pem],
            signer_issuer,
            false,
        )
        .await;

        let source = vault_ca_source(address, roots, secret_id).unwrap();
        let issuer = initial_issuer(&directory);
        let old_leaf = issuer.issue(&["renew.example"]).await.unwrap();
        assert_eq!(source.renew_once(&issuer).await.unwrap(), 1);
        let authority = issuer.current_ca();

        assert_eq!(authority.root_certificate_der().as_ref(), root_der);
        let chain = authority.certificate_chain();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[1].as_ref(), signer_der);
        assert_eq!(chain[2].as_ref(), root_der);
        assert!(authority.intermediate_not_after() > OffsetDateTime::now_utc());
        let new_leaf = issuer.issue(&["renew.example"]).await.unwrap();
        assert!(!Arc::ptr_eq(&old_leaf, &new_leaf));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn signs_a_client_certificate_without_exporting_its_private_key() {
        let directory = TempDir::new().unwrap();
        let (root_pem, _, signer_pem, _, signer_issuer) = generate_vault_signing_hierarchy();
        let roots = write_file(&directory, "roots.pem", root_pem.as_bytes());
        let secret_id = write_file(&directory, "secret-id", b"test-secret");
        let (address, server) = spawn_fake_vault_client_signer(
            signer_pem.clone(),
            vec![signer_pem, root_pem],
            signer_issuer,
        )
        .await;
        let vault = VaultClient::new(vault_config(address, roots, secret_id)).unwrap();

        let certificate = vault
            .issue_client_certificate("authorization-client", "exfilguard-production")
            .await
            .unwrap();

        assert!(certificate.validity.not_before < OffsetDateTime::now_utc());
        assert!(certificate.validity.not_after > OffsetDateTime::now_utc());
        let identity = std::str::from_utf8(&certificate.identity_pem).unwrap();
        assert_eq!(identity.matches("BEGIN CERTIFICATE").count(), 2);
        assert!(identity.contains("BEGIN PRIVATE KEY"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn accepts_ca_chain_that_begins_with_the_issued_intermediate() {
        let directory = TempDir::new().unwrap();
        let (root_pem, root_der, root_issuer) = generate_root("Pinned Root");
        let roots = write_file(&directory, "roots.pem", root_pem.as_bytes());
        let secret_id = write_file(&directory, "secret-id", b"test-secret\n");
        let (address, server) =
            spawn_fake_vault(root_pem.clone(), vec![root_pem], root_issuer, true).await;

        let source = vault_ca_source(address, roots, secret_id).unwrap();
        let authority = source.issue().await.unwrap();

        assert_eq!(authority.root_certificate_der().as_ref(), root_der);
        let chain = authority.certificate_chain();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].as_ref(), root_der);
        authority
            .mint_leaf(&["echoed-chain.example"], StdDuration::from_secs(60 * 60))
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_duplicate_parents_after_removing_the_issued_intermediate() {
        let directory = TempDir::new().unwrap();
        let (root_pem, _, root_issuer) = generate_root("Pinned Root");
        let roots = write_file(&directory, "roots.pem", root_pem.as_bytes());
        let secret_id = write_file(&directory, "secret-id", b"test-secret\n");
        let (address, server) = spawn_fake_vault(
            root_pem.clone(),
            vec![root_pem.clone(), root_pem],
            root_issuer,
            true,
        )
        .await;

        let source = vault_ca_source(address, roots, secret_id).unwrap();
        let error = match source.issue().await {
            Ok(_) => panic!("duplicate parent certificates must be rejected"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("duplicate certificate"),
            "unexpected error: {error:#}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_an_intermediate_from_an_unpinned_root() {
        let directory = TempDir::new().unwrap();
        let (returned_root_pem, _, returned_root_issuer) = generate_root("Returned Root");
        let (pinned_root_pem, _, _) = generate_root("Pinned Root");
        let roots = write_file(&directory, "roots.pem", pinned_root_pem.as_bytes());
        let secret_id = write_file(&directory, "secret-id", b"test-secret");
        let (address, server) = spawn_fake_vault(
            returned_root_pem.clone(),
            vec![returned_root_pem],
            returned_root_issuer,
            false,
        )
        .await;

        let source = vault_ca_source(address, roots, secret_id).unwrap();
        let issuer = initial_issuer(&directory);
        let original = issuer.current_ca();
        let original_leaf = issuer.issue(&["retain.example"]).await.unwrap();
        let error = match source.renew_once(&issuer).await {
            Ok(_) => panic!("an unpinned root must be rejected"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("unpinned root"),
            "unexpected error: {error:#}"
        );
        assert_eq!(issuer.generation(), 0);
        assert!(Arc::ptr_eq(&issuer.current_ca(), &original));
        assert!(Arc::ptr_eq(
            &issuer.issue(&["retain.example"]).await.unwrap(),
            &original_leaf
        ));
        server.await.unwrap();
    }
}
