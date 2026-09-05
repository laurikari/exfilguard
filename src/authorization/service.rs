use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use http::{Method, StatusCode};
use lru::LruCache;
use reqwest::redirect::Policy as RedirectPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore, watch};
use tokio::time::{Instant, sleep, timeout, timeout_at};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::{
    config::{MethodMatch, RuleAction},
    tls::validation::ClientCertificateValidity,
    util::normalize_mapped_ip,
};

use super::FinalizedRequestV1;
use super::config::{
    AuthorizationClientCertificateSettings, AuthorizationServiceSettings, AuthorizationSettings,
    buffered_body_memory_reservation,
};
use super::credentials::CredentialPreparerClient;
use super::policy::{
    CredentialAuthorization, DynamicPolicy, build_dynamic_credential, make_dynamic_rule,
};

const AUTHORIZATION_SCHEME: &str = "ExfilGuard";
const MAX_POLICY_VERSION_SIZE: usize = 128;

pub(crate) struct AuthorizationToken {
    token: Zeroizing<String>,
    hash: [u8; 32],
    correlation: Arc<str>,
}

impl std::fmt::Debug for AuthorizationToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationToken")
            .field("correlation", &self.correlation)
            .finish_non_exhaustive()
    }
}

impl AuthorizationToken {
    pub(crate) fn parse(value: &[u8], max_size: usize) -> Result<Arc<Self>, AuthorizationError> {
        if value.len() > max_size {
            return Err(AuthorizationError::Denied);
        }
        let value = std::str::from_utf8(value).map_err(|_| AuthorizationError::Denied)?;
        let Some((scheme, token)) = value.split_once(' ') else {
            return Err(AuthorizationError::Denied);
        };
        if !scheme.eq_ignore_ascii_case(AUTHORIZATION_SCHEME)
            || token.is_empty()
            || token.contains(char::is_whitespace)
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(AuthorizationError::Denied);
        }
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let correlation: String = hash[..8].iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Arc::new(Self {
            token: Zeroizing::new(token.to_string()),
            hash,
            correlation: Arc::from(correlation),
        }))
    }

    pub(crate) fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub(crate) fn correlation(&self) -> &str {
        &self.correlation
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }
}

pub(crate) struct ResolvedAuthorizationPolicy {
    pub(crate) dynamic: DynamicPolicy,
    pub(crate) policy_version: Arc<str>,
    wall_valid_until: u64,
    valid_until: Instant,
}

impl ResolvedAuthorizationPolicy {
    fn is_valid(&self) -> bool {
        Instant::now() < self.valid_until
            && unix_now().is_some_and(|now| now < self.wall_valid_until)
    }

    #[cfg(test)]
    pub(crate) fn from_test_rules(rules: Vec<crate::config::Rule>) -> Arc<Self> {
        let now = unix_now().unwrap();
        Arc::new(Self {
            dynamic: DynamicPolicy::compile_rules(rules).unwrap(),
            policy_version: Arc::from("test-policy"),
            wall_valid_until: now + 60,
            valid_until: Instant::now() + Duration::from_secs(60),
        })
    }
}

#[derive(Debug, Clone, Copy, Error)]
pub(crate) enum AuthorizationError {
    #[error("proxy authorization denied")]
    Denied,
    #[error("proxy authorization service unavailable")]
    Unavailable,
    #[error("proxy authorization timed out")]
    Timeout,
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    token_hash: [u8; 32],
    source_ip: IpAddr,
}

enum CacheEntry {
    Positive(Arc<ResolvedAuthorizationPolicy>),
    Negative { valid_until: Instant },
}

type ResolutionResult = Result<Arc<ResolvedAuthorizationPolicy>, AuthorizationError>;
type SharedResolution = watch::Receiver<Option<ResolutionResult>>;

struct CacheState {
    entries: LruCache<CacheKey, CacheEntry>,
    pending: HashMap<CacheKey, SharedResolution>,
    pending_capacity: usize,
}

#[derive(Clone, Serialize)]
struct PolicyRequest<'a> {
    authorization_token: &'a str,
    audience: &'a str,
    source_ip: IpAddr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyResponse {
    active: bool,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    client_constraints: Option<ClientConstraints>,
    #[serde(default)]
    expires_at: Option<u64>,
    #[serde(default)]
    cache_until: Option<u64>,
    #[serde(default)]
    policy_version: Option<String>,
    #[serde(default)]
    rules: Vec<DynamicRuleWire>,
}

enum PolicyResponseError {
    Denied,
    Invalid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConstraints {
    #[serde(default)]
    source_ip: Option<IpAddr>,
    #[serde(default)]
    authenticated_client_identity: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DynamicRuleWire {
    action: DynamicAction,
    #[serde(default)]
    methods: Option<Vec<String>>,
    #[serde(default)]
    url_pattern: Option<String>,
    #[serde(default)]
    credential: Option<DynamicCredentialWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum DynamicAction {
    Allow,
    Deny,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DynamicCredentialWire {
    credential_reference: String,
    protected_headers: Vec<String>,
    #[serde(default)]
    body_access: crate::config::BodyAccess,
}

#[async_trait]
trait PolicyClient: Send + Sync {
    async fn resolve_policy(&self, request: PolicyRequest<'_>) -> Result<Vec<u8>>;
}

struct HttpsPolicyClient {
    client: AuthorizationHttpClient,
    url: reqwest::Url,
    concurrency: Arc<Semaphore>,
    max_response_size: usize,
    timeout: Duration,
}

#[async_trait]
impl PolicyClient for HttpsPolicyClient {
    async fn resolve_policy(&self, request: PolicyRequest<'_>) -> Result<Vec<u8>> {
        timeout(self.timeout, async {
            let _permit = self
                .concurrency
                .acquire()
                .await
                .context("authorization-service concurrency limiter closed")?;
            let client = self.client.current().await?;
            let response = client
                .post(self.url.clone())
                .json(&request)
                .send()
                .await
                .context("authorization-service policy request failed")?;
            ensure!(
                response.status().is_success(),
                "authorization service returned a non-success policy status"
            );
            read_bounded_response(response, self.max_response_size).await
        })
        .await
        .context("authorization-service policy operation timed out")?
    }
}

#[derive(Clone)]
pub(super) struct AuthorizationHttpClient {
    current: Arc<RwLock<ClientGeneration>>,
}

struct ClientGeneration {
    client: reqwest::Client,
    validity: Option<ClientCertificateValidity>,
}

impl AuthorizationHttpClient {
    fn new(client: reqwest::Client, validity: Option<ClientCertificateValidity>) -> Self {
        Self {
            current: Arc::new(RwLock::new(ClientGeneration { client, validity })),
        }
    }

    pub(super) async fn current(&self) -> Result<reqwest::Client> {
        let generation = self.current.read().await;
        if let Some(validity) = generation.validity {
            let now = OffsetDateTime::now_utc();
            ensure!(
                now >= validity.not_before && now < validity.not_after,
                "authorization-service client certificate is not currently valid"
            );
        }
        Ok(generation.client.clone())
    }

    async fn replace(&self, client: reqwest::Client, validity: ClientCertificateValidity) {
        *self.current.write().await = ClientGeneration {
            client,
            validity: Some(validity),
        };
    }
}

struct PolicyResolver {
    audience: Arc<str>,
    policy_client: Arc<dyn PolicyClient>,
    max_cache_duration: Duration,
    max_rules: usize,
    max_protected_headers: usize,
}

pub(crate) struct AuthorizationService {
    name: Arc<str>,
    audience: Arc<str>,
    resolver: Arc<PolicyResolver>,
    cache: Arc<Mutex<CacheState>>,
    negative_cache_duration: Duration,
    credential_preparer: CredentialPreparerClient,
    max_protected_headers: usize,
}

pub(crate) struct AuthorizationServices {
    services: HashMap<Arc<str>, Arc<AuthorizationService>>,
    max_token_header_size: usize,
    buffered_body_permits: Arc<Semaphore>,
    max_buffered_body_size: usize,
}

impl AuthorizationServices {
    pub(crate) async fn new(
        settings: &AuthorizationSettings,
        vault: Option<Arc<crate::tls::vault::VaultClient>>,
    ) -> Result<Self> {
        settings.validate()?;
        let mut services = HashMap::with_capacity(settings.services.len());
        for service in &settings.services {
            let name = Arc::<str>::from(service.name.as_str());
            services.insert(
                name,
                Arc::new(AuthorizationService::new(service, settings, vault.clone()).await?),
            );
        }
        Ok(Self {
            services,
            max_token_header_size: settings.max_token_header_size,
            buffered_body_permits: Arc::new(Semaphore::new(settings.max_buffered_body_capacity)),
            max_buffered_body_size: settings.max_buffered_body_size,
        })
    }

    pub(crate) fn service(&self, name: &str) -> Option<Arc<AuthorizationService>> {
        self.services.get(name).cloned()
    }

    pub(crate) fn parse_token(
        &self,
        proxy_authorization: &[u8],
    ) -> Result<Arc<AuthorizationToken>, AuthorizationError> {
        AuthorizationToken::parse(proxy_authorization, self.max_token_header_size)
    }

    pub(crate) async fn prepare_headers(
        &self,
        authorization: &CredentialAuthorization,
        request: &mut FinalizedRequestV1,
        peer: SocketAddr,
        max_header_bytes: usize,
    ) -> Result<()> {
        let service = self
            .services
            .get(&authorization.authorization_service)
            .context("credential decision references an unavailable authorization service")?;
        service
            .credential_preparer
            .prepare_headers(
                &service.audience,
                normalize_mapped_ip(peer.ip()),
                authorization,
                request,
                service.max_protected_headers,
                max_header_bytes,
            )
            .await
    }

    pub(crate) fn buffered_body_limit(&self, max_request_body_size: usize) -> usize {
        if max_request_body_size == 0 {
            self.max_buffered_body_size
        } else {
            self.max_buffered_body_size.min(max_request_body_size)
        }
    }

    pub(crate) async fn reserve_buffered_body(
        &self,
        payload_limit: usize,
    ) -> Result<OwnedSemaphorePermit> {
        let reservation = buffered_body_memory_reservation(payload_limit)?;
        let permits = u32::try_from(reservation)
            .context("credential body memory reservation exceeds semaphore limit")?;
        self.buffered_body_permits
            .clone()
            .acquire_many_owned(permits)
            .await
            .context("credential body memory limiter closed")
    }
}

impl AuthorizationService {
    async fn new(
        service: &AuthorizationServiceSettings,
        settings: &AuthorizationSettings,
        vault: Option<Arc<crate::tls::vault::VaultClient>>,
    ) -> Result<Self> {
        let name = Arc::<str>::from(service.name.as_str());
        let audience = Arc::<str>::from(service.audience.as_str());
        let client_config = AuthorizationClientConfig::load(service)?;
        let client = match &service.client_certificate {
            AuthorizationClientCertificateSettings::Files { cert, key } => {
                let identity = load_file_identity(cert, key)?;
                AuthorizationHttpClient::new(client_config.build(&identity)?, None)
            }
            AuthorizationClientCertificateSettings::Vault { role, common_name } => {
                let source = Arc::new(VaultAuthorizationClientSource {
                    vault: vault.context("Vault-backed client certificate requires [vault]")?,
                    role: role.clone(),
                    common_name: common_name.clone(),
                    service_name: name.clone(),
                    client_config,
                });
                let (initial, validity) = source
                    .issue()
                    .await
                    .with_context(|| {
                        format!(
                            "failed to initialize Vault-backed client certificate for authorization service '{}'",
                            service.name
                        )
                    })?;
                crate::metrics::set_authorization_service_client_certificate(
                    &name,
                    validity.not_after.unix_timestamp(),
                );
                let client = AuthorizationHttpClient::new(initial, Some(validity));
                source.spawn_renewal(client.clone(), validity);
                client
            }
        };
        let concurrency = Arc::new(Semaphore::new(service.max_concurrency));
        let policy_client: Arc<dyn PolicyClient> = Arc::new(HttpsPolicyClient {
            client: client.clone(),
            url: reqwest::Url::parse(&service.policy_url)?,
            concurrency: concurrency.clone(),
            max_response_size: settings.max_policy_response_size,
            timeout: Duration::from_secs(service.timeout),
        });
        let cache_capacity = NonZeroUsize::new(settings.policy_cache_capacity)
            .expect("validated nonzero policy cache capacity");
        Ok(Self {
            name,
            audience: audience.clone(),
            resolver: Arc::new(PolicyResolver {
                audience,
                policy_client,
                max_cache_duration: Duration::from_secs(settings.max_policy_cache_duration),
                max_rules: settings.max_policy_rules,
                max_protected_headers: settings.max_protected_headers,
            }),
            cache: Arc::new(Mutex::new(CacheState {
                entries: LruCache::new(cache_capacity),
                pending: HashMap::new(),
                pending_capacity: settings.policy_cache_capacity,
            })),
            negative_cache_duration: Duration::from_secs(settings.negative_cache_duration),
            credential_preparer: CredentialPreparerClient::new(
                service,
                client,
                concurrency,
                settings.max_credential_response_size,
            )?,
            max_protected_headers: settings.max_protected_headers,
        })
    }

    pub(crate) fn name(&self) -> &Arc<str> {
        &self.name
    }

    pub(crate) async fn resolve(
        &self,
        token: &Arc<AuthorizationToken>,
        peer: SocketAddr,
        request_deadline: Option<std::time::Instant>,
    ) -> Result<Arc<ResolvedAuthorizationPolicy>, AuthorizationError> {
        let source_ip = normalize_mapped_ip(peer.ip());
        let key = CacheKey {
            token_hash: token.hash(),
            source_ip,
        };

        let (mut resolution, new_resolution) = {
            let mut cache = self.cache.lock().await;
            let expired = if let Some(entry) = cache.entries.get(&key) {
                match entry {
                    CacheEntry::Positive(policy) if policy.is_valid() => {
                        return Ok(policy.clone());
                    }
                    CacheEntry::Negative { valid_until } if Instant::now() < *valid_until => {
                        return Err(AuthorizationError::Denied);
                    }
                    CacheEntry::Positive(_) | CacheEntry::Negative { .. } => true,
                }
            } else {
                false
            };
            if expired {
                cache.entries.pop(&key);
            }
            if let Some(resolution) = cache.pending.get(&key) {
                (resolution.clone(), None)
            } else {
                if cache.pending.len() >= cache.pending_capacity {
                    return Err(AuthorizationError::Unavailable);
                }
                let (sender, receiver) = watch::channel(None);
                cache.pending.insert(key.clone(), receiver.clone());
                (receiver, Some(sender))
            }
        };

        if let Some(sender) = new_resolution {
            let resolver = self.resolver.clone();
            let cache = self.cache.clone();
            let token = token.clone();
            let negative_cache_duration = self.negative_cache_duration;
            tokio::spawn(async move {
                let result = resolver.resolve_uncached(&token, peer, source_ip).await;
                let mut cache = cache.lock().await;
                cache.pending.remove(&key);
                match &result {
                    Ok(policy) => {
                        cache.entries.put(key, CacheEntry::Positive(policy.clone()));
                    }
                    Err(AuthorizationError::Denied) => {
                        cache.entries.put(
                            key,
                            CacheEntry::Negative {
                                valid_until: Instant::now() + negative_cache_duration,
                            },
                        );
                    }
                    Err(AuthorizationError::Unavailable | AuthorizationError::Timeout) => {}
                }
                drop(cache);
                let _ = sender.send(Some(result));
            });
        }

        wait_for_resolution(&mut resolution, request_deadline).await
    }
}

impl PolicyResolver {
    async fn resolve_uncached(
        &self,
        token: &AuthorizationToken,
        peer: SocketAddr,
        source_ip: IpAddr,
    ) -> Result<Arc<ResolvedAuthorizationPolicy>, AuthorizationError> {
        let bytes = self
            .policy_client
            .resolve_policy(PolicyRequest {
                authorization_token: token.token(),
                audience: &self.audience,
                source_ip,
            })
            .await
            .map_err(|error| {
                warn!(
                    peer = %peer,
                    authorization_token_id = token.correlation(),
                    error_category = "authorization_service_unavailable",
                    error = %error,
                    "authorization policy request failed"
                );
                AuthorizationError::Unavailable
            })?;
        match self.parse_response(&bytes, source_ip) {
            Ok(policy) => Ok(policy),
            Err(PolicyResponseError::Denied) => Err(AuthorizationError::Denied),
            Err(PolicyResponseError::Invalid) => {
                warn!(
                    peer = %peer,
                    authorization_token_id = token.correlation(),
                    error_category = "invalid_policy_response",
                    "authorization policy response rejected"
                );
                Err(AuthorizationError::Unavailable)
            }
        }
    }

    fn parse_response(
        &self,
        bytes: &[u8],
        source_ip: IpAddr,
    ) -> std::result::Result<Arc<ResolvedAuthorizationPolicy>, PolicyResponseError> {
        let response: PolicyResponse =
            serde_json::from_slice(bytes).map_err(|_| PolicyResponseError::Invalid)?;
        if !response.active {
            return Err(PolicyResponseError::Denied);
        }
        if response.audience.as_deref() != Some(self.audience.as_ref()) {
            return Err(PolicyResponseError::Invalid);
        }
        if let Some(constraints) = response.client_constraints.as_ref() {
            if let Some(constrained_source_ip) = constraints.source_ip
                && normalize_mapped_ip(constrained_source_ip) != source_ip
            {
                return Err(PolicyResponseError::Denied);
            }
            if constraints.authenticated_client_identity.is_some() {
                return Err(PolicyResponseError::Invalid);
            }
        }
        self.build_active_policy(response)
            .map_err(|_| PolicyResponseError::Invalid)
    }

    fn build_active_policy(
        &self,
        response: PolicyResponse,
    ) -> Result<Arc<ResolvedAuthorizationPolicy>> {
        let expires_at = response
            .expires_at
            .context("active authorization response missing expires_at")?;
        let cache_until = response
            .cache_until
            .context("active authorization response missing cache_until")?;
        let policy_version = response
            .policy_version
            .context("active authorization response missing policy_version")?;
        ensure!(
            !policy_version.is_empty()
                && policy_version.len() <= MAX_POLICY_VERSION_SIZE
                && policy_version.bytes().all(|byte| byte.is_ascii_graphic()),
            "policy_version must contain 1 to {MAX_POLICY_VERSION_SIZE} visible ASCII bytes"
        );
        let now_system = SystemTime::now();
        let now = now_system
            .duration_since(UNIX_EPOCH)
            .context("system time is before the Unix epoch")?
            .as_secs();
        ensure!(expires_at > now, "authorization policy is expired");
        ensure!(
            cache_until > now,
            "authorization policy cache lifetime is expired"
        );
        ensure!(
            !response.rules.is_empty() && response.rules.len() <= self.max_rules,
            "dynamic rule count is outside the configured limit"
        );

        let mut rules = Vec::with_capacity(response.rules.len());
        for (index, raw) in response.rules.into_iter().enumerate() {
            let methods = parse_methods(raw.methods)?;
            let url_pattern = raw
                .url_pattern
                .as_deref()
                .map(crate::config::parse_url_pattern)
                .transpose()
                .with_context(|| format!("dynamic rule {index} has invalid url_pattern"))?;
            let action = match raw.action {
                DynamicAction::Allow => RuleAction::Allow,
                DynamicAction::Deny => {
                    ensure!(
                        raw.credential.is_none(),
                        "dynamic deny rule {index} must not contain a credential"
                    );
                    RuleAction::Deny {
                        status: StatusCode::FORBIDDEN,
                        reason: None,
                        body: None,
                    }
                }
            };
            let credential = raw
                .credential
                .map(|credential| {
                    ensure!(
                        credential.protected_headers.len() <= self.max_protected_headers,
                        "dynamic rule {index} credential exceeds the protected-header count limit"
                    );
                    build_dynamic_credential(
                        credential.credential_reference,
                        credential.protected_headers,
                        credential.body_access,
                    )
                })
                .transpose()?;
            rules.push((
                make_dynamic_rule(index, action, methods, url_pattern),
                credential,
            ));
        }
        let dynamic = DynamicPolicy::compile(rules)?;
        let wall_valid_until = expires_at.min(cache_until);
        let ttl = bounded_cache_ttl(now_system, wall_valid_until, self.max_cache_duration)?;
        let valid_until = Instant::now()
            .checked_add(ttl)
            .context("authorization policy cache lifetime exceeds the monotonic clock range")?;

        Ok(Arc::new(ResolvedAuthorizationPolicy {
            dynamic,
            policy_version: Arc::from(policy_version),
            wall_valid_until,
            valid_until,
        }))
    }
}

async fn wait_for_resolution(
    resolution: &mut SharedResolution,
    request_deadline: Option<std::time::Instant>,
) -> ResolutionResult {
    loop {
        if let Some(result) = resolution.borrow().clone() {
            return match result {
                Ok(policy) if policy.is_valid() => Ok(policy),
                Ok(_) => Err(AuthorizationError::Denied),
                Err(error) => Err(error),
            };
        }
        let changed = resolution.changed();
        if let Some(deadline) = request_deadline {
            timeout_at(deadline.into(), changed)
                .await
                .map_err(|_| AuthorizationError::Timeout)?
                .map_err(|_| AuthorizationError::Unavailable)?;
        } else {
            changed.await.map_err(|_| AuthorizationError::Unavailable)?;
        }
    }
}

fn bounded_cache_ttl(
    now: SystemTime,
    wall_valid_until: u64,
    max_cache_duration: Duration,
) -> Result<Duration> {
    let wall_deadline = UNIX_EPOCH
        .checked_add(Duration::from_secs(wall_valid_until))
        .context("authorization policy cache deadline exceeds the system clock range")?;
    let ttl = wall_deadline
        .duration_since(now)
        .context("authorization policy cache lifetime is expired")?
        .min(max_cache_duration);
    ensure!(
        !ttl.is_zero(),
        "authorization policy cache lifetime is empty"
    );
    Ok(ttl)
}

pub(super) fn parse_methods(methods: Option<Vec<String>>) -> Result<MethodMatch> {
    let Some(methods) = methods else {
        return Ok(MethodMatch::Any);
    };
    ensure!(
        !methods.is_empty(),
        "dynamic methods array must not be empty"
    );
    if methods.len() == 1 && methods[0].eq_ignore_ascii_case("ANY") {
        return Ok(MethodMatch::Any);
    }
    let mut seen = std::collections::HashSet::new();
    let mut parsed = Vec::with_capacity(methods.len());
    for value in methods {
        ensure!(
            !value.eq_ignore_ascii_case("ANY"),
            "dynamic methods must not mix ANY with explicit methods"
        );
        let method = Method::from_bytes(value.to_ascii_uppercase().as_bytes())
            .with_context(|| format!("invalid dynamic HTTP method '{value}'"))?;
        ensure!(
            method != Method::CONNECT,
            "dynamic CONNECT rules are not supported"
        );
        ensure!(seen.insert(method.clone()), "duplicate dynamic HTTP method");
        parsed.push(method);
    }
    Ok(MethodMatch::List(parsed))
}

#[derive(Clone)]
struct AuthorizationClientConfig {
    roots: Arc<Vec<reqwest::Certificate>>,
    timeout: Duration,
}

impl AuthorizationClientConfig {
    fn load(settings: &AuthorizationServiceSettings) -> Result<Self> {
        let certificates =
            crate::tls::vault::read_public_certificate_bundle(&settings.server_ca_cert)
                .with_context(|| {
                    format!(
                        "failed to load authorization-service CA certificate {}",
                        settings.server_ca_cert.display()
                    )
                })?;
        let roots = certificates
            .iter()
            .map(|certificate| {
                reqwest::Certificate::from_der(certificate)
                    .context("failed to parse authorization-service CA certificate")
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            roots: Arc::new(roots),
            timeout: Duration::from_secs(settings.timeout),
        })
    }

    fn build(&self, identity_pem: &[u8]) -> Result<reqwest::Client> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let identity = reqwest::Identity::from_pem(identity_pem)
            .context("failed to parse authorization-service client identity")?;
        reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(RedirectPolicy::none())
            .tls_certs_only(self.roots.iter().cloned())
            .identity(identity)
            .timeout(self.timeout)
            .connect_timeout(self.timeout)
            .build()
            .context("failed to build authorization-service HTTPS client")
    }
}

fn load_file_identity(cert_path: &Path, key_path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let cert = fs::read(cert_path).with_context(|| {
        format!(
            "failed to read authorization-service client certificate {}",
            cert_path.display()
        )
    })?;
    let key = crate::tls::vault::read_secret_bytes(key_path).with_context(|| {
        format!(
            "failed to read authorization-service client key {}",
            key_path.display()
        )
    })?;
    let mut identity_pem = Zeroizing::new(cert);
    identity_pem.extend_from_slice(b"\n");
    identity_pem.extend_from_slice(&key);
    Ok(identity_pem)
}

struct VaultAuthorizationClientSource {
    vault: Arc<crate::tls::vault::VaultClient>,
    role: String,
    common_name: String,
    service_name: Arc<str>,
    client_config: AuthorizationClientConfig,
}

impl VaultAuthorizationClientSource {
    async fn issue(&self) -> Result<(reqwest::Client, ClientCertificateValidity)> {
        let certificate = self
            .vault
            .issue_client_certificate(&self.role, &self.common_name)
            .await?;
        ensure_client_certificate_is_renewable(certificate.validity, OffsetDateTime::now_utc())?;
        let client = self.client_config.build(&certificate.identity_pem)?;
        Ok((client, certificate.validity))
    }

    fn spawn_renewal(
        self: Arc<Self>,
        client: AuthorizationHttpClient,
        initial_validity: ClientCertificateValidity,
    ) {
        tokio::spawn(async move {
            self.renewal_loop(client, initial_validity).await;
        });
    }

    async fn renewal_loop(
        &self,
        client: AuthorizationHttpClient,
        mut validity: ClientCertificateValidity,
    ) {
        let mut retry_delay = crate::tls::vault::INITIAL_RETRY_DELAY;
        loop {
            let threshold = renewal_threshold(validity);
            let waited_for_schedule =
                crate::tls::vault::wait_until_renewal_due(validity.not_after, threshold).await;
            if waited_for_schedule {
                retry_delay = crate::tls::vault::INITIAL_RETRY_DELAY;
            }

            match self.issue().await {
                Ok((next, next_validity)) => {
                    client.replace(next, next_validity).await;
                    validity = next_validity;
                    crate::metrics::set_authorization_service_client_certificate(
                        &self.service_name,
                        validity.not_after.unix_timestamp(),
                    );
                    crate::metrics::record_authorization_service_vault_renewal(
                        &self.service_name,
                        "success",
                        "none",
                    );
                    info!(
                        authorization_service = %self.service_name,
                        not_after = %validity.not_after,
                        "renewed Vault-backed authorization-service client certificate"
                    );
                    retry_delay = crate::tls::vault::INITIAL_RETRY_DELAY;
                    continue;
                }
                Err(error) => {
                    let reason = crate::tls::vault::failure_kind(&error);
                    crate::metrics::record_authorization_service_vault_renewal(
                        &self.service_name,
                        "failure",
                        reason,
                    );
                    warn!(
                        authorization_service = %self.service_name,
                        reason,
                        error = %error,
                        "Vault authorization-service client certificate renewal failed"
                    );
                }
            }

            sleep(crate::tls::vault::with_jitter(retry_delay)).await;
            retry_delay = retry_delay
                .saturating_mul(2)
                .min(crate::tls::vault::MAX_RETRY_DELAY);
        }
    }
}

fn renewal_threshold(validity: ClientCertificateValidity) -> time::Duration {
    let lifetime = validity.not_after - validity.not_before;
    time::Duration::seconds((lifetime.whole_seconds() / 2).max(1))
}

fn ensure_client_certificate_is_renewable(
    validity: ClientCertificateValidity,
    now: OffsetDateTime,
) -> Result<()> {
    ensure!(
        validity.not_after - now > renewal_threshold(validity),
        "Vault-issued authorization-service client certificate is already due for renewal"
    );
    Ok(())
}

pub(super) async fn read_bounded_response(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("remote-service response exceeds configured limit");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read remote-service response")?
    {
        ensure!(
            body.len().saturating_add(chunk.len()) <= limit,
            "remote-service response exceeds configured limit"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockPolicyClient {
        responses: Mutex<VecDeque<Result<Vec<u8>>>>,
        calls: AtomicUsize,
    }

    struct PendingPolicyClient {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl PolicyClient for PendingPolicyClient {
        async fn resolve_policy(&self, _request: PolicyRequest<'_>) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }
    }

    impl MockPolicyClient {
        fn new(responses: Vec<Result<Vec<u8>>>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses.into()),
                calls: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl PolicyClient for MockPolicyClient {
        async fn resolve_policy(&self, _request: PolicyRequest<'_>) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.responses
                .lock()
                .await
                .pop_front()
                .unwrap_or_else(|| anyhow::bail!("mock policy service unavailable"))
        }
    }

    fn active_response(cache_seconds: u64, extra: serde_json::Value) -> Vec<u8> {
        let now = unix_now().unwrap();
        let mut value = serde_json::json!({
            "active": true,
            "audience": "test-audience",
            "expires_at": now + 60,
            "cache_until": now + cache_seconds,
            "policy_version": "test-policy-v1",
            "rules": [{
                "action": "ALLOW",
                "methods": ["GET"],
                "url_pattern": "https://example.com/**"
            }]
        });
        if let (Some(target), Some(extra)) = (value.as_object_mut(), extra.as_object()) {
            target.extend(extra.clone());
        }
        serde_json::to_vec(&value).unwrap()
    }

    fn test_service(
        policy_client: Arc<dyn PolicyClient>,
        max_cache_duration: Duration,
    ) -> AuthorizationService {
        let audience: Arc<str> = Arc::from("test-audience");
        let service_settings = AuthorizationServiceSettings {
            name: "test".to_string(),
            audience: "test-audience".to_string(),
            policy_url: "https://example.invalid/policy".to_string(),
            credential_url: "https://example.invalid/credential".to_string(),
            server_ca_cert: "unused-ca".into(),
            client_certificate: AuthorizationClientCertificateSettings::Files {
                cert: "unused-cert".into(),
                key: "unused-key".into(),
            },
            timeout: 1,
            max_concurrency: 1,
        };
        AuthorizationService {
            name: Arc::from("test"),
            audience: audience.clone(),
            resolver: Arc::new(PolicyResolver {
                audience,
                policy_client,
                max_cache_duration,
                max_rules: 16,
                max_protected_headers: 4,
            }),
            cache: Arc::new(Mutex::new(CacheState {
                entries: LruCache::new(NonZeroUsize::new(16).unwrap()),
                pending: HashMap::new(),
                pending_capacity: 16,
            })),
            negative_cache_duration: Duration::from_secs(1),
            credential_preparer: CredentialPreparerClient::new(
                &service_settings,
                AuthorizationHttpClient::new(reqwest::Client::new(), None),
                Arc::new(Semaphore::new(1)),
                1024,
            )
            .unwrap(),
            max_protected_headers: 4,
        }
    }

    #[test]
    fn parses_strict_exfilguard_proxy_authorization() {
        let token = AuthorizationToken::parse(b"ExfilGuard abc_DEF-123", 128).unwrap();
        assert_eq!(token.token(), "abc_DEF-123");
        assert_eq!(token.correlation().len(), 16);

        for value in [
            b"Bearer abc".as_slice(),
            b"ExfilGuard".as_slice(),
            b"ExfilGuard abc def".as_slice(),
            b"ExfilGuard abc=".as_slice(),
            b"ExfilGuard ".as_slice(),
        ] {
            assert!(
                AuthorizationToken::parse(value, 128).is_err(),
                "accepted {value:?}"
            );
        }
    }

    #[tokio::test]
    async fn authorization_http_client_never_starts_with_an_expired_certificate() {
        let now = OffsetDateTime::now_utc();
        let client = AuthorizationHttpClient::new(
            reqwest::Client::new(),
            Some(ClientCertificateValidity {
                not_before: now - time::Duration::hours(2),
                not_after: now - time::Duration::hours(1),
            }),
        );
        assert!(client.current().await.is_err());

        client
            .replace(
                reqwest::Client::new(),
                ClientCertificateValidity {
                    not_before: now - time::Duration::minutes(1),
                    not_after: now + time::Duration::hours(1),
                },
            )
            .await;
        assert!(client.current().await.is_ok());
    }

    #[test]
    fn vault_client_certificate_must_have_more_than_half_its_lifetime_remaining() {
        let now = OffsetDateTime::now_utc();
        assert!(
            ensure_client_certificate_is_renewable(
                ClientCertificateValidity {
                    not_before: now - time::Duration::minutes(1),
                    not_after: now + time::Duration::hours(1),
                },
                now,
            )
            .is_ok()
        );
        assert!(
            ensure_client_certificate_is_renewable(
                ClientCertificateValidity {
                    not_before: now - time::Duration::hours(2),
                    not_after: now + time::Duration::hours(1),
                },
                now,
            )
            .is_err()
        );
    }

    #[test]
    fn cache_ttl_does_not_round_past_wall_deadline() {
        let now = UNIX_EPOCH + Duration::from_millis(100_750);
        assert_eq!(
            bounded_cache_ttl(now, 101, Duration::from_secs(30)).unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(
            bounded_cache_ttl(now, 200, Duration::from_secs(2)).unwrap(),
            Duration::from_secs(2)
        );
    }

    #[tokio::test]
    async fn shared_resolution_rejects_a_policy_that_expired_before_handoff() {
        let now = unix_now().unwrap();
        let policy = Arc::new(ResolvedAuthorizationPolicy {
            dynamic: DynamicPolicy::compile_rules(vec![make_dynamic_rule(
                0,
                RuleAction::Allow,
                MethodMatch::Any,
                None,
            )])
            .unwrap(),
            policy_version: Arc::from("expired-policy"),
            wall_valid_until: now,
            valid_until: Instant::now(),
        });
        let (_sender, mut resolution) = watch::channel(Some(Ok(policy)));

        assert!(matches!(
            wait_for_resolution(&mut resolution, None).await,
            Err(AuthorizationError::Denied)
        ));
    }

    #[test]
    fn buffered_body_limit_keeps_the_stricter_cap() {
        let services = AuthorizationServices {
            services: HashMap::new(),
            max_token_header_size: 128,
            buffered_body_permits: Arc::new(Semaphore::new(8192)),
            max_buffered_body_size: 1024,
        };
        assert_eq!(services.buffered_body_limit(0), 1024);
        assert_eq!(services.buffered_body_limit(2048), 1024);
        assert_eq!(services.buffered_body_limit(512), 512);
    }

    #[test]
    fn policy_version_is_a_bounded_visible_identifier() {
        let service = test_service(MockPolicyClient::new(vec![]), Duration::from_secs(30));
        let source_ip = "192.0.2.10".parse().unwrap();

        let longest_valid = "v".repeat(MAX_POLICY_VERSION_SIZE);
        let valid = active_response(30, serde_json::json!({"policy_version": longest_valid}));
        assert!(service.resolver.parse_response(&valid, source_ip).is_ok());

        for invalid in [
            String::new(),
            "contains space".to_string(),
            "contains\nnewline".to_string(),
            "v".repeat(MAX_POLICY_VERSION_SIZE + 1),
            "non-ascii-å".to_string(),
        ] {
            let response = active_response(30, serde_json::json!({"policy_version": invalid}));
            assert!(
                service
                    .resolver
                    .parse_response(&response, source_ip)
                    .is_err(),
                "accepted invalid policy_version"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn valid_cached_policy_avoids_service_call_during_outage() {
        let policy_client =
            MockPolicyClient::new(vec![Ok(active_response(30, serde_json::json!({})))]);
        let service = test_service(policy_client.clone(), Duration::from_secs(30));
        let token = AuthorizationToken::parse(b"ExfilGuard cached-token", 128).unwrap();
        let peer = "192.0.2.10:1234".parse().unwrap();

        service.resolve(&token, peer, None).await.unwrap();
        service.resolve(&token, peer, None).await.unwrap();

        assert_eq!(policy_client.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn named_services_keep_separate_policy_caches() {
        let first_client =
            MockPolicyClient::new(vec![Ok(active_response(30, serde_json::json!({})))]);
        let second_client =
            MockPolicyClient::new(vec![Ok(active_response(30, serde_json::json!({})))]);
        let first = test_service(first_client.clone(), Duration::from_secs(30));
        let second = test_service(second_client.clone(), Duration::from_secs(30));
        let token = AuthorizationToken::parse(b"ExfilGuard shared-token", 128).unwrap();
        let peer = "192.0.2.10:1234".parse().unwrap();

        first.resolve(&token, peer, None).await.unwrap();
        second.resolve(&token, peer, None).await.unwrap();
        first.resolve(&token, peer, None).await.unwrap();
        second.resolve(&token, peer, None).await.unwrap();

        assert_eq!(first_client.calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_client.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn revocation_is_observed_after_local_cache_lifetime() {
        let policy_client = MockPolicyClient::new(vec![
            Ok(active_response(30, serde_json::json!({}))),
            Ok(serde_json::to_vec(&serde_json::json!({"active": false})).unwrap()),
        ]);
        let service = test_service(policy_client.clone(), Duration::from_secs(1));
        let token = AuthorizationToken::parse(b"ExfilGuard revoked-token", 128).unwrap();
        let peer = "192.0.2.10:1234".parse().unwrap();

        service.resolve(&token, peer, None).await.unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(matches!(
            service.resolve(&token, peer, None).await,
            Err(AuthorizationError::Denied)
        ));
        assert_eq!(policy_client.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn source_address_partitions_the_policy_cache() {
        let policy_client = MockPolicyClient::new(vec![
            Ok(active_response(30, serde_json::json!({}))),
            Ok(active_response(30, serde_json::json!({}))),
        ]);
        let service = test_service(policy_client.clone(), Duration::from_secs(30));
        let token = AuthorizationToken::parse(b"ExfilGuard shared-token", 128).unwrap();

        service
            .resolve(&token, "192.0.2.10:1234".parse().unwrap(), None)
            .await
            .unwrap();
        service
            .resolve(&token, "192.0.2.11:1234".parse().unwrap(), None)
            .await
            .unwrap();
        assert_eq!(policy_client.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn ipv4_mapped_source_uses_canonical_policy_cache_identity() {
        let policy_client = MockPolicyClient::new(vec![Ok(active_response(
            30,
            serde_json::json!({
                "client_constraints": {"source_ip": "192.0.2.10"}
            }),
        ))]);
        let service = test_service(policy_client.clone(), Duration::from_secs(30));
        let token = AuthorizationToken::parse(b"ExfilGuard mapped-source-token", 128).unwrap();

        service
            .resolve(&token, "[::ffff:192.0.2.10]:1234".parse().unwrap(), None)
            .await
            .unwrap();
        service
            .resolve(&token, "192.0.2.10:4321".parse().unwrap(), None)
            .await
            .unwrap();

        assert_eq!(policy_client.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pending_lookups_remain_singleflight_and_bounded_after_cancellation() {
        let policy_client = Arc::new(PendingPolicyClient {
            calls: AtomicUsize::new(0),
        });
        let service = Arc::new(test_service(policy_client.clone(), Duration::from_secs(30)));
        let peer = "192.0.2.10:1234".parse().unwrap();
        let token = AuthorizationToken::parse(b"ExfilGuard coalesced-token", 128).unwrap();
        let first = tokio::spawn({
            let service = service.clone();
            let token = token.clone();
            async move { service.resolve(&token, peer, None).await }
        });
        while policy_client.calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        let second = tokio::spawn({
            let service = service.clone();
            let token = token.clone();
            async move { service.resolve(&token, peer, None).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(policy_client.calls.load(Ordering::SeqCst), 1);
        first.abort();
        second.abort();
        let _ = first.await;
        let _ = second.await;

        let mut pending = Vec::new();
        for index in 0..15 {
            let token = AuthorizationToken::parse(
                format!("ExfilGuard cancelled-token-{index}").as_bytes(),
                128,
            )
            .unwrap();
            let expected_calls = policy_client.calls.load(Ordering::SeqCst) + 1;
            let task = tokio::spawn({
                let service = service.clone();
                async move { service.resolve(&token, peer, None).await }
            });
            while policy_client.calls.load(Ordering::SeqCst) < expected_calls {
                tokio::task::yield_now().await;
            }
            pending.push(task);
        }

        let saturated = AuthorizationToken::parse(b"ExfilGuard saturated-token", 128).unwrap();
        assert!(matches!(
            service.resolve(&saturated, peer, None).await,
            Err(AuthorizationError::Unavailable)
        ));
        assert_eq!(policy_client.calls.load(Ordering::SeqCst), 16);

        let coalesced = tokio::spawn({
            let service = service.clone();
            async move { service.resolve(&token, peer, None).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(policy_client.calls.load(Ordering::SeqCst), 16);
        coalesced.abort();
        let _ = coalesced.await;

        for task in pending {
            task.abort();
            let _ = task.await;
        }
        let cache = service.cache.lock().await;
        assert_eq!(cache.pending.len(), 16);
        assert!(cache.entries.is_empty());
    }

    #[tokio::test]
    async fn constrained_source_address_and_unknown_fields_fail_closed() {
        let constrained = MockPolicyClient::new(vec![Ok(active_response(
            30,
            serde_json::json!({
                "client_constraints": {"source_ip": "192.0.2.20"}
            }),
        ))]);
        let service = test_service(constrained, Duration::from_secs(30));
        let token = AuthorizationToken::parse(b"ExfilGuard constrained-token", 128).unwrap();
        assert!(matches!(
            service
                .resolve(&token, "192.0.2.21:1234".parse().unwrap(), None)
                .await,
            Err(AuthorizationError::Denied)
        ));

        let unknown = MockPolicyClient::new(vec![
            Ok(active_response(
                30,
                serde_json::json!({"cache": {"ttl": 300}}),
            )),
            Ok(active_response(30, serde_json::json!({}))),
        ]);
        let service = test_service(unknown.clone(), Duration::from_secs(30));
        let token = AuthorizationToken::parse(b"ExfilGuard unknown-field-token", 128).unwrap();
        assert!(matches!(
            service
                .resolve(&token, "192.0.2.22:1234".parse().unwrap(), None)
                .await,
            Err(AuthorizationError::Unavailable)
        ));
        service
            .resolve(&token, "192.0.2.22:1234".parse().unwrap(), None)
            .await
            .unwrap();
        assert_eq!(unknown.calls.load(Ordering::SeqCst), 2);
    }
}
