use std::{fmt, net::IpAddr, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD};
use parking_lot::Mutex;
use rand::{TryRng, rngs::SysRng};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use super::{
    AuthenticationSettings, PasswordHash,
    hash::{valid_password, valid_username},
};
use crate::{
    authorization::AuthorizationToken,
    policy::{matcher::PolicySnapshot, model::ClientEntry},
    proxy::AppContext,
};

#[derive(Debug, Clone, Copy)]
pub(crate) enum AuthenticationError {
    Denied,
    Busy,
}

pub(crate) struct PasswordVerifier {
    pending: Arc<Semaphore>,
    workers: Arc<Semaphore>,
    key: Zeroizing<[u8; 32]>,
    dummy: PasswordHash,
}

impl PasswordVerifier {
    pub(crate) fn new(settings: &AuthenticationSettings) -> Self {
        let mut key = Zeroizing::new([0; 32]);
        SysRng
            .try_fill_bytes(key.as_mut())
            .expect("OS randomness unavailable");
        Self {
            pending: Arc::new(Semaphore::new(settings.max_pending_connections)),
            workers: Arc::new(Semaphore::new(settings.max_concurrent_verifications)),
            key,
            dummy: PasswordHash::parse("$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").expect("valid dummy password hash"),
        }
    }

    pub(crate) fn pending(&self) -> Option<OwnedSemaphorePermit> {
        self.pending.clone().try_acquire_owned().ok()
    }

    async fn verify(
        &self,
        hash: Option<PasswordHash>,
        password: Zeroizing<String>,
    ) -> Result<(), AuthenticationError> {
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| AuthenticationError::Busy)?;
        let known = hash.is_some();
        let hash = hash.unwrap_or_else(|| self.dummy.clone());
        let metric = crate::metrics::track_password_verification();
        let matches = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _metric = metric;
            hash.verify(&password)
        })
        .await
        .map_err(|_| AuthenticationError::Denied)?;
        if known && matches {
            Ok(())
        } else {
            Err(AuthenticationError::Denied)
        }
    }

    fn fingerprint(&self, bytes: &[u8]) -> blake3::Hash {
        blake3::keyed_hash(&self.key, bytes)
    }
}

enum Credentials {
    Anonymous,
    Password {
        fingerprint: blake3::Hash,
        hash: PasswordHash,
    },
    Lease {
        token: Arc<AuthorizationToken>,
        service: Arc<str>,
    },
}

struct Binding {
    name: Arc<str>,
    credentials: Credentials,
    _permit: crate::proxy::admission::ClientConnectionPermit,
    _metric: crate::metrics::ClientConnectionMetricGuard,
}

pub(crate) struct ConnectionSession {
    binding: Mutex<Option<Binding>>,
    pending: Mutex<Option<(OwnedSemaphorePermit, crate::metrics::MetricGuard)>>,
}

impl fmt::Debug for ConnectionSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionSession")
            .field("client", &self.client_name())
            .finish_non_exhaustive()
    }
}

impl ConnectionSession {
    pub(crate) fn new(pending: Option<OwnedSemaphorePermit>) -> Arc<Self> {
        Arc::new(Self {
            binding: Mutex::new(None),
            pending: Mutex::new(
                pending.map(|permit| (permit, crate::metrics::track_authentication_pending())),
            ),
        })
    }

    pub(crate) fn client_name(&self) -> Option<Arc<str>> {
        self.binding
            .lock()
            .as_ref()
            .map(|binding| binding.name.clone())
    }

    pub(crate) fn authorization_token(&self) -> Option<Arc<AuthorizationToken>> {
        self.binding
            .lock()
            .as_ref()
            .and_then(|binding| match &binding.credentials {
                Credentials::Lease { token, .. } => Some(token.clone()),
                _ => None,
            })
    }

    pub(crate) fn valid(&self, snapshot: &PolicySnapshot, peer: IpAddr) -> bool {
        let binding = self.binding.lock();
        let Some(binding) = binding.as_ref() else {
            return true;
        };
        let Some(client) = snapshot
            .client_named(&binding.name)
            .filter(|client| client.selector.contains(peer))
        else {
            return false;
        };
        match &binding.credentials {
            Credentials::Password { hash, .. } => client.password_hash.as_ref() == Some(hash),
            Credentials::Lease { service, .. } => {
                client.authorization_service.as_ref() == Some(service)
                    && snapshot
                        .resolve_lease_client(peer)
                        .is_some_and(|current| current.name == binding.name)
            }
            Credentials::Anonymous => {
                client.password_hash.is_none()
                    && client.authorization_service.is_none()
                    && snapshot
                        .resolve_client(peer)
                        .is_some_and(|current| current.name == binding.name)
            }
        }
    }

    fn bind(
        &self,
        client: &ClientEntry,
        credentials: Credentials,
        app: &AppContext,
    ) -> Result<(), AuthenticationError> {
        let Some(permit) = app
            .client_connections()
            .try_acquire(client.name.clone(), client.max_connections)
        else {
            crate::metrics::record_downstream_connection_rejection(&client.name);
            return Err(AuthenticationError::Busy);
        };
        *self.binding.lock() = Some(Binding {
            name: client.name.clone(),
            credentials,
            _permit: permit,
            _metric: crate::metrics::track_downstream_connection_for_client(client.name.clone()),
        });
        self.pending.lock().take();
        Ok(())
    }

    pub(crate) fn admit_anonymous(
        &self,
        client: &ClientEntry,
        app: &AppContext,
    ) -> Result<(), AuthenticationError> {
        self.bind(client, Credentials::Anonymous, app)
    }

    pub(crate) async fn authenticate(
        &self,
        snapshot: &PolicySnapshot,
        peer: IpAddr,
        values: Vec<&[u8]>,
        app: &AppContext,
    ) -> Result<(), AuthenticationError> {
        let mut values = values.into_iter();
        let presented = values.next();
        if values.next().is_some() || !self.valid(snapshot, peer) {
            return Err(AuthenticationError::Denied);
        }
        {
            let binding = self.binding.lock();
            if let Some(binding) = binding.as_ref() {
                let Some(value) = presented else {
                    return Ok(());
                };
                return match &binding.credentials {
                    Credentials::Anonymous => Err(AuthenticationError::Denied),
                    Credentials::Password { fingerprint, .. } => {
                        let basic = parse_basic(value)?;
                        if app.password_verifier.fingerprint(basic.as_bytes()) == *fingerprint {
                            Ok(())
                        } else {
                            Err(AuthenticationError::Denied)
                        }
                    }
                    Credentials::Lease { token, .. } => app
                        .authorization
                        .as_ref()
                        .ok_or(AuthenticationError::Denied)?
                        .bind_token([value].into_iter(), Some(token))
                        .map(|_| ())
                        .map_err(|_| AuthenticationError::Denied),
                };
            }
        }
        let Some(value) = presented else {
            let client = snapshot
                .resolve_client(peer)
                .ok_or(AuthenticationError::Denied)?;
            return self.bind(client, Credentials::Anonymous, app);
        };
        let scheme = value.split(|byte| *byte == b' ').next().unwrap_or_default();
        if scheme.eq_ignore_ascii_case(b"Basic") {
            if app.proxy_tls.is_none() {
                return Err(AuthenticationError::Denied);
            }
            let basic = parse_basic(value)?;
            let (username, password) = basic.split_once(':').ok_or(AuthenticationError::Denied)?;
            let client = snapshot
                .password_client(username)
                .filter(|client| client.selector.contains(peer));
            let hash = client.and_then(|client| client.password_hash.clone());
            app.password_verifier
                .verify(hash, Zeroizing::new(password.to_owned()))
                .await?;
            let client = client.ok_or(AuthenticationError::Denied)?;
            let latest = app.policies.snapshot();
            let current = latest
                .password_client(username)
                .filter(|current| {
                    current.password_hash == client.password_hash && current.selector.contains(peer)
                })
                .ok_or(AuthenticationError::Denied)?;
            return self.bind(
                current,
                Credentials::Password {
                    fingerprint: app.password_verifier.fingerprint(basic.as_bytes()),
                    hash: client.password_hash.clone().expect("password client"),
                },
                app,
            );
        }
        if scheme.eq_ignore_ascii_case(b"ExfilGuard") {
            let client = snapshot
                .resolve_lease_client(peer)
                .ok_or(AuthenticationError::Denied)?;
            let token = app
                .authorization
                .as_ref()
                .ok_or(AuthenticationError::Denied)?
                .bind_token([value].into_iter(), None)
                .map_err(|_| AuthenticationError::Denied)?;
            return self.bind(
                client,
                Credentials::Lease {
                    token,
                    service: client.authorization_service.clone().expect("lease client"),
                },
                app,
            );
        }
        Err(AuthenticationError::Denied)
    }
}

fn parse_basic(value: &[u8]) -> Result<Zeroizing<String>, AuthenticationError> {
    if value.len() > 2048 {
        return Err(AuthenticationError::Denied);
    }
    let (scheme, encoded) = std::str::from_utf8(value)
        .map_err(|_| AuthenticationError::Denied)?
        .split_once(' ')
        .ok_or(AuthenticationError::Denied)?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Err(AuthenticationError::Denied);
    }
    let mut decoded = Zeroizing::new(Vec::new());
    STANDARD
        .decode_vec(encoded.trim_start_matches(' '), &mut decoded)
        .map_err(|_| AuthenticationError::Denied)?;
    let text = std::str::from_utf8(&decoded).map_err(|_| AuthenticationError::Denied)?;
    let (username, password) = text.split_once(':').ok_or(AuthenticationError::Denied)?;
    if !valid_username(username) || !valid_password(password) {
        return Err(AuthenticationError::Denied);
    }
    Ok(Zeroizing::new(text.to_owned()))
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_basic_header(value: &[u8]) {
    let _ = parse_basic(value);
}

pub(crate) fn challenges(snapshot: &PolicySnapshot, peer: IpAddr) -> Vec<&'static str> {
    let mut values = Vec::new();
    if snapshot.password_available(peer) {
        values.push("Basic realm=\"exfilguard\", charset=\"UTF-8\"");
    }
    if snapshot.resolve_lease_client(peer).is_some() {
        values.push("ExfilGuard");
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";

    #[test]
    fn basic_parser_is_strict_and_preserves_password_colons() {
        let header = format!("bAsIc {}", STANDARD.encode("agent:p:a:ssé"));
        assert_eq!(&*parse_basic(header.as_bytes()).unwrap(), "agent:p:a:ssé");
        for header in [
            "Basic !!!",
            "Basic",
            "Basic ",
            "Basic YTpi c",
            "Bearer YTpi",
            "Basic Og==",
            "Basic YTo=",
            "Basic /w==",
        ] {
            assert!(parse_basic(header.as_bytes()).is_err(), "{header}");
        }
        for text in ["agent", "agent:\n", "a b:password", "agent:\0"] {
            assert!(parse_basic(format!("Basic {}", STANDARD.encode(text)).as_bytes()).is_err());
        }
        assert!(parse_basic(&vec![b'x'; 2049]).is_err());
    }

    #[tokio::test]
    async fn verification_and_pending_limits_recover() {
        let verifier = PasswordVerifier::new(&AuthenticationSettings {
            max_pending_connections: 1,
            max_concurrent_verifications: 1,
        });
        let pending = verifier.pending().unwrap();
        assert!(verifier.pending().is_none());
        drop(pending);
        assert!(verifier.pending().is_some());
        let permit = verifier.workers.clone().try_acquire_owned().unwrap();
        assert!(matches!(
            verifier
                .verify(
                    Some(PasswordHash::parse(HASH).unwrap()),
                    Zeroizing::new("correctbatteryhorsestapler".into())
                )
                .await,
            Err(AuthenticationError::Busy)
        ));
        drop(permit);
        assert!(
            verifier
                .verify(
                    Some(PasswordHash::parse(HASH).unwrap()),
                    Zeroizing::new("correctbatteryhorsestapler".into())
                )
                .await
                .is_ok()
        );
        assert!(matches!(
            verifier
                .verify(None, Zeroizing::new("incorrect-password".into()))
                .await,
            Err(AuthenticationError::Denied)
        ));
    }

    #[test]
    fn cancellation_keeps_worker_permit_until_job_finishes() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap()
            .block_on(async {
                let verifier = Arc::new(PasswordVerifier::new(&AuthenticationSettings {
                    max_pending_connections: 1,
                    max_concurrent_verifications: 1,
                }));
                let (started_tx, started_rx) = tokio::sync::oneshot::channel();
                let (release_tx, release_rx) = std::sync::mpsc::channel();
                let blocker = tokio::task::spawn_blocking(move || {
                    let _ = started_tx.send(());
                    let _ = release_rx.recv_timeout(std::time::Duration::from_secs(5));
                });
                started_rx.await.unwrap();
                let worker = verifier.clone();
                let task = tokio::spawn(async move {
                    worker
                        .verify(
                            Some(PasswordHash::parse(HASH).unwrap()),
                            Zeroizing::new("correctbatteryhorsestapler".into()),
                        )
                        .await
                });
                while verifier.workers.available_permits() != 0 {
                    tokio::task::yield_now().await;
                }
                task.abort();
                let _ = task.await;
                assert_eq!(verifier.workers.available_permits(), 0);
                release_tx.send(()).unwrap();
                blocker.await.unwrap();
                tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    while verifier.workers.available_permits() == 0 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
            });
    }
}
