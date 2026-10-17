use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use parking_lot::RwLock;
use rustls::{
    ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use time::OffsetDateTime;
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::{info, warn};

use super::{
    validation::CertificateValidity,
    vault::{self, VaultClient},
};
use crate::settings::ProxyTlsSettings;

struct ServerIdentity {
    config: Arc<ServerConfig>,
    validity: CertificateValidity,
}

impl ServerIdentity {
    fn new(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result<Self> {
        let validity = super::validation::validate_server_certificate_chain(&chain)?;
        let mut config = ServerConfig::builder_with_provider(ring::default_provider().into())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .context("invalid proxy server certificate or private key")?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            config: Arc::new(config),
            validity,
        })
    }

    fn check_validity(&self) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        ensure!(
            now >= self.validity.not_before && now < self.validity.not_after,
            "proxy server certificate is not currently valid"
        );
        Ok(())
    }

    fn renewal_threshold(&self) -> time::Duration {
        time::Duration::seconds(
            ((self.validity.not_after - self.validity.not_before).whole_seconds() / 2).max(1),
        )
    }
}

pub(crate) struct ProxyTls {
    source: ProxyTlsSettings,
    vault: Option<Arc<VaultClient>>,
    current: RwLock<Arc<ServerIdentity>>,
}

impl ProxyTls {
    pub(crate) async fn new(
        source: &ProxyTlsSettings,
        vault: Option<Arc<VaultClient>>,
    ) -> Result<Arc<Self>> {
        let identity = Self::issue(source, vault.as_deref()).await?;
        let this = Arc::new(Self {
            source: source.clone(),
            vault,
            current: RwLock::new(Arc::new(identity)),
        });
        this.record_expiry();
        if matches!(source, ProxyTlsSettings::Vault { .. }) {
            let renewer = this.clone();
            tokio::spawn(async move {
                renewer.renewal_loop().await;
            });
        }
        Ok(this)
    }

    async fn issue(
        source: &ProxyTlsSettings,
        vault: Option<&VaultClient>,
    ) -> Result<ServerIdentity> {
        match source {
            ProxyTlsSettings::Files { cert, key } => {
                let (cert, key) = (cert.clone(), key.clone());
                tokio::task::spawn_blocking(move || {
                    let chain = vault::read_public_certificate_bundle(&cert)?
                        .into_iter()
                        .map(CertificateDer::from)
                        .collect();
                    let bytes = vault::read_secret_bytes(&key)?;
                    let key = PrivateKeyDer::from_pem_slice(&bytes)
                        .context("invalid proxy TLS private key")?;
                    ServerIdentity::new(chain, key)
                })
                .await
                .context("proxy certificate file worker failed")?
            }
            ProxyTlsSettings::Vault { role, server_name } => {
                let certificate = vault
                    .context("Vault-backed proxy TLS requires [vault]")?
                    .issue_server_certificate(role, server_name)
                    .await?;
                let identity = ServerIdentity::new(certificate.chain, certificate.key)?;
                ensure!(
                    identity.validity.not_after - OffsetDateTime::now_utc()
                        > identity.renewal_threshold(),
                    "Vault-issued proxy certificate is already due for renewal"
                );
                Ok(identity)
            }
        }
    }

    fn replace(&self, identity: ServerIdentity) {
        *self.current.write() = Arc::new(identity);
        self.record_expiry();
    }

    fn record_expiry(&self) {
        crate::metrics::set_proxy_tls_certificate_expiry(
            self.current.read().validity.not_after.unix_timestamp(),
        );
    }

    pub(crate) async fn accept(
        &self,
        stream: TcpStream,
        deadline: Duration,
    ) -> Result<TlsStream<TcpStream>> {
        let identity = self.current.read().clone();
        identity.check_validity()?;
        let stream = timeout(
            deadline,
            TlsAcceptor::from(identity.config.clone()).accept(stream),
        )
        .await
        .context("proxy TLS handshake timed out")?
        .context("proxy TLS handshake failed")?;
        identity.check_validity()?;
        Ok(stream)
    }

    pub(crate) async fn reload_files(&self) -> Result<()> {
        if matches!(self.source, ProxyTlsSettings::Files { .. }) {
            let identity = Self::issue(&self.source, None).await?;
            self.replace(identity);
            info!("proxy TLS certificate files reloaded");
        }
        Ok(())
    }

    async fn renewal_loop(&self) {
        let mut retry = vault::INITIAL_RETRY_DELAY;
        loop {
            let identity = self.current.read().clone();
            if vault::wait_until_renewal_due(
                identity.validity.not_after,
                identity.renewal_threshold(),
            )
            .await
            {
                retry = vault::INITIAL_RETRY_DELAY;
            }
            match self.renew_once().await {
                Ok(()) => {
                    crate::metrics::record_proxy_tls_vault_renewal("success", "none");
                    info!("proxy TLS certificate renewed through Vault");
                    continue;
                }
                Err(error) => {
                    let reason = vault::failure_kind(&error);
                    crate::metrics::record_proxy_tls_vault_renewal("failure", reason);
                    warn!(reason, error = %error, "proxy TLS certificate renewal failed");
                }
            }
            sleep(vault::with_jitter(retry)).await;
            retry = retry.saturating_mul(2).min(vault::MAX_RETRY_DELAY);
        }
    }

    async fn renew_once(&self) -> Result<()> {
        let identity = Self::issue(&self.source, self.vault.as_deref()).await?;
        self.replace(identity);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{RootCertStore, pki_types::ServerName};
    use std::{fs, os::unix::fs::PermissionsExt};
    use tempfile::TempDir;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::TlsConnector;

    fn files(dir: &TempDir, certificate: &rcgen::CertifiedKey<rcgen::KeyPair>) -> ProxyTlsSettings {
        let cert = dir.path().join("proxy.pem");
        let key = dir.path().join("proxy.key");
        fs::write(&cert, certificate.cert.pem()).unwrap();
        fs::set_permissions(&cert, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&key, certificate.signing_key.serialize_pem()).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        ProxyTlsSettings::Files { cert, key }
    }

    async fn connect(
        proxy: &Arc<ProxyTls>,
        roots: &RootCertStore,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            if let Ok(mut tls) = proxy.accept(stream, Duration::from_secs(2)).await {
                let (mut read, mut write) = tokio::io::split(&mut tls);
                let _ = tokio::io::copy(&mut read, &mut write).await;
            }
        });
        let config = rustls::ClientConfig::builder_with_provider(ring::default_provider().into())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        Ok(TlsConnector::from(Arc::new(config))
            .connect(
                ServerName::try_from("localhost")?,
                TcpStream::connect(addr).await?,
            )
            .await?)
    }

    async fn ping(stream: &mut tokio_rustls::client::TlsStream<TcpStream>) {
        stream.write_all(b"hi").await.unwrap();
        let mut bytes = [0; 2];
        timeout(Duration::from_secs(2), stream.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"hi");
    }

    #[tokio::test]
    async fn file_rotation_keeps_connections_and_rejects_bad_replacements() {
        let dir = TempDir::new().unwrap();
        let first = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let second = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let settings = files(&dir, &first);
        let proxy = ProxyTls::new(&settings, None).await.unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(first.cert.der().clone()).unwrap();
        roots.add(second.cert.der().clone()).unwrap();
        let mut existing = connect(&proxy, &roots).await.unwrap();
        ping(&mut existing).await;
        files(&dir, &second);
        proxy.reload_files().await.unwrap();
        ping(&mut existing).await;
        let mut next = connect(&proxy, &roots).await.unwrap();
        assert_eq!(
            &next.get_ref().1.peer_certificates().unwrap()[0],
            second.cert.der()
        );
        ping(&mut next).await;
        let ProxyTlsSettings::Files { cert, key } = &settings else {
            unreachable!()
        };
        fs::write(cert, "invalid certificate").unwrap();
        assert!(proxy.reload_files().await.is_err());
        assert!(ProxyTls::new(&settings, None).await.is_err());
        ping(&mut connect(&proxy, &roots).await.unwrap()).await;
        fs::write(cert, second.cert.pem()).unwrap();
        fs::write(key, first.signing_key.serialize_pem()).unwrap();
        assert!(proxy.reload_files().await.is_err());
        assert!(ProxyTls::new(&settings, None).await.is_err());
        ping(&mut existing).await;
    }

    #[tokio::test]
    async fn vault_renewal_validates_replacements_and_recovers_after_expiry() {
        use crate::tls::vault::tests::{ServerReply::*, spawn_fake_server_signer, vault_config};
        let dir = TempDir::new().unwrap();
        let (address, root, server) = spawn_fake_server_signer(
            "localhost",
            vec![
                Valid,
                Valid,
                Unavailable,
                WrongName,
                ClientOnly,
                WrongRoot,
                Expired,
                Unavailable,
                Valid,
            ],
        )
        .await;
        let roots_path = dir.path().join("roots.pem");
        let secret = dir.path().join("secret");
        fs::write(&roots_path, &root).unwrap();
        fs::set_permissions(&roots_path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&secret, "test-secret").unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        let vault = Arc::new(VaultClient::new(vault_config(address, roots_path, secret)).unwrap());
        let proxy = ProxyTls::new(
            &ProxyTlsSettings::Vault {
                role: "proxy-server".into(),
                server_name: "localhost".into(),
            },
            Some(vault),
        )
        .await
        .unwrap();
        let mut roots = RootCertStore::empty();
        for der in CertificateDer::pem_slice_iter(root.as_bytes()) {
            roots.add(der.unwrap()).unwrap();
        }
        let mut existing = connect(&proxy, &roots).await.unwrap();
        let first = proxy.current.read().config.clone();
        proxy.renew_once().await.unwrap();
        assert!(!Arc::ptr_eq(&first, &proxy.current.read().config));
        ping(&mut existing).await;
        let current = proxy.current.read().clone();
        for _ in 0..5 {
            assert!(proxy.renew_once().await.is_err());
            assert!(Arc::ptr_eq(&current, &proxy.current.read()));
        }
        let expired = ServerIdentity {
            config: current.config.clone(),
            validity: CertificateValidity {
                not_before: current.validity.not_before,
                not_after: OffsetDateTime::now_utc() - time::Duration::seconds(1),
            },
        };
        proxy.replace(expired);
        assert!(proxy.renew_once().await.is_err());
        assert!(connect(&proxy, &roots).await.is_err());
        ping(&mut existing).await;
        proxy.renew_once().await.unwrap();
        ping(&mut connect(&proxy, &roots).await.unwrap()).await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn files_reject_invalid_validity_and_certificate_usage() {
        let dir = TempDir::new().unwrap();
        for case in ["expired", "future", "client", "ca"] {
            let now = OffsetDateTime::now_utc();
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
            params.not_before = now - time::Duration::hours(1);
            params.not_after = now + time::Duration::hours(1);
            match case {
                "expired" => params.not_after = now - time::Duration::seconds(1),
                "future" => params.not_before = now + time::Duration::seconds(60),
                "client" => {
                    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth]
                }
                "ca" => params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained),
                _ => unreachable!(),
            }
            let certificate = rcgen::CertifiedKey {
                cert: params.self_signed(&key).unwrap(),
                signing_key: key,
            };
            assert!(
                ProxyTls::new(&files(&dir, &certificate), None)
                    .await
                    .is_err(),
                "{case}"
            );
        }
    }
}
