mod support;

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, ensure};
use bytes::Bytes;
use exfilguard::config::BodyAccess;
use exfilguard::settings::{
    AuthorizationClientCertificateSettings, AuthorizationServiceSettings, AuthorizationSettings,
    ProxyProtocolMode, VaultAuth, VaultPkiSettings, VaultSettings,
};
use exfilguard::tls::ca::CertificateAuthority;
use futures::future::poll_fn;
use h2::server::SendResponse;
use http::{Method, StatusCode, Uri};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, ExtendedKeyUsagePurpose,
    IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, crypto::ring};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use support::{
    LogCapture, PolicySpec, ProxyHarnessBuilder, RuleSpec, TestConfigBuilder, TestDirs,
    build_client_tls_h2_only, build_upstream_h2_tls_config, read_http_response_with_length,
    read_until_double_crlf,
};

const AUTHORIZATION_TOKEN: &str = "integration-token";
const REFLECTED_TOKEN: &str = "reflected-integration-token";
const AUDIENCE: &str = "integration-audience";
const CREDENTIAL_REFERENCE: &str = "integration-credential";
const AUTHORIZATION_SERVICE: &str = "integration-authorization";
const PROTECTED_VALUE: &str = "Bearer integration-secret";
const EARLY_H2_BODY_SIZE: usize = 128 * 1024;

struct AuthorizationFixture {
    addr: SocketAddr,
    _temp: TempDir,
    ca_path: std::path::PathBuf,
    client_cert_path: std::path::PathBuf,
    client_key_path: std::path::PathBuf,
    signing_issuer: Option<Issuer<'static, KeyPair>>,
    policy_calls: Arc<AtomicUsize>,
    credential_calls: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl AuthorizationFixture {
    async fn spawn(credential_scope: String) -> Result<Self> {
        Self::spawn_with_body_access(credential_scope, BodyAccess::None).await
    }

    async fn spawn_with_body_access(
        credential_scope: String,
        body_access: BodyAccess,
    ) -> Result<Self> {
        let temp = TempDir::new()?;
        let ServiceTls {
            server_config,
            ca_path,
            client_cert_path,
            client_key_path,
            signing_issuer,
        } = make_service_tls(&temp)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let policy_calls = Arc::new(AtomicUsize::new(0));
        let credential_calls = Arc::new(AtomicUsize::new(0));
        let policy_counter = policy_calls.clone();
        let credential_counter = credential_calls.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = TlsAcceptor::from(server_config.clone());
                let credential_scope = credential_scope.clone();
                let policy_counter = policy_counter.clone();
                let credential_counter = credential_counter.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_authorization_request(
                        stream,
                        acceptor,
                        &credential_scope,
                        body_access,
                        policy_counter,
                        credential_counter,
                    )
                    .await
                    {
                        tracing::warn!(%error, "authorization fixture request failed");
                    }
                });
            }
        });
        Ok(Self {
            addr,
            _temp: temp,
            ca_path,
            client_cert_path,
            client_key_path,
            signing_issuer: Some(signing_issuer),
            policy_calls,
            credential_calls,
            task,
        })
    }

    fn settings(&self) -> AuthorizationSettings {
        AuthorizationSettings {
            services: vec![AuthorizationServiceSettings {
                name: AUTHORIZATION_SERVICE.to_string(),
                audience: AUDIENCE.to_string(),
                policy_url: format!("https://localhost:{}/policy", self.addr.port()),
                credential_url: format!("https://localhost:{}/credential", self.addr.port()),
                server_ca_cert: self.ca_path.clone(),
                client_certificate: AuthorizationClientCertificateSettings::Files {
                    cert: self.client_cert_path.clone(),
                    key: self.client_key_path.clone(),
                },
                timeout: 2,
                max_concurrency: 4,
            }],
            max_token_header_size: 256,
            policy_cache_capacity: 32,
            max_policy_cache_duration: 30,
            negative_cache_duration: 1,
            max_policy_response_size: 32 * 1024,
            max_policy_rules: 16,
            max_credential_response_size: 8 * 1024,
            max_protected_headers: 4,
            max_buffered_body_size: 1024,
            max_buffered_body_capacity: 8192,
        }
    }

    async fn spawn_vault_signer(&mut self) -> Result<(VaultSettings, JoinHandle<Result<()>>)> {
        let signing_issuer = self
            .signing_issuer
            .take()
            .context("authorization fixture Vault signer already started")?;
        let root_pem = fs::read_to_string(&self.ca_path)?;
        let secret_id_file = self._temp.path().join("vault-secret-id");
        fs::write(&secret_id_file, "integration-secret-id\n")?;
        fs::set_permissions(&secret_id_file, fs::Permissions::from_mode(0o600))?;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            let (mut login, _) = listener.accept().await?;
            let (path, body) = read_json_request(&mut login).await?;
            ensure!(
                path == "/v1/auth/approle/login",
                "unexpected Vault login path"
            );
            ensure!(
                serde_json::from_slice::<Value>(&body)?
                    == json!({
                        "role_id": "integration-role",
                        "secret_id": "integration-secret-id"
                    }),
                "unexpected Vault AppRole login body"
            );
            write_json_response(
                &mut login,
                StatusCode::OK,
                &json!({"auth": {"client_token": "one-use-integration-token"}}),
            )
            .await?;

            let (mut sign, _) = listener.accept().await?;
            let (path, body) = read_json_request(&mut sign).await?;
            ensure!(
                path == "/v1/pki/sign/authorization-client",
                "unexpected Vault signing path"
            );
            let body: Value = serde_json::from_slice(&body)?;
            ensure!(body["common_name"] == "exfilguard-integration");
            let mut request = CertificateSigningRequestParams::from_pem(
                body["csr"].as_str().context("Vault fixture CSR missing")?,
            )?;
            let now = time::OffsetDateTime::now_utc();
            request.params.not_before = now - time::Duration::minutes(1);
            request.params.not_after = now + time::Duration::hours(12);
            request.params.is_ca = IsCa::NoCa;
            request.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            request.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let certificate = request.signed_by(&signing_issuer)?;
            write_json_response(
                &mut sign,
                StatusCode::OK,
                &json!({
                    "data": {
                        "certificate": certificate.pem(),
                        "issuing_ca": root_pem.clone(),
                        "ca_chain": [root_pem],
                    }
                }),
            )
            .await
        });

        Ok((
            VaultSettings {
                address,
                tls_ca_cert: None,
                tls_server_name: None,
                namespace: None,
                request_timeout: 2,
                tls_client_cert: None,
                tls_client_key: None,
                pki: VaultPkiSettings {
                    mount: "pki".to_string(),
                    expected_root_certs: self.ca_path.clone(),
                },
                auth: VaultAuth::AppRole {
                    mount: "approle".to_string(),
                    role_id: "integration-role".to_string(),
                    secret_id_file,
                },
            },
            task,
        ))
    }
}

impl Drop for AuthorizationFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn with_delegated_authorization(
    mut clients: String,
    origin_scope: &str,
    body_access: BodyAccess,
) -> String {
    use std::fmt::Write;

    let body_access = match body_access {
        BodyAccess::None => "none",
        BodyAccess::BoundedPayload => "bounded_payload",
    };
    let _ = writeln!(
        clients,
        "authorization_service = \"{AUTHORIZATION_SERVICE}\"\n\
         \n\
         [[client.credential_limit]]\n\
         credential_reference = \"{CREDENTIAL_REFERENCE}\"\n\
         origin_scope = \"{origin_scope}\"\n\
         protected_headers = [\"authorization\"]\n\
         body_access = \"{body_access}\""
    );
    clients
}

struct H2Origin {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl H2Origin {
    async fn spawn(ca: &CertificateAuthority) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let tls = build_upstream_h2_tls_config(ca, "localhost")?;
        let accepts = Arc::new(AtomicUsize::new(0));
        let accept_counter = accepts.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                accept_counter.fetch_add(1, Ordering::SeqCst);
                let acceptor = TlsAcceptor::from(tls.clone());
                tokio::spawn(async move {
                    if let Err(error) = serve_h2_origin(stream, acceptor).await {
                        tracing::debug!(%error, "H2 origin fixture connection ended");
                    }
                });
            }
        });
        Ok(Self {
            addr,
            accepts,
            task,
        })
    }
}

impl Drop for H2Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Http1Origin {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Http1Origin {
    async fn spawn() -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let requests = Arc::new(AtomicUsize::new(0));
        let request_counter = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let request_counter = request_counter.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_http1_origin(&mut stream, request_counter).await {
                        tracing::debug!(%error, "HTTP/1 origin fixture connection ended");
                    }
                });
            }
        });
        Ok(Self {
            addr,
            requests,
            task,
        })
    }
}

impl Drop for Http1Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authorization_service_rejects_an_untrusted_server_certificate() -> Result<()> {
    let origin = Http1Origin::spawn().await?;
    let credential_scope = format!("http://127.0.0.1:{}/credential", origin.addr.port());
    let services = AuthorizationFixture::spawn(credential_scope.clone()).await?;
    let unrelated_ca_dir = TempDir::new()?;
    let unrelated_tls = make_service_tls(&unrelated_ca_dir)?;
    let mut authorization = services.settings();
    authorization.services[0].server_ca_cert = unrelated_tls.ca_path;

    let policy_name = "allow-untrusted-service-origin";
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&[policy_name])
        .policy(PolicySpec::new(policy_name).rule(RuleSpec::allow(
            &["GET"],
            format!("http://127.0.0.1:{}/**", origin.addr.port()),
        )))
        .render();
    let clients = with_delegated_authorization(clients, &credential_scope, BodyAccess::None);
    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .with_settings(move |settings| settings.authorization = Some(authorization))
        .spawn()
        .await?;

    let mut downstream = TcpStream::connect(harness.addr).await?;
    downstream
        .write_all(
            format!(
                "GET {credential_scope} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: ExfilGuard {AUTHORIZATION_TOKEN}\r\nConnection: close\r\n\r\n",
                origin.addr.port(),
            )
            .as_bytes(),
        )
        .await?;
    let response = read_http_response_with_length(&mut downstream).await?;
    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    assert!(
        response.contains("authorization service failed"),
        "{response}"
    );
    assert_eq!(services.policy_calls.load(Ordering::SeqCst), 0);
    assert_eq!(services.credential_calls.load(Ordering::SeqCst), 0);
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);

    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plain_http_binds_token_applies_credentials_and_bypasses_cache() -> Result<()> {
    let log_capture = LogCapture::new("info").await;
    let mut dirs = TestDirs::new()?;
    dirs.enable_cache_dir()?;
    let origin = Http1Origin::spawn().await?;
    let credential_scope = format!("http://127.0.0.1:{}/credential", origin.addr.port());
    let services = AuthorizationFixture::spawn(credential_scope.clone()).await?;

    let policy_name = "allow-http-integration-origin";
    let policy = PolicySpec::new(policy_name).rule(
        RuleSpec::allow(
            &["GET"],
            format!("http://127.0.0.1:{}/**", origin.addr.port()),
        )
        .cache_enabled(),
    );
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&[policy_name])
        .policy(policy)
        .render();
    let clients = with_delegated_authorization(clients, &credential_scope, BodyAccess::None);
    let authorization = services.settings();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(move |settings| settings.authorization = Some(authorization))
        .spawn()
        .await?;

    let mut downstream = TcpStream::connect(harness.addr).await?;
    let first = format!(
        "GET http://127.0.0.1:{}/credential HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: ExfilGuard {AUTHORIZATION_TOKEN}\r\nConnection: keep-alive\r\n\r\n",
        origin.addr.port(),
        origin.addr.port(),
    );
    downstream.write_all(first.as_bytes()).await?;
    downstream.flush().await?;
    let first_response = read_http_response_with_length(&mut downstream).await?;
    assert!(
        first_response.starts_with("HTTP/1.1 200"),
        "{first_response}"
    );
    assert!(
        first_response.contains(&format!("authorization={PROTECTED_VALUE}")),
        "{first_response}"
    );
    assert!(first_response.contains("proxy-authorization=<missing>"));

    // The token is bound to the downstream connection, so the client need not repeat the header.
    let second = format!(
        "GET http://127.0.0.1:{}/credential HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin.addr.port(),
        origin.addr.port(),
    );
    downstream.write_all(second.as_bytes()).await?;
    downstream.flush().await?;
    let second_response = read_http_response_with_length(&mut downstream).await?;
    assert!(
        second_response.starts_with("HTTP/1.1 200"),
        "{second_response}"
    );
    assert!(
        second_response.contains(&format!("authorization={PROTECTED_VALUE}")),
        "{second_response}"
    );

    let mut rejected = TcpStream::connect(harness.addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{}/credential HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: ExfilGuard {AUTHORIZATION_TOKEN}\r\nAuthorization: Bearer client-value\r\nConnection: close\r\n\r\n",
        origin.addr.port(),
        origin.addr.port(),
    );
    rejected.write_all(request.as_bytes()).await?;
    rejected.flush().await?;
    let rejected_response = read_http_response_with_length(&mut rejected).await?;
    assert!(
        rejected_response.starts_with("HTTP/1.1 403"),
        "{rejected_response}"
    );
    assert!(
        rejected_response.contains("request blocked by credential policy"),
        "{rejected_response}"
    );

    assert_eq!(services.policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(services.credential_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        origin.requests.load(Ordering::SeqCst),
        2,
        "credential-bearing responses must not be served from the shared cache"
    );
    let logs = log_capture.text();
    assert!(!logs.contains(AUTHORIZATION_TOKEN), "{logs}");
    assert!(!logs.contains(PROTECTED_VALUE), "{logs}");

    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vault_issued_client_certificate_authenticates_to_authorization_service() -> Result<()> {
    let origin = Http1Origin::spawn().await?;
    let credential_scope = format!("http://127.0.0.1:{}/credential", origin.addr.port());
    let mut services = AuthorizationFixture::spawn(credential_scope.clone()).await?;
    let (vault, vault_task) = services.spawn_vault_signer().await?;

    let policy_name = "allow-vault-client-certificate-origin";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["GET"],
        format!("http://127.0.0.1:{}/**", origin.addr.port()),
    ));
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&[policy_name])
        .policy(policy)
        .render();
    let clients = with_delegated_authorization(clients, &credential_scope, BodyAccess::None);
    let mut authorization = services.settings();
    authorization.services[0].client_certificate = AuthorizationClientCertificateSettings::Vault {
        role: "authorization-client".to_string(),
        common_name: "exfilguard-integration".to_string(),
    };
    let harness = ProxyHarnessBuilder::new(&clients, &policies)?
        .with_settings(move |settings| {
            settings.vault = Some(vault);
            settings.authorization = Some(authorization);
        })
        .spawn()
        .await?;
    vault_task.await??;

    let mut downstream = TcpStream::connect(harness.addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{}/credential HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: ExfilGuard {AUTHORIZATION_TOKEN}\r\nConnection: close\r\n\r\n",
        origin.addr.port(),
        origin.addr.port(),
    );
    downstream.write_all(request.as_bytes()).await?;
    downstream.flush().await?;
    let response = read_http_response_with_length(&mut downstream).await?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains(&format!("authorization={PROTECTED_VALUE}")));
    assert_eq!(services.policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(services.credential_calls.load(Ordering::SeqCst), 1);

    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn static_and_delegated_clients_share_one_listener() -> Result<()> {
    let dirs = TestDirs::new()?;
    let origin = Http1Origin::spawn().await?;
    let credential_scope = format!("http://127.0.0.1:{}/credential", origin.addr.port());
    let services = AuthorizationFixture::spawn(credential_scope.clone()).await?;
    let policy_name = "allow-mixed-client-origin";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["GET"],
        format!("http://127.0.0.1:{}/**", origin.addr.port()),
    ));
    let (_, policies) = TestConfigBuilder::new().policy(policy).render();
    let clients = format!(
        r#"[[client]]
name = "delegated"
cidr = "192.0.2.0/24"
policies = ["{policy_name}"]
authorization_service = "{AUTHORIZATION_SERVICE}"

[[client.credential_limit]]
credential_reference = "{CREDENTIAL_REFERENCE}"
origin_scope = "{credential_scope}"
protected_headers = ["authorization"]

[[client]]
name = "static"
policies = ["{policy_name}"]
fallback = true
"#
    );
    let authorization = services.settings();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(move |settings| {
            settings.authorization = Some(authorization);
            settings.proxy_protocol = ProxyProtocolMode::Required;
            settings.proxy_protocol_allowed_cidrs = Some(vec!["127.0.0.0/8".parse().unwrap()]);
        })
        .spawn()
        .await?;

    let request = format!(
        "GET http://127.0.0.1:{}/credential HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin.addr.port(),
        origin.addr.port(),
    );

    let mut static_client = TcpStream::connect(harness.addr).await?;
    static_client
        .write_all(b"PROXY TCP4 198.51.100.10 192.0.2.1 5555 3128\r\n")
        .await?;
    static_client.write_all(request.as_bytes()).await?;
    let response = read_http_response_with_length(&mut static_client).await?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("authorization=<missing>"), "{response}");
    assert_eq!(services.policy_calls.load(Ordering::SeqCst), 0);

    let mut missing_token = TcpStream::connect(harness.addr).await?;
    missing_token
        .write_all(b"PROXY TCP4 192.0.2.10 192.0.2.1 5555 3128\r\n")
        .await?;
    missing_token.write_all(request.as_bytes()).await?;
    let response = read_http_response_with_length(&mut missing_token).await?;
    assert!(response.starts_with("HTTP/1.1 407"), "{response}");
    assert!(
        response.contains("Proxy-Authenticate: ExfilGuard"),
        "{response}"
    );
    assert_eq!(services.policy_calls.load(Ordering::SeqCst), 0);

    let mut delegated_client = TcpStream::connect(harness.addr).await?;
    delegated_client
        .write_all(b"PROXY TCP4 192.0.2.10 192.0.2.1 5555 3128\r\n")
        .await?;
    let delegated_request = request.replacen(
        "Connection: close",
        &format!("Proxy-Authorization: ExfilGuard {AUTHORIZATION_TOKEN}\r\nConnection: close"),
        1,
    );
    delegated_client
        .write_all(delegated_request.as_bytes())
        .await?;
    let response = read_http_response_with_length(&mut delegated_client).await?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.contains(&format!("authorization={PROTECTED_VALUE}")),
        "{response}"
    );
    assert_eq!(services.policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(services.credential_calls.load(Ordering::SeqCst), 1);

    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clients_are_routed_to_their_named_authorization_services() -> Result<()> {
    let dirs = TestDirs::new()?;
    let origin = Http1Origin::spawn().await?;
    let credential_scope = format!("http://127.0.0.1:{}/credential", origin.addr.port());
    let first_service = AuthorizationFixture::spawn(credential_scope.clone()).await?;
    let second_service = AuthorizationFixture::spawn(credential_scope.clone()).await?;
    let policy_name = "allow-named-service-origin";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["GET"],
        format!("http://127.0.0.1:{}/**", origin.addr.port()),
    ));
    let (_, policies) = TestConfigBuilder::new().policy(policy).render();
    let clients = format!(
        r#"[[client]]
name = "first"
cidr = "192.0.2.0/24"
policies = ["{policy_name}"]
authorization_service = "first"

[[client.credential_limit]]
credential_reference = "{CREDENTIAL_REFERENCE}"
origin_scope = "{credential_scope}"
protected_headers = ["authorization"]

[[client]]
name = "second"
policies = ["{policy_name}"]
fallback = true
authorization_service = "second"

[[client.credential_limit]]
credential_reference = "{CREDENTIAL_REFERENCE}"
origin_scope = "{credential_scope}"
protected_headers = ["authorization"]
"#
    );
    let mut authorization = first_service.settings();
    authorization.services[0].name = "first".to_string();
    let mut second_settings = second_service.settings();
    second_settings.services[0].name = "second".to_string();
    authorization.services.extend(second_settings.services);
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(move |settings| {
            settings.authorization = Some(authorization);
            settings.proxy_protocol = ProxyProtocolMode::Required;
            settings.proxy_protocol_allowed_cidrs = Some(vec!["127.0.0.0/8".parse().unwrap()]);
        })
        .spawn()
        .await?;

    let request = format!(
        "GET http://127.0.0.1:{}/credential HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: ExfilGuard {AUTHORIZATION_TOKEN}\r\nConnection: close\r\n\r\n",
        origin.addr.port(),
        origin.addr.port(),
    );
    for source in ["192.0.2.10", "198.51.100.10"] {
        let mut client = TcpStream::connect(harness.addr).await?;
        client
            .write_all(format!("PROXY TCP4 {source} 192.0.2.1 5555 3128\r\n").as_bytes())
            .await?;
        client.write_all(request.as_bytes()).await?;
        let response = read_http_response_with_length(&mut client).await?;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    assert_eq!(first_service.policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(first_service.credential_calls.load(Ordering::SeqCst), 1);
    assert_eq!(second_service.policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(second_service.credential_calls.load(Ordering::SeqCst), 1);

    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_policy_response_does_not_log_the_token() -> Result<()> {
    let log_capture = LogCapture::new("info").await;
    let dirs = TestDirs::new()?;
    let origin = Http1Origin::spawn().await?;
    let credential_scope = format!("http://127.0.0.1:{}/**", origin.addr.port());
    let services = AuthorizationFixture::spawn(credential_scope.clone()).await?;

    let policy_name = "allow-invalid-policy-response";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["GET"],
        format!("http://127.0.0.1:{}/**", origin.addr.port()),
    ));
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&[policy_name])
        .policy(policy)
        .render();
    let clients = with_delegated_authorization(clients, &credential_scope, BodyAccess::None);
    let authorization = services.settings();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(move |settings| settings.authorization = Some(authorization))
        .spawn()
        .await?;

    let mut downstream = TcpStream::connect(harness.addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{}/credential HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: ExfilGuard {REFLECTED_TOKEN}\r\nConnection: close\r\n\r\n",
        origin.addr.port(),
        origin.addr.port(),
    );
    downstream.write_all(request.as_bytes()).await?;
    downstream.flush().await?;
    let response = read_http_response_with_length(&mut downstream).await?;
    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    assert!(!response.contains("Proxy-Authenticate"), "{response}");
    assert_eq!(services.policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(services.credential_calls.load(Ordering::SeqCst), 0);
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);

    let logs = log_capture.text();
    assert!(logs.contains("invalid_policy_response"), "{logs}");
    assert!(logs.contains("authorization_service_failed"), "{logs}");
    assert!(!logs.contains(REFLECTED_TOKEN), "{logs}");

    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunked_body_is_finalized_for_signing_and_forwarded_with_credentials() -> Result<()> {
    let dirs = TestDirs::new()?;
    let origin = Http1Origin::spawn().await?;
    let credential_scope = format!("http://127.0.0.1:{}/**", origin.addr.port());
    let services = AuthorizationFixture::spawn_with_body_access(
        credential_scope.clone(),
        BodyAccess::BoundedPayload,
    )
    .await?;

    let policy_name = "allow-body-integration-origin";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["POST"],
        format!("http://127.0.0.1:{}/**", origin.addr.port()),
    ));
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&[policy_name])
        .policy(policy)
        .render();
    let clients =
        with_delegated_authorization(clients, &credential_scope, BodyAccess::BoundedPayload);
    let authorization = services.settings();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(move |settings| {
            settings.authorization = Some(authorization);
            settings.max_request_body_size = 64;
        })
        .spawn()
        .await?;

    let mut downstream = TcpStream::connect(harness.addr).await?;
    let request = format!(
        "POST http://127.0.0.1:{}/credential HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: ExfilGuard {AUTHORIZATION_TOKEN}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nsigned\r\n8\r\n payload\r\n0\r\n\r\n",
        origin.addr.port(),
        origin.addr.port(),
    );
    downstream.write_all(request.as_bytes()).await?;
    downstream.flush().await?;
    let response = read_http_response_with_length(&mut downstream).await?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.contains(&format!("authorization={PROTECTED_VALUE}")),
        "{response}"
    );
    assert!(response.contains("payload=signed payload"), "{response}");
    assert_eq!(services.policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(services.credential_calls.load(Ordering::SeqCst), 1);
    assert_eq!(origin.requests.load(Ordering::SeqCst), 1);

    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn body_limit_and_credential_failure_deny_before_origin_request() -> Result<()> {
    let log_capture = LogCapture::new("info").await;
    let dirs = TestDirs::new()?;
    let origin = Http1Origin::spawn().await?;
    let credential_scope = format!("http://127.0.0.1:{}/**", origin.addr.port());
    let services = AuthorizationFixture::spawn_with_body_access(
        credential_scope.clone(),
        BodyAccess::BoundedPayload,
    )
    .await?;

    let policy_name = "allow-failure-integration-origin";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["POST"],
        format!("http://127.0.0.1:{}/**", origin.addr.port()),
    ));
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&[policy_name])
        .policy(policy)
        .render();
    let clients =
        with_delegated_authorization(clients, &credential_scope, BodyAccess::BoundedPayload);
    let authorization = services.settings();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(move |settings| {
            settings.authorization = Some(authorization);
            settings.max_request_body_size = 8;
        })
        .spawn()
        .await?;

    let mut oversized = TcpStream::connect(harness.addr).await?;
    let request = format!(
        "POST http://127.0.0.1:{}/credential HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: ExfilGuard {AUTHORIZATION_TOKEN}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\ne\r\nsigned payload\r\n0\r\n\r\n",
        origin.addr.port(),
        origin.addr.port(),
    );
    oversized.write_all(request.as_bytes()).await?;
    oversized.flush().await?;
    let response = read_http_response_with_length(&mut oversized).await?;
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    assert_eq!(services.credential_calls.load(Ordering::SeqCst), 0);
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);

    let mut credential_failure = TcpStream::connect(harness.addr).await?;
    let request = format!(
        "POST http://127.0.0.1:{}/credential-failure HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: ExfilGuard {AUTHORIZATION_TOKEN}\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsigned",
        origin.addr.port(),
        origin.addr.port(),
    );
    let expected_bytes_in = request.len();
    credential_failure.write_all(request.as_bytes()).await?;
    credential_failure.flush().await?;
    let response = read_http_response_with_length(&mut credential_failure).await?;
    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    assert!(
        response.contains("credential preparation failed"),
        "{response}"
    );
    assert_eq!(services.policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(services.credential_calls.load(Ordering::SeqCst), 1);
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);

    harness.shutdown().await;
    let logs = log_capture.text();
    let access_log = logs
        .lines()
        .find(|line| {
            line.contains("target=\"access_log\"")
                && line.contains("path=\"/credential-failure\"")
                && line.contains("error_reason=\"credential_preparation_failed\"")
        })
        .with_context(|| format!("credential failure access log missing: {logs}"))?;
    assert!(
        access_log.contains(&format!("bytes_in={expected_bytes_in}")),
        "buffered request body missing from access log: {access_log}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inspected_h2_applies_credentials_on_shared_token_connection() -> Result<()> {
    let dirs = TestDirs::new()?;
    let interception_ca = Arc::new(CertificateAuthority::load_builtin(&dirs.ca_dir)?);
    let origin = H2Origin::spawn(&interception_ca).await?;
    let credential_scope = format!("https://*:{}/credential/**", origin.addr.port());
    let services = AuthorizationFixture::spawn_with_body_access(
        credential_scope.clone(),
        BodyAccess::BoundedPayload,
    )
    .await?;

    let policy_name = "allow-integration-origin";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["GET", "POST"],
        format!("https://*:{}/**", origin.addr.port()),
    ));
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&[policy_name])
        .policy(policy)
        .render();
    let clients =
        with_delegated_authorization(clients, &credential_scope, BodyAccess::BoundedPayload);
    let mut proxy_roots = RootCertStore::empty();
    proxy_roots.add(CertificateDer::from(
        interception_ca.root_certificate_der().to_vec(),
    ))?;
    let mut authorization = services.settings();
    authorization.max_buffered_body_size = EARLY_H2_BODY_SIZE;
    authorization.max_buffered_body_capacity = 1024 * 1024;
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_proxy_root_store(proxy_roots)
        .with_settings(move |settings| settings.authorization = Some(authorization))
        .spawn()
        .await?;

    let mut downstream = TcpStream::connect(harness.addr).await?;
    let connect = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nProxy-Authorization: ExfilGuard {AUTHORIZATION_TOKEN}\r\n\r\n",
        origin.addr.port(),
        origin.addr.port(),
    );
    downstream.write_all(connect.as_bytes()).await?;
    downstream.flush().await?;
    let response = read_until_double_crlf(&mut downstream).await?;
    ensure!(response.starts_with("HTTP/1.1 200"), "{response}");

    let mut client_roots = RootCertStore::empty();
    client_roots.add(CertificateDer::from(
        interception_ca.root_certificate_der().to_vec(),
    ))?;
    let connector = TlsConnector::from(build_client_tls_h2_only(client_roots)?);
    let tls = connector
        .connect(ServerName::try_from("localhost")?, downstream)
        .await?;
    let (mut sender, connection) = h2::client::handshake(tls).await?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let credential_uri: Uri = format!(
        "https://localhost:{}/credential/success",
        origin.addr.port()
    )
    .parse()?;
    let credential_request = http::Request::builder()
        .method(Method::GET)
        .uri(credential_uri.clone())
        .body(())?;
    let (credential_response, _) = sender.send_request(credential_request, true)?;
    let credential_body = read_h2_body(credential_response.await?.into_body()).await?;
    assert_eq!(
        credential_body,
        format!("path=/credential/success\nauthorization={PROTECTED_VALUE}")
    );

    let early_request = http::Request::builder()
        .method(Method::POST)
        .uri(credential_uri)
        .body(())?;
    let (early_response, mut upload) = sender.send_request(early_request, false)?;
    send_h2_body(&mut upload, vec![b'x'; EARLY_H2_BODY_SIZE]).await?;
    let early_response = tokio::time::timeout(Duration::from_secs(2), early_response)
        .await
        .context("timed out waiting for early finalized HTTP/2 response")??;
    let early_body = read_h2_body(early_response.into_body()).await?;
    assert_eq!(
        early_body,
        format!("path=/credential/success\nauthorization={PROTECTED_VALUE}")
    );

    let misdirected_uri: Uri = format!(
        "https://127.0.0.1:{}/credential/success",
        origin.addr.port()
    )
    .parse()?;
    let misdirected_request = http::Request::builder()
        .method(Method::GET)
        .uri(misdirected_uri)
        .body(())?;
    let (misdirected_response, _) = sender.send_request(misdirected_request, true)?;
    let misdirected_response = misdirected_response.await?;
    assert_eq!(
        misdirected_response.status(),
        StatusCode::MISDIRECTED_REQUEST
    );
    assert_eq!(
        read_h2_body(misdirected_response.into_body()).await?,
        "misdirected request"
    );
    assert_eq!(
        services.credential_calls.load(Ordering::SeqCst),
        2,
        "misdirected request must be rejected before credential preparation"
    );

    let shadowing_request = http::Request::builder()
        .method(Method::GET)
        .uri(format!(
            "https://localhost:{}/credential/success",
            origin.addr.port()
        ))
        .header(http::header::AUTHORIZATION, "Bearer client-value")
        .body(())?;
    let (shadowing_response, _) = sender.send_request(shadowing_request, true)?;
    let shadowing_response = shadowing_response.await?;
    assert_eq!(shadowing_response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        read_h2_body(shadowing_response.into_body()).await?,
        "request blocked by credential policy"
    );
    assert_eq!(
        services.credential_calls.load(Ordering::SeqCst),
        2,
        "client protected header must be rejected before credential preparation"
    );

    let failure_uri: Uri = format!(
        "https://localhost:{}/credential/credential-failure",
        origin.addr.port()
    )
    .parse()?;
    let failure_request = http::Request::builder()
        .method(Method::GET)
        .uri(failure_uri)
        .body(())?;
    let (failure_response, _) = sender.send_request(failure_request, true)?;
    let failure_response = failure_response.await?;
    assert_eq!(failure_response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        read_h2_body(failure_response.into_body()).await?,
        "credential preparation failed"
    );

    let plain_uri: Uri = format!("https://localhost:{}/plain", origin.addr.port()).parse()?;
    let plain_request = http::Request::builder()
        .method(Method::GET)
        .uri(plain_uri)
        .body(())?;
    let (plain_response, _) = sender.send_request(plain_request, true)?;
    let plain_body = read_h2_body(plain_response.await?.into_body()).await?;
    assert_eq!(plain_body, "path=/plain\nauthorization=<missing>");

    assert_eq!(services.policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(services.credential_calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        origin.accepts.load(Ordering::SeqCst),
        1,
        "one token-bound H2 session should share one origin connection"
    );

    connection_task.abort();
    let _ = connection_task.await;
    harness.shutdown().await;
    Ok(())
}

async fn serve_authorization_request(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    credential_scope: &str,
    body_access: BodyAccess,
    policy_calls: Arc<AtomicUsize>,
    credential_calls: Arc<AtomicUsize>,
) -> Result<()> {
    let mut tls = acceptor.accept(stream).await?;
    let (path, body) = read_json_request(&mut tls).await?;
    let request: Value = serde_json::from_slice(&body)?;
    let now = unix_now();
    let body_access_name = match body_access {
        BodyAccess::None => "none",
        BodyAccess::BoundedPayload => "bounded_payload",
    };
    let allowed_methods = match body_access {
        BodyAccess::None => json!(["GET"]),
        BodyAccess::BoundedPayload => json!(["GET", "POST"]),
    };
    let (status, response) = match path.as_str() {
        "/policy" => {
            policy_calls.fetch_add(1, Ordering::SeqCst);
            if request.get("authorization_token").and_then(Value::as_str) == Some(REFLECTED_TOKEN) {
                (
                    StatusCode::OK,
                    json!({
                        "active": true,
                        "audience": AUDIENCE,
                        "expires_at": now + 120,
                        "cache_until": now + 30,
                        "policy_version": "invalid-response",
                        "rules": [{"action": REFLECTED_TOKEN}]
                    }),
                )
            } else if request.get("authorization_token").and_then(Value::as_str)
                != Some(AUTHORIZATION_TOKEN)
                || request.get("audience").and_then(Value::as_str) != Some(AUDIENCE)
            {
                (StatusCode::OK, json!({"active": false}))
            } else {
                (
                    StatusCode::OK,
                    json!({
                        "active": true,
                        "audience": AUDIENCE,
                        "client_constraints": {"source_ip": request["source_ip"].clone()},
                        "expires_at": now + 120,
                        "cache_until": now + 30,
                        "policy_version": "integration-v1",
                        "rules": [
                            {
                                "action": "ALLOW",
                                "methods": allowed_methods,
                                "url_pattern": credential_scope,
                                "credential": {
                                    "credential_reference": CREDENTIAL_REFERENCE,
                                    "protected_headers": ["authorization"],
                                    "body_access": body_access_name
                                }
                            },
                            {"action": "ALLOW", "methods": allowed_methods}
                        ]
                    }),
                )
            }
        }
        "/credential" => {
            credential_calls.fetch_add(1, Ordering::SeqCst);
            let fingerprint_valid = finalized_fingerprint(&request).is_ok_and(|fingerprint| {
                json_bytes(&request["request_fingerprint"])
                    .is_ok_and(|claimed| claimed == fingerprint)
            });
            let finalized_body = request
                .pointer("/finalized_request/body")
                .and_then(Value::as_array)
                .map(|bytes| {
                    bytes
                        .iter()
                        .filter_map(Value::as_u64)
                        .map(|byte| byte as u8)
                        .collect::<Vec<_>>()
                });
            let valid = request.get("authorization_token").and_then(Value::as_str)
                == Some(AUTHORIZATION_TOKEN)
                && request.get("audience").and_then(Value::as_str) == Some(AUDIENCE)
                && request.get("credential_reference").and_then(Value::as_str)
                    == Some(CREDENTIAL_REFERENCE)
                && fingerprint_valid
                && request
                    .pointer("/finalized_request/raw_path_and_query")
                    .and_then(Value::as_array)
                    .is_some_and(|bytes| {
                        let path = bytes
                            .iter()
                            .filter_map(Value::as_u64)
                            .map(|b| b as u8)
                            .collect::<Vec<_>>();
                        path == b"/credential" || path == b"/credential/success"
                    })
                && finalized_body.as_deref().is_some_and(|body| {
                    body.is_empty()
                        || body == b"signed payload"
                        || (body.len() == EARLY_H2_BODY_SIZE
                            && body.iter().all(|byte| *byte == b'x'))
                });
            if !valid {
                (StatusCode::FORBIDDEN, json!({"error": "denied"}))
            } else {
                (
                    StatusCode::OK,
                    json!({
                        "request_nonce": request["request_nonce"].clone(),
                        "request_fingerprint": request["request_fingerprint"].clone(),
                        "expires_at": now + 30,
                        "protected_headers": [{
                            "name": "authorization",
                            "value": PROTECTED_VALUE.as_bytes()
                        }]
                    }),
                )
            }
        }
        _ => (StatusCode::NOT_FOUND, json!({"error": "not found"})),
    };
    write_json_response(&mut tls, status, &response).await
}

fn finalized_fingerprint(request: &Value) -> Result<Vec<u8>> {
    let finalized = request
        .get("finalized_request")
        .context("missing finalized request")?;
    let mut encoded = b"exfilguard:finalized-request:v1\0".to_vec();
    encode_cbor_map_len(&mut encoded, 13);
    encode_cbor_uint(&mut encoded, 0);
    encode_cbor_uint(&mut encoded, json_u64(&finalized["version"])?);
    encode_cbor_uint(&mut encoded, 1);
    encode_cbor_text(&mut encoded, json_text(&finalized["scheme"])?);
    encode_cbor_uint(&mut encoded, 2);
    encode_cbor_text(&mut encoded, json_text(&finalized["origin_host"])?);
    encode_cbor_uint(&mut encoded, 3);
    encode_cbor_uint(&mut encoded, json_u64(&finalized["effective_port"])?);
    encode_cbor_uint(&mut encoded, 4);
    encode_cbor_text(&mut encoded, json_text(&finalized["authority"])?);
    encode_cbor_uint(&mut encoded, 5);
    encode_cbor_text(&mut encoded, json_text(&finalized["method"])?);
    encode_cbor_uint(&mut encoded, 6);
    encode_cbor_bytes(&mut encoded, &json_bytes(&finalized["raw_path_and_query"])?);
    encode_cbor_uint(&mut encoded, 7);
    let headers = finalized["headers"]
        .as_array()
        .context("finalized headers are not an array")?;
    encode_cbor_array_len(&mut encoded, headers.len());
    for header in headers {
        encode_cbor_array_len(&mut encoded, 2);
        encode_cbor_text(&mut encoded, json_text(&header["name"])?);
        encode_cbor_bytes(&mut encoded, &json_bytes(&header["value"])?);
    }
    encode_cbor_uint(&mut encoded, 8);
    let slots = finalized["protected_header_slots"]
        .as_array()
        .context("protected header slots are not an array")?;
    encode_cbor_array_len(&mut encoded, slots.len());
    for slot in slots {
        encode_cbor_text(&mut encoded, json_text(slot)?);
    }
    encode_cbor_uint(&mut encoded, 9);
    encode_cbor_text(&mut encoded, json_text(&finalized["body_kind"])?);
    encode_cbor_uint(&mut encoded, 10);
    encode_cbor_bytes(&mut encoded, &json_bytes(&finalized["body"])?);
    encode_cbor_uint(&mut encoded, 11);
    encode_cbor_uint(&mut encoded, json_u64(&finalized["payload_length"])?);
    encode_cbor_uint(&mut encoded, 12);
    ensure!(finalized["trailers"].is_null(), "trailers must be null");
    encoded.push(0xf6);
    Ok(Sha256::digest(encoded).to_vec())
}

fn json_text(value: &Value) -> Result<&str> {
    value.as_str().context("fingerprint field is not text")
}

fn json_u64(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .context("fingerprint field is not an unsigned integer")
}

fn json_bytes(value: &Value) -> Result<Vec<u8>> {
    value
        .as_array()
        .context("fingerprint field is not a byte array")?
        .iter()
        .map(|byte| {
            u8::try_from(json_u64(byte)?)
                .context("fingerprint byte-array value is outside the byte range")
        })
        .collect()
}

fn encode_cbor_uint(output: &mut Vec<u8>, value: u64) {
    encode_cbor_major(output, 0, value);
}

fn encode_cbor_bytes(output: &mut Vec<u8>, value: &[u8]) {
    encode_cbor_major(output, 2, value.len() as u64);
    output.extend_from_slice(value);
}

fn encode_cbor_text(output: &mut Vec<u8>, value: &str) {
    encode_cbor_major(output, 3, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
}

fn encode_cbor_array_len(output: &mut Vec<u8>, length: usize) {
    encode_cbor_major(output, 4, length as u64);
}

fn encode_cbor_map_len(output: &mut Vec<u8>, length: usize) {
    encode_cbor_major(output, 5, length as u64);
}

fn encode_cbor_major(output: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | value as u8),
        24..=0xff => output.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            output.push(prefix | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

async fn serve_h2_origin(stream: TcpStream, acceptor: TlsAcceptor) -> Result<()> {
    let tls = acceptor.accept(stream).await?;
    let mut connection = h2::server::handshake(tls).await?;
    while let Some(request) = connection.accept().await {
        let (request, respond) = request?;
        tokio::spawn(serve_h2_origin_request(request, respond));
    }
    Ok(())
}

async fn serve_h2_origin_request(
    request: http::Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
) -> Result<()> {
    let path = request.uri().path().to_string();
    let authorization = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("<missing>")
        .to_string();
    let body = format!("path={path}\nauthorization={authorization}");
    let response = http::Response::builder().status(StatusCode::OK).body(())?;
    let mut send = respond.send_response(response, false)?;
    send.send_data(Bytes::from(body), true)?;
    Ok(())
}

async fn serve_http1_origin(stream: &mut TcpStream, requests: Arc<AtomicUsize>) -> Result<()> {
    let request = read_until_double_crlf(stream).await?;
    requests.fetch_add(1, Ordering::SeqCst);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("<missing>");
    let header = |name: &str| {
        request.lines().find_map(|line| {
            let (candidate, value) = line.split_once(':')?;
            candidate.eq_ignore_ascii_case(name).then_some(value.trim())
        })
    };
    let content_length = header("content-length")
        .map(str::parse::<usize>)
        .transpose()?
        .unwrap_or(0);
    let mut request_body = vec![0; content_length];
    stream.read_exact(&mut request_body).await?;
    let body = format!(
        "path={path}\nauthorization={}\nproxy-authorization={}\npayload={}",
        header("authorization").unwrap_or("<missing>"),
        header("proxy-authorization").unwrap_or("<missing>"),
        String::from_utf8_lossy(&request_body),
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nCache-Control: max-age=60\r\nConnection: keep-alive\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_h2_body(mut body: h2::RecvStream) -> Result<String> {
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        bytes.extend_from_slice(&chunk?);
    }
    Ok(String::from_utf8(bytes)?)
}

async fn send_h2_body(stream: &mut h2::SendStream<Bytes>, body: Vec<u8>) -> Result<()> {
    let mut body = Bytes::from(body);
    stream.reserve_capacity(body.len());
    while !body.is_empty() {
        let capacity = poll_fn(|context| stream.poll_capacity(context))
            .await
            .context("HTTP/2 upload stream closed")??;
        if capacity == 0 {
            continue;
        }
        let chunk = body.split_to(capacity.min(body.len()));
        stream.send_data(chunk, false)?;
    }
    stream.send_data(Bytes::new(), true)?;
    Ok(())
}

struct ServiceTls {
    server_config: Arc<ServerConfig>,
    ca_path: std::path::PathBuf,
    client_cert_path: std::path::PathBuf,
    client_key_path: std::path::PathBuf,
    signing_issuer: Issuer<'static, KeyPair>,
}

fn make_service_tls(temp: &TempDir) -> Result<ServiceTls> {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);

    let mut server_params = CertificateParams::new(vec!["localhost".to_string()])?;
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate()?;
    let server_cert = server_params.signed_by(&server_key, &issuer)?;

    let mut client_params = CertificateParams::new(Vec::<String>::new())?;
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate()?;
    let client_cert = client_params.signed_by(&client_key, &issuer)?;

    let ca_path = temp.path().join("ca.pem");
    let client_cert_path = temp.path().join("client.pem");
    let client_key_path = temp.path().join("client.key");
    fs::write(&ca_path, ca_cert.pem())?;
    fs::write(&client_cert_path, client_cert.pem())?;
    fs::write(&client_key_path, client_key.serialize_pem())?;
    fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o644))?;
    fs::set_permissions(&client_key_path, fs::Permissions::from_mode(0o600))?;

    let mut client_roots = RootCertStore::empty();
    client_roots.add(CertificateDer::from(ca_cert.der().to_vec()))?;
    let provider = ring::default_provider();
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(client_roots),
        Arc::new(provider.clone()),
    )
    .build()?;
    let builder = ServerConfig::builder_with_provider(provider.into());
    let builder = builder.with_safe_default_protocol_versions()?;
    let key = PrivateKeyDer::try_from(server_key.serialize_der())
        .map_err(|error| anyhow!("invalid service fixture key: {error}"))?;
    let mut config = builder
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from(server_cert.der().to_vec())], key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(ServiceTls {
        server_config: Arc::new(config),
        ca_path,
        client_cert_path,
        client_key_path,
        signing_issuer: issuer,
    })
}

async fn read_json_request<S>(stream: &mut S) -> Result<(String, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        ensure!(head.len() < 64 * 1024, "fixture request head too large");
        let read = stream.read(&mut byte).await?;
        ensure!(read != 0, "unexpected EOF reading fixture request head");
        head.push(byte[0]);
    }
    let text = std::str::from_utf8(&head)?;
    let path = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("fixture request path missing")?
        .to_string();
    let length = text
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>())
        })
        .transpose()?
        .context("fixture request content-length missing")?;
    ensure!(length <= 2 * 1024 * 1024, "fixture request body too large");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    Ok((path, body))
}

async fn write_json_response<S>(stream: &mut S, status: StatusCode, value: &Value) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let body = serde_json::to_vec(value)?;
    let reason = status.canonical_reason().unwrap_or("Unknown");
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status.as_u16(),
        reason,
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;
    stream.shutdown().await?;
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_rejects_changed_malformed_and_duplicate_proxy_tokens() -> Result<()> {
    let dirs = TestDirs::new()?;
    let interception_ca = Arc::new(CertificateAuthority::load_builtin(&dirs.ca_dir)?);
    let origin = H2Origin::spawn(&interception_ca).await?;
    let credential_scope = format!("https://*:{}/credential/**", origin.addr.port());
    let services = AuthorizationFixture::spawn_with_body_access(
        credential_scope.clone(),
        BodyAccess::BoundedPayload,
    )
    .await?;
    let policy_name = "allow-integration-origin";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["GET"],
        format!("https://*:{}/**", origin.addr.port()),
    ));
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&[policy_name])
        .policy(policy)
        .render();
    let clients =
        with_delegated_authorization(clients, &credential_scope, BodyAccess::BoundedPayload);
    let mut proxy_roots = RootCertStore::empty();
    proxy_roots.add(CertificateDer::from(
        interception_ca.root_certificate_der().to_vec(),
    ))?;
    let authorization = services.settings();
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_proxy_root_store(proxy_roots)
        .with_settings(move |settings| settings.authorization = Some(authorization))
        .spawn()
        .await?;
    let mut downstream = TcpStream::connect(harness.addr).await?;
    let connect = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nProxy-Authorization: ExfilGuard {AUTHORIZATION_TOKEN}\r\n\r\n",
        origin.addr.port(),
        origin.addr.port(),
    );
    downstream.write_all(connect.as_bytes()).await?;
    downstream.flush().await?;
    let response = read_until_double_crlf(&mut downstream).await?;
    ensure!(response.starts_with("HTTP/1.1 200"), "{response}");
    let mut client_roots = RootCertStore::empty();
    client_roots.add(CertificateDer::from(
        interception_ca.root_certificate_der().to_vec(),
    ))?;
    let connector = TlsConnector::from(build_client_tls_h2_only(client_roots)?);
    let tls = connector
        .connect(ServerName::try_from("localhost")?, downstream)
        .await?;
    let (mut sender, connection) = h2::client::handshake(tls).await?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    for supplied in ["ExfilGuard changed-token", "malformed"] {
        let request = http::Request::builder()
            .method(Method::GET)
            .uri(format!(
                "https://localhost:{}/credential/success",
                origin.addr.port()
            ))
            .header(http::header::PROXY_AUTHORIZATION, supplied)
            .body(())?;
        let (response, _) = sender.send_request(request, true)?;
        let response = response.await?;
        assert_eq!(
            response.status(),
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "{supplied:?}"
        );
        let _ = read_h2_body(response.into_body()).await?;
    }
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(format!(
            "https://localhost:{}/credential/success",
            origin.addr.port()
        ))
        .header(
            http::header::PROXY_AUTHORIZATION,
            "ExfilGuard changed-token",
        )
        .header(http::header::PROXY_AUTHORIZATION, "malformed")
        .body(())?;
    let (response, _) = sender.send_request(request, true)?;
    let response = response.await?;
    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    let _ = read_h2_body(response.into_body()).await?;
    assert_eq!(services.credential_calls.load(Ordering::SeqCst), 0);
    // Rejected streams must not change or close the authenticated session.
    for token in [None, Some(format!("ExfilGuard {AUTHORIZATION_TOKEN}"))] {
        let mut request = http::Request::builder().method(Method::GET).uri(format!(
            "https://localhost:{}/credential/success",
            origin.addr.port()
        ));
        if let Some(token) = token {
            request = request.header(http::header::PROXY_AUTHORIZATION, token);
        }
        let (response, _) = sender.send_request(request.body(())?, true)?;
        let response = response.await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            read_h2_body(response.into_body()).await?,
            format!("path=/credential/success\nauthorization={PROTECTED_VALUE}")
        );
    }
    assert_eq!(services.credential_calls.load(Ordering::SeqCst), 2);
    connection_task.abort();
    let _ = connection_task.await;
    harness.shutdown().await;
    Ok(())
}
