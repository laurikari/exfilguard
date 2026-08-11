mod support;

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, ensure};
use exfilguard::settings::{
    AuthorizationClientCertificateSettings, AuthorizationServiceSettings, AuthorizationSettings,
    ProxyProtocolMode,
};
use http::StatusCode;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, crypto::ring};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use support::{
    LogCapture, PolicySpec, ProxyHarnessBuilder, RuleSpec, TestConfigBuilder, TestDirs,
    read_http_response_with_length, read_until_double_crlf,
};

const AUTHORIZATION_TOKEN: &str = "integration-token";
const REFLECTED_TOKEN: &str = "reflected-integration-token";
const AUDIENCE: &str = "integration-audience";

struct AuthorizationFixture {
    addr: SocketAddr,
    _temp: TempDir,
    ca_path: std::path::PathBuf,
    client_cert_path: std::path::PathBuf,
    client_key_path: std::path::PathBuf,
    policy_calls: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl AuthorizationFixture {
    async fn spawn(policy_scope: String) -> Result<Self> {
        let temp = TempDir::new()?;
        let ServiceTls {
            server_config,
            ca_path,
            client_cert_path,
            client_key_path,
        } = make_service_tls(&temp)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let policy_calls = Arc::new(AtomicUsize::new(0));
        let counter = policy_calls.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = TlsAcceptor::from(server_config.clone());
                let policy_scope = policy_scope.clone();
                let counter = counter.clone();
                tokio::spawn(async move {
                    if let Err(error) =
                        serve_policy_request(stream, acceptor, &policy_scope, counter).await
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
            policy_calls,
            task,
        })
    }

    fn service_settings(&self, name: &str) -> AuthorizationServiceSettings {
        AuthorizationServiceSettings {
            name: name.to_string(),
            audience: AUDIENCE.to_string(),
            policy_url: format!("https://localhost:{}/policy", self.addr.port()),
            server_ca_cert: self.ca_path.clone(),
            client_certificate: AuthorizationClientCertificateSettings::Files {
                cert: self.client_cert_path.clone(),
                key: self.client_key_path.clone(),
            },
            timeout: 2,
            max_concurrency: 4,
        }
    }
}

impl Drop for AuthorizationFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn authorization_settings(services: Vec<AuthorizationServiceSettings>) -> AuthorizationSettings {
    AuthorizationSettings {
        services,
        max_token_header_size: 256,
        policy_cache_capacity: 32,
        max_policy_cache_duration: 30,
        negative_cache_duration: 1,
        max_policy_response_size: 32 * 1024,
        max_policy_rules: 16,
    }
}

struct HttpOrigin {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl HttpOrigin {
    async fn spawn() -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let counter = counter.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_origin(&mut stream, counter).await {
                        tracing::debug!(%error, "origin fixture connection ended");
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

impl Drop for HttpOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn static_and_delegated_clients_share_one_listener_and_named_services() -> Result<()> {
    let dirs = TestDirs::new()?;
    let origin = HttpOrigin::spawn().await?;
    let scope = format!("http://127.0.0.1:{}/allowed", origin.addr.port());
    let first = AuthorizationFixture::spawn(scope.clone()).await?;
    let second = AuthorizationFixture::spawn(scope).await?;
    let policy_name = "local-ceiling";
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

[[client]]
name = "second"
cidr = "198.51.100.0/24"
policies = ["{policy_name}"]
authorization_service = "second"

[[client]]
name = "static"
policies = ["{policy_name}"]
fallback = true
"#
    );
    let authorization = authorization_settings(vec![
        first.service_settings("first"),
        second.service_settings("second"),
    ]);
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(move |settings| {
            settings.authorization = Some(authorization);
            settings.proxy_protocol = ProxyProtocolMode::Required;
            settings.proxy_protocol_allowed_cidrs = Some(vec!["127.0.0.0/8".parse().unwrap()]);
        })
        .spawn()
        .await?;

    let static_response = request_from_source(&harness, &origin, "203.0.113.10", None).await?;
    assert!(
        static_response.starts_with("HTTP/1.1 200"),
        "{static_response}"
    );
    assert_eq!(first.policy_calls.load(Ordering::SeqCst), 0);
    assert_eq!(second.policy_calls.load(Ordering::SeqCst), 0);

    let missing = request_from_source(&harness, &origin, "192.0.2.10", None).await?;
    assert!(missing.starts_with("HTTP/1.1 407"), "{missing}");
    assert!(missing.contains("Proxy-Authenticate: ExfilGuard\r\n"));

    for (source, fixture) in [("192.0.2.10", &first), ("198.51.100.10", &second)] {
        let response =
            request_from_source(&harness, &origin, source, Some(AUTHORIZATION_TOKEN)).await?;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert_eq!(fixture.policy_calls.load(Ordering::SeqCst), 1);
    }
    assert_eq!(origin.requests.load(Ordering::SeqCst), 3);

    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_policy_response_does_not_log_the_token() -> Result<()> {
    let log_capture = LogCapture::new("info").await;
    let dirs = TestDirs::new()?;
    let origin = HttpOrigin::spawn().await?;
    let scope = format!("http://127.0.0.1:{}/allowed", origin.addr.port());
    let service = AuthorizationFixture::spawn(scope).await?;
    let policy_name = "local-ceiling";
    let policy = PolicySpec::new(policy_name).rule(RuleSpec::allow(
        &["GET"],
        format!("http://127.0.0.1:{}/**", origin.addr.port()),
    ));
    let (mut clients, policies) = TestConfigBuilder::new()
        .default_client(&[policy_name])
        .policy(policy)
        .render();
    clients.push_str("authorization_service = \"central\"\n");
    let authorization = authorization_settings(vec![service.service_settings("central")]);
    let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
        .with_settings(move |settings| {
            settings.authorization = Some(authorization);
            settings.proxy_protocol = ProxyProtocolMode::Required;
            settings.proxy_protocol_allowed_cidrs = Some(vec!["127.0.0.0/8".parse().unwrap()]);
        })
        .spawn()
        .await?;

    let response =
        request_from_source(&harness, &origin, "127.0.0.1", Some(REFLECTED_TOKEN)).await?;
    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    assert!(!response.contains("Proxy-Authenticate"), "{response}");
    assert_eq!(service.policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);
    let logs = log_capture.text();
    assert!(logs.contains("invalid_policy_response"), "{logs}");
    assert!(logs.contains("authorization_service_failed"), "{logs}");
    assert!(!logs.contains(REFLECTED_TOKEN), "{logs}");

    harness.shutdown().await;
    Ok(())
}

async fn request_from_source(
    harness: &support::ProxyHarness,
    origin: &HttpOrigin,
    source: &str,
    token: Option<&str>,
) -> Result<String> {
    let mut downstream = TcpStream::connect(harness.addr).await?;
    downstream
        .write_all(format!("PROXY TCP4 {source} 192.0.2.1 5555 3128\r\n").as_bytes())
        .await?;
    let authorization = token
        .map(|token| format!("Proxy-Authorization: ExfilGuard {token}\r\n"))
        .unwrap_or_default();
    downstream
        .write_all(
            format!(
                "GET http://127.0.0.1:{}/allowed HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{authorization}Connection: close\r\n\r\n",
                origin.addr.port(),
                origin.addr.port(),
            )
            .as_bytes(),
        )
        .await?;
    read_http_response_with_length(&mut downstream).await
}

async fn serve_policy_request(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    policy_scope: &str,
    calls: Arc<AtomicUsize>,
) -> Result<()> {
    let mut tls = acceptor.accept(stream).await?;
    let (path, body) = read_json_request(&mut tls).await?;
    ensure!(path == "/policy", "unexpected authorization request path");
    calls.fetch_add(1, Ordering::SeqCst);
    let request: Value = serde_json::from_slice(&body)?;
    let now = unix_now();
    let response =
        if request.get("authorization_token").and_then(Value::as_str) == Some(REFLECTED_TOKEN) {
            json!({
                "active": true,
                "audience": AUDIENCE,
                "expires_at": now + 120,
                "cache_until": now + 30,
                "policy_version": "invalid-response",
                "rules": [{"action": REFLECTED_TOKEN}]
            })
        } else if request.get("authorization_token").and_then(Value::as_str)
            == Some(AUTHORIZATION_TOKEN)
            && request.get("audience").and_then(Value::as_str) == Some(AUDIENCE)
        {
            json!({
                "active": true,
                "audience": AUDIENCE,
                "client_constraints": {"source_ip": request["source_ip"].clone()},
                "expires_at": now + 120,
                "cache_until": now + 30,
                "policy_version": "integration-v1",
                "rules": [{
                    "action": "ALLOW",
                    "methods": ["GET"],
                    "url_pattern": policy_scope
                }]
            })
        } else {
            json!({"active": false})
        };
    write_json_response(&mut tls, StatusCode::OK, &response).await
}

struct ServiceTls {
    server_config: Arc<ServerConfig>,
    ca_path: std::path::PathBuf,
    client_cert_path: std::path::PathBuf,
    client_key_path: std::path::PathBuf,
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
    let config = builder
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from(server_cert.der().to_vec())], key)?;
    Ok(ServiceTls {
        server_config: Arc::new(config),
        ca_path,
        client_cert_path,
        client_key_path,
    })
}

async fn serve_origin(stream: &mut TcpStream, requests: Arc<AtomicUsize>) -> Result<()> {
    let request = read_until_double_crlf(stream).await?;
    requests.fetch_add(1, Ordering::SeqCst);
    let lower = request.to_ascii_lowercase();
    let body = format!(
        "authorization={}\nproxy-authorization={}",
        if lower.contains("\r\nauthorization:") {
            "present"
        } else {
            "<missing>"
        },
        if lower.contains("\r\nproxy-authorization:") {
            "present"
        } else {
            "<missing>"
        },
    );
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    Ok(())
}

async fn read_json_request<S>(stream: &mut S) -> Result<(String, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut head = Vec::new();
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        let read = stream.read(&mut byte).await?;
        ensure!(read != 0, "unexpected EOF reading fixture request head");
        head.push(byte[0]);
        ensure!(head.len() < 64 * 1024, "fixture request head too large");
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
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await?;
    Ok((path, body))
}

async fn write_json_response<S>(stream: &mut S, status: StatusCode, value: &Value) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let body = serde_json::to_vec(value)?;
    stream
        .write_all(
            format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown"),
                body.len(),
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(&body).await?;
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
}
