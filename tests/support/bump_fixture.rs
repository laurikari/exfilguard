use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use h2::server as h2_server;
use http::{HeaderValue, StatusCode};
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

use exfilguard::tls::ca::CertificateAuthority;

use super::{
    PolicySpec, ProxyHarness, ProxyHarnessBuilder, RuleSpec, TestConfigBuilder, build_client_tls,
    build_client_tls_h2, build_upstream_h2_tls_config, build_upstream_tls_config,
    read_until_double_crlf,
};

#[derive(Clone, Copy)]
pub enum ClientProtocols {
    Http1,
    Http2,
}

impl ClientProtocols {
    fn build(self, root_store: RootCertStore) -> Result<Arc<rustls::ClientConfig>> {
        match self {
            ClientProtocols::Http1 => build_client_tls(root_store),
            ClientProtocols::Http2 => build_client_tls_h2(root_store),
        }
    }
}

#[derive(Clone, Copy)]
pub enum UpstreamMode {
    Http1Keepalive,
    Http1Redirect,
    Http2,
}

pub struct BumpedTlsOptions<'a> {
    upstream_host: &'a str,
    policy_name: &'a str,
    policy: PolicySpec,
    client_protocols: ClientProtocols,
    upstream_mode: UpstreamMode,
}

impl<'a> BumpedTlsOptions<'a> {
    pub fn new(upstream_host: &'a str, policy_name: &'a str, policy: PolicySpec) -> Self {
        Self {
            upstream_host,
            policy_name,
            policy,
            client_protocols: ClientProtocols::Http1,
            upstream_mode: UpstreamMode::Http1Keepalive,
        }
    }

    pub fn client_protocols(mut self, protocols: ClientProtocols) -> Self {
        self.client_protocols = protocols;
        self
    }

    pub fn upstream_mode(mut self, mode: UpstreamMode) -> Self {
        self.upstream_mode = mode;
        self
    }
}

pub struct BumpedTlsFixture {
    upstream_addr: SocketAddr,
    tls_stream: Option<tokio_rustls::client::TlsStream<TcpStream>>,
    shutdown_tx: oneshot::Sender<()>,
    upstream_task: tokio::task::JoinHandle<Result<()>>,
    harness: ProxyHarness,
    accept_count: Arc<AtomicUsize>,
}

impl BumpedTlsFixture {
    pub async fn new(options: BumpedTlsOptions<'_>) -> Result<Self> {
        let BumpedTlsOptions {
            upstream_host,
            policy_name,
            policy,
            client_protocols,
            upstream_mode,
        } = options;
        let dirs = super::TestDirs::new()?;
        let workspace = dirs.config_dir.parent().expect("temp workspace directory");
        let cert_cache_dir = workspace.join("cert_cache");
        std::fs::create_dir_all(&cert_cache_dir)?;

        let ca = Arc::new(CertificateAuthority::load_or_generate(&dirs.ca_dir)?);
        let (clients, policies) = TestConfigBuilder::new()
            .default_client(&[policy_name])
            .policy(policy)
            .render();

        let mut proxy_root_store = RootCertStore::empty();
        let (added_proxy, _) =
            proxy_root_store.add_parsable_certificates([ca.root_certificate_der()]);
        assert!(added_proxy > 0, "expected CA root to be trusted by proxy");
        let cert_cache_path = cert_cache_dir.clone();
        let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
            .with_proxy_root_store(proxy_root_store)
            .with_settings(move |settings| {
                settings.cert_cache_dir = Some(cert_cache_path.clone());
            })
            .spawn()
            .await?;

        let upstream_config = match upstream_mode {
            UpstreamMode::Http1Keepalive | UpstreamMode::Http1Redirect => {
                build_upstream_tls_config(&ca, upstream_host)?
            }
            UpstreamMode::Http2 => build_upstream_h2_tls_config(&ca, upstream_host)?,
        };

        let accept_count = Arc::new(AtomicUsize::new(0));
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let upstream_addr = upstream_listener.local_addr()?;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let accept_counter = accept_count.clone();
        let upstream_task = {
            let upstream_config = upstream_config.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut shutdown_rx => break,
                        accept = upstream_listener.accept() => {
                            let (stream, peer) = match accept {
                                Ok(pair) => pair,
                                Err(err) => {
                                    return Err(anyhow!("upstream accept error: {err}"));
                                }
                            };
                            accept_counter.fetch_add(1, Ordering::SeqCst);
                            let acceptor = TlsAcceptor::from(upstream_config.clone());
                            tokio::spawn(async move {
                                let result = match upstream_mode {
                                    UpstreamMode::Http1Keepalive => {
                                        serve_tls_keepalive(stream, acceptor, peer).await
                                    }
                                    UpstreamMode::Http1Redirect => {
                                        serve_redirect(stream, acceptor, peer).await
                                    }
                                    UpstreamMode::Http2 => {
                                        serve_tls_h2(stream, acceptor, peer).await
                                    }
                                };
                                if let Err(err) = result {
                                    tracing::warn!(error = %err, "tls upstream handler error");
                                }
                            });
                        }
                    }
                }
                Ok::<(), anyhow::Error>(())
            })
        };

        let mut client_root_store = RootCertStore::empty();
        let (added_client, _) =
            client_root_store.add_parsable_certificates([ca.root_certificate_der()]);
        assert!(added_client > 0, "expected CA root to be trusted by client");
        let client_tls_config = client_protocols.build(client_root_store)?;

        let mut stream = TcpStream::connect(harness.addr).await?;
        let connect_request = format!(
            "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n",
            host = upstream_host,
            port = upstream_addr.port()
        );
        stream.write_all(connect_request.as_bytes()).await?;
        stream.flush().await?;

        let connect_response = read_until_double_crlf(&mut stream).await?;
        assert!(
            connect_response.starts_with("HTTP/1.1 200"),
            "unexpected CONNECT response: {connect_response}"
        );

        let connector = tokio_rustls::TlsConnector::from(client_tls_config);
        let server_name = ServerName::try_from(upstream_host.to_string()).unwrap();
        let tls_stream = connector.connect(server_name, stream).await?;

        Ok(Self {
            upstream_addr,
            tls_stream: Some(tls_stream),
            shutdown_tx,
            upstream_task,
            harness,
            accept_count,
        })
    }

    pub fn tls_stream_mut(&mut self) -> &mut tokio_rustls::client::TlsStream<TcpStream> {
        self.tls_stream
            .as_mut()
            .expect("tls stream should be available")
    }

    pub fn take_tls_stream(&mut self) -> tokio_rustls::client::TlsStream<TcpStream> {
        self.tls_stream
            .take()
            .expect("tls stream should be available")
    }

    pub fn upstream_addr(&self) -> SocketAddr {
        self.upstream_addr
    }

    pub fn accept_count(&self) -> usize {
        self.accept_count.load(Ordering::SeqCst)
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        let _ = self.upstream_task.await;
        self.harness.shutdown().await;
    }
}

async fn serve_tls_keepalive(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    _peer: SocketAddr,
) -> Result<()> {
    let mut tls = acceptor
        .accept(stream)
        .await
        .context("tls handshake with proxy failed")?;
    loop {
        let request_bytes = read_request(&mut tls).await?;
        if request_bytes.is_empty() {
            break;
        }
        let request = String::from_utf8(request_bytes)?;
        let path = request_path(&request);
        let close = request.to_ascii_lowercase().contains("connection: close");
        let body = path.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n{}",
            body.len(),
            if close { "close" } else { "keep-alive" },
            body
        );
        tls.write_all(response.as_bytes())
            .await
            .context("failed to write TLS upstream response")?;
        tls.flush()
            .await
            .context("failed to flush TLS upstream response")?;
        if close {
            break;
        }
    }
    tls.shutdown()
        .await
        .context("failed to shutdown TLS upstream stream")?;
    Ok(())
}

async fn serve_tls_h2(stream: TcpStream, acceptor: TlsAcceptor, _peer: SocketAddr) -> Result<()> {
    let tls = acceptor
        .accept(stream)
        .await
        .context("tls handshake with proxy failed")?;
    let mut connection = h2_server::handshake(tls)
        .await
        .context("failed to establish HTTP/2 handshake with proxy")?;

    while let Some(result) = connection.accept().await {
        let (request, mut respond) = result.context("failed to accept HTTP/2 request")?;
        let path = request.uri().path().to_string();
        let mut builder = http::Response::builder().status(StatusCode::OK);
        {
            let headers = builder
                .headers_mut()
                .expect("headers available before body");
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
        }
        let response = builder
            .body(())
            .map_err(|err| anyhow!("failed to build HTTP/2 response: {err}"))?;
        let mut send = respond
            .send_response(response, path.is_empty())
            .context("failed to send HTTP/2 response headers")?;
        if !path.is_empty() {
            send.send_data(Bytes::copy_from_slice(path.as_bytes()), true)
                .context("failed to send HTTP/2 response body")?;
        }
    }

    Ok(())
}

async fn serve_redirect(stream: TcpStream, acceptor: TlsAcceptor, _peer: SocketAddr) -> Result<()> {
    let mut tls = acceptor
        .accept(stream)
        .await
        .context("tls handshake with client failed")?;

    let mut request_buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let read = tls
            .read(&mut byte)
            .await
            .context("failed to read request from proxy")?;
        if read == 0 {
            break;
        }
        request_buf.extend_from_slice(&byte[..read]);
        if request_buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let response = b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.searchkit.com/\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    tls.write_all(response)
        .await
        .context("failed to write upstream response")?;
    tls.shutdown()
        .await
        .context("failed to shutdown upstream TLS")?;
    Ok(())
}

async fn read_request<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let read = stream
            .read(&mut byte)
            .await
            .context("failed to read request byte")?;
        if read == 0 {
            return Ok(buffer);
        }
        buffer.extend_from_slice(&byte[..read]);
        if buffer.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    Ok(buffer)
}

fn request_path(request: &str) -> &str {
    request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
}
