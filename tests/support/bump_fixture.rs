use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use futures::future::poll_fn;
use h2::{client as h2_client, server as h2_server};
use http::{HeaderValue, StatusCode};
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;

use exfilguard::settings::Settings;
use exfilguard::tls::ca::CertificateAuthority;

use super::{
    PolicySpec, ProxyHarness, ProxyHarnessBuilder, RuleSpec, TestConfigBuilder, build_client_tls,
    build_client_tls_h2, build_upstream_h2_tls_config, build_upstream_tls_config,
    read_http_response, read_http_response_with_length, read_until_double_crlf,
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
    Http2CloseBeforeResponse,
    Http2HeadersThenStallBody,
    Http2NoResponse,
    Http2SingleUse,
    Http2Inspect,
}

pub struct BumpedTlsOptions<'a> {
    upstream_host: &'a str,
    policy_name: &'a str,
    policy: PolicySpec,
    client_protocols: ClientProtocols,
    upstream_mode: UpstreamMode,
    settings_override: Option<Box<dyn FnOnce(&mut Settings) + Send>>,
}

impl<'a> BumpedTlsOptions<'a> {
    pub fn new(upstream_host: &'a str, policy_name: &'a str, policy: PolicySpec) -> Self {
        Self {
            upstream_host,
            policy_name,
            policy,
            client_protocols: ClientProtocols::Http1,
            upstream_mode: UpstreamMode::Http1Keepalive,
            settings_override: None,
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

    pub fn with_settings<F>(mut self, func: F) -> Self
    where
        F: FnOnce(&mut Settings) + Send + 'static,
    {
        self.settings_override = Some(Box::new(func));
        self
    }
}

pub struct BumpedHttp1Client<'a> {
    stream: &'a mut tokio_rustls::client::TlsStream<TcpStream>,
}

impl<'a> BumpedHttp1Client<'a> {
    pub async fn send(&mut self, request: impl AsRef<[u8]>) -> Result<()> {
        self.stream.write_all(request.as_ref()).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn read_response(&mut self) -> Result<String> {
        read_http_response(self.stream).await
    }

    pub async fn read_response_with_length(&mut self) -> Result<String> {
        read_http_response_with_length(self.stream).await
    }

    pub fn stream(&self) -> &tokio_rustls::client::TlsStream<TcpStream> {
        self.stream
    }

    pub fn stream_mut(&mut self) -> &mut tokio_rustls::client::TlsStream<TcpStream> {
        self.stream
    }
}

pub struct BumpedH2Client {
    send_request: h2::client::SendRequest<Bytes>,
    connection: Option<tokio::task::JoinHandle<()>>,
}

impl BumpedH2Client {
    pub async fn request(
        &mut self,
        request: http::Request<()>,
    ) -> Result<http::Response<h2::RecvStream>> {
        let (response_fut, _) = self
            .send_request
            .send_request(request, true)
            .context("failed to send HTTP/2 request")?;
        let response = response_fut
            .await
            .context("failed to receive HTTP/2 response")?;
        Ok(response)
    }

    pub async fn request_text(
        &mut self,
        request: http::Request<()>,
    ) -> Result<(StatusCode, String)> {
        let response = self.request(request).await?;
        let status = response.status();
        let body = Self::read_body(response.into_body()).await?;
        Ok((status, body))
    }

    pub async fn request_text_with_body(
        &mut self,
        request: http::Request<()>,
        body: Bytes,
    ) -> Result<(StatusCode, String)> {
        let end_stream = body.is_empty();
        let (response_fut, mut send_stream) = self
            .send_request
            .send_request(request, end_stream)
            .context("failed to send HTTP/2 request")?;
        if !end_stream {
            send_stream
                .send_data(body, true)
                .context("failed to send HTTP/2 request body")?;
        }
        let response = response_fut
            .await
            .context("failed to receive HTTP/2 response")?;
        let status = response.status();
        let body = Self::read_body(response.into_body()).await?;
        Ok((status, body))
    }

    pub async fn read_body(mut body: h2::RecvStream) -> Result<String> {
        let mut bytes = Vec::new();
        while let Some(frame) = body.data().await {
            let chunk = frame.context("failed to read HTTP/2 response chunk")?;
            bytes.extend_from_slice(&chunk);
        }
        Ok(String::from_utf8(bytes)?)
    }

    pub async fn wait_closed(&mut self, timeout_dur: Duration) -> Result<()> {
        let handle = self
            .connection
            .take()
            .ok_or_else(|| anyhow!("HTTP/2 connection task not available"))?;
        timeout(timeout_dur, handle)
            .await
            .map_err(|_| anyhow!("timed out waiting for downstream HTTP/2 connection to close"))?
            .context("downstream HTTP/2 connection task failed")?;
        Ok(())
    }

    pub async fn shutdown(mut self) {
        if let Some(handle) = self.connection.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl Drop for BumpedH2Client {
    fn drop(&mut self) {
        if let Some(handle) = self.connection.take() {
            handle.abort();
        }
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
            settings_override,
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
        let mut settings_override = settings_override;
        let harness = ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
            .with_proxy_root_store(proxy_root_store)
            .with_settings(move |settings| {
                settings.cert_cache_dir = Some(cert_cache_path.clone());
                if let Some(override_fn) = settings_override.take() {
                    override_fn(settings);
                }
            })
            .spawn()
            .await?;

        let upstream_config = match upstream_mode {
            UpstreamMode::Http1Keepalive | UpstreamMode::Http1Redirect => {
                build_upstream_tls_config(&ca, upstream_host)?
            }
            UpstreamMode::Http2
            | UpstreamMode::Http2CloseBeforeResponse
            | UpstreamMode::Http2HeadersThenStallBody
            | UpstreamMode::Http2NoResponse
            | UpstreamMode::Http2SingleUse
            | UpstreamMode::Http2Inspect => build_upstream_h2_tls_config(&ca, upstream_host)?,
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
                                    UpstreamMode::Http2CloseBeforeResponse => {
                                        serve_tls_h2_close_before_response(stream, acceptor, peer).await
                                    }
                                    UpstreamMode::Http2HeadersThenStallBody => {
                                        serve_tls_h2_headers_then_stall_body(stream, acceptor, peer).await
                                    }
                                    UpstreamMode::Http2NoResponse => {
                                        serve_tls_h2_no_response(stream, acceptor, peer).await
                                    }
                                    UpstreamMode::Http2SingleUse => {
                                        serve_tls_h2_single_use(stream, acceptor, peer).await
                                    }
                                    UpstreamMode::Http2Inspect => {
                                        serve_tls_h2_inspect(stream, acceptor, peer).await
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

    pub fn http1_client(&mut self) -> BumpedHttp1Client<'_> {
        BumpedHttp1Client {
            stream: self.tls_stream_mut(),
        }
    }

    pub fn take_tls_stream(&mut self) -> tokio_rustls::client::TlsStream<TcpStream> {
        self.tls_stream
            .take()
            .expect("tls stream should be available")
    }

    pub async fn h2_client(&mut self) -> Result<BumpedH2Client> {
        let tls_stream = self.take_tls_stream();
        let (send_request, connection) = h2_client::handshake(tls_stream)
            .await
            .context("failed to negotiate HTTP/2 with proxy")?;
        let task = tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::warn!(error = %err, "downstream HTTP/2 connection ended");
            }
        });
        Ok(BumpedH2Client {
            send_request,
            connection: Some(task),
        })
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

async fn serve_tls_h2_close_before_response(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    _peer: SocketAddr,
) -> Result<()> {
    let tls = acceptor
        .accept(stream)
        .await
        .context("tls handshake with proxy failed")?;
    let mut connection = h2_server::handshake(tls)
        .await
        .context("failed to establish HTTP/2 handshake with proxy")?;

    let Some(result) = connection.accept().await else {
        return Ok(());
    };
    let (_request, _respond) = result.context("failed to accept HTTP/2 request")?;
    Ok(())
}

async fn serve_tls_h2_headers_then_stall_body(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    _peer: SocketAddr,
) -> Result<()> {
    let tls = acceptor
        .accept(stream)
        .await
        .context("tls handshake with proxy failed")?;
    let mut connection = h2_server::handshake(tls)
        .await
        .context("failed to establish HTTP/2 handshake with proxy")?;

    let Some(result) = connection.accept().await else {
        return Ok(());
    };
    let (_request, mut respond) = result.context("failed to accept HTTP/2 request")?;
    let response = http::Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|err| anyhow!("failed to build HTTP/2 response: {err}"))?;
    let _send = respond
        .send_response(response, false)
        .context("failed to send HTTP/2 response headers")?;
    sleep(Duration::from_secs(5)).await;
    Ok(())
}

async fn serve_tls_h2_no_response(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    _peer: SocketAddr,
) -> Result<()> {
    let tls = acceptor
        .accept(stream)
        .await
        .context("tls handshake with proxy failed")?;
    let mut connection = h2_server::handshake(tls)
        .await
        .context("failed to establish HTTP/2 handshake with proxy")?;

    let Some(result) = connection.accept().await else {
        return Ok(());
    };
    let (_request, _respond) = result.context("failed to accept HTTP/2 request")?;
    sleep(Duration::from_secs(5)).await;
    Ok(())
}

async fn serve_tls_h2_single_use(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    _peer: SocketAddr,
) -> Result<()> {
    let tls = acceptor
        .accept(stream)
        .await
        .context("tls handshake with proxy failed")?;
    let mut connection = h2_server::handshake(tls)
        .await
        .context("failed to establish HTTP/2 handshake with proxy")?;

    let Some(result) = connection.accept().await else {
        return Ok(());
    };
    let (request, mut respond) = result.context("failed to accept HTTP/2 request")?;
    let path = request.uri().path().to_string();
    let response = http::Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|err| anyhow!("failed to build HTTP/2 response: {err}"))?;
    let mut send = respond
        .send_response(response, path.is_empty())
        .context("failed to send HTTP/2 response headers")?;
    if !path.is_empty() {
        send.send_data(Bytes::copy_from_slice(path.as_bytes()), true)
            .context("failed to send HTTP/2 response body")?;
    }

    connection.graceful_shutdown();
    poll_fn(|cx| connection.poll_closed(cx))
        .await
        .context("failed to close single-use HTTP/2 upstream connection")?;

    Ok(())
}

async fn serve_tls_h2_inspect(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    _peer: SocketAddr,
) -> Result<()> {
    let tls = acceptor
        .accept(stream)
        .await
        .context("tls handshake with proxy failed")?;
    let mut connection = h2_server::handshake(tls)
        .await
        .context("failed to establish HTTP/2 handshake with proxy")?;

    while let Some(result) = connection.accept().await {
        let (request, mut respond) = result.context("failed to accept HTTP/2 request")?;
        let content_length = request
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("<missing>")
            .to_string();
        let mut request_body = request.into_body();
        let mut body = Vec::new();
        while let Some(frame) = request_body.data().await {
            let chunk = frame.context("failed to read HTTP/2 request body")?;
            body.extend_from_slice(&chunk);
        }

        let response_body = format!(
            "content-length={content_length}\nbody-len={}\nbody={}",
            body.len(),
            String::from_utf8_lossy(&body)
        );
        let response = http::Response::builder()
            .status(StatusCode::OK)
            .body(())
            .map_err(|err| anyhow!("failed to build HTTP/2 response: {err}"))?;
        let mut send = respond
            .send_response(response, response_body.is_empty())
            .context("failed to send HTTP/2 response headers")?;
        if !response_body.is_empty() {
            send.send_data(Bytes::from(response_body), true)
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
