use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use h2::client;
use tokio::{
    net::TcpStream,
    sync::{Mutex, watch},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{TlsConnector, client::TlsStream as ClientTlsStream};
use tracing::debug;

use crate::{
    config::Scheme,
    proxy::{
        AppContext,
        connect::ResolvedTarget,
        forward_error::{MisdirectedRequest, UpstreamClosed},
        request::ParsedRequest,
        upstream,
    },
};
use rustls::pki_types::ServerName;

pub struct PrimedHttp2Upstream {
    pub stream: ClientTlsStream<TcpStream>,
    pub peer: SocketAddr,
    pub host: String,
    pub port: u16,
}

pub(super) struct Http2Upstream {
    app: AppContext,
    binding: ResolvedTarget,
    handle: Option<UpstreamHandle>,
    primed: Option<PrimedHttp2Upstream>,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
}

pub(super) struct UpstreamHandle {
    pub sender: Arc<Mutex<client::SendRequest<Bytes>>>,
    pub peer: SocketAddr,
    pub reused: bool,
    _metrics: crate::metrics::UpstreamConnectionTracker,
    connection_task: JoinHandle<()>,
}

pub(super) struct UpstreamCheckout {
    pub sender: Arc<Mutex<client::SendRequest<Bytes>>>,
    pub peer: SocketAddr,
    pub reused_existing: bool,
}

impl Http2Upstream {
    pub(super) fn new(
        app: AppContext,
        binding: ResolvedTarget,
        primed: Option<PrimedHttp2Upstream>,
    ) -> Self {
        let (closed_tx, closed_rx) = watch::channel(false);
        Self {
            app,
            binding,
            handle: None,
            primed,
            closed_tx,
            closed_rx,
        }
    }

    pub(super) fn closed_receiver(&self) -> watch::Receiver<bool> {
        self.closed_rx.clone()
    }

    pub(super) async fn checkout_sender(
        &mut self,
        request: &ParsedRequest,
    ) -> Result<UpstreamCheckout> {
        self.reap_finished_handle().await;
        self.validate_request_target(request)?;

        if *self.closed_rx.borrow() {
            return Err(UpstreamClosed.into());
        }

        if self.handle.is_none() {
            let handle = self.establish_connection(request).await?;
            self.handle = Some(handle);
        }
        let handle = self.handle.as_mut().expect("upstream handle available");
        let reused_existing = handle.reused;
        handle.reused = true;
        Ok(UpstreamCheckout {
            sender: handle.sender.clone(),
            peer: handle.peer,
            reused_existing,
        })
    }

    pub(super) fn validate_request_target(&self, request: &ParsedRequest) -> Result<()> {
        let port = request.port.unwrap_or(request.scheme.default_port());
        if request.scheme != Scheme::Https
            || request.host != self.binding.host()
            || port != self.binding.port()
        {
            return Err(MisdirectedRequest::new(
                self.binding.host().to_string(),
                self.binding.port(),
                request.host.clone(),
                port,
            )
            .into());
        }
        Ok(())
    }

    async fn establish_connection(&mut self, request: &ParsedRequest) -> Result<UpstreamHandle> {
        let port = request.port.unwrap_or(request.scheme.default_port());
        if request.scheme != Scheme::Https {
            bail!("HTTP/2 upstream requires HTTPS scheme");
        }

        if let Some(primed) = self.primed.as_ref()
            && (primed.host != request.host || primed.port != port)
        {
            return Err(MisdirectedRequest::new(
                primed.host.clone(),
                primed.port,
                request.host.clone(),
                port,
            )
            .into());
        }

        if let Some(primed) = self.primed.take() {
            return make_handle_from_stream(
                primed.stream,
                primed.peer,
                self.app
                    .settings
                    .max_response_header_size
                    .min(u32::MAX as usize) as u32,
                self.closed_tx.clone(),
            )
            .await;
        }

        let connect_timeout = self.app.settings.upstream_connect_timeout();
        let addresses = upstream::resolve_or_use_binding(
            &request.host,
            port,
            Some(&self.binding),
            self.app.upstream_resolver(),
            self.app.settings.dns_resolve_timeout(),
        )
        .await?;
        let (tcp_stream, peer) = upstream::connect_to_addrs(&addresses, connect_timeout).await?;

        let connector = TlsConnector::from(self.app.tls.client_http2.clone());
        let server_name = ServerName::try_from(request.host.clone())
            .map_err(|_| anyhow!("invalid upstream host for TLS '{}'", request.host))?;
        let tls_stream = timeout(
            self.app.settings.tls_handshake_timeout(),
            connector.connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| anyhow!("TLS handshake with upstream timed out"))?
        .context("failed to establish TLS with upstream for HTTP/2")?;
        let protocol = tls_stream
            .get_ref()
            .1
            .alpn_protocol()
            .map(|proto| proto.to_vec());
        if protocol.as_deref() != Some(b"h2") {
            bail!(
                "upstream did not negotiate HTTP/2 (protocol {:?})",
                protocol
            );
        }

        make_handle_from_stream(
            tls_stream,
            peer,
            self.app
                .settings
                .max_response_header_size
                .min(u32::MAX as usize) as u32,
            self.closed_tx.clone(),
        )
        .await
    }

    pub(super) async fn shutdown(&mut self) {
        self.primed.take();
        if let Some(handle) = self.handle.take() {
            handle.connection_task.abort();
            let _ = handle.connection_task.await;
        }
    }

    pub(super) async fn terminate_session(&mut self) {
        let _ = self.closed_tx.send(true);
        self.primed.take();
        if let Some(handle) = self.handle.take() {
            handle.connection_task.abort();
            let _ = handle.connection_task.await;
        }
    }

    async fn reap_finished_handle(&mut self) {
        let finished = self
            .handle
            .as_ref()
            .map(|handle| handle.connection_task.is_finished())
            .unwrap_or(false);
        if finished && let Some(handle) = self.handle.take() {
            let _ = handle.connection_task.await;
        }
    }
}

async fn make_handle_from_stream(
    tls_stream: ClientTlsStream<TcpStream>,
    peer: SocketAddr,
    max_response_header_size: u32,
    closed_tx: watch::Sender<bool>,
) -> Result<UpstreamHandle> {
    let mut builder = client::Builder::new();
    builder.max_header_list_size(max_response_header_size);
    let metrics = crate::metrics::track_upstream_connection();
    let task_metrics = metrics.clone();
    let (sender, connection) = builder
        .handshake(tls_stream)
        .await
        .context("failed to complete HTTP/2 handshake with upstream")?;

    let task = tokio::spawn(async move {
        if let Err(err) = connection.await {
            debug!(error = %err, "HTTP/2 upstream connection terminated with error");
        }
        task_metrics.close();
        let _ = closed_tx.send(true);
    });

    Ok(UpstreamHandle {
        sender: Arc::new(Mutex::new(sender)),
        connection_task: task,
        peer,
        reused: false,
        _metrics: metrics,
    })
}
