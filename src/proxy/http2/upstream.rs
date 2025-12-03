use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use h2::client;
use tokio::{net::TcpStream, task::JoinHandle};
use tokio_rustls::{TlsConnector, client::TlsStream as ClientTlsStream};
use tracing::debug;

use crate::{
    config::Scheme,
    proxy::{AppContext, connect::ResolvedTarget, request::ParsedRequest, upstream},
};
use rustls::pki_types::ServerName;

pub struct PrimedHttp2Upstream {
    pub stream: ClientTlsStream<TcpStream>,
    pub peer: SocketAddr,
}

pub(super) struct Http2Upstream {
    app: AppContext,
    binding: Option<ResolvedTarget>,
    handle: Option<UpstreamHandle>,
    primed: Option<PrimedHttp2Upstream>,
}

pub(super) struct UpstreamHandle {
    pub sender: client::SendRequest<Bytes>,
    pub peer: SocketAddr,
    pub reused: bool,
    connection_task: JoinHandle<()>,
}

pub(super) struct UpstreamCheckout {
    pub sender: client::SendRequest<Bytes>,
    pub peer: SocketAddr,
    pub reused_existing: bool,
}

impl Http2Upstream {
    pub(super) fn new(
        app: AppContext,
        binding: Option<ResolvedTarget>,
        primed: Option<PrimedHttp2Upstream>,
    ) -> Self {
        Self {
            app,
            binding,
            handle: None,
            primed,
        }
    }

    pub(super) async fn checkout_sender(
        &mut self,
        allow_private_connect: bool,
        request: &ParsedRequest,
    ) -> Result<UpstreamCheckout> {
        if self.handle.is_none() {
            let handle = self
                .establish_connection(allow_private_connect, request)
                .await?;
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

    async fn establish_connection(
        &mut self,
        allow_private_connect: bool,
        request: &ParsedRequest,
    ) -> Result<UpstreamHandle> {
        if let Some(primed) = self.primed.take() {
            return make_handle_from_stream(primed.stream, primed.peer).await;
        }

        let connect_timeout = self.app.settings.upstream_connect_timeout();
        let port = request.port.unwrap_or(request.scheme.default_port());
        let addresses = upstream::resolve_or_use_binding(
            &request.host,
            port,
            self.binding.as_ref(),
            connect_timeout,
            allow_private_connect,
            "policy allow_private_connect permitted private upstream address",
        )
        .await?;
        let (tcp_stream, peer) = upstream::connect_to_addrs(&addresses, connect_timeout).await?;

        if request.scheme != Scheme::Https {
            bail!("HTTP/2 upstream requires HTTPS scheme");
        }

        let connector = TlsConnector::from(self.app.tls.client_http2.clone());
        let server_name = ServerName::try_from(request.host.clone())
            .map_err(|_| anyhow!("invalid upstream host for TLS '{}'", request.host))?;
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
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

        make_handle_from_stream(tls_stream, peer).await
    }

    pub(super) async fn shutdown(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.connection_task.abort();
            let _ = handle.connection_task.await;
        }
    }
}

async fn make_handle_from_stream(
    tls_stream: ClientTlsStream<TcpStream>,
    peer: SocketAddr,
) -> Result<UpstreamHandle> {
    let (sender, connection) = client::handshake(tls_stream)
        .await
        .context("failed to complete HTTP/2 handshake with upstream")?;

    let task = tokio::spawn(async move {
        if let Err(err) = connection.await {
            debug!(error = %err, "HTTP/2 upstream connection terminated with error");
        }
    });

    Ok(UpstreamHandle {
        sender,
        connection_task: task,
        peer,
        reused: false,
    })
}
