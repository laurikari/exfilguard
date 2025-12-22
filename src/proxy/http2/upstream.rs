use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use h2::client;
use tokio::{net::TcpStream, task::JoinHandle, time::timeout};
use tokio_rustls::{TlsConnector, client::TlsStream as ClientTlsStream};
use tracing::debug;

use crate::util;
use crate::{
    config::Scheme,
    proxy::{
        AppContext, connect::ResolvedTarget, forward_error::MisdirectedRequest,
        request::ParsedRequest, upstream,
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
    binding: Option<ResolvedTarget>,
    handle: Option<UpstreamHandle>,
    primed: Option<PrimedHttp2Upstream>,
}

pub(super) struct UpstreamHandle {
    pub sender: client::SendRequest<Bytes>,
    pub peer: SocketAddr,
    pub host: String,
    pub port: u16,
    pub scheme: Scheme,
    pub reused: bool,
    pub is_private_peer: bool,
    connection_task: JoinHandle<()>,
}

pub(super) struct UpstreamCheckout {
    pub sender: client::SendRequest<Bytes>,
    pub peer: SocketAddr,
    pub reused_existing: bool,
}

impl Http2Upstream {
    fn reuse_forbidden(handle: &UpstreamHandle, allow_private_upstream: bool) -> bool {
        handle.is_private_peer && !allow_private_upstream
    }

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
        allow_private_upstream: bool,
        request: &ParsedRequest,
    ) -> Result<UpstreamCheckout> {
        if let Some(handle) = self.handle.as_ref() {
            ensure_request_matches(handle, request)?;
            if Self::reuse_forbidden(handle, allow_private_upstream) {
                self.shutdown().await;
            }
        }

        if self.handle.is_none() {
            let handle = self
                .establish_connection(allow_private_upstream, request)
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
        allow_private_upstream: bool,
        request: &ParsedRequest,
    ) -> Result<UpstreamHandle> {
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
                primed.host,
                primed.port,
                request.scheme,
            )
            .await;
        }

        let connect_timeout = self.app.settings.upstream_connect_timeout();
        let addresses = upstream::resolve_or_use_binding(
            &request.host,
            port,
            self.binding.as_ref(),
            self.app.settings.dns_resolve_timeout(),
            allow_private_upstream,
            "policy allow_private_upstream permitted private upstream address",
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

        make_handle_from_stream(tls_stream, peer, request.host.clone(), port, request.scheme).await
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
    host: String,
    port: u16,
    scheme: Scheme,
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
        host,
        port,
        scheme,
        reused: false,
        is_private_peer: util::is_private_ip(peer.ip()),
    })
}

fn ensure_request_matches(handle: &UpstreamHandle, request: &ParsedRequest) -> Result<()> {
    let port = request.port.unwrap_or(request.scheme.default_port());
    if handle.scheme != request.scheme || handle.host != request.host || handle.port != port {
        return Err(MisdirectedRequest::new(
            handle.host.clone(),
            handle.port,
            request.host.clone(),
            port,
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn reuse_forbidden_detects_private_peer() -> Result<()> {
        let (_client_io, server_io) = duplex(1024);
        let (sender, connection) = client::handshake(server_io).await?;
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });

        let handle = UpstreamHandle {
            sender,
            peer: "10.0.0.5:443".parse().unwrap(),
            host: "example.com".to_string(),
            port: 443,
            scheme: Scheme::Https,
            reused: false,
            is_private_peer: true,
            connection_task,
        };

        assert!(
            Http2Upstream::reuse_forbidden(&handle, false),
            "private peer must not be reused when allow_private_upstream is false"
        );
        assert!(
            !Http2Upstream::reuse_forbidden(&handle, true),
            "private peer may be reused when allow_private_upstream is true"
        );
        handle.connection_task.abort();
        Ok(())
    }
}
