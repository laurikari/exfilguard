use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use futures::FutureExt;
use lru::LruCache;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::{
    config::Scheme,
    proxy::{AppContext, connect::ResolvedTarget, request::ParsedRequest, upstream},
};

use super::forward::UpstreamIo;
use super::pipeline::shutdown_stream;

pub(super) struct UpstreamPool {
    entries: LruCache<UpstreamKey, UpstreamConnection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(super) struct UpstreamKey {
    scheme: Scheme,
    host: String,
    port: u16,
    authorization_context: Option<[u8; 32]>,
}

pub(super) struct UpstreamConnection {
    pub(super) stream: UpstreamIo,
    pub(super) peer: SocketAddr,
    pub(super) scheme: Scheme,
    pub(super) host: String,
    pub(super) port: u16,
    metrics: crate::metrics::UpstreamConnectionTracker,
    idle: bool,
}

impl UpstreamPool {
    pub(super) fn new(capacity: NonZeroUsize) -> Self {
        let entries = LruCache::new(capacity);
        Self { entries }
    }

    pub(super) fn take(&mut self, key: &UpstreamKey) -> Option<UpstreamConnection> {
        let mut conn = self.entries.pop(key)?;
        if !idle_stream_is_reusable(&mut conn.stream) {
            debug!(
                host = %conn.host,
                port = conn.port,
                scheme = ?conn.scheme,
                "discarding readable or closed idle upstream connection"
            );
            return None;
        }
        conn.mark_active();
        Some(conn)
    }

    pub(super) fn put(
        &mut self,
        key: UpstreamKey,
        mut conn: UpstreamConnection,
        shutdown_timeout: Duration,
    ) {
        conn.mark_idle();
        if let Some((_evicted_key, mut evicted_conn)) = self.entries.push(key, conn) {
            evicted_conn.mark_active();
            tokio::spawn(async move {
                if let Err(err) = evicted_conn.shutdown(shutdown_timeout).await {
                    debug!(
                        host = %evicted_conn.host,
                        port = evicted_conn.port,
                        scheme = ?evicted_conn.scheme,
                        error = %err,
                        "failed to shutdown evicted upstream connection"
                    );
                }
            });
        }
    }

    pub(super) async fn shutdown_all(&mut self, timeout: Duration) -> Result<()> {
        while let Some((_key, mut conn)) = self.entries.pop_lru() {
            conn.mark_active();
            if let Err(err) = conn.shutdown(timeout).await {
                debug!(
                    host = %conn.host,
                    port = conn.port,
                    scheme = ?conn.scheme,
                    error = %err,
                    "failed to shutdown cached upstream connection"
                );
            }
        }
        Ok(())
    }
}

fn idle_stream_is_reusable(stream: &mut (impl AsyncRead + Unpin)) -> bool {
    // Poll once before sending a request. EOF, errors, and unsolicited HTTP
    // bytes make an idle connection unusable. The peer can still close later.
    let mut probe = [0u8; 1];
    stream.read(&mut probe).now_or_never().is_none()
}

impl UpstreamKey {
    pub(super) fn from_request(
        request: &ParsedRequest,
        authorization_context: Option<[u8; 32]>,
    ) -> Self {
        let port = request
            .port
            .unwrap_or_else(|| request.scheme.default_port());
        Self {
            scheme: request.scheme,
            host: request.host.clone(),
            port,
            authorization_context,
        }
    }
}

impl UpstreamConnection {
    fn mark_idle(&mut self) {
        if !self.idle {
            self.idle = true;
            crate::metrics::inc_upstream_connections_idle();
        }
    }

    fn mark_active(&mut self) {
        if self.idle {
            self.idle = false;
            crate::metrics::dec_upstream_connections_idle();
        }
    }

    pub(super) async fn connect(
        request: &ParsedRequest,
        app: &AppContext,
        connect_timeout: Duration,
        binding: Option<&ResolvedTarget>,
    ) -> Result<Self> {
        let port = request
            .port
            .unwrap_or_else(|| request.scheme.default_port());
        let addresses = upstream::resolve_or_use_binding(
            &request.host,
            port,
            binding,
            app.upstream_resolver(),
            app.settings.dns_resolve_timeout(),
        )
        .await?;
        Self::connect_resolved(request, app, connect_timeout, &addresses).await
    }

    pub(super) async fn connect_resolved(
        request: &ParsedRequest,
        app: &AppContext,
        connect_timeout: Duration,
        addresses: &[SocketAddr],
    ) -> Result<Self> {
        let port = request
            .port
            .unwrap_or_else(|| request.scheme.default_port());
        let (upstream_tcp, peer) = upstream::connect_to_addrs(addresses, connect_timeout).await?;
        let metrics = crate::metrics::track_upstream_connection();
        let stream = if request.scheme == Scheme::Https {
            let server_name = ServerName::try_from(request.host.as_str())
                .map_err(|_| anyhow!("invalid upstream host for TLS '{}'", request.host))?
                .to_owned();
            let connector = TlsConnector::from(app.tls.client_http1.clone());
            let tls = timeout(
                app.settings.tls_handshake_timeout(),
                connector.connect(server_name, upstream_tcp),
            )
            .await
            .map_err(|_| anyhow!("TLS handshake with upstream timed out"))?
            .with_context(|| {
                format!(
                    "failed to establish TLS with upstream {}:{}",
                    request.host, port
                )
            })?;
            UpstreamIo::Tls(Box::new(tls))
        } else {
            UpstreamIo::Plain(upstream_tcp)
        };
        Ok(Self {
            stream,
            peer,
            scheme: request.scheme,
            host: request.host.clone(),
            port,
            metrics,
            idle: false,
        })
    }

    pub(super) async fn shutdown(&mut self, timeout: Duration) -> Result<()> {
        self.mark_active();
        shutdown_stream(&mut self.stream, timeout).await
    }
}

impl Drop for UpstreamConnection {
    fn drop(&mut self) {
        if self.idle {
            self.idle = false;
            crate::metrics::dec_upstream_connections_idle();
        }
        self.metrics.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_stream_reuses_pending_read() {
        let (mut stream, _peer) = tokio::io::duplex(1);
        assert!(idle_stream_is_reusable(&mut stream));
    }

    #[test]
    fn idle_stream_discards_eof() {
        assert!(!idle_stream_is_reusable(&mut tokio::io::empty()));
    }

    #[test]
    fn idle_stream_discards_unsolicited_data() {
        let mut stream = b"HTTP/1.1 200 OK\r\n\r\n".as_slice();
        assert!(!idle_stream_is_reusable(&mut stream));
    }

    #[test]
    fn idle_stream_discards_read_error() {
        struct ResetStream;

        impl AsyncRead for ResetStream {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
            }
        }

        assert!(!idle_stream_is_reusable(&mut ResetStream));
    }

    #[test]
    fn upstream_key_depends_only_on_origin() {
        let request = ParsedRequest {
            method: http::Method::GET,
            scheme: Scheme::Https,
            authority: "example.com".to_string(),
            host: "example.com".to_string(),
            port: Some(443),
            path: "/".to_string(),
            policy_path: "/".to_string(),
            flow: None,
            client_name: None,
        };

        let first = UpstreamKey::from_request(&request, None);
        let second = UpstreamKey::from_request(
            &ParsedRequest {
                path: "/other".to_string(),
                ..request
            },
            None,
        );

        assert_eq!(first, second, "upstream key should ignore request path");
    }

    #[test]
    fn upstream_key_separates_authorization_contexts() {
        let request = ParsedRequest {
            method: http::Method::GET,
            scheme: Scheme::Https,
            authority: "example.com".to_string(),
            host: "example.com".to_string(),
            port: Some(443),
            path: "/".to_string(),
            policy_path: "/".to_string(),
            flow: None,
            client_name: None,
        };
        assert_ne!(
            UpstreamKey::from_request(&request, Some([1; 32])),
            UpstreamKey::from_request(&request, Some([2; 32]))
        );
    }
}
