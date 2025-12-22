use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use lru::LruCache;
use rustls::pki_types::ServerName;
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
    allow_private: bool,
}

pub(super) struct UpstreamConnection {
    pub(super) stream: UpstreamIo,
    pub(super) peer: SocketAddr,
    pub(super) scheme: Scheme,
    pub(super) host: String,
    pub(super) port: u16,
}

impl UpstreamPool {
    pub(super) fn new(capacity: NonZeroUsize) -> Self {
        crate::metrics::set_pool_capacity(capacity.get());
        let entries = LruCache::new(capacity);
        let pool = Self { entries };
        crate::metrics::set_pool_in_use(pool.entries.len());
        pool
    }

    pub(super) fn take(&mut self, key: &UpstreamKey) -> Option<UpstreamConnection> {
        let value = self.entries.pop(key);
        crate::metrics::set_pool_in_use(self.entries.len());
        value
    }

    pub(super) fn put(
        &mut self,
        key: UpstreamKey,
        conn: UpstreamConnection,
        shutdown_timeout: Duration,
    ) {
        if let Some((_evicted_key, mut evicted_conn)) = self.entries.push(key, conn) {
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
        crate::metrics::set_pool_in_use(self.entries.len());
    }

    pub(super) async fn shutdown_all(&mut self, timeout: Duration) -> Result<()> {
        while let Some((_key, mut conn)) = self.entries.pop_lru() {
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
        crate::metrics::set_pool_in_use(0);
        Ok(())
    }
}

impl UpstreamKey {
    pub(super) fn from_request(request: &ParsedRequest, allow_private: bool) -> Self {
        let port = request
            .port
            .unwrap_or_else(|| request.scheme.default_port());
        Self {
            scheme: request.scheme,
            host: request.host.clone(),
            port,
            allow_private,
        }
    }

    #[cfg(test)]
    pub(super) fn new(scheme: Scheme, host: String, port: u16, allow_private: bool) -> Self {
        Self {
            scheme,
            host,
            port,
            allow_private,
        }
    }
}

impl UpstreamConnection {
    pub(super) async fn connect(
        request: &ParsedRequest,
        app: &AppContext,
        connect_timeout: Duration,
        binding: Option<&ResolvedTarget>,
        allow_private_upstream: bool,
    ) -> Result<Self> {
        let port = request
            .port
            .unwrap_or_else(|| request.scheme.default_port());
        let addresses = upstream::resolve_or_use_binding(
            &request.host,
            port,
            binding,
            app.settings.dns_resolve_timeout(),
            allow_private_upstream,
            "policy allow_private_upstream permitted private upstream address",
        )
        .await?;
        let (upstream_tcp, peer) = upstream::connect_to_addrs(&addresses, connect_timeout).await?;
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
        })
    }

    pub(super) async fn shutdown(&mut self, timeout: Duration) -> Result<()> {
        shutdown_stream(&mut self.stream, timeout).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_key_includes_allow_private_flag() {
        let request = ParsedRequest {
            method: http::Method::GET,
            scheme: Scheme::Https,
            host: "example.com".to_string(),
            port: Some(443),
            path: "/".to_string(),
        };

        let key_allow = UpstreamKey::from_request(&request, true);
        let key_disallow = UpstreamKey::from_request(&request, false);

        assert_ne!(
            key_allow, key_disallow,
            "allow_private flag must contribute to the upstream pool key"
        );
    }

    #[tokio::test]
    async fn pool_does_not_reuse_private_allowed_conn_for_disallowing_request() -> Result<()> {
        use crate::proxy::http::forward::UpstreamIo;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind listener")?;
        let addr = listener.local_addr().context("local addr")?;
        let accept = tokio::spawn(async move { listener.accept().await });

        let mut pool = UpstreamPool::new(std::num::NonZeroUsize::new(4).unwrap());
        let client = tokio::net::TcpStream::connect(addr)
            .await
            .context("connect to listener")?;

        // Complete accept so the client stream is valid.
        let (_server_stream, _) = accept
            .await
            .expect("accept join")
            .context("accept stream")?;

        let allow_key = UpstreamKey::new(Scheme::Http, "example.com".into(), addr.port(), true);
        let disallow_key = UpstreamKey::new(Scheme::Http, "example.com".into(), addr.port(), false);

        pool.put(
            allow_key.clone(),
            UpstreamConnection {
                stream: UpstreamIo::Plain(client),
                peer: addr,
                scheme: Scheme::Http,
                host: "example.com".into(),
                port: addr.port(),
            },
            Duration::from_millis(50),
        );

        assert!(
            pool.take(&disallow_key).is_none(),
            "connection made with allow_private=true must not be reused when allow_private=false"
        );

        // It should still be reusable when allow_private=true.
        let mut reused = pool
            .take(&allow_key)
            .expect("allow_private=true connection should be reused when allowed");
        reused.shutdown(Duration::from_millis(50)).await?;
        Ok(())
    }
}
