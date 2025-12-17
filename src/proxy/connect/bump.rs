use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use rustls::{crypto::ring, pki_types::ServerName, server::ServerConfig, sign::SingleCertAndKey};
use tokio::time::timeout;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::warn;

use crate::proxy::{
    AppContext,
    http::handle_decrypted_https,
    http2::{self, PrimedHttp2Upstream},
    upstream,
};

use super::{resolve::ResolvedTarget, splice::send_connect_established, target::ConnectTarget};

pub struct BumpStats {
    pub handshake_bytes: u64,
}

pub async fn handle_bump(
    stream: TcpStream,
    target: &ConnectTarget,
    resolved: ResolvedTarget,
    app: &AppContext,
    peer: SocketAddr,
) -> Result<BumpStats> {
    let mut stream = stream;
    let client_timeout = app.settings.client_timeout();
    let handshake_bytes = send_connect_established(&mut stream, client_timeout).await?;

    let probe = match probe_upstream_http2(&resolved, app).await {
        Ok(outcome) => outcome,
        Err(err) => {
            warn!(
                peer = %peer,
                host = %target.host,
                error = %err,
                "failed to probe upstream for HTTP/2 support; preferring HTTP/1.1"
            );
            UpstreamProbe::Http1
        }
    };

    let (supports_h2, primed) = match probe {
        UpstreamProbe::Http2 { stream, peer } => (
            true,
            Some(PrimedHttp2Upstream {
                stream: *stream,
                peer,
            }),
        ),
        UpstreamProbe::Http1 => (false, None),
    };

    let server_config = build_server_config(app, &target.host, supports_h2)?;
    let acceptor = TlsAcceptor::from(server_config);
    let tls_stream = acceptor
        .accept(stream)
        .await
        .context("failed to complete TLS handshake with client during CONNECT bump")?;
    let negotiated = tls_stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|proto| proto.to_vec());

    if supports_h2 && negotiated.as_deref() == Some(b"h2") {
        http2::serve_bumped_http2(
            tls_stream,
            peer,
            app.clone(),
            Some(resolved.clone()),
            primed,
        )
        .await?;
    } else {
        handle_decrypted_https(tls_stream, peer, app.clone(), Some(resolved)).await?;
    }

    Ok(BumpStats { handshake_bytes })
}

fn build_server_config(app: &AppContext, host: &str, prefer_h2: bool) -> Result<Arc<ServerConfig>> {
    let certified = app.tls.issuer.issue(&[host])?;
    let provider = ring::default_provider();
    let builder = ServerConfig::builder_with_provider(provider.into());
    let builder = builder.with_safe_default_protocol_versions()?;
    let resolver = SingleCertAndKey::from(certified.clone());
    let mut config = builder
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    if prefer_h2 {
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    } else {
        config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
    }
    Ok(Arc::new(config))
}

/// Attempts to determine if the upstream server supports HTTP/2.
///
/// This is critical because if the proxy negotiates H2 with the client but the
/// upstream only supports H1.1, the proxy would have to perform expensive
/// protocol translation. By probing first, we can align the ALPN offer
/// sent to the client with the upstream's capabilities.
async fn probe_upstream_http2(
    resolved: &ResolvedTarget,
    app: &AppContext,
) -> Result<UpstreamProbe> {
    let connect_timeout = app.settings.upstream_connect_timeout();
    let (tcp, peer) = upstream::connect_to_addrs(resolved.addresses(), connect_timeout).await?;

    let server_name = match ServerName::try_from(resolved.host()) {
        Ok(name) => name.to_owned(),
        Err(_) => return Ok(UpstreamProbe::Http1),
    };

    let connector = TlsConnector::from(app.tls.client_http2.clone());
    let tls_stream = match timeout(
        app.settings.upstream_timeout(),
        connector.connect(server_name, tcp),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            if is_no_alpn_error(&err) {
                return Ok(UpstreamProbe::Http1);
            }
            return Err(err.into());
        }
        Err(_) => return Err(anyhow!("probing upstream for HTTP/2 support timed out")),
    };

    let negotiated = tls_stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|proto| proto.to_vec());

    if negotiated.as_deref() == Some(b"h2") {
        let peer_addr = tls_stream.get_ref().0.peer_addr().unwrap_or(peer);
        Ok(UpstreamProbe::Http2 {
            stream: Box::new(tls_stream),
            peer: peer_addr,
        })
    } else {
        let mut tls_stream = tls_stream;
        let _ = tls_stream.shutdown().await;
        Ok(UpstreamProbe::Http1)
    }
}

fn is_no_alpn_error(err: &std::io::Error) -> bool {
    if let Some(inner) = err.get_ref()
        && inner.to_string().contains("NoApplicationProtocol")
    {
        return true;
    }
    err.to_string().contains("NoApplicationProtocol")
}

enum UpstreamProbe {
    Http2 {
        stream: Box<tokio_rustls::client::TlsStream<TcpStream>>,
        peer: SocketAddr,
    },
    Http1,
}
