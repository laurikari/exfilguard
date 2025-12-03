use std::net::SocketAddr;

use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::config::Scheme;
use crate::proxy::AppContext;
use crate::proxy::connect::{self, ResolvedTarget};

use super::dispatch::{self, HttpLoopOptions, LoopOutcome};

pub async fn handle_http(stream: TcpStream, peer: SocketAddr, app: AppContext) -> Result<()> {
    serve_plain_http(stream, peer, app).await
}

pub async fn handle_decrypted_https<S>(
    stream: S,
    peer: SocketAddr,
    app: AppContext,
    connect_binding: Option<ResolvedTarget>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_bumped_connection(stream, peer, app, connect_binding).await
}

async fn serve_plain_http(stream: TcpStream, peer: SocketAddr, app: AppContext) -> Result<()> {
    match dispatch::serve_http_loop(
        stream,
        peer,
        &app,
        HttpLoopOptions {
            allow_connect: true,
            fallback_scheme: Scheme::Http,
            connect_binding: None,
        },
    )
    .await?
    {
        LoopOutcome::Completed => Ok(()),
        LoopOutcome::Connect(connect) => {
            let snapshot = app.policies.snapshot();
            connect::handle_connect(connect::ConnectRequest {
                stream: connect.stream,
                peer,
                target: connect.target.as_str(),
                host_header: connect.host_header.as_deref(),
                snapshot,
                app: &app,
                request_bytes: connect.request_bytes,
                start: connect.start,
            })
            .await
        }
    }
}

async fn serve_bumped_connection<S>(
    stream: S,
    peer: SocketAddr,
    app: AppContext,
    connect_binding: Option<ResolvedTarget>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    match dispatch::serve_http_loop(
        stream,
        peer,
        &app,
        HttpLoopOptions {
            allow_connect: false,
            fallback_scheme: Scheme::Https,
            connect_binding,
        },
    )
    .await?
    {
        LoopOutcome::Completed => Ok(()),
        LoopOutcome::Connect(_) => bail!("unexpected CONNECT request over bumped HTTPS connection"),
    }
}
