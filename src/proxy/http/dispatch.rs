use std::{net::SocketAddr, time::Instant};

use anyhow::Result;
use http::Method;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};

use crate::config::Scheme;

use crate::proxy::AppContext;
use crate::proxy::connect::ResolvedTarget;

use super::codec::{RequestHead, read_request_head};
use super::pipeline::{ClientDisposition, RequestContext, handle_non_connect};
use super::upstream::UpstreamPool;

pub(super) struct HttpLoopOptions {
    pub allow_connect: bool,
    pub fallback_scheme: Scheme,
    pub connect_binding: Option<ResolvedTarget>,
}

pub(super) enum LoopOutcome<S> {
    Completed,
    Connect(ConnectRequest<S>),
}

pub(super) struct ConnectRequest<S> {
    pub stream: S,
    pub target: String,
    pub host_header: Option<String>,
    pub request_bytes: usize,
    pub start: Instant,
}

pub(super) async fn serve_http_loop<S>(
    stream: S,
    peer: SocketAddr,
    app: &AppContext,
    options: HttpLoopOptions,
) -> Result<LoopOutcome<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let HttpLoopOptions {
        allow_connect,
        fallback_scheme,
        connect_binding,
    } = options;
    let client_timeout = app.settings.client_timeout();
    let max_header_size = app.settings.max_header_size;
    let mut reader = BufReader::new(stream);
    let mut upstream_pool = UpstreamPool::new(app.settings.upstream_pool_capacity_nonzero());
    let binding = connect_binding.as_ref();

    loop {
        let start = Instant::now();
        let Some(RequestHead {
            method,
            target,
            headers,
            request_line_bytes,
            header_bytes,
        }) = read_request_head(&mut reader, peer, client_timeout, max_header_size).await?
        else {
            break;
        };

        if allow_connect && method == Method::CONNECT {
            let host_header = headers.host().map(|h| h.to_owned());
            let request_bytes = request_line_bytes + header_bytes;
            let stream = reader.into_inner();
            upstream_pool
                .shutdown_all(app.settings.upstream_timeout())
                .await?;
            return Ok(LoopOutcome::Connect(ConnectRequest {
                stream,
                target,
                host_header,
                request_bytes,
                start,
            }));
        }

        let ctx = RequestContext {
            method,
            target,
            headers,
            request_line_bytes,
            header_bytes,
            start,
            fallback_scheme,
        };

        match handle_non_connect(&mut reader, peer, app, &mut upstream_pool, ctx, binding).await? {
            ClientDisposition::Continue => continue,
            ClientDisposition::Close => break,
        }
    }

    upstream_pool
        .shutdown_all(app.settings.upstream_timeout())
        .await?;
    Ok(LoopOutcome::Completed)
}
