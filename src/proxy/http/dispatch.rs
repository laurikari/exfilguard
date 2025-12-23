use std::{net::SocketAddr, time::Instant};

use anyhow::Result;
use http::{Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tracing::warn;

use crate::config::Scheme;
use crate::logging::AccessLogBuilder;

use crate::proxy::AppContext;
use crate::proxy::connect::ResolvedTarget;
use crate::proxy::request::scheme_name;

use super::codec::{Http1RequestHead, read_http1_request_head};
use super::pipeline::{
    ClientDisposition, RequestContext, handle_non_connect, respond_with_access_log,
};
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
    let keepalive_timeout = app.settings.client_keepalive_idle_timeout();
    let header_timeout = app.settings.request_header_timeout();
    let response_timeout = app.settings.response_body_idle_timeout();
    let max_request_header_size = app.settings.max_request_header_size;
    let mut reader = BufReader::new(stream);
    let mut upstream_pool = UpstreamPool::new(app.settings.upstream_pool_capacity_nonzero());
    let binding = connect_binding.as_ref();

    loop {
        let start = Instant::now();
        let request_head = match read_http1_request_head(
            &mut reader,
            peer,
            keepalive_timeout,
            header_timeout,
            max_request_header_size,
        )
        .await
        {
            Ok(Some(head)) => head,
            Ok(None) => break,
            Err(err) => {
                let err_message = err.to_string();
                if err_message.starts_with("timed out") {
                    warn!(peer = %peer, error = %err, "client request timed out");
                    break;
                }
                warn!(peer = %peer, error = %err, "invalid request");
                respond_with_access_log(
                    reader.get_mut(),
                    StatusCode::BAD_REQUEST,
                    None,
                    b"invalid request\r\n",
                    response_timeout,
                    0,
                    start.elapsed(),
                    AccessLogBuilder::new(peer)
                        .method("UNKNOWN")
                        .scheme(scheme_name(fallback_scheme))
                        .host("")
                        .path("")
                        .decision("ERROR"),
                )
                .await?;
                break;
            }
        };
        let Http1RequestHead {
            method,
            target,
            headers,
            request_line_bytes,
            header_bytes,
        } = request_head;

        if allow_connect && method == Method::CONNECT {
            let host_header = headers.host().map(|h| h.to_owned());
            let request_bytes = request_line_bytes + header_bytes;
            let stream = reader.into_inner();
            upstream_pool
                .shutdown_all(app.settings.response_body_idle_timeout())
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
        .shutdown_all(app.settings.response_body_idle_timeout())
        .await?;
    Ok(LoopOutcome::Completed)
}
