use std::{net::SocketAddr, time::Instant};

use anyhow::Result;
use http::{Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::warn;

use crate::config::Scheme;
use crate::logging::AccessLogBuilder;

use crate::proxy::AppContext;
use crate::proxy::connect::ResolvedTarget;
use crate::proxy::request::{RequestFlowContext, request_target_for_log, scheme_name};

use super::codec::{Http1RequestHead, read_http1_request_head};
use super::pipeline::{
    ClientDisposition, RequestContext, handle_non_connect, respond_with_access_log,
};
use super::upstream::UpstreamPool;

pub(super) struct HttpLoopOptions {
    pub allow_connect: bool,
    pub fallback_scheme: Scheme,
    pub connect_binding: Option<ResolvedTarget>,
    pub flow_context: Option<RequestFlowContext>,
    pub client_session: std::sync::Arc<crate::authentication::ConnectionSession>,
}

pub(super) enum LoopOutcome<S> {
    Completed,
    Connect(ConnectRequest<S>),
}

pub(super) struct ConnectRequest<S> {
    pub stream: S,
    pub prefetched: Vec<u8>,
    pub target: String,
    pub request_bytes: usize,
    pub start: Instant,
    pub snapshot: crate::policy::matcher::PolicySnapshot,
    pub authorization_token: Option<std::sync::Arc<crate::authorization::AuthorizationToken>>,
    pub client_session: std::sync::Arc<crate::authentication::ConnectionSession>,
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
        flow_context,
        client_session,
    } = options;
    let keepalive_timeout = app.settings.client_keepalive_idle_timeout();
    let header_timeout = app.settings.request_header_timeout();
    let response_timeout = app.settings.response_body_idle_timeout();
    let max_request_header_size = app.settings.max_request_header_size;
    let mut reader = BufReader::new(stream);
    let mut upstream_pool = UpstreamPool::new(app.settings.upstream_pool_capacity_nonzero());
    let binding = connect_binding.as_ref();

    loop {
        let header_start = Instant::now();
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
                    None,
                    response_timeout,
                    0,
                    header_start.elapsed(),
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

        let snapshot = app.policies.snapshot();
        let was_bound = client_session.client_name().is_some();
        let authentication = client_session
            .authenticate(
                &snapshot,
                peer.ip(),
                headers
                    .proxy_authorizations()
                    .iter()
                    .map(|value| value.as_slice())
                    .collect(),
                app,
            )
            .await;
        let snapshot = app.policies.snapshot();
        let authentication = authentication.and_then(|()| {
            if client_session.valid(&snapshot, peer.ip()) {
                Ok(())
            } else {
                Err(crate::authentication::AuthenticationError::Denied)
            }
        });
        if let Err(error) = authentication {
            let busy = matches!(error, crate::authentication::AuthenticationError::Busy);
            crate::metrics::record_authentication(if busy { "busy" } else { "denied" });
            let challenge = crate::authentication::challenges(&snapshot, peer.ip());
            respond_with_access_log(
                reader.get_mut(),
                if busy {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::PROXY_AUTHENTICATION_REQUIRED
                },
                None,
                b"proxy authentication failed\r\n",
                if busy || challenge.is_empty() {
                    None
                } else {
                    Some(challenge.as_slice())
                },
                response_timeout,
                (request_line_bytes + header_bytes) as u64,
                header_start.elapsed(),
                AccessLogBuilder::new(peer)
                    .method(method.as_str())
                    .scheme(scheme_name(fallback_scheme))
                    .host(headers.host().unwrap_or(""))
                    .path("")
                    .decision("DENY")
                    .error_reason(if busy {
                        "authentication_busy"
                    } else {
                        "proxy_authentication"
                    }),
            )
            .await?;
            break;
        }
        if !was_bound {
            crate::metrics::record_authentication("success");
        }
        let authorization_token = client_session.authorization_token();
        if headers.requests_upgrade() {
            let scheme = if method == Method::CONNECT {
                Scheme::Https
            } else {
                fallback_scheme
            };
            let mut log = AccessLogBuilder::new(peer)
                .method(method.as_str())
                .scheme(scheme_name(scheme))
                .host(headers.host().unwrap_or(""))
                .path(request_target_for_log(&target, app.settings.log_queries))
                .apply_flow_context(flow_context.as_ref(), method.as_str())
                .decision("ERROR")
                .error_reason("upgrade_unsupported");
            if let Some(client) =
                snapshot.request_client(peer.ip(), client_session.client_name().as_deref())
            {
                log = log.client(client.name.as_ref());
            }
            respond_with_access_log(
                reader.get_mut(),
                StatusCode::NOT_IMPLEMENTED,
                None,
                b"HTTP/1.1 Upgrade is not supported by ExfilGuard\r\n",
                None,
                response_timeout,
                (request_line_bytes + header_bytes) as u64,
                header_start.elapsed(),
                log,
            )
            .await?;
            break;
        }

        if allow_connect && method == Method::CONNECT {
            let request_bytes = request_line_bytes + header_bytes;
            let prefetched = reader.buffer().to_vec();
            let stream = reader.into_inner();
            upstream_pool
                .shutdown_all(app.settings.response_body_idle_timeout())
                .await?;
            return Ok(LoopOutcome::Connect(ConnectRequest {
                stream,
                prefetched,
                target,
                request_bytes,
                start: header_start,
                snapshot,
                authorization_token,
                client_session: client_session.clone(),
            }));
        }

        // Connection authentication is complete. Give request processing its full timeout budget.
        let start = Instant::now();

        let ctx = RequestContext {
            method,
            target,
            headers,
            request_line_bytes,
            header_bytes,
            start,
            fallback_scheme,
            snapshot,
            authorization_token,
            client_name: client_session.client_name(),
        };

        match handle_non_connect(
            &mut reader,
            peer,
            app,
            &mut upstream_pool,
            ctx,
            binding,
            flow_context.as_ref(),
        )
        .await?
        {
            ClientDisposition::Continue => continue,
            ClientDisposition::Close => break,
        }
    }

    upstream_pool
        .shutdown_all(app.settings.response_body_idle_timeout())
        .await?;
    let _ = tokio::time::timeout(
        app.settings.response_body_idle_timeout(),
        reader.get_mut().shutdown(),
    )
    .await;
    Ok(LoopOutcome::Completed)
}
