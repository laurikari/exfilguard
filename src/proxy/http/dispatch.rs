use std::{net::SocketAddr, time::Instant};

use anyhow::Result;
use http::{Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tracing::warn;

use crate::authorization::AuthorizationToken;
use crate::config::Scheme;
use crate::logging::AccessLogBuilder;

use crate::proxy::AppContext;
use crate::proxy::connect::ResolvedTarget;
use crate::proxy::request::{RequestFlowContext, scheme_name};

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
    pub authorization_token: Option<std::sync::Arc<AuthorizationToken>>,
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
    } = options;
    let keepalive_timeout = app.settings.client_keepalive_idle_timeout();
    let header_timeout = app.settings.request_header_timeout();
    let response_timeout = app.settings.response_body_idle_timeout();
    let max_request_header_size = app.settings.max_request_header_size;
    let mut reader = BufReader::new(stream);
    let mut upstream_pool = UpstreamPool::new(app.settings.upstream_pool_capacity_nonzero());
    let binding = connect_binding.as_ref();
    let mut bound_authorization_token = flow_context
        .as_ref()
        .and_then(|flow| flow.authorization_token.clone());

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
        let requires_authorization = snapshot
            .resolve_client(peer.ip())
            .is_some_and(|client| client.authorization_service.is_some());
        let authorization_token = match bind_authorization_token(
            app,
            &headers,
            &mut bound_authorization_token,
            requires_authorization,
        ) {
            Ok(token) => token,
            Err(()) => {
                warn!(peer = %peer, "proxy authorization token rejected");
                respond_with_access_log(
                    reader.get_mut(),
                    StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                    None,
                    b"proxy authentication required\r\n",
                    Some("ExfilGuard"),
                    response_timeout,
                    (request_line_bytes + header_bytes) as u64,
                    header_start.elapsed(),
                    AccessLogBuilder::new(peer)
                        .method(method.as_str())
                        .scheme(scheme_name(fallback_scheme))
                        .host(headers.host().unwrap_or(""))
                        .path("")
                        .decision("DENY")
                        .error_reason("proxy_authentication"),
                )
                .await?;
                break;
            }
        };

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
            }));
        }

        // Header receipt has its own deadline. The total request budget begins only after the
        // complete request head is accepted, matching HTTP/2 stream handling.
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
    Ok(LoopOutcome::Completed)
}

fn bind_authorization_token(
    app: &AppContext,
    headers: &super::codec::Http1HeaderAccumulator,
    bound: &mut Option<std::sync::Arc<AuthorizationToken>>,
    required: bool,
) -> Result<Option<std::sync::Arc<AuthorizationToken>>, ()> {
    if !required {
        return Ok(None);
    }
    let authorization = app.authorization.as_ref().ok_or(())?;
    let values = headers.proxy_authorizations();
    if values.len() > 1 {
        return Err(());
    }
    let presented = values
        .first()
        .map(|value| authorization.parse_token(value.as_slice()))
        .transpose()
        .map_err(|_| ())?;
    update_bound_authorization_token(bound, presented)
}

fn update_bound_authorization_token(
    bound: &mut Option<std::sync::Arc<AuthorizationToken>>,
    presented: Option<std::sync::Arc<AuthorizationToken>>,
) -> Result<Option<std::sync::Arc<AuthorizationToken>>, ()> {
    match (bound.as_ref(), presented) {
        (Some(existing), Some(presented)) if existing.hash() == presented.hash() => {
            Ok(Some(existing.clone()))
        }
        (Some(existing), None) => Ok(Some(existing.clone())),
        (Some(_), Some(_)) => Err(()),
        (None, Some(presented)) => {
            *bound = Some(presented.clone());
            Ok(Some(presented))
        }
        (None, None) => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::update_bound_authorization_token;
    use crate::authorization::AuthorizationToken;

    #[test]
    fn downstream_connection_binds_one_authorization_token_and_rejects_switching() {
        let first = AuthorizationToken::parse(b"ExfilGuard first-token", 128).unwrap();
        let same = AuthorizationToken::parse(b"ExfilGuard first-token", 128).unwrap();
        let second = AuthorizationToken::parse(b"ExfilGuard second-token", 128).unwrap();
        let mut bound = None;

        update_bound_authorization_token(&mut bound, Some(first.clone())).unwrap();
        update_bound_authorization_token(&mut bound, None).unwrap();
        update_bound_authorization_token(&mut bound, Some(same)).unwrap();
        assert!(update_bound_authorization_token(&mut bound, Some(second)).is_err());
        assert_eq!(bound.unwrap().hash(), first.hash());
    }
}
