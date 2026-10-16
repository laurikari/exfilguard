mod cache;
mod connection;
mod request;
mod response;

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use http::Method;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tracing::debug;

use crate::authorization::{BodyAccess, BufferedBody, FinalizedProtocol, FinalizedRequestV1};
use crate::proxy::AppContext;
use crate::proxy::connect::ResolvedTarget;
use crate::proxy::forward_error::{InformationalResponseStarted, UpstreamClosed};
use crate::proxy::forward_limits::{AllowLogTracker, RequestDeadline, ResponseProgress};
use crate::proxy::policy_eval::AllowDecision;
use crate::proxy::request::ParsedRequest;

use super::body::{BodyPlan, BodyTooLarge, buffer_chunked_body, buffer_fixed_body};
use super::codec::Http1HeaderAccumulator;
use super::upstream::{UpstreamConnection, UpstreamKey, UpstreamPool};

pub(crate) use connection::UpstreamIo;
#[cfg(test)]
pub(crate) use request::build_upstream_request;
#[cfg(feature = "fuzzing")]
pub(crate) use response::normalize_final_response_framing;
pub(crate) use response::{ResponseBodyPlan, determine_response_body_plan};

pub struct ForwardTimeouts {
    pub connect: Duration,
    pub request_io: Duration,
    pub response_header: Duration,
    pub response_io: Duration,
}

#[derive(Clone, Copy)]
pub enum CacheStoreResult {
    Stored,
    Skipped,
    Bypassed,
}

impl CacheStoreResult {
    pub fn as_str(self) -> &'static str {
        match self {
            CacheStoreResult::Stored => "stored",
            CacheStoreResult::Skipped => "skipped",
            CacheStoreResult::Bypassed => "bypassed",
        }
    }
}

pub struct ForwardStats {
    pub bytes_to_client: u64,
    pub status: http::StatusCode,
    pub client_body_bytes: u64,
    pub cache_store: CacheStoreResult,
}

pub struct ForwardResult {
    pub stats: ForwardStats,
    pub client_close: bool,
    pub upstream_addr: SocketAddr,
    pub reused_existing: bool,
}

#[allow(clippy::too_many_arguments)]
pub async fn forward_to_upstream<S>(
    client_reader: &mut BufReader<S>,
    pool: &mut UpstreamPool,
    request: &ParsedRequest,
    headers: &Http1HeaderAccumulator,
    body_plan: BodyPlan,
    connect_binding: Option<&ResolvedTarget>,
    timeouts: &ForwardTimeouts,
    request_deadline: RequestDeadline,
    response_progress: &ResponseProgress,
    expect_continue: bool,
    decision: &AllowDecision,
    peer: SocketAddr,
    max_request_body_size: usize,
    app: &AppContext,
    log_tracker: &mut AllowLogTracker,
) -> Result<ForwardResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(credential) = decision
        .authorization
        .as_ref()
        .and_then(|authorization| authorization.credential.as_ref())
    {
        return forward_credential_request(
            client_reader,
            pool,
            request,
            headers,
            body_plan,
            connect_binding,
            timeouts,
            request_deadline,
            response_progress,
            expect_continue,
            decision,
            credential,
            peer,
            app,
            log_tracker,
        )
        .await;
    }

    let authorization_context = decision
        .authorization
        .as_ref()
        .map(|authorization| authorization.token.hash());
    let key = UpstreamKey::from_request(request, authorization_context);
    let request_close = headers.wants_connection_close();
    let (mut connection, reused_existing) = match pool.take(&key) {
        Some(conn) => {
            debug!(
                host = %conn.host,
                port = conn.port,
                scheme = ?conn.scheme,
                "reusing upstream connection"
            );
            crate::metrics::record_pool_reuse(true);
            (conn, true)
        }
        None => {
            crate::metrics::record_pool_miss();
            let conn = UpstreamConnection::connect(request, app, timeouts.connect, connect_binding)
                .await?;
            crate::metrics::record_pool_reuse(false);
            (conn, false)
        }
    };

    let outcome = connection::forward_with_connection(
        client_reader,
        &mut connection,
        request,
        headers,
        body_plan,
        timeouts,
        request_deadline,
        response_progress,
        expect_continue,
        peer,
        max_request_body_size,
        request_close,
        app.settings.max_response_header_size,
        decision,
        app,
        None,
    )
    .await;

    match outcome {
        Err(err)
            if should_retry_reused_connection(
                reused_existing,
                &request.method,
                body_plan,
                response_progress,
                &err,
            ) =>
        {
            debug!(
                host = %connection.host,
                port = connection.port,
                scheme = ?connection.scheme,
                error = %err,
                "retrying request on a fresh upstream connection after stale keep-alive reuse"
            );
            if let Err(shutdown_err) = connection.shutdown(timeouts.response_io).await {
                debug!(
                    host = %connection.host,
                    port = connection.port,
                    scheme = ?connection.scheme,
                    error = %shutdown_err,
                    "failed to shutdown stale upstream connection before retry"
                );
            }

            crate::metrics::record_pool_miss();
            let mut fresh_connection =
                UpstreamConnection::connect(request, app, timeouts.connect, connect_binding)
                    .await?;
            crate::metrics::record_pool_reuse(false);

            let retry_outcome = connection::forward_with_connection(
                client_reader,
                &mut fresh_connection,
                request,
                headers,
                body_plan,
                timeouts,
                request_deadline,
                response_progress,
                expect_continue,
                peer,
                max_request_body_size,
                request_close,
                app.settings.max_response_header_size,
                decision,
                app,
                None,
            )
            .await;

            finalize_forward_attempt(
                pool,
                key,
                fresh_connection,
                retry_outcome,
                timeouts.response_io,
                false,
            )
            .await
        }
        _ => {
            finalize_forward_attempt(
                pool,
                key,
                connection,
                outcome,
                timeouts.response_io,
                reused_existing,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_credential_request<S>(
    client_reader: &mut BufReader<S>,
    pool: &mut UpstreamPool,
    request: &ParsedRequest,
    headers: &Http1HeaderAccumulator,
    body_plan: BodyPlan,
    connect_binding: Option<&ResolvedTarget>,
    timeouts: &ForwardTimeouts,
    request_deadline: RequestDeadline,
    response_progress: &ResponseProgress,
    expect_continue: bool,
    decision: &AllowDecision,
    credential: &crate::authorization::policy::CredentialAuthorization,
    peer: SocketAddr,
    app: &AppContext,
    log_tracker: &mut AllowLogTracker,
) -> Result<ForwardResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if expect_continue {
        return Err(
            crate::proxy::forward_error::CredentialRequestRejected::expectation_failed().into(),
        );
    }
    if credential.body_access == BodyAccess::None && !body_plan.is_definitely_empty() {
        return Err(
            crate::proxy::forward_error::CredentialRequestRejected::body_not_allowed().into(),
        );
    }
    let port = request
        .port
        .unwrap_or_else(|| request.scheme.default_port());
    let addresses = crate::proxy::upstream::resolve_or_use_binding(
        &request.host,
        port,
        connect_binding,
        app.upstream_resolver(),
        app.settings.dns_resolve_timeout(),
    )
    .await?;

    let buffered_body = match body_plan {
        BodyPlan::Empty | BodyPlan::Fixed(0) => None,
        BodyPlan::Fixed(length) => {
            let authorization = app
                .authorization
                .as_ref()
                .expect("credential decision requires authorization services");
            let body_limit = authorization.buffered_body_limit(app.settings.max_request_body_size);
            if length > body_limit {
                return Err(BodyTooLarge { bytes_read: 0 }.into());
            }
            let permit = authorization.reserve_buffered_body(length).await?;
            let (bytes, wire_bytes) = buffer_fixed_body(
                client_reader,
                length,
                timeouts.request_io,
                request_deadline.instant(),
            )
            .await?;
            Some(BufferedBody::new(bytes, wire_bytes, permit))
        }
        BodyPlan::Chunked => {
            let authorization = app
                .authorization
                .as_ref()
                .expect("credential decision requires authorization services");
            let reservation = authorization.buffered_body_limit(app.settings.max_request_body_size);
            let permit = authorization.reserve_buffered_body(reservation).await?;
            let (bytes, wire_bytes) = buffer_chunked_body(
                client_reader,
                timeouts.request_io,
                request_deadline.instant(),
                peer,
                reservation,
                app.settings.max_request_header_size,
            )
            .await?;
            Some(BufferedBody::new(bytes, wire_bytes, permit))
        }
    };
    let declared_content_length = match body_plan {
        BodyPlan::Fixed(length) => Some(length),
        BodyPlan::Empty | BodyPlan::Chunked => None,
    };
    let client_body_bytes = buffered_body.as_ref().map_or(0, BufferedBody::wire_bytes);
    log_tracker.record_client_body_bytes(client_body_bytes);
    let mut finalized = FinalizedRequestV1::new(
        request,
        headers
            .forward_headers()
            .map(|header| (header.header_name().clone(), header.header_value().clone())),
        declared_content_length,
        buffered_body,
        credential.protected_headers.clone(),
        FinalizedProtocol::Http1,
        app.settings.max_request_header_size,
    )
    .map_err(crate::proxy::forward_error::credential_finalization_failed)?;
    app.authorization
        .as_ref()
        .expect("credential decision requires authorization services")
        .prepare_headers(
            credential,
            &mut finalized,
            peer,
            app.settings.max_request_header_size,
        )
        .await
        .map_err(crate::proxy::forward_error::credential_preparation_failed)?;

    crate::metrics::record_pool_miss();
    crate::metrics::record_pool_reuse(false);
    let mut connection =
        UpstreamConnection::connect_resolved(request, app, timeouts.connect, &addresses).await?;
    let outcome = connection::forward_with_connection(
        client_reader,
        &mut connection,
        request,
        headers,
        body_plan,
        timeouts,
        request_deadline,
        response_progress,
        false,
        peer,
        app.settings.max_request_body_size,
        headers.wants_connection_close(),
        app.settings.max_response_header_size,
        decision,
        app,
        Some(finalized),
    )
    .await
    .map(|(stats, _reuse_upstream, client_close)| (stats, false, client_close));
    let key = UpstreamKey::from_request(request, Some(credential.token.hash()));
    finalize_forward_attempt(pool, key, connection, outcome, timeouts.response_io, false).await
}

async fn finalize_forward_attempt(
    pool: &mut UpstreamPool,
    key: UpstreamKey,
    mut connection: UpstreamConnection,
    outcome: Result<(ForwardStats, bool, bool)>,
    shutdown_timeout: Duration,
    reused_existing: bool,
) -> Result<ForwardResult> {
    let upstream_addr = connection.peer;

    match outcome {
        Ok((stats, reuse_upstream, client_close)) => {
            if reuse_upstream {
                pool.put(key, connection, shutdown_timeout);
            } else if let Err(err) = connection.shutdown(shutdown_timeout).await {
                debug!(
                    host = %connection.host,
                    port = connection.port,
                    scheme = ?connection.scheme,
                    error = %err,
                    "failed to shutdown upstream connection after response"
                );
            }
            Ok(ForwardResult {
                stats,
                client_close,
                upstream_addr,
                reused_existing,
            })
        }
        Err(err) => {
            if let Err(shutdown_err) = connection.shutdown(shutdown_timeout).await {
                debug!(
                    host = %connection.host,
                    port = connection.port,
                    scheme = ?connection.scheme,
                    error = %shutdown_err,
                    "failed to shutdown upstream connection after error"
                );
            }
            Err(err)
        }
    }
}

fn should_retry_reused_connection(
    reused_existing: bool,
    method: &Method,
    body_plan: BodyPlan,
    response_progress: &ResponseProgress,
    err: &anyhow::Error,
) -> bool {
    if !reused_existing
        || !is_standard_idempotent_method(method)
        || !matches!(body_plan, BodyPlan::Empty)
        || response_progress.has_started()
        || err.downcast_ref::<InformationalResponseStarted>().is_some()
    {
        return false;
    }

    err.chain().any(|cause| {
        cause.downcast_ref::<UpstreamClosed>().is_some()
            || cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io_err| {
                    matches!(
                        io_err.kind(),
                        ErrorKind::BrokenPipe
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::ConnectionReset
                            | ErrorKind::NotConnected
                            | ErrorKind::UnexpectedEof
                    )
                })
    })
}

fn is_standard_idempotent_method(method: &Method) -> bool {
    method == Method::GET
        || method == Method::HEAD
        || method == Method::OPTIONS
        || method == Method::TRACE
        || method == Method::PUT
        || method == Method::DELETE
}

#[cfg(test)]
mod tests {
    use super::{BodyPlan, should_retry_reused_connection};
    use crate::proxy::forward_error::{ResponseAlreadyStarted, UpstreamClosed};
    use crate::proxy::forward_limits::ResponseProgress;
    use http::Method;

    #[test]
    fn retry_standard_idempotent_methods_on_reused_empty_stale_connections() {
        let stale = anyhow::Error::new(UpstreamClosed);

        for method in [
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::TRACE,
            Method::PUT,
            Method::DELETE,
        ] {
            assert!(
                should_retry_reused_connection(
                    true,
                    &method,
                    BodyPlan::Empty,
                    &ResponseProgress::default(),
                    &stale
                ),
                "expected {method} to be retryable"
            );
        }
    }

    #[test]
    fn do_not_retry_non_idempotent_or_extension_methods() {
        let stale = anyhow::Error::new(UpstreamClosed);

        for method in [
            Method::POST,
            Method::PATCH,
            Method::CONNECT,
            Method::from_bytes(b"CUSTOM").unwrap(),
        ] {
            assert!(
                !should_retry_reused_connection(
                    true,
                    &method,
                    BodyPlan::Empty,
                    &ResponseProgress::default(),
                    &stale
                ),
                "expected {method} not to be retryable"
            );
        }
    }

    #[test]
    fn retry_requires_reuse_empty_body_and_stale_connection_error() {
        let stale = anyhow::Error::new(UpstreamClosed);
        assert!(!should_retry_reused_connection(
            false,
            &Method::GET,
            BodyPlan::Empty,
            &ResponseProgress::default(),
            &stale
        ));
        assert!(!should_retry_reused_connection(
            true,
            &Method::GET,
            BodyPlan::Fixed(1),
            &ResponseProgress::default(),
            &stale,
        ));

        let unrelated = anyhow::anyhow!("some other upstream failure");
        assert!(!should_retry_reused_connection(
            true,
            &Method::GET,
            BodyPlan::Empty,
            &ResponseProgress::default(),
            &unrelated,
        ));
    }

    #[test]
    fn do_not_retry_after_final_response_starts() {
        let reset = || {
            anyhow::Error::from(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "connection reset",
            ))
        };

        // Head writes can fail before an error wrapper is constructed. Body
        // failures carry the same I/O cause inside ResponseAlreadyStarted.
        for error in [
            reset(),
            ResponseAlreadyStarted::new(http::StatusCode::OK, 128, reset()).into(),
        ] {
            let progress = ResponseProgress::default();
            progress.mark_started(http::StatusCode::OK, 128);
            assert!(!should_retry_reused_connection(
                true,
                &Method::GET,
                BodyPlan::Empty,
                &progress,
                &error,
            ));
            progress.mark_complete();
            assert!(!should_retry_reused_connection(
                true,
                &Method::GET,
                BodyPlan::Empty,
                &progress,
                &error,
            ));
        }
    }
}
