mod cache;
mod connection;
mod request;
mod response;

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tracing::debug;

use crate::proxy::AppContext;
use crate::proxy::connect::ResolvedTarget;
use crate::proxy::forward_error::UpstreamClosed;
use crate::proxy::policy_eval::AllowDecision;
use crate::proxy::request::ParsedRequest;

use super::body::BodyPlan;
use super::codec::Http1HeaderAccumulator;
use super::upstream::{UpstreamConnection, UpstreamKey, UpstreamPool};

pub(crate) use connection::UpstreamIo;
#[cfg(test)]
pub(crate) use request::build_upstream_request;
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
    request_start: Instant,
    request_total_timeout: Option<Duration>,
    expect_continue: bool,
    decision: &AllowDecision,
    peer: SocketAddr,
    max_request_body_size: usize,
    app: &AppContext,
) -> Result<ForwardResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = UpstreamKey::from_request(request);
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
        request_start,
        request_total_timeout,
        expect_continue,
        peer,
        max_request_body_size,
        request_close,
        app.settings.max_response_header_size,
        decision,
        app,
    )
    .await;

    match outcome {
        Err(err) if should_retry_reused_connection(reused_existing, body_plan, &err) => {
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
                request_start,
                request_total_timeout,
                expect_continue,
                peer,
                max_request_body_size,
                request_close,
                app.settings.max_response_header_size,
                decision,
                app,
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
    body_plan: BodyPlan,
    err: &anyhow::Error,
) -> bool {
    if !reused_existing || !matches!(body_plan, BodyPlan::Empty) {
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

#[cfg(test)]
mod tests {
    use super::{BodyPlan, should_retry_reused_connection};
    use crate::proxy::forward_error::UpstreamClosed;

    #[test]
    fn retry_only_on_reused_empty_body_stale_connection_errors() {
        let stale = anyhow::Error::new(UpstreamClosed);
        assert!(should_retry_reused_connection(
            true,
            BodyPlan::Empty,
            &stale
        ));
        assert!(!should_retry_reused_connection(
            false,
            BodyPlan::Empty,
            &stale
        ));
        assert!(!should_retry_reused_connection(
            true,
            BodyPlan::Fixed(1),
            &stale,
        ));

        let unrelated = anyhow::anyhow!("some other upstream failure");
        assert!(!should_retry_reused_connection(
            true,
            BodyPlan::Empty,
            &unrelated,
        ));
    }
}
