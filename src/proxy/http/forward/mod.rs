mod cache;
mod connection;
mod request;
mod response;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tracing::debug;

use crate::proxy::AppContext;
use crate::proxy::connect::ResolvedTarget;
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
    let key = UpstreamKey::from_request(request, decision.allow_private_upstream);
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
            let conn = UpstreamConnection::connect(
                request,
                app,
                timeouts.connect,
                connect_binding,
                decision.allow_private_upstream,
            )
            .await?;
            crate::metrics::record_pool_reuse(false);
            (conn, false)
        }
    };
    let upstream_addr = connection.peer;

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
        Ok((stats, reuse_upstream, client_close)) => {
            if reuse_upstream {
                pool.put(key, connection, timeouts.response_io);
            } else if let Err(err) = connection.shutdown(timeouts.response_io).await {
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
            if let Err(shutdown_err) = connection.shutdown(timeouts.response_io).await {
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
