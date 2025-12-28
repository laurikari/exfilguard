use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::proxy::{
    allow_log::AllowLogStats,
    policy_eval::{AllowDecision, RequestLogContext},
    policy_response::{self, ForwardErrorSpec},
};

use super::ClientDisposition;
use super::handler::Http1RequestHandler;
use super::respond::{respond_with_access_log, shutdown_stream};

use super::super::forward::{ForwardResult, ForwardTimeouts, forward_to_upstream};

pub(super) async fn forward_request<S>(
    handler: &mut Http1RequestHandler<'_, S>,
    decision: &AllowDecision,
) -> Result<ForwardResult>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    forward_to_upstream(
        handler.reader,
        handler.upstream_pool,
        handler.parsed,
        &handler.headers,
        handler.body_plan,
        handler.connect_binding,
        &ForwardTimeouts {
            connect: handler.app.settings.upstream_connect_timeout(),
            request_io: handler.request_body_timeout,
            response_header: handler.response_header_timeout,
            response_io: handler.response_body_timeout,
        },
        handler.request_start,
        handler.request_total_timeout,
        handler.expect_continue,
        decision,
        handler.peer,
        handler.app.settings.max_request_body_size,
        handler.app,
    )
    .await
}

pub(super) fn build_allow_log_stats<S>(
    handler: &mut Http1RequestHandler<'_, S>,
    success: &ForwardResult,
) -> AllowLogStats
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    handler
        .log_tracker
        .add_client_bytes(success.stats.client_body_bytes);
    handler.log_tracker.build_allow_log_stats(
        success.stats.status,
        success.stats.bytes_to_client,
        success.upstream_addr,
        success.reused_existing,
    )
}

pub(super) async fn handle_forward_success<S>(
    handler: &mut Http1RequestHandler<'_, S>,
    success: ForwardResult,
) -> Result<ClientDisposition>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    if success.client_close {
        shutdown_stream(handler.reader.get_mut(), handler.response_body_timeout).await?;
        Ok(ClientDisposition::Close)
    } else {
        Ok(ClientDisposition::Continue)
    }
}

pub(super) async fn respond_forward_error<S>(
    handler: &mut Http1RequestHandler<'_, S>,
    spec: ForwardErrorSpec,
    log: RequestLogContext<'_>,
    decision: AllowDecision,
    error_detail: &str,
) -> Result<ClientDisposition>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    if spec.extra_client_bytes > 0 {
        handler
            .log_tracker
            .add_client_bytes(spec.extra_client_bytes);
    }
    respond_with_access_log(
        handler.reader.get_mut(),
        spec.status,
        None,
        spec.body_http1,
        handler.response_body_timeout,
        handler.log_tracker.current_bytes(),
        handler.log_tracker.elapsed(),
        policy_response::forward_error_log_builder(
            log.access_log_builder(),
            &decision,
            &spec,
            error_detail,
        ),
    )
    .await?;
    Ok(ClientDisposition::Close)
}
