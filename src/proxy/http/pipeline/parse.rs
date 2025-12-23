use anyhow::Result;
use http::StatusCode;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tracing::warn;

use crate::logging::AccessLogBuilder;
use crate::proxy::{
    AppContext,
    connect::ResolvedTarget,
    forward_limits::AllowLogTracker,
    policy_eval::PolicyLogConfig,
    request::{parse_http1_request, scheme_name},
    request_pipeline,
};

use super::handler::Http1RequestHandler;
use super::respond::respond_with_access_log;
use super::{ClientDisposition, RequestContext};

use super::super::body::BodyPlan;
use super::super::upstream::UpstreamPool;

pub async fn handle_non_connect<S>(
    reader: &mut BufReader<S>,
    peer: SocketAddr,
    app: &AppContext,
    upstream_pool: &mut UpstreamPool,
    ctx: RequestContext,
    connect_binding: Option<&ResolvedTarget>,
) -> Result<ClientDisposition>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let total_request_bytes = ctx.total_request_bytes();
    let RequestContext {
        method,
        target,
        headers,
        request_line_bytes: _,
        header_bytes: _,
        start,
        fallback_scheme,
    } = ctx;
    let request_body_timeout = app.settings.request_body_idle_timeout();
    let response_header_timeout = app.settings.response_header_timeout();
    let response_body_timeout = app.settings.response_body_idle_timeout();
    let request_total_timeout = app.settings.request_total_timeout();
    let content_length = match headers.content_length() {
        Ok(value) => value,
        Err(err) => {
            warn!(peer = %peer, error = %err, "invalid content-length header");
            let stream = reader.get_mut();
            respond_with_access_log(
                stream,
                StatusCode::BAD_REQUEST,
                None,
                b"invalid Content-Length header\r\n",
                response_body_timeout,
                total_request_bytes,
                start.elapsed(),
                AccessLogBuilder::new(peer)
                    .method(method.as_str())
                    .scheme(scheme_name(fallback_scheme))
                    .host(headers.host().unwrap_or(""))
                    .path(target.clone())
                    .decision("ERROR"),
            )
            .await?;
            return Ok(ClientDisposition::Close);
        }
    };

    let expect_continue = match headers.expect_continue() {
        Ok(value) => value,
        Err(err) => {
            warn!(peer = %peer, error = %err, "unsupported Expect header");
            respond_with_access_log(
                reader.get_mut(),
                StatusCode::EXPECTATION_FAILED,
                None,
                b"expectation failed\r\n",
                response_body_timeout,
                total_request_bytes,
                start.elapsed(),
                AccessLogBuilder::new(peer)
                    .method(method.as_str())
                    .scheme(scheme_name(fallback_scheme))
                    .host(headers.host().unwrap_or(""))
                    .path(target.clone())
                    .decision("ERROR"),
            )
            .await?;
            return Ok(ClientDisposition::Close);
        }
    };

    if !headers.is_chunked()
        && let Some(length) = content_length
        && length > app.settings.max_request_body_size
    {
        warn!(
            peer = %peer,
            length,
            max = app.settings.max_request_body_size,
            "request body exceeds limit"
        );
        respond_with_access_log(
            reader.get_mut(),
            StatusCode::PAYLOAD_TOO_LARGE,
            None,
            b"request body exceeds configured limit\r\n",
            response_body_timeout,
            total_request_bytes,
            start.elapsed(),
            AccessLogBuilder::new(peer)
                .method(method.as_str())
                .scheme(scheme_name(fallback_scheme))
                .host(headers.host().unwrap_or(""))
                .path(target.clone())
                .decision("DENY"),
        )
        .await?;
        return Ok(ClientDisposition::Close);
    }

    let body_plan = if headers.is_chunked() {
        BodyPlan::Chunked
    } else {
        match content_length {
            Some(length) if length > 0 => BodyPlan::Fixed(length),
            _ => BodyPlan::Empty,
        }
    };
    let parsed = match parse_http1_request(method.clone(), &target, headers.host(), fallback_scheme)
    {
        Ok(parsed) => parsed,
        Err(err) => {
            warn!(peer = %peer, error = ?err, "failed to parse HTTP request target");
            respond_with_access_log(
                reader.get_mut(),
                StatusCode::BAD_REQUEST,
                None,
                b"invalid request target\r\n",
                response_body_timeout,
                total_request_bytes,
                start.elapsed(),
                AccessLogBuilder::new(peer)
                    .method(method.as_str())
                    .scheme(scheme_name(fallback_scheme))
                    .host(headers.host().unwrap_or(""))
                    .path(target)
                    .decision("ERROR"),
            )
            .await?;
            return Ok(ClientDisposition::Close);
        }
    };
    let snapshot = app.policies.snapshot();
    let log_tracker = AllowLogTracker::new(total_request_bytes, start);
    let mut handler = Http1RequestHandler {
        reader,
        upstream_pool,
        app,
        connect_binding,
        headers,
        body_plan,
        log_tracker,
        peer,
        request_body_timeout,
        response_header_timeout,
        response_body_timeout,
        request_start: start,
        request_total_timeout,
        parsed: &parsed,
        expect_continue,
    };
    request_pipeline::process_request(
        peer,
        &parsed,
        &snapshot,
        app.settings.log_queries,
        PolicyLogConfig::http1(),
        &mut handler,
    )
    .await
}
