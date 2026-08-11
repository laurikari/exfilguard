use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::{Instant, SystemTime};

use anyhow::Result;
use http::{Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use crate::authorization::FinalizedRequestV1;
use crate::io_util::{CountingWriter, write_all_with_timeout};
use crate::proxy::AppContext;
use crate::proxy::forward_error::{RequestTimeout, ResponseAlreadyStarted};
use crate::proxy::forward_limits::{RequestDeadline, ResponseProgress};
use crate::proxy::policy_eval::AllowDecision;
use crate::proxy::request::ParsedRequest;
use crate::util::timeout_with_context;

use super::cache::{CacheResponse, prepare_cache_write};
use super::request::{build_upstream_request, send_continue_if_needed};
use super::response::{ResponseBodyPlan, determine_response_body_plan, read_final_response_head};
use super::{ForwardStats, ForwardTimeouts};
use crate::proxy::http::body::{BodyPlan, stream_chunked_body, stream_fixed_body};
use crate::proxy::http::codec::{ConnectionOverride, Http1HeaderAccumulator};
use crate::proxy::http::upstream::UpstreamConnection;

pub(crate) enum UpstreamIo {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Unpin for UpstreamIo {}

impl AsyncRead for UpstreamIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamIo::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            UpstreamIo::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            UpstreamIo::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            UpstreamIo::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamIo::Plain(stream) => Pin::new(stream).poll_flush(cx),
            UpstreamIo::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamIo::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            UpstreamIo::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn forward_with_connection<S>(
    client_reader: &mut BufReader<S>,
    connection: &mut UpstreamConnection,
    request: &ParsedRequest,
    headers: &Http1HeaderAccumulator,
    body_plan: BodyPlan,
    timeouts: &ForwardTimeouts,
    request_deadline: RequestDeadline,
    response_progress: &ResponseProgress,
    expect_continue: bool,
    peer: SocketAddr,
    max_request_body_size: usize,
    request_close: bool,
    max_response_header_bytes: usize,
    decision: &AllowDecision,
    app: &AppContext,
    finalized: Option<FinalizedRequestV1>,
) -> Result<(ForwardStats, bool, bool)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request_deadline = request_deadline.instant();
    let request_bytes = Zeroizing::new(match finalized.as_ref() {
        Some(finalized) => finalized.encode_http1_head(),
        None => {
            build_upstream_request(request, headers, request_close, &body_plan, expect_continue)
        }
    });
    let upstream_request_instant = Instant::now();
    write_all_with_timeout(
        &mut connection.stream,
        &request_bytes,
        timeouts.request_io,
        "sending request headers to upstream",
    )
    .await?;
    drop(request_bytes);

    let client_body_bytes = if let Some(finalized) = finalized.as_ref() {
        if let Some(body) = finalized.body() {
            write_all_with_timeout(
                &mut connection.stream,
                body,
                timeouts.request_io,
                "sending finalized request body to upstream",
            )
            .await?;
        }
        finalized.client_body_wire_bytes()
    } else {
        send_continue_if_needed(
            client_reader.get_mut(),
            expect_continue,
            body_plan,
            timeouts.request_io,
        )
        .await?;

        match body_plan {
            BodyPlan::Empty => 0,
            BodyPlan::Fixed(length) => {
                stream_fixed_body(
                    client_reader,
                    &mut connection.stream,
                    length,
                    timeouts.request_io,
                    timeouts.request_io,
                    request_deadline,
                )
                .await?
            }
            BodyPlan::Chunked => {
                stream_chunked_body(
                    client_reader,
                    &mut connection.stream,
                    timeouts.request_io,
                    timeouts.request_io,
                    request_deadline,
                    peer,
                    max_request_body_size,
                    app.settings.max_request_header_size,
                )
                .await?
            }
        }
    };

    drop(finalized);
    timeout_with_context(
        timeouts.request_io,
        connection.stream.flush(),
        "flushing upstream stream",
    )
    .await?;

    let mut upstream_reader = BufReader::new(&mut connection.stream);
    let head_fut = read_final_response_head(
        &mut upstream_reader,
        client_reader.get_mut(),
        timeouts,
        connection.peer,
        max_response_header_bytes,
    );
    let (mut head, informational_bytes) = if let Some(deadline) = request_deadline {
        let now = Instant::now();
        if now >= deadline {
            return Err(RequestTimeout.into());
        }
        let remaining = deadline - now;
        match timeout(remaining, head_fut).await {
            Ok(result) => result?,
            Err(_) => return Err(RequestTimeout.into()),
        }
    } else {
        head_fut.await?
    };
    let response_instant = Instant::now();
    let response_time = SystemTime::now();
    head.normalize_date(response_time);
    let response_delay = response_instant.saturating_duration_since(upstream_request_instant);
    let response_body_plan = determine_response_body_plan(&request.method, head.status, &head);

    let mut client_close = request_close || head.connection_close;
    if matches!(response_body_plan, ResponseBodyPlan::UntilClose)
        || (head.status == StatusCode::RESET_CONTENT && head.content_length.is_none())
    {
        client_close = true;
    }

    let cache_state = prepare_cache_write(
        decision,
        app,
        request,
        headers,
        body_plan,
        CacheResponse {
            head: &head,
            timing: crate::proxy::cache::CacheResponseTiming {
                response_time,
                response_delay,
            },
        },
        peer,
    )
    .await;

    let override_connection = if client_close {
        Some(ConnectionOverride::Close)
    } else {
        None
    };

    let encoded_head = head.encode(response_body_plan, override_connection);
    response_progress.mark_started(
        head.status,
        informational_bytes.saturating_add(encoded_head.len() as u64),
    );
    {
        let client_stream = client_reader.get_mut();
        write_all_with_timeout(
            client_stream,
            &encoded_head,
            timeouts.response_io,
            "writing response head to client",
        )
        .await?;
    }
    let mut bytes_to_client = informational_bytes.saturating_add(encoded_head.len() as u64);

    let (relay_result, relayed_bytes) = {
        let mut response_body_writer = CountingWriter::new(client_reader.get_mut());
        let result = cache_state
            .relay_body(
                &mut upstream_reader,
                &mut response_body_writer,
                response_body_plan,
                timeouts,
                connection.peer,
                request_deadline,
                max_response_header_bytes,
                peer,
                request,
            )
            .await;
        (result, response_body_writer.bytes_written())
    };
    let (body_bytes, cache_store) = match relay_result {
        Ok(result) => result,
        Err(source) => {
            return Err(ResponseAlreadyStarted::new(
                head.status,
                bytes_to_client.saturating_add(relayed_bytes),
                source,
            )
            .into());
        }
    };
    bytes_to_client = bytes_to_client.saturating_add(body_bytes);
    response_progress.add_bytes(body_bytes);

    if let Err(source) = timeout_with_context(
        timeouts.response_io,
        client_reader.get_mut().flush(),
        "flushing client stream",
    )
    .await
    {
        return Err(ResponseAlreadyStarted::new(head.status, bytes_to_client, source).into());
    }

    response_progress.mark_complete();

    drop(upstream_reader);

    // Avoid reusing upstream after HEAD: some servers incorrectly send a body,
    // which would desync the next response on a keep-alive connection.
    let reuse_upstream = request.method != Method::HEAD
        && !client_close
        && !matches!(response_body_plan, ResponseBodyPlan::UntilClose);

    Ok((
        ForwardStats {
            bytes_to_client,
            status: head.status,
            client_body_bytes,
            cache_store,
        },
        reuse_upstream,
        client_close,
    ))
}
