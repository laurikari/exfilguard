use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::Result;
use http::{Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tracing::{debug, warn};

use crate::io_util::{BestEffortWriter, TeeWriter, write_all_with_timeout};
use crate::proxy::AppContext;
use crate::proxy::cache::{CacheSkipReason, CacheStorePlan, CacheWritePlan, plan_cache_write};
use crate::proxy::connect::ResolvedTarget;
use crate::proxy::forward_error::RequestTimeout;
use crate::proxy::policy_eval::AllowDecision;
use crate::proxy::request::ParsedRequest;
use crate::util::timeout_with_context;
use tokio::net::TcpStream;

use super::body::{
    BodyPlan, relay_chunked_body, relay_fixed_body, relay_until_close, stream_chunked_body,
    stream_fixed_body,
};
use super::codec::{ConnectionDirective, HeaderAccumulator, ResponseHead, read_response_head};
use super::upstream::{UpstreamConnection, UpstreamKey, UpstreamPool};
use crate::proxy::cache::{build_cache_request_context, header_lines_to_map};

pub struct ForwardTimeouts {
    pub connect: Duration,
    pub request_io: Duration,
    pub response_header: Duration,
    pub response_io: Duration,
}

#[derive(Clone, Copy)]
pub enum ResponseBodyPlan {
    Empty,
    Fixed(u64),
    Chunked,
    UntilClose,
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
    pub status: StatusCode,
    pub client_body_bytes: u64,
    pub cache_store: CacheStoreResult,
}

pub struct ForwardResult {
    pub stats: ForwardStats,
    pub client_close: bool,
    pub upstream_addr: SocketAddr,
    pub reused_existing: bool,
}

pub enum UpstreamIo {
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
pub async fn forward_to_upstream<S>(
    client_reader: &mut BufReader<S>,
    pool: &mut UpstreamPool,
    request: &ParsedRequest,
    headers: &HeaderAccumulator,
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

    let outcome = forward_with_connection(
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

#[allow(clippy::too_many_arguments)]
pub async fn forward_with_connection<S>(
    client_reader: &mut BufReader<S>,
    connection: &mut UpstreamConnection,
    request: &ParsedRequest,
    headers: &HeaderAccumulator,
    body_plan: BodyPlan,
    timeouts: &ForwardTimeouts,
    request_start: Instant,
    request_total_timeout: Option<Duration>,
    expect_continue: bool,
    peer: SocketAddr,
    max_request_body_size: usize,
    request_close: bool,
    max_response_header_bytes: usize,
    decision: &AllowDecision,
    app: &AppContext,
) -> Result<(ForwardStats, bool, bool)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request_deadline = request_total_timeout.map(|timeout| request_start + timeout);
    let request_bytes =
        build_upstream_request(request, headers, request_close, &body_plan, expect_continue);
    write_all_with_timeout(
        &mut connection.stream,
        &request_bytes,
        timeouts.request_io,
        "sending request headers to upstream",
    )
    .await?;

    send_continue_if_needed(
        client_reader.get_mut(),
        expect_continue,
        body_plan,
        timeouts.request_io,
    )
    .await?;

    let mut client_body_bytes = 0u64;
    match body_plan {
        BodyPlan::Empty => {}
        BodyPlan::Fixed(length) => {
            client_body_bytes = stream_fixed_body(
                client_reader,
                &mut connection.stream,
                length,
                timeouts.request_io,
                timeouts.request_io,
                request_deadline,
            )
            .await?;
        }
        BodyPlan::Chunked => {
            client_body_bytes = stream_chunked_body(
                client_reader,
                &mut connection.stream,
                timeouts.request_io,
                timeouts.request_io,
                request_deadline,
                peer,
                max_request_body_size,
            )
            .await?;
        }
    }

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
    let (head, informational_bytes) = if let Some(deadline) = request_deadline {
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
    let response_body_plan = determine_response_body_plan(&request.method, head.status, &head);

    let mut client_close = request_close || head.connection_close;
    if matches!(response_body_plan, ResponseBodyPlan::UntilClose) {
        client_close = true;
    }

    // Check caching
    let mut cache_store = CacheStoreResult::Bypassed;
    let mut cache_stream = None;
    if let (Some(cache_config), Some(cache)) = (&decision.cache, &app.cache) {
        cache_store = CacheStoreResult::Skipped;

        let method_obj = &request.method;
        let has_sensitive_headers = headers.has_sensitive_cache_headers();
        let cache_request = if has_sensitive_headers {
            None
        } else {
            match build_cache_request_context(request, headers) {
                Ok(context) => Some(context),
                Err(err) => {
                    debug!(peer = %peer, error = %err, host = %request.host, "skipping cache due to URI build failure");
                    None
                }
            }
        };

        let resp_headers_map = header_lines_to_map(head.headers.iter());
        let plan = plan_cache_write(
            method_obj,
            cache_request,
            head.status,
            resp_headers_map,
            cache_config.force_cache_duration,
            has_sensitive_headers,
        );

        match plan {
            CacheWritePlan::Bypass => {
                cache_store = CacheStoreResult::Bypassed;
            }
            CacheWritePlan::Skip(reason) => {
                if reason == CacheSkipReason::ResponseSetCookie {
                    debug!(
                        peer = %peer,
                        host = %request.host,
                        status = head.status.as_u16(),
                        "skipping cache write due to Set-Cookie response header"
                    );
                }
            }
            CacheWritePlan::Store(plan) => {
                let CacheStorePlan {
                    request,
                    response_headers,
                    ttl,
                } = *plan;
                match cache
                    .open_stream(
                        method_obj,
                        &request.uri,
                        &request.headers,
                        &response_headers,
                    )
                    .await
                {
                    Ok(Some(stream)) => {
                        cache_stream = Some((stream, ttl, response_headers));
                    }
                    Ok(None) => {
                        tracing::debug!("skipping cache write due to Vary limits");
                    }
                    Err(e) => {
                        tracing::debug!("failed to open cache stream: {}", e);
                    }
                }
            }
        }
    }

    let override_connection = if client_close {
        Some(ConnectionDirective::Close)
    } else {
        None
    };

    let encoded_head = head.encode(response_body_plan, override_connection);
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

    {
        let client_stream = client_reader.get_mut();

        let body_bytes = if let Some((mut stream, ttl, resp_headers)) = cache_stream {
            let (res, cache_error) = {
                let mut cache_writer = BestEffortWriter::new(&mut stream);
                let res = {
                    let mut tee = TeeWriter::new(client_stream, &mut cache_writer);
                    relay_body_generic(
                        &mut upstream_reader,
                        &mut tee,
                        response_body_plan,
                        timeouts.response_io,
                        timeouts.response_io,
                        connection.peer,
                    )
                    .await
                };
                (res, cache_writer.take_error())
            };

            let mut cache_failed = false;
            if let Some(err) = cache_error.as_ref() {
                cache_failed = true;
                warn!(
                    peer = %peer,
                    host = %request.host,
                    error = %err,
                    "cache write failed; continuing without cache"
                );
                crate::metrics::record_cache_store_error();
                stream.discard();
            }

            match res {
                Ok(bytes) => {
                    if let Err(err) = stream.finish(head.status, resp_headers, ttl).await {
                        if !cache_failed {
                            warn!(
                                peer = %peer,
                                host = %request.host,
                                error = %err,
                                "failed to commit cache entry"
                            );
                            crate::metrics::record_cache_store_error();
                        }
                        cache_store = CacheStoreResult::Skipped;
                    } else if cache_failed {
                        cache_store = CacheStoreResult::Skipped;
                    } else {
                        cache_store = CacheStoreResult::Stored;
                    }
                    Ok(bytes)
                }
                Err(e) => {
                    cache_store = CacheStoreResult::Skipped;
                    Err(e)
                }
            }?
        } else {
            relay_body_generic(
                &mut upstream_reader,
                client_stream,
                response_body_plan,
                timeouts.response_io,
                timeouts.response_io,
                connection.peer,
            )
            .await?
        };

        bytes_to_client = bytes_to_client.saturating_add(body_bytes);
    }
    // Access client_stream again to flush
    timeout_with_context(
        timeouts.response_io,
        client_reader.get_mut().flush(),
        "flushing client stream",
    )
    .await?;

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

// Helper to consolidate body relay logic
async fn relay_body_generic<S, C>(
    upstream: &mut BufReader<S>,
    client: &mut C,
    plan: ResponseBodyPlan,
    upstream_io_timeout: Duration,
    client_io_timeout: Duration,
    peer: SocketAddr,
) -> Result<u64>
where
    S: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    match plan {
        ResponseBodyPlan::Empty => Ok(0),
        ResponseBodyPlan::Fixed(length) => {
            relay_fixed_body(
                upstream,
                client,
                length,
                upstream_io_timeout,
                client_io_timeout,
                peer,
            )
            .await
        }
        ResponseBodyPlan::Chunked => {
            relay_chunked_body(
                upstream,
                client,
                upstream_io_timeout,
                client_io_timeout,
                peer,
            )
            .await
        }
        ResponseBodyPlan::UntilClose => {
            relay_until_close(
                upstream,
                client,
                upstream_io_timeout,
                client_io_timeout,
                peer,
            )
            .await
        }
    }
}

async fn read_final_response_head<S, C>(
    upstream: &mut BufReader<S>,
    client: &mut C,
    timeouts: &ForwardTimeouts,
    peer: SocketAddr,
    max_response_header_bytes: usize,
) -> Result<(ResponseHead, u64)>
where
    S: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut bytes_to_client = 0u64;
    loop {
        let mut head = read_response_head(
            upstream,
            timeouts.response_header,
            peer,
            max_response_header_bytes,
        )
        .await?;
        if head.status == StatusCode::SWITCHING_PROTOCOLS {
            anyhow::bail!("upstream attempted protocol upgrade (101 Switching Protocols)");
        }
        if head.status.is_informational() {
            if head.transfer_encoding_present {
                anyhow::bail!("informational response must not include a body");
            }
            if let Some(length) = head.content_length
                && length > 0
            {
                anyhow::bail!("informational response must not include a body");
            }
            head.content_length = None;
            let encoded = head.encode(ResponseBodyPlan::Empty, None);
            write_all_with_timeout(
                client,
                &encoded,
                timeouts.response_io,
                "writing informational response to client",
            )
            .await?;
            timeout_with_context(
                timeouts.response_io,
                client.flush(),
                "flushing informational response to client",
            )
            .await?;
            bytes_to_client = bytes_to_client.saturating_add(encoded.len() as u64);
            continue;
        }
        return Ok((head, bytes_to_client));
    }
}

async fn send_continue_if_needed<S>(
    client: &mut S,
    expect_continue: bool,
    body_plan: BodyPlan,
    timeout: Duration,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    if !expect_continue || matches!(body_plan, BodyPlan::Empty) {
        return Ok(());
    }

    let response = b"HTTP/1.1 100 Continue\r\n\r\n";
    write_all_with_timeout(
        client,
        response,
        timeout,
        "writing 100-continue response to client",
    )
    .await?;
    timeout_with_context(timeout, client.flush(), "flushing 100-continue response").await?;
    Ok(())
}

pub fn determine_response_body_plan(
    method: &Method,
    status: StatusCode,
    head: &ResponseHead,
) -> ResponseBodyPlan {
    if method == Method::HEAD {
        return ResponseBodyPlan::Empty;
    }
    if status.is_informational() {
        return ResponseBodyPlan::Empty;
    }
    if status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED {
        return ResponseBodyPlan::Empty;
    }
    if head.chunked {
        return ResponseBodyPlan::Chunked;
    }
    if head.transfer_encoding_present {
        return ResponseBodyPlan::UntilClose;
    }
    if let Some(length) = head.content_length {
        if length == 0 {
            return ResponseBodyPlan::Empty;
        }
        return ResponseBodyPlan::Fixed(length);
    }
    ResponseBodyPlan::UntilClose
}

pub fn build_upstream_request(
    request: &ParsedRequest,
    headers: &HeaderAccumulator,
    close: bool,
    body_plan: &BodyPlan,
    expect_continue: bool,
) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(512);
    buffer
        .extend_from_slice(format!("{} {} HTTP/1.1\r\n", request.method, request.path).as_bytes());

    for header in headers.forward_headers() {
        if expect_continue && header.lower_name() == "expect" {
            continue;
        }
        buffer.extend_from_slice(header.name.as_bytes());
        buffer.extend_from_slice(b": ");
        buffer.extend_from_slice(header.value.as_bytes());
        buffer.extend_from_slice(b"\r\n");
    }

    let authority = request.authority_host();
    buffer.extend_from_slice(b"Host: ");
    buffer.extend_from_slice(authority.as_bytes());
    buffer.extend_from_slice(b"\r\n");

    match body_plan {
        BodyPlan::Fixed(length) => {
            buffer.extend_from_slice(b"Content-Length: ");
            buffer.extend_from_slice(length.to_string().as_bytes());
            buffer.extend_from_slice(b"\r\n");
        }
        BodyPlan::Chunked => {
            buffer.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
        BodyPlan::Empty => {}
    }

    if close {
        buffer.extend_from_slice(b"Connection: close\r\n");
    } else {
        buffer.extend_from_slice(b"Connection: keep-alive\r\n");
    }

    buffer.extend_from_slice(b"\r\n");
    buffer
}

#[cfg(test)]
mod tests {
    use super::{ForwardTimeouts, ResponseBodyPlan, determine_response_body_plan};
    use crate::proxy::http::codec::ResponseHead;
    use http::StatusCode;
    use std::time::Duration;

    #[tokio::test]
    async fn send_continue_writes_expected_response() -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, duplex};

        let (mut client, mut server) = duplex(64);
        super::send_continue_if_needed(
            &mut server,
            true,
            super::BodyPlan::Fixed(1),
            Duration::from_secs(1),
        )
        .await?;
        drop(server);

        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await?;
        assert_eq!(buf, b"HTTP/1.1 100 Continue\r\n\r\n");
        Ok(())
    }

    #[test]
    fn transfer_encoding_without_chunked_forces_until_close() {
        let head = ResponseHead {
            status_line: "HTTP/1.1 200 OK".to_string(),
            status: StatusCode::OK,
            headers: Vec::new(),
            content_length: Some(123),
            chunked: false,
            transfer_encoding_present: true,
            connection_close: false,
        };
        let plan = determine_response_body_plan(&http::Method::GET, StatusCode::OK, &head);
        assert!(matches!(plan, ResponseBodyPlan::UntilClose));
    }

    #[tokio::test]
    async fn forwards_informational_responses_before_final() -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, duplex};

        let (mut upstream_writer, upstream_reader) = duplex(1024);
        let (mut client_reader, client_writer) = duplex(1024);

        let response = concat!(
            "HTTP/1.1 100 Continue\r\nX-Test: one\r\n\r\n",
            "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        );
        upstream_writer.write_all(response.as_bytes()).await?;
        drop(upstream_writer);

        let mut upstream_reader = BufReader::new(upstream_reader);
        let mut client_writer = client_writer;
        let timeouts = ForwardTimeouts {
            connect: Duration::from_secs(1),
            request_io: Duration::from_secs(1),
            response_header: Duration::from_secs(1),
            response_io: Duration::from_secs(1),
        };
        let (head, bytes) = super::read_final_response_head(
            &mut upstream_reader,
            &mut client_writer,
            &timeouts,
            "127.0.0.1:80".parse().unwrap(),
            1024,
        )
        .await?;

        assert_eq!(head.status, StatusCode::OK);
        assert!(bytes > 0);
        drop(client_writer);

        let mut buf = Vec::new();
        client_reader.read_to_end(&mut buf).await?;
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("HTTP/1.1 100"));
        assert!(text.contains("HTTP/1.1 103"));
        assert!(!text.contains("HTTP/1.1 200"));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_switching_protocols() -> anyhow::Result<()> {
        use tokio::io::{AsyncWriteExt, BufReader, duplex};

        let (mut upstream_writer, upstream_reader) = duplex(512);
        let (_client_reader, mut client_writer) = duplex(512);
        let response = concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Connection: Upgrade\r\n",
            "Upgrade: websocket\r\n\r\n"
        );
        upstream_writer.write_all(response.as_bytes()).await?;
        drop(upstream_writer);

        let mut upstream_reader = BufReader::new(upstream_reader);
        let timeouts = ForwardTimeouts {
            connect: Duration::from_secs(1),
            request_io: Duration::from_secs(1),
            response_header: Duration::from_secs(1),
            response_io: Duration::from_secs(1),
        };
        let result = super::read_final_response_head(
            &mut upstream_reader,
            &mut client_writer,
            &timeouts,
            "127.0.0.1:80".parse().unwrap(),
            1024,
        )
        .await;
        match result {
            Ok(_) => panic!("expected 101 to be rejected"),
            Err(err) => {
                assert!(err.to_string().contains("Switching Protocols"));
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn rejects_informational_with_body_indicators() -> anyhow::Result<()> {
        use tokio::io::{AsyncWriteExt, BufReader, duplex};

        let (mut upstream_writer, upstream_reader) = duplex(512);
        let (_client_reader, mut client_writer) = duplex(512);
        let response = concat!("HTTP/1.1 100 Continue\r\n", "Content-Length: 5\r\n", "\r\n");
        upstream_writer.write_all(response.as_bytes()).await?;
        drop(upstream_writer);

        let mut upstream_reader = BufReader::new(upstream_reader);
        let timeouts = ForwardTimeouts {
            connect: Duration::from_secs(1),
            request_io: Duration::from_secs(1),
            response_header: Duration::from_secs(1),
            response_io: Duration::from_secs(1),
        };
        let result = super::read_final_response_head(
            &mut upstream_reader,
            &mut client_writer,
            &timeouts,
            "127.0.0.1:80".parse().unwrap(),
            1024,
        )
        .await;
        match result {
            Ok(_) => panic!("expected informational response to be rejected"),
            Err(err) => {
                assert!(
                    err.to_string()
                        .contains("informational response must not include a body")
                );
            }
        }
        Ok(())
    }
}
