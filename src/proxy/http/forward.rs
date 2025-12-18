use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::Result;
use http::{Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_rustls::client::TlsStream;
use tracing::debug;

use crate::io_util::TeeWriter;
use crate::proxy::AppContext;
use crate::proxy::connect::ResolvedTarget;
use crate::proxy::http::cache_control::{get_freshness_lifetime, is_cacheable};
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

pub struct ForwardTimeouts {
    pub connect: Duration,
    pub upstream: Duration,
    pub client: Duration,
}

#[derive(Clone, Copy)]
pub enum ResponseBodyPlan {
    Empty,
    Fixed(u64),
    Chunked,
    UntilClose,
}

pub struct ForwardStats {
    pub bytes_to_client: u64,
    pub status: StatusCode,
    pub client_body_bytes: u64,
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
    decision: &AllowDecision,
    peer: SocketAddr,
    max_body_size: usize,
    app: &AppContext,
) -> Result<ForwardResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = UpstreamKey::from_request(request, decision.allow_private_connect);
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
                decision.allow_private_connect,
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
        peer,
        max_body_size,
        request_close,
        app.settings.max_response_header_size,
        decision,
        app,
    )
    .await;

    match outcome {
        Ok((stats, reuse_upstream, client_close)) => {
            if reuse_upstream {
                pool.put(key, connection, timeouts.upstream);
            } else if let Err(err) = connection.shutdown(timeouts.upstream).await {
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
            if let Err(shutdown_err) = connection.shutdown(timeouts.upstream).await {
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
    peer: SocketAddr,
    max_body_size: usize,
    request_close: bool,
    max_response_header_bytes: usize,
    decision: &AllowDecision,
    app: &AppContext,
) -> Result<(ForwardStats, bool, bool)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request_bytes = build_upstream_request(request, headers, request_close, &body_plan);
    timeout_with_context(
        timeouts.upstream,
        connection.stream.write_all(&request_bytes),
        "sending request headers to upstream",
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
                timeouts.client,
                timeouts.upstream,
            )
            .await?;
        }
        BodyPlan::Chunked => {
            client_body_bytes = stream_chunked_body(
                client_reader,
                &mut connection.stream,
                timeouts.client,
                timeouts.upstream,
                peer,
                max_body_size,
            )
            .await?;
        }
    }

    timeout_with_context(
        timeouts.upstream,
        connection.stream.flush(),
        "flushing upstream stream",
    )
    .await?;

    let mut upstream_reader = BufReader::new(&mut connection.stream);
    let head = read_response_head(
        &mut upstream_reader,
        timeouts.upstream,
        connection.peer,
        max_response_header_bytes,
    )
    .await?;
    let response_body_plan = determine_response_body_plan(&request.method, head.status, &head);

    let mut client_close = request_close || head.connection_close;
    if matches!(response_body_plan, ResponseBodyPlan::UntilClose) {
        client_close = true;
    }

    // Check caching
    let mut cache_stream = None;
    if let Some(cache_config) = &decision.cache
        && let Some(cache) = &app.cache
    {
        let method_obj = &request.method;
        let cache_uri = match request.cache_uri() {
            Ok(uri) => Some(uri),
            Err(err) => {
                debug!(peer = %peer, error = %err, host = %request.host, "skipping cache due to URI build failure");
                None
            }
        };

        let mut req_headers_map = http::HeaderMap::new();
        for h in headers.forward_headers() {
            if let Ok(k) = http::header::HeaderName::from_bytes(h.name.as_bytes())
                && let Ok(v) = http::header::HeaderValue::from_bytes(h.value.as_bytes())
            {
                req_headers_map.append(k, v);
            }
        }

        let mut resp_headers_map = http::HeaderMap::new();
        for h in &head.headers {
            if let Ok(k) = http::header::HeaderName::from_bytes(h.name.as_bytes())
                && let Ok(v) = http::header::HeaderValue::from_bytes(h.value.as_bytes())
            {
                resp_headers_map.append(k, v);
            }
        }

        if let Some(uri_obj) = cache_uri
            && is_cacheable(method_obj, head.status, &resp_headers_map)
        {
            let ttl = select_cache_ttl(
                get_freshness_lifetime(&resp_headers_map),
                cache_config.force_cache_duration,
            );

            if ttl > Duration::ZERO {
                match cache
                    .open_stream(method_obj, &uri_obj, &req_headers_map, &resp_headers_map)
                    .await
                {
                    Ok(stream) => {
                        cache_stream = Some((stream, ttl, resp_headers_map));
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

    let encoded_head = head.encode(override_connection);
    {
        let client_stream = client_reader.get_mut();
        timeout_with_context(
            timeouts.client,
            client_stream.write_all(&encoded_head),
            "writing response head to client",
        )
        .await?;
    }
    let mut bytes_to_client = encoded_head.len() as u64;

    {
        let client_stream = client_reader.get_mut();

        let body_bytes = if let Some((mut stream, ttl, resp_headers)) = cache_stream {
            let mut tee = TeeWriter::new(client_stream, &mut stream);
            let res = relay_body_generic(
                &mut upstream_reader,
                &mut tee,
                response_body_plan,
                timeouts.upstream,
                timeouts.client,
                connection.peer,
            )
            .await;

            match res {
                Ok(bytes) => {
                    if let Err(e) = stream.finish(head.status, resp_headers, ttl).await {
                        debug!("failed to commit cache entry: {}", e);
                    }
                    Ok(bytes)
                }
                Err(e) => Err(e),
            }?
        } else {
            relay_body_generic(
                &mut upstream_reader,
                client_stream,
                response_body_plan,
                timeouts.upstream,
                timeouts.client,
                connection.peer,
            )
            .await?
        };

        bytes_to_client = bytes_to_client.saturating_add(body_bytes);
    }
    // Access client_stream again to flush
    timeout_with_context(
        timeouts.client,
        client_reader.get_mut().flush(),
        "flushing client stream",
    )
    .await?;

    drop(upstream_reader);

    let reuse_upstream =
        !client_close && !matches!(response_body_plan, ResponseBodyPlan::UntilClose);

    Ok((
        ForwardStats {
            bytes_to_client,
            status: head.status,
            client_body_bytes,
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
    upstream_timeout: Duration,
    client_timeout: Duration,
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
                upstream_timeout,
                client_timeout,
                peer,
            )
            .await
        }
        ResponseBodyPlan::Chunked => {
            relay_chunked_body(upstream, client, upstream_timeout, client_timeout, peer).await
        }
        ResponseBodyPlan::UntilClose => {
            relay_until_close(upstream, client, upstream_timeout, client_timeout, peer).await
        }
    }
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
    if let Some(length) = head.content_length {
        if length == 0 {
            return ResponseBodyPlan::Empty;
        }
        return ResponseBodyPlan::Fixed(length);
    }
    ResponseBodyPlan::UntilClose
}

fn select_cache_ttl(origin_ttl: Option<Duration>, forced: Option<Duration>) -> Duration {
    if let Some(ttl) = origin_ttl
        && ttl > Duration::ZERO
    {
        return ttl;
    }
    forced.unwrap_or(Duration::ZERO)
}

pub fn build_upstream_request(
    request: &ParsedRequest,
    headers: &HeaderAccumulator,
    close: bool,
    body_plan: &BodyPlan,
) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(512);
    buffer
        .extend_from_slice(format!("{} {} HTTP/1.1\r\n", request.method, request.path).as_bytes());

    for header in headers.forward_headers() {
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
    use super::select_cache_ttl;
    use std::time::Duration;

    #[test]
    fn prefers_origin_ttl_when_present() {
        let origin = Some(Duration::from_secs(30));
        let forced = Some(Duration::from_secs(5));
        assert_eq!(select_cache_ttl(origin, forced), Duration::from_secs(30));
    }

    #[test]
    fn falls_back_to_forced_when_origin_is_zero_or_missing() {
        let forced = Some(Duration::from_secs(5));
        assert_eq!(
            select_cache_ttl(Some(Duration::ZERO), forced),
            Duration::from_secs(5)
        );
        assert_eq!(select_cache_ttl(None, forced), Duration::from_secs(5));
    }

    #[test]
    fn returns_zero_without_origin_or_forced() {
        assert_eq!(select_cache_ttl(None, None), Duration::ZERO);
        assert_eq!(select_cache_ttl(Some(Duration::ZERO), None), Duration::ZERO);
    }
}
