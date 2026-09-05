use std::{
    collections::HashSet,
    future::Future,
    net::SocketAddr,
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use futures::future::poll_fn;
use h2::{RecvStream, SendStream};
use h2::{client, server::SendResponse};
use http::{HeaderMap, HeaderValue, StatusCode};
use tokio::{sync::Mutex, time::timeout};

use crate::{
    authorization::FinalizedRequestV1,
    proxy::forward_error::{ClientBodyIdleTimeout, RequestTimeout},
    proxy::forward_limits::{BodySizeTracker, HeaderBudget, RequestDeadline, ResponseProgress},
    proxy::headers::{
        response_header_should_skip, sanitize_request_trailer_map, sanitize_response_trailer_map,
    },
    util::timeout_with_context,
};

use super::{
    cache::{CacheMiss, CacheWriteState},
    request::{SanitizedRequest, build_upstream_uri},
    upstream::UpstreamCheckout,
};

const HEADER_PADDING: usize = 4;

pub(super) async fn with_total_deadline<F, T>(
    total_deadline: Option<Instant>,
    future: F,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    if let Some(deadline) = total_deadline {
        let now = Instant::now();
        if now >= deadline {
            return Err(RequestTimeout.into());
        }
        let remaining = deadline - now;
        match timeout(remaining, future).await {
            Ok(result) => result,
            Err(_) => Err(RequestTimeout.into()),
        }
    } else {
        future.await
    }
}

pub(super) async fn send_data_with_backpressure(
    stream: &mut SendStream<Bytes>,
    mut data: Bytes,
    idle_timeout: Duration,
    total_deadline: Option<Instant>,
    context: &'static str,
) -> Result<()> {
    stream.reserve_capacity(data.len());
    while !data.is_empty() {
        let capacity = if stream.capacity() > 0 {
            stream.capacity()
        } else {
            with_total_deadline(total_deadline, async {
                timeout(idle_timeout, poll_fn(|cx| stream.poll_capacity(cx)))
                    .await
                    .map_err(|_| anyhow!("timed out {context}"))?
                    .ok_or_else(|| anyhow!("{context}: stream closed"))?
                    .with_context(|| context)
            })
            .await?
        };
        if capacity == 0 {
            continue;
        }

        let send_len = capacity.min(data.len());
        let chunk = data.split_to(send_len);
        stream.send_data(chunk, false).with_context(|| context)?;
    }
    Ok(())
}

async fn open_upstream_stream(
    sender: &Mutex<client::SendRequest<Bytes>>,
    request: http::Request<()>,
    end_of_stream: bool,
    request_deadline: Option<Instant>,
) -> Result<(client::ResponseFuture, SendStream<Bytes>, Instant)> {
    with_total_deadline(request_deadline, async {
        let mut sender = sender.lock().await;
        poll_fn(|cx| sender.poll_ready(cx))
            .await
            .context("upstream HTTP/2 sender not ready")?;
        let upstream_request_instant = Instant::now();
        let (response_fut, send_stream) = sender
            .send_request(request, end_of_stream)
            .context("failed to send headers to upstream over HTTP/2")?;
        Ok((response_fut, send_stream, upstream_request_instant))
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn upload_request_body(
    body: &mut RecvStream,
    send_stream: &mut SendStream<Bytes>,
    body_tracker: &mut BodySizeTracker,
    request_body_timeout: Duration,
    request_deadline: Option<Instant>,
    max_request_header_bytes: usize,
) -> Result<()> {
    while let Some(frame) = with_total_deadline(request_deadline, async {
        timeout(request_body_timeout, body.data())
            .await
            .map_err(|_| anyhow::Error::new(ClientBodyIdleTimeout))
    })
    .await?
    {
        let chunk = frame.context("failed to read data frame from HTTP/2 client")?;
        if chunk.is_empty() {
            continue;
        }
        let chunk_len = chunk.len();
        body_tracker.record(chunk_len)?;
        send_data_with_backpressure(
            send_stream,
            chunk,
            request_body_timeout,
            request_deadline,
            "forwarding HTTP/2 request body upstream",
        )
        .await?;
        body.flow_control()
            .release_capacity(chunk_len)
            .context("failed to release HTTP/2 request body flow-control capacity")?;
    }

    match with_total_deadline(request_deadline, async {
        timeout(request_body_timeout, body.trailers())
            .await
            .map_err(|_| anyhow::Error::new(ClientBodyIdleTimeout))?
            .context("failed while reading HTTP/2 request trailers from client")
    })
    .await?
    {
        Some(trailers) => {
            let sanitized = sanitize_request_trailer_map(&trailers, max_request_header_bytes)
                .context("invalid HTTP/2 request trailers from client")?;
            if sanitized.is_empty() {
                send_stream
                    .send_data(Bytes::new(), true)
                    .context("failed to terminate upstream HTTP/2 request stream")?;
            } else {
                send_stream
                    .send_trailers(sanitized)
                    .context("failed to forward HTTP/2 request trailers upstream")?;
            }
        }
        None => {
            send_stream
                .send_data(Bytes::new(), true)
                .context("failed to terminate upstream HTTP/2 request stream")?;
        }
    }
    Ok(())
}

pub(super) async fn buffer_request_body(
    body: &mut RecvStream,
    request_body_timeout: Duration,
    request_deadline: Option<Instant>,
    max_request_body_size: usize,
) -> Result<(Vec<u8>, u64)> {
    let mut tracker = BodySizeTracker::new(max_request_body_size);
    let mut buffered = Vec::with_capacity(max_request_body_size);
    while let Some(frame) = with_total_deadline(request_deadline, async {
        timeout(request_body_timeout, body.data())
            .await
            .map_err(|_| anyhow::Error::new(ClientBodyIdleTimeout))
    })
    .await?
    {
        let chunk = frame.context("failed to read credential-bearing HTTP/2 request body")?;
        let chunk_len = chunk.len();
        tracker.record(chunk_len)?;
        buffered.extend_from_slice(&chunk);
        body.flow_control()
            .release_capacity(chunk_len)
            .context("failed to release HTTP/2 request body flow-control capacity")?;
    }
    let trailers = with_total_deadline(request_deadline, async {
        timeout(request_body_timeout, body.trailers())
            .await
            .map_err(|_| anyhow::Error::new(ClientBodyIdleTimeout))?
            .context("failed while reading credential-bearing HTTP/2 request trailers")
    })
    .await?;
    if trailers.is_some() {
        return Err(crate::proxy::http::InvalidRequestBody::new(
            tracker.total(),
            "credential-bearing requests must not contain trailers",
        )
        .into());
    }
    Ok((buffered, tracker.total()))
}

struct RelayedResponse {
    status: StatusCode,
    response_body_bytes: u64,
    response_header_bytes: usize,
    cache_store: &'static str,
}

#[allow(clippy::too_many_arguments)]
async fn relay_upstream_response(
    response: http::Response<RecvStream>,
    respond: &mut SendResponse<Bytes>,
    response_body_timeout: Duration,
    request_deadline: Option<Instant>,
    response_progress: &ResponseProgress,
    max_response_header_bytes: usize,
    cache_miss: Option<Box<CacheMiss>>,
    request_method: &http::Method,
    upstream_peer: SocketAddr,
    upstream_request_instant: Instant,
) -> Result<RelayedResponse> {
    let response_instant = Instant::now();
    let response_time = SystemTime::now();
    let response_delay = response_instant.saturating_duration_since(upstream_request_instant);

    let status = response.status();
    let mut response_headers = HeaderMap::new();
    let mut header_budget = HeaderBudget::new(
        max_response_header_bytes,
        "upstream response headers exceed configured limit",
    )?;
    let mut connection_tokens = HashSet::new();
    for value in response.headers().get_all(http::header::CONNECTION) {
        if let Ok(s) = value.to_str() {
            for token in s.split(',') {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                connection_tokens.insert(token.to_ascii_lowercase());
            }
        }
    }
    for (name, value) in response.headers().iter() {
        let name_str = name.as_str();
        let lower = name_str.to_ascii_lowercase();
        if response_header_should_skip(&lower, &connection_tokens) {
            continue;
        }
        header_budget.record(name_str.len() + value.as_bytes().len() + HEADER_PADDING)?;
        response_headers.append(name.clone(), value.clone());
    }
    crate::proxy::http::cache_control::normalize_response_date(
        &mut response_headers,
        response_time,
    );
    let mut normalized_header_budget = HeaderBudget::new(
        max_response_header_bytes,
        "upstream response headers exceed configured limit",
    )?;
    for (name, value) in &response_headers {
        normalized_header_budget
            .record(name.as_str().len() + value.as_bytes().len() + HEADER_PADDING)?;
    }
    let response_header_bytes = normalized_header_budget.used();

    let mut cache_write = CacheWriteState::prepare(
        cache_miss,
        request_method,
        status,
        response_headers.clone(),
        response_time,
        response_delay,
        upstream_peer,
        response_body_timeout,
    )
    .await;

    let mut response_builder = http::Response::builder().status(status);
    {
        let headers = response_builder
            .headers_mut()
            .expect("headers_mut available before body");
        *headers = response_headers;
    }
    let end_stream = response.body().is_end_stream();
    let response_head = response_builder
        .body(())
        .map_err(|err| anyhow!("failed to build downstream HTTP/2 response: {err}"))?;

    let mut send_body = respond
        .send_response(response_head, end_stream)
        .context("failed to send HTTP/2 response headers downstream")?;
    response_progress.mark_started(status, response_header_bytes as u64);

    let mut upstream_body_bytes = 0u64;
    let mut response_body = response.into_body();
    if !end_stream {
        while let Some(frame) = with_total_deadline(request_deadline, async {
            timeout(response_body_timeout, response_body.data())
                .await
                .map_err(|_| anyhow!("timed out reading HTTP/2 response body from upstream"))
        })
        .await?
        {
            let chunk = frame.context("failed to read HTTP/2 response data frame")?;
            if chunk.is_empty() {
                continue;
            }
            let chunk_len = chunk.len();
            upstream_body_bytes = upstream_body_bytes
                .checked_add(chunk_len as u64)
                .ok_or_else(|| anyhow!("response body size overflow"))?;
            cache_write
                .write(&chunk, upstream_peer, response_body_timeout)
                .await;
            send_data_with_backpressure(
                &mut send_body,
                chunk,
                response_body_timeout,
                request_deadline,
                "forwarding HTTP/2 response body to client",
            )
            .await?;
            response_progress.add_bytes(chunk_len as u64);
            response_body
                .flow_control()
                .release_capacity(chunk_len)
                .context("failed to release HTTP/2 response body flow-control capacity")?;
        }

        match with_total_deadline(
            request_deadline,
            timeout_with_context(
                response_body_timeout,
                response_body.trailers(),
                "reading HTTP/2 response trailers from upstream",
            ),
        )
        .await?
        {
            Some(trailers) => {
                cache_write.discard();
                let sanitized = sanitize_response_trailer_map(&trailers, max_response_header_bytes)
                    .context("invalid HTTP/2 response trailers from upstream")?;
                if sanitized.is_empty() {
                    send_body
                        .send_data(Bytes::new(), true)
                        .context("failed to terminate downstream HTTP/2 response stream")?;
                } else {
                    send_body
                        .send_trailers(sanitized)
                        .context("failed to forward HTTP/2 response trailers to client")?;
                }
            }
            None => {
                send_body
                    .send_data(Bytes::new(), true)
                    .context("failed to terminate downstream HTTP/2 response stream")?;
            }
        }
    }

    response_progress.mark_complete();
    let cache_store = cache_write
        .finish(upstream_peer, response_body_timeout)
        .await;

    Ok(RelayedResponse {
        status,
        response_body_bytes: upstream_body_bytes,
        response_header_bytes,
        cache_store,
    })
}

#[derive(Clone)]
pub(super) struct ForwardOutcome {
    log: ForwardLog,
}

impl ForwardOutcome {
    pub fn status(&self) -> StatusCode {
        self.log.status
    }

    pub fn client_body_bytes(&self) -> u64 {
        self.log.client_body_bytes
    }

    pub fn bytes_to_client(&self) -> u64 {
        self.log.response_header_bytes as u64 + self.log.response_body_bytes
    }

    pub fn upstream_addr(&self) -> SocketAddr {
        self.log.upstream_addr
    }

    pub fn upstream_reused(&self) -> bool {
        self.log.upstream_reused
    }

    pub fn cache_store(&self) -> &'static str {
        self.log.cache_store
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn forward_request_to_upstream(
    checkout: UpstreamCheckout,
    meta: SanitizedRequest,
    body: &mut RecvStream,
    respond: &mut SendResponse<Bytes>,
    request_body_timeout: Duration,
    response_header_timeout: Duration,
    response_body_timeout: Duration,
    request_deadline: RequestDeadline,
    response_progress: &ResponseProgress,
    max_request_body_size: usize,
    max_request_header_bytes: usize,
    max_response_header_bytes: usize,
    cache_miss: Option<Box<CacheMiss>>,
) -> Result<ForwardOutcome> {
    let request_deadline = request_deadline.instant();
    let sender = checkout.sender;
    let upstream_peer = checkout.peer;
    let reused_existing = checkout.reused_existing;

    let authority_host = meta.parsed.authority_host();
    let uri = build_upstream_uri(&meta.parsed)?;
    let mut builder = http::Request::builder()
        .method(meta.parsed.method.clone())
        .uri(uri);
    {
        let headers = builder
            .headers_mut()
            .expect("headers_mut available before body");
        for (name, value) in &meta.forward_headers {
            headers.append(name.clone(), value.clone());
        }
        if let Some(content_length) = meta.content_length {
            let value = HeaderValue::from_str(&content_length.to_string())
                .context("invalid content-length header value")?;
            headers.insert(http::header::CONTENT_LENGTH, value);
        }
        headers.insert(
            http::header::HOST,
            HeaderValue::from_str(authority_host).context("invalid host header value")?,
        );
    }
    let request = builder
        .body(())
        .map_err(|err| anyhow!("failed to build upstream HTTP/2 request: {err}"))?;

    let end_of_stream = body.is_end_stream();
    let (response_fut, mut send_stream, upstream_request_instant) =
        open_upstream_stream(sender.as_ref(), request, end_of_stream, request_deadline).await?;

    let mut body_tracker = BodySizeTracker::new(max_request_body_size);
    let request_method = meta.parsed.method.clone();
    let mut cache_miss = cache_miss;
    let receive_response = async {
        response_fut
            .await
            .context("failed while receiving HTTP/2 response from upstream")
    };
    tokio::pin!(receive_response);

    let relayed = if end_of_stream {
        let response = with_total_deadline(request_deadline, async {
            timeout(response_header_timeout, &mut receive_response)
                .await
                .map_err(|_| anyhow::Error::new(RequestTimeout))?
        })
        .await?;
        relay_upstream_response(
            response,
            respond,
            response_body_timeout,
            request_deadline,
            response_progress,
            max_response_header_bytes,
            cache_miss.take(),
            &request_method,
            upstream_peer,
            upstream_request_instant,
        )
        .await?
    } else {
        let upload = upload_request_body(
            body,
            &mut send_stream,
            &mut body_tracker,
            request_body_timeout,
            request_deadline,
            max_request_header_bytes,
        );
        tokio::pin!(upload);

        tokio::select! {
            biased;
            response = &mut receive_response => {
                let response = response?;
                let relay = relay_upstream_response(
                    response,
                    respond,
                    response_body_timeout,
                    request_deadline,
                    response_progress,
                    max_response_header_bytes,
                    cache_miss.take(),
                    &request_method,
                    upstream_peer,
                    upstream_request_instant,
                );
                tokio::pin!(relay);
                tokio::select! {
                    biased;
                    result = &mut relay => result?,
                    upload_result = &mut upload => {
                        if let Err(err) = upload_result {
                            tracing::debug!(
                                error = %err,
                                "request upload ended after upstream sent a final HTTP/2 response"
                            );
                        }
                        relay.await?
                    }
                }
            }
            upload_result = &mut upload => {
                upload_result?;
                let response = with_total_deadline(request_deadline, async {
                    timeout(response_header_timeout, &mut receive_response)
                        .await
                        .map_err(|_| anyhow::Error::new(RequestTimeout))?
                })
                .await?;
                relay_upstream_response(
                    response,
                    respond,
                    response_body_timeout,
                    request_deadline,
                    response_progress,
                    max_response_header_bytes,
                    cache_miss.take(),
                    &request_method,
                    upstream_peer,
                    upstream_request_instant,
                )
                .await?
            }
        }
    };
    let client_body_bytes = body_tracker.total();

    Ok(ForwardOutcome {
        log: ForwardLog {
            status: relayed.status,
            client_body_bytes,
            response_body_bytes: relayed.response_body_bytes,
            response_header_bytes: relayed.response_header_bytes,
            upstream_addr: upstream_peer,
            upstream_reused: reused_existing,
            cache_store: relayed.cache_store,
        },
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn forward_finalized_request_to_upstream(
    checkout: UpstreamCheckout,
    finalized: FinalizedRequestV1,
    respond: &mut SendResponse<Bytes>,
    request_body_timeout: Duration,
    response_header_timeout: Duration,
    response_body_timeout: Duration,
    request_deadline: RequestDeadline,
    response_progress: &ResponseProgress,
    max_response_header_bytes: usize,
) -> Result<ForwardOutcome> {
    let request_deadline = request_deadline.instant();
    let upstream_peer = checkout.peer;
    let reused_existing = checkout.reused_existing;
    let request_method = finalized.method().clone();
    let client_body_bytes = finalized.client_body_wire_bytes();
    let (request, body) = finalized.into_http2_parts()?;
    let end_of_stream = body.is_none();
    let (response_fut, mut send_stream, upstream_request_instant) = open_upstream_stream(
        checkout.sender.as_ref(),
        request,
        end_of_stream,
        request_deadline,
    )
    .await?;
    let receive_response = async {
        response_fut
            .await
            .context("failed while receiving HTTP/2 response from upstream")
    };
    tokio::pin!(receive_response);

    let relayed = if let Some(body) = body {
        let mut upload = Box::pin(async {
            let payload = Bytes::copy_from_slice(body.bytes());
            send_data_with_backpressure(
                &mut send_stream,
                payload,
                request_body_timeout,
                request_deadline,
                "forwarding finalized HTTP/2 request body upstream",
            )
            .await?;
            send_stream
                .send_data(Bytes::new(), true)
                .context("failed to terminate finalized HTTP/2 request stream")
        });

        tokio::select! {
            biased;
            response = &mut receive_response => {
                let response = response?;
                drop(upload);
                drop(body);
                relay_upstream_response(
                    response,
                    respond,
                    response_body_timeout,
                    request_deadline,
                    response_progress,
                    max_response_header_bytes,
                    None,
                    &request_method,
                    upstream_peer,
                    upstream_request_instant,
                )
                .await?
            }
            upload_result = &mut upload => {
                upload_result?;
                drop(upload);
                drop(body);
                let response = with_total_deadline(request_deadline, async {
                    timeout(response_header_timeout, &mut receive_response)
                        .await
                        .map_err(|_| anyhow::Error::new(RequestTimeout))?
                })
                .await?;
                relay_upstream_response(
                    response,
                    respond,
                    response_body_timeout,
                    request_deadline,
                    response_progress,
                    max_response_header_bytes,
                    None,
                    &request_method,
                    upstream_peer,
                    upstream_request_instant,
                )
                .await?
            }
        }
    } else {
        let response = with_total_deadline(request_deadline, async {
            timeout(response_header_timeout, &mut receive_response)
                .await
                .map_err(|_| anyhow::Error::new(RequestTimeout))?
        })
        .await?;
        relay_upstream_response(
            response,
            respond,
            response_body_timeout,
            request_deadline,
            response_progress,
            max_response_header_bytes,
            None,
            &request_method,
            upstream_peer,
            upstream_request_instant,
        )
        .await?
    };
    Ok(ForwardOutcome {
        log: ForwardLog {
            status: relayed.status,
            client_body_bytes,
            response_body_bytes: relayed.response_body_bytes,
            response_header_bytes: relayed.response_header_bytes,
            upstream_addr: upstream_peer,
            upstream_reused: reused_existing,
            cache_store: relayed.cache_store,
        },
    })
}

pub(super) async fn send_error_response(
    respond: &mut SendResponse<Bytes>,
    status: StatusCode,
    message: &str,
    proxy_authenticate: Option<&str>,
) -> Result<()> {
    let mut builder = http::Response::builder().status(status);
    {
        let headers = builder
            .headers_mut()
            .expect("headers_mut available before body");
        if let Some(value) = proxy_authenticate {
            headers.insert(
                http::header::PROXY_AUTHENTICATE,
                HeaderValue::from_str(value).context("invalid proxy authentication challenge")?,
            );
        }
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&message.len().to_string()).unwrap(),
        );
    }
    let response = builder
        .body(())
        .map_err(|err| anyhow!("failed to build error response: {err}"))?;
    let mut stream = respond
        .send_response(response, message.is_empty())
        .context("failed to send HTTP/2 error response headers")?;
    if !message.is_empty() {
        stream
            .send_data(Bytes::copy_from_slice(message.as_bytes()), true)
            .context("failed to send HTTP/2 error response body")?;
    }
    Ok(())
}

#[derive(Clone)]
struct ForwardLog {
    status: StatusCode,
    client_body_bytes: u64,
    response_body_bytes: u64,
    response_header_bytes: usize,
    upstream_addr: SocketAddr,
    upstream_reused: bool,
    cache_store: &'static str,
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use bytes::Bytes;
    use h2::{client, server};
    use http::StatusCode;
    use tokio::{
        io::duplex,
        sync::{Mutex, mpsc},
        time::timeout,
    };

    use crate::proxy::forward_error::RequestTimeout;

    use super::open_upstream_stream;

    fn request(path: &str) -> http::Request<()> {
        http::Request::builder()
            .method("GET")
            .uri(format!("https://example.test{path}"))
            .version(http::Version::HTTP_2)
            .body(())
            .unwrap()
    }

    fn send_empty_response(mut respond: server::SendResponse<Bytes>) {
        let response = http::Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap();
        respond.send_response(response, true).unwrap();
    }

    #[tokio::test]
    async fn upstream_stream_admission_uses_one_authoritative_sender() {
        let (client_io, server_io) = duplex(64 * 1024);
        let (accepted_tx, mut accepted_rx) = mpsc::channel(4);

        let server_task = tokio::spawn(async move {
            let mut builder = server::Builder::new();
            builder.max_concurrent_streams(1);
            let mut connection = builder.handshake(server_io).await.unwrap();
            while let Some(result) = connection.accept().await {
                let (request, respond) = result.unwrap();
                accepted_tx
                    .send((request.uri().path().to_owned(), respond))
                    .await
                    .unwrap();
            }
        });

        let mut builder = client::Builder::new();
        builder.initial_max_send_streams(1);
        let (sender, connection) = builder.handshake(client_io).await.unwrap();
        let connection_task = tokio::spawn(connection);
        let sender = Arc::new(Mutex::new(sender));

        timeout(Duration::from_secs(1), async {
            loop {
                if sender.lock().await.current_max_send_streams() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("server concurrency setting was not received");

        let (first_response, _first_body, _) =
            open_upstream_stream(sender.as_ref(), request("/one"), true, None)
                .await
                .unwrap();
        let (first_path, first_respond) = timeout(Duration::from_secs(1), accepted_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_path, "/one");

        // h2 permits the authoritative handle to hold one pending-open stream. Keeping that
        // state on the shared handle is what makes the following request wait for readiness.
        let (second_response, _second_body, _) =
            open_upstream_stream(sender.as_ref(), request("/two"), true, None)
                .await
                .unwrap();
        assert!(accepted_rx.try_recv().is_err());

        let third_deadline = std::time::Instant::now() + Duration::from_millis(100);
        let third = open_upstream_stream(
            sender.as_ref(),
            request("/three"),
            true,
            Some(third_deadline),
        );
        tokio::pin!(third);
        assert!(matches!(
            futures::poll!(third.as_mut()),
            std::task::Poll::Pending
        ));
        let error = match third.await {
            Ok(_) => panic!("third stream bypassed upstream admission"),
            Err(error) => error,
        };
        assert!(error.downcast_ref::<RequestTimeout>().is_some());

        send_empty_response(first_respond);
        timeout(Duration::from_secs(1), first_response)
            .await
            .unwrap()
            .unwrap();

        let (second_path, second_respond) = timeout(Duration::from_secs(1), accepted_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second_path, "/two");
        send_empty_response(second_respond);
        timeout(Duration::from_secs(1), second_response)
            .await
            .unwrap()
            .unwrap();

        let (fourth_response, _fourth_body, _) =
            open_upstream_stream(sender.as_ref(), request("/four"), true, None)
                .await
                .unwrap();
        let (fourth_path, fourth_respond) = timeout(Duration::from_secs(1), accepted_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fourth_path, "/four");
        send_empty_response(fourth_respond);
        timeout(Duration::from_secs(1), fourth_response)
            .await
            .unwrap()
            .unwrap();

        connection_task.abort();
        server_task.abort();
    }
}
