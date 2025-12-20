use std::{collections::HashSet, net::SocketAddr, time::Duration};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use h2::RecvStream;
use h2::server::SendResponse;
use http::{HeaderMap, HeaderValue, StatusCode};
use tokio::time::timeout;

use crate::{
    proxy::forward_limits::{BodySizeTracker, HeaderBudget},
    util::timeout_with_context,
};

use super::{
    request::{SanitizedRequest, build_upstream_uri},
    upstream::UpstreamCheckout,
};

const HEADER_PADDING: usize = 4;

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
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn forward_request_to_upstream(
    checkout: UpstreamCheckout,
    meta: SanitizedRequest,
    body: &mut RecvStream,
    respond: &mut SendResponse<Bytes>,
    client_timeout: Duration,
    upstream_timeout: Duration,
    max_request_body_size: usize,
    max_response_header_bytes: usize,
) -> Result<ForwardOutcome> {
    let mut sender = checkout.sender;
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
        headers.insert(
            http::header::HOST,
            HeaderValue::from_str(&authority_host).context("invalid host header value")?,
        );
    }
    let request = builder
        .body(())
        .map_err(|err| anyhow!("failed to build upstream HTTP/2 request: {err}"))?;

    let end_of_stream = body.is_end_stream();
    let (response_fut, mut send_stream) = sender
        .send_request(request, end_of_stream)
        .context("failed to send headers to upstream over HTTP/2")?;

    let mut body_tracker = BodySizeTracker::new(max_request_body_size);

    if !end_of_stream {
        while let Some(frame) = timeout(client_timeout, body.data())
            .await
            .map_err(|_| anyhow!("timed out reading HTTP/2 request body from client"))?
        {
            let chunk = frame.context("failed to read data frame from HTTP/2 client")?;
            if chunk.is_empty() {
                continue;
            }
            body_tracker.record(chunk.len())?;
            send_stream
                .send_data(chunk, false)
                .context("failed to forward HTTP/2 request body upstream")?;
        }

        match timeout_with_context(
            client_timeout,
            body.trailers(),
            "reading HTTP/2 request trailers from client",
        )
        .await?
        {
            Some(trailers) => {
                send_stream
                    .send_trailers(trailers)
                    .context("failed to forward HTTP/2 request trailers upstream")?;
            }
            None => {
                send_stream
                    .send_data(Bytes::new(), true)
                    .context("failed to terminate upstream HTTP/2 request stream")?;
            }
        }
    }

    let response = timeout_with_context(
        upstream_timeout,
        response_fut,
        "receiving HTTP/2 response from upstream",
    )
    .await?;
    let client_body_bytes = body_tracker.total();

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
        if lower == "connection"
            || lower == "transfer-encoding"
            || lower == "keep-alive"
            || lower == "proxy-connection"
            || lower == "proxy-authenticate"
            || lower == "proxy-authorization"
            || lower == "trailer"
            || lower == "upgrade"
            || connection_tokens.contains(lower.as_str())
        {
            continue;
        }
        header_budget.record(name_str.len() + value.as_bytes().len() + HEADER_PADDING)?;
        response_headers.append(name.clone(), value.clone());
    }
    let response_header_bytes = header_budget.used();

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

    let mut upstream_body_bytes = 0u64;
    let mut response_body = response.into_body();
    if !end_stream {
        while let Some(frame) = timeout(upstream_timeout, response_body.data())
            .await
            .map_err(|_| anyhow!("timed out reading HTTP/2 response body from upstream"))?
        {
            let chunk = frame.context("failed to read HTTP/2 response data frame")?;
            if chunk.is_empty() {
                continue;
            }
            upstream_body_bytes = upstream_body_bytes
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| anyhow!("response body size overflow"))?;
            send_body
                .send_data(chunk, false)
                .context("failed to forward HTTP/2 response body to client")?;
        }

        match timeout_with_context(
            upstream_timeout,
            response_body.trailers(),
            "reading HTTP/2 response trailers from upstream",
        )
        .await?
        {
            Some(trailers) => {
                send_body
                    .send_trailers(trailers)
                    .context("failed to forward HTTP/2 response trailers to client")?;
            }
            None => {
                send_body
                    .send_data(Bytes::new(), true)
                    .context("failed to terminate downstream HTTP/2 response stream")?;
            }
        }
    }

    Ok(ForwardOutcome {
        log: ForwardLog {
            status,
            client_body_bytes,
            response_body_bytes: upstream_body_bytes,
            response_header_bytes,
            upstream_addr: upstream_peer,
            upstream_reused: reused_existing,
        },
    })
}

pub(super) async fn send_error_response(
    respond: &mut SendResponse<Bytes>,
    status: StatusCode,
    message: &str,
) -> Result<()> {
    let mut builder = http::Response::builder().status(status);
    {
        let headers = builder
            .headers_mut()
            .expect("headers_mut available before body");
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
}
