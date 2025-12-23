use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::io_util::write_all_with_timeout;
use crate::proxy::request::ParsedRequest;
use crate::util::timeout_with_context;

use super::super::body::BodyPlan;
use super::super::codec::Http1HeaderAccumulator;

pub(crate) fn build_upstream_request(
    request: &ParsedRequest,
    headers: &Http1HeaderAccumulator,
    request_close: bool,
    body_plan: &BodyPlan,
    expect_continue: bool,
) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(256);
    buffer.extend_from_slice(request.method.as_str().as_bytes());
    buffer.extend_from_slice(b" ");
    buffer.extend_from_slice(request.path.as_bytes());
    buffer.extend_from_slice(b" HTTP/1.1\r\n");

    buffer.extend_from_slice(b"Host: ");
    buffer.extend_from_slice(request.authority_host().as_bytes());
    buffer.extend_from_slice(b"\r\n");

    for header in headers.forward_headers() {
        if expect_continue && header.lower_name() == "expect" {
            continue;
        }
        buffer.extend_from_slice(header.name.as_bytes());
        buffer.extend_from_slice(b": ");
        buffer.extend_from_slice(header.value.as_bytes());
        buffer.extend_from_slice(b"\r\n");
    }

    if request_close {
        buffer.extend_from_slice(b"Connection: close\r\n");
    }

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

    buffer.extend_from_slice(b"\r\n");
    buffer
}

pub(super) async fn send_continue_if_needed<S>(
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

    write_all_with_timeout(
        client,
        b"HTTP/1.1 100 Continue\r\n\r\n",
        timeout,
        "sending 100 Continue to client",
    )
    .await?;
    timeout_with_context(timeout, client.flush(), "flushing 100 Continue to client").await
}
