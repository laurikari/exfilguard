use std::net::SocketAddr;
use std::time::Instant;

use anyhow::{Result, bail};
use http::{Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::io_util::write_all_with_timeout;
use crate::util::timeout_with_context;

use super::super::body::{relay_chunked_body, relay_fixed_body, relay_until_close};
use super::super::codec::{Http1ResponseHead, read_http1_response_head};
use super::ForwardTimeouts;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResponseBodyPlan {
    Chunked,
    Fixed(u64),
    Empty,
    UntilClose,
}

pub(super) async fn read_final_response_head<S, C>(
    upstream_reader: &mut BufReader<S>,
    client: &mut C,
    timeouts: &ForwardTimeouts,
    upstream_peer: SocketAddr,
    max_header_bytes: usize,
) -> Result<(Http1ResponseHead, u64)>
where
    S: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut informational_bytes = 0u64;
    loop {
        let mut head = read_http1_response_head(
            upstream_reader,
            timeouts.response_header,
            upstream_peer,
            max_header_bytes,
        )
        .await?;

        if head.status == StatusCode::SWITCHING_PROTOCOLS {
            bail!("upstream attempted protocol upgrade (101 Switching Protocols)");
        }

        if head.status.is_informational() && head.status != StatusCode::SWITCHING_PROTOCOLS {
            if head.transfer_encoding_present {
                bail!("informational response must not include a body");
            }
            if let Some(length) = head.content_length
                && length > 0
            {
                bail!("informational response must not include a body");
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
            informational_bytes = informational_bytes.saturating_add(encoded.len() as u64);
            continue;
        }

        return Ok((head, informational_bytes));
    }
}

pub(crate) fn determine_response_body_plan(
    method: &Method,
    status: StatusCode,
    head: &Http1ResponseHead,
) -> ResponseBodyPlan {
    if method == Method::HEAD {
        return ResponseBodyPlan::Empty;
    }

    if status == StatusCode::SWITCHING_PROTOCOLS {
        return ResponseBodyPlan::UntilClose;
    }

    if status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::RESET_CONTENT
        || status == StatusCode::NOT_MODIFIED
    {
        return ResponseBodyPlan::Empty;
    }

    if head.chunked {
        return ResponseBodyPlan::Chunked;
    }

    if let Some(length) = head.content_length {
        return ResponseBodyPlan::Fixed(length);
    }

    if head.transfer_encoding_present {
        return ResponseBodyPlan::UntilClose;
    }

    ResponseBodyPlan::UntilClose
}

pub(super) async fn relay_body<S, C>(
    upstream: &mut BufReader<S>,
    client: &mut C,
    body_plan: ResponseBodyPlan,
    timeouts: &ForwardTimeouts,
    upstream_peer: SocketAddr,
    total_deadline: Option<Instant>,
) -> Result<u64>
where
    S: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    match body_plan {
        ResponseBodyPlan::Empty => Ok(0),
        ResponseBodyPlan::Fixed(length) => {
            relay_fixed_body(
                upstream,
                client,
                length,
                timeouts.response_io,
                timeouts.response_io,
                upstream_peer,
                total_deadline,
            )
            .await
        }
        ResponseBodyPlan::Chunked => {
            relay_chunked_body(
                upstream,
                client,
                timeouts.response_io,
                timeouts.response_io,
                upstream_peer,
                total_deadline,
            )
            .await
        }
        ResponseBodyPlan::UntilClose => {
            relay_until_close(
                upstream,
                client,
                timeouts.response_io,
                timeouts.response_io,
                upstream_peer,
                total_deadline,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ResponseBodyPlan, determine_response_body_plan, read_final_response_head};
    use crate::proxy::forward_error::RequestTimeout;
    use crate::proxy::http::codec::Http1ResponseHead;
    use crate::proxy::http::forward::ForwardTimeouts;
    use http::{Method, StatusCode};
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, duplex};

    fn head_with_status(status: StatusCode) -> Http1ResponseHead {
        Http1ResponseHead {
            status_line: format!(
                "HTTP/1.1 {} {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("OK")
            ),
            status,
            headers: Vec::new(),
            content_length: None,
            chunked: false,
            transfer_encoding_present: false,
            connection_close: false,
        }
    }

    #[test]
    fn determine_response_body_plan_respects_status_and_method() {
        let head = head_with_status(StatusCode::OK);
        assert_eq!(
            determine_response_body_plan(&Method::HEAD, head.status, &head),
            ResponseBodyPlan::Empty
        );

        let head = head_with_status(StatusCode::NO_CONTENT);
        assert_eq!(
            determine_response_body_plan(&Method::GET, head.status, &head),
            ResponseBodyPlan::Empty
        );

        let head = head_with_status(StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            determine_response_body_plan(&Method::GET, head.status, &head),
            ResponseBodyPlan::UntilClose
        );
    }

    #[test]
    fn determine_response_body_plan_prefers_length_headers() {
        let mut head = head_with_status(StatusCode::OK);
        head.content_length = Some(5);
        assert_eq!(
            determine_response_body_plan(&Method::GET, head.status, &head),
            ResponseBodyPlan::Fixed(5)
        );

        let mut head = head_with_status(StatusCode::OK);
        head.chunked = true;
        assert_eq!(
            determine_response_body_plan(&Method::GET, head.status, &head),
            ResponseBodyPlan::Chunked
        );
    }

    #[tokio::test(start_paused = true)]
    async fn relay_body_respects_total_deadline() {
        let (_upstream_writer, upstream_stream) = duplex(1024);
        let (client_stream, _client_reader) = duplex(1024);
        let mut upstream_reader = BufReader::new(upstream_stream);
        let mut client = client_stream;

        let timeouts = ForwardTimeouts {
            connect: Duration::from_secs(5),
            request_io: Duration::from_secs(5),
            response_header: Duration::from_secs(5),
            response_io: Duration::from_secs(5),
        };
        let total_deadline = Some(Instant::now() + Duration::from_millis(50));
        let upstream_peer: SocketAddr = "127.0.0.1:8443".parse().unwrap();

        let handle = tokio::spawn(async move {
            super::relay_body(
                &mut upstream_reader,
                &mut client,
                ResponseBodyPlan::Fixed(4),
                &timeouts,
                upstream_peer,
                total_deadline,
            )
            .await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(100)).await;

        let err = handle
            .await
            .expect("task panicked")
            .expect_err("expected total deadline to trigger timeout");
        assert!(
            err.downcast_ref::<RequestTimeout>().is_some(),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn read_final_response_head_forwards_informational() -> anyhow::Result<()> {
        let (upstream_stream, mut upstream_writer) = duplex(256);
        let (mut client_stream, mut client_reader) = duplex(256);
        upstream_writer
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await?;
        drop(upstream_writer);

        let mut upstream_reader = BufReader::new(upstream_stream);
        let timeouts = ForwardTimeouts {
            connect: Duration::from_secs(1),
            request_io: Duration::from_secs(1),
            response_header: Duration::from_secs(1),
            response_io: Duration::from_secs(1),
        };
        let peer: SocketAddr = "127.0.0.1:8080".parse()?;
        let (head, informational_bytes) = read_final_response_head(
            &mut upstream_reader,
            &mut client_stream,
            &timeouts,
            peer,
            256,
        )
        .await?;
        assert_eq!(head.status, StatusCode::OK);
        assert!(informational_bytes > 0);

        client_stream.shutdown().await?;
        let mut buf = Vec::new();
        client_reader.read_to_end(&mut buf).await?;
        assert!(buf.starts_with(b"HTTP/1.1 100"));
        Ok(())
    }

    #[tokio::test]
    async fn read_final_response_head_rejects_switching_protocols() -> anyhow::Result<()> {
        use tokio::io::{AsyncWriteExt, BufReader, duplex};

        let (mut upstream_writer, upstream_reader) = duplex(256);
        let (_client_reader, mut client_writer) = duplex(256);
        upstream_writer
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await?;
        drop(upstream_writer);

        let mut upstream_reader = BufReader::new(upstream_reader);
        let timeouts = ForwardTimeouts {
            connect: Duration::from_secs(1),
            request_io: Duration::from_secs(1),
            response_header: Duration::from_secs(1),
            response_io: Duration::from_secs(1),
        };
        let peer: SocketAddr = "127.0.0.1:8080".parse()?;
        let result = read_final_response_head(
            &mut upstream_reader,
            &mut client_writer,
            &timeouts,
            peer,
            256,
        )
        .await;
        match result {
            Ok(_) => panic!("expected switching protocols response to be rejected"),
            Err(err) => assert!(err.to_string().contains("Switching Protocols")),
        }
        Ok(())
    }

    #[tokio::test]
    async fn read_final_response_head_rejects_informational_with_body_indicators()
    -> anyhow::Result<()> {
        use tokio::io::{AsyncWriteExt, BufReader, duplex};

        let (mut upstream_writer, upstream_reader) = duplex(256);
        let (_client_reader, mut client_writer) = duplex(256);
        upstream_writer
            .write_all(b"HTTP/1.1 100 Continue\r\nContent-Length: 5\r\n\r\n")
            .await?;
        drop(upstream_writer);

        let mut upstream_reader = BufReader::new(upstream_reader);
        let timeouts = ForwardTimeouts {
            connect: Duration::from_secs(1),
            request_io: Duration::from_secs(1),
            response_header: Duration::from_secs(1),
            response_io: Duration::from_secs(1),
        };
        let peer: SocketAddr = "127.0.0.1:8080".parse()?;
        let result = read_final_response_head(
            &mut upstream_reader,
            &mut client_writer,
            &timeouts,
            peer,
            256,
        )
        .await;
        match result {
            Ok(_) => panic!("expected informational response to be rejected"),
            Err(err) => assert!(
                err.to_string()
                    .contains("informational response must not include a body")
            ),
        }
        Ok(())
    }
}
