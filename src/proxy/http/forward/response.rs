use std::net::SocketAddr;
use std::time::Instant;

use anyhow::{Result, bail};
use http::{Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::timeout;

use crate::io_util::{PayloadCopy, write_all_with_timeout};
use crate::proxy::forward_error::{InformationalResponseStarted, RequestTimeout};
use crate::proxy::forward_limits::HeaderBudget;
use crate::util::timeout_with_context;

use super::super::body::{relay_chunked_body, relay_unframed_body};
use super::super::codec::{Http1ResponseHead, read_http1_response_head_with_budget};
use super::ForwardTimeouts;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResponseBodyPlan {
    Chunked,
    Fixed(u64),
    Empty,
    UntilClose,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResponseRelayStats {
    pub bytes: u64,
    pub had_trailers: bool,
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
    let mut budget = HeaderBudget::new(
        max_header_bytes,
        "upstream response headers exceed configured limit",
    )?;
    // The enclosing deadline is authoritative. Keep a longer per-read timeout
    // only as a defensive fallback for the shared line-reading helper.
    let per_read_timeout = timeouts
        .response_header
        .saturating_add(timeouts.response_header);
    let read_sequence = async {
        loop {
            let mut head = read_http1_response_head_with_budget(
                upstream_reader,
                per_read_timeout,
                upstream_peer,
                max_header_bytes,
                &mut budget,
            )
            .await?;

            if head.status == StatusCode::SWITCHING_PROTOCOLS {
                bail!("upstream attempted protocol upgrade (101 Switching Protocols)");
            }

            if head.status.is_informational() && head.status != StatusCode::SWITCHING_PROTOCOLS {
                if head.transfer_encoding_present || head.content_length.is_some() {
                    bail!("informational response must not include body framing");
                }
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

            normalize_final_response_framing(&mut head)?;

            return Ok(head);
        }
    };

    let result = match timeout(timeouts.response_header, read_sequence).await {
        Ok(result) => result,
        Err(_) => Err(RequestTimeout.into()),
    };
    match result {
        Ok(head) => Ok((head, informational_bytes)),
        Err(source) if informational_bytes > 0 => {
            Err(InformationalResponseStarted::new(source).into())
        }
        Err(source) => Err(source),
    }
}

pub(crate) fn normalize_final_response_framing(head: &mut Http1ResponseHead) -> Result<()> {
    if head.status == StatusCode::NO_CONTENT {
        if head.transfer_encoding_present
            || head.content_length.is_some_and(|length| length != 0)
            || head.headers.iter().any(|header| {
                header.lower_name() == "content-length"
                    && !header.value_bytes().iter().all(u8::is_ascii_digit)
            })
        {
            bail!(
                "204 response must not include nonzero or invalid Content-Length or Transfer-Encoding"
            );
        }
        if head.content_length == Some(0) {
            // Some origins send this forbidden but unambiguous header. Strip it
            // from both wire framing and cache metadata. Retire the connection
            // so unsolicited bytes cannot become a later pooled response.
            head.content_length = None;
            head.headers
                .retain(|header| header.lower_name() != "content-length");
            head.connection_close = true;
        }
    }

    if head.status == StatusCode::RESET_CONTENT {
        if head.transfer_encoding_present {
            bail!("205 response with Transfer-Encoding is not supported");
        }
        if head.content_length.is_some_and(|length| length != 0) {
            bail!("205 response must not include a nonzero Content-Length");
        }
    }

    Ok(())
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn relay_body<S, C>(
    upstream: &mut BufReader<S>,
    client: &mut C,
    payload_copy: Option<&mut PayloadCopy<'_>>,
    body_plan: ResponseBodyPlan,
    timeouts: &ForwardTimeouts,
    upstream_peer: SocketAddr,
    total_deadline: Option<Instant>,
    max_response_trailer_bytes: usize,
) -> Result<ResponseRelayStats>
where
    S: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    match body_plan {
        ResponseBodyPlan::Empty => Ok(ResponseRelayStats::default()),
        ResponseBodyPlan::Fixed(length) => relay_unframed_body(
            upstream,
            client,
            Some(length),
            timeouts.response_io,
            timeouts.response_io,
            upstream_peer,
            total_deadline,
            payload_copy,
        )
        .await
        .map(|bytes| ResponseRelayStats {
            bytes,
            had_trailers: false,
        }),
        ResponseBodyPlan::Chunked => relay_chunked_body(
            upstream,
            client,
            payload_copy,
            timeouts.response_io,
            timeouts.response_io,
            upstream_peer,
            total_deadline,
            max_response_trailer_bytes,
        )
        .await
        .map(|stats| ResponseRelayStats {
            bytes: stats.bytes_written,
            had_trailers: stats.had_trailers,
        }),
        ResponseBodyPlan::UntilClose => relay_unframed_body(
            upstream,
            client,
            None,
            timeouts.response_io,
            timeouts.response_io,
            upstream_peer,
            total_deadline,
            payload_copy,
        )
        .await
        .map(|bytes| ResponseRelayStats {
            bytes,
            had_trailers: false,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{ResponseBodyPlan, determine_response_body_plan, read_final_response_head};
    use crate::proxy::forward_error::{
        ForwardErrorKind, InformationalResponseStarted, RequestTimeout, UpstreamClosed,
        classify_forward_error,
    };
    use crate::proxy::http::body::BodyPlan;
    use crate::proxy::http::codec::Http1ResponseHead;
    use crate::proxy::http::forward::ForwardTimeouts;
    use http::{Method, StatusCode};
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, duplex};

    #[tokio::test(start_paused = true)]
    async fn cache_errors_and_stalls_do_not_truncate_response_bodies() {
        let payload = "x".repeat(16 * 1024);
        let chunked = format!("4000\r\n{payload}\r\n0\r\n\r\n");
        let timeout = Duration::from_secs(1);
        let timeouts = ForwardTimeouts {
            connect: timeout,
            request_io: timeout,
            response_header: timeout,
            response_io: timeout,
        };
        for stall in [false, true] {
            for (plan, wire) in [
                (
                    ResponseBodyPlan::Fixed(payload.len() as u64),
                    payload.as_bytes(),
                ),
                (ResponseBodyPlan::UntilClose, payload.as_bytes()),
                (ResponseBodyPlan::Chunked, chunked.as_bytes()),
            ] {
                let (mut cache_writer, cache_reader) = duplex(1);
                let _reader = stall.then_some(cache_reader);
                let mut copy = crate::io_util::PayloadCopy::best_effort(&mut cache_writer);
                let mut upstream = BufReader::new(wire);
                let mut client = Vec::new();
                let stats = super::relay_body(
                    &mut upstream,
                    &mut client,
                    Some(&mut copy),
                    plan,
                    &timeouts,
                    "127.0.0.1:80".parse().unwrap(),
                    None,
                    1024,
                )
                .await
                .unwrap();
                assert_eq!(client, wire, "{plan:?}, stall={stall}");
                assert_eq!(stats.bytes, wire.len() as u64);
                assert!(copy.take_error().is_some());
            }
        }
    }

    fn head_with_status(status: StatusCode) -> Http1ResponseHead {
        Http1ResponseHead {
            status_line: format!(
                "HTTP/1.1 {} {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("OK")
            )
            .into_bytes(),
            status,
            headers: Vec::new(),
            content_length: None,
            chunked: false,
            transfer_encoding_present: false,
            connection_close: false,
        }
    }

    fn test_timeouts(response_header: Duration) -> ForwardTimeouts {
        ForwardTimeouts {
            connect: Duration::from_secs(1),
            request_io: Duration::from_secs(1),
            response_header,
            response_io: Duration::from_secs(1),
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

    #[test]
    fn stale_connection_retry_is_disabled_after_informational_response() {
        let err = anyhow::Error::new(InformationalResponseStarted::new(anyhow::Error::new(
            UpstreamClosed,
        )));
        assert!(!super::super::should_retry_reused_connection(
            true,
            &Method::GET,
            BodyPlan::Empty,
            &err,
        ));

        let timeout = anyhow::Error::new(InformationalResponseStarted::new(anyhow::Error::new(
            RequestTimeout,
        )));
        assert!(matches!(
            classify_forward_error(&timeout),
            ForwardErrorKind::RequestTimeout
        ));
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
                None,
                ResponseBodyPlan::Fixed(4),
                &timeouts,
                upstream_peer,
                total_deadline,
                1024,
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

    #[tokio::test(start_paused = true)]
    async fn response_header_deadline_does_not_reset_for_each_byte() {
        let (upstream_stream, mut upstream_writer) = duplex(256);
        let (mut client_stream, _client_reader) = duplex(256);
        let mut upstream_reader = BufReader::new(upstream_stream);
        let timeouts = test_timeouts(Duration::from_millis(100));
        let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let handle = tokio::spawn(async move {
            read_final_response_head(
                &mut upstream_reader,
                &mut client_stream,
                &timeouts,
                peer,
                256,
            )
            .await
        });

        tokio::task::yield_now().await;
        upstream_writer.write_all(b"H").await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(60)).await;
        upstream_writer.write_all(b"T").await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(60)).await;
        tokio::task::yield_now().await;

        assert!(
            handle.is_finished(),
            "response-header timeout reset after partial-line progress"
        );
        let err = match handle.await.expect("response reader task panicked") {
            Ok(_) => panic!("drip-fed status line should exceed one absolute deadline"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn response_header_deadline_does_not_reset_for_each_line() {
        let (upstream_stream, mut upstream_writer) = duplex(256);
        let (mut client_stream, _client_reader) = duplex(256);
        let mut upstream_reader = BufReader::new(upstream_stream);
        let timeouts = test_timeouts(Duration::from_millis(100));
        let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let handle = tokio::spawn(async move {
            read_final_response_head(
                &mut upstream_reader,
                &mut client_stream,
                &timeouts,
                peer,
                256,
            )
            .await
        });

        tokio::task::yield_now().await;
        upstream_writer
            .write_all(b"HTTP/1.1 200 OK\r\n")
            .await
            .unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(60)).await;
        upstream_writer
            .write_all(b"X-Test: progress\r\n")
            .await
            .unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(60)).await;
        tokio::task::yield_now().await;

        assert!(
            handle.is_finished(),
            "response-header timeout reset after a complete header line"
        );
        let err = match handle.await.expect("response reader task panicked") {
            Ok(_) => panic!("line-dripped response head should exceed one absolute deadline"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn informational_and_final_heads_share_one_byte_budget() -> anyhow::Result<()> {
        let (upstream_stream, mut upstream_writer) = duplex(512);
        let (mut client_stream, _client_reader) = duplex(512);
        upstream_writer
            .write_all(
                b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        drop(upstream_writer);

        let mut upstream_reader = BufReader::new(upstream_stream);
        let peer: SocketAddr = "127.0.0.1:8080".parse()?;
        let result = read_final_response_head(
            &mut upstream_reader,
            &mut client_stream,
            &test_timeouts(Duration::from_secs(1)),
            peer,
            100,
        )
        .await;
        let err = match result {
            Ok(_) => panic!("informational sequence should exceed aggregate header budget"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("headers exceed configured limit"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn small_informational_chain_reaches_final_response() -> anyhow::Result<()> {
        let (upstream_stream, mut upstream_writer) = duplex(512);
        let (mut client_stream, mut client_reader) = duplex(512);
        upstream_writer
            .write_all(
                b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        drop(upstream_writer);

        let mut upstream_reader = BufReader::new(upstream_stream);
        let peer: SocketAddr = "127.0.0.1:8080".parse()?;
        let (head, informational_bytes) = read_final_response_head(
            &mut upstream_reader,
            &mut client_stream,
            &test_timeouts(Duration::from_secs(1)),
            peer,
            256,
        )
        .await?;
        assert_eq!(head.status, StatusCode::OK);
        assert!(informational_bytes > 0);

        client_stream.shutdown().await?;
        let mut forwarded = Vec::new();
        client_reader.read_to_end(&mut forwarded).await?;
        assert!(forwarded.starts_with(b"HTTP/1.1 100 Continue\r\n"));
        assert!(
            forwarded
                .windows(24)
                .any(|bytes| bytes == b"HTTP/1.1 103 Early Hints")
        );
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
                    .contains("informational response must not include body framing")
            ),
        }
        Ok(())
    }

    #[tokio::test]
    async fn read_final_response_head_rejects_forbidden_no_content_framing() -> anyhow::Result<()> {
        for response in [
            b"HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 No Content\r\nContent-Length: +0\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 No Content\r\nContent-Length: -0\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0, 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 No Content\r\nContent-Length: 18446744073709551616\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 No Content\r\nContent-Length: \r\n\r\n".as_slice(),
            b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: gzip\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
            b"HTTP/1.1 205 Reset Content\r\nContent-Length: 1\r\n\r\n".as_slice(),
            b"HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 103 Early Hints\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
        ] {
            let (mut upstream_writer, upstream_reader) = duplex(256);
            let (_client_reader, mut client_writer) = duplex(256);
            upstream_writer.write_all(response).await?;
            drop(upstream_writer);

            let mut upstream_reader = BufReader::new(upstream_reader);
            let peer: SocketAddr = "127.0.0.1:8080".parse()?;
            let result = read_final_response_head(
                &mut upstream_reader,
                &mut client_writer,
                &test_timeouts(Duration::from_secs(1)),
                peer,
                256,
            )
            .await;
            assert!(
                result.is_err(),
                "invalid response was accepted: {response:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn read_final_response_head_normalizes_zero_length_no_content() -> anyhow::Result<()> {
        for field in ["Content-Length: 0", "cOnTeNt-LeNgTh:\t000 \t"] {
            let (mut upstream_writer, upstream_reader) = duplex(512);
            let (mut client_writer, mut client_reader) = duplex(512);
            upstream_writer
                .write_all(format!("HTTP/1.1 204 No Content\r\n{field}\r\nETag: \"kept\"\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\npoison").as_bytes())
                .await?;
            // Keep the origin open: accepting 204 must not wait for EOF.
            let mut upstream_reader = BufReader::new(upstream_reader);
            let (head, informational_bytes) = read_final_response_head(
                &mut upstream_reader,
                &mut client_writer,
                &test_timeouts(Duration::from_secs(1)),
                "127.0.0.1:8080".parse()?,
                512,
            )
            .await?;
            assert_eq!(head.status, StatusCode::NO_CONTENT);
            assert_eq!(informational_bytes, 0);
            assert_eq!(head.content_length, None);
            assert!(head.connection_close);
            assert!(!head.header_map().contains_key(http::header::CONTENT_LENGTH));
            assert_eq!(head.header_map()[http::header::ETAG], "\"kept\"");
            assert_eq!(
                determine_response_body_plan(&Method::GET, head.status, &head),
                ResponseBodyPlan::Empty
            );
            let encoded = String::from_utf8(head.encode(ResponseBodyPlan::Empty, None))?;
            assert!(!encoded.to_ascii_lowercase().contains("content-length"));
            assert!(encoded.ends_with("\r\n\r\n"));
            client_writer.shutdown().await?;
            let mut forwarded = Vec::new();
            client_reader.read_to_end(&mut forwarded).await?;
            assert!(
                forwarded.is_empty(),
                "final head reader forwarded origin bytes"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn no_content_compatibility_preserves_other_bodyless_responses() -> anyhow::Result<()> {
        for (status, method, length) in [
            (204, Method::GET, None),
            (200, Method::HEAD, Some(123)),
            (304, Method::GET, Some(123)),
            (205, Method::GET, Some(0)),
            (205, Method::GET, None),
        ] {
            let (mut upstream_writer, upstream_reader) = duplex(256);
            let (_client_reader, mut client_writer) = duplex(256);
            let field = length.map_or_else(String::new, |n| format!("Content-Length: {n}\r\n"));
            upstream_writer
                .write_all(format!("HTTP/1.1 {status} Test\r\n{field}\r\n").as_bytes())
                .await?;
            let mut upstream_reader = BufReader::new(upstream_reader);
            let (head, _) = read_final_response_head(
                &mut upstream_reader,
                &mut client_writer,
                &test_timeouts(Duration::from_secs(1)),
                "127.0.0.1:8080".parse()?,
                256,
            )
            .await?;
            assert_eq!(head.status.as_u16(), status);
            assert_eq!(head.content_length, length);
            assert!(!head.connection_close);
            assert_eq!(
                determine_response_body_plan(&method, head.status, &head),
                ResponseBodyPlan::Empty
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn read_final_response_head_accepts_safe_reset_content_framing() -> anyhow::Result<()> {
        for response in [
            b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 205 Reset Content\r\n\r\n".as_slice(),
        ] {
            let (mut upstream_writer, upstream_reader) = duplex(256);
            let (_client_reader, mut client_writer) = duplex(256);
            upstream_writer.write_all(response).await?;
            drop(upstream_writer);

            let mut upstream_reader = BufReader::new(upstream_reader);
            let peer: SocketAddr = "127.0.0.1:8080".parse()?;
            let (head, _) = read_final_response_head(
                &mut upstream_reader,
                &mut client_writer,
                &test_timeouts(Duration::from_secs(1)),
                peer,
                256,
            )
            .await?;
            assert_eq!(head.status, StatusCode::RESET_CONTENT);
        }
        Ok(())
    }
}
