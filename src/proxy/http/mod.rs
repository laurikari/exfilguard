mod body;
mod codec;
mod dispatch;
mod forward;
mod pipeline;
mod server;
pub mod upstream;

pub use body::BodyTooLarge;
pub(crate) use codec::{Http1HeaderAccumulator, Http1ResponseHead};
pub use pipeline::{respond_with_access_log, send_response, shutdown_stream};
pub use server::{handle_decrypted_https, handle_http};

#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    use std::net::SocketAddr;
    use std::time::Duration;

    use anyhow::Result;
    use tokio::io::{AsyncRead, BufReader};

    pub use super::body::stream_chunked_body;

    pub async fn parse_http1_request_head<S>(
        reader: &mut BufReader<S>,
        peer: SocketAddr,
        timeout: Duration,
        max_header_bytes: usize,
    ) -> Result<()>
    where
        S: AsyncRead + Unpin,
    {
        if let Some(head) =
            super::codec::read_http1_request_head(reader, peer, timeout, timeout, max_header_bytes)
                .await?
        {
            let host = head.headers.host();
            let _ = crate::proxy::request::parse_http1_request(
                head.method.clone(),
                &head.target,
                host,
                crate::config::Scheme::Http,
            );
            let _ = head.headers.expect_continue();
            let _ = head.headers.content_length();
        }
        Ok(())
    }

    pub async fn parse_http1_response_head<S>(
        reader: &mut BufReader<S>,
        timeout: Duration,
        peer: SocketAddr,
        max_header_bytes: usize,
    ) -> Result<()>
    where
        S: AsyncRead + Unpin,
    {
        let _ =
            super::codec::read_http1_response_head(reader, timeout, peer, max_header_bytes).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::proxy::request::parse_http1_request;
    use http::Method;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Duration;
    use tokio::io::BufReader;

    use super::body::{BodyPlan, BodyTooLarge, stream_chunked_body};
    use super::codec::{Http1HeaderAccumulator, read_http1_request_head};
    use super::forward::build_upstream_request;
    use crate::config::Scheme;

    #[tokio::test]
    async fn stream_chunked_body_errors_when_over_limit() {
        use tokio::io::{AsyncWriteExt, duplex};

        let (client_stream, mut client_writer) = duplex(1024);
        let (_upstream_stream, mut upstream_sink) = duplex(1024);

        client_writer
            .write_all(b"5\r\nhello\r\n0\r\n\r\n")
            .await
            .unwrap();
        drop(client_writer);

        let mut reader = BufReader::new(client_stream);
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443));
        let err = stream_chunked_body(
            &mut reader,
            &mut upstream_sink,
            Duration::from_secs(1),
            Duration::from_secs(1),
            None,
            peer,
            2,
        )
        .await
        .expect_err("expected body size limit error");
        assert!(err.downcast::<BodyTooLarge>().is_ok());
    }

    #[tokio::test]
    async fn read_request_head_parses_basic_request() -> anyhow::Result<()> {
        use tokio::io::{AsyncWriteExt, duplex};

        let (client_stream, mut writer) = duplex(1024);
        writer
            .write_all(b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await?;
        drop(writer);

        let mut reader = BufReader::new(client_stream);
        let head = read_http1_request_head(
            &mut reader,
            "127.0.0.1:12345".parse().unwrap(),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1024,
        )
        .await?
        .expect("expected request head");
        assert_eq!(head.method, Method::GET);
        assert_eq!(head.target, "http://example.com/path");
        assert_eq!(head.headers.host(), Some("example.com"));
        Ok(())
    }

    #[tokio::test]
    async fn read_request_head_rejects_long_request_line() -> anyhow::Result<()> {
        use tokio::io::{AsyncWriteExt, duplex};

        let (client_stream, mut writer) = duplex(4096);
        let long_path = "a".repeat(2048);
        let request =
            format!("GET http://example.com/{long_path} HTTP/1.1\r\nHost: example.com\r\n\r\n");
        writer.write_all(request.as_bytes()).await?;
        drop(writer);

        let mut reader = BufReader::new(client_stream);
        let result = read_http1_request_head(
            &mut reader,
            "127.0.0.1:12345".parse().unwrap(),
            Duration::from_secs(1),
            Duration::from_secs(1),
            512,
        )
        .await;
        let err = match result {
            Ok(_) => panic!("request line should exceed limit"),
            Err(err) => err,
        };
        let message = format!("{err}");
        assert!(
            message.contains("request line exceeds"),
            "unexpected error message: {message}"
        );
        Ok(())
    }

    #[test]
    fn parse_request_handles_ipv6_host() -> anyhow::Result<()> {
        let method = Method::GET;
        let target = "http://[2001:db8::10]/resource";
        let parsed = parse_http1_request(method, target, None, Scheme::Http)?;
        assert_eq!(parsed.host, "2001:db8::10");
        assert_eq!(parsed.scheme, Scheme::Http);
        assert_eq!(parsed.port, Some(80));
        assert_eq!(parsed.path, "/resource");
        Ok(())
    }

    #[test]
    fn build_upstream_request_formats_ipv6_host_header() -> anyhow::Result<()> {
        let method = Method::GET;
        let target = "http://[fd00:1234::1]:8080/data";
        let parsed = parse_http1_request(method, target, None, Scheme::Http)?;
        let headers = Http1HeaderAccumulator::new(2048);
        let request_bytes =
            build_upstream_request(&parsed, &headers, false, &BodyPlan::Empty, false);
        let request_text = String::from_utf8(request_bytes)?;
        assert!(request_text.contains("Host: [fd00:1234::1]:8080"));
        assert!(request_text.starts_with("GET /data HTTP/1.1"));
        Ok(())
    }

    #[test]
    fn build_upstream_request_strips_expect_continue() -> anyhow::Result<()> {
        let method = Method::POST;
        let target = "http://example.com/upload";
        let parsed = parse_http1_request(method, target, None, Scheme::Http)?;
        let mut headers = Http1HeaderAccumulator::new(2048);
        headers.push_line("Expect: 100-continue\r\n")?;
        headers.push_line("\r\n")?;

        let request_bytes =
            build_upstream_request(&parsed, &headers, false, &BodyPlan::Fixed(1), true);
        let request_text = String::from_utf8(request_bytes)?;
        assert!(!request_text.contains("Expect:"));
        Ok(())
    }
}
pub mod cache_control;
