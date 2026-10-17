mod support;

use std::{net::Ipv4Addr, time::Duration};

use anyhow::{Context, Result};
use rustls::{RootCertStore, pki_types::ServerName};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use exfilguard::tls::ca::CertificateAuthority;
use support::*;

#[tokio::test]
async fn http_put_discards_closed_idle_upstream() -> Result<()> {
    idle_uploads(false, true).await
}

#[tokio::test]
async fn https_put_discards_closed_idle_upstream() -> Result<()> {
    idle_uploads(true, true).await
}

#[tokio::test]
async fn http_put_reuses_open_idle_upstream() -> Result<()> {
    idle_uploads(false, false).await
}

#[tokio::test]
async fn https_put_reuses_open_idle_upstream() -> Result<()> {
    idle_uploads(true, false).await
}

async fn idle_uploads(tls: bool, close_idle: bool) -> Result<()> {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let origin_dirs = TestDirs::new()?;
        let origin_ca = CertificateAuthority::load_builtin(&origin_dirs.ca_dir)?;
        let acceptor = TlsAcceptor::from(build_upstream_tls_config(&origin_ca, "localhost")?);
        let mut roots = RootCertStore::empty();
        roots.add(origin_ca.root_certificate_der())?;
        let scheme = if tls { "https" } else { "http" };
        let (clients, policies) = TestConfigBuilder::new()
            .default_client(&["uploads"])
            .policy(PolicySpec::new("uploads").rule(RuleSpec::allow(
                &["PUT"],
                format!("{scheme}://localhost:{port}/**"),
            )))
            .render();
        let harness = ProxyHarnessBuilder::new(&clients, &policies)?
            .with_proxy_root_store(roots)
            .spawn()
            .await?;

        let (closed_tx, mut closed_rx) = mpsc::channel(2);
        let origin = tokio::spawn(async move {
            let mut bodies = Vec::new();
            let mut used_connections = 0;
            while bodies.len() < 2 {
                let (stream, _) = listener.accept().await?;
                let requests = if close_idle { 1 } else { 2 };
                let uploads = if tls {
                    let stream = acceptor.accept(stream).await?;
                    serve_uploads(stream, requests).await?
                } else {
                    serve_uploads(stream, requests).await?
                };
                // CONNECT's TLS preflight can close without sending HTTP.
                if !uploads.is_empty() {
                    used_connections += 1;
                    bodies.extend(uploads);
                    closed_tx.send(()).await?;
                }
            }
            Ok::<_, anyhow::Error>((bodies, used_connections))
        });

        let stream = TcpStream::connect(harness.addr).await?;
        let bodies = if tls {
            let mut stream = stream;
            stream
                .write_all(
                    format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
                        .as_bytes(),
                )
                .await?;
            let response = read_until_double_crlf(&mut stream).await?;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            let mut roots = RootCertStore::empty();
            roots.add(harness.ca.root_certificate_der())?;
            let connector = TlsConnector::from(build_client_tls(roots)?);
            let stream = connector
                .connect(ServerName::try_from("localhost")?, stream)
                .await?;
            send_uploads(stream, scheme, port, close_idle, &mut closed_rx).await?
        } else {
            send_uploads(stream, scheme, port, close_idle, &mut closed_rx).await?
        };
        let (received, used_connections) = origin.await??;
        assert_eq!(received, bodies, "each upload must arrive exactly once");
        assert_eq!(used_connections, if close_idle { 2 } else { 1 });
        harness.shutdown().await;
        Ok(())
    })
    .await
    .context("idle upload test timed out")?
}

async fn serve_uploads<S>(mut stream: S, requests: usize) -> Result<Vec<Vec<u8>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut bodies = Vec::new();
    for _ in 0..requests {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read_u8().await {
                Ok(byte) => head.push(byte),
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof && head.is_empty() => {
                    return Ok(bodies);
                }
                Err(err) => return Err(err.into()),
            }
        }
        let head = String::from_utf8(head)?;
        assert!(head.starts_with("PUT "), "{head}");
        let length: usize = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .context("missing upload content length")?;
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await?;
        bodies.push(body);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
            .await?;
        stream.flush().await?;
    }
    stream.shutdown().await?;
    Ok(bodies)
}

async fn send_uploads<S>(
    mut stream: S,
    scheme: &str,
    port: u16,
    close_idle: bool,
    closed_rx: &mut mpsc::Receiver<()>,
) -> Result<Vec<Vec<u8>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bodies = vec![b"first snapshot".to_vec(), b"second snapshot".to_vec()];
    for (index, body) in bodies.iter().enumerate() {
        if index == 1 && close_idle {
            closed_rx.recv().await.context("origin did not close")?;
            // Let the loopback FIN/close_notify reach the proxy before checkout.
            sleep(Duration::from_millis(50)).await;
        }
        let connection = if index == 0 { "keep-alive" } else { "close" };
        stream.write_all(format!(
            "PUT {scheme}://localhost:{port}/snapshot/{index} HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
            body.len()
        ).as_bytes()).await?;
        stream.write_all(body).await?;
        stream.flush().await?;
        let response = read_http_response_with_length(&mut stream).await?;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "upload {index}: {response}"
        );
    }
    stream.shutdown().await?;
    Ok(bodies)
}
