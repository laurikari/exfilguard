use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::read_until_double_crlf;

#[derive(Clone)]
enum UpstreamBehavior {
    Close,
    Echo,
    HttpResponse { response: Arc<Vec<u8>> },
}

pub struct TestUpstream {
    addr: SocketAddr,
    handle: JoinHandle<()>,
}

impl TestUpstream {
    pub async fn close() -> Result<Self> {
        Self::spawn(UpstreamBehavior::Close).await
    }

    pub async fn echo() -> Result<Self> {
        Self::spawn(UpstreamBehavior::Echo).await
    }

    pub async fn http_response(response: impl Into<Vec<u8>>) -> Result<Self> {
        Self::spawn(UpstreamBehavior::HttpResponse {
            response: Arc::new(response.into()),
        })
        .await
    }

    pub async fn http_ok(body: &str) -> Result<Self> {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        Self::http_response(response.into_bytes()).await
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    async fn spawn(behavior: UpstreamBehavior) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };
                let behavior = behavior.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(&mut stream, behavior).await;
                });
            }
        });
        Ok(Self { addr, handle })
    }
}

impl Drop for TestUpstream {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn handle_connection(stream: &mut TcpStream, behavior: UpstreamBehavior) -> Result<()> {
    match behavior {
        UpstreamBehavior::Close => {
            stream.shutdown().await.ok();
        }
        UpstreamBehavior::Echo => {
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        }
        UpstreamBehavior::HttpResponse { response } => {
            let _ = read_until_double_crlf(stream).await;
            let _ = stream.write_all(&response).await;
            stream.shutdown().await.ok();
        }
    }
    Ok(())
}
