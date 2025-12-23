use std::net::SocketAddr;

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::{read_http_response, read_until_double_crlf};

pub struct ProxyClient {
    stream: TcpStream,
}

impl ProxyClient {
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            stream: TcpStream::connect(addr).await?,
        })
    }

    pub async fn send(&mut self, request: impl AsRef<[u8]>) -> Result<()> {
        self.stream.write_all(request.as_ref()).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn read_response(&mut self) -> Result<String> {
        read_http_response(&mut self.stream).await
    }

    pub async fn read_headers(&mut self) -> Result<String> {
        read_until_double_crlf(&mut self.stream).await
    }

    pub async fn shutdown(mut self) {
        self.stream.shutdown().await.ok();
    }

    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }
}
