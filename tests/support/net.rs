use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration as StdDuration;

use anyhow::{Result, anyhow};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

pub fn find_free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

pub async fn wait_for_listener(addr: SocketAddr) -> Result<()> {
    for _ in 0..50 {
        match timeout(StdDuration::from_millis(50), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                stream.shutdown().await.ok();
                return Ok(());
            }
            _ => sleep(StdDuration::from_millis(50)).await,
        }
    }
    Err(anyhow!("listener {addr} did not become ready"))
}
