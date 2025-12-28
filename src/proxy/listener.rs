use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

use super::{AppContext, http};

pub async fn start_listener(app: AppContext) -> Result<()> {
    let bind_addr = app.settings.listen;
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind listener on {}", bind_addr))?;
    let local_addr = listener.local_addr().unwrap_or(bind_addr);
    info!(address = %local_addr, "proxy listener started");

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                error!(error = %err, "failed to accept incoming connection");
                continue;
            }
        };
        debug!(peer = %peer_addr, "accepted connection");
        if let Err(err) = stream.set_nodelay(true) {
            debug!(peer = %peer_addr, error = %err, "failed to set TCP_NODELAY on downstream stream");
        }
        let connection_app = app.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, peer_addr, connection_app).await {
                debug!(peer = %peer_addr, error = %err, "connection closed with error");
            }
        });
    }
}

async fn handle_connection(stream: TcpStream, peer: SocketAddr, app: AppContext) -> Result<()> {
    http::handle_http(stream, peer, app).await
}
