#![cfg(unix)]

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration as StdDuration, Instant};

use anyhow::{Context, Result, anyhow};
use nix::sys::signal::{self, Signal};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

use exfilguard::cli::Cli;
use exfilguard::settings::Settings;
use support::*;

const OK_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";

fn send_sighup() -> Result<()> {
    signal::raise(Signal::SIGHUP).context("failed to raise SIGHUP")?;
    Ok(())
}

async fn send_proxy_request(addr: SocketAddr, upstream_port: u16) -> Result<u16> {
    let mut stream = TcpStream::connect(addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/resource HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut reader = BufReader::new(stream);
    read_response_status(&mut reader).await
}

async fn run_upstream(listener: TcpListener) -> Result<()> {
    loop {
        let (mut socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            let _ = read_until_double_crlf(&mut socket).await;
            let _ = socket.write_all(OK_RESPONSE).await;
            let _ = socket.shutdown().await;
        });
    }
}

fn load_settings(dirs: &TestDirs, addr: SocketAddr) -> Result<Settings> {
    let config_path = dirs.config_dir.join("exfilguard.toml");
    let config = format!(
        "listen = \"{addr}\"\n\nca_dir = \"{}\"\nclients = \"clients.toml\"\npolicies = \"policies.toml\"\nlog = \"text\"\n",
        dirs.ca_dir.display()
    );
    std::fs::write(&config_path, config)?;
    let cli = Cli {
        config: Some(config_path),
    };
    Settings::load(&cli)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_on_sighup_updates_policy() -> Result<()> {
    let log_capture = LogCapture::new("info").await;

    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_port = upstream_listener.local_addr()?.port();
    let upstream_task = tokio::spawn(run_upstream(upstream_listener));

    let (clients, policies_deny) = TestConfigBuilder::new()
        .default_client(&["reload-policy"])
        .policy(PolicySpec::new("reload-policy").rule(
            RuleSpec::deny(&["GET"], format!("http://127.0.0.1:{upstream_port}/**")).status(403),
        ))
        .render();

    let policies_allow = TestConfigBuilder::new()
        .policy(
            PolicySpec::new("reload-policy").rule(
                RuleSpec::allow(&["GET"], format!("http://127.0.0.1:{upstream_port}/**"))
                    .allow_private_upstream(true),
            ),
        )
        .render()
        .1;

    let dirs = TestDirs::new()?;
    write_clients_and_policies(&dirs, &clients, &policies_deny)?;

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, find_free_port()?));
    let settings = load_settings(&dirs, addr)?;

    let run_task = tokio::spawn(async move {
        if let Err(err) = exfilguard::run(settings).await {
            tracing::error!(error = ?err, "proxy run failed");
        }
    });

    wait_for_listener(addr).await?;

    let status = send_proxy_request(addr, upstream_port).await?;
    assert_eq!(status, 403, "expected initial deny before reload");

    std::fs::write(&dirs.policies_path, policies_allow)?;
    send_sighup()?;

    let deadline = Instant::now() + StdDuration::from_secs(3);
    loop {
        let status = send_proxy_request(addr, upstream_port).await?;
        if status == 200 {
            break;
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "expected allow after reload; last status was {status}"
            ));
        }
        sleep(StdDuration::from_millis(50)).await;
    }
    let logs = log_capture.text();
    assert!(
        logs.contains("configuration reloaded"),
        "expected reload log entry, got: {logs}"
    );

    run_task.abort();
    let _ = run_task.await;
    upstream_task.abort();
    let _ = upstream_task.await;

    Ok(())
}
