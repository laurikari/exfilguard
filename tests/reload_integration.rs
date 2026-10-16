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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sighup_reloads_proxy_certificates_independently_of_policy() -> Result<()> {
    use exfilguard::settings::ProxyTlsSettings;
    use rustls::{RootCertStore, pki_types::ServerName};
    use std::{fs, os::unix::fs::PermissionsExt};
    use tokio_rustls::TlsConnector;
    let logs = LogCapture::new("info").await;
    let dirs = TestDirs::new()?;
    let first = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let second = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert = dirs.config_dir.join("proxy.pem");
    let key = dirs.config_dir.join("proxy.key");
    fs::write(&cert, first.cert.pem())?;
    fs::write(&key, first.signing_key.serialize_pem())?;
    fs::set_permissions(&cert, fs::Permissions::from_mode(0o644))?;
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
    let (clients, policies) = TestConfigBuilder::new()
        .default_client(&["deny"])
        .policy(PolicySpec::new("deny").rule(RuleSpec::deny(&["ANY"], "http://**/**").status(403)))
        .render();
    write_clients_and_policies(&dirs, &clients, &policies)?;
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, find_free_port()?));
    let mut settings = load_settings(&dirs, addr)?;
    settings.proxy_tls = Some(ProxyTlsSettings::Files {
        cert: cert.clone(),
        key: key.clone(),
    });
    let proxy = tokio::spawn(exfilguard::run_for_tests(settings));
    wait_for_listener(addr).await?;
    let mut roots = RootCertStore::empty();
    roots.add(first.cert.der().clone())?;
    roots.add(second.cert.der().clone())?;
    let connector = TlsConnector::from(build_client_tls(roots)?);
    let connect = || async {
        Ok::<_, anyhow::Error>(
            connector
                .connect(
                    ServerName::try_from("localhost")?,
                    TcpStream::connect(addr).await?,
                )
                .await?,
        )
    };
    let tls = connect().await?;
    assert_eq!(
        &tls.get_ref().1.peer_certificates().unwrap()[0],
        first.cert.der()
    );
    drop(tls);
    fs::write(&cert, second.cert.pem())?;
    fs::write(&key, second.signing_key.serialize_pem())?;
    fs::write(&dirs.policies_path, "invalid policy TOML")?;
    send_sighup()?;
    tokio::time::timeout(StdDuration::from_secs(3), async {
        loop {
            let tls = connect().await?;
            if &tls.get_ref().1.peer_certificates().unwrap()[0] == second.cert.der()
                && logs.text().contains("runtime policy reload failed")
            {
                break Ok::<_, anyhow::Error>(());
            }
            sleep(StdDuration::from_millis(5)).await;
        }
    })
    .await??;
    fs::write(&cert, "invalid certificate PEM")?;
    send_sighup()?;
    tokio::time::timeout(StdDuration::from_secs(3), async {
        while !logs.text().contains("proxy TLS certificate reload failed") {
            sleep(StdDuration::from_millis(5)).await;
        }
    })
    .await?;
    let tls = connect().await?;
    assert_eq!(
        &tls.get_ref().1.peer_certificates().unwrap()[0],
        second.cert.der()
    );
    proxy.abort();
    let _ = proxy.await;
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

fn write_main_config(dirs: &TestDirs, addr: SocketAddr) -> Result<()> {
    let config_path = dirs.config_dir.join("exfilguard.toml");
    let config = format!(
        "listen = \"{addr}\"\nca = {{ source = \"builtin\", dir = \"{}\" }}\nclients = \"clients.toml\"\npolicies = \"policies.toml\"\nlog = \"text\"\n",
        dirs.ca_dir.display()
    );
    std::fs::write(&config_path, config)?;
    Ok(())
}

fn load_settings(dirs: &TestDirs, addr: SocketAddr) -> Result<Settings> {
    write_main_config(dirs, addr)?;
    let config_path = dirs.config_dir.join("exfilguard.toml");
    let cli = Cli {
        config: Some(config_path),
    };
    Settings::load(&cli)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_on_sighup_updates_runtime_policy() -> Result<()> {
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
        .policy(PolicySpec::new("reload-policy").rule(RuleSpec::allow(
            &["GET"],
            format!("http://127.0.0.1:{upstream_port}/**"),
        )))
        .render()
        .1;

    let dirs = TestDirs::new()?;
    write_clients_and_policies(&dirs, &clients, &policies_deny)?;

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, find_free_port()?));
    let settings = load_settings(&dirs, addr)?;

    let run_task = tokio::spawn(async move {
        if let Err(err) = exfilguard::run_for_tests(settings).await {
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
        logs.contains("runtime policy reloaded"),
        "expected reload log entry, got: {logs}"
    );

    run_task.abort();
    let _ = run_task.await;
    upstream_task.abort();
    let _ = upstream_task.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_on_sighup_does_not_rebind_listener() -> Result<()> {
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
        .policy(PolicySpec::new("reload-policy").rule(RuleSpec::allow(
            &["GET"],
            format!("http://127.0.0.1:{upstream_port}/**"),
        )))
        .render()
        .1;

    let dirs = TestDirs::new()?;
    write_clients_and_policies(&dirs, &clients, &policies_deny)?;

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, find_free_port()?));
    let new_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, find_free_port()?));
    let settings = load_settings(&dirs, addr)?;

    let run_task = tokio::spawn(async move {
        if let Err(err) = exfilguard::run_for_tests(settings).await {
            tracing::error!(error = ?err, "proxy run failed");
        }
    });

    wait_for_listener(addr).await?;

    let status = send_proxy_request(addr, upstream_port).await?;
    assert_eq!(status, 403, "expected initial deny before reload");

    write_main_config(&dirs, new_addr)?;
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
                "expected allow after reload on original listener; last status was {status}"
            ));
        }
        sleep(StdDuration::from_millis(50)).await;
    }

    let new_listener = TcpStream::connect(new_addr).await;
    assert!(
        new_listener.is_err(),
        "listener should not rebind on SIGHUP to startup-only address {new_addr}"
    );

    run_task.abort();
    let _ = run_task.await;
    upstream_task.abort();
    let _ = upstream_task.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_on_sighup_updates_clients() -> Result<()> {
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_port = upstream_listener.local_addr()?.port();
    let upstream_task = tokio::spawn(run_upstream(upstream_listener));

    let (clients_deny, policies) = TestConfigBuilder::new()
        .client_ip("loopback", "127.0.0.1", &["deny-policy"])
        .default_client(&["allow-policy"])
        .policy(PolicySpec::new("deny-policy").rule(
            RuleSpec::deny(&["GET"], format!("http://127.0.0.1:{upstream_port}/**")).status(403),
        ))
        .policy(PolicySpec::new("allow-policy").rule(RuleSpec::allow(
            &["GET"],
            format!("http://127.0.0.1:{upstream_port}/**"),
        )))
        .render();

    let clients_allow = TestConfigBuilder::new()
        .client_ip("loopback", "127.0.0.1", &["allow-policy"])
        .default_client(&["allow-policy"])
        .render()
        .0;

    let dirs = TestDirs::new()?;
    write_clients_and_policies(&dirs, &clients_deny, &policies)?;

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, find_free_port()?));
    let settings = load_settings(&dirs, addr)?;

    let run_task = tokio::spawn(async move {
        if let Err(err) = exfilguard::run_for_tests(settings).await {
            tracing::error!(error = ?err, "proxy run failed");
        }
    });

    wait_for_listener(addr).await?;

    let status = send_proxy_request(addr, upstream_port).await?;
    assert_eq!(status, 403, "expected initial deny before client reload");

    std::fs::write(&dirs.clients_path, clients_allow)?;
    send_sighup()?;

    let deadline = Instant::now() + StdDuration::from_secs(3);
    loop {
        let status = send_proxy_request(addr, upstream_port).await?;
        if status == 200 {
            break;
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "expected allow after client reload; last status was {status}"
            ));
        }
        sleep(StdDuration::from_millis(50)).await;
    }

    run_task.abort();
    let _ = run_task.await;
    upstream_task.abort();
    let _ = upstream_task.await;

    Ok(())
}
