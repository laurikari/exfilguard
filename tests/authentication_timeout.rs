mod support;

use std::time::Duration;

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{sleep, timeout},
};

const HASH: &str = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";

fn metric(name: &str) -> Option<f64> {
    String::from_utf8(exfilguard::metrics::gather())
        .unwrap()
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(' ')?;
            (key == name).then(|| value.parse().unwrap())
        })
}

#[test]
fn password_verification_precedes_the_request_budget() -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()?
        .block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let origin = listener.local_addr()?;
            let upstream = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                read_until_double_crlf(&mut stream).await?;
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await?;
                read_until_double_crlf(&mut stream).await?;
                // Leave the response pending until the proxy closes the timed-out request.
                stream.read_to_end(&mut Vec::new()).await?;
                Ok::<_, anyhow::Error>(())
            });
            let (mut clients, policies) = TestConfigBuilder::new()
                .fallback_client("node", &["deny"])
                .policy(PolicySpec::new("deny").rule(RuleSpec::deny(&["ANY"], "http://**/**").status(403)))
                .policy(PolicySpec::new("allow").rule(RuleSpec::allow(
                    &["GET"],
                    format!("http://{origin}/**"),
                )))
                .render();
            clients.push_str(&format!(
                "\n[[client]]\nname='worker'\nip='127.0.0.1'\npassword_hash='{HASH}'\npolicies=['allow']\n"
            ));
            let harness = ProxyHarnessBuilder::new(&clients, &policies)?
                .with_tls_proxy()
                .with_settings(|settings| settings.request_total_timeout = 1)
                .spawn()
                .await?;
            let mut stream = harness.connect_tls().await?;

            // Hold the blocking worker so authentication takes longer than the request budget,
            // independent of password hash speed. Dropping release_tx also releases the worker.
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                let _ = started_tx.send(());
                release_rx.recv_timeout(Duration::from_secs(10))
            });
            started_rx.await?;
            let credentials = STANDARD.encode("worker:correctbatteryhorsestapler");
            let request = format!(
                "GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\nProxy-Authorization: Basic {credentials}\r\n\r\n"
            );
            stream.write_all(request.as_bytes()).await?;
            timeout(Duration::from_secs(3), async {
                while metric("client_password_verifications_in_flight") != Some(1.0) {
                    sleep(Duration::from_millis(5)).await;
                }
            })
            .await?;
            sleep(Duration::from_millis(1100)).await;
            release_tx.send(())?;
            blocker.await??;
            let response = timeout(
                Duration::from_secs(3),
                read_http_response_with_length(&mut stream),
            )
            .await??;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert_eq!(metric("client_password_verifications_in_flight"), Some(0.0));
            assert_eq!(metric("client_password_verification_duration_seconds_count"), Some(1.0));
            assert!(metric("client_password_verification_duration_seconds_sum").unwrap() >= 1.1);

            // Repeating credentials reuses the identity; upstream work still has a deadline.
            stream.write_all(request.as_bytes()).await?;
            let response = timeout(
                Duration::from_secs(3),
                read_http_response_with_length(&mut stream),
            )
            .await??;
            assert!(response.starts_with("HTTP/1.1 504"), "{response}");
            assert_eq!(metric("client_password_verification_duration_seconds_count"), Some(1.0));
            timeout(Duration::from_secs(3), upstream).await???;
            harness.shutdown().await;
            Ok(())
        })
}
