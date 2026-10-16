//! Client, upstream server, and proxy for local HTTP/2 benchmarks.
use std::{
    future::poll_fn,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use clap::{Parser, Subcommand, ValueEnum};
use nix::time::{ClockId, clock_gettime};
use rustls::{RootCertStore, pki_types::ServerName};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[path = "../../tests/support/mod.rs"]
mod support;

const CHUNK: usize = 16 * 1024;
const ENDPOINT_WINDOW: u32 = 128 * 1024 * 1024;
const BODY_SIZE: u64 = 1 << 40;
const ORIGIN_HOST: &str = "origin.perf.test";

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "/data/ca")]
    ca: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init,
    Proxy {
        #[arg(long, default_value = "0.0.0.0:3128")]
        listen: SocketAddr,
        #[arg(long)]
        stream_window: Option<u32>,
        #[arg(long)]
        connection_window: Option<u32>,
    },
    Origin {
        #[arg(long, default_value = "0.0.0.0:8443")]
        listen: SocketAddr,
        #[arg(long, default_value_t = ENDPOINT_WINDOW, value_parser = clap::value_parser!(u32).range(65_535..=2_147_483_647))]
        receive_window: u32,
    },
    Stats,
    Probe {
        #[arg(long, default_value = "10.221.2.2:8082")]
        target: SocketAddr,
    },
    Client {
        #[arg(long, default_value = "10.221.2.2:8443")]
        target: SocketAddr,
        #[arg(long)]
        proxy: Option<SocketAddr>,
        #[arg(long, value_enum, default_value = "h2")]
        protocol: Protocol,
        #[arg(long)]
        upload: bool,
        #[arg(long, default_value_t = 1)]
        streams: usize,
        #[arg(long, default_value_t = 1)]
        sessions: usize,
        #[arg(long, default_value_t = 2)]
        warmup: u64,
        #[arg(long, default_value_t = 5)]
        seconds: u64,
        /// Measure completion and first-byte times for a fixed-size transfer.
        #[arg(long)]
        bytes: Option<u64>,
        #[arg(long, default_value_t = 0)]
        read_delay_ms: u64,
        /// Pause the first stream of each session, then resume it.
        #[arg(long, default_value_t = 0)]
        pause_ms: u64,
        #[arg(long, default_value_t = ENDPOINT_WINDOW, value_parser = clap::value_parser!(u32).range(65_535..=2_147_483_647))]
        receive_window: u32,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Protocol {
    H1,
    H2,
}

#[derive(Clone)]
struct Transfer {
    target: SocketAddr,
    proxy: Option<SocketAddr>,
    upload: bool,
    size: u64,
    start_ns: u64,
    end_ns: u64,
    read_delay_ms: u64,
    pause_ms: u64,
    pause_deadline_ns: u64,
}

#[derive(Default)]
struct Stats {
    bytes: AtomicU64,
    errors: AtomicU64,
    first_ns: AtomicU64,
    streams: Mutex<Vec<Arc<StreamProgress>>>,
}

#[derive(Default)]
struct StreamProgress {
    bytes: AtomicU64,
    first_ns: AtomicU64,
    last_during_pause_ns: AtomicU64,
}

impl Stats {
    fn stream_progress(&self) -> Vec<serde_json::Value> {
        self.streams
            .lock()
            .unwrap()
            .iter()
            .map(|stream| {
                json!({
                    "bytes": stream.bytes.load(Ordering::Relaxed),
                    "first_ns": stream.first_ns.load(Ordering::Relaxed),
                    "last_during_pause_ns": stream.last_during_pause_ns.load(Ordering::Relaxed),
                })
            })
            .collect()
    }
}

fn now_ns() -> u64 {
    // All endpoint containers share this clock with Tokio's deadline clock.
    let time = clock_gettime(ClockId::CLOCK_MONOTONIC).expect("monotonic clock");
    time.tv_sec() as u64 * 1_000_000_000 + time.tv_nsec() as u64
}

async fn probe(target: SocketAddr) -> Result<Vec<Option<f64>>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(target).await?;
    let mut samples = Vec::new();
    for sequence in 0u64..10 {
        let payload = sequence.to_be_bytes();
        let started = tokio::time::Instant::now();
        socket.send(&payload).await?;
        let reply = tokio::time::timeout(Duration::from_secs(2), async {
            let mut response = [0; 64];
            loop {
                let len = socket.recv(&mut response).await?;
                if response[..len] == payload {
                    return Ok::<_, std::io::Error>(started.elapsed().as_secs_f64() * 1000.0);
                }
            }
        })
        .await;
        samples.push(match reply {
            Ok(sample) => Some(sample?),
            Err(_) => None,
        });
        tokio::time::sleep(Duration::from_millis(137)).await;
    }
    Ok(samples)
}

async fn serve_probe(socket: UdpSocket) -> std::io::Result<()> {
    let mut payload = [0; 64];
    loop {
        let (len, peer) = socket.recv_from(&mut payload).await?;
        socket.send_to(&payload[..len], peer).await?;
    }
}

fn record(stats: &Stats, transfer: &Transfer, data: &[u8]) -> Result<u64> {
    ensure!(data.iter().all(|byte| *byte == b'x'), "corrupt payload");
    let now = now_ns();
    let _ = stats
        .first_ns
        .compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed);
    if now >= transfer.start_ns && now < transfer.end_ns {
        stats.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
    }
    Ok(now)
}

async fn pace(transfer: &Transfer, first: &mut bool) {
    if *first {
        *first = false;
        tokio::time::sleep(Duration::from_millis(transfer.pause_ms)).await;
    }
    if transfer.read_delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(transfer.read_delay_ms)).await;
    }
}

fn roots(ca: &exfilguard::tls::ca::CertificateAuthority) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(ca.root_certificate_der()).unwrap();
    roots
}

async fn head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<String> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        ensure!(bytes.len() < 32768, "oversized HTTP head");
        bytes.push(stream.read_u8().await?);
    }
    Ok(String::from_utf8(bytes)?)
}

async fn connect(
    transfer: &Transfer,
    tls: Arc<rustls::ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut tcp = TcpStream::connect(transfer.proxy.unwrap_or(transfer.target)).await?;
    tcp.set_nodelay(true)?;
    if transfer.proxy.is_some() {
        let authority = format!("{ORIGIN_HOST}:{}", transfer.target.port());
        tcp.write_all(
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
        )
        .await?;
        let response = head(&mut tcp).await?;
        ensure!(
            response.starts_with("HTTP/1.1 200 "),
            "CONNECT failed: {response}"
        );
    }
    Ok(TlsConnector::from(tls)
        .connect(ServerName::try_from(ORIGIN_HOST)?, tcp)
        .await?)
}

async fn send_body(mut stream: h2::SendStream<Bytes>, size: u64) -> Result<()> {
    let chunk = Bytes::from(vec![b'x'; CHUNK]);
    let mut remaining = size;
    while remaining > 0 {
        stream.reserve_capacity(CHUNK.min(remaining as usize));
        let capacity = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .context("send stream closed")??;
        if capacity == 0 {
            continue;
        }
        let len = capacity.min(CHUNK).min(remaining as usize);
        remaining -= len as u64;
        stream.send_data(chunk.slice(..len), remaining == 0)?;
    }
    Ok(())
}

async fn receive_body(mut body: h2::RecvStream, transfer: &Transfer, stats: &Stats) -> Result<()> {
    let mut first = true;
    let mut total = 0;
    let progress = Arc::new(StreamProgress::default());
    stats.streams.lock().unwrap().push(progress.clone());
    while let Some(data) = body.data().await {
        let data = data?;
        pace(transfer, &mut first).await;
        let now = record(stats, transfer, &data)?;
        if total == 0 {
            progress.first_ns.store(now, Ordering::Relaxed);
        }
        if now < transfer.pause_deadline_ns {
            progress.last_during_pause_ns.store(now, Ordering::Relaxed);
        }
        total += data.len() as u64;
        progress.bytes.store(total, Ordering::Relaxed);
        body.flow_control().release_capacity(data.len())?;
    }
    ensure!(
        total == transfer.size,
        "incomplete body: {total}/{}",
        transfer.size
    );
    Ok(())
}

fn request_transfer(headers: &http::HeaderMap, size: u64) -> Result<Transfer> {
    let number = |name| -> Result<u64> {
        Ok(headers
            .get(name)
            .context("missing benchmark header")?
            .to_str()?
            .parse()?)
    };
    Ok(Transfer {
        target: "127.0.0.1:8443".parse()?,
        proxy: None,
        upload: true,
        size,
        start_ns: number("x-bench-start")?,
        end_ns: number("x-bench-end")?,
        read_delay_ms: number("x-bench-delay")?,
        pause_ms: number("x-bench-pause")?,
        pause_deadline_ns: number("x-bench-pause-deadline")?,
    })
}

async fn origin_connection(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    stats: Arc<Stats>,
    receive_window: u32,
) -> Result<()> {
    if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
        let mut builder = h2::server::Builder::new();
        builder
            .initial_window_size(receive_window)
            .initial_connection_window_size(ENDPOINT_WINDOW * 2);
        let mut conn = builder.handshake(tls).await?;
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                request = conn.accept() => {
                    let Some(request) = request else { break; };
                    let (request, mut respond) = request?;
                    let stats = stats.clone();
                    tasks.spawn(async move {
                        let size: u64 = request.uri().path().trim_start_matches('/').parse()?;
                        let upload = request.method() == http::Method::POST;
                        if upload {
                            let transfer = request_transfer(request.headers(), size)?;
                            receive_body(request.into_body(), &transfer, &stats).await?;
                        }
                        let response = http::Response::builder().header("content-length", if upload { 0 } else { size }).body(())?;
                        let body = respond.send_response(response, upload)?;
                        if !upload { send_body(body, size).await?; }
                        Ok::<_, anyhow::Error>(())
                    });
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(result) = result { result??; }
                }
            }
        }
    } else {
        let mut tls = tls;
        let request = head(&mut tls).await?;
        let size: u64 = request
            .split_whitespace()
            .nth(1)
            .context("missing path")?
            .trim_start_matches('/')
            .parse()?;
        let upload = request.starts_with("POST ");
        if upload {
            let mut headers = http::HeaderMap::new();
            for line in request
                .split("\r\n")
                .skip(1)
                .filter(|line| !line.is_empty())
            {
                let (name, value) = line.split_once(':').context("bad header")?;
                headers.insert(
                    http::header::HeaderName::from_bytes(name.as_bytes())?,
                    value.trim().parse()?,
                );
            }
            let transfer = request_transfer(&headers, size)?;
            let mut remaining = size;
            let mut buf = vec![0; CHUNK];
            let mut first = true;
            while remaining > 0 {
                let len = CHUNK.min(remaining as usize);
                let n = tls.read(&mut buf[..len]).await?;
                ensure!(n != 0, "truncated upload");
                pace(&transfer, &mut first).await;
                record(&stats, &transfer, &buf[..n])?;
                remaining -= n as u64;
            }
        }
        tls.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                if upload { 0 } else { size }
            )
            .as_bytes(),
        )
        .await?;
        if !upload {
            let buf = vec![b'x'; CHUNK];
            let mut remaining = size;
            while remaining > 0 {
                let len = CHUNK.min(remaining as usize);
                tls.write_all(&buf[..len]).await?;
                remaining -= len as u64;
            }
        }
        tls.flush().await?;
    }
    Ok(())
}

fn extra_headers(transfer: &Transfer) -> String {
    format!(
        "X-Bench-Start: {}\r\nX-Bench-End: {}\r\nX-Bench-Delay: {}\r\nX-Bench-Pause: {}\r\nX-Bench-Pause-Deadline: {}\r\n",
        transfer.start_ns,
        transfer.end_ns,
        transfer.read_delay_ms,
        transfer.pause_ms,
        transfer.pause_deadline_ns
    )
}

async fn client_h1(
    transfer: Transfer,
    tls: Arc<rustls::ClientConfig>,
    stats: Arc<Stats>,
) -> Result<()> {
    let mut conn = connect(&transfer, tls).await?;
    let method = if transfer.upload { "POST" } else { "GET" };
    conn.write_all(format!("{method} /{} HTTP/1.1\r\nHost: {ORIGIN_HOST}:{}\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n", transfer.size, transfer.target.port(), if transfer.upload { transfer.size } else { 0 }, extra_headers(&transfer)).as_bytes()).await?;
    if transfer.upload {
        let chunk = vec![b'x'; CHUNK];
        let mut remaining = transfer.size;
        while remaining > 0 {
            let len = CHUNK.min(remaining as usize);
            conn.write_all(&chunk[..len]).await?;
            remaining -= len as u64;
        }
        conn.flush().await?;
    }
    ensure!(
        head(&mut conn).await?.starts_with("HTTP/1.1 200 "),
        "HTTP/1 origin failed"
    );
    if !transfer.upload {
        let mut buf = vec![0; CHUNK];
        let mut first = true;
        let mut remaining = transfer.size;
        while remaining > 0 {
            let len = CHUNK.min(remaining as usize);
            let n = conn.read(&mut buf[..len]).await?;
            ensure!(n != 0, "truncated download");
            pace(&transfer, &mut first).await;
            record(&stats, &transfer, &buf[..n])?;
            remaining -= n as u64;
        }
    }
    Ok(())
}

async fn client_h2(
    transfer: Transfer,
    tls: Arc<rustls::ClientConfig>,
    stats: Arc<Stats>,
    streams: usize,
    receive_window: u32,
) -> Result<()> {
    let conn = connect(&transfer, tls).await?;
    ensure!(
        conn.get_ref().1.alpn_protocol() == Some(b"h2"),
        "HTTP/2 not negotiated"
    );
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(receive_window)
        .initial_connection_window_size(ENDPOINT_WINDOW * 2);
    let (sender, connection) = builder.handshake(conn).await?;
    let driver = tokio::spawn(connection);
    let _driver_guard = AbortOnDrop(driver.abort_handle());
    let mut tasks = JoinSet::new();
    for index in 0..streams {
        let sender = sender.clone();
        let stats = stats.clone();
        let mut transfer = transfer.clone();
        if index > 0 {
            transfer.pause_ms = 0;
        }
        tasks.spawn(async move {
            let mut sender = sender.ready().await?;
            let request = http::Request::builder()
                .method(if transfer.upload { "POST" } else { "GET" })
                .uri(format!(
                    "https://{ORIGIN_HOST}:{}/{}",
                    transfer.target.port(),
                    transfer.size
                ))
                .header(
                    "content-length",
                    if transfer.upload { transfer.size } else { 0 },
                )
                .header("x-bench-start", transfer.start_ns)
                .header("x-bench-end", transfer.end_ns)
                .header("x-bench-delay", transfer.read_delay_ms)
                .header("x-bench-pause", transfer.pause_ms)
                .header("x-bench-pause-deadline", transfer.pause_deadline_ns)
                .body(())?;
            let (response, send) = sender.send_request(request, !transfer.upload)?;
            if transfer.upload {
                send_body(send, transfer.size).await?;
            }
            let response = response.await?;
            ensure!(
                response.status() == 200,
                "HTTP/2 origin failed: {}",
                response.status()
            );
            if !transfer.upload {
                receive_body(response.into_body(), &transfer, &stats).await?;
            }
            Ok::<_, anyhow::Error>(())
        });
    }
    while let Some(result) = tasks.join_next().await {
        result??;
    }
    Ok(())
}

struct AbortOnDrop(tokio::task::AbortHandle);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::main(worker_threads = 4)]
async fn main() -> Result<()> {
    let args = Args::parse();
    if let Command::Probe { target } = &args.command {
        println!("{}", json!({"rtt_ms": probe(*target).await?}));
        return Ok(());
    }
    if matches!(args.command, Command::Stats) {
        let mut socket = TcpStream::connect("127.0.0.1:8081").await?;
        let mut result = String::new();
        socket.read_to_string(&mut result).await?;
        print!("{result}");
        return Ok(());
    }
    let ca = exfilguard::tls::ca::CertificateAuthority::load_builtin(&args.ca)?;
    match args.command {
        Command::Init => println!("{}", args.ca.display()),
        Command::Stats | Command::Probe { .. } => unreachable!(),
        Command::Proxy {
            listen,
            stream_window,
            connection_window,
        } => {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_max_level(tracing::Level::INFO)
                .init();
            let mut settings: exfilguard::settings::Settings = toml::from_str(
                "listen='127.0.0.1:3128'\nclients='clients.toml'\npolicies='policies.toml'\nca={source='builtin',dir='ca'}",
            )?;
            if let Some(value) = stream_window {
                settings.http2_stream_window_size = value;
            }
            if let Some(value) = connection_window {
                settings.http2_connection_window_size = value;
            }
            settings.validate()?;
            let mut dirs = support::TestDirs::new()?;
            dirs.ca_dir = args.ca;
            let (clients, policies) = support::TestConfigBuilder::new()
                .default_client(&["perf"])
                .policy(
                    support::PolicySpec::new("perf").rule(support::RuleSpec::allow(
                        &["GET", "POST"],
                        "https://origin.perf.test:8443/**",
                    )),
                )
                .render();
            let _proxy = support::ProxyHarnessBuilder::with_dirs(dirs, &clients, &policies)
                .with_proxy_root_store(roots(&ca))
                .with_settings(move |target| {
                    target.listen = listen;
                    target.http2_stream_window_size = settings.http2_stream_window_size;
                    target.http2_connection_window_size = settings.http2_connection_window_size;
                    target.client_keepalive_idle_timeout = 120;
                    target.request_body_idle_timeout = 120;
                    target.response_body_idle_timeout = 120;
                })
                .spawn()
                .await?;
            std::future::pending::<()>().await;
        }
        Command::Origin {
            listen,
            receive_window,
        } => {
            let tls = support::build_upstream_tls_config_with_alpn(
                &ca,
                ORIGIN_HOST,
                vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            )?;
            let acceptor = TlsAcceptor::from(tls);
            let stats = Arc::new(Stats::default());
            let echo = UdpSocket::bind(SocketAddr::new(listen.ip(), 8082)).await?;
            tokio::spawn(serve_probe(echo));
            let admin = TcpListener::bind("127.0.0.1:8081").await?;
            let admin_stats = stats.clone();
            tokio::spawn(async move {
                loop {
                    let (mut socket, _) = admin.accept().await.unwrap();
                    let result = json!({"bytes":admin_stats.bytes.load(Ordering::Relaxed), "errors":admin_stats.errors.load(Ordering::Relaxed), "stream_progress":admin_stats.stream_progress()});
                    let _ = socket.write_all(result.to_string().as_bytes()).await;
                }
            });
            let listener = TcpListener::bind(listen).await?;
            loop {
                let (tcp, _) = listener.accept().await?;
                tcp.set_nodelay(true)?;
                let acceptor = acceptor.clone();
                let stats = stats.clone();
                tokio::spawn(async move {
                    // Timed runs deliberately cancel incomplete transfers at the deadline.
                    if let Ok(tls) = acceptor.accept(tcp).await
                        && let Err(error) =
                            origin_connection(tls, stats.clone(), receive_window).await
                        && error.to_string().contains("corrupt payload")
                    {
                        stats.errors.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        }
        Command::Client {
            target,
            proxy,
            protocol,
            upload,
            streams,
            sessions,
            warmup,
            seconds,
            bytes,
            read_delay_ms,
            pause_ms,
            receive_window,
        } => {
            ensure!(
                streams > 0 && sessions > 0 && seconds > 0,
                "positive streams, sessions and seconds required"
            );
            let started = now_ns();
            let transfer = Transfer {
                target,
                proxy,
                upload,
                size: bytes.unwrap_or(BODY_SIZE),
                start_ns: if bytes.is_some() {
                    started
                } else {
                    started + warmup * 1_000_000_000
                },
                end_ns: if bytes.is_some() {
                    u64::MAX
                } else {
                    started + (warmup + seconds) * 1_000_000_000
                },
                read_delay_ms,
                pause_ms,
                pause_deadline_ns: if pause_ms == 0 {
                    0
                } else {
                    started + pause_ms * 1_000_000
                },
            };
            let tls = support::build_client_tls_with_protocols(
                roots(&ca),
                vec![match protocol {
                    Protocol::H1 => b"http/1.1".to_vec(),
                    Protocol::H2 => b"h2".to_vec(),
                }],
            )?;
            let stats = Arc::new(Stats::default());
            let errors = Arc::new(Mutex::new(Vec::<String>::new()));
            let mut tasks = JoinSet::new();
            for _ in 0..sessions {
                for index in 0..match protocol {
                    Protocol::H1 => streams,
                    Protocol::H2 => 1,
                } {
                    let mut transfer = transfer.clone();
                    if index > 0 {
                        transfer.pause_ms = 0;
                    }
                    let tls = tls.clone();
                    let stats = stats.clone();
                    tasks.spawn(async move {
                        match protocol {
                            Protocol::H1 => client_h1(transfer, tls, stats).await,
                            Protocol::H2 => {
                                client_h2(transfer, tls, stats, streams, receive_window).await
                            }
                        }
                    });
                }
            }
            let collect = async {
                while let Some(result) = tasks.join_next().await {
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => errors.lock().unwrap().push(format!("{error:#}")),
                        Err(error) => errors.lock().unwrap().push(error.to_string()),
                    }
                }
            };
            let limit = if bytes.is_some() {
                60
            } else {
                warmup + seconds
            };
            let timed_out = tokio::time::timeout(Duration::from_secs(limit), collect)
                .await
                .is_err();
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            if bytes.is_some() && timed_out {
                errors
                    .lock()
                    .unwrap()
                    .push("fixed-size transfer timed out".into());
            }
            let elapsed = (now_ns() - started) as f64 / 1e9;
            let first_ns = stats.first_ns.load(Ordering::Relaxed);
            println!(
                "{}",
                json!({"bytes":stats.bytes.load(Ordering::Relaxed), "seconds":if bytes.is_some() { elapsed } else { seconds as f64 }, "elapsed":elapsed, "first_byte_seconds":if first_ns == 0 { None } else { Some((first_ns - started) as f64 / 1e9) }, "errors":*errors.lock().unwrap(), "started_ns":started, "stream_progress":stats.stream_progress()})
            );
        }
    }
    Ok(())
}
