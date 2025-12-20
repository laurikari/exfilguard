use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use http::StatusCode;
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
};
use rustls::{ServerConfig, pki_types::PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    time::timeout,
};

static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

static REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new("requests_total", "Total requests by decision");
    let vec = IntCounterVec::new(opts, &["decision"]).expect("create counter vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register requests_total");
    vec
});

static CLIENT_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new(
        "client_requests_total",
        "Total requests by client and decision",
    );
    let vec = IntCounterVec::new(opts, &["client", "decision"]).expect("create counter vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register client_requests_total");
    vec
});

static POLICY_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new(
        "policy_requests_total",
        "Total requests by policy and decision",
    );
    let vec = IntCounterVec::new(opts, &["policy", "decision"]).expect("create counter vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register policy_requests_total");
    vec
});

static RULE_HITS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new("rule_hits_total", "Rule match counter");
    let vec = IntCounterVec::new(opts, &["rule"]).expect("create counter vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register rule_hits_total");
    vec
});

static REQUEST_STATUS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new("requests_status_total", "Requests by status class");
    let vec = IntCounterVec::new(opts, &["status_class"]).expect("create counter vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register requests_status_total");
    vec
});

static REQUEST_METHOD_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new("requests_method_total", "Requests by method");
    let vec = IntCounterVec::new(opts, &["method"]).expect("create counter vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register requests_method_total");
    vec
});

static CLIENT_LATENCY_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    let opts = HistogramOpts::new(
        "client_request_duration_seconds",
        "Request latency per client",
    )
    .buckets(latency_buckets());
    let vec = HistogramVec::new(opts, &["client", "decision"]).expect("create histogram vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register client_request_duration_seconds");
    vec
});

static POLICY_LATENCY_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    let opts = HistogramOpts::new(
        "policy_request_duration_seconds",
        "Request latency per policy",
    )
    .buckets(latency_buckets());
    let vec = HistogramVec::new(opts, &["policy", "decision"]).expect("create histogram vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register policy_request_duration_seconds");
    vec
});

static CACHE_LOOKUP_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new("cache_lookup_total", "HTTP cache lookups by result");
    let vec = IntCounterVec::new(opts, &["result"]).expect("create counter vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register cache_lookup_total");
    vec
});

static CACHE_STORE_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new("cache_store_total", "HTTP cache store calls")
        .expect("create cache_store_total");
    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("register cache_store_total");
    counter
});

static CACHE_STORE_ERRORS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new("cache_store_errors_total", "HTTP cache store errors")
        .expect("create cache_store_errors_total");
    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("register cache_store_errors_total");
    counter
});

static CACHE_EVICTIONS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter =
        IntCounter::new("cache_evictions_total", "HTTP cache evictions").expect("create counter");
    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("register cache_evictions_total");
    counter
});

static CACHE_SWEEP_RUNS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter =
        IntCounter::new("cache_sweep_runs_total", "HTTP cache sweep runs").expect("create counter");
    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("register cache_sweep_runs_total");
    counter
});

static CACHE_SWEEP_EXPIRED_ENTRIES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new(
        "cache_sweep_expired_entries_total",
        "Expired cache entries removed by sweeper",
    )
    .expect("create counter");
    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("register cache_sweep_expired_entries_total");
    counter
});

static CACHE_SWEEP_BYTES_RECLAIMED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new(
        "cache_sweep_bytes_reclaimed_total",
        "Bytes reclaimed by cache sweeper",
    )
    .expect("create counter");
    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("register cache_sweep_bytes_reclaimed_total");
    counter
});

static CACHE_CLEANUP_DIRS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new(
        "cache_cleanup_dirs_total",
        "Old cache directories removed after version upgrade",
    )
    .expect("create counter");
    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("register cache_cleanup_dirs_total");
    counter
});

static INFLIGHT_REQUESTS: Lazy<IntGauge> = Lazy::new(|| {
    let gauge =
        IntGauge::new("inflight_requests", "Current inflight requests").expect("create gauge");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register inflight_requests");
    gauge
});

static INFLIGHT_REQUESTS_BY_CLIENT: Lazy<IntGaugeVec> = Lazy::new(|| {
    let vec = IntGaugeVec::new(
        Opts::new("inflight_requests_by_client", "Inflight per client"),
        &["client"],
    )
    .expect("create gauge vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register inflight_requests_by_client");
    vec
});

static UPSTREAM_POOL_IN_USE: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new("upstream_pool_in_use", "Idle upstream pool size")
        .expect("create upstream_pool_in_use");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register upstream_pool_in_use");
    gauge
});

static UPSTREAM_POOL_CAPACITY: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new(
        "upstream_pool_capacity",
        "Configured upstream pool capacity",
    )
    .expect("create upstream_pool_capacity");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register upstream_pool_capacity");
    gauge
});

static UPSTREAM_POOL_REUSE_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let vec = IntCounterVec::new(
        Opts::new(
            "upstream_pool_reuse_total",
            "Upstream connection reuse counts",
        ),
        &["reused"],
    )
    .expect("create upstream_pool_reuse_total");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register upstream_pool_reuse_total");
    vec
});

static UPSTREAM_POOL_MISS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new("upstream_pool_miss_total", "Misses in upstream pool")
        .expect("create upstream_pool_miss_total");
    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("register upstream_pool_miss_total");
    counter
});

static UPSTREAM_ERRORS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let vec = IntCounterVec::new(
        Opts::new("upstream_errors_total", "Upstream errors by kind"),
        &["kind"],
    )
    .expect("create upstream_errors_total");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register upstream_errors_total");
    vec
});

fn latency_buckets() -> Vec<f64> {
    // Focused buckets for proxy latency in seconds.
    vec![
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]
}

const METRICS_MAX_REQUEST_BYTES: usize = 8192;
const METRICS_READ_TIMEOUT: Duration = Duration::from_secs(5);

fn status_class(status: u16) -> &'static str {
    match status {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

fn normalize_label(value: &str, empty: &'static str) -> String {
    if value.is_empty() {
        empty.to_string()
    } else {
        value.to_string()
    }
}

pub fn inc_inflight(client: Option<&str>) {
    INFLIGHT_REQUESTS.inc();
    if let Some(client) = client {
        INFLIGHT_REQUESTS_BY_CLIENT
            .with_label_values(&[client])
            .inc();
    }
}

pub fn dec_inflight(client: Option<&str>) {
    INFLIGHT_REQUESTS.dec();
    if let Some(client) = client {
        INFLIGHT_REQUESTS_BY_CLIENT
            .with_label_values(&[client])
            .dec();
    }
}

pub fn record_rule_hit(rule: &str) {
    RULE_HITS_TOTAL.with_label_values(&[rule]).inc();
}

pub fn record_request(
    client: Option<&str>,
    policy: Option<&str>,
    decision: &str,
    method: &str,
    status: StatusCode,
    elapsed: Duration,
) {
    let decision = normalize_label(decision, "unknown");
    let status_class = status_class(status.as_u16());

    REQUESTS_TOTAL.with_label_values(&[decision.as_str()]).inc();
    REQUEST_STATUS_TOTAL
        .with_label_values(&[status_class])
        .inc();
    REQUEST_METHOD_TOTAL.with_label_values(&[method]).inc();

    if let Some(client) = client {
        CLIENT_REQUESTS_TOTAL
            .with_label_values(&[client, decision.as_str()])
            .inc();
        CLIENT_LATENCY_SECONDS
            .with_label_values(&[client, decision.as_str()])
            .observe(duration_to_seconds(elapsed));
    }

    if let Some(policy) = policy {
        POLICY_REQUESTS_TOTAL
            .with_label_values(&[policy, decision.as_str()])
            .inc();
        POLICY_LATENCY_SECONDS
            .with_label_values(&[policy, decision.as_str()])
            .observe(duration_to_seconds(elapsed));
    }
}

pub fn record_cache_lookup(hit: bool) {
    let label = if hit { "hit" } else { "miss" };
    CACHE_LOOKUP_TOTAL.with_label_values(&[label]).inc();
}

pub fn record_cache_store() {
    CACHE_STORE_TOTAL.inc();
}

pub fn record_cache_store_error() {
    CACHE_STORE_ERRORS_TOTAL.inc();
}

pub fn record_cache_eviction() {
    CACHE_EVICTIONS_TOTAL.inc();
}

pub fn record_cache_sweep_run() {
    CACHE_SWEEP_RUNS_TOTAL.inc();
}

pub fn record_cache_sweep_removed(entries: u64, bytes: u64) {
    if entries > 0 {
        CACHE_SWEEP_EXPIRED_ENTRIES_TOTAL.inc_by(entries);
    }
    if bytes > 0 {
        CACHE_SWEEP_BYTES_RECLAIMED_TOTAL.inc_by(bytes);
    }
}

pub fn record_cache_cleanup_dir() {
    CACHE_CLEANUP_DIRS_TOTAL.inc();
}

pub fn set_pool_capacity(capacity: usize) {
    UPSTREAM_POOL_CAPACITY.set(capacity as i64);
}

pub fn set_pool_in_use(size: usize) {
    UPSTREAM_POOL_IN_USE.set(size as i64);
}

pub fn record_pool_reuse(reused: bool) {
    let label = if reused { "yes" } else { "no" };
    UPSTREAM_POOL_REUSE_TOTAL.with_label_values(&[label]).inc();
}

pub fn record_pool_miss() {
    UPSTREAM_POOL_MISS_TOTAL.inc();
}

pub fn record_upstream_error(kind: &str) {
    UPSTREAM_ERRORS_TOTAL.with_label_values(&[kind]).inc();
}

pub fn gather() -> Vec<u8> {
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .expect("encode metrics");
    buffer
}

fn duration_to_seconds(dur: Duration) -> f64 {
    dur.as_secs_f64()
}

pub struct MetricsTlsConfig {
    pub cert_path: std::path::PathBuf,
    pub key_path: std::path::PathBuf,
}

pub async fn serve(addr: SocketAddr, path: String, tls: Option<MetricsTlsConfig>) -> Result<()> {
    let tls_acceptor = if let Some(cfg) = tls {
        Some(build_tls_acceptor(&cfg.cert_path, &cfg.key_path)?)
    } else {
        None
    };
    let listener = TcpListener::bind(addr).await?;
    let path = if path.is_empty() {
        "/metrics".to_string()
    } else {
        path
    };
    loop {
        let (stream, _) = listener.accept().await?;
        let path = path.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, &path, tls_acceptor).await {
                tracing::debug!(error = %err, "metrics handler error");
            }
        });
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    path: &str,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
) -> Result<()> {
    if let Some(acceptor) = tls_acceptor {
        let tls = acceptor.accept(stream).await?;
        handle_stream(tls, path).await
    } else {
        handle_stream(stream, path).await
    }
}

async fn handle_stream<S>(stream: S, path: &str) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    handle_stream_with_limits(
        stream,
        path,
        METRICS_READ_TIMEOUT,
        METRICS_MAX_REQUEST_BYTES,
    )
    .await
}

async fn handle_stream_with_limits<S>(
    stream: S,
    path: &str,
    read_timeout: Duration,
    max_bytes: usize,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    let mut total_bytes = 0usize;
    let bytes = read_line_with_limits(
        &mut reader,
        &mut request_line,
        read_timeout,
        max_bytes,
        &mut total_bytes,
        "reading metrics request line",
    )
    .await?;
    if bytes == 0 {
        return Ok(());
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let uri = parts.next().unwrap_or_default();

    // Consume and ignore headers until empty line.
    loop {
        let mut line = String::new();
        let n = read_line_with_limits(
            &mut reader,
            &mut line,
            read_timeout,
            max_bytes,
            &mut total_bytes,
            "reading metrics request headers",
        )
        .await?;
        if n == 0 || line == "\r\n" {
            break;
        }
    }

    let response = if method == "GET" && uri == path {
        let body = gather();
        build_response(200, TextEncoder::new().format_type(), body)
    } else {
        build_response(404, "text/plain", b"not found".to_vec())
    };

    reader.get_mut().write_all(&response).await?;
    reader.get_mut().shutdown().await?;
    Ok(())
}

fn build_response(status: u16, content_type: &str, body: Vec<u8>) -> Vec<u8> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut response = header.into_bytes();
    response.extend_from_slice(&body);
    response
}

fn load_certs(path: &std::path::Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read certs from {}", path.display()))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let certs = certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("failed to parse certs: {e}"))?;
    Ok(certs)
}

fn load_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read key from {}", path.display()))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    if let Some(key) = pkcs8_private_keys(&mut reader).next() {
        let key = key.map_err(|e| anyhow!("failed to parse pkcs8 key: {e}"))?;
        return Ok(PrivateKeyDer::Pkcs8(key));
    }

    let mut reader = std::io::BufReader::new(&data[..]);
    if let Some(key) = rsa_private_keys(&mut reader).next() {
        let key = key.map_err(|e| anyhow!("failed to parse rsa key: {e}"))?;
        return Ok(PrivateKeyDer::from(key));
    }

    Err(anyhow!("no valid private key found in {}", path.display()))
}

fn build_tls_acceptor(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<tokio_rustls::TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("failed to build server config: {e}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

async fn read_line_with_limits<R>(
    reader: &mut BufReader<R>,
    buf: &mut String,
    timeout_dur: Duration,
    max_bytes: usize,
    total: &mut usize,
    context: &str,
) -> Result<usize>
where
    R: tokio::io::AsyncRead + Unpin,
{
    if max_bytes == 0 {
        anyhow::bail!("max_bytes must be greater than zero");
    }
    buf.clear();
    let mut collected = Vec::new();
    loop {
        let available = timeout(timeout_dur, reader.fill_buf())
            .await
            .map_err(|_| anyhow!("timed out {context}"))??;
        if available.is_empty() {
            if collected.is_empty() {
                return Ok(0);
            }
            anyhow::bail!("connection closed while {context}");
        }

        let newline_pos = available.iter().position(|byte| *byte == b'\n');
        let consume = newline_pos.map(|idx| idx + 1).unwrap_or(available.len());

        let remaining = max_bytes
            .checked_sub(*total)
            .ok_or_else(|| anyhow!("metrics request exceeded allowed size"))?;
        if collected
            .len()
            .checked_add(consume)
            .ok_or_else(|| anyhow!("metrics request length overflow"))?
            > remaining
        {
            anyhow::bail!("metrics request exceeded allowed size");
        }

        collected.extend_from_slice(&available[..consume]);
        reader.consume(consume);

        if newline_pos.is_some() {
            break;
        }
    }

    let string = String::from_utf8(collected)
        .map_err(|_| anyhow!("metrics request contained invalid bytes"))?;
    let bytes = string.len();
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| anyhow!("metrics request length overflow"))?;
    ensure!(*total <= max_bytes, "metrics request exceeded allowed size");
    *buf = string;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;

    #[test]
    fn record_basic_metrics() {
        record_request(
            Some("client-a"),
            Some("policy-a"),
            "ALLOW",
            "GET",
            StatusCode::OK,
            Duration::from_millis(10),
        );
        record_rule_hit("rule-1");
        let text = String::from_utf8(gather()).expect("utf8");
        assert!(
            text.contains("requests_total"),
            "expected requests_total in metrics output"
        );
        assert!(
            text.contains("rule_hits_total"),
            "expected rule_hits_total in metrics output"
        );
    }

    #[tokio::test]
    async fn rejects_oversized_request_line() {
        let (mut client, server) = tokio::io::duplex(1024);
        // Build a request line that exceeds a tiny limit.
        let oversized = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(64));
        client.write_all(oversized.as_bytes()).await.unwrap();
        drop(client);

        let err = super::handle_stream_with_limits(
            server,
            "/metrics",
            Duration::from_secs(1),
            32, // very small limit to trigger rejection
        )
        .await
        .expect_err("oversized request should be rejected");
        assert!(
            err.to_string().contains("exceeded allowed size"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_oversized_header_line() {
        let (mut client, server) = tokio::io::duplex(2048);
        let oversized = format!(
            "GET /metrics HTTP/1.1\r\nX-Test: {}\r\n\r\n",
            "a".repeat(128)
        );
        client.write_all(oversized.as_bytes()).await.unwrap();
        drop(client);

        let err = super::handle_stream_with_limits(server, "/metrics", Duration::from_secs(1), 64)
            .await
            .expect_err("oversized header should be rejected");
        assert!(
            err.to_string().contains("exceeded allowed size"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn times_out_on_slow_request() {
        let (_client, server) = tokio::io::duplex(1024);
        let err =
            super::handle_stream_with_limits(server, "/metrics", Duration::from_millis(50), 1024)
                .await
                .expect_err("slow request should time out");
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );
    }
}
