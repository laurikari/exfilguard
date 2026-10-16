use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, ensure};
use http::StatusCode;
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
};
use rustls::{
    ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    time::{Instant, timeout},
};

static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

static REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new(
        "requests_total",
        "Total requests by decision and effective mode",
    );
    let vec =
        IntCounterVec::new(opts, &["decision", "effective_mode"]).expect("create counter vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register requests_total");
    vec
});

static CLIENT_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new(
        "client_requests_total",
        "Total requests by client, decision, and effective mode",
    );
    let vec = IntCounterVec::new(opts, &["client", "decision", "effective_mode"])
        .expect("create counter vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register client_requests_total");
    vec
});

static POLICY_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new(
        "policy_requests_total",
        "Total requests by policy, decision, and effective mode",
    );
    let vec = IntCounterVec::new(opts, &["policy", "decision", "effective_mode"])
        .expect("create counter vec");
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
    let opts = Opts::new(
        "requests_status_total",
        "Requests by status class and effective mode",
    );
    let vec =
        IntCounterVec::new(opts, &["status_class", "effective_mode"]).expect("create counter vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register requests_status_total");
    vec
});

static REQUEST_METHOD_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new(
        "requests_method_total",
        "Requests by method and effective mode",
    );
    let vec = IntCounterVec::new(opts, &["method", "effective_mode"]).expect("create counter vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register requests_method_total");
    vec
});

static CLIENT_LATENCY_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    let opts = HistogramOpts::new(
        "client_request_duration_seconds",
        "Request latency per client, decision, and effective mode",
    )
    .buckets(latency_buckets());
    let vec = HistogramVec::new(opts, &["client", "decision", "effective_mode"])
        .expect("create histogram vec");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register client_request_duration_seconds");
    vec
});

static POLICY_LATENCY_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    let opts = HistogramOpts::new(
        "policy_request_duration_seconds",
        "Request latency per policy, decision, and effective mode",
    )
    .buckets(latency_buckets());
    let vec = HistogramVec::new(opts, &["policy", "decision", "effective_mode"])
        .expect("create histogram vec");
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

static DOWNSTREAM_CONNECTIONS_ACTIVE: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new(
        "downstream_connections_active",
        "Current accepted downstream client connections",
    )
    .expect("create downstream_connections_active");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register downstream_connections_active");
    gauge
});

static DOWNSTREAM_CONNECTIONS_ACTIVE_BY_CLIENT: Lazy<IntGaugeVec> = Lazy::new(|| {
    let vec = IntGaugeVec::new(
        Opts::new(
            "downstream_connections_active_by_client",
            "Current admitted downstream connections by configured client",
        ),
        &["client"],
    )
    .expect("create downstream_connections_active_by_client");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register downstream_connections_active_by_client");
    vec
});

static DOWNSTREAM_CONNECTION_REJECTIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let vec = IntCounterVec::new(
        Opts::new(
            "downstream_connection_rejections_total",
            "Downstream connections rejected at the configured client limit",
        ),
        &["client"],
    )
    .expect("create downstream_connection_rejections_total");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register downstream_connection_rejections_total");
    vec
});

static PROXY_PROTOCOL_PENDING_CONNECTIONS_ACTIVE: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new(
        "proxy_protocol_pending_connections_active",
        "Current connections from allowlisted peers awaiting PROXY protocol admission",
    )
    .expect("create proxy_protocol_pending_connections_active");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register proxy_protocol_pending_connections_active");
    gauge
});

static PROXY_PROTOCOL_PENDING_CONNECTION_REJECTIONS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new(
        "proxy_protocol_pending_connection_rejections_total",
        "Connections rejected at the PROXY protocol pending admission limit",
    )
    .expect("create proxy_protocol_pending_connection_rejections_total");
    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("register proxy_protocol_pending_connection_rejections_total");
    counter
});

static CONNECT_TUNNELS_ACTIVE: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new(
        "connect_tunnels_active",
        "Current CONNECT tunnels relaying bytes",
    )
    .expect("create connect_tunnels_active");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register connect_tunnels_active");
    gauge
});

static TLS_BUMP_SESSIONS_ACTIVE: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new(
        "tls_bump_sessions_active",
        "Current bumped TLS sessions serving decrypted requests",
    )
    .expect("create tls_bump_sessions_active");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register tls_bump_sessions_active");
    gauge
});

static HTTP2_STREAMS_ACTIVE: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new(
        "http2_streams_active",
        "Current active downstream HTTP/2 request streams",
    )
    .expect("create http2_streams_active");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register http2_streams_active");
    gauge
});

static UPSTREAM_CONNECTIONS_OPEN: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new(
        "upstream_connections_open",
        "Current open upstream connections",
    )
    .expect("create upstream_connections_open");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register upstream_connections_open");
    gauge
});

static UPSTREAM_CONNECTIONS_IDLE: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new(
        "upstream_connections_idle",
        "Current idle reusable upstream HTTP/1.1 connections",
    )
    .expect("create upstream_connections_idle");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register upstream_connections_idle");
    gauge
});

static CACHE_ENTRIES: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new("cache_entries", "Current cached response entries")
        .expect("create cache_entries");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register cache_entries");
    gauge
});

static CACHE_BYTES_USED: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new("cache_bytes_used", "Current cache bytes in use")
        .expect("create cache_bytes_used");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register cache_bytes_used");
    gauge
});

static POLICY_RELOAD_LAST_SUCCESS_UNIXTIME: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new(
        "policy_reload_last_success_unixtime",
        "Unix timestamp of the last successful policy load or reload",
    )
    .expect("create policy_reload_last_success_unixtime");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register policy_reload_last_success_unixtime");
    gauge
});

static CA_CERTIFICATE_NOT_AFTER_TIMESTAMP_SECONDS: Lazy<IntGaugeVec> = Lazy::new(|| {
    let vec = IntGaugeVec::new(
        Opts::new(
            "ca_certificate_not_after_timestamp_seconds",
            "Unix timestamp when the active CA certificate expires",
        ),
        &["certificate"],
    )
    .expect("create ca_certificate_not_after_timestamp_seconds");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register ca_certificate_not_after_timestamp_seconds");
    vec
});

static CA_SOURCE_INFO: Lazy<IntGaugeVec> = Lazy::new(|| {
    let vec = IntGaugeVec::new(
        Opts::new("ca_source_info", "Configured CA source"),
        &["source"],
    )
    .expect("create ca_source_info");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register ca_source_info");
    vec
});

static CA_ISSUER_USABLE: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new(
        "ca_issuer_usable",
        "Whether the active CA issuer can mint a safely bounded leaf",
    )
    .expect("create ca_issuer_usable");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register ca_issuer_usable");
    gauge
});

static CA_ISSUER_GENERATION: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new(
        "ca_issuer_generation",
        "In-process active CA issuer generation",
    )
    .expect("create ca_issuer_generation");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register ca_issuer_generation");
    gauge
});

static CA_VAULT_RENEWAL_ATTEMPTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let vec = IntCounterVec::new(
        Opts::new(
            "ca_vault_renewal_attempts_total",
            "Vault CA renewal attempts by result and bounded reason",
        ),
        &["result", "reason"],
    )
    .expect("create ca_vault_renewal_attempts_total");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register ca_vault_renewal_attempts_total");
    vec
});

static CA_VAULT_LAST_RENEWAL_ATTEMPT_TIMESTAMP_SECONDS: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new(
        "ca_vault_last_renewal_attempt_timestamp_seconds",
        "Unix timestamp of the last Vault CA renewal attempt",
    )
    .expect("create ca_vault_last_renewal_attempt_timestamp_seconds");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register ca_vault_last_renewal_attempt_timestamp_seconds");
    gauge
});

static CA_VAULT_LAST_RENEWAL_SUCCESS_TIMESTAMP_SECONDS: Lazy<IntGauge> = Lazy::new(|| {
    let gauge = IntGauge::new(
        "ca_vault_last_renewal_success_timestamp_seconds",
        "Unix timestamp of the last successful Vault CA renewal",
    )
    .expect("create ca_vault_last_renewal_success_timestamp_seconds");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("register ca_vault_last_renewal_success_timestamp_seconds");
    gauge
});

static AUTHORIZATION_SERVICE_CLIENT_CERTIFICATE_NOT_AFTER_TIMESTAMP_SECONDS: Lazy<IntGaugeVec> =
    Lazy::new(|| {
        let vec = IntGaugeVec::new(
            Opts::new(
                "authorization_service_client_certificate_not_after_timestamp_seconds",
                "Expiry of the active Vault-backed authorization-service client certificate",
            ),
            &["service"],
        )
        .expect("create authorization_service_client_certificate_not_after_timestamp_seconds");
        REGISTRY.register(Box::new(vec.clone())).expect(
            "register authorization_service_client_certificate_not_after_timestamp_seconds",
        );
        vec
    });

static AUTHORIZATION_SERVICE_VAULT_RENEWAL_ATTEMPTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let vec = IntCounterVec::new(
        Opts::new(
            "authorization_service_vault_renewal_attempts_total",
            "Vault authorization-service client certificate renewal attempts",
        ),
        &["service", "result", "reason"],
    )
    .expect("create authorization_service_vault_renewal_attempts_total");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("register authorization_service_vault_renewal_attempts_total");
    vec
});

static AUTHORIZATION_SERVICE_VAULT_LAST_RENEWAL_ATTEMPT_TIMESTAMP_SECONDS: Lazy<IntGaugeVec> =
    Lazy::new(|| {
        let vec = IntGaugeVec::new(
            Opts::new(
                "authorization_service_vault_last_renewal_attempt_timestamp_seconds",
                "Last Vault client certificate renewal attempt for an authorization service",
            ),
            &["service"],
        )
        .expect("create authorization_service_vault_last_renewal_attempt_timestamp_seconds");
        REGISTRY
            .register(Box::new(vec.clone()))
            .expect("register authorization_service_vault_last_renewal_attempt_timestamp_seconds");
        vec
    });

static AUTHORIZATION_SERVICE_VAULT_LAST_RENEWAL_SUCCESS_TIMESTAMP_SECONDS: Lazy<IntGaugeVec> =
    Lazy::new(|| {
        let vec = IntGaugeVec::new(
            Opts::new(
                "authorization_service_vault_last_renewal_success_timestamp_seconds",
                "Last successful Vault client certificate renewal for an authorization service",
            ),
            &["service"],
        )
        .expect("create authorization_service_vault_last_renewal_success_timestamp_seconds");
        REGISTRY
            .register(Box::new(vec.clone()))
            .expect("register authorization_service_vault_last_renewal_success_timestamp_seconds");
        vec
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
const METRICS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

fn status_class(status: u16) -> &'static str {
    match status {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

fn method_label(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "CONNECT" => "CONNECT",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "PATCH" => "PATCH",
        _ => "OTHER",
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
    effective_mode: &str,
    method: &str,
    status: StatusCode,
    elapsed: Duration,
) {
    let decision = normalize_label(decision, "unknown");
    let effective_mode = normalize_label(effective_mode, "unknown");
    let status_class = status_class(status.as_u16());

    REQUESTS_TOTAL
        .with_label_values(&[decision.as_str(), effective_mode.as_str()])
        .inc();
    REQUEST_STATUS_TOTAL
        .with_label_values(&[status_class, effective_mode.as_str()])
        .inc();
    REQUEST_METHOD_TOTAL
        .with_label_values(&[method_label(method), effective_mode.as_str()])
        .inc();

    if let Some(client) = client {
        CLIENT_REQUESTS_TOTAL
            .with_label_values(&[client, decision.as_str(), effective_mode.as_str()])
            .inc();
        CLIENT_LATENCY_SECONDS
            .with_label_values(&[client, decision.as_str(), effective_mode.as_str()])
            .observe(duration_to_seconds(elapsed));
    }

    if let Some(policy) = policy {
        POLICY_REQUESTS_TOTAL
            .with_label_values(&[policy, decision.as_str(), effective_mode.as_str()])
            .inc();
        POLICY_LATENCY_SECONDS
            .with_label_values(&[policy, decision.as_str(), effective_mode.as_str()])
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

#[must_use]
pub struct MetricGuard {
    on_drop: fn(),
}

#[must_use]
pub struct ClientConnectionMetricGuard {
    client: Arc<str>,
}

impl Drop for ClientConnectionMetricGuard {
    fn drop(&mut self) {
        DOWNSTREAM_CONNECTIONS_ACTIVE_BY_CLIENT
            .with_label_values(&[self.client.as_ref()])
            .dec();
    }
}

impl Drop for MetricGuard {
    fn drop(&mut self) {
        (self.on_drop)();
    }
}

#[derive(Clone)]
pub struct UpstreamConnectionTracker {
    open: Arc<AtomicBool>,
}

impl UpstreamConnectionTracker {
    fn new() -> Self {
        UPSTREAM_CONNECTIONS_OPEN.inc();
        Self {
            open: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn close(&self) {
        if self.open.swap(false, Ordering::Relaxed) {
            UPSTREAM_CONNECTIONS_OPEN.dec();
        }
    }
}

impl Drop for UpstreamConnectionTracker {
    fn drop(&mut self) {
        self.close();
    }
}

fn guard(on_drop: fn()) -> MetricGuard {
    MetricGuard { on_drop }
}

fn dec_downstream_connections_active() {
    DOWNSTREAM_CONNECTIONS_ACTIVE.dec();
}

fn dec_proxy_protocol_pending_connections_active() {
    PROXY_PROTOCOL_PENDING_CONNECTIONS_ACTIVE.dec();
}

fn dec_connect_tunnels_active() {
    CONNECT_TUNNELS_ACTIVE.dec();
}

fn dec_tls_bump_sessions_active() {
    TLS_BUMP_SESSIONS_ACTIVE.dec();
}

fn dec_http2_streams_active() {
    HTTP2_STREAMS_ACTIVE.dec();
}

pub fn track_downstream_connection() -> MetricGuard {
    DOWNSTREAM_CONNECTIONS_ACTIVE.inc();
    guard(dec_downstream_connections_active)
}

pub fn track_downstream_connection_for_client(client: Arc<str>) -> ClientConnectionMetricGuard {
    DOWNSTREAM_CONNECTIONS_ACTIVE_BY_CLIENT
        .with_label_values(&[client.as_ref()])
        .inc();
    ClientConnectionMetricGuard { client }
}

pub fn record_downstream_connection_rejection(client: &str) {
    DOWNSTREAM_CONNECTION_REJECTIONS_TOTAL
        .with_label_values(&[client])
        .inc();
}

pub fn track_proxy_protocol_pending_connection() -> MetricGuard {
    PROXY_PROTOCOL_PENDING_CONNECTIONS_ACTIVE.inc();
    guard(dec_proxy_protocol_pending_connections_active)
}

pub fn record_proxy_protocol_pending_connection_rejection() {
    PROXY_PROTOCOL_PENDING_CONNECTION_REJECTIONS_TOTAL.inc();
}

pub fn track_connect_tunnel() -> MetricGuard {
    CONNECT_TUNNELS_ACTIVE.inc();
    guard(dec_connect_tunnels_active)
}

pub fn track_tls_bump_session() -> MetricGuard {
    TLS_BUMP_SESSIONS_ACTIVE.inc();
    guard(dec_tls_bump_sessions_active)
}

pub fn track_http2_stream() -> MetricGuard {
    HTTP2_STREAMS_ACTIVE.inc();
    guard(dec_http2_streams_active)
}

pub fn track_upstream_connection() -> UpstreamConnectionTracker {
    UpstreamConnectionTracker::new()
}

pub fn inc_upstream_connections_idle() {
    UPSTREAM_CONNECTIONS_IDLE.inc();
}

pub fn dec_upstream_connections_idle() {
    UPSTREAM_CONNECTIONS_IDLE.dec();
}

pub fn set_cache_usage(entries: usize, bytes: u64) {
    CACHE_ENTRIES.set(entries.min(i64::MAX as usize) as i64);
    CACHE_BYTES_USED.set(bytes.min(i64::MAX as u64) as i64);
}

pub fn mark_policy_reload_success() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64;
    POLICY_RELOAD_LAST_SUCCESS_UNIXTIME.set(now);
}

fn unix_timestamp_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

pub fn set_ca_state(
    source: &str,
    root_not_after: i64,
    intermediate_not_after: i64,
    usable: bool,
    generation: u64,
) {
    CA_SOURCE_INFO.with_label_values(&[source]).set(1);
    CA_CERTIFICATE_NOT_AFTER_TIMESTAMP_SECONDS
        .with_label_values(&["root"])
        .set(root_not_after);
    CA_CERTIFICATE_NOT_AFTER_TIMESTAMP_SECONDS
        .with_label_values(&["intermediate"])
        .set(intermediate_not_after);
    CA_ISSUER_USABLE.set(i64::from(usable));
    CA_ISSUER_GENERATION.set(generation.min(i64::MAX as u64) as i64);
}

pub fn set_ca_issuer_usable(usable: bool) {
    CA_ISSUER_USABLE.set(i64::from(usable));
}

pub fn record_ca_vault_renewal(result: &str, reason: &str) {
    let now = unix_timestamp_now();
    CA_VAULT_LAST_RENEWAL_ATTEMPT_TIMESTAMP_SECONDS.set(now);
    CA_VAULT_RENEWAL_ATTEMPTS_TOTAL
        .with_label_values(&[result, reason])
        .inc();
    if result == "success" {
        CA_VAULT_LAST_RENEWAL_SUCCESS_TIMESTAMP_SECONDS.set(now);
    }
}

pub(crate) fn set_authorization_service_client_certificate(service: &str, not_after: i64) {
    AUTHORIZATION_SERVICE_CLIENT_CERTIFICATE_NOT_AFTER_TIMESTAMP_SECONDS
        .with_label_values(&[service])
        .set(not_after);
}

pub(crate) fn record_authorization_service_vault_renewal(
    service: &str,
    result: &str,
    reason: &str,
) {
    let now = unix_timestamp_now();
    AUTHORIZATION_SERVICE_VAULT_LAST_RENEWAL_ATTEMPT_TIMESTAMP_SECONDS
        .with_label_values(&[service])
        .set(now);
    AUTHORIZATION_SERVICE_VAULT_RENEWAL_ATTEMPTS_TOTAL
        .with_label_values(&[service, result, reason])
        .inc();
    if result == "success" {
        AUTHORIZATION_SERVICE_VAULT_LAST_RENEWAL_SUCCESS_TIMESTAMP_SECONDS
            .with_label_values(&[service])
            .set(now);
    }
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
        let tls = timeout(METRICS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
            .await
            .map_err(|_| anyhow!("timed out during TLS handshake"))??;
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
    let deadline = Instant::now() + read_timeout;
    let bytes = read_line_with_limits(
        &mut reader,
        &mut request_line,
        deadline,
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
            deadline,
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

fn load_certs(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read certs from {}", path.display()))?;
    let certs = CertificateDer::pem_slice_iter(&data)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("failed to parse certs: {e}"))?;
    Ok(certs)
}

fn load_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read key from {}", path.display()))?;
    PrivateKeyDer::from_pem_slice(&data)
        .map_err(|e| anyhow!("failed to parse private key from {}: {e}", path.display()))
}

fn build_tls_acceptor(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<tokio_rustls::TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let provider = ring::default_provider();
    let builder = ServerConfig::builder_with_provider(provider.into());
    let builder = builder.with_safe_default_protocol_versions()?;
    let mut config = builder
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("failed to build server config: {e}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

async fn read_line_with_limits<R>(
    reader: &mut BufReader<R>,
    buf: &mut String,
    deadline: Instant,
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
        let remaining = remaining_deadline(deadline, context)?;
        let available = timeout(remaining, reader.fill_buf())
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

fn remaining_deadline(deadline: Instant, context: &str) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| anyhow!("timed out {context}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use std::fs;
    use tempfile::TempDir;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn request_method_labels_are_bounded() {
        for method in [
            "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
        ] {
            assert_eq!(method_label(method), method);
        }
        for method in ["get", "CUSTOM", "UNKNOWN", "M-SEARCH", ""] {
            assert_eq!(method_label(method), "OTHER");
        }

        for index in 0..1_000 {
            record_request(
                None,
                None,
                "ALLOW",
                "m17-cardinality-test",
                &format!("CUSTOM-{index}"),
                StatusCode::OK,
                Duration::ZERO,
            );
        }
        let text = String::from_utf8(gather()).expect("utf8");
        let method_series: Vec<_> = text
            .lines()
            .filter(|line| {
                line.starts_with("requests_method_total{")
                    && line.contains("effective_mode=\"m17-cardinality-test\"")
            })
            .collect();
        assert_eq!(method_series.len(), 1, "{method_series:?}");
        assert!(method_series[0].contains("method=\"OTHER\""));
        assert!(method_series[0].ends_with(" 1000"));
    }

    #[test]
    fn record_basic_metrics() {
        record_request(
            Some("client-a"),
            Some("policy-a"),
            "ALLOW",
            "bump",
            "GET",
            StatusCode::OK,
            Duration::from_millis(10),
        );
        record_rule_hit("rule-1");
        set_ca_state("files", 2_000_000_000, 1_900_000_000, true, 3);
        record_ca_vault_renewal("failure", "signing");
        set_authorization_service_client_certificate("central", 1_800_000_000);
        record_authorization_service_vault_renewal("central", "failure", "authentication");
        let text = String::from_utf8(gather()).expect("utf8");
        assert!(
            text.contains("requests_total"),
            "expected requests_total in metrics output"
        );
        assert!(
            text.contains("effective_mode=\"bump\""),
            "expected effective_mode label in metrics output"
        );
        assert!(
            text.contains("rule_hits_total"),
            "expected rule_hits_total in metrics output"
        );
        assert!(text.contains("ca_source_info{source=\"files\"} 1"));
        assert!(text.contains(
            "ca_certificate_not_after_timestamp_seconds{certificate=\"intermediate\"} 1900000000"
        ));
        assert!(text.contains("ca_issuer_usable 1"));
        assert!(text.contains("ca_issuer_generation 3"));
        assert!(
            text.contains("ca_vault_renewal_attempts_total{reason=\"signing\",result=\"failure\"}")
        );
        assert!(text.contains(
            "authorization_service_client_certificate_not_after_timestamp_seconds{service=\"central\"} 1800000000"
        ));
        assert!(text.contains(
            "authorization_service_vault_renewal_attempts_total{reason=\"authentication\",result=\"failure\",service=\"central\"}"
        ));
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

    #[tokio::test(start_paused = true)]
    async fn tls_handshake_times_out_when_client_is_idle() -> anyhow::Result<()> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_der = cert.cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let provider = ring::default_provider();
        let builder = ServerConfig::builder_with_provider(provider.into());
        let builder = builder.with_safe_default_protocol_versions()?;
        let config = builder
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)?;
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            super::handle_connection(stream, "/metrics", Some(acceptor)).await
        });

        let _client = TcpStream::connect(addr).await?;
        tokio::task::yield_now().await;
        tokio::time::advance(super::METRICS_HANDSHAKE_TIMEOUT + Duration::from_millis(50)).await;

        let err = server
            .await
            .expect("server task panicked")
            .expect_err("handshake should time out");
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[test]
    fn build_tls_acceptor_loads_generated_pem_material() -> anyhow::Result<()> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let dir = TempDir::new()?;
        let cert_path = dir.path().join("metrics.crt");
        let key_path = dir.path().join("metrics.key");
        fs::write(&cert_path, cert.cert.pem())?;
        fs::write(&key_path, cert.signing_key.serialize_pem())?;

        let _acceptor = super::build_tls_acceptor(&cert_path, &key_path)?;
        Ok(())
    }
}
