use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Result, anyhow};
use http::StatusCode;
use time::OffsetDateTime;
use tracing_subscriber::{EnvFilter, fmt};

use crate::cli::LogFormat;

const DEFAULT_FILTER: &str = "info";

pub fn init_logger(format: LogFormat) -> Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));

    match format {
        LogFormat::Json => fmt::fmt()
            .with_env_filter(filter)
            .json()
            .with_current_span(false)
            .with_span_list(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .try_init()
            .map_err(|err| anyhow!(err))?,
        LogFormat::Text => fmt::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .compact()
            .try_init()
            .map_err(|err| anyhow!(err))?,
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct AccessLogEvent {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub client: Option<String>,
    pub status: u16,
    pub decision: String,
    pub policy: Option<String>,
    pub rule: Option<String>,
    pub inspect_payload: bool,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub elapsed_ms: u128,
    pub upstream_addr: Option<String>,
    pub upstream_reused: Option<bool>,
}

#[derive(Debug)]
pub struct AccessLogBuilder {
    event: AccessLogEvent,
}

impl AccessLogBuilder {
    pub fn new(peer: SocketAddr) -> Self {
        Self {
            event: AccessLogEvent {
                client_ip: peer.ip(),
                client_port: peer.port(),
                method: String::new(),
                scheme: String::new(),
                host: String::new(),
                path: String::new(),
                client: None,
                status: 0,
                decision: String::from("UNKNOWN"),
                policy: None,
                rule: None,
                inspect_payload: true,
                bytes_in: 0,
                bytes_out: 0,
                elapsed_ms: 0,
                upstream_addr: None,
                upstream_reused: None,
            },
        }
    }

    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.event.method = method.into();
        self
    }

    pub fn scheme(mut self, scheme: impl Into<String>) -> Self {
        self.event.scheme = scheme.into();
        self
    }

    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.event.host = host.into();
        self
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.event.path = path.into();
        self
    }

    pub fn client(mut self, client: impl Into<String>) -> Self {
        self.event.client = Some(client.into());
        self
    }

    pub fn status(mut self, status: StatusCode) -> Self {
        self.event.status = status.as_u16();
        self
    }

    pub fn decision(mut self, decision: impl Into<String>) -> Self {
        self.event.decision = decision.into();
        self
    }

    pub fn policy(mut self, policy: impl Into<String>) -> Self {
        self.event.policy = Some(policy.into());
        self
    }

    pub fn rule(mut self, rule: impl Into<String>) -> Self {
        self.event.rule = Some(rule.into());
        self
    }

    pub fn inspect_payload(mut self, inspect: bool) -> Self {
        self.event.inspect_payload = inspect;
        self
    }

    pub fn bytes_in(mut self, bytes: u64) -> Self {
        self.event.bytes_in = bytes;
        self
    }

    pub fn bytes_out(mut self, bytes: u64) -> Self {
        self.event.bytes_out = bytes;
        self
    }

    pub fn bytes(mut self, in_bytes: u64, out_bytes: u64) -> Self {
        self.event.bytes_in = in_bytes;
        self.event.bytes_out = out_bytes;
        self
    }

    pub fn elapsed(mut self, elapsed: Duration) -> Self {
        self.event.elapsed_ms = elapsed.as_millis();
        self
    }

    pub fn upstream_addr(mut self, addr: impl Into<String>) -> Self {
        self.event.upstream_addr = Some(addr.into());
        self
    }

    pub fn upstream_reused(mut self, reused: bool) -> Self {
        self.event.upstream_reused = Some(reused);
        self
    }

    pub fn build(self) -> AccessLogEvent {
        self.event
    }

    pub fn log(self) {
        log_access(self.build());
    }

    pub fn for_connect(peer: SocketAddr, host: impl Into<String>, path: impl Into<String>) -> Self {
        Self::new(peer)
            .method("CONNECT")
            .scheme("https")
            .host(host)
            .path(path)
    }
}

pub fn log_access(event: AccessLogEvent) {
    let AccessLogEvent {
        client_ip,
        client_port,
        method,
        scheme,
        host,
        path,
        client,
        status,
        decision,
        policy,
        rule,
        inspect_payload,
        bytes_in,
        bytes_out,
        elapsed_ms,
        upstream_addr,
        upstream_reused,
    } = event;

    let now = OffsetDateTime::now_utc();
    let (year, month, day) = now.to_calendar_date();
    let (hour, minute, second) = now.to_hms();
    let millisecond = now.millisecond();
    let month_number: u8 = month.into();
    let ts = format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millisecond:03}Z",
        month = month_number
    );
    let policy_field = policy.as_deref().unwrap_or_default();
    let rule_field = rule.as_deref().unwrap_or_default();

    tracing::info!(
        target = "access_log",
        ts,
        client_ip = %client_ip,
        method,
        scheme,
        host,
        path,
        status,
        decision,
        policy = policy_field,
        rule = rule_field,
        inspect_payload,
        bytes_in,
        bytes_out,
        elapsed_ms,
        client_port,
        upstream_addr = upstream_addr.unwrap_or_default(),
        upstream_reused = upstream_reused.unwrap_or(false)
    );

    crate::metrics::record_request(
        client.as_deref(),
        policy.as_deref(),
        &decision,
        &method,
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Duration::from_millis(elapsed_ms as u64),
    );
}
