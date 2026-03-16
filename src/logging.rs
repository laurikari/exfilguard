use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Result, anyhow};
use http::StatusCode;
use time::OffsetDateTime;
use tracing::Level;
use tracing_subscriber::{EnvFilter, fmt};

use crate::cli::LogFormat;
use crate::proxy::request::RequestFlowContext;

const DEFAULT_FILTER: &str = "info";

macro_rules! log_with_level {
    ($level:expr, $($tt:tt)*) => {
        match $level {
            ::tracing::Level::ERROR => ::tracing::error!($($tt)*),
            ::tracing::Level::WARN => ::tracing::warn!($($tt)*),
            ::tracing::Level::INFO => ::tracing::info!($($tt)*),
            ::tracing::Level::DEBUG => ::tracing::debug!($($tt)*),
            ::tracing::Level::TRACE => ::tracing::trace!($($tt)*),
        }
    };
}

pub(crate) use log_with_level;

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
    pub cache_lookup: Option<String>,
    pub cache_store: Option<String>,
    pub client: Option<String>,
    pub status: u16,
    pub decision: String,
    pub policy: Option<String>,
    pub rule: Option<String>,
    pub policy_basis: Option<String>,
    pub session_id: Option<String>,
    pub outer_method: Option<String>,
    pub inner_method: Option<String>,
    pub effective_mode: Option<String>,
    pub transport: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub elapsed_ms: u128,
    pub upstream_addr: Option<String>,
    pub upstream_reused: Option<bool>,
    pub error_reason: Option<String>,
    pub error_detail: Option<String>,
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
                cache_lookup: None,
                cache_store: None,
                client: None,
                status: 0,
                decision: String::from("UNKNOWN"),
                policy: None,
                rule: None,
                policy_basis: None,
                session_id: None,
                outer_method: None,
                inner_method: None,
                effective_mode: None,
                transport: None,
                bytes_in: 0,
                bytes_out: 0,
                elapsed_ms: 0,
                upstream_addr: None,
                upstream_reused: None,
                error_reason: None,
                error_detail: None,
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

    pub fn cache_lookup(mut self, value: impl Into<String>) -> Self {
        self.event.cache_lookup = Some(value.into());
        self
    }

    pub fn cache_store(mut self, value: impl Into<String>) -> Self {
        self.event.cache_store = Some(value.into());
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
        let rule = rule.into();
        self.event.policy_basis = Some(rule.clone());
        self.event.rule = Some(rule);
        self
    }

    pub fn policy_basis(mut self, basis: impl Into<String>) -> Self {
        self.event.policy_basis = Some(basis.into());
        self
    }

    pub fn session_id(mut self, session_id: impl Into<String>) -> Self {
        self.event.session_id = Some(session_id.into());
        self
    }

    pub fn outer_method(mut self, method: impl Into<String>) -> Self {
        self.event.outer_method = Some(method.into());
        self
    }

    pub fn inner_method(mut self, method: impl Into<String>) -> Self {
        self.event.inner_method = Some(method.into());
        self
    }

    pub fn effective_mode(mut self, mode: impl Into<String>) -> Self {
        self.event.effective_mode = Some(mode.into());
        self
    }

    pub fn transport(mut self, transport: impl Into<String>) -> Self {
        self.event.transport = Some(transport.into());
        self
    }

    pub fn apply_flow_context(
        mut self,
        flow: Option<&RequestFlowContext>,
        inner_method: &str,
    ) -> Self {
        if let Some(flow) = flow {
            self.event.session_id = Some(flow.session_id.to_string());
            self.event.outer_method = Some(flow.outer_method.to_string());
            self.event.effective_mode = Some(flow.effective_mode.as_str().to_string());
            if flow.outer_method.as_ref() != inner_method {
                self.event.inner_method = Some(inner_method.to_string());
            }
        }
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

    pub fn error_reason(mut self, reason: impl Into<String>) -> Self {
        self.event.error_reason = Some(reason.into());
        self
    }

    pub fn error_detail(mut self, detail: impl Into<String>) -> Self {
        self.event.error_detail = Some(detail.into());
        self
    }

    pub fn build(self) -> AccessLogEvent {
        self.event
    }

    pub fn log(self) {
        log_access(self.build());
    }

    pub fn log_with_level(self, level: Level) {
        log_access_with_level(self.build(), level);
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
    log_access_with_level(event, Level::INFO);
}

fn metrics_effective_mode<'a>(method: &str, effective_mode: Option<&'a str>) -> &'a str {
    match effective_mode {
        Some(mode) if !mode.is_empty() => mode,
        _ if method.eq_ignore_ascii_case("CONNECT") => "unknown",
        _ => "direct",
    }
}

pub fn log_access_with_level(event: AccessLogEvent, level: Level) {
    let AccessLogEvent {
        client_ip,
        client_port,
        method,
        scheme,
        host,
        path,
        cache_lookup,
        cache_store,
        client,
        status,
        decision,
        policy,
        rule,
        policy_basis,
        session_id,
        outer_method,
        inner_method,
        effective_mode,
        transport,
        bytes_in,
        bytes_out,
        elapsed_ms,
        upstream_addr,
        upstream_reused,
        error_reason,
        error_detail,
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

    let cache_lookup_field = cache_lookup.as_deref();
    let cache_store_field = cache_store.as_deref();
    let client_field = client.as_deref();
    let policy_field = policy.as_deref();
    let rule_field = rule.as_deref();
    let policy_basis_field = policy_basis.as_deref();
    let session_id_field = session_id.as_deref();
    let outer_method_field = outer_method.as_deref();
    let inner_method_field = inner_method.as_deref();
    let effective_mode_field = effective_mode.as_deref();
    let transport_field = transport.as_deref();
    let upstream_addr_field = upstream_addr.as_deref();
    let upstream_reused_field = upstream_reused;
    let error_reason_field = error_reason.as_deref();
    let error_detail_field = error_detail.as_deref();

    log_with_level!(
        level,
        target = "access_log",
        ts,
        client_ip = %client_ip,
        method,
        scheme,
        host,
        path,
        cache_lookup = cache_lookup_field,
        cache_store = cache_store_field,
        client = client_field,
        status,
        decision,
        policy = policy_field,
        rule = rule_field,
        policy_basis = policy_basis_field,
        session_id = session_id_field,
        outer_method = outer_method_field,
        inner_method = inner_method_field,
        effective_mode = effective_mode_field,
        transport = transport_field,
        bytes_in,
        bytes_out,
        elapsed_ms,
        client_port,
        upstream_addr = upstream_addr_field,
        upstream_reused = upstream_reused_field,
        error_reason = error_reason_field,
        error_detail = error_detail_field
    );

    if level == Level::INFO {
        let metrics_mode = metrics_effective_mode(&method, effective_mode.as_deref());
        crate::metrics::record_request(
            client.as_deref(),
            policy.as_deref(),
            &decision,
            metrics_mode,
            &method,
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Duration::from_millis(elapsed_ms as u64),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct BufferWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buf.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufferWriter {
        type Writer = BufferWriter;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn strip_ansi(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' && chars.peek() == Some(&'[') {
                chars.next();
                for next in chars.by_ref() {
                    if next == 'm' {
                        break;
                    }
                }
                continue;
            }
            out.push(ch);
        }
        out
    }

    #[test]
    fn access_log_includes_cache_fields() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = BufferWriter {
            buf: buffer.clone(),
        };
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_target(false)
            .without_time()
            .compact()
            .finish();

        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let event = AccessLogBuilder::new(peer)
            .method("GET")
            .scheme("http")
            .host("example.com")
            .path("/resource")
            .decision("ALLOW")
            .status(StatusCode::OK)
            .cache_lookup("hit")
            .cache_store("stored")
            .build();

        tracing::subscriber::with_default(subscriber, || {
            log_access(event);
        });

        let output = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        let output = strip_ansi(&output);
        assert!(
            output.contains("cache_lookup=\"hit\""),
            "missing cache_lookup in output: {output}"
        );
        assert!(
            output.contains("cache_store=\"stored\""),
            "missing cache_store in output: {output}"
        );
    }
}
