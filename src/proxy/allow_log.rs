use std::time::Duration;

use http::StatusCode;

use crate::proxy::policy_eval::{AllowDecision, RequestLogContext};

pub struct AllowLogStats {
    pub status: StatusCode,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub elapsed: Duration,
    pub upstream_addr: String,
    pub upstream_reused: bool,
}

pub fn log_allow_success(log: RequestLogContext, allow: &AllowDecision, stats: AllowLogStats) {
    log.access_log_builder()
        .status(stats.status)
        .decision("ALLOW")
        .client(allow.client.as_ref())
        .policy(allow.policy.as_ref())
        .rule(allow.rule.as_ref())
        .inspect_payload(allow.inspect_payload)
        .bytes(stats.bytes_in, stats.bytes_out)
        .elapsed(stats.elapsed)
        .upstream_addr(stats.upstream_addr)
        .upstream_reused(stats.upstream_reused)
        .log();
}
