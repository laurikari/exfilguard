use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;

use crate::policy::matcher::PolicySnapshot;
use crate::proxy::policy_eval::{self, PolicyLogConfig, PolicyOutcome};
use crate::proxy::request::ParsedRequest;

/// The core abstraction for request processing.
///
/// This trait allows the proxy to use the same policy evaluation engine for
/// multiple protocols (HTTP/1, H2, CONNECT). Implementations define what
/// happens after a policy decision is made—e.g., establishing a TCP splice
/// for CONNECT or forwarding an HTTP request to an upstream pool.
#[async_trait]
pub trait RequestHandler {
    type Output;

    async fn on_allow(&mut self, outcome: policy_eval::AllowOutcome<'_>) -> Result<Self::Output>;

    async fn on_deny(&mut self, outcome: policy_eval::DenyOutcome<'_>) -> Result<Self::Output>;

    async fn on_default_deny(
        &mut self,
        outcome: policy_eval::DefaultDenyOutcome<'_>,
    ) -> Result<Self::Output>;
}

pub async fn process_request<H: RequestHandler>(
    peer: SocketAddr,
    parsed: &ParsedRequest,
    snapshot: &PolicySnapshot,
    log_queries: bool,
    log_config: PolicyLogConfig,
    handler: &mut H,
) -> Result<H::Output> {
    let policy_outcome =
        policy_eval::evaluate_request(peer, parsed, snapshot, log_queries, log_config);
    match policy_outcome {
        PolicyOutcome::Allow(outcome) => handler.on_allow(outcome).await,
        PolicyOutcome::Deny(outcome) => handler.on_deny(outcome).await,
        PolicyOutcome::DefaultDeny(outcome) => handler.on_default_deny(outcome).await,
    }
}
