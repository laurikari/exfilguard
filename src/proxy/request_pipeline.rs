use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;

use crate::authorization::{AuthorizationServices, AuthorizationToken};
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
pub(crate) trait RequestHandler {
    type Output;

    async fn on_allow(&mut self, outcome: policy_eval::AllowOutcome<'_>) -> Result<Self::Output>;

    async fn on_deny(&mut self, outcome: policy_eval::DenyOutcome<'_>) -> Result<Self::Output>;

    async fn on_default_deny(
        &mut self,
        outcome: policy_eval::DefaultDenyOutcome<'_>,
    ) -> Result<Self::Output>;

    async fn on_tls_bump_preflight(
        &mut self,
        outcome: policy_eval::TlsBumpPreflightOutcome<'_>,
    ) -> Result<Self::Output>
    where
        Self: Send,
    {
        self.on_default_deny(policy_eval::DefaultDenyOutcome { log: outcome.log })
            .await
    }

    async fn on_auth_deny(
        &mut self,
        log: policy_eval::RequestLogContext<'_>,
    ) -> Result<Self::Output>;

    async fn on_authorization_service_error(
        &mut self,
        log: policy_eval::RequestLogContext<'_>,
    ) -> Result<Self::Output>;

    async fn on_request_timeout(
        &mut self,
        log: policy_eval::RequestLogContext<'_>,
    ) -> Result<Self::Output>
    where
        Self: Send,
    {
        self.on_default_deny(policy_eval::DefaultDenyOutcome { log })
            .await
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn process_request<H: RequestHandler + Send>(
    peer: SocketAddr,
    parsed: &ParsedRequest,
    snapshot: &PolicySnapshot,
    authorization: Option<(
        &AuthorizationServices,
        Option<&std::sync::Arc<AuthorizationToken>>,
    )>,
    request_deadline: Option<std::time::Instant>,
    log_queries: bool,
    log_config: PolicyLogConfig,
    handler: &mut H,
) -> Result<H::Output> {
    let authorization_service = snapshot
        .resolve_client(peer.ip())
        .and_then(|client| client.authorization_service.as_ref());
    let policy_outcome = if let Some(service_name) = authorization_service {
        let Some((authorization, authorization_token)) = authorization else {
            let log = policy_eval::RequestLogContext::new(peer, parsed, log_queries);
            tracing::error!(
                peer = %peer,
                request_id = log.request_id(),
                authorization_service = %service_name,
                "client references an unavailable authorization service"
            );
            return handler.on_auth_deny(log).await;
        };
        let Some(token) = authorization_token else {
            let log = policy_eval::RequestLogContext::new(peer, parsed, log_queries);
            tracing::warn!(
                peer = %peer,
                request_id = log.request_id(),
                "delegated request has no authorization token"
            );
            return handler.on_auth_deny(log).await;
        };
        let Some(service) = authorization.service(service_name) else {
            let log = policy_eval::RequestLogContext::new(peer, parsed, log_queries);
            tracing::error!(
                peer = %peer,
                request_id = log.request_id(),
                authorization_service = %service_name,
                "client references an unavailable authorization service"
            );
            return handler.on_auth_deny(log).await;
        };
        let authorization_policy = match service.resolve(token, peer, request_deadline).await {
            Ok(policy) => policy,
            Err(crate::authorization::AuthorizationError::Timeout) => {
                let log = policy_eval::RequestLogContext::new(peer, parsed, log_queries);
                tracing::warn!(
                    peer = %peer,
                    request_id = log.request_id(),
                    authorization_token_id = token.correlation(),
                    "proxy authorization exceeded request deadline"
                );
                return handler.on_request_timeout(log).await;
            }
            Err(crate::authorization::AuthorizationError::Denied) => {
                let log = policy_eval::RequestLogContext::new(peer, parsed, log_queries);
                tracing::warn!(
                    peer = %peer,
                    request_id = log.request_id(),
                    authorization_token_id = token.correlation(),
                    "proxy authorization denied"
                );
                return handler.on_auth_deny(log).await;
            }
            Err(crate::authorization::AuthorizationError::Unavailable) => {
                let log = policy_eval::RequestLogContext::new(peer, parsed, log_queries);
                tracing::warn!(
                    peer = %peer,
                    request_id = log.request_id(),
                    authorization_token_id = token.correlation(),
                    "authorization service failed"
                );
                return handler.on_authorization_service_error(log).await;
            }
        };
        policy_eval::evaluate_delegated_request(
            peer,
            parsed,
            snapshot,
            (token.clone(), authorization_policy),
            log_queries,
            log_config,
        )
    } else {
        policy_eval::evaluate_request(peer, parsed, snapshot, log_queries, log_config)
    };
    dispatch_policy_outcome(policy_outcome, handler).await
}

async fn dispatch_policy_outcome<H: RequestHandler + Send>(
    policy_outcome: PolicyOutcome<'_>,
    handler: &mut H,
) -> Result<H::Output> {
    let inflight_client = match &policy_outcome {
        PolicyOutcome::Allow(outcome) => Some(outcome.decision.client.as_ref()),
        PolicyOutcome::Deny(outcome) => Some(outcome.decision.client.as_ref()),
        PolicyOutcome::TlsBumpPreflight(outcome) => Some(outcome.client.as_ref()),
        PolicyOutcome::DefaultDeny(_) => None,
    };
    crate::metrics::inc_inflight(inflight_client);
    struct InflightGuard(Option<String>);
    impl Drop for InflightGuard {
        fn drop(&mut self) {
            crate::metrics::dec_inflight(self.0.as_deref());
        }
    }
    let _guard = InflightGuard(inflight_client.map(str::to_owned));
    match policy_outcome {
        PolicyOutcome::Allow(outcome) => handler.on_allow(outcome).await,
        PolicyOutcome::Deny(outcome) => handler.on_deny(outcome).await,
        PolicyOutcome::TlsBumpPreflight(outcome) => handler.on_tls_bump_preflight(outcome).await,
        PolicyOutcome::DefaultDeny(outcome) => handler.on_default_deny(outcome).await,
    }
}
