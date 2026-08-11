use std::{net::SocketAddr, time::Instant};

use anyhow::Result;
use http::{Method, StatusCode};
use tokio::net::TcpStream;
use tracing::warn;

use crate::{
    config::Scheme,
    logging::AccessLogBuilder,
    policy::matcher::PolicySnapshot,
    proxy::{
        AppContext,
        http::respond_with_access_log,
        policy_eval::{self, PolicyLogConfig},
        request::ParsedRequest,
        request_pipeline::{self, RequestHandler},
    },
};
use async_trait::async_trait;

use super::{session::ConnectSession, target::parse_connect_target};

pub(crate) struct ConnectRequest<'a> {
    pub(crate) stream: TcpStream,
    pub(crate) prefetched: Vec<u8>,
    pub(crate) peer: SocketAddr,
    pub(crate) target: &'a str,
    pub(crate) snapshot: PolicySnapshot,
    pub(crate) app: &'a AppContext,
    pub(crate) request_bytes: usize,
    pub(crate) start: Instant,
}

/// Handles an incoming CONNECT request, delegating policy evaluation to the shared request
/// pipeline and invoking splice/bump logic via the session handler.
pub(crate) async fn handle_connect(
    ctx: ConnectRequest<'_>,
    authorization_token: Option<std::sync::Arc<crate::authorization::AuthorizationToken>>,
) -> Result<()> {
    let ConnectRequest {
        stream,
        prefetched,
        peer,
        target,
        snapshot,
        app,
        request_bytes,
        start,
    } = ctx;
    let response_timeout = app.settings.response_body_idle_timeout();
    let mut stream = Some(stream);
    let mut prefetched = Some(prefetched);
    let parsed_target = match parse_connect_target(target) {
        Ok(parsed) => parsed,
        Err(err) => {
            warn!(peer = %peer, target, error = %err, "invalid CONNECT target");
            respond_invalid_connect_target(
                stream.as_mut().expect("stream present"),
                peer,
                target,
                response_timeout,
                request_bytes as u64,
                start,
            )
            .await?;
            return Ok(());
        }
    };

    let mut session = ConnectSession::new(
        peer,
        target.to_string(),
        parsed_target,
        request_bytes as u64,
        start,
        response_timeout,
        authorization_token.clone(),
    );

    let parsed_request = ParsedRequest {
        method: Method::CONNECT,
        scheme: Scheme::Https,
        authority: session.original_target().to_string(),
        host: session.parsed().host.clone(),
        port: Some(session.parsed().port),
        path: session.original_target().to_string(),
        policy_path: session.original_target().to_string(),
        flow: None,
    };

    let mut handler = ConnectRequestHandler {
        session: &mut session,
        stream: &mut stream,
        prefetched: &mut prefetched,
        app,
        peer,
        snapshot: &snapshot,
        parsed_request: &parsed_request,
    };
    let policy_authorization_token = authorization_token.clone();

    request_pipeline::process_request(
        peer,
        &parsed_request,
        &snapshot,
        app.authorization
            .as_deref()
            .map(|authorization| (authorization, policy_authorization_token.as_ref())),
        None,
        app.settings.log_queries,
        PolicyLogConfig::connect_tunnel(),
        &mut handler,
    )
    .await
}

struct ConnectRequestHandler<'a> {
    session: &'a mut ConnectSession,
    stream: &'a mut Option<TcpStream>,
    prefetched: &'a mut Option<Vec<u8>>,
    app: &'a AppContext,
    peer: SocketAddr,
    snapshot: &'a PolicySnapshot,
    parsed_request: &'a ParsedRequest,
}

#[async_trait]
impl<'a> RequestHandler for ConnectRequestHandler<'a> {
    type Output = ();

    async fn on_allow(&mut self, outcome: policy_eval::AllowOutcome<'_>) -> Result<Self::Output> {
        let stream = self.stream.take().expect("stream present");
        let prefetched = self.prefetched.take().expect("prefetched bytes present");
        let policy_eval::AllowOutcome { decision, log } = outcome;
        self.session
            .process_tunnel_allow(stream, prefetched, decision, log, self.app)
            .await
    }

    async fn on_deny(&mut self, outcome: policy_eval::DenyOutcome<'_>) -> Result<Self::Output> {
        self.session
            .respond_policy_deny(
                self.stream.as_mut().expect("stream present"),
                &outcome.decision,
                &outcome.log,
            )
            .await
    }

    async fn on_default_deny(
        &mut self,
        outcome: policy_eval::DefaultDenyOutcome<'_>,
    ) -> Result<Self::Output> {
        let request = self.parsed_request.as_policy_request();
        if self
            .snapshot
            .resolve_client(self.peer.ip())
            .is_some_and(|client| client.authorization_service.is_some())
        {
            return self
                .session
                .respond_default_denial(self.stream.as_mut().expect("stream present"), &outcome.log)
                .await;
        }
        if let Some(preflight) = self
            .snapshot
            .evaluate_tls_bump_preflight(self.peer.ip(), &request)
        {
            let stream = self.stream.take().expect("stream present");
            let prefetched = self.prefetched.take().expect("prefetched bytes present");
            return self
                .session
                .process_tls_bump_preflight(
                    stream,
                    prefetched,
                    preflight.client,
                    outcome.log,
                    self.app,
                )
                .await;
        }
        self.session
            .respond_default_denial(self.stream.as_mut().expect("stream present"), &outcome.log)
            .await
    }

    async fn on_tls_bump_preflight(
        &mut self,
        outcome: policy_eval::TlsBumpPreflightOutcome<'_>,
    ) -> Result<Self::Output> {
        let stream = self.stream.take().expect("stream present");
        let prefetched = self.prefetched.take().expect("prefetched bytes present");
        self.session
            .process_tls_bump_preflight(stream, prefetched, outcome.client, outcome.log, self.app)
            .await
    }

    async fn on_auth_deny(
        &mut self,
        log: policy_eval::RequestLogContext<'_>,
    ) -> Result<Self::Output> {
        self.respond_auth_deny(log).await
    }

    async fn on_authorization_service_error(
        &mut self,
        log: policy_eval::RequestLogContext<'_>,
    ) -> Result<Self::Output> {
        respond_with_access_log(
            self.stream.as_mut().expect("stream present"),
            StatusCode::BAD_GATEWAY,
            None,
            b"authorization service failed\r\n",
            None,
            self.app.settings.response_body_idle_timeout(),
            self.session.request_bytes(),
            self.session.elapsed(),
            log.access_log_builder()
                .status(StatusCode::BAD_GATEWAY)
                .decision("ERROR")
                .error_reason("authorization_service_failed"),
        )
        .await
    }
}

impl ConnectRequestHandler<'_> {
    async fn respond_auth_deny(&mut self, log: policy_eval::RequestLogContext<'_>) -> Result<()> {
        respond_with_access_log(
            self.stream.as_mut().expect("stream present"),
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            None,
            b"proxy authentication required\r\n",
            Some("ExfilGuard"),
            self.app.settings.response_body_idle_timeout(),
            self.session.request_bytes(),
            self.session.elapsed(),
            log.access_log_builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .decision("DENY")
                .error_reason("proxy_authentication"),
        )
        .await
    }
}

async fn respond_invalid_connect_target(
    stream: &mut TcpStream,
    peer: SocketAddr,
    target: &str,
    response_timeout: std::time::Duration,
    bytes_in: u64,
    start: Instant,
) -> Result<()> {
    respond_with_access_log(
        stream,
        StatusCode::BAD_REQUEST,
        None,
        b"invalid CONNECT target\r\n",
        None,
        response_timeout,
        bytes_in,
        start.elapsed(),
        AccessLogBuilder::for_connect(peer, target.to_string(), target.to_string())
            .decision("ERROR"),
    )
    .await
}
