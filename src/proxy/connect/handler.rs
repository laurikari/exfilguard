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

pub struct ConnectRequest<'a> {
    pub stream: TcpStream,
    pub peer: SocketAddr,
    pub target: &'a str,
    pub host_header: Option<&'a str>,
    pub snapshot: PolicySnapshot,
    pub app: &'a AppContext,
    pub request_bytes: usize,
    pub start: Instant,
}

/// Handles an incoming CONNECT request, delegating policy evaluation to the shared request
/// pipeline and invoking splice/bump logic via the session handler.
pub async fn handle_connect(ctx: ConnectRequest<'_>) -> Result<()> {
    let ConnectRequest {
        stream,
        peer,
        target,
        host_header,
        snapshot,
        app,
        request_bytes,
        start,
    } = ctx;
    let response_timeout = app.settings.response_body_idle_timeout();
    let mut stream = Some(stream);
    let parsed_target = match parse_connect_target(target, host_header) {
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
    );

    let parsed_request = ParsedRequest {
        method: Method::CONNECT,
        scheme: Scheme::Https,
        host: session.parsed().host.clone(),
        port: Some(session.parsed().port),
        path: session.original_target().to_string(),
    };

    let mut handler = ConnectRequestHandler {
        session: &mut session,
        stream: &mut stream,
        app,
    };

    request_pipeline::process_request(
        peer,
        &parsed_request,
        &snapshot,
        app.settings.log_queries,
        PolicyLogConfig::connect(),
        &mut handler,
    )
    .await
}

struct ConnectRequestHandler<'a> {
    session: &'a mut ConnectSession,
    stream: &'a mut Option<TcpStream>,
    app: &'a AppContext,
}

#[async_trait]
impl<'a> RequestHandler for ConnectRequestHandler<'a> {
    type Output = ();

    async fn on_allow(&mut self, outcome: policy_eval::AllowOutcome<'_>) -> Result<Self::Output> {
        let stream = self.stream.take().expect("stream present");
        let policy_eval::AllowOutcome { decision, log } = outcome;
        self.session
            .process_allow(stream, decision, log, self.app)
            .await
    }

    async fn on_deny(&mut self, outcome: policy_eval::DenyOutcome<'_>) -> Result<Self::Output> {
        self.session
            .respond_policy_deny(
                self.stream.as_mut().expect("stream present"),
                &outcome.decision,
            )
            .await
    }

    async fn on_default_deny(
        &mut self,
        _outcome: policy_eval::DefaultDenyOutcome<'_>,
    ) -> Result<Self::Output> {
        self.session
            .respond_default_denial(self.stream.as_mut().expect("stream present"))
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
        response_timeout,
        bytes_in,
        start.elapsed(),
        AccessLogBuilder::for_connect(peer, target.to_string(), target.to_string())
            .decision("ERROR"),
    )
    .await
}
