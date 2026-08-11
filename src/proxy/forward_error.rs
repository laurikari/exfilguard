use anyhow::Error;
use http::StatusCode;
use thiserror::Error;
use tracing::warn;

use crate::authorization::FinalizationRejection;
use crate::proxy::{
    http::{BodyTooLarge, InvalidRequestBody},
    policy_eval::RequestLogContext,
    resolver::PrivateAddressError,
};

#[derive(Debug, Error)]
#[error("request timed out")]
pub struct RequestTimeout;

#[derive(Debug, Error)]
#[error("client request body timed out")]
pub struct ClientBodyIdleTimeout;

#[derive(Debug, Error)]
#[error("{detail}")]
pub struct CredentialRequestRejected {
    pub status: StatusCode,
    pub detail: &'static str,
}

#[derive(Debug, Error)]
#[error("credential preparation failed")]
struct CredentialPreparationFailed {
    #[source]
    source: Error,
}

pub(crate) fn credential_preparation_failed(source: Error) -> Error {
    CredentialPreparationFailed { source }.into()
}

pub(crate) fn credential_finalization_failed(source: Error) -> Error {
    if let Some(rejection) = source.downcast_ref::<FinalizationRejection>() {
        return CredentialRequestRejected::from_finalization(*rejection).into();
    }
    credential_preparation_failed(source)
}

impl CredentialRequestRejected {
    pub const fn expectation_failed() -> Self {
        Self {
            status: StatusCode::EXPECTATION_FAILED,
            detail: "credential-bearing requests must not use Expect: 100-continue",
        }
    }

    pub const fn body_not_allowed() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            detail: "client credential limit does not permit request body access",
        }
    }

    const fn from_finalization(rejection: FinalizationRejection) -> Self {
        match rejection {
            FinalizationRejection::Expectation => Self::expectation_failed(),
            FinalizationRejection::Trailers => Self {
                status: StatusCode::FORBIDDEN,
                detail: "credential-bearing requests must not declare trailers",
            },
            FinalizationRejection::ProtectedHeader => Self {
                status: StatusCode::FORBIDDEN,
                detail: "client supplied a protected header",
            },
        }
    }
}

#[derive(Debug, Error)]
#[error("upstream response failed after an informational response was forwarded: {source}")]
pub struct InformationalResponseStarted {
    #[source]
    source: Error,
}

impl InformationalResponseStarted {
    pub fn new(source: Error) -> Self {
        Self { source }
    }
}

#[derive(Debug, Error)]
#[error("response forwarding failed after downstream response started: {source}")]
pub struct ResponseAlreadyStarted {
    pub status: StatusCode,
    pub bytes_to_client: u64,
    #[source]
    pub source: Error,
}

impl ResponseAlreadyStarted {
    pub fn new(status: StatusCode, bytes_to_client: u64, source: Error) -> Self {
        Self {
            status,
            bytes_to_client,
            source,
        }
    }
}

#[derive(Debug, Error)]
#[error(
    "HTTP/2 request for {requested_host}:{requested_port} does not match upstream {upstream_host}:{upstream_port}"
)]
pub struct MisdirectedRequest {
    pub upstream_host: String,
    pub upstream_port: u16,
    pub requested_host: String,
    pub requested_port: u16,
}

impl MisdirectedRequest {
    pub fn new(
        upstream_host: String,
        upstream_port: u16,
        requested_host: String,
        requested_port: u16,
    ) -> Self {
        Self {
            upstream_host,
            upstream_port,
            requested_host,
            requested_port,
        }
    }
}

/// Normalized classification of forwarding failures so HTTP/1.1 and HTTP/2 can react consistently.
pub enum ForwardErrorKind<'a> {
    ResponseAlreadyStarted(&'a ResponseAlreadyStarted),
    RequestTimeout,
    ClientBodyIdleTimeout,
    CredentialPreparationFailed,
    CredentialRequestRejected(&'a CredentialRequestRejected),
    InvalidRequestBody(&'a InvalidRequestBody),
    BodyTooLarge(&'a BodyTooLarge),
    PrivateAddress(&'a PrivateAddressError),
    MisdirectedRequest(&'a MisdirectedRequest),
    UpstreamClosed,
    Other,
}

impl ForwardErrorKind<'_> {
    pub fn as_metric_label(&self) -> &'static str {
        match self {
            Self::ResponseAlreadyStarted(_) => "response_body_failed",
            Self::RequestTimeout => "request_timeout",
            Self::ClientBodyIdleTimeout => "request_body_timeout",
            Self::CredentialPreparationFailed => "credential_preparation_failed",
            Self::CredentialRequestRejected(_) => "credential_request_rejected",
            Self::InvalidRequestBody(_) => "invalid_request_body",
            Self::BodyTooLarge(_) => "body_too_large",
            Self::PrivateAddress(_) => "private_address",
            Self::MisdirectedRequest(_) => "misdirected_request",
            Self::UpstreamClosed => "upstream_closed",
            Self::Other => "other",
        }
    }
}

pub fn classify_forward_error(err: &Error) -> ForwardErrorKind<'_> {
    if let Some(started) = err.downcast_ref::<InformationalResponseStarted>() {
        classify_forward_error(&started.source)
    } else if let Some(started) = err.downcast_ref::<ResponseAlreadyStarted>() {
        ForwardErrorKind::ResponseAlreadyStarted(started)
    } else if err.downcast_ref::<RequestTimeout>().is_some() {
        ForwardErrorKind::RequestTimeout
    } else if err.downcast_ref::<ClientBodyIdleTimeout>().is_some() {
        ForwardErrorKind::ClientBodyIdleTimeout
    } else if err.downcast_ref::<CredentialPreparationFailed>().is_some() {
        ForwardErrorKind::CredentialPreparationFailed
    } else if let Some(rejected) = err.downcast_ref::<CredentialRequestRejected>() {
        ForwardErrorKind::CredentialRequestRejected(rejected)
    } else if let Some(invalid) = err.downcast_ref::<InvalidRequestBody>() {
        ForwardErrorKind::InvalidRequestBody(invalid)
    } else if let Some(body) = err.downcast_ref::<BodyTooLarge>() {
        ForwardErrorKind::BodyTooLarge(body)
    } else if let Some(private) = err.downcast_ref::<PrivateAddressError>() {
        ForwardErrorKind::PrivateAddress(private)
    } else if let Some(misdirected) = err.downcast_ref::<MisdirectedRequest>() {
        ForwardErrorKind::MisdirectedRequest(misdirected)
    } else if err.downcast_ref::<UpstreamClosed>().is_some() {
        ForwardErrorKind::UpstreamClosed
    } else {
        ForwardErrorKind::Other
    }
}

pub fn log_forward_error(kind: &ForwardErrorKind<'_>, log: &RequestLogContext<'_>, err: &Error) {
    let peer = log.peer();
    let request_id = log.request_id();
    let method = log.method();
    let host = log.host();
    let path = log.logged_path();
    let session_id = log.session_id();
    let outer_method = log.outer_method();
    let inner_method = log.inner_method();
    let effective_mode = log.effective_mode();

    match kind {
        ForwardErrorKind::ResponseAlreadyStarted(_) => warn!(
            peer = %peer,
            request_id = request_id,
            method,
            host,
            path,
            session_id = session_id,
            outer_method = outer_method,
            inner_method = inner_method,
            effective_mode = effective_mode,
            error = %err,
            "response forwarding failed after downstream response started"
        ),
        ForwardErrorKind::RequestTimeout => warn!(
            peer = %peer,
            request_id = request_id,
            method,
            host,
            path,
            session_id = session_id,
            outer_method = outer_method,
            inner_method = inner_method,
            effective_mode = effective_mode,
            "request timed out while forwarding"
        ),
        ForwardErrorKind::ClientBodyIdleTimeout => warn!(
            peer = %peer,
            request_id = request_id,
            method,
            host,
            path,
            session_id = session_id,
            outer_method = outer_method,
            inner_method = inner_method,
            effective_mode = effective_mode,
            "client request body timed out"
        ),
        ForwardErrorKind::CredentialPreparationFailed => warn!(
            peer = %peer,
            request_id = request_id,
            method,
            host,
            path,
            session_id = session_id,
            outer_method = outer_method,
            inner_method = inner_method,
            effective_mode = effective_mode,
            "credential preparation failed before origin forwarding"
        ),
        ForwardErrorKind::CredentialRequestRejected(_) => warn!(
            peer = %peer,
            request_id = request_id,
            method,
            host,
            path,
            session_id = session_id,
            outer_method = outer_method,
            inner_method = inner_method,
            effective_mode = effective_mode,
            error = %err,
            "credential-bearing request rejected before forwarding"
        ),
        ForwardErrorKind::InvalidRequestBody(_) => warn!(
            peer = %peer,
            request_id = request_id,
            method,
            host,
            path,
            session_id = session_id,
            outer_method = outer_method,
            inner_method = inner_method,
            effective_mode = effective_mode,
            error = %err,
            "invalid request body"
        ),
        ForwardErrorKind::PrivateAddress(private_err) => warn!(
            peer = %peer,
            request_id = request_id,
            method,
            host,
            path,
            session_id = session_id,
            outer_method = outer_method,
            inner_method = inner_method,
            effective_mode = effective_mode,
            port = private_err.port,
            "policy allow decision rejected private upstream address"
        ),
        ForwardErrorKind::MisdirectedRequest(misdirected) => warn!(
            peer = %peer,
            request_id = request_id,
            method,
            host,
            path,
            session_id = session_id,
            outer_method = outer_method,
            inner_method = inner_method,
            effective_mode = effective_mode,
            upstream_host = %misdirected.upstream_host,
            upstream_port = misdirected.upstream_port,
            requested_host = %misdirected.requested_host,
            requested_port = misdirected.requested_port,
            "HTTP/2 request did not match existing upstream connection"
        ),
        ForwardErrorKind::UpstreamClosed => warn!(
            peer = %peer,
            request_id = request_id,
            method,
            host,
            path,
            session_id = session_id,
            outer_method = outer_method,
            inner_method = inner_method,
            effective_mode = effective_mode,
            error = %err,
            "upstream closed connection before response headers"
        ),
        ForwardErrorKind::Other => warn!(
            peer = %peer,
            request_id = request_id,
            method,
            host,
            path,
            session_id = session_id,
            outer_method = outer_method,
            inner_method = inner_method,
            effective_mode = effective_mode,
            error = %err,
            "upstream request failed"
        ),
        ForwardErrorKind::BodyTooLarge(_) => {}
    }
}

#[derive(Debug, Error)]
#[error("upstream closed connection before sending response headers")]
pub struct UpstreamClosed;

#[cfg(test)]
mod tests {
    use super::{ForwardErrorKind, MisdirectedRequest, ResponseAlreadyStarted};
    use crate::{
        proxy::http::{BodyTooLarge, InvalidRequestBody},
        proxy::resolver::PrivateAddressError,
    };

    #[test]
    fn metric_labels_cover_all_forward_error_kinds() {
        let body = BodyTooLarge { bytes_read: 42 };
        let invalid = InvalidRequestBody::new(4, "bad chunk");
        let private = PrivateAddressError::new("example.com", 443, "connect target");
        let misdirected = MisdirectedRequest::new(
            "upstream.test".to_string(),
            443,
            "requested.test".to_string(),
            8443,
        );

        assert_eq!(
            ForwardErrorKind::ResponseAlreadyStarted(&ResponseAlreadyStarted::new(
                http::StatusCode::OK,
                10,
                anyhow::anyhow!("bad body"),
            ))
            .as_metric_label(),
            "response_body_failed"
        );
        assert_eq!(
            ForwardErrorKind::RequestTimeout.as_metric_label(),
            "request_timeout"
        );
        assert_eq!(
            ForwardErrorKind::ClientBodyIdleTimeout.as_metric_label(),
            "request_body_timeout"
        );
        assert_eq!(
            ForwardErrorKind::CredentialPreparationFailed.as_metric_label(),
            "credential_preparation_failed"
        );
        assert_eq!(
            ForwardErrorKind::InvalidRequestBody(&invalid).as_metric_label(),
            "invalid_request_body"
        );
        assert_eq!(
            ForwardErrorKind::BodyTooLarge(&body).as_metric_label(),
            "body_too_large"
        );
        assert_eq!(
            ForwardErrorKind::PrivateAddress(&private).as_metric_label(),
            "private_address"
        );
        assert_eq!(
            ForwardErrorKind::MisdirectedRequest(&misdirected).as_metric_label(),
            "misdirected_request"
        );
        assert_eq!(
            ForwardErrorKind::UpstreamClosed.as_metric_label(),
            "upstream_closed"
        );
        assert_eq!(ForwardErrorKind::Other.as_metric_label(), "other");
    }
}
