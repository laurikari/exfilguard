use std::net::SocketAddr;

use anyhow::Error;
use thiserror::Error;
use tracing::warn;

use crate::{proxy::http::BodyTooLarge, proxy::resolver::PrivateAddressError};

#[derive(Debug, Error)]
#[error("request timed out")]
pub struct RequestTimeout;

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
    RequestTimeout,
    BodyTooLarge(&'a BodyTooLarge),
    PrivateAddress(&'a PrivateAddressError),
    MisdirectedRequest(&'a MisdirectedRequest),
    UpstreamClosed,
    Other,
}

impl ForwardErrorKind<'_> {
    pub fn as_metric_label(&self) -> &'static str {
        match self {
            Self::RequestTimeout => "request_timeout",
            Self::BodyTooLarge(_) => "body_too_large",
            Self::PrivateAddress(_) => "private_address",
            Self::MisdirectedRequest(_) => "misdirected_request",
            Self::UpstreamClosed => "upstream_closed",
            Self::Other => "other",
        }
    }
}

pub fn classify_forward_error(err: &Error) -> ForwardErrorKind<'_> {
    if err.downcast_ref::<RequestTimeout>().is_some() {
        ForwardErrorKind::RequestTimeout
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

pub fn log_forward_error(kind: &ForwardErrorKind<'_>, peer: SocketAddr, host: &str, err: &Error) {
    match kind {
        ForwardErrorKind::RequestTimeout => warn!(
            peer = %peer,
            host,
            "request timed out while forwarding"
        ),
        ForwardErrorKind::PrivateAddress(private_err) => warn!(
            peer = %peer,
            host,
            port = private_err.port,
            "policy allow decision rejected private upstream address"
        ),
        ForwardErrorKind::MisdirectedRequest(misdirected) => warn!(
            peer = %peer,
            host,
            upstream_host = %misdirected.upstream_host,
            upstream_port = misdirected.upstream_port,
            requested_host = %misdirected.requested_host,
            requested_port = misdirected.requested_port,
            "HTTP/2 request did not match existing upstream connection"
        ),
        ForwardErrorKind::UpstreamClosed => warn!(
            peer = %peer,
            host,
            error = %err,
            "upstream closed connection before response headers"
        ),
        ForwardErrorKind::Other => warn!(
            peer = %peer,
            host,
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
    use super::{ForwardErrorKind, MisdirectedRequest};
    use crate::{proxy::http::BodyTooLarge, proxy::resolver::PrivateAddressError};

    #[test]
    fn metric_labels_cover_all_forward_error_kinds() {
        let body = BodyTooLarge { bytes_read: 42 };
        let private = PrivateAddressError::new("example.com", 443, "connect target");
        let misdirected = MisdirectedRequest::new(
            "upstream.test".to_string(),
            443,
            "requested.test".to_string(),
            8443,
        );

        assert_eq!(
            ForwardErrorKind::RequestTimeout.as_metric_label(),
            "request_timeout"
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
