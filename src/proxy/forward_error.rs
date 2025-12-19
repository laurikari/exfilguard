use std::net::SocketAddr;

use anyhow::Error;
use thiserror::Error;
use tracing::warn;

use crate::{proxy::http::BodyTooLarge, proxy::resolver::PrivateAddressError};

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
    BodyTooLarge(&'a BodyTooLarge),
    PrivateAddress(&'a PrivateAddressError),
    MisdirectedRequest(&'a MisdirectedRequest),
    Other,
}

pub fn classify_forward_error(err: &Error) -> ForwardErrorKind<'_> {
    if let Some(body) = err.downcast_ref::<BodyTooLarge>() {
        ForwardErrorKind::BodyTooLarge(body)
    } else if let Some(private) = err.downcast_ref::<PrivateAddressError>() {
        ForwardErrorKind::PrivateAddress(private)
    } else if let Some(misdirected) = err.downcast_ref::<MisdirectedRequest>() {
        ForwardErrorKind::MisdirectedRequest(misdirected)
    } else {
        ForwardErrorKind::Other
    }
}

pub fn log_forward_error(kind: &ForwardErrorKind<'_>, peer: SocketAddr, host: &str, err: &Error) {
    match kind {
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
        ForwardErrorKind::Other => warn!(
            peer = %peer,
            host,
            error = %err,
            "upstream request failed"
        ),
        ForwardErrorKind::BodyTooLarge(_) => {}
    }
}
