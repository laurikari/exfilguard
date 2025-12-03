use std::net::SocketAddr;

use anyhow::Error;
use tracing::warn;

use crate::{proxy::http::BodyTooLarge, proxy::resolver::PrivateAddressError};

/// Normalized classification of forwarding failures so HTTP/1.1 and HTTP/2 can react consistently.
pub enum ForwardErrorKind<'a> {
    BodyTooLarge(&'a BodyTooLarge),
    PrivateAddress(&'a PrivateAddressError),
    Other,
}

pub fn classify_forward_error(err: &Error) -> ForwardErrorKind<'_> {
    if let Some(body) = err.downcast_ref::<BodyTooLarge>() {
        ForwardErrorKind::BodyTooLarge(body)
    } else if let Some(private) = err.downcast_ref::<PrivateAddressError>() {
        ForwardErrorKind::PrivateAddress(private)
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
        ForwardErrorKind::Other => warn!(
            peer = %peer,
            host,
            error = %err,
            "upstream request failed"
        ),
        ForwardErrorKind::BodyTooLarge(_) => {}
    }
}
