mod bump;
mod handler;
mod resolve;
mod session;
mod splice;
mod target;

pub(crate) use self::handler::{ConnectRequest, handle_connect};
pub use self::resolve::ResolvedTarget;

#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    pub use super::target::parse_connect_target;
}
