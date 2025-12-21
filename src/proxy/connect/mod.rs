mod bump;
mod handler;
mod resolve;
mod session;
mod splice;
mod target;

pub use self::{
    handler::{ConnectRequest, handle_connect},
    resolve::ResolvedTarget,
};

#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    pub use super::target::parse_connect_target;
}
