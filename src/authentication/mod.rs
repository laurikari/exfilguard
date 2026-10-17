pub(crate) mod hash;
mod session;

pub use hash::{PasswordAlgorithm, PasswordHash, generate_hash};
pub(crate) use session::challenges;
#[cfg(feature = "fuzzing")]
pub use session::fuzz_basic_header;
pub(crate) use session::{AuthenticationError, ConnectionSession, PasswordVerifier};

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthenticationSettings {
    pub max_pending_connections: usize,
    pub max_concurrent_verifications: usize,
}

impl Default for AuthenticationSettings {
    fn default() -> Self {
        Self {
            max_pending_connections: 128,
            max_concurrent_verifications: 4,
        }
    }
}
