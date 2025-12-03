use std::sync::Arc;

use http::StatusCode;

use self::model::CompiledCacheConfig;

pub mod compile;
pub mod matcher;
pub mod model;

#[derive(Debug, Clone)]
pub enum Decision {
    Allow {
        policy: Arc<str>,
        rule: Arc<str>,
        inspect_payload: bool,
        allow_private_connect: bool,
        cache: Option<CompiledCacheConfig>,
    },
    Deny {
        policy: Arc<str>,
        rule: Arc<str>,
        status: StatusCode,
        reason: Option<Arc<str>>,
        body: Option<Arc<str>>,
    },
}
