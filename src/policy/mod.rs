use crate::config::HttpsMode;

use std::sync::Arc;

use http::StatusCode;

use self::model::CompiledCacheConfig;

pub mod compile;
pub mod matcher;
pub mod model;

#[cfg(test)]
mod preflight_tests;
#[cfg(test)]
mod query_tests;

#[derive(Debug, Clone)]
pub enum Decision {
    Allow {
        policy: Arc<str>,
        rule: Arc<str>,
        https_mode: HttpsMode,
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
