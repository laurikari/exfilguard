use std::time::Duration;

use http::{HeaderMap, Method, StatusCode};

use crate::proxy::http::cache_control::{get_freshness_lifetime, is_cacheable};

use super::CacheRequestContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheSkipReason {
    SensitiveRequestHeaders,
    RequestContextUnavailable,
    ResponseSetCookie,
    NotCacheable,
    ZeroTtl,
}

#[derive(Debug)]
pub(crate) enum CacheWritePlan {
    Bypass,
    Skip(CacheSkipReason),
    Store(Box<CacheStorePlan>),
}

#[derive(Debug)]
pub(crate) struct CacheStorePlan {
    pub request: CacheRequestContext,
    pub response_headers: HeaderMap,
    pub ttl: Duration,
}

pub(crate) fn plan_cache_write(
    method: &Method,
    cache_request: Option<CacheRequestContext>,
    response_status: StatusCode,
    response_headers: HeaderMap,
    forced_cache_duration: Option<Duration>,
    has_sensitive_headers: bool,
) -> CacheWritePlan {
    if has_sensitive_headers {
        return CacheWritePlan::Skip(CacheSkipReason::SensitiveRequestHeaders);
    }

    let cache_request = match cache_request {
        Some(context) => context,
        None => {
            return CacheWritePlan::Skip(CacheSkipReason::RequestContextUnavailable);
        }
    };

    if cache_request.bypass {
        return CacheWritePlan::Bypass;
    }

    if response_headers.contains_key(http::header::SET_COOKIE) {
        return CacheWritePlan::Skip(CacheSkipReason::ResponseSetCookie);
    }

    if !is_cacheable(method, response_status, &response_headers) {
        return CacheWritePlan::Skip(CacheSkipReason::NotCacheable);
    }

    let ttl = select_cache_ttl(
        get_freshness_lifetime(&response_headers),
        forced_cache_duration,
    );
    if ttl <= Duration::ZERO {
        return CacheWritePlan::Skip(CacheSkipReason::ZeroTtl);
    }

    CacheWritePlan::Store(Box::new(CacheStorePlan {
        request: cache_request,
        response_headers,
        ttl,
    }))
}

fn select_cache_ttl(origin_ttl: Option<Duration>, forced: Option<Duration>) -> Duration {
    if let Some(ttl) = origin_ttl
        && ttl > Duration::ZERO
    {
        return ttl;
    }
    forced.unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::select_cache_ttl;
    use std::time::Duration;

    #[test]
    fn prefers_origin_ttl_when_present() {
        let origin = Some(Duration::from_secs(30));
        let forced = Some(Duration::from_secs(5));
        assert_eq!(select_cache_ttl(origin, forced), Duration::from_secs(30));
    }

    #[test]
    fn falls_back_to_forced_when_origin_is_zero_or_missing() {
        let forced = Some(Duration::from_secs(5));
        assert_eq!(
            select_cache_ttl(Some(Duration::ZERO), forced),
            Duration::from_secs(5)
        );
        assert_eq!(select_cache_ttl(None, forced), Duration::from_secs(5));
    }

    #[test]
    fn returns_zero_without_origin_or_forced() {
        assert_eq!(select_cache_ttl(None, None), Duration::ZERO);
        assert_eq!(select_cache_ttl(Some(Duration::ZERO), None), Duration::ZERO);
    }
}
