use std::time::Duration;
use std::time::SystemTime;

use http::{HeaderMap, Method, StatusCode};

use crate::proxy::http::cache_control::{OriginFreshness, get_origin_freshness, is_cacheable};

use super::CacheRequestContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheSkipReason {
    SensitiveRequestHeaders,
    RequestContextUnavailable,
    ResponseSetCookie,
    NotCacheable,
    ZeroTtl,
    UnrepresentableTtl,
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
        get_origin_freshness(&response_headers),
        forced_cache_duration,
    );
    if ttl <= Duration::ZERO {
        return CacheWritePlan::Skip(CacheSkipReason::ZeroTtl);
    }
    if SystemTime::now().checked_add(ttl).is_none() {
        return CacheWritePlan::Skip(CacheSkipReason::UnrepresentableTtl);
    }

    CacheWritePlan::Store(Box::new(CacheStorePlan {
        request: cache_request,
        response_headers,
        ttl,
    }))
}

fn select_cache_ttl(origin: OriginFreshness, forced: Option<Duration>) -> Duration {
    match origin {
        OriginFreshness::Explicit(ttl) => ttl,
        OriginFreshness::Invalid => Duration::ZERO,
        OriginFreshness::Absent => forced.unwrap_or(Duration::ZERO),
    }
}

#[cfg(test)]
mod tests {
    use super::{CacheSkipReason, CacheWritePlan, plan_cache_write, select_cache_ttl};
    use crate::proxy::cache::CacheRequestContext;
    use crate::proxy::http::cache_control::{MAX_CACHE_TTL, OriginFreshness};
    use http::{HeaderMap, HeaderValue, Method, StatusCode};
    use std::time::Duration;

    fn request_context() -> CacheRequestContext {
        CacheRequestContext {
            uri: "http://example.com/resource".parse().unwrap(),
            headers: HeaderMap::new(),
            bypass: false,
        }
    }

    #[test]
    fn prefers_origin_ttl_when_present() {
        let forced = Some(Duration::from_secs(5));
        assert_eq!(
            select_cache_ttl(OriginFreshness::Explicit(Duration::from_secs(30)), forced),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn falls_back_to_forced_only_when_origin_freshness_is_absent() {
        let forced = Some(Duration::from_secs(5));
        assert_eq!(
            select_cache_ttl(OriginFreshness::Explicit(Duration::ZERO), forced),
            Duration::ZERO
        );
        assert_eq!(
            select_cache_ttl(OriginFreshness::Invalid, forced),
            Duration::ZERO
        );
        assert_eq!(
            select_cache_ttl(OriginFreshness::Absent, forced),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn returns_zero_without_origin_or_forced() {
        assert_eq!(
            select_cache_ttl(OriginFreshness::Absent, None),
            Duration::ZERO
        );
        assert_eq!(
            select_cache_ttl(OriginFreshness::Explicit(Duration::ZERO), None),
            Duration::ZERO
        );
    }

    #[test]
    fn forced_ttl_stores_headerless_eligible_response() {
        let plan = plan_cache_write(
            &Method::GET,
            Some(request_context()),
            StatusCode::OK,
            HeaderMap::new(),
            Some(Duration::from_secs(30)),
            false,
        );
        let CacheWritePlan::Store(plan) = plan else {
            panic!("headerless response should use forced TTL");
        };
        assert_eq!(plan.ttl, Duration::from_secs(30));
    }

    #[test]
    fn forced_ttl_does_not_override_explicit_zero_or_invalid_freshness() {
        for (name, value) in [
            (http::header::CACHE_CONTROL, "max-age=0"),
            (http::header::CACHE_CONTROL, "s-maxage=invalid"),
            (http::header::EXPIRES, "not-a-date"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(name, HeaderValue::from_static(value));
            let plan = plan_cache_write(
                &Method::GET,
                Some(request_context()),
                StatusCode::OK,
                headers,
                Some(Duration::from_secs(30)),
                false,
            );
            assert!(matches!(
                plan,
                CacheWritePlan::Skip(CacheSkipReason::ZeroTtl)
            ));
        }
    }

    #[test]
    fn forced_ttl_does_not_override_storage_prohibitions() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        let plan = plan_cache_write(
            &Method::GET,
            Some(request_context()),
            StatusCode::OK,
            headers,
            Some(Duration::from_secs(30)),
            false,
        );
        assert!(matches!(
            plan,
            CacheWritePlan::Skip(CacheSkipReason::NotCacheable)
        ));
    }

    #[test]
    fn overflowing_origin_ttl_is_capped_and_cached() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=18446744073709551615"),
        );
        let plan = plan_cache_write(
            &Method::GET,
            Some(request_context()),
            StatusCode::OK,
            headers,
            None,
            false,
        );
        let CacheWritePlan::Store(plan) = plan else {
            panic!("overflowing HTTP delta-seconds should use the standard cache maximum");
        };
        assert_eq!(plan.ttl, MAX_CACHE_TTL);
    }
}
