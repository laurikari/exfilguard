use std::time::{Duration, SystemTime};

use http::{HeaderMap, Method, StatusCode};

use crate::proxy::http::cache_control::{
    OriginFreshness, corrected_initial_age, get_origin_freshness, is_cacheable,
};

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
    pub timing: CacheTiming,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CacheTiming {
    pub response_time: SystemTime,
    pub corrected_initial_age: Duration,
    pub freshness_lifetime: Duration,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CacheResponseTiming {
    pub response_time: SystemTime,
    pub response_delay: Duration,
}

impl CacheTiming {
    pub fn expires_at(self) -> Option<SystemTime> {
        let remaining = self
            .freshness_lifetime
            .checked_sub(self.corrected_initial_age)?;
        if remaining.is_zero() {
            return None;
        }
        self.response_time.checked_add(remaining)
    }
}

pub(crate) fn plan_cache_write(
    method: &Method,
    cache_request: Option<CacheRequestContext>,
    response_status: StatusCode,
    response_headers: HeaderMap,
    forced_cache_duration: Option<Duration>,
    has_sensitive_headers: bool,
    response_timing: CacheResponseTiming,
) -> CacheWritePlan {
    let CacheResponseTiming {
        response_time,
        response_delay,
    } = response_timing;
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

    let freshness_lifetime = select_cache_ttl(
        get_origin_freshness(&response_headers, response_time),
        forced_cache_duration,
    );
    if freshness_lifetime <= Duration::ZERO {
        return CacheWritePlan::Skip(CacheSkipReason::ZeroTtl);
    }
    let timing = CacheTiming {
        response_time,
        corrected_initial_age: corrected_initial_age(
            &response_headers,
            response_time,
            response_delay,
        ),
        freshness_lifetime,
    };
    if timing.corrected_initial_age >= timing.freshness_lifetime {
        return CacheWritePlan::Skip(CacheSkipReason::ZeroTtl);
    }
    let Some(expires_at) = timing.expires_at() else {
        return CacheWritePlan::Skip(CacheSkipReason::UnrepresentableTtl);
    };
    if SystemTime::now() >= expires_at {
        return CacheWritePlan::Skip(CacheSkipReason::ZeroTtl);
    }

    CacheWritePlan::Store(Box::new(CacheStorePlan {
        request: cache_request,
        response_headers,
        timing,
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
    use super::{
        CacheResponseTiming, CacheSkipReason, CacheWritePlan, plan_cache_write, select_cache_ttl,
    };
    use crate::proxy::cache::CacheRequestContext;
    use crate::proxy::http::cache_control::{MAX_CACHE_TTL, OriginFreshness};
    use http::{HeaderMap, HeaderValue, Method, StatusCode};
    use std::time::{Duration, SystemTime};

    fn request_context() -> CacheRequestContext {
        CacheRequestContext {
            uri: "http://example.com/resource".parse().unwrap(),
            headers: HeaderMap::new(),
            bypass: false,
        }
    }

    fn response_timing(response_delay: Duration) -> CacheResponseTiming {
        CacheResponseTiming {
            response_time: SystemTime::now(),
            response_delay,
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
            response_timing(Duration::ZERO),
        );
        let CacheWritePlan::Store(plan) = plan else {
            panic!("headerless response should use forced TTL");
        };
        assert_eq!(plan.timing.freshness_lifetime, Duration::from_secs(30));
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
                response_timing(Duration::ZERO),
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
            response_timing(Duration::ZERO),
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
            response_timing(Duration::ZERO),
        );
        let CacheWritePlan::Store(plan) = plan else {
            panic!("overflowing HTTP delta-seconds should use the standard cache maximum");
        };
        assert_eq!(plan.timing.freshness_lifetime, MAX_CACHE_TTL);
    }

    #[test]
    fn existing_age_reduces_forced_freshness() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::AGE, HeaderValue::from_static("31"));

        let plan = plan_cache_write(
            &Method::GET,
            Some(request_context()),
            StatusCode::OK,
            headers,
            Some(Duration::from_secs(30)),
            false,
            response_timing(Duration::ZERO),
        );

        assert!(matches!(
            plan,
            CacheWritePlan::Skip(CacheSkipReason::ZeroTtl)
        ));
    }

    #[test]
    fn response_delay_can_consume_all_freshness() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=30"),
        );

        let plan = plan_cache_write(
            &Method::GET,
            Some(request_context()),
            StatusCode::OK,
            headers,
            None,
            false,
            response_timing(Duration::from_secs(30)),
        );

        assert!(matches!(
            plan,
            CacheWritePlan::Skip(CacheSkipReason::ZeroTtl)
        ));
    }
}
