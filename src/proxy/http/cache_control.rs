use http::{HeaderMap, Method, StatusCode};
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct CacheControl {
    pub public: bool,
    pub private: bool,
    pub no_cache: bool,
    pub no_store: bool,
    pub max_age: Option<Duration>,
    pub s_maxage: Option<Duration>,
    pub must_revalidate: bool,
}

pub fn parse_cache_control(headers: &HeaderMap) -> CacheControl {
    let mut cc = CacheControl::default();

    for value in headers.get_all(http::header::CACHE_CONTROL) {
        if let Ok(s) = value.to_str() {
            for part in s.split(',') {
                let part = part.trim();
                if part.eq_ignore_ascii_case("public") {
                    cc.public = true;
                } else if part.eq_ignore_ascii_case("private") {
                    cc.private = true;
                } else if part.eq_ignore_ascii_case("no-cache") {
                    cc.no_cache = true;
                } else if part.eq_ignore_ascii_case("no-store") {
                    cc.no_store = true;
                } else if part.eq_ignore_ascii_case("must-revalidate") {
                    cc.must_revalidate = true;
                } else if let Some(stripped) = part.strip_prefix("max-age=") {
                    if let Ok(secs) = stripped.parse::<u64>() {
                        cc.max_age = Some(Duration::from_secs(secs));
                    }
                } else if let Some(stripped) = part.strip_prefix("s-maxage=")
                    && let Ok(secs) = stripped.parse::<u64>()
                {
                    cc.s_maxage = Some(Duration::from_secs(secs));
                }
            }
        }
    }
    cc
}

pub fn is_cacheable(method: &Method, status: StatusCode, headers: &HeaderMap) -> bool {
    // Only cache GET and HEAD
    if method != Method::GET && method != Method::HEAD {
        return false;
    }

    // Only cache specific status codes (RFC 7231 / 9110)
    if !matches!(
        status,
        StatusCode::OK
            | StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::NON_AUTHORITATIVE_INFORMATION
            | StatusCode::NO_CONTENT
            | StatusCode::RESET_CONTENT
            | StatusCode::PARTIAL_CONTENT
    ) {
        return false;
    }

    let cc = parse_cache_control(headers);

    // Never cache if no-store, no-cache, or private is present (no-cache requires revalidation).
    if cc.no_store || cc.no_cache || cc.private {
        return false;
    }

    // Requires explicit freshness info (max-age, s-maxage, or Expires)
    // or explicit 'public' (though public usually implies some default cacheability,
    // we want to be safe and require explicit lifetime or public indication).
    // For now, let's require either max-age/s-maxage OR Expires.
    // If 'public' is set but no freshness, browsers might cache, but we should be careful.
    // Let's stick to: Must have freshness info OR be 'public'.

    if cc.max_age.is_some() || cc.s_maxage.is_some() || cc.public {
        return true;
    }

    if headers.contains_key(http::header::EXPIRES) {
        return true;
    }

    false
}

pub fn get_freshness_lifetime(headers: &HeaderMap) -> Option<Duration> {
    let cc = parse_cache_control(headers);

    if let Some(s_maxage) = cc.s_maxage {
        return Some(s_maxage);
    }
    if let Some(max_age) = cc.max_age {
        return Some(max_age);
    }

    if let Some(expires) = headers.get(http::header::EXPIRES)
        && let Ok(expires_str) = expires.to_str()
        && let Ok(expires_time) = httpdate::parse_http_date(expires_str)
    {
        // Determine time delta
        let now = std::time::SystemTime::now();
        if let Ok(duration) = expires_time.duration_since(now) {
            return Some(duration);
        }
        // If expires is in the past, duration is 0
        return Some(Duration::ZERO);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn test_parse_cache_control() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=3600"),
        );
        let cc = parse_cache_control(&headers);
        assert!(cc.public);
        assert_eq!(cc.max_age, Some(Duration::from_secs(3600)));
        assert!(!cc.private);
    }

    #[test]
    fn test_is_cacheable_basic() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=60"),
        );
        assert!(is_cacheable(&Method::GET, StatusCode::OK, &headers));
    }

    #[test]
    fn test_not_cacheable_private() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("private, max-age=60"),
        );
        assert!(!is_cacheable(&Method::GET, StatusCode::OK, &headers));
    }

    #[test]
    fn test_not_cacheable_no_store() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        assert!(!is_cacheable(&Method::GET, StatusCode::OK, &headers));
    }

    #[test]
    fn test_not_cacheable_no_cache() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        );
        assert!(!is_cacheable(&Method::GET, StatusCode::OK, &headers));
    }

    #[test]
    fn test_not_cacheable_method() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=60"),
        );
        assert!(!is_cacheable(&Method::POST, StatusCode::OK, &headers));
    }

    #[test]
    fn test_freshness_lifetime_max_age() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=120"),
        );
        assert_eq!(
            get_freshness_lifetime(&headers),
            Some(Duration::from_secs(120))
        );
    }
}
