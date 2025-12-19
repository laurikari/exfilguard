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
                if part.is_empty() {
                    continue;
                }

                let (name, value) = split_directive(part);
                match name.as_str() {
                    "public" => cc.public = true,
                    "private" => cc.private = true,
                    "no-cache" => cc.no_cache = true,
                    "no-store" => cc.no_store = true,
                    "must-revalidate" => cc.must_revalidate = true,
                    "max-age" => {
                        if let Some(value) = value
                            && let Ok(secs) = normalize_cc_value(value).parse::<u64>()
                        {
                            cc.max_age = Some(Duration::from_secs(secs));
                        }
                    }
                    "s-maxage" => {
                        if let Some(value) = value
                            && let Ok(secs) = normalize_cc_value(value).parse::<u64>()
                        {
                            cc.s_maxage = Some(Duration::from_secs(secs));
                        }
                    }
                    _ => {}
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

    // Shared proxy caches must not store Set-Cookie responses.
    if headers.contains_key(http::header::SET_COOKIE) {
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

pub fn request_cache_bypass(headers: &HeaderMap) -> bool {
    for value in headers.get_all(http::header::CACHE_CONTROL) {
        if let Ok(s) = value.to_str() {
            for part in s.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let (name, value) = split_directive(part);
                if name == "no-cache" || name == "no-store" {
                    return true;
                }
                if name == "max-age"
                    && let Some(value) = value
                    && normalize_cc_value(value).parse::<u64>().ok() == Some(0)
                {
                    return true;
                }
            }
        }
    }

    for value in headers.get_all(http::header::PRAGMA) {
        if let Ok(s) = value.to_str() {
            for part in s.split(',') {
                if part.trim().eq_ignore_ascii_case("no-cache") {
                    return true;
                }
            }
        }
    }

    false
}

fn split_directive(part: &str) -> (String, Option<&str>) {
    if let Some((name, value)) = part.split_once('=') {
        (name.trim().to_ascii_lowercase(), Some(value.trim()))
    } else {
        (part.trim().to_ascii_lowercase(), None)
    }
}

fn normalize_cc_value(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value)
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
    fn test_parse_cache_control_case_insensitive_with_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("Max-Age = 120, S-Maxage= 240"),
        );
        let cc = parse_cache_control(&headers);
        assert_eq!(cc.max_age, Some(Duration::from_secs(120)));
        assert_eq!(cc.s_maxage, Some(Duration::from_secs(240)));
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
    fn test_not_cacheable_set_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=60"),
        );
        headers.insert(
            http::header::SET_COOKIE,
            HeaderValue::from_static("session=abc123; Path=/; HttpOnly"),
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

    #[test]
    fn request_cache_bypass_no_cache() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        );
        assert!(request_cache_bypass(&headers));
    }

    #[test]
    fn request_cache_bypass_no_store() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        assert!(request_cache_bypass(&headers));
    }

    #[test]
    fn request_cache_bypass_max_age_zero() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("Max-Age = 0"),
        );
        assert!(request_cache_bypass(&headers));
    }

    #[test]
    fn request_cache_bypass_pragma_no_cache() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::PRAGMA, HeaderValue::from_static("no-cache"));
        assert!(request_cache_bypass(&headers));
    }

    #[test]
    fn request_cache_bypass_ignored_for_cacheable() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=60"),
        );
        assert!(!request_cache_bypass(&headers));
    }
}
