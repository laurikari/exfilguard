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

    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginFreshness {
    Absent,
    Explicit(Duration),
    Invalid,
}

/// Parse origin freshness without treating malformed metadata as absent.
pub fn get_origin_freshness(headers: &HeaderMap) -> OriginFreshness {
    let mut s_maxage = None;
    let mut max_age = None;
    for value in headers.get_all(http::header::CACHE_CONTROL) {
        let Ok(value) = value.to_str() else {
            return OriginFreshness::Invalid;
        };
        for part in value.split(',') {
            let (name, value) = split_directive(part.trim());
            let destination = match name.as_str() {
                "s-maxage" => &mut s_maxage,
                "max-age" => &mut max_age,
                _ => continue,
            };
            if destination.is_some() {
                *destination = Some(Err(()));
                continue;
            }
            *destination = Some(
                value
                    .and_then(|value| normalize_cc_value(value).parse::<u64>().ok())
                    .map(Duration::from_secs)
                    .ok_or(()),
            );
        }
    }

    if let Some(directive) = s_maxage.or(max_age) {
        return match directive {
            Ok(duration) => OriginFreshness::Explicit(duration),
            Err(()) => OriginFreshness::Invalid,
        };
    }

    let mut expires_values = headers.get_all(http::header::EXPIRES).iter();
    let Some(expires) = expires_values.next() else {
        return OriginFreshness::Absent;
    };
    if expires_values.next().is_some() {
        return OriginFreshness::Invalid;
    }
    let Ok(expires) = expires.to_str() else {
        return OriginFreshness::Invalid;
    };
    let Ok(expires) = httpdate::parse_http_date(expires) else {
        return OriginFreshness::Invalid;
    };
    let duration = expires
        .duration_since(std::time::SystemTime::now())
        .unwrap_or(Duration::ZERO);
    OriginFreshness::Explicit(duration)
}

pub fn request_cache_bypass(headers: &HeaderMap) -> bool {
    if headers.contains_key(http::header::RANGE) {
        return true;
    }

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
    fn response_without_freshness_is_storage_eligible() {
        assert!(is_cacheable(
            &Method::GET,
            StatusCode::OK,
            &HeaderMap::new()
        ));
    }

    #[test]
    fn explicit_freshness_detects_invalid_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=invalid"),
        );
        assert_eq!(get_origin_freshness(&headers), OriginFreshness::Invalid);

        headers = HeaderMap::new();
        headers.insert(
            http::header::EXPIRES,
            HeaderValue::from_static("not-a-date"),
        );
        assert_eq!(get_origin_freshness(&headers), OriginFreshness::Invalid);
    }

    #[test]
    fn invalid_higher_priority_or_duplicate_freshness_is_not_ignored() {
        for value in [
            "s-maxage=invalid, max-age=60",
            "s-maxage=60, s-maxage=30",
            "max-age=60, max-age=30",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::CACHE_CONTROL,
                HeaderValue::from_str(value).unwrap(),
            );
            assert_eq!(get_origin_freshness(&headers), OriginFreshness::Invalid);
        }
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
    fn test_not_cacheable_partial_content() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=60"),
        );
        assert!(!is_cacheable(
            &Method::GET,
            StatusCode::PARTIAL_CONTENT,
            &headers
        ));
    }

    #[test]
    fn test_freshness_lifetime_max_age() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=120"),
        );
        assert_eq!(
            get_origin_freshness(&headers),
            OriginFreshness::Explicit(Duration::from_secs(120))
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
    fn request_cache_bypass_range() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::RANGE, HeaderValue::from_static("bytes=0-99"));
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
