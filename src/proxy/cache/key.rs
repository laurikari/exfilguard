use http::{HeaderMap, Method, Uri};

pub(super) const MAX_VARY_HEADERS: usize = 8;
pub(super) const MAX_VARY_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone)]
pub(super) struct CacheKey {
    key_base: String,
    entry_id: String,
}

impl CacheKey {
    pub(super) fn new(method: &Method, uri: &Uri) -> Self {
        let key_base = format!("{}::{}", method, uri);
        Self::from_key_base(key_base)
    }

    pub(super) fn from_key_base(key_base: String) -> Self {
        let entry_id = Self::entry_id_for_key(&key_base);
        Self { key_base, entry_id }
    }

    pub(super) fn key_base(&self) -> &str {
        &self.key_base
    }

    pub(super) fn entry_id(&self) -> &str {
        &self.entry_id
    }

    pub(super) fn entry_id_for_key(key_base: &str) -> String {
        blake3::hash(key_base.as_bytes()).to_hex().to_string()
    }
}

#[derive(Debug, Clone)]
pub(super) struct VaryKey {
    headers: HeaderMap,
}

impl VaryKey {
    pub(super) fn new(headers: HeaderMap) -> Self {
        Self { headers }
    }

    pub(super) fn from_response(resp_headers: &HeaderMap, req_headers: &HeaderMap) -> Option<Self> {
        let mut vary_map = HeaderMap::new();
        let mut vary_bytes = 0usize;
        for value in resp_headers.get_all(http::header::VARY) {
            let s = value.to_str().ok()?;
            for header_name in s.split(',') {
                let header_name = header_name.trim();
                if header_name == "*" {
                    // RFC: Vary:* response is not cacheable.
                    return None;
                }
                let hdr = http::header::HeaderName::from_bytes(header_name.as_bytes()).ok()?;
                if vary_map.contains_key(&hdr) {
                    continue;
                }

                let req_values = req_headers.get_all(&hdr).iter().collect::<Vec<_>>();
                if req_values.is_empty() {
                    // If the request didn't supply a header named in Vary, the
                    // response representation cannot be cached safely.
                    return None;
                }
                if vary_map.keys_len() + 1 > MAX_VARY_HEADERS {
                    return None;
                }
                let added_bytes = req_values.iter().fold(hdr.as_str().len(), |total, value| {
                    total.saturating_add(value.as_bytes().len())
                });
                if vary_bytes.saturating_add(added_bytes) > MAX_VARY_BYTES {
                    return None;
                }
                vary_bytes += added_bytes;
                for req_value in req_values {
                    vary_map.append(hdr.clone(), req_value.clone());
                }
            }
        }
        Some(Self { headers: vary_map })
    }

    pub(super) fn matches(&self, req_headers: &HeaderMap) -> bool {
        for name in self.headers.keys() {
            let stored_values = self.headers.get_all(name);
            let request_values = req_headers.get_all(name);
            if !stored_values.iter().eq(request_values.iter()) {
                return false;
            }
        }
        true
    }

    pub(super) fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderName, HeaderValue, header::VARY};

    fn append(map: &mut HeaderMap, name: &HeaderName, value: &'static str) {
        map.append(name.clone(), HeaderValue::from_static(value));
    }

    #[test]
    fn vary_matches_complete_ordered_value_list() {
        let name = HeaderName::from_static("x-variant");
        let mut request = HeaderMap::new();
        append(&mut request, &name, "common");
        append(&mut request, &name, "secret");
        let mut response = HeaderMap::new();
        response.insert(VARY, HeaderValue::from_static("X-Variant"));

        let vary = VaryKey::from_response(&response, &request).expect("valid Vary key");
        assert!(vary.matches(&request));
        assert_eq!(vary.headers().get_all(&name).iter().count(), 2);

        let mut missing = HeaderMap::new();
        append(&mut missing, &name, "common");
        assert!(!vary.matches(&missing));

        let mut extra = request.clone();
        append(&mut extra, &name, "third");
        assert!(!vary.matches(&extra));

        let mut reversed = HeaderMap::new();
        append(&mut reversed, &name, "secret");
        append(&mut reversed, &name, "common");
        assert!(!vary.matches(&reversed));
    }

    #[test]
    fn repeated_vary_names_count_once() {
        let name = HeaderName::from_static("x-variant");
        let mut request = HeaderMap::new();
        append(&mut request, &name, "value");
        let mut response = HeaderMap::new();
        response.append(VARY, HeaderValue::from_static("X-Variant"));
        response.append(VARY, HeaderValue::from_static("x-variant, X-Variant"));

        let vary = VaryKey::from_response(&response, &request).expect("valid Vary key");
        assert_eq!(vary.headers().keys_len(), 1);
        assert_eq!(vary.headers().len(), 1);
    }

    #[test]
    fn vary_byte_limit_counts_every_repeated_value() {
        let name = HeaderName::from_static("x-variant");
        let mut request = HeaderMap::new();
        let value = HeaderValue::from_str(&"x".repeat(MAX_VARY_BYTES / 2)).unwrap();
        request.append(name.clone(), value.clone());
        request.append(name, value);
        let mut response = HeaderMap::new();
        response.insert(VARY, HeaderValue::from_static("X-Variant"));

        assert!(VaryKey::from_response(&response, &request).is_none());
    }
}
