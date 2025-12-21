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
            if let Ok(s) = value.to_str() {
                for header_name in s.split(',') {
                    let header_name = header_name.trim();
                    if header_name == "*" {
                        // RFC: Vary:* response is not cacheable.
                        return None;
                    }
                    if let Ok(hdr) = http::header::HeaderName::from_bytes(header_name.as_bytes()) {
                        let req_val = match req_headers.get(&hdr) {
                            Some(val) => val,
                            None => {
                                // If the request didn't supply a header named in Vary, the
                                // response representation cannot be cached safely.
                                return None;
                            }
                        };
                        if vary_map.len() + 1 > MAX_VARY_HEADERS {
                            return None;
                        }
                        let added_bytes = hdr.as_str().len() + req_val.as_bytes().len();
                        if vary_bytes.saturating_add(added_bytes) > MAX_VARY_BYTES {
                            return None;
                        }
                        vary_bytes += added_bytes;
                        vary_map.insert(hdr, req_val.clone());
                    }
                }
            }
        }
        Some(Self { headers: vary_map })
    }

    pub(super) fn matches(&self, req_headers: &HeaderMap) -> bool {
        for (name, value) in self.headers.iter() {
            if let Some(req_value) = req_headers.get(name) {
                if req_value != value {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }

    pub(super) fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}
