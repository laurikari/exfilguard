use anyhow::Result;
use http::HeaderMap;

use crate::proxy::cache::CacheRequestContext;
use crate::proxy::request::ParsedRequest;

use super::cache_control::request_cache_bypass;
use super::codec::{HeaderAccumulator, HeaderLine};

pub(super) fn build_cache_request_context(
    request: &ParsedRequest,
    headers: &HeaderAccumulator,
) -> Result<CacheRequestContext> {
    let uri = request.cache_uri()?;
    let headers = header_lines_to_map(headers.forward_headers());
    let bypass = request_cache_bypass(&headers);
    Ok(CacheRequestContext {
        uri,
        headers,
        bypass,
    })
}

pub(super) fn header_lines_to_map<'a, I>(headers: I) -> HeaderMap
where
    I: Iterator<Item = &'a HeaderLine>,
{
    let mut map = HeaderMap::new();
    for header in headers {
        if let Ok(name) = http::header::HeaderName::from_bytes(header.name.as_bytes())
            && let Ok(value) = http::header::HeaderValue::from_bytes(header.value.as_bytes())
        {
            map.append(name, value);
        }
    }
    map
}
