use anyhow::Result;
use http::{HeaderMap, Uri};

use crate::proxy::http::Http1HeaderAccumulator;
use crate::proxy::http::cache_control::request_cache_bypass;
use crate::proxy::request::ParsedRequest;

#[derive(Debug)]
pub(crate) struct CacheRequestContext {
    pub uri: Uri,
    pub headers: HeaderMap,
    pub bypass: bool,
}

pub(crate) fn build_cache_request_context(
    request: &ParsedRequest,
    headers: &Http1HeaderAccumulator,
) -> Result<CacheRequestContext> {
    let uri = request.cache_uri()?;
    let headers = headers.forward_header_map();
    let bypass = request_cache_bypass(&headers);
    Ok(CacheRequestContext {
        uri,
        headers,
        bypass,
    })
}
