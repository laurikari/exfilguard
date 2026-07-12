use anyhow::Result;
use http::{HeaderMap, Uri};

use crate::proxy::http::Http1HeaderAccumulator;
use crate::proxy::http::cache_control::request_cache_bypass;
use crate::proxy::request::ParsedRequest;

#[derive(Clone, Debug)]
pub(crate) struct CacheRequestContext {
    pub uri: Uri,
    pub headers: HeaderMap,
    pub bypass: bool,
}

pub(crate) fn build_cache_request_context(
    request: &ParsedRequest,
    headers: &HeaderMap,
) -> Result<CacheRequestContext> {
    let uri = request.cache_uri()?;
    let bypass = request_cache_bypass(headers);
    Ok(CacheRequestContext {
        uri,
        headers: headers.clone(),
        bypass,
    })
}

pub(crate) fn build_http1_cache_request_context(
    request: &ParsedRequest,
    headers: &Http1HeaderAccumulator,
) -> Result<CacheRequestContext> {
    build_cache_request_context(request, &headers.forward_header_map())
}
