use anyhow::Result;
use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};

use crate::proxy::http::{HeaderAccumulator, ResponseHead};
use crate::proxy::request::ParsedRequest;

use super::{CachedResponse, HttpCache, build_cache_request_context};

pub(crate) struct CacheHit {
    pub cached: CachedResponse,
    pub head: ResponseHead,
}

pub(crate) enum CacheLookupOutcome {
    Bypass,
    Miss,
    Hit(Box<CacheHit>),
}

impl CacheHit {
    fn from_cached(cached: CachedResponse) -> Self {
        let status_line = format!(
            "HTTP/1.1 {} {}",
            cached.status.as_u16(),
            cached.status.canonical_reason().unwrap_or("OK")
        );

        let mut transfer_encoding_present = false;
        let mut chunked = false;
        for value in cached.headers.get_all(TRANSFER_ENCODING).iter() {
            transfer_encoding_present = true;
            if value
                .to_str()
                .ok()
                .map(|s| s.to_ascii_lowercase().contains("chunked"))
                .unwrap_or(false)
            {
                chunked = true;
            }
        }
        let has_content_length = cached.headers.contains_key(CONTENT_LENGTH);
        let content_length = if transfer_encoding_present || !has_content_length {
            None
        } else {
            Some(cached.content_length)
        };

        let head = ResponseHead {
            status_line,
            status: cached.status,
            headers: Vec::new(),
            content_length,
            chunked,
            transfer_encoding_present,
            connection_close: true,
        };

        Self { cached, head }
    }
}

impl HttpCache {
    pub(crate) async fn lookup_for_request(
        &self,
        request: &ParsedRequest,
        headers: &HeaderAccumulator,
    ) -> Result<CacheLookupOutcome> {
        if headers.has_sensitive_cache_headers() {
            return Ok(CacheLookupOutcome::Bypass);
        }

        let cache_request = build_cache_request_context(request, headers)?;
        if cache_request.bypass {
            return Ok(CacheLookupOutcome::Bypass);
        }

        match self
            .lookup(&request.method, &cache_request.uri, &cache_request.headers)
            .await
        {
            Some(cached) => Ok(CacheLookupOutcome::Hit(Box::new(CacheHit::from_cached(
                cached,
            )))),
            None => Ok(CacheLookupOutcome::Miss),
        }
    }
}
