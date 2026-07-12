use anyhow::Result;
use http::{HeaderMap, Method, StatusCode};

use crate::proxy::http::{Http1HeaderAccumulator, Http1ResponseHead};
use crate::proxy::request::ParsedRequest;

use super::{CachedResponse, HttpCache, build_cache_request_context};

pub(crate) struct CacheHit {
    pub cached: CachedResponse,
    pub head: Http1ResponseHead,
}

pub(crate) enum CacheLookupOutcome {
    Bypass,
    Miss,
    Hit(Box<CachedResponse>),
}

pub(crate) enum Http1CacheLookupOutcome {
    Bypass,
    Miss,
    Hit(Box<CacheHit>),
}

impl CacheHit {
    fn from_cached(mut cached: CachedResponse, method: &Method) -> Self {
        let status_line = format!(
            "HTTP/1.1 {} {}",
            cached.status.as_u16(),
            cached.status.canonical_reason().unwrap_or("OK")
        )
        .into_bytes();

        let body_is_empty = method == Method::HEAD
            || matches!(
                cached.status,
                StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
            );
        if cached.status == StatusCode::NO_CONTENT {
            cached.headers.remove(http::header::CONTENT_LENGTH);
        }
        if !body_is_empty {
            cached.headers.remove(http::header::CONTENT_LENGTH);
        }

        let head = Http1ResponseHead {
            status_line,
            status: cached.status,
            headers: Vec::new(),
            content_length: (!body_is_empty).then_some(cached.content_length),
            chunked: false,
            transfer_encoding_present: false,
            connection_close: true,
        };

        Self { cached, head }
    }
}

impl HttpCache {
    pub(crate) async fn lookup_for_header_map(
        &self,
        request: &ParsedRequest,
        headers: &HeaderMap,
    ) -> Result<CacheLookupOutcome> {
        if headers.contains_key(http::header::AUTHORIZATION)
            || headers.contains_key(http::header::COOKIE)
        {
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
            Some(cached) => Ok(CacheLookupOutcome::Hit(Box::new(cached))),
            None => Ok(CacheLookupOutcome::Miss),
        }
    }

    pub(crate) async fn lookup_for_request(
        &self,
        request: &ParsedRequest,
        headers: &Http1HeaderAccumulator,
    ) -> Result<Http1CacheLookupOutcome> {
        Ok(
            match self
                .lookup_for_header_map(request, &headers.forward_header_map())
                .await?
            {
                CacheLookupOutcome::Bypass => Http1CacheLookupOutcome::Bypass,
                CacheLookupOutcome::Miss => Http1CacheLookupOutcome::Miss,
                CacheLookupOutcome::Hit(cached) => Http1CacheLookupOutcome::Hit(Box::new(
                    CacheHit::from_cached(*cached, &request.method),
                )),
            },
        )
    }
}
