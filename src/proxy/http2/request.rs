use anyhow::{Context, Result, anyhow, bail, ensure};
use h2::RecvStream;
use http::{self, HeaderMap, HeaderName, HeaderValue, Uri};

use crate::{
    config::Scheme,
    proxy::{
        headers::{
            HeaderAction, HeaderDisposition, RequestHeaderSanitizer, classify_request_header,
        },
        request::{ParsedRequest, parse_uri_request},
    },
};

#[derive(Clone)]
pub(super) struct SanitizedRequest {
    pub parsed: ParsedRequest,
    pub forward_headers: Vec<(HeaderName, HeaderValue)>,
    pub header_bytes: usize,
    pub request_line_bytes: u64,
}

pub(super) fn sanitize_request(
    request: http::Request<RecvStream>,
    max_header_bytes: usize,
) -> Result<(SanitizedRequest, RecvStream)> {
    ensure!(
        max_header_bytes > 0,
        "configured header limit must be greater than zero"
    );

    reject_expect_header(request.headers())?;

    let uri = request.uri().clone();
    let parsed = parse_uri_request(request.method().clone(), &uri, Scheme::Https)?;

    let mut forward_headers = Vec::new();
    let mut sanitizer = RequestHeaderSanitizer::new(max_header_bytes);
    let authority = uri
        .authority()
        .map(|auth| auth.as_str())
        .ok_or_else(|| anyhow!("HTTP/2 request missing :authority pseudo header"))?;
    let scheme = match parsed.scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    };
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    sanitizer
        .record_name_value(":method", request.method().as_str())
        .context("invalid :method pseudo header")?;
    sanitizer
        .record_name_value(":scheme", scheme)
        .context("invalid :scheme pseudo header")?;
    sanitizer
        .record_name_value(":authority", authority)
        .context("invalid :authority pseudo header")?;
    sanitizer
        .record_name_value(":path", path)
        .context("invalid :path pseudo header")?;

    for (name, value) in request.headers().iter() {
        let name_str = name.as_str();
        let lower = name_str.to_ascii_lowercase();
        let value_str = value
            .to_str()
            .with_context(|| format!("header '{name_str}' contains invalid characters"))?;

        if matches!(
            classify_request_header(&lower),
            HeaderDisposition::TransferEncoding
        ) {
            bail!("HTTP/2 request cannot include Transfer-Encoding header");
        }

        match sanitizer.record_name_value(name_str, value_str)? {
            HeaderAction::Forward => forward_headers.push((name.clone(), value.clone())),
            HeaderAction::Skip => {}
        }
    }

    let request_line_bytes = (parsed.method.as_str().len() + parsed.path.len()) as u64;
    let body = request.into_body();

    Ok((
        SanitizedRequest {
            parsed,
            forward_headers,
            header_bytes: sanitizer.total_bytes(),
            request_line_bytes,
        },
        body,
    ))
}

pub(super) fn reject_expect_header(headers: &HeaderMap) -> Result<()> {
    if let Some(value) = headers.get(http::header::EXPECT) {
        let value = value.to_str().unwrap_or("<invalid>").trim().to_string();
        bail!("HTTP/2 requests must not include Expect header (got '{value}')");
    }
    Ok(())
}

pub(super) fn build_upstream_uri(request: &ParsedRequest) -> Result<Uri> {
    let mut builder = Uri::builder();
    builder = builder.scheme(match request.scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    });

    let authority = request.authority_host();
    builder = builder.authority(authority.as_str());
    builder = builder.path_and_query(request.path.as_str());
    builder.build().context("failed to build upstream URI")
}

#[cfg(test)]
mod tests {
    use super::reject_expect_header;
    use http::{HeaderMap, HeaderValue};

    #[test]
    fn reject_expect_header_allows_absent() {
        let headers = HeaderMap::new();
        assert!(reject_expect_header(&headers).is_ok());
    }

    #[test]
    fn reject_expect_header_blocks_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::EXPECT,
            HeaderValue::from_static("100-continue"),
        );
        let err = reject_expect_header(&headers).expect_err("Expect should be rejected");
        assert!(
            err.to_string().contains("Expect header"),
            "unexpected error: {err}"
        );
    }
}
