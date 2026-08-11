use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use http::header::{HeaderName, HeaderValue};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::OwnedSemaphorePermit;
use zeroize::Zeroizing;

use crate::config::Scheme;
use crate::proxy::request::{ParsedRequest, scheme_name};

pub(crate) struct BufferedBody {
    bytes: Zeroizing<Vec<u8>>,
    wire_bytes: u64,
    _permit: OwnedSemaphorePermit,
}

impl BufferedBody {
    pub(crate) fn new(bytes: Vec<u8>, wire_bytes: u64, permit: OwnedSemaphorePermit) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
            wire_bytes,
            _permit: permit,
        }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn wire_bytes(&self) -> u64 {
        self.wire_bytes
    }
}

pub(crate) struct FinalizedHeader {
    pub(crate) name: HeaderName,
    value: Zeroizing<Vec<u8>>,
    protected: bool,
}

impl FinalizedHeader {
    pub(crate) fn value(&self) -> &[u8] {
        &self.value
    }

    pub(crate) fn is_protected(&self) -> bool {
        self.protected
    }
}

#[derive(Clone, Copy)]
pub(crate) enum FinalizedProtocol {
    Http1,
    Http2,
}

#[derive(Clone, Copy, Debug, Error)]
pub(crate) enum FinalizationRejection {
    #[error("credential-bearing requests must not use Expect")]
    Expectation,
    #[error("credential-bearing requests must not declare trailers")]
    Trailers,
    #[error("client supplied a protected header")]
    ProtectedHeader,
}

pub(crate) struct FinalizedRequestV1 {
    scheme: Scheme,
    origin_host: String,
    effective_port: u16,
    authority: String,
    method: http::Method,
    raw_path_and_query: Vec<u8>,
    headers: Vec<FinalizedHeader>,
    protected_header_slots: Arc<[HeaderName]>,
    body: Option<BufferedBody>,
    protocol: FinalizedProtocol,
    fingerprint: [u8; 32],
}

impl FinalizedRequestV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        parsed: &ParsedRequest,
        forward_headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>,
        declared_content_length: Option<usize>,
        body: Option<BufferedBody>,
        protected_header_slots: Arc<[HeaderName]>,
        protocol: FinalizedProtocol,
        max_header_bytes: usize,
    ) -> Result<Self> {
        let body_length = body.as_ref().map(|body| body.bytes().len());
        if let Some(declared) = declared_content_length {
            ensure!(
                declared == body_length.unwrap_or(0),
                "buffered payload length does not match declared Content-Length"
            );
        }
        let authority_value = HeaderValue::from_str(parsed.authority_host())
            .context("generated request authority is not a valid header value")?;
        let mut headers = vec![FinalizedHeader {
            name: http::header::HOST,
            value: Zeroizing::new(authority_value.as_bytes().to_vec()),
            protected: false,
        }];
        for (name, value) in forward_headers {
            if name == http::header::EXPECT {
                return Err(FinalizationRejection::Expectation.into());
            }
            if name == http::header::TRAILER {
                return Err(FinalizationRejection::Trailers.into());
            }
            if protected_header_slots.contains(&name) {
                return Err(FinalizationRejection::ProtectedHeader.into());
            }
            headers.push(FinalizedHeader {
                name,
                value: Zeroizing::new(value.as_bytes().to_vec()),
                protected: false,
            });
        }
        if let Some(length) = declared_content_length.or(body_length) {
            headers.push(FinalizedHeader {
                name: http::header::CONTENT_LENGTH,
                value: Zeroizing::new(length.to_string().into_bytes()),
                protected: false,
            });
        }
        for name in protected_header_slots.iter() {
            headers.push(FinalizedHeader {
                name: name.clone(),
                value: Zeroizing::new(Vec::new()),
                protected: true,
            });
        }

        let mut request = Self {
            scheme: parsed.scheme,
            origin_host: parsed.host.clone(),
            effective_port: parsed.port.unwrap_or_else(|| parsed.scheme.default_port()),
            authority: parsed.authority_host().to_string(),
            method: parsed.method.clone(),
            raw_path_and_query: parsed.path.as_bytes().to_vec(),
            headers,
            protected_header_slots,
            body,
            protocol,
            fingerprint: [0; 32],
        };
        request.ensure_header_budget(max_header_bytes)?;
        request.fingerprint = request.compute_base_fingerprint();
        Ok(request)
    }

    pub(crate) fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub(crate) fn origin_host(&self) -> &str {
        &self.origin_host
    }

    pub(crate) fn effective_port(&self) -> u16 {
        self.effective_port
    }

    pub(crate) fn authority(&self) -> &str {
        &self.authority
    }

    pub(crate) fn method(&self) -> &http::Method {
        &self.method
    }

    pub(crate) fn raw_path_and_query(&self) -> &[u8] {
        &self.raw_path_and_query
    }

    pub(crate) fn headers(&self) -> &[FinalizedHeader] {
        &self.headers
    }

    pub(crate) fn protected_header_slots(&self) -> &[HeaderName] {
        &self.protected_header_slots
    }

    pub(crate) fn body(&self) -> Option<&[u8]> {
        self.body.as_ref().map(BufferedBody::bytes)
    }

    pub(crate) fn client_body_wire_bytes(&self) -> u64 {
        self.body.as_ref().map_or(0, BufferedBody::wire_bytes)
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub(crate) fn apply_protected_headers(
        &mut self,
        values: Vec<(HeaderName, Zeroizing<Vec<u8>>)>,
        max_header_bytes: usize,
    ) -> Result<()> {
        ensure!(
            values.len() == self.protected_header_slots.len(),
            "authorization service did not return exactly the protected header slots"
        );
        let mut seen = std::collections::HashSet::new();
        for (name, value) in values {
            ensure!(
                seen.insert(name.clone()),
                "authorization service returned a duplicate protected header"
            );
            ensure!(
                self.protected_header_slots.contains(&name),
                "authorization service returned an ungranted protected header"
            );
            HeaderValue::from_bytes(&value).with_context(|| {
                format!("authorization service returned invalid value for '{name}'")
            })?;
            let slot = self
                .headers
                .iter_mut()
                .find(|header| header.protected && header.name == name)
                .context("protected header slot is missing")?;
            slot.value = value;
        }
        self.ensure_header_budget(max_header_bytes)?;
        ensure!(
            self.compute_base_fingerprint() == self.fingerprint,
            "finalized request changed while applying protected headers"
        );
        Ok(())
    }

    pub(crate) fn encode_http1_head(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.method.as_str().as_bytes());
        bytes.push(b' ');
        bytes.extend_from_slice(&self.raw_path_and_query);
        bytes.extend_from_slice(b" HTTP/1.1\r\n");
        for header in &self.headers {
            bytes.extend_from_slice(header.name.as_str().as_bytes());
            bytes.extend_from_slice(b": ");
            bytes.extend_from_slice(header.value());
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"\r\n");
        bytes
    }

    pub(crate) fn build_http2_request(&self) -> Result<http::Request<()>> {
        let path = std::str::from_utf8(&self.raw_path_and_query)
            .context("finalized request path is not UTF-8")?;
        let uri = http::Uri::builder()
            .scheme(scheme_name(self.scheme))
            .authority(self.authority.as_str())
            .path_and_query(path)
            .build()
            .context("failed to build finalized HTTP/2 URI")?;
        let mut builder = http::Request::builder()
            .method(self.method.clone())
            .uri(uri)
            .version(http::Version::HTTP_2);
        let output = builder
            .headers_mut()
            .expect("headers available before request body");
        for header in &self.headers {
            let mut value = HeaderValue::from_bytes(header.value())
                .with_context(|| format!("finalized header '{}' is invalid", header.name))?;
            value.set_sensitive(header.protected);
            output.append(header.name.clone(), value);
        }
        builder
            .body(())
            .context("failed to build finalized HTTP/2 request")
    }

    pub(crate) fn into_http2_parts(mut self) -> Result<(http::Request<()>, Option<BufferedBody>)> {
        let request = self.build_http2_request()?;
        Ok((request, self.body.take()))
    }

    fn ensure_header_budget(&self, max_header_bytes: usize) -> Result<()> {
        let mut total = 0usize;
        let mut record = |name: &[u8], value: &[u8]| -> Result<()> {
            total = total
                .checked_add(name.len())
                .and_then(|total| total.checked_add(value.len()))
                .and_then(|total| total.checked_add(4))
                .context("finalized request header size overflow")?;
            Ok(())
        };
        if matches!(self.protocol, FinalizedProtocol::Http2) {
            record(b":method", self.method.as_str().as_bytes())?;
            record(b":scheme", scheme_name(self.scheme).as_bytes())?;
            record(b":authority", self.authority.as_bytes())?;
            record(b":path", &self.raw_path_and_query)?;
        }
        for header in &self.headers {
            record(header.name.as_str().as_bytes(), header.value())?;
        }
        if matches!(self.protocol, FinalizedProtocol::Http1) {
            total = total
                .checked_add(self.method.as_str().len())
                .and_then(|total| total.checked_add(1))
                .and_then(|total| total.checked_add(self.raw_path_and_query.len()))
                .and_then(|total| total.checked_add(b" HTTP/1.1\r\n".len()))
                .and_then(|total| total.checked_add(2))
                .context("finalized request header size overflow")?;
        }
        ensure!(
            total <= max_header_bytes,
            "finalized request headers exceed configured limit"
        );
        Ok(())
    }

    fn compute_base_fingerprint(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"exfilguard:finalized-request:v1\0");
        encode_map_len(&mut digest, 13);
        encode_uint(&mut digest, 0);
        encode_uint(&mut digest, 1);
        encode_uint(&mut digest, 1);
        encode_text(&mut digest, scheme_name(self.scheme));
        encode_uint(&mut digest, 2);
        encode_text(&mut digest, &self.origin_host);
        encode_uint(&mut digest, 3);
        encode_uint(&mut digest, self.effective_port as u64);
        encode_uint(&mut digest, 4);
        encode_text(&mut digest, &self.authority);
        encode_uint(&mut digest, 5);
        encode_text(&mut digest, self.method.as_str());
        encode_uint(&mut digest, 6);
        encode_bytes(&mut digest, &self.raw_path_and_query);
        encode_uint(&mut digest, 7);
        encode_array_len(&mut digest, self.headers.len());
        for header in &self.headers {
            encode_array_len(&mut digest, 2);
            encode_text(&mut digest, header.name.as_str());
            if header.protected {
                encode_bytes(&mut digest, &[]);
            } else {
                encode_bytes(&mut digest, header.value());
            }
        }
        encode_uint(&mut digest, 8);
        encode_array_len(&mut digest, self.protected_header_slots.len());
        for name in self.protected_header_slots.iter() {
            encode_text(&mut digest, name.as_str());
        }
        encode_uint(&mut digest, 9);
        encode_text(
            &mut digest,
            if self.body.is_some() {
                "buffered_payload"
            } else {
                "none"
            },
        );
        encode_uint(&mut digest, 10);
        encode_bytes(&mut digest, self.body().unwrap_or_default());
        encode_uint(&mut digest, 11);
        encode_uint(&mut digest, self.body().map_or(0, |body| body.len()) as u64);
        encode_uint(&mut digest, 12);
        digest.update([0xf6]);

        digest.finalize().into()
    }
}

fn encode_uint(output: &mut Sha256, value: u64) {
    encode_major(output, 0, value);
}

fn encode_bytes(output: &mut Sha256, value: &[u8]) {
    encode_major(output, 2, value.len() as u64);
    output.update(value);
}

fn encode_text(output: &mut Sha256, value: &str) {
    encode_major(output, 3, value.len() as u64);
    output.update(value.as_bytes());
}

fn encode_array_len(output: &mut Sha256, length: usize) {
    encode_major(output, 4, length as u64);
}

fn encode_map_len(output: &mut Sha256, length: usize) {
    encode_major(output, 5, length as u64);
}

fn encode_major(output: &mut Sha256, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => output.update([prefix | value as u8]),
        24..=0xff => output.update([prefix | 24, value as u8]),
        0x100..=0xffff => {
            output.update([prefix | 25]);
            output.update((value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.update([prefix | 26]);
            output.update((value as u32).to_be_bytes());
        }
        _ => {
            output.update([prefix | 27]);
            output.update(value.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::request::parse_http1_request;
    use tokio::sync::Semaphore;

    #[test]
    fn protected_values_do_not_change_base_fingerprint() {
        let parsed = parse_http1_request(
            http::Method::GET,
            "http://example.com/raw%2Fpath?b=2&a=1",
            None,
            Scheme::Http,
        )
        .unwrap();
        let slots: Arc<[HeaderName]> = Arc::from([http::header::AUTHORIZATION]);
        let mut request = FinalizedRequestV1::new(
            &parsed,
            [(http::header::ACCEPT, HeaderValue::from_static("text/plain"))],
            None,
            None,
            slots,
            FinalizedProtocol::Http1,
            4096,
        )
        .unwrap();
        let before = request.fingerprint();
        assert_eq!(
            before,
            [
                0x08, 0xde, 0xe5, 0xb7, 0x86, 0x36, 0x91, 0xba, 0x26, 0xac, 0x49, 0x1a, 0x2c, 0x1c,
                0x3c, 0x3c, 0x0b, 0xf5, 0x86, 0x55, 0xf7, 0x53, 0xa7, 0x12, 0x27, 0x0a, 0xdb, 0x80,
                0x4c, 0xf0, 0xd6, 0xc8,
            ]
        );
        request
            .apply_protected_headers(
                vec![(
                    http::header::AUTHORIZATION,
                    Zeroizing::new(b"Bearer protected".to_vec()),
                )],
                4096,
            )
            .unwrap();
        assert_eq!(request.fingerprint(), before);
        assert!(
            request
                .encode_http1_head()
                .windows(b"authorization: Bearer protected".len())
                .any(|window| window == b"authorization: Bearer protected")
        );
        let http2 = request.build_http2_request().unwrap();
        assert!(http2.headers()[http::header::AUTHORIZATION].is_sensitive());
        assert!(!http2.headers()[http::header::ACCEPT].is_sensitive());
    }

    #[test]
    fn client_cannot_occupy_a_protected_slot() {
        let parsed = parse_http1_request(
            http::Method::GET,
            "https://example.com/resource",
            None,
            Scheme::Https,
        )
        .unwrap();
        let result = FinalizedRequestV1::new(
            &parsed,
            [(
                http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer client"),
            )],
            None,
            None,
            Arc::from([http::header::AUTHORIZATION]),
            FinalizedProtocol::Http1,
            4096,
        );
        assert!(result.is_err());
    }

    #[test]
    fn authorization_service_must_fill_exactly_the_granted_slots() {
        let parsed = parse_http1_request(
            http::Method::GET,
            "https://example.com/resource",
            None,
            Scheme::Https,
        )
        .unwrap();
        let slots: Arc<[HeaderName]> = Arc::from([
            http::header::AUTHORIZATION,
            HeaderName::from_static("x-api-key"),
        ]);
        let mut request = FinalizedRequestV1::new(
            &parsed,
            std::iter::empty::<(HeaderName, HeaderValue)>(),
            None,
            None,
            slots,
            FinalizedProtocol::Http1,
            4096,
        )
        .unwrap();
        assert!(
            request
                .apply_protected_headers(
                    vec![(
                        http::header::AUTHORIZATION,
                        Zeroizing::new(b"Bearer fixture".to_vec()),
                    )],
                    4096,
                )
                .is_err()
        );
    }

    #[test]
    fn http2_budget_includes_pseudo_headers() {
        let parsed = parse_http1_request(
            http::Method::GET,
            "https://example.com/resource",
            None,
            Scheme::Https,
        )
        .unwrap();
        let headers = std::iter::empty::<(HeaderName, HeaderValue)>();
        assert!(
            FinalizedRequestV1::new(
                &parsed,
                headers.clone(),
                None,
                None,
                Arc::from([]),
                FinalizedProtocol::Http1,
                50,
            )
            .is_ok()
        );
        assert!(
            FinalizedRequestV1::new(
                &parsed,
                headers,
                None,
                None,
                Arc::from([]),
                FinalizedProtocol::Http2,
                50,
            )
            .is_err()
        );
    }

    #[test]
    fn http1_budget_matches_serialized_head() {
        let parsed = parse_http1_request(
            http::Method::POST,
            "https://example.com/a/long/request/target?with=query",
            None,
            Scheme::Https,
        )
        .unwrap();
        let make_request = |limit| {
            FinalizedRequestV1::new(
                &parsed,
                [(
                    http::header::ACCEPT,
                    HeaderValue::from_static("application/json"),
                )],
                None,
                None,
                Arc::from([]),
                FinalizedProtocol::Http1,
                limit,
            )
        };
        let serialized_len = make_request(4096).unwrap().encode_http1_head().len();

        assert!(make_request(serialized_len).is_ok());
        assert!(make_request(serialized_len - 1).is_err());
    }

    #[tokio::test]
    async fn http2_parts_keep_body_reservation_only_with_body() {
        let parsed = parse_http1_request(
            http::Method::POST,
            "https://example.com/resource",
            None,
            Scheme::Https,
        )
        .unwrap();
        let permits = Arc::new(Semaphore::new(1));
        let body = BufferedBody::new(
            vec![b'x'],
            1,
            permits.clone().acquire_owned().await.unwrap(),
        );
        let request = FinalizedRequestV1::new(
            &parsed,
            std::iter::empty::<(HeaderName, HeaderValue)>(),
            Some(1),
            Some(body),
            Arc::from([]),
            FinalizedProtocol::Http2,
            4096,
        )
        .unwrap();

        let (_head, body) = request.into_http2_parts().unwrap();
        assert_eq!(permits.available_permits(), 0);
        drop(body);
        assert_eq!(permits.available_permits(), 1);
    }
}
