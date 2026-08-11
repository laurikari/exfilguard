use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use http::header::HeaderName;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::config::AuthorizationServiceSettings;
use super::finalized::FinalizedRequestV1;
use super::policy::CredentialAuthorization;
use super::service::read_bounded_response;

pub(super) struct CredentialPreparerClient {
    client: reqwest::Client,
    url: reqwest::Url,
    concurrency: Arc<Semaphore>,
    max_response_size: usize,
    timeout: Duration,
}

impl CredentialPreparerClient {
    pub(super) fn new(
        settings: &AuthorizationServiceSettings,
        client: reqwest::Client,
        concurrency: Arc<Semaphore>,
        max_response_size: usize,
    ) -> Result<Self> {
        Ok(Self {
            client,
            url: reqwest::Url::parse(&settings.credential_url)?,
            concurrency,
            max_response_size,
            timeout: Duration::from_secs(settings.timeout),
        })
    }

    pub(super) async fn prepare_headers(
        &self,
        audience: &str,
        source_ip: IpAddr,
        authorization: &CredentialAuthorization,
        request: &mut FinalizedRequestV1,
        max_protected_headers: usize,
        max_header_bytes: usize,
    ) -> Result<()> {
        ensure!(
            authorization.protected_headers.len() <= max_protected_headers,
            "credential decision exceeds the protected-header count limit"
        );
        let nonce = Uuid::new_v4().to_string();
        let fingerprint = request.fingerprint();
        let wire_request = CredentialRequest {
            authorization_token: authorization.token.token(),
            credential_reference: &authorization.credential_reference,
            audience,
            source_ip,
            request_nonce: &nonce,
            request_fingerprint: fingerprint,
            finalized_request: FinalizedRequestWire::from_request(request),
        };

        let response_bytes = Zeroizing::new(
            timeout(self.timeout, async {
                let _permit = self
                    .concurrency
                    .acquire()
                    .await
                    .context("authorization-service concurrency limiter closed")?;
                let request_body = serialize_json_exact(&wire_request)
                    .context("credential request could not be serialized")?;
                let response = self
                    .client
                    .post(self.url.clone())
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(request_body)
                    .send()
                    .await
                    .context("authorization-service credential request failed")?;
                ensure!(
                    response.status().is_success(),
                    "authorization service returned a non-success credential status"
                );
                read_bounded_response(response, self.max_response_size)
                    .await
                    .context("authorization-service credential response could not be read")
            })
            .await
            .context("authorization-service credential operation timed out")??,
        );
        let response: CredentialResponse = serde_json::from_slice(&response_bytes)
            .context("invalid authorization-service credential JSON response")?;

        let headers = validate_response(response, &nonce, fingerprint, max_protected_headers)?;
        request.apply_protected_headers(headers, max_header_bytes)
    }
}

fn serialize_json_exact(value: &impl Serialize) -> Result<Vec<u8>> {
    struct ByteCounter(usize);

    impl Write for ByteCounter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("serialized JSON size overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut count = ByteCounter(0);
    serde_json::to_writer(&mut count, value)?;
    let mut bytes = Vec::with_capacity(count.0);
    serde_json::to_writer(&mut bytes, value)?;
    debug_assert_eq!(bytes.len(), count.0);
    Ok(bytes)
}

#[derive(Serialize)]
struct CredentialRequest<'a> {
    authorization_token: &'a str,
    credential_reference: &'a str,
    audience: &'a str,
    source_ip: IpAddr,
    request_nonce: &'a str,
    request_fingerprint: [u8; 32],
    finalized_request: FinalizedRequestWire<'a>,
}

#[derive(Serialize)]
struct FinalizedRequestWire<'a> {
    version: u8,
    scheme: &'static str,
    origin_host: &'a str,
    effective_port: u16,
    authority: &'a str,
    method: &'a str,
    raw_path_and_query: &'a [u8],
    headers: Vec<HeaderWire<'a>>,
    protected_header_slots: Vec<&'a str>,
    body_kind: &'static str,
    body: &'a [u8],
    payload_length: usize,
    trailers: Option<()>,
}

impl<'a> FinalizedRequestWire<'a> {
    fn from_request(request: &'a FinalizedRequestV1) -> Self {
        let body = request.body().unwrap_or_default();
        Self {
            version: 1,
            scheme: crate::proxy::request::scheme_name(request.scheme()),
            origin_host: request.origin_host(),
            effective_port: request.effective_port(),
            authority: request.authority(),
            method: request.method().as_str(),
            raw_path_and_query: request.raw_path_and_query(),
            headers: request
                .headers()
                .iter()
                .map(|header| HeaderWire {
                    name: header.name.as_str(),
                    value: if header.is_protected() {
                        &[]
                    } else {
                        header.value()
                    },
                })
                .collect(),
            protected_header_slots: request
                .protected_header_slots()
                .iter()
                .map(HeaderName::as_str)
                .collect(),
            body_kind: if request.body().is_some() {
                "buffered_payload"
            } else {
                "none"
            },
            body,
            payload_length: body.len(),
            trailers: None,
        }
    }
}

#[derive(Serialize)]
struct HeaderWire<'a> {
    name: &'a str,
    value: &'a [u8],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialResponse {
    request_nonce: String,
    request_fingerprint: [u8; 32],
    expires_at: u64,
    protected_headers: Vec<ProtectedHeaderWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedHeaderWire {
    name: String,
    value: Vec<u8>,
}

fn validate_response(
    response: CredentialResponse,
    nonce: &str,
    fingerprint: [u8; 32],
    max_protected_headers: usize,
) -> Result<Vec<(HeaderName, Zeroizing<Vec<u8>>)>> {
    ensure!(
        response.request_nonce == nonce,
        "credential response nonce mismatch"
    );
    ensure!(
        response.request_fingerprint == fingerprint,
        "credential response fingerprint mismatch"
    );
    let now = unix_now().context("system time is before the Unix epoch")?;
    ensure!(response.expires_at > now, "credential response is expired");
    ensure!(
        response.protected_headers.len() <= max_protected_headers,
        "authorization service returned too many protected headers"
    );

    let mut headers = Vec::with_capacity(response.protected_headers.len());
    for header in response.protected_headers {
        let name = HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| {
            anyhow::anyhow!("authorization service returned an invalid protected header name")
        })?;
        headers.push((name, Zeroizing::new(header.value)));
    }
    Ok(headers)
}

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response() -> CredentialResponse {
        let now = unix_now().unwrap();
        CredentialResponse {
            request_nonce: "nonce".to_string(),
            request_fingerprint: [7; 32],
            expires_at: now + 10,
            protected_headers: vec![ProtectedHeaderWire {
                name: "authorization".to_string(),
                value: b"Bearer fixture".to_vec(),
            }],
        }
    }

    #[test]
    fn credential_response_is_bound_to_nonce_fingerprint_and_its_own_expiry() {
        let now = unix_now().unwrap();
        assert!(validate_response(response(), "nonce", [7; 32], 2).is_ok());
        assert!(validate_response(response(), "wrong", [7; 32], 2).is_err());
        assert!(validate_response(response(), "nonce", [8; 32], 2).is_err());
        let mut expired = response();
        expired.expires_at = now;
        assert!(validate_response(expired, "nonce", [7; 32], 2).is_err());
        assert!(validate_response(response(), "nonce", [7; 32], 0).is_err());
    }

    #[test]
    fn credential_response_rejects_malformed_header_names() {
        let mut invalid = response();
        invalid.protected_headers[0].name = "SECRET bad header".to_string();
        let error = validate_response(invalid, "nonce", [7; 32], 2)
            .expect_err("malformed header name must be rejected");
        assert_eq!(
            error.to_string(),
            "authorization service returned an invalid protected header name"
        );
    }

    #[test]
    fn exact_json_serialization_does_not_overallocate() {
        let value = serde_json::json!({"body": [0, 9, 99, 255]});
        let bytes = serialize_json_exact(&value).unwrap();
        assert_eq!(bytes.len(), bytes.capacity());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            value
        );
    }
}
