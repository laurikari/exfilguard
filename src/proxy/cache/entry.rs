use std::time::{Duration, SystemTime};

use http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};

use super::VaryKey;

#[derive(Debug, Clone)]
pub(super) struct CacheEntry {
    pub id: u64,
    pub key_id: String,
    pub body_id: String,
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub vary: VaryKey,
    pub response_time: SystemTime,
    pub corrected_initial_age: Duration,
    pub expires_at: SystemTime,
    pub content_hash: String,
    pub content_length: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PersistedEntry {
    pub key_base: String,
    pub body_id: String,
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub vary_headers: Vec<(String, Vec<u8>)>,
    pub response_time_unix_millis: u64,
    pub corrected_initial_age_millis: u64,
    pub expires_at_unix_millis: u64,
    pub content_hash: String,
    pub content_length: u64,
}

impl CacheEntry {
    pub(super) fn to_persisted(&self, key_base: &str) -> PersistedEntry {
        PersistedEntry {
            key_base: key_base.to_string(),
            body_id: self.body_id.clone(),
            status: self.status.as_u16(),
            headers: headermap_to_bytes_vec(&self.headers),
            vary_headers: headermap_to_bytes_vec(self.vary.headers()),
            response_time_unix_millis: system_time_unix_millis(self.response_time),
            corrected_initial_age_millis: duration_millis(self.corrected_initial_age),
            expires_at_unix_millis: system_time_unix_millis(self.expires_at),
            content_hash: self.content_hash.clone(),
            content_length: self.content_length,
        }
    }

    pub(super) fn from_persisted(
        persisted: &PersistedEntry,
        key_id: &str,
        id: u64,
        response_time: SystemTime,
        corrected_initial_age: Duration,
        expires_at: SystemTime,
    ) -> Option<Self> {
        let status = StatusCode::from_u16(persisted.status).ok()?;
        let headers = bytes_vec_to_headermap(&persisted.headers)?;
        let vary_headers = bytes_vec_to_headermap(&persisted.vary_headers)?;
        let vary = VaryKey::new(vary_headers);

        Some(Self {
            id,
            status,
            headers,
            vary,
            response_time,
            corrected_initial_age,
            expires_at,
            key_id: key_id.to_string(),
            body_id: persisted.body_id.clone(),
            content_hash: persisted.content_hash.clone(),
            content_length: persisted.content_length,
        })
    }

    pub(super) fn current_age(&self, now: SystemTime) -> Duration {
        self.corrected_initial_age
            .saturating_add(now.duration_since(self.response_time).unwrap_or_default())
    }
}

fn system_time_unix_millis(value: SystemTime) -> u64 {
    value
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn duration_millis(value: Duration) -> u64 {
    value.as_millis().min(u128::from(u64::MAX)) as u64
}

fn bytes_vec_to_headermap(items: &[(String, Vec<u8>)]) -> Option<HeaderMap> {
    let mut map = HeaderMap::new();
    for (name, value) in items {
        let name = http::header::HeaderName::try_from(name.as_str()).ok()?;
        let value = http::HeaderValue::from_bytes(value).ok()?;
        map.append(name, value);
    }
    Some(map)
}

fn headermap_to_bytes_vec(map: &HeaderMap) -> Vec<(String, Vec<u8>)> {
    map.iter()
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect()
}
