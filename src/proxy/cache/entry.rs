use std::time::SystemTime;

use http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};

use super::VaryKey;

#[derive(Debug, Clone)]
pub(super) struct CacheEntry {
    pub id: u64,
    pub entry_id: String,
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub vary: VaryKey,
    pub expires_at: SystemTime,
    pub content_hash: String,
    pub content_length: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PersistedEntry {
    pub key_base: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub vary_headers: Vec<(String, String)>,
    pub expires_at: u64,
    pub content_hash: String,
    pub content_length: u64,
}

impl CacheEntry {
    pub(super) fn to_persisted(&self, key_base: &str) -> PersistedEntry {
        PersistedEntry {
            key_base: key_base.to_string(),
            status: self.status.as_u16(),
            headers: headermap_to_vec(&self.headers),
            vary_headers: headermap_to_vec(self.vary.headers()),
            expires_at: self
                .expires_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            content_hash: self.content_hash.clone(),
            content_length: self.content_length,
        }
    }

    pub(super) fn from_persisted(
        persisted: &PersistedEntry,
        entry_id: &str,
        id: u64,
        expires_at: SystemTime,
    ) -> Self {
        let headers = to_headermap(&persisted.headers);
        let vary_headers = to_headermap(&persisted.vary_headers);
        let vary = VaryKey::new(vary_headers);

        Self {
            id,
            status: StatusCode::from_u16(persisted.status).unwrap_or(StatusCode::OK),
            headers,
            vary,
            expires_at,
            entry_id: entry_id.to_string(),
            content_hash: persisted.content_hash.clone(),
            content_length: persisted.content_length,
        }
    }
}

fn to_headermap(items: &[(String, String)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in items {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::try_from(name.as_str()),
            http::HeaderValue::from_str(value),
        ) {
            map.append(name, value);
        }
    }
    map
}

fn headermap_to_vec(map: &HeaderMap) -> Vec<(String, String)> {
    let mut items = Vec::new();
    for (name, value) in map.iter() {
        if let Ok(value_str) = value.to_str() {
            items.push((name.as_str().to_string(), value_str.to_string()));
        }
    }
    items
}
