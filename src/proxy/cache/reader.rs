use std::sync::Arc;
use std::time::SystemTime;

use http::{HeaderMap, Method, Uri};
use tokio::fs as async_fs;
use tracing::{trace, warn};

use super::{CacheEntry, CacheKey, CacheState, CachedResponse};

pub(super) struct CacheReader {
    state: Arc<CacheState>,
}

impl CacheReader {
    pub(super) fn new(state: Arc<CacheState>) -> Self {
        Self { state }
    }

    async fn invalidate_entry(&self, key_base: &str, entry: &CacheEntry) {
        let _publish_guard = self.state.publish_lock().lock().await;
        if let Some(removed) = self.state.remove_entry_if_id_matches(key_base, entry.id) {
            self.state
                .store
                .remove_entry_files_async(&removed.key_id, &removed.body_id)
                .await;
        }
    }

    pub(super) async fn lookup(
        &self,
        method: &Method,
        uri: &Uri,
        req_headers: &HeaderMap,
    ) -> Option<CachedResponse> {
        let cache_key = CacheKey::new(method, uri);

        let entry = {
            let mut guard = self.state.index.lock();
            guard.get(cache_key.key_base())
        };

        let entry = match entry {
            Some(entry) => entry,
            None => {
                crate::metrics::record_cache_lookup(false);
                return None;
            }
        };

        let now = SystemTime::now();
        if now >= entry.expires_at {
            trace!("cache entry expired");
            self.invalidate_entry(cache_key.key_base(), &entry).await;
            crate::metrics::record_cache_lookup(false);
            return None;
        }

        if !entry.vary.matches(req_headers) {
            trace!("cache entry vary mismatch");
            crate::metrics::record_cache_lookup(false);
            return None;
        }

        let body_path = self.state.body_path(&entry.body_id);
        let metadata = match async_fs::symlink_metadata(&body_path).await {
            Ok(metadata) => metadata,
            Err(err) => {
                warn!(
                    error = %err,
                    path = %body_path.display(),
                    "cache body missing on disk"
                );
                self.invalidate_entry(cache_key.key_base(), &entry).await;
                crate::metrics::record_cache_lookup(false);
                return None;
            }
        };

        if !metadata.file_type().is_file() || metadata.len() != entry.content_length {
            warn!(
                path = %body_path.display(),
                expected_length = entry.content_length,
                actual_length = metadata.len(),
                "cache body failed validation on disk"
            );
            self.invalidate_entry(cache_key.key_base(), &entry).await;
            crate::metrics::record_cache_lookup(false);
            return None;
        }

        let body = match async_fs::File::open(&body_path).await {
            Ok(file) => file,
            Err(err) => {
                warn!(
                    error = %err,
                    path = %body_path.display(),
                    "cache body could not be opened"
                );
                self.invalidate_entry(cache_key.key_base(), &entry).await;
                crate::metrics::record_cache_lookup(false);
                return None;
            }
        };

        let mut headers = entry.headers.clone();
        headers.remove(http::header::AGE);
        let age = entry.current_age(now).as_secs();
        headers.insert(
            http::header::AGE,
            http::HeaderValue::from_str(&age.to_string()).expect("generated Age header is valid"),
        );

        crate::metrics::record_cache_lookup(true);
        Some(CachedResponse {
            status: entry.status,
            headers,
            body_path,
            body,
            content_length: entry.content_length,
        })
    }
}
