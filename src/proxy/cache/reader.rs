use std::sync::Arc;
use std::time::SystemTime;

use http::{HeaderMap, Method, Uri};
use tokio::fs as async_fs;
use tracing::{trace, warn};

use super::{CacheKey, CacheState, CachedResponse};

pub(super) struct CacheReader {
    state: Arc<CacheState>,
}

impl CacheReader {
    pub(super) fn new(state: Arc<CacheState>) -> Self {
        Self { state }
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

        if SystemTime::now() > entry.expires_at {
            trace!("cache entry expired");
            if self
                .state
                .remove_entry_if_id_matches(cache_key.key_base(), entry.id)
            {
                self.state
                    .remove_entry_files_for_entry_id_async(&entry.entry_id)
                    .await;
            }
            crate::metrics::record_cache_lookup(false);
            return None;
        }

        if !entry.vary.matches(req_headers) {
            trace!("cache entry vary mismatch");
            crate::metrics::record_cache_lookup(false);
            return None;
        }

        let body_path = self.state.body_path(&entry.entry_id);
        if let Err(err) = async_fs::metadata(&body_path).await {
            warn!(
                error = %err,
                path = %body_path.display(),
                "cache body missing on disk"
            );
            if self
                .state
                .remove_entry_if_id_matches(cache_key.key_base(), entry.id)
            {
                self.state
                    .remove_entry_files_for_entry_id_async(&entry.entry_id)
                    .await;
            }
            crate::metrics::record_cache_lookup(false);
            return None;
        }

        crate::metrics::record_cache_lookup(true);
        Some(CachedResponse {
            status: entry.status,
            headers: entry.headers.clone(),
            body_path,
            content_length: entry.content_length,
        })
    }
}
