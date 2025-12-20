use std::num::NonZeroUsize;

use lru::LruCache;

use super::CacheEntry;

#[derive(Debug)]
pub(super) struct CacheIndex {
    lru: LruCache<String, CacheEntry>,
    bytes_in_use: u64,
    max_bytes: u64,
}

impl CacheIndex {
    pub(super) fn new(capacity: NonZeroUsize, max_bytes: u64) -> Self {
        Self {
            lru: LruCache::new(capacity),
            bytes_in_use: 0,
            max_bytes,
        }
    }

    pub(super) fn reset(&mut self) {
        self.bytes_in_use = 0;
        self.lru.clear();
    }

    pub(super) fn get(&mut self, key_base: &str) -> Option<CacheEntry> {
        self.lru.get(key_base).cloned()
    }

    pub(super) fn remove_if_id_matches(
        &mut self,
        key_base: &str,
        entry_id: u64,
    ) -> Option<CacheEntry> {
        let matches = self
            .lru
            .get(key_base)
            .map(|entry| entry.id == entry_id)
            .unwrap_or(false);
        if matches && let Some(removed) = self.lru.pop(key_base) {
            self.bytes_in_use = self.bytes_in_use.saturating_sub(removed.content_length);
            return Some(removed);
        }
        None
    }

    pub(super) fn remove_by_key(&mut self, key_base: &str) -> Option<CacheEntry> {
        if let Some(removed) = self.lru.pop(key_base) {
            self.bytes_in_use = self.bytes_in_use.saturating_sub(removed.content_length);
            return Some(removed);
        }
        None
    }

    pub(super) fn insert(&mut self, key_base: String, entry: CacheEntry) -> Vec<CacheEntry> {
        let mut evicted = Vec::new();

        self.bytes_in_use = self.bytes_in_use.saturating_add(entry.content_length);

        if let Some((_key, removed)) = self.lru.push(key_base, entry) {
            self.bytes_in_use = self.bytes_in_use.saturating_sub(removed.content_length);
            evicted.push(removed);
        }

        while self.bytes_in_use > self.max_bytes {
            if let Some((_key, removed)) = self.lru.pop_lru() {
                self.bytes_in_use = self.bytes_in_use.saturating_sub(removed.content_length);
                evicted.push(removed);
            } else {
                break;
            }
        }

        evicted
    }

    #[cfg(test)]
    pub(super) fn bytes_in_use(&self) -> u64 {
        self.bytes_in_use
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.lru.len()
    }
}
