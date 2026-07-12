use std::{collections::HashMap, sync::Arc};

use parking_lot::Mutex;

#[derive(Default)]
pub struct ClientConnectionLimiter {
    active: Mutex<HashMap<Arc<str>, usize>>,
}

impl ClientConnectionLimiter {
    pub fn try_acquire(
        self: &Arc<Self>,
        client: Arc<str>,
        limit: usize,
    ) -> Option<ClientConnectionPermit> {
        let mut active = self.active.lock();
        let count = active.entry(client.clone()).or_default();
        if *count >= limit {
            return None;
        }
        *count += 1;
        Some(ClientConnectionPermit {
            limiter: self.clone(),
            client,
        })
    }

    fn release(&self, client: &Arc<str>) {
        let mut active = self.active.lock();
        let remove = if let Some(count) = active.get_mut(client) {
            debug_assert!(*count > 0);
            *count -= 1;
            *count == 0
        } else {
            debug_assert!(
                false,
                "client connection permit released without accounting"
            );
            false
        };
        if remove {
            active.remove(client);
        }
    }

    #[cfg(test)]
    fn active(&self, client: &str) -> usize {
        self.active.lock().get(client).copied().unwrap_or(0)
    }
}

#[must_use]
pub struct ClientConnectionPermit {
    limiter: Arc<ClientConnectionLimiter>,
    client: Arc<str>,
}

impl Drop for ClientConnectionPermit {
    fn drop(&mut self) {
        self.limiter.release(&self.client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_is_per_client_and_capacity_recovers_on_drop() {
        let limiter = Arc::new(ClientConnectionLimiter::default());
        let first = limiter
            .try_acquire(Arc::from("alpha"), 2)
            .expect("first alpha connection admitted");
        let second = limiter
            .try_acquire(Arc::from("alpha"), 2)
            .expect("second alpha connection admitted");
        let beta = limiter
            .try_acquire(Arc::from("beta"), 1)
            .expect("beta has an independent budget");

        assert!(limiter.try_acquire(Arc::from("alpha"), 2).is_none());
        assert!(limiter.try_acquire(Arc::from("beta"), 1).is_none());
        assert_eq!(limiter.active("alpha"), 2);
        assert_eq!(limiter.active("beta"), 1);

        drop(first);
        let replacement = limiter
            .try_acquire(Arc::from("alpha"), 2)
            .expect("released capacity should be reusable");
        assert_eq!(limiter.active("alpha"), 2);

        drop(second);
        drop(replacement);
        drop(beta);
        assert_eq!(limiter.active("alpha"), 0);
        assert_eq!(limiter.active("beta"), 0);
    }

    #[test]
    fn lower_reloaded_limit_does_not_reset_existing_accounting() {
        let limiter = Arc::new(ClientConnectionLimiter::default());
        let first = limiter
            .try_acquire(Arc::from("client"), 2)
            .expect("first connection admitted");
        let second = limiter
            .try_acquire(Arc::from("client"), 2)
            .expect("second connection admitted");

        assert!(limiter.try_acquire(Arc::from("client"), 1).is_none());
        drop(first);
        assert!(limiter.try_acquire(Arc::from("client"), 1).is_none());
        drop(second);
        assert!(limiter.try_acquire(Arc::from("client"), 1).is_some());
    }
}
