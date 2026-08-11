use std::future::Future;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicU16, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, ensure};
use http::StatusCode;

use crate::proxy::{
    allow_log::AllowLogStats,
    forward_error::{RequestTimeout, ResponseAlreadyStarted},
    http::BodyTooLarge,
};

const RESPONSE_STARTED: u8 = 1;
const RESPONSE_COMPLETE: u8 = 2;

/// One absolute budget for all work needed to serve an accepted HTTP request.
#[derive(Clone, Copy)]
pub struct RequestDeadline {
    deadline: Option<Instant>,
}

impl RequestDeadline {
    pub fn new(start: Instant, timeout: Option<Duration>) -> Self {
        Self {
            deadline: timeout.and_then(|timeout| start.checked_add(timeout)),
        }
    }

    pub fn instant(self) -> Option<Instant> {
        self.deadline
    }

    /// Enforce the deadline until response delivery completes. Cleanup after delivery is
    /// intentionally allowed to finish without consuming the request budget.
    pub async fn run<F, T>(self, progress: &ResponseProgress, future: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        let Some(deadline) = self.deadline else {
            return progress.guard_result(future.await);
        };

        tokio::pin!(future);
        match tokio::time::timeout_at(deadline.into(), &mut future).await {
            Ok(result) => progress.guard_result(result),
            Err(_) if progress.is_complete() => progress.guard_result(future.await),
            Err(_) => Err(progress.timeout_error()),
        }
    }
}

/// Tracks whether a total-timeout response may still be sent safely.
#[derive(Clone, Default)]
pub struct ResponseProgress {
    inner: Arc<ResponseProgressInner>,
}

#[derive(Default)]
struct ResponseProgressInner {
    state: AtomicU8,
    status: AtomicU16,
    bytes_to_client: AtomicU64,
}

impl ResponseProgress {
    pub fn mark_started(&self, status: StatusCode, bytes_to_client: u64) {
        self.inner.status.store(status.as_u16(), Ordering::Relaxed);
        self.inner
            .bytes_to_client
            .store(bytes_to_client, Ordering::Relaxed);
        self.inner.state.store(RESPONSE_STARTED, Ordering::Release);
    }

    pub fn add_bytes(&self, bytes: u64) {
        self.inner
            .bytes_to_client
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn mark_complete(&self) {
        self.inner.state.store(RESPONSE_COMPLETE, Ordering::Release);
    }

    fn is_complete(&self) -> bool {
        self.inner.state.load(Ordering::Acquire) == RESPONSE_COMPLETE
    }

    fn guard_result<T>(&self, result: Result<T>) -> Result<T> {
        match result {
            Err(source)
                if self.inner.state.load(Ordering::Acquire) != 0
                    && source.downcast_ref::<ResponseAlreadyStarted>().is_none() =>
            {
                Err(self.started_error(source))
            }
            result => result,
        }
    }

    fn timeout_error(&self) -> anyhow::Error {
        if self.inner.state.load(Ordering::Acquire) != 0 {
            self.started_error(RequestTimeout.into())
        } else {
            RequestTimeout.into()
        }
    }

    fn started_error(&self, source: anyhow::Error) -> anyhow::Error {
        let status = StatusCode::from_u16(self.inner.status.load(Ordering::Relaxed))
            .unwrap_or(StatusCode::BAD_GATEWAY);
        let bytes_to_client = self.inner.bytes_to_client.load(Ordering::Relaxed);
        ResponseAlreadyStarted::new(status, bytes_to_client, source).into()
    }
}

/// Tracks cumulative payload bytes and enforces a configured limit.
pub struct BodySizeTracker {
    max_bytes: Option<u64>,
    total_bytes: u64,
}

impl BodySizeTracker {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes: (max_bytes > 0).then_some(max_bytes as u64),
            total_bytes: 0,
        }
    }

    pub fn record(&mut self, chunk_len: usize) -> Result<()> {
        if chunk_len == 0 {
            return Ok(());
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(chunk_len as u64)
            .ok_or(BodyTooLarge {
                bytes_read: self.total_bytes,
            })?;
        if let Some(max_bytes) = self.max_bytes
            && self.total_bytes > max_bytes
        {
            return Err(BodyTooLarge {
                bytes_read: self.total_bytes,
            }
            .into());
        }
        Ok(())
    }

    pub fn total(&self) -> u64 {
        self.total_bytes
    }
}

pub fn validate_declared_body_size(
    content_length: Option<usize>,
    max_request_body_size: usize,
) -> Result<()> {
    if max_request_body_size > 0
        && content_length.is_some_and(|length| length > max_request_body_size)
    {
        return Err(BodyTooLarge { bytes_read: 0 }.into());
    }
    Ok(())
}

/// Utility for enforcing a maximum number of header bytes while parsing.
pub struct HeaderBudget {
    limit: usize,
    used: usize,
    error_message: &'static str,
}

impl HeaderBudget {
    pub fn new(limit: usize, error_message: &'static str) -> Result<Self> {
        ensure!(limit > 0, "header limit must be greater than zero");
        Ok(Self {
            limit,
            used: 0,
            error_message,
        })
    }

    pub fn record(&mut self, bytes: usize) -> Result<()> {
        self.used = self
            .used
            .checked_add(bytes)
            .ok_or_else(|| anyhow!("header size overflow"))?;
        ensure!(self.used <= self.limit, "{}", self.error_message);
        Ok(())
    }

    pub fn used(&self) -> usize {
        self.used
    }
}

/// Tracks bytes seen from the client for logging purposes and builds shared allow-log stats.
pub struct AllowLogTracker {
    base_bytes: u64,
    bytes_in: u64,
    start: Instant,
}

impl AllowLogTracker {
    pub fn new(base_bytes: u64, start: Instant) -> Self {
        Self {
            base_bytes,
            bytes_in: base_bytes,
            start,
        }
    }

    pub fn record_client_body_bytes(&mut self, bytes: u64) {
        self.bytes_in = self.bytes_in.max(self.base_bytes.saturating_add(bytes));
    }

    pub fn base_bytes(&self) -> u64 {
        self.base_bytes
    }

    pub fn current_bytes(&self) -> u64 {
        self.bytes_in
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn build_allow_log_stats(
        &self,
        status: StatusCode,
        bytes_out: u64,
        upstream_addr: SocketAddr,
        upstream_reused: bool,
    ) -> AllowLogStats {
        AllowLogStats {
            status,
            bytes_in: self.bytes_in,
            bytes_out,
            elapsed: self.elapsed(),
            upstream_addr: upstream_addr.to_string(),
            upstream_reused,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;

    #[test]
    fn declared_body_size_validation_respects_limit_semantics() {
        assert!(validate_declared_body_size(Some(999), 1000).is_ok());
        assert!(validate_declared_body_size(Some(1000), 1000).is_ok());
        assert!(validate_declared_body_size(None, 1000).is_ok());
        assert!(validate_declared_body_size(Some(1001), 0).is_ok());

        let error = validate_declared_body_size(Some(1001), 1000).unwrap_err();
        let too_large = error.downcast_ref::<BodyTooLarge>().unwrap();
        assert_eq!(too_large.bytes_read, 0);
    }

    #[test]
    fn allow_log_tracker_records_the_largest_body_progress_once() {
        let mut tracker = AllowLogTracker::new(100, Instant::now());
        tracker.record_client_body_bytes(20);
        tracker.record_client_body_bytes(20);
        tracker.record_client_body_bytes(10);

        assert_eq!(tracker.current_bytes(), 120);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_times_out_before_response_starts() {
        let deadline = RequestDeadline::new(Instant::now(), Some(Duration::from_secs(1)));
        let progress = ResponseProgress::default();
        let task_progress = progress.clone();
        let task =
            tokio::spawn(
                async move { deadline.run(&task_progress, pending::<Result<()>>()).await },
            );

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let err = task.await.unwrap().unwrap_err();
        assert!(err.downcast_ref::<RequestTimeout>().is_some(), "{err:#}");
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_reports_a_started_response() {
        let deadline = RequestDeadline::new(Instant::now(), Some(Duration::from_secs(1)));
        let progress = ResponseProgress::default();
        progress.mark_started(StatusCode::OK, 42);
        let task_progress = progress.clone();
        let task =
            tokio::spawn(
                async move { deadline.run(&task_progress, pending::<Result<()>>()).await },
            );

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let err = task.await.unwrap().unwrap_err();
        let started = err.downcast_ref::<ResponseAlreadyStarted>().unwrap();
        assert_eq!(started.status, StatusCode::OK);
        assert_eq!(started.bytes_to_client, 42);
        assert!(started.source.downcast_ref::<RequestTimeout>().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn completed_response_cleanup_can_outlive_deadline() {
        let deadline = RequestDeadline::new(Instant::now(), Some(Duration::from_secs(1)));
        let progress = ResponseProgress::default();
        let task_progress = progress.clone();
        let task = tokio::spawn(async move {
            deadline
                .run(&task_progress, async {
                    task_progress.mark_started(StatusCode::OK, 42);
                    task_progress.mark_complete();
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Ok(())
                })
                .await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        task.await.unwrap().unwrap();
    }
}
