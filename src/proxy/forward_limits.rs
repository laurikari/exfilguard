use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, ensure};
use http::StatusCode;

use crate::proxy::{allow_log::AllowLogStats, http::BodyTooLarge};

/// Tracks cumulative payload bytes and enforces a configured limit.
pub struct BodySizeTracker {
    max_bytes: usize,
    total_bytes: u64,
}

impl BodySizeTracker {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
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
        if self.total_bytes as usize > self.max_bytes {
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

    pub fn add_client_bytes(&mut self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.bytes_in = self.bytes_in.saturating_add(bytes);
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
