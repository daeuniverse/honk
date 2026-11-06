//! Accepted-flow admission and optional shutdown draining.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tracing::{info, warn};

const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Tracks the state of connection draining during shutdown.
pub struct DrainTracker {
    active_connections: AtomicUsize,
    reject_new: AtomicBool,
    drain_timeout: Duration,
}

impl DrainTracker {
    pub fn new() -> Self {
        Self {
            active_connections: AtomicUsize::new(0),
            reject_new: AtomicBool::new(false),
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        }
    }

    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    pub fn increment(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn start_rejecting(&self) {
        self.reject_new.store(true, Ordering::SeqCst);
        info!("DrainTracker: rejecting new connections");
    }

    /// Stop rejecting new connections (e.g., after config reload).
    pub fn stop_rejecting(&self) {
        self.reject_new.store(false, Ordering::SeqCst);
        info!("DrainTracker: accepting new connections again");
    }

    pub fn should_reject(&self) -> bool {
        self.reject_new.load(Ordering::SeqCst)
    }

    pub fn active_count(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub async fn drain(&self) -> anyhow::Result<usize> {
        self.start_rejecting();

        let remaining = self.active_count();
        if remaining == 0 {
            info!("DrainTracker: no active connections to drain");
            return Ok(0);
        }

        info!(
            "DrainTracker: waiting for {} connections to drain (timeout {:?})",
            remaining, self.drain_timeout
        );

        let deadline = tokio::time::Instant::now() + self.drain_timeout;
        loop {
            let count = self.active_count();
            if count == 0 {
                info!("DrainTracker: all connections drained");
                return Ok(0);
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    "DrainTracker: drain timeout after {:?}, {} connections remaining",
                    self.drain_timeout, count
                );
                return Ok(count);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Default for DrainTracker {
    fn default() -> Self {
        Self::new()
    }
}
