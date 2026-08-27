//! Per-connection state tracker for the Clash API.
//!
//! Uses [`DashMap`] for concurrent-safe access from multiple tokio tasks
//! (accept loop, relay workers, and HTTP API handlers).

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

/// Snapshot of a connection's state, safe to serialize and expose via API.
#[derive(Debug, Clone)]
pub struct ConnectionSnapshot {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub proxy: String,
    /// Matched routing rule (dae expression; "Fallback" = fallback).
    pub rule: String,
    /// Value that drove the match (sniffed domain or destination IP).
    pub rule_payload: String,
    /// Selection path, leaf-first ([leaf, ..sub-groups.., topGroup]).
    pub chains: Vec<String>,
    pub upload: u64,
    pub download: u64,
    pub start_time: Instant,
    pub domain: Option<String>,
    pub network: String,
    /// Originating process name for locally-generated flows (cgroup cookie
    /// attribution); None for LAN-forwarded traffic.
    pub process: Option<String>,
    /// /proc/<pid>/exe at registration time; None when the pid is unknown
    /// or the process already exited.
    pub process_path: Option<String>,
}

/// Live per-connection entry, updated concurrently from the relay task.
pub struct ConnectionEntry {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub proxy: String,
    pub rule: String,
    pub rule_payload: String,
    pub chains: Vec<String>,
    /// Byte counters are shared with the relay task, which increments them
    /// as data flows so `/connections` shows live (not close-time) totals.
    pub upload: Arc<AtomicU64>,
    pub download: Arc<AtomicU64>,
    pub start_time: Instant,
    pub domain: Option<String>,
    pub network: String,
    /// Originating process name for locally-generated flows (cgroup cookie
    /// attribution); None for LAN-forwarded traffic.
    pub process: Option<String>,
    /// /proc/<pid>/exe resolved at registration; None when the pid is
    /// unknown or the process already exited.
    pub process_path: Option<String>,
}

impl ConnectionEntry {
    /// Create a read-only snapshot of the current entry state.
    pub fn snapshot(&self) -> ConnectionSnapshot {
        ConnectionSnapshot {
            id: self.id.clone(),
            source: self.source.clone(),
            destination: self.destination.clone(),
            proxy: self.proxy.clone(),
            rule: self.rule.clone(),
            rule_payload: self.rule_payload.clone(),
            chains: self.chains.clone(),
            upload: self.upload.load(Ordering::Relaxed),
            download: self.download.load(Ordering::Relaxed),
            start_time: self.start_time,
            domain: self.domain.clone(),
            network: self.network.clone(),
            process: self.process.clone(),
            process_path: self.process_path.clone(),
        }
    }
}

/// Concurrent-safe tracking of all active connections.
///
/// Thread-safe by construction via [`DashMap`] — no external locks needed.
pub struct ConnectionTracker {
    entries: DashMap<String, ConnectionEntry>,
    enabled: AtomicBool,
}

impl ConnectionTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            enabled: AtomicBool::new(false),
        }
    }

    #[cfg(any(feature = "clash-api", test))]
    pub(crate) fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub(crate) fn register_if_enabled(
        &self,
        make_entry: impl FnOnce() -> ConnectionEntry,
    ) -> Option<String> {
        self.is_enabled().then(|| self.register(make_entry()))
    }

    /// Register a new connection and return its unique ID (UUID v4).
    pub fn register(&self, entry: ConnectionEntry) -> String {
        let id = entry.id.clone();
        self.entries.insert(id.clone(), entry);
        id
    }

    /// Add upload/download bytes to an existing connection.
    ///
    /// If the connection is no longer in the map, the update is silently
    /// dropped (the relay task may have raced with a close).
    pub fn update_bytes(&self, id: &str, upload_delta: u64, download_delta: u64) {
        if let Some(entry) = self.entries.get(id) {
            entry.upload.fetch_add(upload_delta, Ordering::Relaxed);
            entry.download.fetch_add(download_delta, Ordering::Relaxed);
        }
    }

    /// Attach process metadata after registration. A missing entry means the
    /// flow closed before the blocking `/proc` lookup completed.
    pub fn update_process_path(&self, id: &str, process_path: String) {
        if let Some(mut entry) = self.entries.get_mut(id) {
            entry.process_path = Some(process_path);
        }
    }

    /// Remove a connection from the tracker.
    pub fn remove(&self, id: &str) {
        self.entries.remove(id);
    }

    /// Return a point-in-time snapshot of all active connections.
    pub fn snapshot(&self) -> Vec<ConnectionSnapshot> {
        self.entries
            .iter()
            .map(|ref_multi| ref_multi.value().snapshot())
            .collect()
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectionTracker;

    #[test]
    fn lazy_registration_skips_construction_until_enabled() {
        let tracker = ConnectionTracker::new();
        assert!(
            tracker
                .register_if_enabled(|| panic!("disabled tracker constructed an entry"))
                .is_none()
        );

        tracker.enable();
        assert!(tracker.is_enabled());
    }
}
