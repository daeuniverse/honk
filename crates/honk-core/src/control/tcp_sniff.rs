//! TCP sniffing negative cache.
//!
//! Caches flow signatures for which TCP sniffing has repeatedly failed
//! (non-HTTP/TLS protocols, server-first protocols, etc.) so that
//! future connections to the same destination can skip the costly
//! sniffing prefetch and fall directly to normal relay.
//!
//! ## Design
//!
//! - **TTL**: 10 minutes after the last failure
//! - **Threshold**: 3 consecutive sniff failures before suppression
//! - **Janitor**: periodic cleanup of expired entries
//!
//! Go ref: `tcp_sniff_policy.go` (311L)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Number of consecutive sniff failures before we temporarily skip sniffing
/// on the same flow signature.
const SNIFF_FAILURE_THRESHOLD: u8 = 3;

/// Suppression duration for sniffing after repeated failures.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(600);

/// Janitor cleanup interval.
const JANITOR_INTERVAL: Duration = Duration::from_secs(60);

/// Key for the negative sniff cache: (dst_ip, dst_port, outbound).
///
/// The outbound index is included because different outbounds may
/// have different routing (e.g., direct doesn't need sniffing).
pub type SniffNegKey = (SocketAddr, u8);

/// Entry in the negative sniff cache.
#[derive(Debug, Clone)]
struct SniffNegEntry {
    /// Consecutive failure count (capped at threshold).
    failures: u8,
    /// Absolute time after which this entry is stale.
    expires_at: Instant,
}

/// Cache of flow signatures for which TCP sniffing should be skipped.
///
/// Thread-safe via internal `Mutex`. The janitor prunes expired entries
/// periodically to prevent unbounded growth.
pub struct TcpSniffNegCache {
    inner: Mutex<HashMap<SniffNegKey, SniffNegEntry>>,
}

impl TcpSniffNegCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for TcpSniffNegCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpSniffNegCache {
    /// Check whether sniffing should be skipped for this flow.
    ///
    /// Returns `true` if the flow has accumulated enough failures
    /// and the negative cache entry has not yet expired.
    pub fn should_skip_sniff(&self, key: &SniffNegKey, now: Instant) -> bool {
        let cache = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let Some(entry) = cache.get(key) else {
            return false;
        };
        if now >= entry.expires_at {
            return false;
        }
        entry.failures >= SNIFF_FAILURE_THRESHOLD
    }

    /// Record a sniff failure for this flow.
    ///
    /// Each call increments the failure counter. Once the counter reaches
    /// `SNIFF_FAILURE_THRESHOLD`, subsequent `should_skip_sniff` calls
    /// will return `true` for this flow until the TTL expires.
    pub fn note_sniff_failure(&self, key: SniffNegKey, now: Instant) {
        let mut cache = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let entry = cache.entry(key).or_insert(SniffNegEntry {
            failures: 0,
            expires_at: now,
        });

        if now >= entry.expires_at {
            entry.failures = 0;
        }

        entry.failures = entry
            .failures
            .saturating_add(1)
            .min(SNIFF_FAILURE_THRESHOLD);
        entry.expires_at = now + NEGATIVE_CACHE_TTL;
    }

    /// Clear a negative cache entry (called when sniffing succeeds).
    ///
    /// A successful sniff means the flow IS sniffable, so we remove
    /// any negative cache entry to allow future sniffing.
    pub fn clear_sniff_negative(&self, key: &SniffNegKey) {
        let mut cache = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        cache.remove(key);
    }

    /// Prune all expired entries from the cache and shrink oversized backing storage.
    pub fn prune_expired(&self, now: Instant) {
        let mut cache = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let cap = cache.capacity();
        cache.retain(|_, entry| now < entry.expires_at);
        if cap > 64 && cache.len() <= cap / 4 {
            cache.shrink_to_fit();
        }
    }

    /// Return the number of entries in the cache.
    pub fn len(&self) -> usize {
        let cache = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        cache.len()
    }

    /// Return `true` if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all entries from the cache.
    pub fn clear_all(&self) {
        let mut cache = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        cache.clear();
    }
}

/// Spawn a background janitor that periodically prunes expired entries.
///
/// Returns a `JoinHandle` that can be awaited or aborted on shutdown.
/// The janitor runs at `JANITOR_INTERVAL` (60s) intervals.
pub fn spawn_sniff_neg_cache_janitor(
    cache: std::sync::Arc<TcpSniffNegCache>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(JANITOR_INTERVAL).await;
            let now = Instant::now();
            cache.prune_expired(now);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_key() -> SniffNegKey {
        (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            2,
        )
    }

    #[test]
    fn test_empty_cache_does_not_skip() {
        let cache = TcpSniffNegCache::new();
        assert!(!cache.should_skip_sniff(&test_key(), Instant::now()));
    }

    #[test]
    fn test_single_failure_does_not_skip() {
        let cache = TcpSniffNegCache::new();
        let now = Instant::now();
        cache.note_sniff_failure(test_key(), now);
        assert!(!cache.should_skip_sniff(&test_key(), now));
    }

    #[test]
    fn test_threshold_failures_cause_skip() {
        let cache = TcpSniffNegCache::new();
        let now = Instant::now();
        for _ in 0..SNIFF_FAILURE_THRESHOLD {
            cache.note_sniff_failure(test_key(), now);
        }
        assert!(cache.should_skip_sniff(&test_key(), now));
    }

    #[test]
    fn test_clear_removes_skip() {
        let cache = TcpSniffNegCache::new();
        let now = Instant::now();
        for _ in 0..SNIFF_FAILURE_THRESHOLD {
            cache.note_sniff_failure(test_key(), now);
        }
        assert!(cache.should_skip_sniff(&test_key(), now));
        cache.clear_sniff_negative(&test_key());
        assert!(!cache.should_skip_sniff(&test_key(), now));
    }

    #[test]
    fn test_expired_entry_does_not_skip() {
        let cache = TcpSniffNegCache::new();
        let past = Instant::now() - NEGATIVE_CACHE_TTL - Duration::from_secs(1);
        for _ in 0..SNIFF_FAILURE_THRESHOLD {
            cache.note_sniff_failure(test_key(), past);
        }
        assert!(!cache.should_skip_sniff(&test_key(), Instant::now()));
    }

    #[test]
    fn test_prune_removes_expired() {
        let cache = TcpSniffNegCache::new();
        let past = Instant::now() - NEGATIVE_CACHE_TTL - Duration::from_secs(1);
        cache.note_sniff_failure(test_key(), past);
        assert_eq!(cache.len(), 1);

        cache.prune_expired(Instant::now());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_different_keys_independent() {
        let cache = TcpSniffNegCache::new();
        let now = Instant::now();
        let key1 = (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
            1,
        );
        let key2 = (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 443),
            1,
        );

        for _ in 0..SNIFF_FAILURE_THRESHOLD {
            cache.note_sniff_failure(key1, now);
        }
        assert!(cache.should_skip_sniff(&key1, now));
        assert!(!cache.should_skip_sniff(&key2, now));
    }

    #[test]
    fn test_clear_all() {
        let cache = TcpSniffNegCache::new();
        let now = Instant::now();
        cache.note_sniff_failure(test_key(), now);
        assert!(!cache.is_empty());

        cache.clear_all();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_prune_expired_shrinks_oversized_capacity_with_hysteresis() {
        let key = |host, port| (SocketAddr::from(([198, 51, 100, host], port)), 2);
        let cap = |c: &TcpSniffNegCache| c.inner.lock().unwrap().capacity();
        let now = Instant::now();
        let past = now - NEGATIVE_CACHE_TTL - Duration::from_secs(1);

        let cache = TcpSniffNegCache::new();
        for port in 1000..1200u16 {
            cache.note_sniff_failure(key(1, port), past);
        }
        for port in 2000..2010u16 {
            for _ in 0..SNIFF_FAILURE_THRESHOLD {
                cache.note_sniff_failure(key(2, port), now);
            }
        }
        assert!(cap(&cache) > 64);
        cache.prune_expired(now);
        assert_eq!(cache.len(), 10);
        assert!(cap(&cache) <= 64);
        assert!(cache.should_skip_sniff(&key(2, 2000), now));

        for port in 3000..3200u16 {
            cache.note_sniff_failure(key(3, port), now);
        }
        assert!(cap(&cache) > 64);
        cache.prune_expired(now + NEGATIVE_CACHE_TTL + Duration::from_secs(1));
        assert!(cache.is_empty() && cap(&cache) == 0);

        let small = TcpSniffNegCache::new();
        for port in 4000..4008u16 {
            small.note_sniff_failure(key(4, port), past);
        }
        let small_cap = cap(&small);
        assert!(small_cap > 0 && small_cap <= 64);
        small.prune_expired(now);
        assert!(small.is_empty() && cap(&small) == small_cap);
    }
}
