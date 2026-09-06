//! Sharded, bounded DNS response cache with exact query identities.
//!
//! Positive and negative entries are isolated by canonical query wire,
//! ingress profile, logical scope, policy, and operation. Expired positives
//! remain available only within the bounded serve-stale window.

use std::sync::Arc;
use std::sync::{Mutex as StdMutex, MutexGuard};

mod compatibility {
    use super::{CachedEntry, DnsCache, NegativeCacheHit};

    impl DnsCache {
        pub fn get(&mut self, key: &str) -> Option<CachedEntry> {
            self.service.get(key)
        }

        pub fn get_stale(&mut self, key: &str) -> Option<CachedEntry> {
            self.service.get_stale(key)
        }

        pub fn put(&mut self, key: String, response: Vec<u8>, min_ttl: u32) {
            self.service.put(key, response, min_ttl);
        }

        #[cfg(test)]
        pub(crate) fn insert_expired_for_test(&mut self, key: String, response: Vec<u8>, ttl: u32) {
            self.service.insert_expired_for_test(key, response, ttl);
        }

        #[cfg(test)]
        pub(crate) fn insert_beyond_stale_retention_for_test(
            &mut self,
            key: String,
            response: Vec<u8>,
            ttl: u32,
        ) {
            self.service
                .insert_beyond_stale_retention_for_test(key, response, ttl);
        }

        pub fn put_negative(&mut self, key: String, ttl: u32, rcode: u8) {
            self.service.put_negative(key, ttl, rcode);
        }

        pub fn negative_rcode(&self, key: &str) -> Option<u8> {
            self.service.negative_rcode(key)
        }

        pub fn negative_hit(&self, key: &str) -> Option<NegativeCacheHit> {
            self.service.negative_hit(key)
        }

        pub fn clear_negative(&mut self, key: &str) {
            self.service.clear_negative(key);
        }

        pub fn purge_expired_negatives(&mut self) {
            self.service.purge_expired_negatives();
        }

        pub fn clear(&mut self) {
            self.service.clear();
        }

        pub fn purge_expired(&mut self) {
            self.service.purge_expired();
        }

        pub fn remove(&mut self, key: &str) -> Option<CachedEntry> {
            self.service.remove(key)
        }

        pub fn len(&self) -> usize {
            self.service.len()
        }

        pub fn is_empty(&self) -> bool {
            self.service.is_empty()
        }

        #[cfg(feature = "dns-bench")]
        pub fn benchmark_get(&self, key: &str) -> Option<CachedEntry> {
            self.service.get(key)
        }

        #[cfg(feature = "dns-bench")]
        pub fn benchmark_put(&self, key: String, response: Vec<u8>, min_ttl: u32) {
            self.service.put(key, response, min_ttl);
        }

        #[cfg(feature = "dns-bench")]
        pub fn benchmark_shard_index(&self, key: &str) -> usize {
            self.service
                .shard_index(&super::service::CacheSlot::Legacy(key.to_owned()))
        }

        #[cfg(test)]
        pub(super) fn shard_index(&self, key: &str) -> usize {
            self.service
                .shard_index(&super::service::CacheSlot::Legacy(key.to_owned()))
        }

        #[cfg(test)]
        pub(super) fn shard_capacities(&self) -> Vec<usize> {
            self.service.shard_capacities()
        }

        #[cfg(test)]
        pub(crate) fn positive_entries_for_test(&self) -> Vec<CachedEntry> {
            self.service.positive_entries_for_test()
        }
    }
}
mod counters {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::service::DnsCacheService;

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct CacheCounters {
        pub hits: u64,
        pub misses: u64,
        pub stale: u64,
    }

    #[derive(Default)]
    pub(super) struct CacheCounterSet {
        pub(super) hits: AtomicU64,
        pub(super) misses: AtomicU64,
        pub(super) stale: AtomicU64,
    }

    impl CacheCounterSet {
        fn snapshot(&self) -> CacheCounters {
            CacheCounters {
                hits: self.hits.load(Ordering::Relaxed),
                misses: self.misses.load(Ordering::Relaxed),
                stale: self.stale.load(Ordering::Relaxed),
            }
        }
    }

    impl DnsCacheService {
        pub fn counters(&self) -> CacheCounters {
            self.counters.snapshot()
        }
    }
}
mod key;
mod maintenance {
    use std::time::Instant;

    use super::{CacheSlot, CachedEntry, DnsCacheService, lock};

    impl DnsCacheService {
        pub fn clear_negative(&self, key: &str) {
            let key = CacheSlot::Legacy(key.to_owned());
            let index = self.shard_index(&key);
            let mut shard = lock(&self.shards[index]);
            let remove_slot = shard.get_mut(&key).is_some_and(|value| {
                value.negative = None;
                value.positive.is_none()
            });
            if remove_slot {
                shard.pop(&key);
            }
        }

        pub fn purge_expired_negatives(&self) {
            let now = Instant::now();
            for shard in &self.shards {
                let mut shard = lock(shard);
                let expired: Vec<CacheSlot> = shard
                    .iter()
                    .filter(|(_, value)| {
                        value.negative.is_some_and(|entry| now >= entry.expires_at)
                    })
                    .map(|(key, _)| key.clone())
                    .collect();
                for key in expired {
                    let remove_slot = shard.get_mut(&key).is_some_and(|value| {
                        value.negative = None;
                        value.positive.is_none()
                    });
                    if remove_slot {
                        shard.pop(&key);
                    }
                }
            }
        }

        pub fn clear(&self) {
            for shard in &self.shards {
                lock(shard).clear();
            }
        }

        pub fn purge_expired(&self) {
            for shard in &self.shards {
                let mut shard = lock(shard);
                let expired: Vec<CacheSlot> = shard
                    .iter()
                    .filter(|(_, value)| {
                        value.positive.as_ref().is_some_and(CachedEntry::is_expired)
                    })
                    .map(|(key, _)| key.clone())
                    .collect();
                for key in expired {
                    shard.remove_positive(&key);
                }
            }
            self.purge_expired_negatives();
        }

        pub fn remove(&self, key: &str) -> Option<CachedEntry> {
            let key = CacheSlot::Legacy(key.to_owned());
            let index = self.shard_index(&key);
            lock(&self.shards[index])
                .pop(&key)
                .and_then(|value| value.positive)
        }

        pub fn len(&self) -> usize {
            self.shards.iter().map(|shard| lock(shard).len()).sum()
        }

        pub fn is_empty(&self) -> bool {
            self.shards.iter().all(|shard| lock(shard).is_empty())
        }

        pub(super) fn shard_index(&self, key: &CacheSlot) -> usize {
            let hash = match key {
                CacheSlot::Exact(key) => key.shard_hash(),
                CacheSlot::Legacy(key) => {
                    let digest = super::key::stable_shard_digest(key);
                    u64::from_be_bytes([
                        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
                        digest[6], digest[7],
                    ])
                }
            };
            usize::try_from(hash % u64::try_from(self.shards.len()).unwrap_or(1))
                .unwrap_or_default()
        }

        #[cfg(test)]
        pub(super) fn shard_capacities(&self) -> Vec<usize> {
            self.shards
                .iter()
                .map(|shard| lock(shard).cap().get())
                .collect()
        }

        #[cfg(test)]
        pub(crate) fn positive_entries_for_test(&self) -> Vec<CachedEntry> {
            self.shards
                .iter()
                .flat_map(|shard| {
                    lock(shard)
                        .iter()
                        .filter_map(|(_, value)| value.positive.clone())
                        .collect::<Vec<_>>()
                })
                .collect()
        }
    }
}
mod service;
mod storage {
    use bytes::Bytes;

    use std::time::{Duration, Instant};

    pub(super) const STALE_RETENTION: Duration = Duration::from_secs(3600);

    /// A cached DNS response entry.
    ///
    /// Contains the raw response bytes along with TTL metadata
    /// used to determine expiry.
    #[derive(Debug, Clone)]
    pub struct CachedEntry {
        /// Raw DNS response bytes (full wire-format message).
        pub response: Bytes,
        /// Absolute wall-clock time after which this entry is stale.
        pub expires_at: Instant,
        /// Minimum TTL from the DNS record set, in seconds.
        pub min_ttl: u32,
        pub(crate) strict_reusable: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NegativeCacheHit {
        pub rcode: u8,
        pub remaining_ttl: Duration,
    }

    #[derive(Debug, Clone, Copy)]
    pub(super) struct NegativeEntry {
        pub expires_at: Instant,
        pub rcode: u8,
    }

    pub(super) struct CacheValue {
        pub positive: Option<CachedEntry>,
        pub negative: Option<NegativeEntry>,
    }

    impl CacheValue {
        pub(super) fn positive(entry: CachedEntry) -> Self {
            Self {
                positive: Some(entry),
                negative: None,
            }
        }

        pub(super) fn negative(entry: NegativeEntry) -> Self {
            Self {
                positive: None,
                negative: Some(entry),
            }
        }

        pub(super) fn response_bytes(&self) -> usize {
            self.positive
                .as_ref()
                .map_or(0, |entry| entry.response.len())
        }
    }

    impl CachedEntry {
        /// Returns `true` if the current time is past `expires_at`.
        #[inline]
        pub fn is_expired(&self) -> bool {
            Instant::now() >= self.expires_at
        }

        /// Returns the remaining TTL in seconds (0 if expired).
        pub fn remaining_ttl_secs(&self) -> u64 {
            self.expires_at
                .checked_duration_since(Instant::now())
                .map(|duration| duration.as_secs())
                .unwrap_or(0)
        }

        /// Returns `true` once the entry is too old even for serve-stale use
        /// (past `expires_at + STALE_RETENTION`).
        #[inline]
        pub fn is_stale_retention_exceeded(&self) -> bool {
            Instant::now() >= self.expires_at + STALE_RETENTION
        }
    }
}
mod store;

pub use counters::CacheCounters;
pub(crate) use key::{CacheKey, KeyIdentity, OperationKind};
pub(crate) use service::PublicationEpoch;
pub(crate) use service::{CacheSlot, DnsCacheService};
pub use storage::{CachedEntry, NegativeCacheHit};
pub(crate) use store::ExactLookup;

use storage::{CacheValue, NegativeEntry};

/// DNS response cache with LRU eviction and TTL-based expiry.
///
/// Internally uses [`lru::LruCache`] for bounded storage
/// with least-recently-used eviction. TTL checking is performed
/// at lookup time; expired entries are not returned by [`DnsCache::get`]
/// but remain available via [`DnsCache::get_stale`] for one hour
/// (serve-stale, RFC 8767) before being dropped.
///
/// Also maintains a negative cache for NXDOMAIN/SERVFAIL responses
/// to avoid repeated upstream queries for known-bad domains.
///
/// When a [`DnsCachePersister`](super::persist::DnsCachePersister) is
/// installed (`cache_file.store_dns`), every positive `put` is mirrored to
/// cache.db by a background writer; with no persister the insert path pays
/// a single branch.
pub struct DnsCache {
    service: Arc<DnsCacheService>,
}

impl DnsCache {
    pub(crate) fn service(&self) -> Arc<DnsCacheService> {
        Arc::clone(&self.service)
    }
    /// Install (or remove) the cache.db persistence sink. Wired by the
    /// control plane when `experimental.cache_file.store_dns` is enabled.
    pub fn set_persister(&mut self, persister: Option<super::persist::DnsCachePersister>) {
        *lock(&self.service.persister) = persister;
    }

    pub fn persistence(&self) -> Option<super::persist::DnsCachePersister> {
        self.service.persistence()
    }

    pub fn counters(&self) -> CacheCounters {
        self.service.counters()
    }
}

fn lock<T>(mutex: &StdMutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests;
