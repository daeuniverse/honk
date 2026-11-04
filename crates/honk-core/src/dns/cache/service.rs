use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::CacheKey;
use super::counters::CacheCounterSet;
use super::{CacheValue, DnsCache, NegativeEntry, lock};

static CAPACITY_CLAMP_WARNED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicationEpoch(pub(super) u64);

/// Largest accepted `max_cache_size`; larger values are clamped.
pub(crate) const MAX_CACHE_ENTRIES: usize = 100_000;

pub struct DnsCacheService {
    pub(super) shards: Vec<Mutex<CacheShard>>,
    pub(super) counters: CacheCounterSet,
    pub(super) persister: Mutex<Option<crate::dns::persist::DnsCachePersister>>,
    pub(super) publication: Mutex<PublicationState>,
    pub(super) next_revision: AtomicU64,
    pub(super) mutation: tokio::sync::Mutex<()>,
    #[cfg(any(feature = "native-api", test))]
    pub(super) identity_nonce: uuid::Uuid,
}

pub(super) struct PublicationState {
    pub(super) epoch: u64,
    pub(super) accepting: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum CacheSlot {
    Exact(CacheKey),
    Legacy(String),
}

/// Cached answer bytes allowed per configured entry. An entry-count limit
/// alone lets large HTTPS/TXT answers hold hundreds of MiB, because an answer
/// of any size occupies one entry.
const CACHE_BYTES_PER_ENTRY: usize = 1024;
/// Largest cacheable answer: a DNS message's size limit. Every shard budget is
/// at least this, so an admitted answer can never evict its whole shard.
pub(super) const MAX_ANSWER_BYTES: usize = u16::MAX as usize;

/// One LRU shard bounded by both entry count and retained answer bytes.
///
/// Every mutation goes through this type so `retained` cannot drift.
pub(super) struct CacheShard {
    entries: lru::LruCache<CacheSlot, CacheValue>,
    retained: usize,
}

impl CacheShard {
    fn new(capacity: NonZeroUsize) -> Self {
        Self {
            entries: lru::LruCache::new(capacity),
            retained: 0,
        }
    }

    fn budget(&self) -> usize {
        self.entries
            .cap()
            .get()
            .saturating_mul(CACHE_BYTES_PER_ENTRY)
            .max(MAX_ANSWER_BYTES)
    }

    #[cfg(any(feature = "native-api", test))]
    pub(super) fn cap(&self) -> NonZeroUsize {
        self.entries.cap()
    }

    #[cfg(test)]
    pub(super) fn retained(&self) -> usize {
        self.retained
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(super) fn get(&mut self, key: &CacheSlot) -> Option<&CacheValue> {
        self.entries.get(key)
    }

    pub(super) fn peek(&self, key: &CacheSlot) -> Option<&CacheValue> {
        self.entries.peek(key)
    }

    pub(super) fn iter(&self) -> lru::Iter<'_, CacheSlot, CacheValue> {
        self.entries.iter()
    }

    pub(super) fn pop(&mut self, key: &CacheSlot) -> Option<CacheValue> {
        let value = self.entries.pop(key)?;
        self.retained -= value.response_bytes();
        Some(value)
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.retained = 0;
    }

    /// Insert a value, then evict least-recently-used entries until the shard
    /// fits its byte budget. `push`, unlike `put`, also returns the entry an
    /// entry-count eviction displaced, so its bytes are released.
    pub(super) fn put(&mut self, key: CacheSlot, value: CacheValue) {
        self.retained += value.response_bytes();
        if let Some((_, displaced)) = self.entries.push(key, value) {
            self.retained -= displaced.response_bytes();
        }
        while self.retained > self.budget()
            && let Some((_, evicted)) = self.entries.pop_lru()
        {
            self.retained -= evicted.response_bytes();
        }
    }

    /// Drop a slot's positive answer, and the slot itself when no negative
    /// remains.
    pub(super) fn drop_positive(&mut self, key: &CacheSlot) {
        let Some(value) = self.entries.get_mut(key) else {
            return;
        };
        if let Some(entry) = value.positive.take() {
            self.retained -= entry.response.len();
        }
        if value.negative.is_none() {
            self.entries.pop(key);
        }
    }

    /// Drop a slot's negative answer, and the slot itself when no positive
    /// remains.
    pub(super) fn drop_negative(&mut self, key: &CacheSlot) {
        if self.entries.get_mut(key).is_some_and(|value| {
            value.negative = None;
            value.positive.is_none()
        }) {
            self.entries.pop(key);
        }
    }

    /// Replace a slot's negative answer and revision, keeping its positive
    /// answer. Returns `false` when the slot is absent.
    pub(super) fn set_negative_with_revision(
        &mut self,
        key: &CacheSlot,
        negative: NegativeEntry,
        revision: u64,
    ) -> bool {
        match self.entries.get_mut(key) {
            Some(value) => {
                value.negative = Some(negative);
                value.revision = revision;
                true
            }
            None => false,
        }
    }

    /// Mutable positive entry, for tests that age a fixture in place.
    #[cfg(test)]
    pub(super) fn positive_mut(&mut self, key: &CacheSlot) -> Option<&mut super::CachedEntry> {
        self.entries.get_mut(key)?.positive.as_mut()
    }
}

impl DnsCache {
    /// Create a new DNS cache with the given maximum number of entries.
    ///
    /// Capacity is divided exactly across at most 16 shards. Eviction is LRU
    /// within a shard, so one hot shard cannot evict entries in another. Each
    /// shard also bounds its answer bytes to 1 KiB per entry, but never below
    /// one maximum-size answer.
    pub fn new(max_size: usize) -> Self {
        let capacity = max_size.clamp(1, MAX_CACHE_ENTRIES);
        if capacity != max_size
            && CAPACITY_CLAMP_WARNED
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!(
                requested = max_size,
                effective = capacity,
                "DNS cache capacity clamped"
            );
        }
        let shard_count = capacity.min(16);
        let quotient = capacity / shard_count;
        let remainder = capacity % shard_count;
        let shards = (0..shard_count)
            .map(|index| {
                let shard_capacity = quotient + usize::from(index < remainder);
                Mutex::new(CacheShard::new(
                    NonZeroUsize::new(shard_capacity)
                        .unwrap_or_else(|| unreachable!("shard capacity is positive")),
                ))
            })
            .collect();
        Self {
            service: Arc::new(DnsCacheService {
                shards,
                counters: CacheCounterSet::default(),
                persister: Mutex::new(None),
                publication: Mutex::new(PublicationState {
                    epoch: 0,
                    accepting: true,
                }),
                next_revision: AtomicU64::new(1),
                mutation: tokio::sync::Mutex::new(()),
                #[cfg(any(feature = "native-api", test))]
                identity_nonce: uuid::Uuid::new_v4(),
            }),
        }
    }
}

impl DnsCacheService {
    pub(crate) fn publication_epoch(&self) -> PublicationEpoch {
        PublicationEpoch(lock(&self.publication).epoch)
    }

    pub(crate) fn persistence(&self) -> Option<crate::dns::persist::DnsCachePersister> {
        lock(&self.persister).clone()
    }
}
