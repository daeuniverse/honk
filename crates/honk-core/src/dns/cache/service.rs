use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::CacheKey;
use super::counters::CacheCounterSet;
use super::{CacheValue, DnsCache, lock};

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

pub(super) type CacheShard = lru::LruCache<CacheSlot, CacheValue>;

/// Drop a slot's positive answer, and the slot itself when no negative remains.
pub(super) fn remove_positive(shard: &mut CacheShard, key: &CacheSlot) {
    let remove_slot = shard.get_mut(key).is_some_and(|value| {
        value.positive = None;
        value.negative.is_none()
    });
    if remove_slot {
        shard.pop(key);
    }
}

impl DnsCache {
    /// Create a new DNS cache with the given maximum number of entries.
    ///
    /// Capacity is divided exactly across at most 16 shards. Eviction is LRU
    /// within a shard, so one hot shard cannot evict entries in another.
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
