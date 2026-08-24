use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::{
    CacheKey, CacheSlot, CacheValue, CachedEntry, DnsCacheService, NegativeCacheHit, NegativeEntry,
    PublicationEpoch, lock,
};

pub(crate) enum ExactLookup {
    Negative(NegativeCacheHit),
    Positive(CachedEntry),
    Miss,
}

impl DnsCacheService {
    pub fn get(&self, key: &str) -> Option<CachedEntry> {
        self.get_slot(&CacheSlot::Legacy(key.to_owned()))
    }

    #[cfg(test)]
    pub(crate) fn get_exact(&self, key: &CacheKey) -> Option<CachedEntry> {
        self.get_slot(&CacheSlot::Exact(key.clone()))
    }

    pub(crate) fn lookup_exact(&self, key: &CacheKey, require_strict: bool) -> ExactLookup {
        let key = CacheSlot::Exact(key.clone());
        let index = self.shard_index(&key);
        let now = Instant::now();
        let mut shard = lock(&self.shards[index]);

        let (negative, clear_negative) = match shard.peek(&key) {
            Some(value) => match value.negative.as_ref() {
                Some(negative) => match negative.expires_at.checked_duration_since(now) {
                    Some(remaining) => {
                        let rounded_secs = remaining
                            .as_secs()
                            .saturating_add(u64::from(remaining.subsec_nanos() > 0));
                        (
                            Some(NegativeCacheHit {
                                rcode: negative.rcode,
                                remaining_ttl: Duration::from_secs(rounded_secs),
                            }),
                            false,
                        )
                    }
                    None => (None, true),
                },
                None => (None, false),
            },
            None => (None, false),
        };

        if clear_negative {
            let remove_slot = shard.peek_mut(&key).is_some_and(|value| {
                value.negative = None;
                value.positive.is_none()
            });
            if remove_slot {
                shard.pop(&key);
            }
        }

        let result = if let Some(hit) = negative {
            ExactLookup::Negative(hit)
        } else {
            let (positive, clear_positive) = match shard.get(&key) {
                Some(value) => match value.positive.as_ref() {
                    Some(entry) if entry.is_stale_retention_exceeded() => (None, true),
                    Some(entry) if require_strict && !entry.strict_reusable => (None, false),
                    Some(entry) if !entry.is_expired() => (Some(entry.clone()), false),
                    Some(_) | None => (None, false),
                },
                None => (None, false),
            };
            if clear_positive {
                shard.remove_positive(&key);
            }
            positive.map_or(ExactLookup::Miss, ExactLookup::Positive)
        };

        match &result {
            ExactLookup::Negative(_) => {
                self.counters.hits.fetch_add(1, Ordering::Relaxed);
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheHit);
                tracing::debug!(result = "negative_hit", "DNS cache lookup");
            }
            ExactLookup::Positive(_) => {
                self.counters.hits.fetch_add(1, Ordering::Relaxed);
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheHit);
                tracing::debug!(result = "hit", "DNS cache lookup");
            }
            ExactLookup::Miss => {
                self.counters.misses.fetch_add(1, Ordering::Relaxed);
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheMiss);
                tracing::debug!(result = "miss", "DNS cache lookup");
            }
        }
        result
    }

    pub(crate) fn get_stale_exact(
        &self,
        key: &CacheKey,
        require_strict: bool,
    ) -> Option<CachedEntry> {
        self.get_stale_slot(&CacheSlot::Exact(key.clone()), require_strict)
    }

    fn get_slot(&self, key: &CacheSlot) -> Option<CachedEntry> {
        let index = self.shard_index(key);
        let mut shard = lock(&self.shards[index]);
        let (result, clear_positive) = match shard.get(key) {
            Some(value) => match value.positive.as_ref() {
                Some(entry) if entry.is_stale_retention_exceeded() => (None, true),
                Some(entry) if !entry.is_expired() => (Some(entry.clone()), false),
                Some(_) | None => (None, false),
            },
            None => (None, false),
        };
        if clear_positive {
            shard.remove_positive(key);
        }
        if result.is_some() {
            self.counters.hits.fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheHit);
            tracing::debug!(result = "hit", "DNS cache lookup");
        } else {
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheMiss);
            tracing::debug!(result = "miss", "DNS cache lookup");
        }
        result
    }

    pub fn get_stale(&self, key: &str) -> Option<CachedEntry> {
        self.get_stale_slot(&CacheSlot::Legacy(key.to_owned()), false)
    }

    fn get_stale_slot(&self, key: &CacheSlot, require_strict: bool) -> Option<CachedEntry> {
        let index = self.shard_index(key);
        let mut shard = lock(&self.shards[index]);
        let result = shard.get(key).and_then(|value| {
            value
                .positive
                .as_ref()
                .filter(|entry| !require_strict || entry.strict_reusable)
                .filter(|entry| entry.is_expired() && !entry.is_stale_retention_exceeded())
                .cloned()
        });
        if result.is_some() {
            self.counters.stale.fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheStale);
            tracing::debug!(result = "stale", "DNS cache lookup");
        }
        result
    }

    pub fn put(&self, key: String, response: Vec<u8>, min_ttl: u32) {
        let ttl = min_ttl.max(1);
        self.put_slot(CacheSlot::Legacy(key), response.into(), ttl, true);
    }

    pub(crate) fn put_exact(&self, key: CacheKey, response: Vec<u8>, min_ttl: u32) {
        let ttl = min_ttl.max(1);
        let response = bytes::Bytes::from(response);
        let retained = self.put_slot(CacheSlot::Exact(key.clone()), response.clone(), ttl, true);
        if retained && let Some(persister) = lock(&self.persister).clone() {
            persister.save(
                key,
                response,
                crate::dns::persist::unix_now() + u64::from(ttl),
            );
        }
    }

    pub(crate) fn put_exact_if_current(
        &self,
        epoch: PublicationEpoch,
        key: CacheKey,
        response: Vec<u8>,
        min_ttl: u32,
    ) {
        let registry = lock(&self.refresh_tasks);
        if !registry.accepting_publications || registry.publication_epoch != epoch.0 {
            return;
        }
        self.put_exact(key, response, min_ttl);
    }

    pub(crate) fn put_restored_exact(&self, key: CacheKey, response: Vec<u8>, min_ttl: u32) {
        self.put_slot(CacheSlot::Exact(key), response.into(), min_ttl, false);
    }

    fn put_slot(
        &self,
        key: CacheSlot,
        response: bytes::Bytes,
        min_ttl: u32,
        strict_reusable: bool,
    ) -> bool {
        if crate::dns::response::is_truncated(&response) {
            return false;
        }
        let ttl = min_ttl.max(1);
        let entry = CachedEntry {
            response,
            expires_at: Instant::now() + Duration::from_secs(u64::from(ttl)),
            min_ttl,
            strict_reusable,
        };
        let index = self.shard_index(&key);
        lock(&self.shards[index]).put(key, CacheValue::positive(entry))
    }

    #[cfg(test)]
    pub(crate) fn insert_expired_for_test(&self, key: String, response: Vec<u8>, min_ttl: u32) {
        let key = CacheSlot::Legacy(key);
        let index = self.shard_index(&key);
        lock(&self.shards[index]).put(
            key,
            CacheValue::positive(CachedEntry {
                response: response.into(),
                expires_at: Instant::now() - Duration::from_secs(1),
                min_ttl,
                strict_reusable: true,
            }),
        );
    }

    #[cfg(test)]
    pub(crate) fn insert_expired_exact_for_test(
        &self,
        key: CacheKey,
        response: Vec<u8>,
        min_ttl: u32,
    ) {
        let key = CacheSlot::Exact(key);
        let index = self.shard_index(&key);
        lock(&self.shards[index]).put(
            key,
            CacheValue::positive(CachedEntry {
                response: response.into(),
                expires_at: Instant::now() - Duration::from_secs(1),
                min_ttl,
                strict_reusable: true,
            }),
        );
    }
    #[cfg(test)]
    pub(crate) fn expire_positive_exact_for_test(&self, key: &CacheKey) {
        let key = CacheSlot::Exact(key.clone());
        let index = self.shard_index(&key);
        lock(&self.shards[index])
            .get_mut(&key)
            .and_then(|value| value.positive.as_mut())
            .expect("positive cache fixture")
            .expires_at = Instant::now() - Duration::from_secs(1);
    }

    #[cfg(test)]
    pub(crate) fn insert_expired_negative_exact_for_test(&self, key: CacheKey, rcode: u8) {
        let key = CacheSlot::Exact(key);
        let index = self.shard_index(&key);
        let negative = NegativeEntry {
            expires_at: Instant::now() - Duration::from_secs(1),
            rcode,
        };
        let mut shard = lock(&self.shards[index]);
        if let Some(value) = shard.get_mut(&key) {
            value.negative = Some(negative);
        } else {
            shard.put(key, CacheValue::negative(negative));
        }
    }

    #[cfg(test)]
    pub(crate) fn insert_beyond_stale_retention_for_test(
        &self,
        key: String,
        response: Vec<u8>,
        min_ttl: u32,
    ) {
        let key = CacheSlot::Legacy(key);
        let index = self.shard_index(&key);
        lock(&self.shards[index]).put(
            key,
            CacheValue::positive(CachedEntry {
                response: response.into(),
                expires_at: Instant::now()
                    - super::storage::STALE_RETENTION
                    - Duration::from_secs(1),
                min_ttl,
                strict_reusable: true,
            }),
        );
    }

    pub fn put_negative(&self, key: String, ttl: u32, rcode: u8) {
        let key = CacheSlot::Legacy(key);
        let index = self.shard_index(&key);
        lock(&self.shards[index]).put(key, CacheValue::negative(negative_entry(ttl, rcode)));
    }

    pub(crate) fn put_negative_exact(&self, key: CacheKey, ttl: u32, rcode: u8) {
        self.merge_negative_slot(CacheSlot::Exact(key), ttl, rcode);
    }

    fn merge_negative_slot(&self, key: CacheSlot, ttl: u32, rcode: u8) {
        let negative = negative_entry(ttl, rcode);
        let index = self.shard_index(&key);
        let mut shard = lock(&self.shards[index]);
        if let Some(value) = shard.get_mut(&key) {
            value.negative = Some(negative);
        } else {
            shard.put(key, CacheValue::negative(negative));
        }
    }

    pub(crate) fn put_negative_if_current(
        &self,
        epoch: PublicationEpoch,
        key: CacheKey,
        ttl: u32,
        rcode: u8,
    ) {
        let registry = lock(&self.refresh_tasks);
        if !registry.accepting_publications || registry.publication_epoch != epoch.0 {
            return;
        }
        self.put_negative_exact(key, ttl, rcode);
    }

    pub fn negative_rcode(&self, key: &str) -> Option<u8> {
        self.negative_hit(key).map(|hit| hit.rcode)
    }

    pub fn negative_hit(&self, key: &str) -> Option<NegativeCacheHit> {
        self.negative_hit_slot(&CacheSlot::Legacy(key.to_owned()))
    }

    #[cfg(test)]
    pub(crate) fn negative_hit_exact(&self, key: &CacheKey) -> Option<NegativeCacheHit> {
        self.negative_hit_slot(&CacheSlot::Exact(key.clone()))
    }

    fn negative_hit_slot(&self, key: &CacheSlot) -> Option<NegativeCacheHit> {
        let index = self.shard_index(key);
        let now = Instant::now();
        let mut shard = lock(&self.shards[index]);
        let (result, clear_negative) = match shard.peek(key) {
            Some(value) => match value.negative.as_ref() {
                Some(negative) => match negative.expires_at.checked_duration_since(now) {
                    Some(remaining) => {
                        let rounded_secs = remaining
                            .as_secs()
                            .saturating_add(u64::from(remaining.subsec_nanos() > 0));
                        (
                            Some(NegativeCacheHit {
                                rcode: negative.rcode,
                                remaining_ttl: Duration::from_secs(rounded_secs),
                            }),
                            false,
                        )
                    }
                    None => (None, true),
                },
                None => (None, false),
            },
            None => (None, false),
        };
        if clear_negative {
            let remove_slot = shard.peek_mut(key).is_some_and(|value| {
                value.negative = None;
                value.positive.is_none()
            });
            if remove_slot {
                shard.pop(key);
            }
        }
        if result.is_some() {
            self.counters.hits.fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheHit);
            tracing::debug!(result = "negative_hit", "DNS cache lookup");
        }
        result
    }
}

fn negative_entry(ttl: u32, rcode: u8) -> NegativeEntry {
    NegativeEntry {
        expires_at: Instant::now() + Duration::from_secs(u64::from(ttl.clamp(1, 300))),
        rcode,
    }
}
