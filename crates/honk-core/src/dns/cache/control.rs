use std::sync::Arc;
#[cfg(any(feature = "native-api", test))]
use std::time::Instant;

#[cfg(any(feature = "native-api", test))]
use sha2::{Digest, Sha256};

#[cfg(any(feature = "native-api", test))]
use super::{CacheKey, CacheSlot, CacheValue};
use super::{DnsCacheService, lock};
use crate::dns::persist::{PersistControlError, PersistInvalidation};
#[cfg(any(feature = "native-api", test))]
use crate::dns::query::QueryContext;

#[cfg(any(feature = "native-api", test))]
#[derive(Debug, Clone)]
pub(crate) struct ExactCacheEntry {
    pub id: String,
    pub key: CacheKey,
    pub response: Option<bytes::Bytes>,
    pub expires_at: Instant,
    pub stale_until: Option<Instant>,
    pub negative: Option<u8>,
    pub cost: usize,
}

/// Whole-cache occupancy beside its effective bounds, unaffected by listing filters.
#[cfg(any(feature = "native-api", test))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CacheUsage {
    pub entries: usize,
    pub entry_capacity: usize,
}

#[cfg(any(feature = "native-api", test))]
#[derive(Debug)]
pub(crate) struct CacheInspection {
    pub entries: Vec<ExactCacheEntry>,
    pub usage: CacheUsage,
}

#[cfg(any(feature = "native-api", test))]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("DNS cache snapshot exceeds its retained byte budget")]
pub(crate) struct CacheInspectionError;

#[derive(Debug, Clone)]
pub(crate) enum CacheInvalidation {
    All,
    #[cfg(any(feature = "native-api", test))]
    Id(String),
    #[cfg(any(feature = "native-api", test))]
    Name {
        name: String,
        types: Vec<u16>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CacheMutation {
    #[cfg(any(feature = "native-api", test))]
    pub deleted: usize,
    pub persistent: bool,
}

struct PublicationFence<'a>(&'a DnsCacheService);

impl Drop for PublicationFence<'_> {
    fn drop(&mut self) {
        let mut publication = lock(&self.0.publication);
        publication.epoch = publication
            .epoch
            .checked_add(1)
            .expect("DNS cache epoch exhausted");
        publication.accepting = true;
    }
}

impl DnsCacheService {
    #[cfg(any(feature = "native-api", test))]
    fn incarnation_id(&self, revision: u64) -> String {
        let mut digest = Sha256::new();
        digest.update(self.identity_nonce.as_bytes());
        digest.update(revision.to_be_bytes());
        crate::configuration::encode_digest(&digest.finalize())
    }

    #[cfg(test)]
    pub(crate) fn entry_id(&self, key: &CacheKey) -> Option<String> {
        let slot = CacheSlot::Exact(key.clone());
        let shard = lock(&self.shards[self.shard_index(&slot)]);
        shard
            .peek(&slot)
            .map(|value| self.incarnation_id(value.revision))
    }

    #[cfg(any(feature = "native-api", test))]
    pub(crate) fn entry_id_for_revision(&self, key: &CacheKey, revision: u64) -> Option<String> {
        let slot = CacheSlot::Exact(key.clone());
        let shard = lock(&self.shards[self.shard_index(&slot)]);
        shard
            .peek(&slot)
            .filter(|value| value.revision == revision)
            .map(|_| self.incarnation_id(revision))
    }
    /// The selector must not reenter the cache: publication and shard locks are held.
    ///
    /// Every shard stays locked until the listing and usage are both taken, so
    /// they describe one instant of the whole cache rather than per-shard reads.
    #[cfg(any(feature = "native-api", test))]
    pub(crate) fn inspect_exact(
        &self,
        max_bytes: usize,
        now: Instant,
        mut select: impl FnMut(&CacheKey, Instant) -> bool,
    ) -> Result<CacheInspection, CacheInspectionError> {
        let _publication = lock(&self.publication);
        let shards: Vec<_> = self.shards.iter().map(lock).collect();
        let mut total = 0usize;
        let mut selected = Vec::new();
        let mut usage = CacheUsage::default();
        for shard in &shards {
            usage.entries += shard.len();
            usage.entry_capacity += shard.cap().get();
            for (slot, value) in shard.iter() {
                let CacheSlot::Exact(key) = slot else {
                    continue;
                };
                let negative = value
                    .negative
                    .filter(|entry| now < entry.expires_at || value.positive.is_none());
                let expires_at = negative.map_or_else(
                    || {
                        value
                            .positive
                            .as_ref()
                            .expect("retained cache slots contain an answer")
                            .expires_at
                    },
                    |entry| entry.expires_at,
                );
                if !select(key, expires_at) {
                    continue;
                }
                let cost = inspection_cost(key, value);
                total = total
                    .checked_add(cost)
                    .filter(|total| *total <= max_bytes)
                    .ok_or(CacheInspectionError)?;
                selected.push((key, value, negative, cost));
            }
        }
        let mut entries = Vec::with_capacity(selected.len());
        for (key, value, negative, cost) in selected {
            let (response, expires_at, stale_until, negative) = if let Some(entry) = negative {
                (None, entry.expires_at, None, Some(entry.rcode))
            } else if let Some(entry) = &value.positive {
                (
                    Some(entry.response.clone()),
                    entry.expires_at,
                    Some(entry.expires_at + super::storage::STALE_RETENTION),
                    None,
                )
            } else {
                unreachable!("retained cache slots contain an answer")
            };
            entries.push(ExactCacheEntry {
                id: self.incarnation_id(value.revision),
                key: key.clone(),
                response,
                expires_at,
                stale_until,
                negative,
                cost,
            });
        }
        Ok(CacheInspection { entries, usage })
    }

    pub(crate) async fn invalidate(
        self: &Arc<Self>,
        selection: CacheInvalidation,
    ) -> Result<CacheMutation, PersistControlError> {
        // Reserve before touching memory: cancellation cannot leave an unqueued deletion.
        let _mutation = self.mutation.lock().await;
        let persister = self.persistence();
        let reserved = match &persister {
            Some(persister) => Some(persister.reserve_invalidation().await?),
            None => None,
        };
        let fence;
        let pending;
        #[cfg(any(feature = "native-api", test))]
        let mut deleted = 0usize;
        {
            let mut publication = lock(&self.publication);
            publication.epoch = publication
                .epoch
                .checked_add(1)
                .expect("DNS cache epoch exhausted");
            publication.accepting = false;
            fence = PublicationFence(self);
            #[cfg(any(feature = "native-api", test))]
            let mut exact_keys = Vec::new();
            for shard in &self.shards {
                let mut shard = lock(shard);
                if matches!(selection, CacheInvalidation::All) {
                    #[cfg(any(feature = "native-api", test))]
                    {
                        deleted += shard.len();
                    }
                    shard.clear();
                    continue;
                }
                #[cfg(any(feature = "native-api", test))]
                {
                    let selected: Vec<_> = shard
                        .iter()
                        .filter(|(slot, value)| match &selection {
                            CacheInvalidation::All => true,
                            CacheInvalidation::Id(id) => {
                                matches!(slot, CacheSlot::Exact(_))
                                    && self.incarnation_id(value.revision) == *id
                            }
                            CacheInvalidation::Name { name, types } => match slot {
                                CacheSlot::Exact(key) => {
                                    question_matches(key.wire_identity(), name, types)
                                }
                                CacheSlot::Legacy(key) => legacy_matches(key, name, types),
                            },
                        })
                        .map(|(slot, _)| slot.clone())
                        .collect();
                    for slot in selected {
                        if let CacheSlot::Exact(key) = &slot
                            && matches!(selection, CacheInvalidation::Id(_))
                        {
                            exact_keys.push(key.clone());
                        }
                        if shard.pop(&slot).is_some() {
                            deleted += 1;
                        }
                    }
                }
            }
            let target = match selection {
                CacheInvalidation::All => PersistInvalidation::All,
                #[cfg(any(feature = "native-api", test))]
                CacheInvalidation::Id(_) => PersistInvalidation::Keys(exact_keys),
                #[cfg(any(feature = "native-api", test))]
                CacheInvalidation::Name { name, types } => {
                    PersistInvalidation::Name { name, types }
                }
            };
            // This synchronous enqueue precedes reopening publication even if the waiter drops.
            pending = reserved.map(|reserved| reserved.send(target));
        }
        if let Some(pending) = pending {
            pending.complete().await?;
        }
        drop(fence);
        Ok(CacheMutation {
            #[cfg(any(feature = "native-api", test))]
            deleted,
            persistent: persister.is_some(),
        })
    }
}

#[cfg(any(feature = "native-api", test))]
fn inspection_cost(key: &CacheKey, value: &CacheValue) -> usize {
    let scope = match key.scope() {
        crate::dns::planner::RequestScope::Upstream(tag) => tag.as_str().len(),
        crate::dns::planner::RequestScope::AsIs(_) => 0,
    };
    // Charge shared allocations in full; snapshots retain them after cache eviction.
    std::mem::size_of::<ExactCacheEntry>()
        .saturating_add(128 + 64)
        .saturating_add(key.wire_identity().len())
        .saturating_add(
            key.policy_id()
                .map_or(0, |policy| policy.canonical_bytes().len()),
        )
        .saturating_add(scope)
        .saturating_add(value.response_bytes())
}

#[cfg(any(feature = "native-api", test))]
pub(crate) fn question_matches(wire: &[u8], name: &str, types: &[u16]) -> bool {
    let Ok(query) = QueryContext::parse(wire) else {
        return false;
    };
    let name = name
        .strip_suffix('.')
        .filter(|name| !name.is_empty())
        .unwrap_or(name);
    query
        .qname()
        .and_then(|name| name.to_domain_name())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
        && query
            .qtype()
            .is_some_and(|kind| types.is_empty() || types.contains(&kind.get()))
}

#[cfg(any(feature = "native-api", test))]
pub(crate) fn legacy_matches(key: &str, name: &str, types: &[u16]) -> bool {
    key.rsplit_once(':').is_some_and(|(candidate, kind)| {
        candidate
            .trim_end_matches('.')
            .eq_ignore_ascii_case(name.trim_end_matches('.'))
            && kind
                .parse::<u16>()
                .is_ok_and(|kind| types.is_empty() || types.contains(&kind))
    })
}
