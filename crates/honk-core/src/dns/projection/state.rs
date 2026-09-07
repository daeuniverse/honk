use honk_ebpf_common::DomainRouting;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::time::Instant;

use super::{ProjectionObservation, RoutingProjectionSnapshot, or_bitmap};
type OwnerKey = Arc<str>;

#[derive(Debug)]
pub(super) struct DomainOwner {
    pub(super) ips: BTreeSet<IpAddr>,
    pub(super) expires_at: Instant,
    pub(super) sequence: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RetryMetadata {
    pub(super) attempts: u8,
    pub(super) next_at: Instant,
}

#[derive(Debug)]
pub(super) struct Batch {
    pub(super) generation: u64,
    pub(super) sets: Vec<PendingSet>,
    pub(super) removes: Vec<PendingRemove>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PendingSet {
    pub(super) ip: IpAddr,
    pub(super) bitmap: DomainRouting,
    pub(super) revision: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PendingRemove {
    pub(super) ip: IpAddr,
    pub(super) revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct DeadlineEntry {
    pub(super) at: Instant,
    pub(super) domain: OwnerKey,
    pub(super) sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RetryDeadline {
    pub(super) at: Instant,
    pub(super) ip: IpAddr,
    pub(super) attempts: u8,
}

pub(super) struct DesiredState {
    pub(super) capacity: usize,
    pub(super) sequence: u64,
    pub(super) snapshot: Arc<RoutingProjectionSnapshot>,
    pub(super) owners: BTreeMap<OwnerKey, DomainOwner>,
    pub(super) reverse: BTreeMap<IpAddr, BTreeSet<OwnerKey>>,
    pub(super) desired: BTreeMap<IpAddr, DomainRouting>,
    pub(super) revisions: BTreeMap<IpAddr, u64>,
    pub(super) applied: BTreeMap<IpAddr, DomainRouting>,
    pub(super) dirty_ips: BTreeSet<IpAddr>,
    pub(super) retries: BTreeMap<IpAddr, RetryMetadata>,
    pub(super) expiry_deadlines: BinaryHeap<Reverse<DeadlineEntry>>,
    pub(super) eviction_order: BinaryHeap<Reverse<(u64, OwnerKey)>>,
    pub(super) retry_deadlines: BinaryHeap<Reverse<RetryDeadline>>,
}

impl DesiredState {
    pub(super) fn new(snapshot: Arc<RoutingProjectionSnapshot>, capacity: usize) -> Self {
        Self {
            capacity,
            sequence: 0,
            snapshot,
            owners: BTreeMap::new(),
            reverse: BTreeMap::new(),
            desired: BTreeMap::new(),
            revisions: BTreeMap::new(),
            applied: BTreeMap::new(),
            dirty_ips: BTreeSet::new(),
            retries: BTreeMap::new(),
            expiry_deadlines: BinaryHeap::new(),
            eviction_order: BinaryHeap::new(),
            retry_deadlines: BinaryHeap::new(),
        }
    }

    pub(super) fn update_snapshot(&mut self, snapshot: Arc<RoutingProjectionSnapshot>) -> bool {
        if snapshot.generation() <= self.snapshot.generation() {
            return snapshot.generation() == self.snapshot.generation();
        }
        self.snapshot = snapshot;
        self.rebuild_all();
        true
    }

    pub(super) fn observe(&mut self, observation: ProjectionObservation<'_>, now: Instant) -> u64 {
        self.expire(now);
        match observation {
            ProjectionObservation::Positive {
                domain,
                ips,
                advertised_ttl,
            } => self.replace(domain, ips, now + advertised_ttl),
            ProjectionObservation::Clear { domain } => {
                self.remove_owner(domain);
                0
            }
            ProjectionObservation::Retain => 0,
        }
    }

    fn replace(&mut self, domain: &str, ips: &[IpAddr], expires_at: Instant) -> u64 {
        self.sequence = self.sequence.wrapping_add(1);
        let sequence = self.sequence;
        let ips = ips.iter().copied().collect::<BTreeSet<_>>();
        let existing = self.owners.get_key_value(domain).map(|(key, owner)| {
            let removed = owner.ips.difference(&ips).copied().collect::<Vec<_>>();
            let added = ips.difference(&owner.ips).copied().collect::<Vec<_>>();
            (Arc::clone(key), removed, added)
        });

        let owner_key = existing
            .as_ref()
            .map(|(key, _, _)| Arc::clone(key))
            .unwrap_or_else(|| Arc::<str>::from(domain));
        let mut affected = Vec::new();
        if let Some((_, removed, added)) = &existing {
            affected.reserve(removed.len() + added.len());
            for ip in removed {
                if let Some(domains) = self.reverse.get_mut(ip) {
                    domains.remove(&owner_key);
                    if domains.is_empty() {
                        self.reverse.remove(ip);
                    }
                }
                affected.push(*ip);
            }
            for ip in added {
                self.reverse
                    .entry(*ip)
                    .or_default()
                    .insert(Arc::clone(&owner_key));
                affected.push(*ip);
            }
            let owner = self
                .owners
                .get_mut(&owner_key)
                .expect("existing projection owner disappeared");
            owner.ips = ips;
            owner.expires_at = expires_at;
            owner.sequence = sequence;
        } else {
            affected.reserve(ips.len());
            for ip in &ips {
                self.reverse
                    .entry(*ip)
                    .or_default()
                    .insert(Arc::clone(&owner_key));
                affected.push(*ip);
            }
            self.owners.insert(
                Arc::clone(&owner_key),
                DomainOwner {
                    ips,
                    expires_at,
                    sequence,
                },
            );
        }

        self.expiry_deadlines.push(Reverse(DeadlineEntry {
            at: expires_at,
            domain: Arc::clone(&owner_key),
            sequence,
        }));
        self.eviction_order
            .push(Reverse((sequence, Arc::clone(&owner_key))));
        self.recompute_ips(affected);
        self.compact_owner_heaps_if_needed();
        if self.owners.len() <= self.capacity {
            return 0;
        }

        let evicted = loop {
            let Some(Reverse((candidate_sequence, candidate))) = self.eviction_order.pop() else {
                break None;
            };
            if self
                .owners
                .get(&candidate)
                .is_some_and(|owner| owner.sequence == candidate_sequence)
            {
                break Some(candidate);
            }
        };
        if let Some(evicted) = evicted {
            self.remove_owner(&evicted);
            1
        } else {
            0
        }
    }

    fn remove_owner(&mut self, domain: &str) {
        let Some((owner_key, owner)) = self.owners.remove_entry(domain) else {
            return;
        };
        for ip in &owner.ips {
            if let Some(domains) = self.reverse.get_mut(ip) {
                domains.remove(&owner_key);
                if domains.is_empty() {
                    self.reverse.remove(ip);
                }
            }
        }
        self.recompute_ips(owner.ips);
        self.compact_owner_heaps_if_needed();
    }

    fn recompute_ips(&mut self, ips: impl IntoIterator<Item = IpAddr>) {
        for ip in ips {
            let mut aggregate = DomainRouting::default();
            if let Some(domains) = self.reverse.get(&ip) {
                for domain in domains {
                    if let Some(bitmap) = self.snapshot.bitmap_for(domain) {
                        or_bitmap(&mut aggregate, &bitmap);
                    }
                }
            }
            let next = aggregate
                .bitmap
                .iter()
                .any(|word| *word != 0)
                .then_some(aggregate);
            let unchanged = match (self.desired.get(&ip), next.as_ref()) {
                (Some(current), Some(next)) => current.bitmap == next.bitmap,
                (None, None) => true,
                (Some(_), None) | (None, Some(_)) => false,
            };
            if unchanged {
                continue;
            }
            let revision = self.revisions.entry(ip).or_default();
            *revision = revision.wrapping_add(1);
            if let Some(next) = next {
                self.desired.insert(ip, next);
            } else {
                self.desired.remove(&ip);
            }
            self.dirty_ips.insert(ip);
        }
    }

    pub(super) fn rebuild_all(&mut self) {
        let ips = self
            .reverse
            .keys()
            .chain(self.applied.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        self.recompute_ips(ips);
    }

    fn prune_stale_expiry_heads(&mut self) {
        while self.expiry_deadlines.peek().is_some_and(|entry| {
            let deadline = &entry.0;
            !self.owners.get(&deadline.domain).is_some_and(|owner| {
                owner.sequence == deadline.sequence && owner.expires_at == deadline.at
            })
        }) {
            self.expiry_deadlines.pop();
        }
    }

    pub(super) fn compact_owner_heaps_if_needed(&mut self) {
        self.prune_stale_expiry_heads();
        let live = self.owners.len();
        let stale_limit = live.max(64);
        let expiry_stale = self.expiry_deadlines.len().saturating_sub(live);
        let eviction_stale = self.eviction_order.len().saturating_sub(live);
        if expiry_stale <= stale_limit && eviction_stale <= stale_limit {
            return;
        }
        let mut expiry_deadlines = BinaryHeap::with_capacity(live);
        let mut eviction_order = BinaryHeap::with_capacity(live);
        for (domain, owner) in &self.owners {
            expiry_deadlines.push(Reverse(DeadlineEntry {
                at: owner.expires_at,
                domain: Arc::clone(domain),
                sequence: owner.sequence,
            }));
            eviction_order.push(Reverse((owner.sequence, Arc::clone(domain))));
        }
        self.expiry_deadlines = expiry_deadlines;
        self.eviction_order = eviction_order;
    }

    pub(super) fn project(
        &self,
        snapshot: &RoutingProjectionSnapshot,
    ) -> BTreeMap<IpAddr, DomainRouting> {
        self.reverse
            .iter()
            .filter_map(|(ip, domains)| {
                let mut aggregate = DomainRouting::default();
                for domain in domains {
                    if let Some(bitmap) = snapshot.bitmap_for(domain) {
                        or_bitmap(&mut aggregate, &bitmap);
                    }
                }
                aggregate
                    .bitmap
                    .iter()
                    .any(|word| *word != 0)
                    .then_some((*ip, aggregate))
            })
            .collect()
    }

    pub(super) fn expire(&mut self, now: Instant) {
        self.prune_stale_expiry_heads();
        while let Some(Reverse(deadline)) = self.expiry_deadlines.peek() {
            if deadline.at > now {
                break;
            }
            let deadline = self
                .expiry_deadlines
                .pop()
                .expect("expiry heap entry disappeared")
                .0;
            if self
                .owners
                .get(&deadline.domain)
                .is_some_and(|owner| owner.sequence == deadline.sequence && owner.expires_at <= now)
            {
                self.remove_owner(&deadline.domain);
            }
            self.prune_stale_expiry_heads();
        }
        self.compact_owner_heaps_if_needed();
    }

    #[cfg(test)]
    pub(super) fn owner_domains(&self) -> Vec<String> {
        self.owners.keys().map(ToString::to_string).collect()
    }
}
