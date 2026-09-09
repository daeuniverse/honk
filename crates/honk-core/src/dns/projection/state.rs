use honk_ebpf_common::DomainRouting;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::time::Instant;

use super::{ProjectionObservation, RoutingProjectionSnapshot, or_bitmap};
type OwnerKey = Arc<str>;

// Leave a quarter of the map for sniff writes and another quarter unavailable
// to present-zero facts, so DNS misses cannot crowd out later matching facts.
pub(super) const IP_CAPACITY: usize = crate::ebpf::maps::DOMAIN_MAP_CAPACITY as usize * 3 / 4;
pub(super) const ZERO_IP_CAPACITY: usize = crate::ebpf::maps::DOMAIN_MAP_CAPACITY as usize / 2;

fn aggregate_domains(
    snapshot: &RoutingProjectionSnapshot,
    domains: &BTreeSet<OwnerKey>,
) -> Option<DomainRouting> {
    let mut aggregate = None;
    for domain in domains {
        if let Some(bitmap) = snapshot.bitmap_for(domain) {
            or_bitmap(aggregate.get_or_insert_default(), &bitmap);
        }
    }
    aggregate
}

fn insert_bounded(
    entries: &mut BTreeMap<IpAddr, DomainRouting>,
    zero_ips: &mut BTreeSet<IpAddr>,
    ip: IpAddr,
    bitmap: DomainRouting,
) -> Option<IpAddr> {
    entries.insert(ip, bitmap);
    if bitmap.bitmap == [0; 8] {
        zero_ips.insert(ip);
    } else {
        zero_ips.remove(&ip);
    }
    let evicted = if zero_ips.len() > ZERO_IP_CAPACITY || entries.len() > IP_CAPACITY {
        // Within one priority, lower addresses win independently of arrival order.
        zero_ips
            .last()
            .copied()
            .or_else(|| entries.last_key_value().map(|(ip, _)| *ip))
    } else {
        None
    };
    if let Some(evicted) = evicted {
        entries.remove(&evicted);
        zero_ips.remove(&evicted);
    }
    evicted
}

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
    pub(super) removes: Vec<IpAddr>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PendingSet {
    pub(super) ip: IpAddr,
    pub(super) bitmap: DomainRouting,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct DeadlineEntry {
    pub(super) at: Instant,
    pub(super) domain: OwnerKey,
    pub(super) sequence: u64,
}

pub(super) struct DesiredState {
    pub(super) capacity: usize,
    pub(super) sequence: u64,
    pub(super) snapshot: Arc<RoutingProjectionSnapshot>,
    pub(super) owners: BTreeMap<OwnerKey, DomainOwner>,
    pub(super) reverse: BTreeMap<IpAddr, BTreeSet<OwnerKey>>,
    pub(super) desired: BTreeMap<IpAddr, DomainRouting>,
    zero_ips: BTreeSet<IpAddr>,
    capacity_warning_emitted: bool,
    pub(super) applied: BTreeMap<IpAddr, DomainRouting>,
    pub(super) dirty_ips: BTreeSet<IpAddr>,
    pub(super) retries: BTreeMap<IpAddr, RetryMetadata>,
    pub(super) expiry_deadlines: BinaryHeap<Reverse<DeadlineEntry>>,
    pub(super) eviction_order: BinaryHeap<Reverse<(u64, OwnerKey)>>,
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
            zero_ips: BTreeSet::new(),
            capacity_warning_emitted: false,
            applied: BTreeMap::new(),
            dirty_ips: BTreeSet::new(),
            retries: BTreeMap::new(),
            expiry_deadlines: BinaryHeap::new(),
            eviction_order: BinaryHeap::new(),
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
        let ips = ips
            .iter()
            .map(|ip| ip.to_canonical())
            .collect::<BTreeSet<_>>();
        let existing = self.owners.get_key_value(domain).map(|(key, owner)| {
            let removed = owner.ips.difference(&ips).copied().collect::<Vec<_>>();
            let added = ips
                .iter()
                .filter(|ip| !owner.ips.contains(ip) || !self.desired.contains_key(ip))
                .copied()
                .collect::<Vec<_>>();
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
            let next = self
                .reverse
                .get(&ip)
                .and_then(|domains| aggregate_domains(&self.snapshot, domains));
            let unchanged = match (self.desired.get(&ip), next.as_ref()) {
                (Some(current), Some(next)) => current.bitmap == next.bitmap,
                (None, None) => true,
                (Some(_), None) | (None, Some(_)) => false,
            };
            if unchanged {
                continue;
            }
            let evicted = if let Some(next) = next {
                insert_bounded(&mut self.desired, &mut self.zero_ips, ip, next)
            } else {
                self.desired.remove(&ip);
                self.zero_ips.remove(&ip);
                None
            };
            if evicted.is_some() && !self.capacity_warning_emitted {
                tracing::warn!(
                    ip_capacity = IP_CAPACITY,
                    zero_ip_capacity = ZERO_IP_CAPACITY,
                    "DNS routing projection capacity reached; omitted IPs use cache-miss routing"
                );
                self.capacity_warning_emitted = true;
            }
            if evicted != Some(ip) || self.applied.contains_key(&ip) {
                self.dirty_ips.insert(ip);
            }
            if let Some(evicted) = evicted.filter(|evicted| *evicted != ip) {
                self.dirty_ips.insert(evicted);
            }
        }
    }

    pub(super) fn rebuild_all(&mut self) {
        let desired = self.project(&self.snapshot);
        let ips = self
            .desired
            .keys()
            .chain(desired.keys())
            .chain(self.applied.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for ip in ips {
            let next = desired.get(&ip).map(|entry| entry.bitmap);
            if self.desired.get(&ip).map(|entry| entry.bitmap) != next
                || self.applied.get(&ip).map(|entry| entry.bitmap) != next
            {
                self.dirty_ips.insert(ip);
            }
        }
        self.zero_ips = desired
            .iter()
            .filter_map(|(ip, bitmap)| (bitmap.bitmap == [0; 8]).then_some(*ip))
            .collect();
        self.desired = desired;
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
        let mut entries = BTreeMap::new();
        let mut zero_ips = BTreeSet::new();
        for (ip, domains) in &self.reverse {
            if let Some(bitmap) = aggregate_domains(snapshot, domains) {
                insert_bounded(&mut entries, &mut zero_ips, *ip, bitmap);
            }
        }
        entries
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
