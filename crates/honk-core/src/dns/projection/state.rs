use honk_datapath::ScopeId;
use honk_ebpf_common::DomainRouting;
use honk_outbound::alive::IpVersion;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "ebpf")]
use std::time::Duration;
use tokio::time::Instant;

#[cfg(feature = "ebpf")]
use crate::ebpf::native::{NativePublication, NativeWrite};

use super::{ProjectionObservation, RoutingProjectionSnapshot, or_bitmap};
type OwnerKey = Arc<str>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ProjectionIp {
    pub(super) address: IpAddr,
    scope: u64,
}

impl ProjectionIp {
    pub(super) fn new(scope: ScopeId, address: IpAddr) -> Self {
        Self {
            address: address.to_canonical(),
            scope: scope.as_u64(),
        }
    }

    fn in_scope(scope: u64, address: IpAddr) -> Self {
        Self {
            address: address.to_canonical(),
            scope,
        }
    }

    pub(super) fn is_host(self) -> bool {
        self.scope == ScopeId::HOST.as_u64()
    }
}
/// A name's owner within one address-family slot. A mapped-IPv6 AAAA answer
/// shares its IPv4 key, so one IP may belong to both families of a name.
type FamilyOwner = (OwnerKey, usize);

#[cfg(any(test, feature = "dns-bench"))]
pub(super) fn family_of(ip: IpAddr) -> IpVersion {
    if ip.is_ipv4() {
        IpVersion::V4
    } else {
        IpVersion::V6
    }
}

// Leave a quarter of the map for sniff writes and another quarter unavailable
// to present-zero facts, so DNS misses cannot crowd out later matching facts.
pub(super) const IP_CAPACITY: usize = crate::ebpf::maps::DOMAIN_MAP_CAPACITY as usize * 3 / 4;
pub(super) const ZERO_IP_CAPACITY: usize = crate::ebpf::maps::DOMAIN_MAP_CAPACITY as usize / 2;

/// The owners of one IP and the bitmaps they contribute under the current
/// snapshot. Contributions are counted per member, so changing one owner of a
/// shared IP never re-evaluates the domain matcher for its siblings.
#[derive(Debug, Default)]
pub(super) struct IpOwners {
    pub(super) members: HashSet<FamilyOwner>,
    contributions: Vec<(DomainRouting, u32)>,
}

impl IpOwners {
    fn insert(&mut self, member: FamilyOwner, bitmap: Option<DomainRouting>) {
        if self.members.insert(member)
            && let Some(bitmap) = bitmap
        {
            Self::add_bitmap(&mut self.contributions, bitmap);
        }
    }

    fn add_bitmap(contributions: &mut Vec<(DomainRouting, u32)>, bitmap: DomainRouting) {
        match contributions.iter_mut().find(|(known, _)| *known == bitmap) {
            Some((_, count)) => *count += 1,
            None => contributions.push((bitmap, 1)),
        }
    }

    fn remove(&mut self, member: &FamilyOwner, bitmap: Option<DomainRouting>) {
        if self.members.remove(member)
            && let Some(bitmap) = bitmap
        {
            let index = self
                .contributions
                .iter()
                .position(|(known, _)| *known == bitmap)
                .expect("projection member lost its bitmap contribution");
            self.contributions[index].1 -= 1;
            if self.contributions[index].1 == 0 {
                self.contributions.swap_remove(index);
            }
        }
    }

    fn aggregate(&self) -> Option<DomainRouting> {
        let mut contributions = self.contributions.iter().map(|(bitmap, _)| bitmap);
        let mut aggregate = *contributions.next()?;
        for bitmap in contributions {
            or_bitmap(&mut aggregate, bitmap);
        }
        Some(aggregate)
    }
}

fn insert_bounded(
    entries: &mut BTreeMap<ProjectionIp, DomainRouting>,
    zero_ips: &mut BTreeSet<ProjectionIp>,
    ip: ProjectionIp,
    bitmap: DomainRouting,
    before_evict: impl FnOnce(ProjectionIp),
) -> Option<ProjectionIp> {
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
        before_evict(evicted);
        entries.remove(&evicted);
        zero_ips.remove(&evicted);
    }
    evicted
}

#[derive(Debug)]
pub(super) struct DomainOwner {
    pub(super) ips: BTreeSet<IpAddr>,
    /// The name's bitmap under `DesiredState::snapshot`; `None` means no
    /// domain predicate exists, unlike a present-zero bitmap.
    pub(super) bitmap: Option<DomainRouting>,
    pub(super) expires_at: Instant,
    pub(super) sequence: u64,
    // Queued entries survive refreshes; these fence removed/re-added owners.
    expiry_sequence: u64,
    eviction_sequence: u64,
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
    pub(super) scope: u64,
    pub(super) family: usize,
    pub(super) domain: OwnerKey,
    pub(super) sequence: u64,
}

#[derive(Debug)]
pub(super) struct PacketFactScope {
    scope: ScopeId,
    revision: u64,
}

impl PacketFactScope {
    pub(super) fn new(scope: ScopeId) -> Self {
        Self { scope, revision: 0 }
    }
}

/// One fixed wake for all pending expiry extensions, derived from the installed horizon.
/// Refreshes never move it. A fresh remaining horizon >=2s waits at least 1s;
/// shorter horizons wait half their remaining duration, without extending it.
#[cfg(feature = "ebpf")]
#[derive(Debug, Default)]
pub(super) struct NativeRefresh {
    at: Option<Instant>,
    pending: bool,
}

#[cfg(feature = "ebpf")]
impl NativeRefresh {
    pub(super) fn published(&mut self, horizon: Option<Instant>, now: Instant) {
        self.at = horizon.map(|deadline| {
            let remaining = deadline.saturating_duration_since(now);
            deadline - (remaining / 2).min(Duration::from_secs(1))
        });
        self.pending = false;
    }

    pub(super) fn defer(&mut self) {
        // A publication may have omitted every fact before this extension arrived.
        self.at.get_or_insert_with(Instant::now);
        self.pending = true;
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        self.at.filter(|_| self.pending)
    }

    fn due(&self, now: Instant) -> bool {
        self.deadline().is_some_and(|deadline| deadline <= now)
    }
}

fn advance_revision(scopes: &mut [PacketFactScope], scope: u64) {
    if let Some(entry) = scopes
        .iter_mut()
        .find(|entry| entry.scope.as_u64() == scope)
        && entry.revision != u64::MAX
    {
        entry.revision += 1;
        if entry.revision == u64::MAX {
            tracing::error!(
                scope,
                "packet DNS fact revision exhausted; fact-dependent Core decisions now drop"
            );
        }
    }
}

pub(super) struct DesiredState {
    pub(super) capacity: usize,
    pub(super) sequence: u64,
    pub(super) snapshot: Arc<RoutingProjectionSnapshot>,
    /// Indexed by family, then scope; names share one global owner budget.
    pub(super) owners: [HashMap<u64, HashMap<OwnerKey, DomainOwner>>; 2],
    pub(super) reverse: BTreeMap<ProjectionIp, IpOwners>,
    pub(super) desired: BTreeMap<ProjectionIp, DomainRouting>,
    zero_ips: BTreeSet<ProjectionIp>,
    capacity_warning_emitted: bool,
    pub(super) applied: BTreeMap<IpAddr, DomainRouting>,
    pub(super) dirty_ips: BTreeSet<IpAddr>,
    pub(super) retries: BTreeMap<IpAddr, RetryMetadata>,
    pub(super) expiry_deadlines: BinaryHeap<Reverse<DeadlineEntry>>,
    pub(super) eviction_order: BinaryHeap<Reverse<(u64, u64, usize, OwnerKey)>>,
    /// Advances whenever an owner is added, removed, re-keyed or rebuilt, so
    /// cache-hit hints can detect owner changes without taking the state lock.
    pub(super) structure: Arc<AtomicU64>,
    /// Set once: removing the table would allow a retained stamp's revision to be reissued.
    packet_scopes: Box<[PacketFactScope]>,
    _packet_scope_charge: Option<honk_netstack::MemoryReservation>,
    #[cfg(feature = "ebpf")]
    packet_scope_budget: Option<Arc<honk_netstack::MemoryBudget>>,
    #[cfg(feature = "ebpf")]
    native: Option<Arc<NativePublication>>,
    #[cfg(feature = "ebpf")]
    native_failure_logged: bool,
    #[cfg(feature = "ebpf")]
    pub(super) native_refresh: NativeRefresh,
}

impl DesiredState {
    pub(super) fn new(snapshot: Arc<RoutingProjectionSnapshot>, capacity: usize) -> Self {
        Self {
            capacity,
            sequence: 0,
            snapshot,
            owners: [HashMap::new(), HashMap::new()],
            reverse: BTreeMap::new(),
            desired: BTreeMap::new(),
            zero_ips: BTreeSet::new(),
            capacity_warning_emitted: false,
            applied: BTreeMap::new(),
            dirty_ips: BTreeSet::new(),
            retries: BTreeMap::new(),
            expiry_deadlines: BinaryHeap::new(),
            eviction_order: BinaryHeap::new(),
            structure: Arc::new(AtomicU64::new(0)),
            packet_scopes: Box::default(),
            _packet_scope_charge: None,
            #[cfg(feature = "ebpf")]
            packet_scope_budget: None,
            #[cfg(feature = "ebpf")]
            native: None,
            #[cfg(feature = "ebpf")]
            native_failure_logged: false,
            #[cfg(feature = "ebpf")]
            native_refresh: NativeRefresh::default(),
        }
    }

    pub(super) fn register_packet_scopes(
        &mut self,
        scopes: Box<[PacketFactScope]>,
        charge: honk_netstack::MemoryReservation,
        budget: &Arc<honk_netstack::MemoryBudget>,
    ) -> anyhow::Result<()> {
        if !self.packet_scopes.is_empty() {
            // Parameters otherwise drop the charge before the rejected table.
            drop(scopes);
            anyhow::bail!("packet DNS scopes are already registered");
        }
        self.packet_scopes = scopes;
        self._packet_scope_charge = Some(charge);
        #[cfg(feature = "ebpf")]
        {
            self.packet_scope_budget = Some(Arc::clone(budget));
        }
        #[cfg(not(feature = "ebpf"))]
        let _ = budget;
        Ok(())
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn install_native(&mut self, native: Arc<NativePublication>) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.native.is_none(),
            "native DNS publication is already installed"
        );
        anyhow::ensure!(
            !self.packet_scopes.is_empty(),
            "native DNS publication requires registered packet scopes"
        );
        self.native = Some(native);
        self.mutate(|state| state.expire_inner(Instant::now()))
    }

    fn mutate<R>(&mut self, operation: impl FnOnce(&mut Self) -> R) -> anyhow::Result<R> {
        #[cfg(feature = "ebpf")]
        let write = match self
            .native
            .as_ref()
            .map(|native| native.write(crate::ebpf::native::NativeReason::ScopedDns))
            .transpose()
        {
            Ok(write) => write,
            Err(error) => {
                self.native_refresh.published(None, Instant::now());
                self.log_native_failure(&error);
                None
            }
        };
        let result = operation(self);
        #[cfg(feature = "ebpf")]
        if let Some(write) = write {
            match self.export_native(&write) {
                Ok(()) => write.commit(),
                Err(error) => {
                    self.native_refresh.published(None, Instant::now());
                    self.log_native_failure(&error);
                }
            }
        }
        Ok(result)
    }

    #[cfg(feature = "ebpf")]
    fn log_native_failure(&mut self, error: &anyhow::Error) {
        if !self.native_failure_logged {
            tracing::error!(%error, "native DNS publication failed; native forwarding remains closed");
            self.native_failure_logged = true;
        }
    }

    #[cfg(feature = "ebpf")]
    fn export_native(&mut self, writer: &NativeWrite) -> anyhow::Result<()> {
        let native = Arc::clone(
            self.native
                .as_ref()
                .expect("installed native DNS publication"),
        );
        let capacity = self.desired.keys().filter(|key| !key.is_host()).count();
        let bytes =
            std::alloc::Layout::array::<(IpAddr, DomainRouting, Option<Instant>)>(capacity)?.size();
        let _charge = self
            .packet_scope_budget
            .as_ref()
            .expect("registered packet DNS scope budget")
            .reserve(bytes)
            .ok_or_else(|| anyhow::anyhow!("native DNS export memory capacity"))?;
        let mut facts = Vec::with_capacity(capacity);
        for entry in &self.packet_scopes {
            anyhow::ensure!(
                entry.revision != u64::MAX,
                "packet DNS fact revision is exhausted"
            );
            facts.clear();
            facts.extend(self.native_scope_facts(entry.scope));
            native.update_scope(
                entry.scope,
                entry.revision,
                self.snapshot.generation(),
                self.snapshot.matcher.policy_fingerprint(),
                &facts,
                writer,
            )?;
        }
        self.native_refresh
            .published(native.renewal_deadline()?, Instant::now());
        Ok(())
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn native_scope_facts(
        &self,
        scope: ScopeId,
    ) -> impl Iterator<Item = (IpAddr, DomainRouting, Option<Instant>)> + '_ {
        self.desired
            .iter()
            .filter(move |(key, _)| key.scope == scope.as_u64())
            .map(|(key, bitmap)| (key.address, *bitmap, self.fact_expiry(key)))
    }

    pub(super) fn owns_packet_scope(&self, scope: ScopeId) -> bool {
        scope != ScopeId::HOST && self.packet_scopes.iter().any(|entry| entry.scope == scope)
    }

    pub(super) fn packet_fact(
        &mut self,
        scope: ScopeId,
        ip: IpAddr,
        now: Instant,
    ) -> anyhow::Result<(Option<DomainRouting>, super::FactStamp)> {
        self.try_expire(now)?;
        let revision = self
            .packet_scopes
            .iter()
            .find(|entry| entry.scope == scope)
            .map(|entry| entry.revision)
            .ok_or_else(|| anyhow::anyhow!("packet DNS fact scope is not registered"))?;
        anyhow::ensure!(
            revision != u64::MAX,
            "packet DNS fact revision is exhausted"
        );
        let key = ProjectionIp::new(scope, ip);
        let expires_at = self.fact_expiry(&key);
        Ok((
            self.desired.get(&key).copied(),
            super::FactStamp {
                scope,
                revision,
                expires_at,
            },
        ))
    }

    fn fact_expiry(&self, key: &ProjectionIp) -> Option<Instant> {
        self.reverse
            .get(key)
            .into_iter()
            .flat_map(|owners| &owners.members)
            .filter_map(|(domain, family)| {
                self.owners[*family]
                    .get(&key.scope)
                    .and_then(|owners| owners.get(domain))
                    .map(|owner| owner.expires_at)
            })
            .min()
    }

    pub(super) fn fact_is_current(&mut self, stamp: super::FactStamp, now: Instant) -> bool {
        if self.try_expire(now).is_err() {
            return false;
        }
        stamp.revision != u64::MAX
            && self
                .packet_scopes
                .iter()
                .any(|entry| entry.scope == stamp.scope && entry.revision == stamp.revision)
            && stamp.is_unexpired_at(now)
    }

    #[cfg(all(test, feature = "ebpf"))]
    pub(super) fn install_closed_native_for_test(&mut self, native: Arc<NativePublication>) {
        assert!(native.terminal());
        assert!(self.native.is_none());
        self.native = Some(native);
    }

    #[cfg(test)]
    pub(super) fn set_packet_fact_revision_for_test(&mut self, scope: ScopeId, revision: u64) {
        self.packet_scopes
            .iter_mut()
            .find(|entry| entry.scope == scope)
            .expect("registered test scope")
            .revision = revision;
    }

    pub(super) fn update_snapshot(&mut self, snapshot: &Arc<RoutingProjectionSnapshot>) -> bool {
        if snapshot.generation() <= self.snapshot.generation() {
            return snapshot.generation() == self.snapshot.generation();
        }
        self.mutate(|state| {
            state.snapshot = Arc::clone(snapshot);
            state.rebuild_all();
        })
        .is_ok()
    }

    pub(super) fn observe(
        &mut self,
        scope: ScopeId,
        observation: ProjectionObservation<'_>,
        now: Instant,
    ) -> u64 {
        #[cfg(feature = "ebpf")]
        if self.native.is_some() && self.native_extension_only(scope, observation, now) {
            // Expiry may withdraw a different owner; close for that mutation first.
            if let Err(error) = self.try_expire(now) {
                self.log_native_failure(&error);
            }
            // Publication can outlive the old expiry; admission must use its completion time.
            let now = Instant::now().max(now);
            self.advance_extended_wakes(now);
            let expiry_due = self
                .expiry_deadlines
                .peek()
                .is_some_and(|entry| entry.0.at <= now);
            if !expiry_due && self.native_extension_only(scope, observation, now) {
                let evicted = self.observe_inner(scope, observation, now);
                if let Some(entry) = self.packet_scopes.iter().find(|entry| entry.scope == scope) {
                    let current = self
                        .native
                        .as_ref()
                        .expect("installed native DNS publication")
                        .scope_is_current(
                            scope,
                            entry.revision,
                            self.snapshot.generation(),
                            self.snapshot.matcher.policy_fingerprint(),
                            self.native_scope_facts(scope),
                        );
                    if !current {
                        self.native_refresh.defer();
                    }
                }
                return evicted;
            }
            return self
                .mutate(|state| state.observe_inner(scope, observation, now))
                .unwrap_or(0);
        }
        self.mutate(|state| state.observe_inner(scope, observation, now))
            .unwrap_or(0)
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn native_extension_only(
        &self,
        scope: ScopeId,
        observation: ProjectionObservation<'_>,
        now: Instant,
    ) -> bool {
        let ProjectionObservation::Positive {
            domain,
            family,
            ips,
            expires_at,
        } = observation
        else {
            return false;
        };
        self.unchanged_owner(scope.as_u64(), family as usize, domain, ips)
            .is_some_and(|owner| {
                now < owner.expires_at && now < expires_at && expires_at >= owner.expires_at
            })
    }

    fn observe_inner(
        &mut self,
        scope: ScopeId,
        observation: ProjectionObservation<'_>,
        now: Instant,
    ) -> u64 {
        let scope = scope.as_u64();
        self.expire_inner(now);
        match observation {
            ProjectionObservation::Positive {
                domain,
                family,
                ips,
                expires_at,
            } => {
                if expires_at > now {
                    self.replace(scope, family as usize, domain, ips, expires_at)
                } else {
                    // Reload prefill can run before the expiry worker does.
                    self.remove_owner(scope, family as usize, domain);
                    0
                }
            }
            ProjectionObservation::Clear { domain, family } => {
                self.remove_owner(scope, family as usize, domain);
                0
            }
            ProjectionObservation::ClearName { domain } => {
                self.remove_owner(scope, IpVersion::V4 as usize, domain);
                self.remove_owner(scope, IpVersion::V6 as usize, domain);
                0
            }
            ProjectionObservation::Retain => 0,
        }
    }

    fn owner_count(&self) -> usize {
        self.owners
            .iter()
            .flat_map(HashMap::values)
            .map(HashMap::len)
            .sum()
    }

    fn unchanged_owner(
        &self,
        scope: u64,
        family: usize,
        domain: &str,
        ips: &[IpAddr],
    ) -> Option<&DomainOwner> {
        self.owners[family]
            .get(&scope)
            .and_then(|owners| owners.get(domain))
            .filter(|owner| {
                same_address_set(owner.ips.iter(), ips)
                    && owner
                        .ips
                        .iter()
                        .all(|ip| self.fully_admitted(&ProjectionIp::in_scope(scope, *ip)))
            })
    }

    fn replace(
        &mut self,
        scope: u64,
        family: usize,
        domain: &str,
        ips: &[IpAddr],
        expires_at: Instant,
    ) -> u64 {
        self.sequence = self.sequence.wrapping_add(1);
        let sequence = self.sequence;
        // Cache hits re-submit an unchanged set; avoid rebuilding it. With the
        // same members, recompute changes nothing unless an address was left
        // out of `desired` by capacity, which the general path re-admits.
        let unchanged = self.unchanged_owner(scope, family, domain, ips).is_some();
        if unchanged {
            let (key, owner) = self.owners[family]
                .get(&scope)
                .expect("refreshed projection scope disappeared")
                .get_key_value(domain)
                .expect("refreshed projection owner disappeared");
            let key = Arc::clone(key);
            let shortened = expires_at < owner.expires_at;
            if shortened {
                advance_revision(&mut self.packet_scopes, scope);
            }
            let owner = self.owners[family]
                .get_mut(&scope)
                .expect("refreshed projection scope disappeared")
                .get_mut(domain)
                .expect("refreshed projection owner disappeared");
            if shortened {
                owner.expiry_sequence = sequence;
            }
            owner.expires_at = expires_at;
            owner.sequence = sequence;
            if shortened {
                self.expiry_deadlines.push(Reverse(DeadlineEntry {
                    at: expires_at,
                    scope,
                    family,
                    domain: key,
                    sequence,
                }));
            }
            self.compact_owner_heaps_if_needed();
            return 0;
        }
        let ips = ips
            .iter()
            .map(|ip| ip.to_canonical())
            .collect::<BTreeSet<_>>();
        advance_revision(&mut self.packet_scopes, scope);
        self.structure.fetch_add(1, Ordering::Release);
        let existing = self.owners[family]
            .get(&scope)
            .and_then(|owners| owners.get_key_value(domain))
            .map(|(key, owner)| {
                let removed = owner.ips.difference(&ips).copied().collect::<Vec<_>>();
                let added = ips
                    .iter()
                    .filter(|ip| {
                        !owner.ips.contains(ip)
                            || !self
                                .desired
                                .contains_key(&ProjectionIp::in_scope(scope, **ip))
                    })
                    .copied()
                    .collect::<Vec<_>>();
                (Arc::clone(key), owner.bitmap, removed, added)
            });

        let (owner_key, bitmap) = match &existing {
            Some((key, bitmap, _, _)) => (Arc::clone(key), *bitmap),
            None => match self.owners[1 - family]
                .get(&scope)
                .and_then(|owners| owners.get_key_value(domain))
            {
                Some((key, sibling)) => (Arc::clone(key), sibling.bitmap),
                None => (Arc::<str>::from(domain), self.snapshot.bitmap_for(domain)),
            },
        };
        let member: FamilyOwner = (Arc::clone(&owner_key), family);
        let mut affected = Vec::new();
        let mut schedule_expiry = true;
        if let Some((_, _, removed, added)) = &existing {
            affected.reserve(removed.len() + added.len());
            for ip in removed {
                let key = ProjectionIp::in_scope(scope, *ip);
                if let Some(owners) = self.reverse.get_mut(&key) {
                    owners.remove(&member, bitmap);
                    if owners.members.is_empty() {
                        self.reverse.remove(&key);
                    }
                }
                affected.push(*ip);
            }
            for ip in added {
                self.reverse
                    .entry(ProjectionIp::in_scope(scope, *ip))
                    .or_default()
                    .insert(member.clone(), bitmap);
                affected.push(*ip);
            }
            let owner = self.owners[family]
                .get_mut(&scope)
                .expect("existing projection scope disappeared")
                .get_mut(&owner_key)
                .expect("existing projection owner disappeared");
            owner.ips = ips;
            // Extensions reuse the earlier queued wake; shortening cannot.
            schedule_expiry = expires_at < owner.expires_at;
            if schedule_expiry {
                owner.expiry_sequence = sequence;
            }
            owner.expires_at = expires_at;
            owner.sequence = sequence;
        } else {
            affected.reserve(ips.len());
            for ip in &ips {
                self.reverse
                    .entry(ProjectionIp::in_scope(scope, *ip))
                    .or_default()
                    .insert(member.clone(), bitmap);
                affected.push(*ip);
            }
            self.owners[family].entry(scope).or_default().insert(
                Arc::clone(&owner_key),
                DomainOwner {
                    ips,
                    bitmap,
                    expires_at,
                    sequence,
                    expiry_sequence: sequence,
                    eviction_sequence: sequence,
                },
            );
        }

        if schedule_expiry {
            self.expiry_deadlines.push(Reverse(DeadlineEntry {
                at: expires_at,
                scope,
                family,
                domain: Arc::clone(&owner_key),
                sequence,
            }));
        }
        if existing.is_none() {
            self.eviction_order
                .push(Reverse((sequence, scope, family, Arc::clone(&owner_key))));
        }
        self.recompute_ips(scope, affected);
        self.compact_owner_heaps_if_needed();
        if self.owner_count() <= self.capacity {
            return 0;
        }

        let evicted = loop {
            let Some(Reverse((candidate_sequence, candidate_scope, candidate_family, candidate))) =
                self.eviction_order.pop()
            else {
                break None;
            };
            let Some(owner) = self.owners[candidate_family]
                .get_mut(&candidate_scope)
                .and_then(|owners| owners.get_mut(&candidate))
            else {
                continue;
            };
            if owner.eviction_sequence != candidate_sequence {
                continue;
            }
            if owner.sequence == candidate_sequence {
                break Some((candidate_scope, candidate_family, candidate));
            }
            // A refreshed head is a lower bound, not an eviction candidate.
            let current_sequence = owner.sequence;
            owner.eviction_sequence = current_sequence;
            self.eviction_order.push(Reverse((
                current_sequence,
                candidate_scope,
                candidate_family,
                candidate,
            )));
        };
        if let Some((evicted_scope, evicted_family, evicted)) = evicted {
            self.remove_owner(evicted_scope, evicted_family, &evicted);
            1
        } else {
            0
        }
    }

    fn remove_owner(&mut self, scope: u64, family: usize, domain: &str) {
        let Some(owners) = self.owners[family].get_mut(&scope) else {
            return;
        };
        if !owners.contains_key(domain) {
            return;
        }
        advance_revision(&mut self.packet_scopes, scope);
        let (owner_key, owner) = owners
            .remove_entry(domain)
            .expect("existing projection owner");
        if owners.is_empty() {
            self.owners[family].remove(&scope);
        }
        self.structure.fetch_add(1, Ordering::Release);
        let member: FamilyOwner = (owner_key, family);
        for ip in &owner.ips {
            let key = ProjectionIp::in_scope(scope, *ip);
            if let Some(owners) = self.reverse.get_mut(&key) {
                owners.remove(&member, owner.bitmap);
                if owners.members.is_empty() {
                    self.reverse.remove(&key);
                }
            }
        }
        self.recompute_ips(scope, owner.ips);
        self.compact_owner_heaps_if_needed();
    }

    fn recompute_ips(&mut self, scope: u64, ips: impl IntoIterator<Item = IpAddr>) {
        for address in ips {
            let ip = ProjectionIp::in_scope(scope, address);
            let next = self.reverse.get(&ip).and_then(IpOwners::aggregate);
            let unchanged = match (self.desired.get(&ip), next.as_ref()) {
                (Some(current), Some(next)) => current.bitmap == next.bitmap,
                (None, None) => true,
                (Some(_), None) | (None, Some(_)) => false,
            };
            if unchanged {
                continue;
            }
            let evicted = if let Some(next) = next {
                insert_bounded(&mut self.desired, &mut self.zero_ips, ip, next, |victim| {
                    advance_revision(&mut self.packet_scopes, victim.scope);
                })
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
            if ip.is_host() && (evicted != Some(ip) || self.applied.contains_key(&ip.address)) {
                self.dirty_ips.insert(ip.address);
            }
            if let Some(evicted) = evicted.filter(|evicted| *evicted != ip && evicted.is_host()) {
                self.dirty_ips.insert(evicted.address);
            }
        }
    }

    fn rebuild_all(&mut self) {
        for entry in &mut self.packet_scopes {
            let scope = entry.scope.as_u64();
            advance_revision(std::slice::from_mut(entry), scope);
        }
        self.structure.fetch_add(1, Ordering::Release);
        self.refresh_owner_bitmaps();
        let desired = self.project_by(IpOwners::aggregate);
        let ips = self
            .desired
            .keys()
            .chain(desired.keys())
            .filter(|ip| ip.is_host())
            .map(|ip| ip.address)
            .chain(self.applied.keys().copied())
            .collect::<BTreeSet<_>>();
        for ip in ips {
            let key = ProjectionIp::new(ScopeId::HOST, ip);
            let next = desired.get(&key).map(|entry| entry.bitmap);
            if self.desired.get(&key).map(|entry| entry.bitmap) != next
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
            !self.owners[deadline.family]
                .get(&deadline.scope)
                .and_then(|owners| owners.get(&deadline.domain))
                .is_some_and(|owner| owner.expiry_sequence == deadline.sequence)
        }) {
            self.expiry_deadlines.pop();
        }
    }

    pub(super) fn compact_owner_heaps_if_needed(&mut self) {
        self.prune_stale_expiry_heads();
        let live = self.owner_count();
        let stale_limit = live.max(64);
        let expiry_stale = self.expiry_deadlines.len().saturating_sub(live);
        let eviction_stale = self.eviction_order.len().saturating_sub(live);
        if expiry_stale <= stale_limit && eviction_stale <= stale_limit {
            return;
        }
        let mut expiry_deadlines = BinaryHeap::with_capacity(live);
        let mut eviction_order = BinaryHeap::with_capacity(live);
        for (family, scopes) in self.owners.iter_mut().enumerate() {
            for (&scope, owners) in scopes {
                for (domain, owner) in owners {
                    owner.expiry_sequence = owner.sequence;
                    owner.eviction_sequence = owner.sequence;
                    expiry_deadlines.push(Reverse(DeadlineEntry {
                        at: owner.expires_at,
                        scope,
                        family,
                        domain: Arc::clone(domain),
                        sequence: owner.sequence,
                    }));
                    eviction_order.push(Reverse((
                        owner.sequence,
                        scope,
                        family,
                        Arc::clone(domain),
                    )));
                }
            }
        }
        self.expiry_deadlines = expiry_deadlines;
        self.eviction_order = eviction_order;
    }

    /// Re-evaluate each name once under the current snapshot and rebuild every
    /// IP's counted contributions from its unchanged members.
    fn refresh_owner_bitmaps(&mut self) {
        let [v4, v6] = &mut self.owners;
        for (domain, owner) in v4.values_mut().flat_map(HashMap::iter_mut) {
            owner.bitmap = self.snapshot.bitmap_for(domain);
        }
        for (scope, owners) in v6.iter_mut() {
            for (domain, owner) in owners {
                owner.bitmap = v4
                    .get(scope)
                    .and_then(|owners| owners.get(domain))
                    .map_or_else(
                        || self.snapshot.bitmap_for(domain),
                        |sibling| sibling.bitmap,
                    );
            }
        }
        for (ip, owners) in self.reverse.iter_mut() {
            owners.contributions.clear();
            for (domain, family) in &owners.members {
                if let Some(bitmap) = self.owners[*family]
                    .get(&ip.scope)
                    .and_then(|owners| owners.get(domain))
                    .expect("projection IP lost its domain owner")
                    .bitmap
                {
                    IpOwners::add_bitmap(&mut owners.contributions, bitmap);
                }
            }
        }
    }

    /// Pure projection under any snapshot, evaluating each name at most once;
    /// reload uses it before the replacement snapshot is committed.
    pub(super) fn project(
        &self,
        snapshot: &RoutingProjectionSnapshot,
    ) -> BTreeMap<IpAddr, DomainRouting> {
        let mut bitmaps = HashMap::<&str, Option<DomainRouting>>::new();
        self.project_by(|owners| {
            owners
                .members
                .iter()
                .fold(None, |mut aggregate, (domain, _)| {
                    if let Some(bitmap) = *bitmaps
                        .entry(domain)
                        .or_insert_with(|| snapshot.bitmap_for(domain))
                    {
                        or_bitmap(aggregate.get_or_insert_default(), &bitmap);
                    }
                    aggregate
                })
        })
        .into_iter()
        .filter_map(|(ip, bitmap)| ip.is_host().then_some((ip.address, bitmap)))
        .collect()
    }

    fn project_by<'a>(
        &'a self,
        mut aggregate: impl FnMut(&'a IpOwners) -> Option<DomainRouting>,
    ) -> BTreeMap<ProjectionIp, DomainRouting> {
        let mut entries = BTreeMap::new();
        let mut zero_ips = BTreeSet::new();
        for (ip, owners) in &self.reverse {
            if let Some(bitmap) = aggregate(owners) {
                insert_bounded(&mut entries, &mut zero_ips, *ip, bitmap, |_| {});
            }
        }
        entries
    }
    pub(super) fn expire(&mut self, now: Instant) {
        let _ = self.try_expire(now);
    }

    pub(super) fn try_expire(&mut self, now: Instant) -> anyhow::Result<()> {
        self.prune_stale_expiry_heads();
        #[cfg(feature = "ebpf")]
        if self.native.is_some() {
            self.advance_extended_wakes(now);
        }
        #[cfg(feature = "ebpf")]
        let native_due = self.native_refresh.due(now);
        #[cfg(not(feature = "ebpf"))]
        let native_due = false;
        if native_due
            || self
                .expiry_deadlines
                .peek()
                .is_some_and(|entry| entry.0.at <= now)
        {
            self.mutate(|state| state.expire_inner(now))
        } else {
            self.compact_owner_heaps_if_needed();
            Ok(())
        }
    }

    #[cfg(feature = "ebpf")]
    fn advance_extended_wakes(&mut self, now: Instant) {
        loop {
            self.prune_stale_expiry_heads();
            let Some(Reverse(deadline)) = self.expiry_deadlines.peek() else {
                break;
            };
            if deadline.at > now {
                break;
            }
            let expires_at = self.owners[deadline.family]
                .get(&deadline.scope)
                .and_then(|owners| owners.get(&deadline.domain))
                .expect("pruned expiry owner disappeared")
                .expires_at;
            if expires_at <= now {
                break;
            }
            // An extension retained this earlier heap wake; only queue metadata changes.
            let Reverse(mut deadline) = self
                .expiry_deadlines
                .pop()
                .expect("expiry wake disappeared");
            deadline.at = expires_at;
            self.expiry_deadlines.push(Reverse(deadline));
        }
    }

    fn expire_inner(&mut self, now: Instant) {
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
            if let Some(owner) = self.owners[deadline.family]
                .get(&deadline.scope)
                .and_then(|owners| owners.get(&deadline.domain))
                && owner.expiry_sequence == deadline.sequence
            {
                if owner.expires_at <= now {
                    self.remove_owner(deadline.scope, deadline.family, &deadline.domain);
                } else {
                    self.expiry_deadlines.push(Reverse(DeadlineEntry {
                        at: owner.expires_at,
                        ..deadline
                    }));
                }
            }
            self.prune_stale_expiry_heads();
        }
        self.compact_owner_heaps_if_needed();
    }

    /// The live owner's key, exact canonical address set and expiry, for a
    /// cache-hit hint that skips the projection fence and state lock. Owners with
    /// capacity-omitted addresses are excluded so refreshes keep retrying admission.
    pub(super) fn cache_hit_hint(
        &self,
        scope: ScopeId,
        family: usize,
        domain: &str,
    ) -> Option<(OwnerKey, Box<[IpAddr]>, Instant)> {
        let (key, owner) = self.owners[family]
            .get(&scope.as_u64())?
            .get_key_value(domain)?;
        owner
            .ips
            .iter()
            .all(|ip| self.fully_admitted(&ProjectionIp::new(scope, *ip)))
            .then(|| {
                (
                    Arc::clone(key),
                    owner.ips.iter().copied().collect(),
                    owner.expires_at,
                )
            })
    }

    /// True unless capacity left this address out of `desired` although its
    /// owners contribute a bitmap; such addresses must retry admission.
    fn fully_admitted(&self, ip: &ProjectionIp) -> bool {
        self.desired.contains_key(ip)
            || self.reverse.get(ip).and_then(IpOwners::aggregate).is_none()
    }

    pub(super) fn try_bitmap(
        &mut self,
        scope: ScopeId,
        ip: IpAddr,
    ) -> anyhow::Result<Option<DomainRouting>> {
        self.try_expire(Instant::now())?;
        Ok(self.desired.get(&ProjectionIp::new(scope, ip)).copied())
    }

    #[cfg(test)]
    pub(super) fn bitmap(&mut self, scope: ScopeId, ip: IpAddr) -> Option<DomainRouting> {
        self.try_bitmap(scope, ip).unwrap()
    }

    #[cfg(test)]
    pub(super) fn owner_domains(&self) -> Vec<String> {
        let mut domains = Vec::new();
        for owners in &self.owners {
            let start = domains.len();
            domains.extend(
                owners
                    .values()
                    .flat_map(HashMap::keys)
                    .map(ToString::to_string),
            );
            domains[start..].sort_unstable();
        }
        domains
    }
}

/// Whether `ips` canonicalizes to exactly the ascending set `known`.
pub(super) fn same_address_set<'a>(
    known: impl ExactSizeIterator<Item = &'a IpAddr> + Clone,
    ips: &[IpAddr],
) -> bool {
    // Answers are usually tiny; a large one sorts once instead of comparing
    // quadratically. Duplicates break the strict ascending match.
    const SMALL_SET: usize = 16;
    if known.len() != ips.len() {
        return false;
    }
    if ips.len() <= SMALL_SET {
        return ips
            .iter()
            .all(|ip| known.clone().any(|known| *known == ip.to_canonical()))
            && known
                .clone()
                .all(|known| ips.iter().any(|ip| ip.to_canonical() == *known));
    }
    let mut sorted = ips.iter().map(IpAddr::to_canonical).collect::<Vec<_>>();
    sorted.sort_unstable();
    sorted.iter().eq(known)
}

#[cfg(all(test, feature = "ebpf"))]
mod native_tests {
    use super::*;
    use crate::routing::Router;
    use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
    use honk_netstack::MemoryBudget;

    fn registered_state(
        scopes: &[ScopeId],
    ) -> (
        DesiredState,
        Arc<RoutingProjectionSnapshot>,
        Arc<MemoryBudget>,
    ) {
        let router = Router::new(
            &[RoutingRule {
                name: "domains".into(),
                condition: RoutingCondition {
                    domain: vec!["a.test".into(), "b.test".into()],
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple("direct".into()),
                priority: 0,
                must: false,
                mark: None,
            }],
            "direct",
        )
        .unwrap();
        let snapshot = Arc::new(RoutingProjectionSnapshot::new(1, Arc::new(router)));
        let mut state = DesiredState::new(Arc::clone(&snapshot), 16);
        let budget = MemoryBudget::new(1 << 20);
        state
            .register_packet_scopes(
                scopes.iter().copied().map(PacketFactScope::new).collect(),
                budget.reserve(4096).unwrap(),
                &budget,
            )
            .unwrap();
        (state, snapshot, budget)
    }

    #[tokio::test(start_paused = true)]
    async fn extension_rechecks_time_after_expiry_publication() {
        let scope = ScopeId::allocate().unwrap();
        let (mut state, snapshot, budget) = registered_state(&[scope]);
        let start = Instant::now();
        let ips = ["192.0.2.1".parse().unwrap()];
        let positive = |domain, expires_at| ProjectionObservation::Positive {
            domain,
            family: IpVersion::V4,
            ips: &ips,
            expires_at,
        };
        for (domain, seconds) in [("a.test", 3), ("b.test", 1)] {
            state.observe(
                scope,
                positive(domain, start + Duration::from_secs(seconds)),
                start,
            );
        }
        let native = NativePublication::closed_for_test(budget).unwrap();
        state.install_native(Arc::clone(&native)).unwrap();
        let writes = native.write_attempts_for_test();
        let revision = state.packet_scopes[0].revision;
        let captured = start + Duration::from_secs(2);
        tokio::time::advance(Duration::from_secs(4)).await;
        let extended = start + Duration::from_secs(60);

        // A refused publication clears the horizon too, without requiring kernel hooks.
        state.observe(scope, positive("a.test", extended), captured);

        assert_eq!(native.write_attempts_for_test(), writes + 2);
        assert_eq!(state.packet_scopes[0].revision, revision + 3);
        assert_eq!(state.owner_domains(), ["a.test"]);
        assert_eq!(
            state.native_scope_facts(scope).collect::<Vec<_>>(),
            [(
                ips[0],
                snapshot.bitmap_for("a.test").unwrap(),
                Some(extended)
            )]
        );
        assert_eq!(state.next_deadline(), Some(extended));
    }

    #[tokio::test(start_paused = true)]
    async fn extension_fences_siblings_expiring_during_publication() {
        let scope = ScopeId::allocate().unwrap();
        let sibling = ScopeId::allocate().unwrap();
        let (mut state, _, budget) = registered_state(&[scope, sibling]);
        let start = Instant::now();
        let ips = ["192.0.2.1".parse().unwrap()];
        let positive = |domain, expires_at| ProjectionObservation::Positive {
            domain,
            family: IpVersion::V4,
            ips: &ips,
            expires_at,
        };
        for (owner_scope, domain, seconds) in [
            (scope, "a.test", 30),
            (scope, "b.test", 1),
            (sibling, "b.test", 3),
        ] {
            state.observe(
                owner_scope,
                positive(domain, start + Duration::from_secs(seconds)),
                start,
            );
        }
        let native = NativePublication::closed_for_test(budget).unwrap();
        state.install_native(Arc::clone(&native)).unwrap();
        let writes = native.write_attempts_for_test();
        let revision = state.packet_scopes[1].revision;
        let captured = start + Duration::from_secs(2);
        tokio::time::advance(Duration::from_secs(4)).await;

        state.observe(
            scope,
            positive("a.test", start + Duration::from_secs(30)),
            captured,
        );

        assert_eq!(native.write_attempts_for_test(), writes + 2);
        assert_eq!(state.packet_scopes[1].revision, revision + 1);
        assert!(state.native_scope_facts(sibling).next().is_none());
        assert_eq!(state.owner_domains(), ["a.test"]);
    }

    #[tokio::test(start_paused = true)]
    async fn extension_without_an_installed_horizon_gets_an_immediate_wake() {
        let now = Instant::now();
        let mut refresh = NativeRefresh::default();
        refresh.published(None, now);
        refresh.defer();
        assert_eq!(refresh.deadline(), Some(now));
        assert!(refresh.due(now));
    }
}
