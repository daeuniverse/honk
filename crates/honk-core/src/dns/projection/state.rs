use honk_datapath::ScopeId;
use honk_ebpf_common::DomainRouting;
use honk_outbound::alive::IpVersion;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::Instant;

use super::{ProjectionObservation, ProjectionSource, RoutingProjectionSnapshot, or_bitmap};
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
    cache_revision: Option<u64>,
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
    // Zero is a permanent scope. Auxiliary incarnations start offline (odd).
    // Every close/open advances it. The last representable value is closed.
    binding: u64,
}

impl PacketFactScope {
    pub(super) fn new(scope: ScopeId) -> Self {
        Self {
            scope,
            revision: 0,
            binding: 0,
        }
    }
}

struct AuxiliaryRegistration {
    scopes: Box<[ScopeId]>,
    root: Arc<honk_netstack::MemoryBudget>,
    _charge: honk_netstack::MemoryReservation,
}

#[cfg(target_os = "linux")]
struct HostPort {
    source: crate::control::netstack::PacketScope,
    stamp: u64,
}

#[cfg(target_os = "linux")]
impl HostPort {
    fn active(&self) -> bool {
        self.stamp & 1 == 0 && self.source.binding() == self.stamp
    }
}

#[cfg(target_os = "linux")]
struct HostScopes {
    shared: ScopeId,
    standalone: ScopeId,
    ports: Box<[HostPort]>,
    _charge: honk_netstack::MemoryReservation,
}

#[cfg(target_os = "linux")]
impl HostScopes {
    fn port(&self, scope: ScopeId) -> Option<&HostPort> {
        self.ports.iter().find(|port| port.source.scope() == scope)
    }
}

#[derive(Default)]
struct PacketScopes {
    entries: Box<[PacketFactScope]>,
    auxiliary_registration: Option<AuxiliaryRegistration>,
    #[cfg(target_os = "linux")]
    host: Option<HostScopes>,
    #[cfg(target_os = "linux")]
    bank: Option<Arc<super::GatewayDnsBank>>,
}

impl PacketScopes {
    fn entry(&self, scope: ScopeId) -> Option<&PacketFactScope> {
        self.entries.iter().find(|entry| entry.scope == scope)
    }

    fn withdraw(&mut self, scope: u64) {
        #[cfg(target_os = "linux")]
        if let Some(bank) = &self.bank {
            bank.revoke(scope);
        }
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.scope.as_u64() == scope)
        else {
            return;
        };
        Self::advance_revision(entry);
    }

    fn advance_revision(entry: &mut PacketFactScope) {
        if entry.revision == u64::MAX {
            return;
        }
        entry.revision += 1;
        if entry.revision == u64::MAX {
            tracing::error!(
                scope = entry.scope.as_u64(),
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
    packet_scopes: PacketScopes,
    _packet_scope_charge: Option<honk_netstack::MemoryReservation>,
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
            packet_scopes: PacketScopes::default(),
            _packet_scope_charge: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn register_aux_scopes(
        &mut self,
        scopes: &[ScopeId],
        budget: &Arc<honk_netstack::MemoryBudget>,
    ) -> std::io::Result<()> {
        if scopes.is_empty() {
            return Ok(());
        }
        if !self.packet_scopes.entries.is_empty()
            || self.packet_scopes.auxiliary_registration.is_some()
            || scopes
                .iter()
                .enumerate()
                .any(|(i, scope)| *scope == ScopeId::HOST || scopes[..i].contains(scope))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid auxiliary DNS scope registration",
            ));
        }
        let charge = budget
            .reserve(std::mem::size_of_val(scopes))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::OutOfMemory,
                    "auxiliary DNS scope registration memory capacity",
                )
            })?;
        self.packet_scopes.auxiliary_registration = Some(AuxiliaryRegistration {
            scopes: scopes.into(),
            root: Arc::clone(budget),
            _charge: charge,
        });
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn register_host_scopes(
        &mut self,
        shared: ScopeId,
        standalone: ScopeId,
        ports: &[crate::control::netstack::PacketScope],
        budget: &Arc<honk_netstack::MemoryBudget>,
    ) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind};

        if !self.packet_scopes.entries.is_empty()
            || self.packet_scopes.host.is_some()
            || shared == ScopeId::HOST
            || standalone == ScopeId::HOST
            || shared == standalone
            || ports.is_empty()
            || ports.iter().enumerate().any(|(i, port)| {
                let scope = port.scope();
                scope == shared
                    || scope == standalone
                    || port.binding() & 1 == 0
                    || !Arc::ptr_eq(&port.budget(), budget)
                    || ports[..i].iter().any(|earlier| earlier.scope() == scope)
            })
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid Host DNS scope registration",
            ));
        }
        let bytes = std::alloc::Layout::array::<HostPort>(ports.len())
            .map_err(Error::other)?
            .size();
        let charge = budget.reserve(bytes).ok_or_else(|| {
            Error::new(
                ErrorKind::OutOfMemory,
                "Host DNS scope registration memory capacity",
            )
        })?;
        self.packet_scopes.host = Some(HostScopes {
            shared,
            standalone,
            ports: ports
                .iter()
                .map(|source| HostPort {
                    source: source.clone(),
                    stamp: 1,
                })
                .collect(),
            _charge: charge,
        });
        Ok(())
    }

    pub(super) fn register_packet_scopes(
        &mut self,
        scopes: impl ExactSizeIterator<Item = ScopeId>,
        budget: &Arc<honk_netstack::MemoryBudget>,
    ) -> anyhow::Result<()> {
        if !self.packet_scopes.entries.is_empty() {
            anyhow::bail!("packet DNS scopes are already registered");
        }
        let count = scopes.len();
        #[cfg(target_os = "linux")]
        let count = count + 2 * usize::from(self.packet_scopes.host.is_some());
        let bytes = std::alloc::Layout::array::<PacketFactScope>(count)?.size();
        let charge = budget
            .reserve(bytes)
            .ok_or_else(|| anyhow::anyhow!("packet DNS scope registration memory capacity"))?;
        let mut table = Vec::with_capacity(count);
        table.extend(scopes.map(PacketFactScope::new));
        if let Some(aux) = &self.packet_scopes.auxiliary_registration {
            anyhow::ensure!(
                Arc::ptr_eq(&aux.root, budget),
                "auxiliary DNS scopes must share the capture budget"
            );
            for scope in &aux.scopes {
                let entry = table
                    .iter_mut()
                    .find(|entry| entry.scope == *scope)
                    .ok_or_else(|| {
                        anyhow::anyhow!("auxiliary DNS scope missing from packet registration")
                    })?;
                entry.binding = 1;
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(host) = &self.packet_scopes.host {
            anyhow::ensure!(
                Arc::ptr_eq(&host.ports[0].source.budget(), budget)
                    && table.iter().all(|entry| {
                        entry.scope != host.shared && entry.scope != host.standalone
                    })
                    && host.ports.iter().all(|port| {
                        table
                            .iter()
                            .any(|entry| entry.scope == port.source.scope() && entry.binding == 0)
                    }),
                "Host DNS scopes must be distinct and share the registered packet budget"
            );
            let mut shared = PacketFactScope::new(host.shared);
            shared.binding = 1;
            table.push(shared);
            table.push(PacketFactScope::new(host.standalone));
        }
        self.packet_scopes.auxiliary_registration.take();
        self.packet_scopes.entries = table.into_boxed_slice();
        self._packet_scope_charge = Some(charge);
        Ok(())
    }

    pub(super) fn owns_packet_scope(&self, scope: ScopeId) -> bool {
        self.packet_scopes.entry(scope).is_some()
    }

    pub(super) fn packet_query_scope(&self, scope: ScopeId) -> Option<super::QueryScope> {
        #[cfg(target_os = "linux")]
        if let Some(host) = &self.packet_scopes.host {
            if let Some(port) = host.port(scope) {
                return port
                    .active()
                    .then(|| super::QueryScope::packet(host.shared, scope, port.stamp));
            }
            if scope == host.shared {
                return None;
            }
        }
        match self.packet_scopes.entry(scope)?.binding {
            0 => Some(super::QueryScope::permanent(scope)),
            stamp if stamp & 1 == 0 => Some(super::QueryScope::packet(scope, scope, stamp)),
            _ => None,
        }
    }

    pub(super) fn query_scope_is_current(&self, query: super::QueryScope) -> bool {
        match query.origin {
            super::QueryOrigin::Permanent => true,
            super::QueryOrigin::Packet { execution, .. } => {
                self.packet_query_scope(execution) == Some(query)
            }
            #[cfg(target_os = "linux")]
            super::QueryOrigin::HostListener { stamp } => {
                self.host_fact_binding(query.fact_scope) == Some(stamp)
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn host_listener_query_scope(
        &self,
        standalone: ScopeId,
    ) -> Option<super::QueryScope> {
        let host = self
            .packet_scopes
            .host
            .as_ref()
            .filter(|host| host.standalone == standalone)?;
        Some(self.host_listener_scope(host.shared))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn host_listener_scope(&self, scope: ScopeId) -> super::QueryScope {
        super::QueryScope {
            fact_scope: scope,
            origin: super::QueryOrigin::HostListener {
                stamp: self.host_fact_binding(scope).unwrap_or(0),
            },
        }
    }

    #[cfg(target_os = "linux")]
    fn host_fact_binding(&self, scope: ScopeId) -> Option<u64> {
        let host = self
            .packet_scopes
            .host
            .as_ref()
            .filter(|host| host.shared == scope)?;
        let stamp = self.packet_scopes.entry(scope)?.binding;
        (stamp & 1 == 0 && host.ports.iter().any(HostPort::active)).then_some(stamp)
    }

    pub(super) fn packet_fact_destination(&self, scope: ScopeId) -> Option<ScopeId> {
        #[cfg(target_os = "linux")]
        if let Some(host) = &self.packet_scopes.host {
            if let Some(port) = host.port(scope) {
                return port.active().then_some(host.shared);
            }
            if scope == host.shared {
                return self.host_fact_binding(scope).map(|_| scope);
            }
        }
        Some(scope)
    }

    #[cfg(all(target_os = "linux", any(feature = "packet-ebpf", test)))]
    pub(super) fn set_host_binding(
        &mut self,
        scope: ScopeId,
        stamp: u64,
        active: bool,
    ) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind};

        let invalid = || {
            Error::new(
                ErrorKind::InvalidInput,
                "invalid Host DNS execution binding",
            )
        };
        let host = self.packet_scopes.host.as_ref().ok_or_else(invalid)?;
        let index = host
            .ports
            .iter()
            .position(|port| port.source.scope() == scope)
            .ok_or_else(invalid)?;
        let port = &host.ports[index];
        if stamp == 0 || stamp & 1 != 0 {
            return Err(invalid());
        }
        if active {
            if port.source.binding() != stamp || stamp < port.stamp {
                return Err(invalid());
            }
            if stamp == port.stamp {
                return Ok(());
            }
            if port.stamp & 1 == 0 {
                return Err(invalid());
            }
        } else if stamp != port.stamp {
            return if stamp < port.stamp {
                Ok(())
            } else {
                Err(invalid())
            };
        }

        let shared = host.shared;
        let another = host
            .ports
            .iter()
            .enumerate()
            .any(|(i, port)| i != index && port.active());
        if !another {
            // The driver's source can close before its publisher reports withdrawal.
            self.set_fact_binding(shared, false)?;
            if active {
                self.set_fact_binding(shared, true)?;
            }
        } else if !active && let Some(bank) = &self.packet_scopes.bank {
            bank.discard_fill(super::QueryScope::packet(shared, scope, stamp));
        }
        self.packet_scopes
            .host
            .as_mut()
            .expect("registered Host scopes")
            .ports[index]
            .stamp = stamp | u64::from(!active);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn set_aux_binding(&mut self, scope: ScopeId, active: bool) -> std::io::Result<()> {
        if self
            .packet_scopes
            .host
            .as_ref()
            .is_some_and(|host| host.shared == scope)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Host DNS binding requires a packet source stamp",
            ));
        }
        self.set_fact_binding(scope, active)
    }

    #[cfg(target_os = "linux")]
    fn set_fact_binding(&mut self, scope: ScopeId, active: bool) -> std::io::Result<()> {
        let entry = self
            .packet_scopes
            .entries
            .iter_mut()
            .find(|entry| entry.scope == scope && entry.binding != 0)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "unregistered auxiliary DNS scope",
                )
            })?;
        if (entry.binding & 1 == 0) == active {
            return Ok(());
        }
        let next = entry
            .binding
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("auxiliary DNS binding identity exhausted"))?;
        if let Some(bank) = &self.packet_scopes.bank {
            bank.set_binding(scope, active)?;
        }
        entry.binding = next;
        if !active {
            PacketScopes::advance_revision(entry);
            let scope = scope.as_u64();
            for family in &mut self.owners {
                if let Some(owners) = family.remove(&scope) {
                    for owner in owners.into_values() {
                        for ip in owner.ips {
                            let key = ProjectionIp::in_scope(scope, ip);
                            if self.reverse.remove(&key).is_some() {
                                self.desired.remove(&key);
                                self.zero_ips.remove(&key);
                            }
                        }
                    }
                }
            }
            self.expiry_deadlines
                .retain(|Reverse(row)| row.scope != scope);
            self.eviction_order
                .retain(|Reverse((_, owner_scope, _, _))| *owner_scope != scope);
        }
        Ok(())
    }

    pub(super) fn packet_fact(
        &mut self,
        scope: ScopeId,
        ip: IpAddr,
        now: Instant,
    ) -> anyhow::Result<(Option<DomainRouting>, super::FactStamp)> {
        self.try_expire(now)?;
        let scope = self
            .packet_fact_destination(scope)
            .ok_or_else(|| anyhow::anyhow!("packet DNS fact scope is unavailable"))?;
        let revision = self
            .packet_scopes
            .entries
            .iter()
            .find(|entry| entry.scope == scope && entry.binding & 1 == 0)
            .map(|entry| entry.revision)
            .ok_or_else(|| anyhow::anyhow!("packet DNS fact scope is unavailable"))?;
        anyhow::ensure!(
            revision != u64::MAX,
            "packet DNS fact revision is exhausted"
        );
        let key = ProjectionIp::new(scope, ip);
        let expires_at = self
            .reverse
            .get(&key)
            .and_then(|owners| self.fact_expiry(key.scope, owners));
        Ok((
            self.desired.get(&key).copied(),
            super::FactStamp {
                scope,
                revision,
                expires_at,
            },
        ))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn gateway_bank(&self) -> Option<&Arc<super::GatewayDnsBank>> {
        self.packet_scopes.bank.as_ref()
    }

    #[cfg(target_os = "linux")]
    pub(super) fn close_gateway_dns(&mut self) -> Option<Arc<super::GatewayDnsBank>> {
        let bank = self.packet_scopes.bank.take()?;
        bank.close();
        Some(bank)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn bind_gateway_dns(
        &mut self,
        bank: Option<&Arc<super::GatewayDnsBank>>,
        allowed: impl FnOnce() -> bool,
    ) -> bool {
        debug_assert!(self.gateway_bank().is_none());
        let Some(bank) = bank else { return false };
        if !allowed()
            || !bank.scopes().all(|scope| {
                self.owns_packet_scope(scope)
                    && self
                        .packet_scopes
                        .host
                        .as_ref()
                        .is_none_or(|host| scope != host.standalone && host.port(scope).is_none())
            })
        {
            bank.close();
            return false;
        }
        if !bank.activate(|scope| {
            self.packet_query_scope(scope).is_some() || self.host_fact_binding(scope).is_some()
        }) {
            return false;
        }
        self.packet_scopes.bank = Some(Arc::clone(bank));
        true
    }

    #[cfg(target_os = "linux")]
    pub(super) fn gateway_fact(
        &self,
        scope: ScopeId,
        ip: IpAddr,
        now: Instant,
    ) -> Option<(DomainRouting, Instant)> {
        let key = ProjectionIp::new(scope, ip);
        let bitmap = *self.desired.get(&key)?;
        self.gateway_expiry(key, bitmap, now)
            .map(|until| (bitmap, until))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn gateway_expiry(
        &self,
        key: ProjectionIp,
        bitmap: DomainRouting,
        now: Instant,
    ) -> Option<Instant> {
        let owners = self.reverse.get(&key)?;
        let [(shared, count)] = owners.contributions.as_slice() else {
            return None;
        };
        if !(1..=32).contains(&owners.members.len())
            || *count as usize != owners.members.len()
            || *shared != bitmap
        {
            return None;
        }
        let until = self.fact_expiry(key.scope, owners)?;
        (now < until).then_some(until)
    }

    fn fact_expiry(&self, scope: u64, owners: &IpOwners) -> Option<Instant> {
        owners
            .members
            .iter()
            .map(|(domain, family)| {
                self.owners[*family]
                    .get(&scope)
                    .and_then(|owners| owners.get(domain))
                    .map(|owner| owner.expires_at)
            })
            .min()
            .flatten()
    }

    pub(super) fn fact_is_current(&mut self, stamp: super::FactStamp, now: Instant) -> bool {
        if self.try_expire(now).is_err() {
            return false;
        }
        stamp.revision != u64::MAX
            && self.packet_fact_destination(stamp.scope) == Some(stamp.scope)
            && self
                .packet_scopes
                .entries
                .iter()
                .any(|entry| entry.scope == stamp.scope && entry.revision == stamp.revision)
            && stamp.is_unexpired_at(now)
    }

    #[cfg(test)]
    pub(super) fn set_packet_fact_revision_for_test(&mut self, scope: ScopeId, revision: u64) {
        self.packet_scopes
            .entries
            .iter_mut()
            .find(|entry| entry.scope == scope)
            .expect("registered test scope")
            .revision = revision;
    }

    pub(super) fn update_snapshot(&mut self, snapshot: &Arc<RoutingProjectionSnapshot>) -> bool {
        if snapshot.generation() <= self.snapshot.generation() {
            return snapshot.generation() == self.snapshot.generation();
        }
        #[cfg(target_os = "linux")]
        debug_assert!(
            self.gateway_bank().is_none(),
            "gateway authority must be withdrawn before rebuilding"
        );
        self.snapshot = Arc::clone(snapshot);
        self.rebuild_all();
        true
    }

    pub(super) fn observe_cache_hit(
        &mut self,
        scope: ScopeId,
        mut observation: ProjectionObservation<'_>,
        now: Instant,
    ) -> u64 {
        if let ProjectionObservation::Positive {
            domain,
            family,
            ips,
            ref mut expires_at,
            source: ProjectionSource::CacheEntry(revision),
        } = observation
            && *expires_at > now
            && let Some(owner) = self.owners[family as usize]
                .get(&scope.as_u64())
                .and_then(|owners| owners.get(domain))
            && owner.cache_revision == Some(revision)
            && owner.expires_at != *expires_at
            && same_address_set(owner.ips.iter(), ips)
        {
            // An exact fresh hit can refresh recency, but it cannot move the entry's original deadline.
            *expires_at = owner.expires_at;
        }
        self.observe(scope, observation, now)
    }

    pub(super) fn observe(
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
                source,
            } => {
                if expires_at > now {
                    self.replace(
                        scope,
                        family as usize,
                        domain,
                        ips,
                        expires_at,
                        source.cache_revision(),
                    )
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
                (scope != ScopeId::HOST.as_u64() || owner.ips.len() == ips.len())
                    && same_address_set(owner.ips.iter(), ips)
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
        cache_revision: Option<u64>,
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
                self.packet_scopes.withdraw(scope);
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
            owner.cache_revision = cache_revision;
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
        self.packet_scopes.withdraw(scope);
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
            owner.cache_revision = cache_revision;
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
                    cache_revision,
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
        self.packet_scopes.withdraw(scope);
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
                    self.packet_scopes.withdraw(victim.scope);
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
        for entry in &mut self.packet_scopes.entries {
            PacketScopes::advance_revision(entry);
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
            owner.cache_revision = None;
            owner.bitmap = self.snapshot.bitmap_for(domain);
        }
        for (scope, owners) in v6.iter_mut() {
            for (domain, owner) in owners {
                owner.cache_revision = None;
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
        if self
            .expiry_deadlines
            .peek()
            .is_some_and(|entry| entry.0.at <= now)
        {
            self.expire_inner(now);
            Ok(())
        } else {
            self.compact_owner_heaps_if_needed();
            Ok(())
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
    // Answers are usually tiny; a large one sorts once instead of comparing quadratically.
    const SMALL_SET: usize = 16;
    if known.len() > ips.len() {
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
    sorted.dedup();
    sorted.iter().eq(known)
}
