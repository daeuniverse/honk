use super::*;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};

#[derive(Clone)]
pub(crate) struct PacketRealm(Arc<RealmOwners>);

impl fmt::Debug for PacketRealm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PacketRealm").field(&self.0.owners).finish()
    }
}

struct RealmOwners {
    owners: Box<[PacketScope]>,
    placement: RandomState,
    affinity: Option<Arc<RealmResources>>,
    _memory: MemoryReservation,
}

pub(crate) struct PacketRealmPlan {
    pub(crate) realm: io::Result<PacketRealm>,
    pub(crate) owners: Vec<PacketOwner>,
}

impl From<(PacketRealm, Vec<PacketOwner>)> for PacketRealmPlan {
    fn from((realm, owners): (PacketRealm, Vec<PacketOwner>)) -> Self {
        Self {
            realm: Ok(realm),
            owners,
        }
    }
}

impl From<(PacketScope, PacketOwner)> for PacketRealmPlan {
    fn from((scope, owner): (PacketScope, PacketOwner)) -> Self {
        Self {
            realm: PacketRealm::singleton(scope),
            owners: vec![owner],
        }
    }
}

impl PacketRealm {
    pub(crate) fn install_admission_fence(
        &self,
        admission: Arc<std::sync::atomic::AtomicBool>,
    ) -> io::Result<()> {
        for scope in self.owners() {
            let mut inner = scope.0.inner.lock();
            if inner.capture_admission.is_some()
                || !inner.stack.as_ref().is_some_and(Stack::is_quiescent)
            {
                return Err(invalid(
                    "capture admission fence requires an unstarted realm",
                ));
            }
            inner.capture_admission = Some(Arc::clone(&admission));
        }
        Ok(())
    }

    pub(crate) fn singleton(scope: PacketScope) -> io::Result<Self> {
        if scope.worker() != 0 || scope.0.workers != 1 {
            return Err(invalid(
                "a sharded scope requires its complete original realm",
            ));
        }
        Self::from_owners(vec![scope], false)
    }

    fn from_owners(owners: Vec<PacketScope>, queue_affine: bool) -> io::Result<Self> {
        let bytes = size_of::<RealmOwners>()
            + 2 * size_of::<usize>()
            + owners.len() * size_of::<PacketScope>();
        let memory = owners[0].0.budget.reserve(bytes).ok_or_else(capacity)?;
        Ok(Self(Arc::new(RealmOwners {
            affinity: if queue_affine {
                owners[0].0.inner.lock().resources.clone()
            } else {
                None
            },
            owners: owners.into_boxed_slice(),
            placement: RandomState::new(),
            _memory: memory,
        })))
    }

    pub(crate) fn scope(&self) -> ScopeId {
        self.0.owners[0].scope()
    }
    pub(crate) fn owners(&self) -> &[PacketScope] {
        &self.0.owners
    }
    pub(crate) fn owner(&self, worker: usize) -> Option<&PacketScope> {
        self.0.owners.get(worker)
    }

    fn worker(&self, key: impl Hash) -> usize {
        let mut hash = self.0.placement.build_hasher();
        self.scope().hash(&mut hash);
        key.hash(&mut hash);
        hash.finish() as usize % self.0.owners.len()
    }

    pub(crate) fn worker_for_tcp(&self, client: SocketAddr, destination: SocketAddr) -> usize {
        self.worker((
            SocketAddr::new(client.ip().to_canonical(), client.port()),
            SocketAddr::new(destination.ip().to_canonical(), destination.port()),
        ))
    }

    pub(crate) fn worker_for_udp(&self, client: IpAddr) -> usize {
        self.worker(client.to_canonical())
    }

    pub(crate) fn queue_affine(&self) -> bool {
        self.0.affinity.is_some()
    }

    pub(crate) fn tcp_dispatch(
        &self,
        local: usize,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<(usize, Option<TcpClaim>)> {
        let Some(resources) = &self.0.affinity else {
            return Ok((self.worker_for_tcp(source, destination), None));
        };
        let tuple = (source, destination);
        let mut state = resources.half_open.lock();
        let index = state
            .claims
            .iter()
            .position(|cell| cell.as_ref().is_some_and(|entry| entry.tuple == tuple))
            .or_else(|| state.claims.iter().position(Option::is_none))
            .ok_or_else(capacity)?;
        let entry = state.claims[index].get_or_insert(ClaimEntry {
            tuple,
            preferred: local,
            owner: None,
            users: 0,
        });
        entry.users += 1;
        let claim = TcpClaim {
            resources: Arc::clone(resources),
            index,
        };
        if let Some(owner) = entry.owner {
            return Ok((owner, Some(claim)));
        }
        let preferred = entry.preferred;
        drop(state);

        // No shard lock may nest under half_open: receive takes them in the other order.
        // Until publication, contenders may scan independently but cannot enter a Stack.
        let owner = if self.owners()[preferred].retains_tcp(source, destination)
            || !self.owners()[1 - preferred].retains_tcp(source, destination)
        {
            preferred
        } else {
            1 - preferred
        };
        let mut state = resources.half_open.lock();
        let entry = state.claims[index].as_mut().expect("live dispatch claim");
        Ok((*entry.owner.get_or_insert(owner), Some(claim)))
    }

    pub(crate) fn datagram_sender(&self, source: SocketAddr) -> DatagramSender {
        DatagramSender {
            scope: self.0.owners[0].clone(),
            source,
            packet_source: None,
            realm: Some(self.clone()),
        }
    }
}

pub(super) struct RealmResources {
    half_open: Mutex<HalfOpen>,
    pub(super) icmp: Mutex<(honk_netstack::IcmpState, Instant)>,
    pub(super) udp_pending: Arc<MemoryBudget>,
    _memory: MemoryReservation,
}

struct HalfOpen {
    total: usize,
    sources: Box<[Option<(IpAddr, usize)>]>,
    claims: Box<[Option<ClaimEntry>]>,
}

struct ClaimEntry {
    tuple: (SocketAddr, SocketAddr),
    preferred: usize,
    owner: Option<usize>,
    users: usize,
}

pub(crate) struct TcpClaim {
    resources: Arc<RealmResources>,
    index: usize,
}

impl Drop for TcpClaim {
    fn drop(&mut self) {
        let mut state = self.resources.half_open.lock();
        let cell = &mut state.claims[self.index];
        let entry = cell.as_mut().expect("live dispatch claim");
        entry.users -= 1;
        if entry.users == 0 {
            *cell = None;
        }
    }
}

pub(super) struct HalfOpenHold {
    resources: Arc<RealmResources>,
    source: IpAddr,
}

impl RealmResources {
    fn new(budget: &Arc<MemoryBudget>, now: Instant, claims: usize) -> io::Result<Arc<Self>> {
        let limits = honk_netstack::IcmpLimits::default();
        let bytes = honk_netstack::IcmpState::overhead_bound(limits)
            .and_then(|n| {
                n.checked_add(
                    size_of::<Self>() + size_of::<MemoryBudget>() + 4 * size_of::<usize>(),
                )
            })
            .and_then(|n| n.checked_add(1024 * size_of::<Option<(IpAddr, usize)>>()))
            .and_then(|n| n.checked_add(claims * size_of::<Option<ClaimEntry>>()))
            .ok_or_else(capacity)?;
        let memory = budget.reserve(bytes).ok_or_else(capacity)?;
        Ok(Arc::new(Self {
            half_open: Mutex::new(HalfOpen {
                total: 0,
                sources: (0..1024).map(|_| None).collect(),
                claims: (0..claims).map(|_| None).collect(),
            }),
            icmp: Mutex::new((honk_netstack::IcmpState::new(limits), now)),
            udp_pending: MemoryBudget::new(512 * 1024),
            _memory: memory,
        }))
    }

    pub(super) fn reserve(self: &Arc<Self>, source: IpAddr) -> Option<HalfOpenHold> {
        let source = source.to_canonical();
        let mut state = self.half_open.lock();
        if state.total == 1024 {
            return None;
        }
        let index = state
            .sources
            .iter()
            .position(|entry| entry.is_some_and(|(ip, _)| ip == source))
            .or_else(|| state.sources.iter().position(Option::is_none))?;
        let entry = state.sources[index].get_or_insert((source, 0));
        if entry.1 == 128 {
            return None;
        }
        entry.1 += 1;
        state.total += 1;
        Some(HalfOpenHold {
            resources: Arc::clone(self),
            source,
        })
    }
}

impl Drop for HalfOpenHold {
    fn drop(&mut self) {
        let mut state = self.resources.half_open.lock();
        let entry = state
            .sources
            .iter_mut()
            .find(|entry| entry.is_some_and(|(ip, _)| ip == self.source))
            .expect("original half-open grant");
        let (_, count) = entry.as_mut().expect("retained half-open source");
        *count -= 1;
        if *count == 0 {
            *entry = None;
        }
        state.total -= 1;
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn capture_realm(
    mtu: u32,
    realms: usize,
    bulk_frames: usize,
    workers: usize,
    members: usize,
    budget: &Arc<MemoryBudget>,
) -> anyhow::Result<(PacketRealm, Vec<PacketOwner>)> {
    capture_realm_with_output(
        mtu,
        realms,
        bulk_frames,
        workers,
        usize::try_from(mtu.max(1280))?,
        TxCaps::NONE,
        members,
        budget,
    )
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn capture_realm_with_output(
    mtu: u32,
    realms: usize,
    bulk_frames: usize,
    workers: usize,
    output_capacity: usize,
    caps: TxCaps,
    members: usize,
    budget: &Arc<MemoryBudget>,
) -> anyhow::Result<(PacketRealm, Vec<PacketOwner>)> {
    let (scopes, owners) = capture_partition(
        mtu,
        realms,
        bulk_frames,
        workers,
        output_capacity,
        caps,
        budget,
        members,
    )?;
    Ok((
        PacketRealm::from_owners(scopes, workers == 2 && members == 1)?,
        owners,
    ))
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub(super) fn capture_partition(
    mtu: u32,
    realms: usize,
    bulk_frames: usize,
    workers: usize,
    output_capacity: usize,
    caps: TxCaps,
    budget: &Arc<MemoryBudget>,
    members: usize,
) -> anyhow::Result<(Vec<PacketScope>, Vec<PacketOwner>)> {
    anyhow::ensure!(
        bulk_frames >= workers,
        "each capture owner requires bulk progress credit"
    );
    anyhow::ensure!(
        (1..=64).contains(&realms) && (1..=2).contains(&workers),
        "invalid capture realm partition"
    );
    let scope = ScopeId::allocate().ok_or_else(|| invalid("scope identities exhausted"))?;
    let now = Instant::now();
    let physical = members != 0;
    let resources = if physical {
        // Both RX callbacks can hold a claim in addition to all in-flight handoff cells.
        let claims = if workers == 2 && members == 1 {
            crate::xdp::worker::CELLS + workers
        } else {
            0
        };
        Some(RealmResources::new(budget, now, claims)?)
    } else {
        None
    };
    let partition =
        |total: usize, worker: usize| total / workers + usize::from(worker < total % workers);
    let slots = (4096 / realms).min(1024);
    let mut scopes = Vec::with_capacity(workers);
    let mut owners = Vec::with_capacity(workers);
    for worker in 0..workers {
        let mut cfg = Config::new(rand::random());
        cfg.mode = Mode::Transparent {
            exclude: Default::default(),
        };
        cfg.mtu = u16::try_from(mtu)?;
        cfg.max_flows = partition(slots, worker) as u32;
        cfg.memory_limit = partition(CAPTURE_MEMORY / 2 / realms, worker);
        let (owner_scope, owner) = PacketScope::new_partition(
            cfg,
            Arc::clone(budget),
            RuntimeLimits {
                max_slots: partition(slots, worker),
                control_frames: partition(CAPTURE_CONTROL_FRAMES, worker),
                bulk_frames: partition(bulk_frames, worker),
                max_waiters: partition(256, worker),
            },
            now,
            caps,
            output_capacity,
            scope,
            worker,
            workers,
            resources.clone(),
            physical,
        )?;
        scopes.push(owner_scope);
        owners.push(owner);
    }
    Ok((scopes, owners))
}

#[cfg(target_os = "linux")]
impl PacketRealm {
    /// Try the wider window while the physical capture fence is still closed.
    pub(crate) fn widen_startup_output(&self, base_bulk_frames: usize) -> bool {
        if !self.queue_affine() || base_bulk_frames != CAPTURE_WIDE_BULK_FRAMES {
            return false;
        }
        let [first, second] = self.owners() else {
            return false;
        };
        let Some(first_window) = OutputWindowGrowth::reserve(first) else {
            return false;
        };
        let Some(second_window) = OutputWindowGrowth::reserve(second) else {
            return false;
        };
        let first_frames = first_window.layout.allocate(first_window.retained_frames);
        let second_frames = second_window.layout.allocate(second_window.retained_frames);
        first_window.install(first, first_frames);
        second_window.install(second, second_frames);
        true
    }
}

#[cfg(target_os = "linux")]
struct OutputWindowGrowth {
    layout: ScopeFrameLayout,
    retained_frames: usize,
    ledger: FrameLedger<Option<FlowId>>,
    growth: MemoryReservation,
    overlap: MemoryReservation,
}

#[cfg(target_os = "linux")]
impl OutputWindowGrowth {
    fn reserve(scope: &PacketScope) -> Option<Self> {
        let (limits, frame_size, retained_frames, original_bytes) = {
            let inner = scope.0.inner.lock();
            let ledger = inner.ledger.drain_state();
            if inner
                .capture_admission
                .as_ref()
                .is_none_or(|gate| gate.load(Ordering::Acquire))
                || inner.closing
                || !inner.stack.as_ref().is_some_and(Stack::is_quiescent)
                || inner.queued != 0
                || inner.slots.iter().any(Option::is_some)
                || inner.peer_end != 0
                || !inner.source_work.is_empty()
                || ledger.control_free != CAPTURE_CONTROL_FRAMES / 2
                || ledger.bulk_free != CAPTURE_WIDE_BULK_FRAMES / 2
                || !ledger.is_drained()
            {
                return None;
            }
            (
                RuntimeLimits {
                    max_slots: inner.half_open.len(),
                    control_frames: CAPTURE_CONTROL_FRAMES,
                    bulk_frames: CAPTURE_WIDE_BULK_FRAMES,
                    max_waiters: inner.waiters.len(),
                },
                inner.frame_size,
                inner.frames.len(),
                inner._storage.bytes(),
            )
        };
        let layout = ScopeFrameLayout::new(limits, frame_size, scope.worker(), 2, true).ok()?;
        let old_frame_bytes = retained_frames * frame_size;
        let old_metadata_bytes = original_bytes - old_frame_bytes;
        let growth_bytes = layout.storage_bytes + layout.metadata_bytes - original_bytes;
        let budget = &scope.0.budget;
        // The original CPU byte boxes move to the replacement. At the allocation peak
        // both ledgers and the old and new arrays coexist.
        let growth = budget.reserve(growth_bytes)?;
        let overlap = budget.reserve(old_metadata_bytes)?;
        let ledger = FrameLedger::new(layout.config, budget).ok()?;
        Some(Self {
            layout,
            retained_frames,
            ledger,
            growth,
            overlap,
        })
    }

    fn install(self, scope: &PacketScope, frames: ScopeFrames) {
        let mut ledger = self.ledger;
        let (old_frames, old_ledger) = {
            let mut inner = scope.0.inner.lock();
            // The coordinator alone opens capture. Shutdown can still finish this empty scope.
            if inner.finished {
                ledger.close();
            }
            let old_frames = frames.exchange(&mut inner);
            let old_ledger = std::mem::replace(&mut inner.ledger, ledger);
            inner._storage.absorb(self.growth);
            (old_frames, old_ledger)
        };
        drop((old_frames, old_ledger, self.overlap));
    }
}
