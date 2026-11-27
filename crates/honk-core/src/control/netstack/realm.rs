use super::*;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};

mod ownership;
use ownership::OwnershipDir;
pub(crate) use ownership::TcpClaim;

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
            affinity: if queue_affine || owners.len() == 1 {
                owners[0]
                    .0
                    .inner
                    .lock()
                    .resources
                    .clone()
                    .filter(|r| queue_affine || r.tracks_tcp())
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
        self.worker(ownership::canonical(client, destination))
    }

    pub(crate) fn worker_for_udp(&self, client: IpAddr) -> usize {
        self.worker(client.to_canonical())
    }

    pub(crate) fn queue_affine(&self) -> bool {
        self.0.owners.len() == 2 && self.0.affinity.is_some()
    }

    pub(crate) fn datagram_sender(&self, source: SocketAddr) -> DatagramSender {
        DatagramSender {
            scope: self.0.owners[0].clone(),
            binding: self.0.owners[0].binding(),
            source,
            packet_source: None,
            realm: Some(self.clone()),
        }
    }
}

pub(super) struct RealmResources {
    half_open: Mutex<HalfOpen>,
    directory: Option<OwnershipDir>,
    pub(super) icmp: Mutex<(honk_netstack::IcmpState, Instant)>,
    pub(super) udp_pending: Arc<MemoryBudget>,
    _memory: MemoryReservation,
}

struct HalfOpen {
    total: usize,
    sources: Box<[Option<(IpAddr, usize)>]>,
    claims: Box<[Option<SharedClaim>]>,
}

struct SharedClaim {
    tuple: (SocketAddr, SocketAddr),
    preferred: usize,
    worker: Option<usize>,
    users: usize,
}

pub(super) struct HalfOpenHold {
    resources: Arc<RealmResources>,
    source: IpAddr,
}

impl RealmResources {
    fn new(
        budget: &Arc<MemoryBudget>,
        now: Instant,
        directory_slots: usize,
        workers: usize,
        shared_claims: usize,
    ) -> io::Result<Arc<Self>> {
        let limits = honk_netstack::IcmpLimits::default();
        let bytes = honk_netstack::IcmpState::overhead_bound(limits)
            .and_then(|n| {
                n.checked_add(
                    size_of::<Self>() + size_of::<MemoryBudget>() + 4 * size_of::<usize>(),
                )
            })
            .and_then(|n| n.checked_add(1024 * size_of::<Option<(IpAddr, usize)>>()))
            .and_then(|n| n.checked_add(OwnershipDir::bytes(directory_slots)?))
            .and_then(|n| {
                n.checked_add(shared_claims.checked_mul(size_of::<Option<SharedClaim>>())?)
            })
            .ok_or_else(capacity)?;
        let memory = budget.reserve(bytes).ok_or_else(capacity)?;
        Ok(Arc::new(Self {
            half_open: Mutex::new(HalfOpen {
                total: 0,
                sources: (0..1024).map(|_| None).collect(),
                claims: (0..shared_claims).map(|_| None).collect(),
            }),
            directory: (directory_slots != 0).then(|| OwnershipDir::new(directory_slots, workers)),
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

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn capture_realm(
    mtu: u32,
    realms: usize,
    bulk_frames: usize,
    workers: usize,
    members: usize,
    budget: &Arc<MemoryBudget>,
) -> anyhow::Result<(PacketRealm, Vec<PacketOwner>)> {
    capture_realm_for_workers(
        mtu,
        realms,
        bulk_frames,
        workers,
        members,
        members == 1,
        budget,
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn capture_realm_for_workers(
    mtu: u32,
    realms: usize,
    bulk_frames: usize,
    workers: usize,
    members: usize,
    local: bool,
    budget: &Arc<MemoryBudget>,
) -> anyhow::Result<(PacketRealm, Vec<PacketOwner>)> {
    let (scopes, owners) = capture_partition(
        mtu,
        realms,
        bulk_frames,
        workers,
        usize::try_from(mtu.max(1280))?,
        TxCaps::NONE,
        budget,
        members,
        local,
    )?;
    Ok((
        PacketRealm::from_owners(scopes, workers == 2 && members == 1)?,
        owners,
    ))
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn capture_tun_realm(
    mtu: u32,
    queues: usize,
    caps: TxCaps,
    budget: &Arc<MemoryBudget>,
) -> anyhow::Result<(PacketRealm, Vec<PacketOwner>)> {
    let (scopes, owners) = capture_partition(
        mtu,
        1,
        128,
        queues,
        u16::MAX as usize,
        caps,
        budget,
        0,
        false,
    )?;
    Ok((PacketRealm::from_owners(scopes, false)?, owners))
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
    local: bool,
) -> anyhow::Result<(Vec<PacketScope>, Vec<PacketOwner>)> {
    let physical = members != 0;
    let max_workers = if physical {
        2
    } else {
        honk_netstack::MAX_ACCOUNTED_SHARDS
    };
    anyhow::ensure!(
        !local || members == 1,
        "local packet owners require one physical member"
    );
    anyhow::ensure!(
        bulk_frames >= workers,
        "each capture owner requires bulk progress credit"
    );
    anyhow::ensure!(
        (1..=64).contains(&realms) && (1..=max_workers).contains(&workers),
        "invalid capture realm partition"
    );
    let scope = ScopeId::allocate().ok_or_else(|| invalid("scope identities exhausted"))?;
    let now = Instant::now();
    let slots = (4096 / realms).min(1024);
    let shared_realm = workers > 1 || physical;
    let resources = if shared_realm {
        let directory_slots = if local {
            // Exported generations can overlap their replacements and in-flight ingress claims.
            let per_worker_outputs = bulk_frames
                .checked_add(CAPTURE_CONTROL_FRAMES)
                .ok_or_else(capacity)?;
            per_worker_outputs
                .checked_mul(workers)
                .and_then(|n| n.checked_add(slots))
                .and_then(|n| {
                    n.checked_add(if workers == 2 {
                        crate::xdp::worker::CELLS + workers
                    } else {
                        0
                    })
                })
                .and_then(|n| n.checked_next_multiple_of(workers))
                .ok_or_else(capacity)?
        } else {
            0
        };
        let shared_claims = if !local && members == 1 && workers == 2 {
            crate::xdp::worker::CELLS + workers
        } else {
            0
        };
        Some(RealmResources::new(
            budget,
            now,
            directory_slots,
            workers,
            shared_claims,
        )?)
    } else {
        None
    };
    let partition =
        |total: usize, worker: usize| total / workers + usize::from(worker < total % workers);
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
            None,
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
        let Some(first_window) = OutputWindowGrowth::reserve(first, &first.0.inner.lock()) else {
            return false;
        };
        let Some(second_window) = OutputWindowGrowth::reserve(second, &second.0.inner.lock())
        else {
            return false;
        };
        let first_frames = first_window.layout.allocate(first_window.retained_frames);
        let second_frames = second_window.layout.allocate(second_window.retained_frames);
        first_window.install(&mut first.0.inner.lock(), first_frames);
        second_window.install(&mut second.0.inner.lock(), second_frames);
        true
    }
}

#[cfg(target_os = "linux")]
impl PacketDriver {
    pub(crate) fn widen_local_pair(
        first: &mut Self,
        second: &mut Self,
        base_bulk_frames: usize,
    ) -> bool {
        if base_bulk_frames != CAPTURE_WIDE_BULK_FRAMES
            || first.scope.scope() != second.scope.scope()
            || first.scope.0.workers != 2
            || second.scope.0.workers != 2
            || first.scope.worker() != 0
            || second.scope.worker() != 1
        {
            return false;
        }
        let (Some(one), Some(two)) = (first.local.as_deref_mut(), second.local.as_deref_mut())
        else {
            return false;
        };
        if !one
            .inner
            .resources
            .as_ref()
            .is_some_and(|resources| resources.tracks_tcp())
        {
            return false;
        }
        // The parked scopes own the externally held SourceWork table. Keep both empty
        // tables and shutdown fenced until both replacement sets have been installed.
        let mut parked_one = first.scope.0.inner.lock();
        let mut parked_two = second.scope.0.inner.lock();
        if parked_one.closing
            || parked_two.closing
            || !parked_one.source_work.is_empty()
            || !parked_two.source_work.is_empty()
        {
            return false;
        }
        let prepare = |scope: &PacketScope, owner: &local::LocalOwner| {
            let window = OutputWindowGrowth::reserve(scope, &owner.inner)?;
            let layout = &window.layout;
            let metadata = owner.prepare_wide(
                scope,
                layout.aliases,
                layout.config.tx_capacity,
                layout.peer_capacity,
            )?;
            Some((window, metadata))
        };
        let Some(first_growth) = prepare(&first.scope, one) else {
            return false;
        };
        let Some(second_growth) = prepare(&second.scope, two) else {
            return false;
        };
        for ((window, metadata), owner, scope, parked) in [
            (first_growth, one, &first.scope, &mut *parked_one),
            (second_growth, two, &second.scope, &mut *parked_two),
        ] {
            let frames = window.layout.allocate(window.retained_frames);
            std::mem::swap(&mut owner.inner.source_work, &mut parked.source_work);
            window.install(&mut owner.inner, frames);
            std::mem::swap(&mut owner.inner.source_work, &mut parked.source_work);
            metadata.install(owner, scope);
        }
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
    fn reserve(scope: &PacketScope, inner: &Inner) -> Option<Self> {
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
        let limits = RuntimeLimits {
            max_slots: inner.half_open.len(),
            control_frames: CAPTURE_CONTROL_FRAMES,
            bulk_frames: CAPTURE_WIDE_BULK_FRAMES,
            max_waiters: inner.waiters.len(),
        };
        let frame_size = inner.frame_size;
        let retained_frames = inner.frames.len();
        let original_bytes = inner._storage.bytes();
        let layout = ScopeFrameLayout::new(limits, frame_size, scope.worker(), 2, true).ok()?;
        let old_frame_bytes = retained_frames * frame_size;
        let old_metadata_bytes = original_bytes - old_frame_bytes;
        let growth_bytes = layout.storage_bytes + layout.metadata_bytes - original_bytes;
        let budget = &scope.0.budget;
        // The original CPU byte boxes move to the replacement. At the allocation peak
        // both ledgers and the old and new arrays coexist.
        let growth = scope.reserve_memory(growth_bytes)?;
        let overlap = scope.reserve_memory(old_metadata_bytes)?;
        let ledger = FrameLedger::new(layout.config, budget)
            .or_else(|error| {
                if error == honk_datapath::buffer::LedgerError::BudgetExhausted
                    && let Some(local) = scope.0.local.get()
                {
                    local.drain_pool();
                    return FrameLedger::new(layout.config, budget);
                }
                Err(error)
            })
            .ok()?;
        Some(Self {
            layout,
            retained_frames,
            ledger,
            growth,
            overlap,
        })
    }

    fn install(self, inner: &mut Inner, frames: ScopeFrames) {
        let mut ledger = self.ledger;
        // Shutdown may finish the shared scope before the coordinator opens capture.
        if inner.finished {
            ledger.close();
        }
        let old_frames = frames.exchange(inner);
        let old_ledger = std::mem::replace(&mut inner.ledger, ledger);
        inner._storage.absorb(self.growth);
        drop((old_frames, old_ledger, self.overlap));
    }
}
