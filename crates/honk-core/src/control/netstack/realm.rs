use super::*;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};

#[derive(Clone, Debug)]
pub(crate) struct PacketRealm(Arc<RealmOwners>);

#[derive(Debug)]
struct RealmOwners {
    owners: Box<[PacketScope]>,
    placement: RandomState,
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
        Self::from_owners(vec![scope])
    }

    fn from_owners(owners: Vec<PacketScope>) -> io::Result<Self> {
        let bytes = size_of::<RealmOwners>()
            + 2 * size_of::<usize>()
            + owners.len() * size_of::<PacketScope>();
        let memory = owners[0].0.budget.reserve(bytes).ok_or_else(capacity)?;
        Ok(Self(Arc::new(RealmOwners {
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
}

pub(super) struct HalfOpenHold {
    resources: Arc<RealmResources>,
    source: IpAddr,
}

impl RealmResources {
    fn new(budget: &Arc<MemoryBudget>, now: Instant) -> io::Result<Arc<Self>> {
        let limits = honk_netstack::IcmpLimits::default();
        let bytes = honk_netstack::IcmpState::overhead_bound(limits)
            .and_then(|n| {
                n.checked_add(
                    size_of::<Self>() + size_of::<MemoryBudget>() + 4 * size_of::<usize>(),
                )
            })
            .and_then(|n| n.checked_add(1024 * size_of::<Option<(IpAddr, usize)>>()))
            .ok_or_else(capacity)?;
        let memory = budget.reserve(bytes).ok_or_else(capacity)?;
        Ok(Arc::new(Self {
            half_open: Mutex::new(HalfOpen {
                total: 0,
                sources: (0..1024).map(|_| None).collect(),
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
    budget: &Arc<MemoryBudget>,
) -> anyhow::Result<(PacketRealm, Vec<PacketOwner>)> {
    capture_realm_with_output(
        mtu,
        realms,
        bulk_frames,
        workers,
        usize::try_from(mtu.max(1280))?,
        TxCaps::NONE,
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
        true,
    )?;
    Ok((PacketRealm::from_owners(scopes)?, owners))
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
    physical: bool,
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
    let resources = if physical {
        Some(RealmResources::new(budget, now)?)
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
                control_frames: partition(32, worker),
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
