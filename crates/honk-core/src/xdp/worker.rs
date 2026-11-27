use super::*;
use crate::control::netstack::{RealmRxBatch, TcpClaim};
mod adaptive;
pub(crate) mod direct;
pub(crate) mod epoll;
mod runtime;
#[cfg(test)]
mod startup_tests;
#[cfg(test)]
mod tests;
use parking_lot::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicUsize;
use tokio::sync::mpsc;

pub(crate) const CELLS: usize = 64;
pub(super) const THREAD_STACK: usize = 2 << 20;
const DESTINATION: usize = 32;

#[derive(Debug)]
struct PeerSlot {
    address: IpAddr,
    scope: ScopeId,
    path: ReturnPath,
    generation: u64,
    last_seen: Instant,
    conflict: Option<Instant>,
}

impl PeerSlot {
    fn observe(
        &mut self,
        authority: &PeerAuthority,
        path: ReturnPath,
        now: Instant,
        can_relearn: bool,
        rst: bool,
        pending: bool,
    ) -> bool {
        let changed = self.conflict.is_some() || (!pending && !rst && self.path != path);
        if !self.path.same_identity(path) || self.conflict.is_some() {
            if rst || !can_relearn {
                return false;
            }
            if !self
                .conflict
                .is_some_and(|at| now.saturating_duration_since(at) >= PEER_CONFLICT_HOLD)
            {
                if self.conflict != Some(now) {
                    self.conflict = Some(now);
                    authority.invalidate();
                }
                return false;
            }
            self.conflict = None;
        }
        if !rst {
            if !pending {
                self.path = path;
            }
            self.last_seen = self.last_seen.max(now);
        }
        if changed {
            authority.invalidate();
        }
        true
    }
}

#[derive(Debug)]
pub(crate) struct PeerAuthority {
    slots: Mutex<Vec<PeerSlot>>,
    pins: Box<[AtomicUsize]>,
    _memory: MemoryReservation,
    admission: Arc<AtomicBool>,
    revision: std::sync::atomic::AtomicU64,
}

/// Repeating last_seen = max(last_seen, ingress_at) at the same timestamp is idempotent.
/// Observe the first checked packet immediately; batch end never writes a potentially older path.
pub(crate) struct PeerObservation<'a> {
    authority: &'a PeerAuthority,
    scope: ScopeId,
    slot: usize,
    generation: u64,
    path: ReturnPath,
    ingress_at: Instant,
    revision: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PeerPathChanged;

#[derive(Debug)]
pub(crate) struct PeerHold {
    authority: Arc<PeerAuthority>,
    slot: usize,
    generation: u64,
    address: IpAddr,
    path: ReturnPath,
}

impl PeerHold {
    pub(crate) fn address(&self) -> IpAddr {
        self.address
    }
    pub(crate) fn learned(&self) -> bool {
        self.slot != usize::MAX
    }
    pub(super) fn path(&self) -> Option<ReturnPath> {
        self.learned().then_some(self.path)
    }
    pub(crate) fn original_path(&self) -> ReturnPath {
        self.path
    }
    #[cfg(test)]
    pub(crate) fn for_test(address: IpAddr, path: ReturnPath) -> Self {
        Self::unlearned(
            PeerAuthority::isolated(Arc::new(AtomicBool::new(true))),
            address,
            path,
        )
    }
    fn unlearned(authority: Arc<PeerAuthority>, address: IpAddr, path: ReturnPath) -> Self {
        Self {
            authority,
            slot: usize::MAX,
            generation: 0,
            address,
            path,
        }
    }
}

impl Clone for PeerHold {
    fn clone(&self) -> Self {
        if !self.learned() {
            return Self::unlearned(Arc::clone(&self.authority), self.address, self.path);
        }
        // The existing hold prevents this slot from being recycled before the increment.
        self.authority
            .pin(self.slot, true)
            .expect("invalid peer pin count");
        Self {
            authority: Arc::clone(&self.authority),
            slot: self.slot,
            generation: self.generation,
            address: self.address,
            path: self.path,
        }
    }
}

impl Drop for PeerHold {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.authority.admission.store(false, Ordering::Release);
        }
        if !self.learned() {
            return;
        }
        self.authority.pins[self.slot]
            .try_update(Ordering::Release, Ordering::Relaxed, |n| n.checked_sub(1))
            .expect("peer hold underflow");
    }
}

impl PeerAuthority {
    const STORAGE: usize = size_of::<Self>()
        + 2 * size_of::<usize>()
        + PEERS * (size_of::<PeerSlot>() + size_of::<AtomicUsize>());

    pub(crate) fn new(
        admission: Arc<AtomicBool>,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Arc<Self>> {
        let memory = budget
            .reserve(Self::STORAGE)
            .ok_or_else(|| io::Error::other("XDP peer storage capacity"))?;
        Ok(Arc::new(Self {
            slots: Mutex::new(Vec::with_capacity(PEERS)),
            pins: (0..PEERS).map(|_| AtomicUsize::new(0)).collect(),
            _memory: memory,
            admission,
            revision: 0.into(),
        }))
    }

    #[cfg(test)]
    pub(crate) fn isolated(admission: Arc<AtomicBool>) -> Arc<Self> {
        Self::new(admission, &MemoryBudget::new(Self::STORAGE)).unwrap()
    }

    fn pin_count(&self, slot: usize) -> usize {
        self.pins[slot].load(Ordering::Acquire)
    }

    fn pin(&self, slot: usize, require_live: bool) -> Option<()> {
        self.pins[slot]
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                if require_live && n == 0 {
                    return None;
                }
                if n == usize::MAX - 1 {
                    self.revision.store(u64::MAX, Ordering::Release);
                }
                n.checked_add(1)
            })
            .ok()
            .map(|_| ())
    }

    fn invalidate(&self) {
        let _ = self
            .revision
            .try_update(Ordering::Release, Ordering::Relaxed, |n| n.checked_add(1));
    }

    #[cfg(test)]
    pub(crate) fn saturate_revision_for_test(&self) {
        let _slots = self.slots.lock();
        self.revision.store(u64::MAX, Ordering::Release);
    }

    pub(crate) fn retain(
        self: &Arc<Self>,
        scope: ScopeId,
        source: honk_netstack::ValidatedSource,
        path: ReturnPath,
        now: Instant,
        pending: bool,
    ) -> Option<PeerHold> {
        let address = source.src.ip();
        if address.is_unspecified() || address.is_multicast() || path.mac[0] & 1 != 0 {
            return None;
        }
        let rst = source
            .tcp_flags
            .is_some_and(|flags| flags & wire::tcp::RST != 0);
        let opens = source.protocol == wire::PROTO_UDP
            || source.tcp_flags.is_some_and(|flags| {
                flags & (wire::tcp::SYN | wire::tcp::ACK | wire::tcp::RST | wire::tcp::FIN)
                    == wire::tcp::SYN
            });
        let mut peers = self.slots.lock();
        let slot = if let Some(slot) = peers
            .iter()
            .position(|peer| peer.scope == scope && peer.address == address)
        {
            if !peers[slot].observe(
                self,
                path,
                now,
                opens && self.pin_count(slot) == 0,
                rst,
                pending,
            ) {
                return None;
            }
            slot
        } else {
            // Stray control cannot learn a reverse delivery identity.
            if !opens {
                return Some(PeerHold::unlearned(Arc::clone(self), address, path));
            }
            let slot = if peers.len() < PEERS {
                peers.len()
            } else {
                peers
                    .iter()
                    .enumerate()
                    .filter(|(slot, peer)| {
                        self.pin_count(*slot) == 0
                            && peer.conflict.is_none_or(|at| {
                                now.saturating_duration_since(at) >= PEER_CONFLICT_HOLD
                            })
                    })
                    .min_by_key(|(_, peer)| peer.last_seen)
                    .map(|(slot, _)| slot)?
            };
            let generation = if slot == peers.len() {
                1
            } else {
                peers[slot].generation.checked_add(1)?
            };
            let peer = PeerSlot {
                address,
                scope,
                path,
                generation,
                last_seen: now,
                conflict: None,
            };
            if slot == peers.len() {
                peers.push(peer);
            } else {
                peers[slot] = peer;
            }
            self.invalidate();
            slot
        };
        let peer = &peers[slot];
        self.pin(slot, false)?;
        Some(PeerHold {
            authority: Arc::clone(self),
            slot,
            generation: peer.generation,
            address,
            path: peer.path,
        })
    }

    /// A live realm hold pins this exact generation. Other workers can still change its path.
    #[inline]
    pub(crate) fn confirm_tcp<'a, const SHARDED: bool>(
        &'a self,
        held: &PeerHold,
        scope: ScopeId,
        source: honk_netstack::ValidatedSource,
        path: ReturnPath,
        now: Instant,
        checked: &mut Option<PeerObservation<'a>>,
    ) -> Result<bool, PeerPathChanged> {
        if !std::ptr::eq(self, held.authority.as_ref())
            || !held.learned()
            || held.address != source.src.ip()
            || held.path != path
            || source.protocol != wire::PROTO_TCP
            || !source.tcp_flags.is_some_and(|flags| {
                flags & (wire::tcp::SYN | wire::tcp::FIN | wire::tcp::RST | wire::tcp::ACK)
                    == wire::tcp::ACK
            })
        {
            return Ok(false);
        }
        if checked.as_ref().is_some_and(|previous| {
            std::ptr::eq(previous.authority, self)
                && previous.scope == scope
                && previous.slot == held.slot
                && previous.generation == held.generation
                && previous.path == path
                && previous.ingress_at == now
                && previous.revision != u64::MAX
                && previous.revision == self.revision.load(Ordering::Acquire)
        }) {
            return Ok(true);
        }
        let mut peers = self.slots.lock();
        let peer = &mut peers[held.slot];
        if peer.scope != scope || peer.generation != held.generation {
            return Ok(false);
        }
        let pins = self.pin_count(held.slot);
        if SHARDED {
            if peer.address != held.address
                || pins == 0
                || pins == usize::MAX
                || peer.conflict.is_some()
            {
                return Ok(false);
            }
            if peer.path != path {
                return Err(PeerPathChanged);
            }
            peer.last_seen = peer.last_seen.max(now);
        } else if !peer.observe(self, path, now, false, false, false) || pins == usize::MAX {
            return Ok(false);
        }
        *checked = Some(PeerObservation {
            authority: self,
            scope,
            slot: held.slot,
            generation: held.generation,
            path,
            ingress_at: now,
            revision: self.revision.load(Ordering::Relaxed),
        });
        Ok(true)
    }

    fn pin_fragment(
        self: &Arc<Self>,
        scope: ScopeId,
        address: IpAddr,
        path: ReturnPath,
    ) -> io::Result<Option<PeerHold>> {
        let peers = self.slots.lock();
        let Some(slot) = peers
            .iter()
            .position(|peer| peer.scope == scope && peer.address == address)
        else {
            return Ok(Some(PeerHold::unlearned(Arc::clone(self), address, path)));
        };
        let peer = &peers[slot];
        if !peer.path.same_identity(path) || peer.conflict.is_some() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        self.pin(slot, false)
            .ok_or_else(|| io::Error::other("peer hold exhausted"))?;
        Ok(Some(PeerHold {
            authority: Arc::clone(self),
            slot,
            generation: peer.generation,
            address,
            path: peer.path,
        }))
    }
}

struct CellPool {
    free: Mutex<Vec<(usize, Box<[u8]>)>>,
    _memory: MemoryReservation,
}

pub(super) struct Cell {
    pool: Arc<CellPool>,
    slot: usize,
    bytes: Option<Box<[u8]>>,
    length: usize,
    metadata: usize,
}

impl Cell {
    fn copy(&mut self, segments: &[&[u8]], metadata: &[u8]) -> io::Result<()> {
        let bytes = self.bytes.as_mut().expect("owned handoff storage");
        let length = segments
            .iter()
            .try_fold(metadata.len(), |sum, bytes| sum.checked_add(bytes.len()))
            .ok_or_else(|| io::Error::other("handoff extent overflow"))?;
        if length > bytes.len() {
            return Err(io::Error::other("handoff exceeds admitted MTU"));
        }
        bytes[..metadata.len()].copy_from_slice(metadata);
        let mut offset = metadata.len();
        for segment in segments {
            bytes[offset..offset + segment.len()].copy_from_slice(segment);
            offset += segment.len();
        }
        self.metadata = metadata.len();
        self.length = length;
        Ok(())
    }
    pub(super) fn packet(&self) -> &[u8] {
        &self.bytes.as_ref().unwrap()[self.metadata..self.length]
    }
}

impl Drop for Cell {
    fn drop(&mut self) {
        if let Some(bytes) = self.bytes.take() {
            self.pool.free.lock().push((self.slot, bytes));
        }
    }
}

impl CellPool {
    fn new(
        extent: usize,
        workers: u8,
        ports: usize,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Arc<Self>> {
        let bytes = extent
            .checked_mul(CELLS)
            .and_then(|bytes| {
                bytes.checked_add(
                    CELLS * (size_of::<Cell>() + size_of::<Envelope>() + 128)
                        + usize::from(workers)
                            * (THREAD_STACK + 256 * 1024 + size_of::<WorkerRuntime>())
                        + ports * 4096
                        + size_of::<Shared>()
                        + 65536,
                )
            })
            .ok_or_else(|| io::Error::other("worker storage overflow"))?;
        let memory = budget
            .reserve(bytes)
            .ok_or_else(|| io::Error::other("XDP worker storage capacity"))?;
        let mut free = Vec::new();
        free.try_reserve_exact(CELLS).map_err(io::Error::other)?;
        for slot in 0..CELLS {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(extent).map_err(io::Error::other)?;
            bytes.resize(extent, 0);
            free.push((slot, bytes.into_boxed_slice()));
        }

        Ok(Arc::new(Self {
            free: Mutex::new(free),
            _memory: memory,
        }))
    }
    fn take(self: &Arc<Self>) -> Option<Cell> {
        self.free.lock().pop().map(|(slot, bytes)| Cell {
            pool: Arc::clone(self),
            slot,
            bytes: Some(bytes),
            length: 0,
            metadata: 0,
        })
    }
}
pub(super) struct Placement {
    pub(super) realm_id: u32,
    pub(super) realm: crate::control::netstack::PacketRealm,
    pub(super) ingress: Ingress,
    pub(super) device: usize,
    pub(super) link: LogicalLink,
}

pub(super) struct Placements {
    pub(super) entries: Vec<Placement>,
    _memory: MemoryReservation,
}

impl Placements {
    pub(super) fn new(count: usize, budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let bytes = count
            .checked_mul(size_of::<Placement>())
            .and_then(|bytes| bytes.checked_add(size_of::<Self>() + 2 * size_of::<usize>()))
            .ok_or_else(|| io::Error::other("XDP placement storage overflow"))?;
        let memory = budget
            .reserve(bytes)
            .ok_or_else(|| io::Error::other("XDP placement storage capacity"))?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).map_err(io::Error::other)?;
        Ok(Self {
            entries,
            _memory: memory,
        })
    }
}

pub(super) enum Payload {
    Ingress,
    Endpoint {
        owner: PacketScope,
        check_output: bool,
        admission: Option<EndpointAdmission>,
    },
}

// Boxing packet bodies would allocate on the packet dispatch path.
#[allow(clippy::large_enum_variant)]
pub(super) enum PacketBody {
    Core(Packet),
    Reassembled(honk_netstack::OwnedPacket),
}
pub(super) struct Envelope {
    pub(super) ingress: Ingress,
    pub(super) scope: ScopeId,
    pub(super) path: ReturnPath,
    pub(super) ingress_at: Instant,
    pub(super) cell: Cell,
    pub(super) body: Option<PacketBody>,
    pub(super) peer: Option<PeerHold>,
    pub(super) l3_offset: usize,
    pub(super) l3_length: usize,
    pub(super) payload: Payload,
    _claim: Option<TcpClaim>,
}

#[derive(Clone, Copy, Default)]
enum Drain {
    #[default]
    Unarmed,
    Until(Instant),
    Revoked,
    Quiesced,
}

impl Drain {
    fn deadline(self) -> Option<Instant> {
        match self {
            Self::Until(deadline) => Some(deadline),
            _ => None,
        }
    }
}

#[derive(Default)]
struct State {
    ready: bool,
    queues_registered: bool,
    startup: Option<tokio::sync::oneshot::Receiver<Vec<Realm>>>,
    activated: bool,
    drain: Drain,
    stop: bool,
    exited: bool,
    failure: Option<anyhow::Error>,
}

struct RelayOwners {
    primary: RelayOwner,
    secondary: Option<RelayOwner>,
}

struct RelayOwner {
    handle: OnceLock<tokio::runtime::Handle>,
    fence: Arc<DirectRelayFence>,
    _runtime_memory: MemoryReservation,
}

impl RelayOwner {
    fn reserve(budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        Ok(Self {
            handle: OnceLock::new(),
            fence: DirectRelayFence::new(budget)?,
            _runtime_memory: budget
                .reserve(THREAD_STACK + 256 * 1024)
                .ok_or(io::ErrorKind::OutOfMemory)?,
        })
    }

    fn start(&self, name: &'static str) -> io::Result<tokio::runtime::Runtime> {
        // A legacy child must keep running while its capture thread blocks in epoll.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name(name)
            .thread_stack_size(THREAD_STACK)
            .enable_all()
            .build()?;
        self.handle
            .set(runtime.handle().clone())
            .expect("one relay runtime per owner");
        Ok(runtime)
    }
}

pub(super) struct Shared {
    pool: Arc<CellPool>,
    senders: [mpsc::Sender<Envelope>; 2],
    states: [Mutex<State>; 2],
    admission: Arc<AtomicBool>,
    relays: OnceLock<RelayOwners>,
    pub(super) auxiliary: OnceLock<super::aux_tasks::AuxTasks>,
    closing: AtomicBool,
    peers: Arc<PeerAuthority>,
    pub(super) workers: u8,
    pub(super) placements: OnceLock<Arc<Placements>>,
    wakers: [futures::task::AtomicWaker; 2],
    pub(super) diagnostics: OnceLock<Arc<Diagnostics>>,
    contexts: Mutex<[Option<Result<String, &'static str>>; 2]>,
    context_changed: [AtomicBool; 2],
    #[cfg(test)]
    secondary_test_control: OnceLock<Arc<polling::testing::Control>>,
    #[cfg(test)]
    close_before_secondary_drain: AtomicBool,
}

impl Shared {
    pub(super) fn new(
        workers: u8,
        extent: usize,
        ports: usize,
        budget: &Arc<MemoryBudget>,
        admission: Arc<AtomicBool>,
    ) -> io::Result<(Arc<Self>, [mpsc::Receiver<Envelope>; 2])> {
        let (send0, receive0) = mpsc::channel(DESTINATION);
        let (send1, receive1) = mpsc::channel(DESTINATION);
        Ok((
            Arc::new(Self {
                pool: CellPool::new(extent, workers, ports, budget)?,
                senders: [send0, send1],
                states: std::array::from_fn(|_| Mutex::new(State::default())),
                peers: PeerAuthority::new(Arc::clone(&admission), budget)?,
                admission,
                relays: OnceLock::new(),
                auxiliary: OnceLock::new(),
                closing: AtomicBool::new(false),
                workers,
                placements: OnceLock::new(),
                wakers: std::array::from_fn(|_| futures::task::AtomicWaker::new()),
                diagnostics: OnceLock::new(),
                contexts: Mutex::new([None, None]),
                context_changed: std::array::from_fn(|_| AtomicBool::new(true)),
                #[cfg(test)]
                secondary_test_control: OnceLock::new(),
                #[cfg(test)]
                close_before_secondary_drain: AtomicBool::new(false),
            }),
            [receive0, receive1],
        ))
    }

    #[cfg(test)]
    fn secondary_test_control(&self) -> &Arc<polling::testing::Control> {
        self.secondary_test_control
            .get()
            .expect("registered secondary polling participant")
    }

    // Reserve the complete set before handing any fence to a worker or publishing a scope.
    pub(super) fn prepare_relays(
        &self,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Option<tokio::runtime::Runtime>> {
        let reserve = || -> io::Result<RelayOwners> {
            let primary = RelayOwner::reserve(budget)?;
            let secondary = match self.workers {
                1 => None,
                2 => Some(RelayOwner::reserve(budget)?),
                _ => return Err(io::Error::other("invalid XDP relay owner count")),
            };
            Ok(RelayOwners { primary, secondary })
        };
        let owners = match reserve() {
            Ok(owners) => owners,
            Err(error) if error.kind() == io::ErrorKind::OutOfMemory => return Ok(None),
            Err(error) => return Err(error),
        };
        self.relays
            .set(owners)
            .map_err(|_| io::Error::other("XDP relay owners already reserved"))?;
        self.relays
            .get()
            .expect("reserved relay owners")
            .primary
            .start("honk-xdp-relay0")
            .map(Some)
    }

    fn start_secondary_relays(&self) -> io::Result<Option<tokio::runtime::Runtime>> {
        self.relays
            .get()
            .and_then(|relays| relays.secondary.as_ref())
            .map(|owner| owner.start("honk-xdp-relay1"))
            .transpose()
    }

    fn publish_relays(
        &self,
        realm: &PacketRealm,
        shutdown: &crate::control::ShutdownIntent,
    ) -> io::Result<()> {
        let Some(relays) = self.relays.get() else {
            return Ok(());
        };
        let owners = realm.owners();
        if owners.len() != usize::from(self.workers) {
            return Ok(());
        }
        let secondary = relays
            .secondary
            .as_ref()
            .map(|secondary| {
                secondary
                    .handle
                    .get()
                    .map(|handle| (handle, &secondary.fence))
                    .ok_or_else(|| io::Error::other("XDP secondary relay owner not ready"))
            })
            .transpose()?;
        // Only the coordinator publishes during startup, with capture admission still closed.
        if owners.iter().any(PacketScope::direct_relay_published) {
            return Err(io::Error::other("XDP relay scope already published"));
        }
        let _start = shutdown.lock_capture_start()?;
        owners[0].publish_direct_relay_runtime(
            relays
                .primary
                .handle
                .get()
                .ok_or_else(|| io::Error::other("XDP primary relay owner not ready"))?
                .clone(),
            Arc::clone(&relays.primary.fence),
        )?;
        if let Some((handle, fence)) = secondary {
            owners[1].publish_direct_relay_runtime(handle.clone(), Arc::clone(fence))?;
        }
        Ok(())
    }

    fn close_relays(&self) {
        if let Some(relays) = self.relays.get() {
            relays.primary.fence.close();
            if let Some(secondary) = &relays.secondary {
                secondary.fence.close();
            }
        }
    }

    async fn close_and_join_relays(&self) {
        self.close_relays();
        if let Some(relays) = self.relays.get() {
            relays.primary.fence.join_closed().await;
            if let Some(secondary) = &relays.secondary {
                secondary.fence.join_closed().await;
            }
        }
    }

    // Boxing the returned envelope would allocate when packet dispatch is full.
    #[allow(clippy::result_large_err)]
    pub(super) fn send(&self, destination: usize, envelope: Envelope) -> Result<(), Envelope> {
        let bytes = envelope
            .body
            .as_ref()
            .map_or(envelope.l3_length, |body| body.bytes().len());
        let endpoint = matches!(envelope.payload, Payload::Endpoint { .. });
        let sent = self.senders[destination].try_send(envelope);
        if let Some(diagnostics) = self.diagnostics.get() {
            diagnostics.record_worker_handoff(destination, endpoint, bytes, sent.is_ok());
        }
        sent.map_err(|error| error.into_inner())
    }

    fn handoff_cell(
        &self,
        destination: usize,
        endpoint: bool,
        bytes: impl FnOnce() -> usize,
    ) -> io::Result<Cell> {
        self.pool.take().ok_or_else(|| {
            if let Some(diagnostics) = self.diagnostics.get() {
                diagnostics.record_worker_handoff(destination, endpoint, bytes(), false);
            }
            io::Error::from(io::ErrorKind::WouldBlock)
        })
    }

    pub(super) fn wake_worker(&self, worker: usize) {
        self.wakers[worker].wake();
    }

    async fn join_secondary_relays(&self) {
        if let Some(secondary) = self
            .relays
            .get()
            .and_then(|relays| relays.secondary.as_ref())
        {
            secondary.fence.close_and_join().await;
        }
    }

    fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }

    pub(super) fn defer_secondary_ready(&self) -> tokio::sync::oneshot::Sender<Vec<Realm>> {
        let (send, receive) = tokio::sync::oneshot::channel();
        self.states[1].lock().startup = Some(receive);
        send
    }

    pub(super) fn activate<'a>(
        &self,
        shutdown: &crate::control::ShutdownIntent,
        endpoints: &PacketEndpoints,
        direct: Option<DirectProfile>,
        candidates: impl Iterator<Item = (&'a PacketRealm, usize, bool)>,
    ) -> anyhow::Result<()> {
        // The worker close/failure state precedes ShutdownIntent's cold commit lock.
        let starting = || -> anyhow::Result<parking_lot::MutexGuard<'_, State>> {
            let state = self.states[1].lock();
            ensure!(
                !state.activated
                    && !self.is_closing()
                    && !state.stop
                    && !state.exited
                    && state.failure.is_none()
                    && matches!(state.drain, Drain::Unarmed)
                    && (self.workers == 1 || state.ready)
                    && !endpoints.is_closing(),
                "XDP capture closed or already activated"
            );
            Ok(state)
        };
        if self.relays.get().is_some() {
            // Probe the PF outside status locks. A close during any probe invalidates the
            // entire startup: neither publishing this pair nor opening capture may revive it.
            for (realm, members, physical) in candidates {
                if direct_relay_eligible(
                    direct,
                    self.workers,
                    realm.owners().len(),
                    members,
                    physical,
                ) {
                    let _state = starting()?;
                    self.publish_relays(realm, shutdown)?;
                }
            }
        }
        let mut state = starting()?;
        shutdown.open_capture(&self.admission)?;
        state.activated = true;
        drop(state);
        if self.auxiliary.get().is_none()
            && let Err(error) = endpoints.capture_ready()
        {
            self.begin_close();
            return Err(error.into());
        }
        // An RX edge can arrive while admission is closed. Recheck those same rings on open.
        if self.workers == 2 {
            self.wake_worker(1);
        }
        Ok(())
    }

    pub(super) fn begin_close(&self) {
        self.fence_admission(self.states[1].lock());
    }

    fn fence_admission(&self, state: parking_lot::MutexGuard<'_, State>) {
        self.closing.store(true, Ordering::Release);
        self.admission.store(false, Ordering::Release);
        drop(state);
        self.wake_worker(0);
        self.wake_worker(1);
        self.close_relays();
    }

    pub(super) fn close(&self) {
        let mut state = self.states[1].lock();
        state.drain = Drain::Revoked;
        self.fence_admission(state);
    }

    pub(super) fn quiesce(&self, deadline: Instant) {
        let mut state = self.states[1].lock();
        if matches!(state.drain, Drain::Unarmed) {
            state.drain = Drain::Until(deadline);
        }
        self.fence_admission(state);
    }

    fn can_kick_outstanding(&self) -> bool {
        let state = self.states[1].lock();
        state.failure.is_none()
            && state
                .drain
                .deadline()
                .is_some_and(|deadline| Instant::now() < deadline)
    }

    fn acknowledge_quiescence(&self) {
        let mut state = self.states[1].lock();
        if state.failure.is_none()
            && state
                .drain
                .deadline()
                .is_some_and(|deadline| Instant::now() < deadline)
        {
            state.drain = Drain::Quiesced;
            drop(state);
            self.wake_worker(0);
        }
    }

    pub(super) fn poll_quiesced(&self, cx: &mut Context<'_>) -> Poll<anyhow::Result<()>> {
        if self.workers == 1 {
            return Poll::Ready(Ok(()));
        }
        self.wakers[0].register(cx.waker());
        let state = self.states[1].lock();
        if let Some(error) = &state.failure {
            Poll::Ready(Err(anyhow::anyhow!("{error:#}")))
        } else if matches!(state.drain, Drain::Quiesced) {
            Poll::Ready(Ok(()))
        } else if state.exited {
            Poll::Ready(Err(anyhow::anyhow!(
                "XDP worker 1 exited before quiescence"
            )))
        } else {
            Poll::Pending
        }
    }

    pub(super) fn failed(&self, worker: u8, error: anyhow::Error) {
        let mut secondary = self.states[1].lock();
        if worker == 1 {
            secondary.failure.get_or_insert(error);
        } else {
            self.states[usize::from(worker)]
                .lock()
                .failure
                .get_or_insert(error);
        }
        secondary.drain = Drain::Revoked;
        self.fence_admission(secondary);
    }
}

pub(super) fn admit(workers: u8, infos: &[DeviceInfo]) -> anyhow::Result<()> {
    ensure!(
        (1..=2).contains(&workers),
        "XDP requires one or two physical owners"
    );
    if workers == 1 {
        return Ok(());
    }
    ensure!(
        infos.iter().any(|info| info.queues.len() >= 2),
        "workers: 2 requires two actual physical queue owners"
    );
    let affinity = polling::owner_affinity().map_err(anyhow::Error::msg)?;
    ensure!(
        affinity.iter().map(|byte| byte.count_ones()).sum::<u32>() >= 2,
        "workers: 2 requires at least two online CPUs in the inherited effective cpuset"
    );
    Ok(())
}

impl PacketBody {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Core(packet) => packet.as_ref(),
            Self::Reassembled(packet) => packet.as_ref(),
        }
    }
}

impl Envelope {
    pub(super) fn ip(&self) -> &[u8] {
        self.body.as_ref().map_or_else(
            || &self.cell.packet()[self.l3_offset..self.l3_offset + self.l3_length],
            PacketBody::bytes,
        )
    }

    fn receive_endpoint(
        &mut self,
        shared: &Shared,
        endpoints: &PacketEndpoints,
        now: Instant,
        driver: Option<&mut PacketDriver>,
    ) -> io::Result<PacketReceive> {
        let Payload::Endpoint {
            owner,
            admission,
            check_output,
        } = std::mem::replace(&mut self.payload, Payload::Ingress)
        else {
            return Err(io::Error::other(
                "worker 1 received coordinator-only ingress",
            ));
        };
        shared.receive_with_output_check(
            endpoints,
            &owner,
            self.ip(),
            self.ingress_at,
            now,
            self.path,
            admission,
            check_output,
            driver,
        )
    }
}

/// Port drops this closure before replenishing FILL or kicking the socket, even on partial RX.
/// Only the scope lock lives across callbacks. Each packet borrow ends inside its callback.
pub(super) fn receive_batch<'a>(
    port: &mut Port<Retained>,
    limit: usize,
    metadata_len: usize,
    mut packet: impl FnMut(
        &mut Option<RealmRxBatch<'a>>,
        &[&[u8]],
        &[u8],
        &mut honk_xsk::TxSink<'_, Retained>,
    ),
) -> io::Result<usize> {
    let mut batch = None;
    port.receive_segments_with(
        limit.min(BATCH),
        metadata_len,
        move |segments, metadata, sink| {
            packet(&mut batch, segments, metadata, sink);
        },
    )
}

impl Shared {
    pub(super) fn placements(&self) -> &[Placement] {
        &self
            .placements
            .get()
            .expect("published physical placements")
            .entries
    }

    pub(super) fn placement(&self, scope: ScopeId) -> io::Result<&Placement> {
        self.placements()
            .iter()
            .find(|placement| placement.realm.scope() == scope)
            .ok_or_else(|| io::Error::other("unregistered physical realm"))
    }

    pub(super) fn established<'a>(
        &'a self,
        batch: &mut Option<RealmRxBatch<'a>>,
        owner: &'a PacketScope,
        packet: &[u8],
        times: (Instant, Instant),
        path: ReturnPath,
        endpoints: &PacketEndpoints,
    ) -> Option<PacketReceive> {
        RealmRxBatch::receive(batch, owner, packet, times, path, &self.peers, || {
            endpoints.can_batch_tcp()
        })
    }

    pub(super) fn established_sharded<'a>(
        &'a self,
        batch: &mut Option<RealmRxBatch<'a>>,
        owner: &'a PacketScope,
        packet: &[u8],
        times: (Instant, Instant),
        path: ReturnPath,
        endpoints: &PacketEndpoints,
    ) -> Result<Option<PacketReceive>, PeerPathChanged> {
        RealmRxBatch::receive_sharded(batch, owner, packet, times, path, &self.peers, || {
            endpoints.can_batch_tcp()
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn receive(
        &self,
        endpoints: &PacketEndpoints,
        owner: &PacketScope,
        packet: &[u8],
        ingress_at: Instant,
        service_at: Instant,
        path: ReturnPath,
        admission: Option<EndpointAdmission>,
    ) -> io::Result<PacketReceive> {
        self.receive_with_output_check(
            endpoints, owner, packet, ingress_at, service_at, path, admission, false, None,
        )
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn receive_with_output_check(
        &self,
        endpoints: &PacketEndpoints,
        owner: &PacketScope,
        packet: &[u8],
        ingress_at: Instant,
        service_at: Instant,
        path: ReturnPath,
        admission: Option<EndpointAdmission>,
        force_output_check: bool,
        driver: Option<&mut PacketDriver>,
    ) -> io::Result<PacketReceive> {
        let previous = wire::packet_addresses(packet)
            .ok()
            .and_then(|(source, _)| match &driver {
                Some(local) => local.local_peer_hold(source),
                None => owner.peer_hold(source),
            });
        let check_output = force_output_check
            || previous
                .as_ref()
                .and_then(PeerHold::path)
                .is_some_and(|old| old != path);
        let retain = |source: honk_netstack::ValidatedSource, pending| {
            let hold = self
                .peers
                .retain(owner.scope(), source, path, ingress_at, pending)?;
            if pending {
                previous
                    .as_ref()
                    .filter(|held| held.address() == source.src.ip())
                    .cloned()
                    .or(Some(hold))
            } else {
                Some(hold)
            }
        };
        match driver {
            Some(local) => endpoints.receive_local_on_timed(
                local,
                packet,
                ingress_at,
                service_at,
                admission,
                check_output,
                retain,
            ),
            None => endpoints.receive_on_timed(
                owner,
                packet,
                ingress_at,
                service_at,
                admission,
                check_output,
                retain,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn physical_endpoint<'a>(
        &'a self,
        batch: &mut Option<RealmRxBatch<'a>>,
        endpoints: &PacketEndpoints,
        realm: &'a PacketRealm,
        local: usize,
        ingress: Ingress,
        segments: &[&[u8]],
        view: PacketView<'_>,
        staging: &mut [u8],
        times: (Instant, Instant),
        path: ReturnPath,
        mixed: bool,
        mut driver: Option<&mut PacketDriver>,
        checked: &mut Option<PeerObservation<'a>>,
    ) -> io::Result<PacketReceive> {
        let mut check_output = false;
        if let Some(owner) = driver.as_deref_mut()
            && endpoints.can_batch_tcp()
            && let [packet] = segments
        {
            match owner.try_local_established(packet, times, path, &self.peers, checked) {
                Ok(Some(report)) => return Ok(report),
                Ok(None) => {}
                Err(_) => check_output = true,
            }
        }
        let fixed = if let Some(owner) = driver.as_deref() {
            if realm.owners().len() == 1 || locally_retained_tcp(owner, view) {
                Some((&realm.owners()[local], None))
            } else {
                Some(realm.dispatch_owner(local, view)?)
            }
        } else if realm.queue_affine() {
            None
        } else {
            Some(realm.dispatch_owner(local, view)?)
        };
        let tentative = fixed.as_ref().map_or(local, |(owner, _)| owner.worker());
        if driver.is_none()
            && tentative == local
            && !mixed
            && let [packet] = segments
        {
            match self.established_sharded(
                batch,
                &realm.owners()[local],
                packet,
                times,
                path,
                endpoints,
            ) {
                Ok(Some(report)) => return Ok(report),
                Ok(None) => {}
                Err(_) => check_output = true,
            }
        }
        batch.take();
        let (owner, claim) = match fixed {
            Some(route) => route,
            None => realm.dispatch_owner(local, view)?,
        };
        if owner.worker() != local {
            // The coordinator rechecks Core ownership when delegated mixed ingress arrives.
            let payload = if (mixed && local == 1)
                || matches!(view.parse_ip(), Err(wire::ParseError::Fragment))
            {
                Payload::Ingress
            } else {
                Payload::Endpoint {
                    owner: owner.clone(),
                    admission: None,
                    check_output,
                }
            };
            return self.handoff_segments(
                owner.worker(),
                ingress,
                realm.scope(),
                segments,
                times.0,
                path,
                payload,
                claim,
            );
        }
        let packet = if let [packet] = segments {
            *packet
        } else {
            let bytes = staging
                .get_mut(..view.len())
                .ok_or(io::ErrorKind::InvalidData)?;
            view.copy_to(0..view.len(), bytes)
                .ok_or(io::ErrorKind::InvalidData)?;
            bytes
        };
        if matches!(wire::parse_ip(packet), Err(wire::ParseError::Fragment)) {
            return self.endpoint_fragment(endpoints, realm.scope(), packet, times.0, path, driver);
        }
        self.receive_with_output_check(
            endpoints,
            owner,
            packet,
            times.0,
            times.1,
            path,
            None,
            check_output,
            driver,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn handoff_segments(
        &self,
        target: usize,
        ingress: Ingress,
        scope: ScopeId,
        segments: &[&[u8]],
        ingress_at: Instant,
        path: ReturnPath,
        payload: Payload,
        claim: Option<TcpClaim>,
    ) -> io::Result<PacketReceive> {
        let mut cell =
            self.handoff_cell(target, matches!(payload, Payload::Endpoint { .. }), || {
                segments.iter().map(|s| s.len()).sum()
            })?;
        cell.copy(segments, &[])?;
        let peer = if matches!(payload, Payload::Ingress)
            && matches!(
                wire::parse_ip(cell.packet()),
                Err(wire::ParseError::Fragment)
            ) {
            self.fragment_peer(scope, cell.packet(), path)?
        } else {
            None
        };
        let envelope = Envelope {
            ingress,
            scope,
            path,
            ingress_at,
            l3_offset: 0,
            l3_length: cell.packet().len(),
            cell,
            body: None,
            peer,
            payload,
            _claim: claim,
        };
        self.send(target, envelope)
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        Ok(PacketReceive::default())
    }

    pub(super) fn endpoint_fragment(
        &self,
        endpoints: &PacketEndpoints,
        scope: ScopeId,
        fragment: &[u8],
        ingress_at: Instant,
        path: ReturnPath,
        mut driver: Option<&mut PacketDriver>,
    ) -> io::Result<PacketReceive> {
        let realm = endpoints
            .realm(scope)
            .ok_or_else(|| io::Error::other("unregistered physical realm"))?;
        let peer = self.fragment_peer(scope, fragment, path)?;
        let completed = match driver.as_deref_mut() {
            Some(local) => {
                local.reassemble_for_dispatch_with_peer(fragment, ingress_at, Instant::now(), peer)
            }
            None => endpoints.reassemble_for_dispatch_on(
                &realm.owners()[0],
                fragment,
                ingress_at,
                Instant::now(),
                peer,
            ),
        };
        let (packet, peer) = match completed {
            Ok(Some(packet)) => packet,
            Ok(None) | Err(_) => return Ok(PacketReceive::default()),
        };
        let path = peer.as_ref().map(PeerHold::original_path).unwrap_or(path);
        let ingress_at = packet.completion_ingress();
        let (owner, claim) = realm.dispatch_owner(0, PacketView::from_slice(packet.as_ref()))?;
        if owner.worker() == 0 {
            return self.receive_with_output_check(
                endpoints,
                owner,
                packet.as_ref(),
                ingress_at,
                Instant::now(),
                path,
                None,
                false,
                driver,
            );
        }
        let envelope = Envelope {
            ingress: self.placement(scope)?.ingress,
            scope,
            path,
            ingress_at,
            cell: self.handoff_cell(owner.worker(), true, || packet.as_ref().len())?,
            body: Some(PacketBody::Reassembled(packet)),
            peer,
            l3_offset: 0,
            l3_length: 0,
            payload: Payload::Endpoint {
                owner: owner.clone(),
                admission: None,
                check_output: false,
            },
            _claim: claim,
        };
        self.send(owner.worker(), envelope)
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        Ok(PacketReceive::default())
    }

    pub(super) fn ready(&self, worker: u8) {
        self.states[worker as usize].lock().ready = true;
        self.wake_worker(0);
    }

    pub(super) fn all_ready(&self, cx: &mut Context<'_>) -> Poll<anyhow::Result<()>> {
        self.poll_ready(cx, false)
    }

    pub(super) fn poll_ready(
        &self,
        cx: &mut Context<'_>,
        queues_only: bool,
    ) -> Poll<anyhow::Result<()>> {
        self.wakers[0].register(cx.waker());
        let mut ready = true;
        let mut exited = false;
        for state in self.states.iter().take(usize::from(self.workers)) {
            let state = state.lock();
            if let Some(error) = &state.failure {
                return Poll::Ready(Err(anyhow::anyhow!("{error:#}")));
            }
            exited |= state.exited;
            ready &= state.ready || queues_only && state.queues_registered;
        }
        if self.is_closing() || exited {
            Poll::Ready(Err(anyhow::anyhow!("XDP worker closed before readiness")))
        } else if ready {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    pub(super) fn check_failure(&self) -> anyhow::Result<()> {
        for state in self.states.iter().take(usize::from(self.workers)) {
            if let Some(error) = &state.lock().failure {
                return Err(anyhow::anyhow!("{error:#}"));
            }
        }
        Ok(())
    }
}

// Placement only: the Stack still verifies the full transport header and checksum.
fn locally_retained_tcp(driver: &PacketDriver, view: PacketView<'_>) -> bool {
    let Ok(ip) = view.parse_ip() else {
        return false;
    };
    if ip.proto != wire::PROTO_TCP || ip.payload.len() < 4 {
        return false;
    }
    let mut ports = [0; 4];
    if view
        .copy_to(ip.payload.start..ip.payload.start + 4, &mut ports)
        .is_none()
    {
        return false;
    }
    driver.local_retains_tcp(
        (ip.src, u16::from_be_bytes([ports[0], ports[1]])).into(),
        (ip.dst, u16::from_be_bytes([ports[2], ports[3]])).into(),
    )
}

struct WorkerDevice {
    index: usize,
    info: Arc<DeviceInfo>,
    capture: GeneralCapture,
    queues: Vec<Queue>,
    features: Option<FeatureQuery>,
}

pub(super) struct Worker {
    shared: Arc<Shared>,
    thread: Option<std::thread::JoinHandle<()>>,
}

struct WorkerRuntime {
    shared: Arc<Shared>,
    placements: Arc<Placements>,
    devices: Vec<WorkerDevice>,
    realms: Vec<Realm>,
    endpoints: PacketEndpoints,
    receiver: mpsc::Receiver<Envelope>,
    mixed: bool,
    staging: Vec<u8>,
    sampled: Instant,
    closing: bool,
    polling: AdaptivePoll,
    polling_budget: Arc<MemoryBudget>,
    polling_prefix: Result<ContextDigest, &'static str>,
    polling_affinity: Option<[u8; libc::CPU_SETSIZE as usize / 8]>,
    context_revision: u64,
    context_recheck: bool,
    qualified_rx: u64,
    qualification_unavailable: bool,
    shutdown: Arc<crate::control::ShutdownIntent>,
    rx_device: usize,
    rx_queue: usize,
    tx_realm: usize,
}

impl Worker {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn start(
        shared: Arc<Shared>,
        devices: &mut [Device],
        realms: Vec<Realm>,
        endpoints: PacketEndpoints,
        receiver: mpsc::Receiver<Envelope>,
        mixed: bool,
        polling: AdaptivePoll,
        polling_budget: Arc<MemoryBudget>,
        shutdown: Arc<crate::control::ShutdownIntent>,
    ) -> io::Result<Self> {
        let placements = Arc::clone(
            shared
                .placements
                .get()
                .expect("published physical placements"),
        );
        #[cfg(test)]
        assert!(
            shared
                .secondary_test_control
                .set(polling.test_control())
                .is_ok()
        );
        let mut owned = Vec::with_capacity(devices.len());
        for (index, device) in devices.iter_mut().enumerate() {
            let mut queues = Vec::new();
            let mut local = Vec::with_capacity(device.queues.len());
            for queue in device.queues.drain(..) {
                if queue.id % u32::from(shared.workers) == 1 {
                    queues.push(queue);
                } else {
                    local.push(queue);
                }
            }
            device.queues = local;
            owned.push(WorkerDevice {
                index,
                info: Arc::clone(&device.info),
                capture: GeneralCapture {
                    authority: device.capture.authority,
                    bypass_mark: device.capture.bypass_mark,
                    vlan_metadata: device.capture.vlan_metadata,
                },
                queues,
                features: None,
            });
        }
        let thread_shared = Arc::clone(&shared);
        let pending = Arc::new(Mutex::new(Some((owned, realms, endpoints, receiver))));
        let thread_pending = Arc::clone(&pending);
        let thread = std::thread::Builder::new()
            .name("honk-xdp-1".into())
            .stack_size(THREAD_STACK)
            .spawn(move || {
                let (owned, realms, endpoints, receiver) = thread_pending
                    .lock()
                    .take()
                    .expect("one physical owner handoff");
                let mut worker = WorkerRuntime {
                    shared: Arc::clone(&thread_shared),
                    placements,
                    devices: owned,
                    realms,
                    endpoints,
                    receiver,
                    mixed,
                    staging: vec![0; 65536],
                    sampled: Instant::now(),
                    closing: false,
                    polling,
                    polling_prefix: ContextDigest::platform(&polling_budget),
                    polling_budget,
                    polling_affinity: None,
                    context_revision: 0,
                    context_recheck: true,
                    qualified_rx: 0,
                    qualification_unavailable: false,
                    shutdown,
                    rx_device: 0,
                    rx_queue: 0,
                    tx_realm: 0,
                };
                let mut relay_runtime = None;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    worker.run(&mut relay_runtime)
                }));
                let failure = match result {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(error),
                    Err(_) => Some(anyhow::anyhow!(
                        "XDP worker 1 panicked; retaining actual owners"
                    )),
                };
                if let Some(error) = failure {
                    thread_shared.failed(1, error);
                    fail_local_applications(&mut worker.realms);
                    std::mem::forget(worker);
                    futures::executor::block_on(thread_shared.join_secondary_relays());
                    loop {
                        std::thread::park();
                    }
                }
                drop(relay_runtime);
                thread_shared.states[1].lock().exited = true;
                thread_shared.wake_worker(0);
            });
        let thread = match thread {
            Ok(thread) => thread,
            Err(error) => {
                if let Some((owned, mut realms, endpoints, receiver)) = pending.lock().take() {
                    fail_local_applications(&mut realms);
                    std::mem::forget((owned, realms, endpoints, receiver));
                }
                return Err(error);
            }
        };
        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }

    #[cfg(test)]
    pub(super) fn test_control(&self) -> Arc<polling::testing::Control> {
        Arc::clone(self.shared.secondary_test_control())
    }

    pub(super) async fn join(&mut self) -> anyhow::Result<()> {
        {
            let mut state = self.shared.states[1].lock();
            // Stop and close admission before notifying either reactor.
            state.stop = true;
            self.shared.fence_admission(state);
        }
        poll_fn(|cx| {
            self.shared.wakers[0].register(cx.waker());
            let state = self.shared.states[1].lock();
            if let Some(error) = &state.failure {
                return Poll::Ready(Err(anyhow::anyhow!("{error:#}")));
            }
            if state.exited {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
        if let Some(thread) = self.thread.take() {
            tokio::task::spawn_blocking(move || thread.join())
                .await
                .map_err(anyhow::Error::from)?
                .map_err(|_| anyhow::anyhow!("XDP worker 1 thread panicked"))?;
        }
        Ok(())
    }
}

impl Shared {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn endpoint_packet(
        &self,
        endpoints: &PacketEndpoints,
        scope: ScopeId,
        ingress_worker: usize,
        packet: Packet,
        ingress_at: Instant,
        path: ReturnPath,
        admission: Option<EndpointAdmission>,
        cell: Option<Cell>,
        peer: Option<PeerHold>,
    ) -> io::Result<PacketReceive> {
        let realm = endpoints
            .realm(scope)
            .ok_or_else(|| io::Error::other("unregistered physical realm"))?;
        let preferred = if packet.is_reassembled() {
            0
        } else {
            ingress_worker
        };
        let (owner, claim) =
            realm.dispatch_owner(preferred, PacketView::from_slice(packet.as_ref()))?;
        if owner.worker() == 0 {
            return self.receive(
                endpoints,
                owner,
                packet.as_ref(),
                ingress_at,
                Instant::now(),
                path,
                admission,
            );
        }
        let placement = self.placement(scope)?;
        let cell = match cell {
            Some(cell) => cell,
            None => self.handoff_cell(1, true, || packet.as_ref().len())?,
        };
        let envelope = Envelope {
            _claim: claim,
            ingress: placement.ingress,
            scope,
            path,
            ingress_at,
            cell,
            body: Some(PacketBody::Core(packet)),
            peer,
            l3_offset: 0,
            l3_length: 0,
            payload: Payload::Endpoint {
                owner: owner.clone(),
                admission,
                check_output: false,
            },
        };
        self.send(1, envelope)
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        Ok(PacketReceive::default())
    }

    fn dispatch_envelope(
        &self,
        endpoints: &PacketEndpoints,
        mut envelope: Envelope,
        mut driver: Option<&mut PacketDriver>,
    ) -> io::Result<PacketReceive> {
        if matches!(
            wire::parse_ip(envelope.ip()),
            Err(wire::ParseError::Fragment)
        ) {
            let placement = self.placement(envelope.scope)?;
            let completed = match driver.as_deref_mut() {
                Some(local) => local.reassemble_for_dispatch_with_peer(
                    envelope.ip(),
                    envelope.ingress_at,
                    Instant::now(),
                    envelope.peer.clone(),
                ),
                None => endpoints.reassemble_for_dispatch_on(
                    placement.realm.owner(0).unwrap(),
                    envelope.ip(),
                    envelope.ingress_at,
                    Instant::now(),
                    envelope.peer.clone(),
                ),
            };
            let (packet, peer) = match completed {
                Ok(Some(packet)) => packet,
                Ok(None) | Err(_) => return Ok(PacketReceive::default()),
            };
            envelope.path = peer
                .as_ref()
                .map(PeerHold::original_path)
                .unwrap_or(envelope.path);
            envelope.peer = peer;
            envelope.ingress_at = packet.completion_ingress();
            envelope.body = Some(PacketBody::Reassembled(packet));
        }
        let realm = endpoints
            .realm(envelope.scope)
            .ok_or_else(|| io::Error::other("unregistered physical realm"))?;
        let preferred = usize::from(envelope.body.is_none()); // Raw coordinator handoffs came from queue owner 1.
        let (owner, claim) =
            realm.dispatch_owner(preferred, PacketView::from_slice(envelope.ip()))?;
        if owner.worker() == 0 {
            return self.receive_with_output_check(
                endpoints,
                owner,
                envelope.ip(),
                envelope.ingress_at,
                Instant::now(),
                envelope.path,
                None,
                false,
                driver,
            );
        }
        envelope._claim = claim;
        envelope.payload = Payload::Endpoint {
            owner: owner.clone(),
            admission: None,
            check_output: false,
        };
        self.send(1, envelope)
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        Ok(PacketReceive::default())
    }
}

impl Runtime {
    pub(super) fn poll_handoffs(
        &mut self,
        cx: &mut Context<'_>,
        now: Instant,
    ) -> anyhow::Result<usize> {
        self.workers.wakers[0].register(cx.waker());
        self.workers.check_failure()?;
        let mut progress = 0;
        for _ in 0..BATCH {
            let mut envelope = match self.inbox.poll_recv(cx) {
                Poll::Ready(Some(envelope)) => envelope,
                _ => break,
            };
            if self.closing {
                progress += 1;
                continue;
            }
            let local = self
                .realms
                .iter_mut()
                .find(|r| r.realm_id == envelope.path.realm && r.driver.is_local())
                .map(|r| &mut r.driver);
            let result = match envelope.payload {
                Payload::Endpoint { .. } => {
                    envelope.receive_endpoint(&self.workers, &self.endpoints, now, local)
                }
                Payload::Ingress => {
                    if let Some(core) = &mut self.core
                        && !retained_endpoint(
                            &self.endpoints,
                            envelope.scope,
                            PacketView::from_slice(envelope.ip()),
                        )
                    {
                        if self.waiting.len() != PENDING {
                            let received = match core.receive_segments_with_peer_at(
                                envelope.ingress,
                                envelope.ingress_at,
                                now,
                                &[envelope.ip()],
                                envelope.peer.clone(),
                            ) {
                                Ok(received) => received,
                                Err(error)
                                    if error
                                        .downcast_ref::<honk_datapath::forward::ForwardError>()
                                        .is_some() =>
                                {
                                    self.pressure.counters.core_ingress_refused = self
                                        .pressure
                                        .counters
                                        .core_ingress_refused
                                        .saturating_add(1);
                                    None
                                }
                                Err(error) => return Err(error),
                            };
                            if let Some((packet, peer)) = received {
                                let ingress_at = packet.received_at();
                                let path = peer
                                    .as_ref()
                                    .map(PeerHold::original_path)
                                    .unwrap_or(envelope.path);
                                self.waiting.push_back(Waiting {
                                    packet,
                                    mac: path.mac,
                                    retry: now,
                                    scope: envelope.scope,
                                    ingress_worker: 1,
                                    path,
                                    ingress_at,
                                    cell: Some(envelope.cell),
                                    peer,
                                });
                            }
                        } else {
                            self.pressure.counters.waiting_full =
                                self.pressure.counters.waiting_full.saturating_add(1);
                        }
                        Ok(PacketReceive::default())
                    } else {
                        self.workers
                            .dispatch_envelope(&self.endpoints, envelope, local)
                    }
                }
            };
            match result {
                Ok(report) if report.qualified_rx => {
                    qualify_packet(&mut self.qualified_rx, &mut self.qualification_unavailable)
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
                    ) => {}
                Err(error) => return Err(error.into()),
            }
            progress += 1;
        }
        Ok(progress)
    }
}

struct CoordinatorJoin {
    thread: Option<std::thread::JoinHandle<()>>,
    completion: Option<tokio::sync::oneshot::Receiver<(Option<ControlPlane>, anyhow::Result<()>)>>,
    shutdown: Arc<crate::control::ShutdownIntent>,
    admission: Arc<AtomicBool>,
    shared_runtime: tokio::runtime::Handle,
}

impl Drop for CoordinatorJoin {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.shutdown.request();
            self.admission.store(false, Ordering::Release);
            if let Some(completion) = self.completion.take() {
                self.shared_runtime.spawn(async move {
                    match completion.await {
                        Ok(result) if result.0.is_some() || result.1.is_ok() => {
                            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
                            drop(result);
                        }
                        _ => std::mem::forget(thread),
                    }
                });
            } else {
                std::mem::forget(thread);
            }
        }
    }
}

async fn finish_coordinator(
    outcome: std::thread::Result<(Option<ControlPlane>, anyhow::Result<()>)>,
    capture: Option<&(Arc<Shared>, PacketEndpoints)>,
) -> (Option<ControlPlane>, anyhow::Result<()>) {
    let mut result = outcome.unwrap_or_else(|_| {
        (
            None,
            Err(anyhow::anyhow!(
                "XDP coordinator panicked; retaining actual owners"
            )),
        )
    });
    if let Some((workers, endpoints)) = capture {
        if result.0.is_none() && result.1.is_err() {
            workers.close();
            // Closing a scope can deliver application wakers. Even a panicking wake must
            // leave this reactor driving its admitted TCP children until their parents join.
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| endpoints.close())).is_err()
            {
                result.1 = result.1.map_err(|error| {
                    error.context("packet endpoint close panicked while retaining capture")
                });
            }
        }
        if let Some(auxiliary) = workers.auxiliary.get() {
            auxiliary.stop();
            if let Err(aux) = auxiliary.join().await {
                result.1 = Err(match result.1 {
                    Ok(()) => aux,
                    Err(error) => {
                        error.context(format!("auxiliary TUN teardown also failed: {aux:#}"))
                    }
                });
            }
        }
        // The shared TCP parent holds its lease until it collects the actual owner task.
        workers.close_and_join_relays().await;
    }
    result
}

pub(super) async fn run_coordinator(
    plane: ControlPlane,
    admission: Arc<AtomicBool>,
    pname_support: crate::ebpf::PnameSupportCell,
) -> (Option<ControlPlane>, anyhow::Result<()>) {
    let shared_runtime = tokio::runtime::Handle::current();
    let shutdown = plane.shutdown_intent();
    let (send, receive) = tokio::sync::oneshot::channel();
    let runtime_handle = shared_runtime.clone();
    let thread_admission = Arc::clone(&admission);
    let pending_plane = Arc::new(Mutex::new(Some(plane)));
    let thread_plane = Arc::clone(&pending_plane);
    let thread = match std::thread::Builder::new()
        .name("honk-xdp-0".into())
        .stack_size(THREAD_STACK)
        .spawn(move || {
            let plane = thread_plane
                .lock()
                .take()
                .expect("one coordinator plane handoff");
            // The caller keeps driving Tokio I/O, timers and spawned tasks while capture
            // occupies this thread. Cold capture futures still run on the coordinator.
            let mut capture = None;
            let mut primary_relay = None;
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                runtime_handle.block_on(super::run_capture(
                    plane,
                    thread_admission,
                    pname_support,
                    runtime_handle.clone(),
                    &mut capture,
                    &mut primary_relay,
                ))
            }));
            let result = runtime_handle.block_on(finish_coordinator(outcome, capture.as_ref()));
            // Its children and their parents have joined; Tokio runtime destruction can block.
            drop(primary_relay);
            let retained = result.0.is_none() && result.1.is_err();
            let _ = send.send(result);
            if retained {
                loop {
                    std::thread::park();
                }
            }
        }) {
        Ok(thread) => thread,
        Err(error) => return (pending_plane.lock().take(), Err(error.into())),
    };
    let mut join = CoordinatorJoin {
        thread: Some(thread),
        completion: Some(receive),
        shutdown,
        admission,
        shared_runtime,
    };
    let result = join
        .completion
        .as_mut()
        .expect("coordinator result custody")
        .await;
    join.completion.take();
    let result = match result {
        Ok(result) => result,
        Err(error) => return (None, Err(error.into())),
    };
    if result.0.is_none() && result.1.is_err() {
        // The fenced thread and its I/O runtime are still retaining real custody.
        std::mem::forget(join.thread.take());
        return result;
    }
    let thread = join.thread.take().unwrap();
    match tokio::task::spawn_blocking(move || thread.join()).await {
        Ok(Ok(())) => result,
        Ok(Err(_)) => (
            None,
            Err(anyhow::anyhow!("XDP coordinator thread panicked")),
        ),
        Err(error) => (None, Err(error.into())),
    }
}

impl Shared {
    pub(super) fn fragment_peer(
        &self,
        scope: ScopeId,
        packet: &[u8],
        path: ReturnPath,
    ) -> io::Result<Option<PeerHold>> {
        let (source, _) = wire::packet_addresses(packet).map_err(io::Error::other)?;
        self.peers.pin_fragment(scope, source, path)
    }
}

impl Shared {
    pub(super) fn peer_count(&self) -> usize {
        self.peers.slots.lock().len()
    }
}
