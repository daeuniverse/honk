use super::*;
use crate::control::netstack::RealmRxBatch;
use futures::FutureExt as _;
mod adaptive;
mod runtime;
#[cfg(test)]
mod tests;
use parking_lot::Mutex;
use tokio::sync::{Notify, mpsc};

const CELLS: usize = 64;
pub(super) const THREAD_STACK: usize = 2 << 20;
const DESTINATION: usize = 32;

#[derive(Debug)]
struct PeerSlot {
    address: IpAddr,
    scope: ScopeId,
    path: ReturnPath,
    generation: u64,
    holds: usize,
    last_seen: Instant,
    conflict: Option<Instant>,
}

impl PeerSlot {
    fn observe(
        &mut self,
        authority: &PeerAuthority,
        path: ReturnPath,
        now: Instant,
        opens: bool,
        rst: bool,
        pending: bool,
    ) -> bool {
        let changed = self.conflict.is_some() || (!pending && !rst && self.path != path);
        if !self.path.same_identity(path) || self.conflict.is_some() {
            if rst || !opens || self.holds != 0 {
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

    fn pin(&mut self, authority: &PeerAuthority) -> Option<()> {
        self.holds = self.holds.checked_add(1)?;
        if self.holds == usize::MAX {
            authority.invalidate();
        }
        Some(())
    }
}

#[derive(Debug)]
pub(crate) struct PeerAuthority {
    slots: Mutex<Vec<PeerSlot>>,
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
            PeerAuthority::new(Arc::new(AtomicBool::new(true))),
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
        let mut peers = self.authority.slots.lock();
        let peer = &mut peers[self.slot];
        assert_eq!(peer.generation, self.generation);
        peer.pin(&self.authority)
            .expect("peer hold count exhausted");
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
        let mut peers = self.authority.slots.lock();
        let peer = &mut peers[self.slot];
        assert_eq!(peer.generation, self.generation);
        peer.holds = peer.holds.checked_sub(1).expect("peer hold underflow");
    }
}

impl PeerAuthority {
    pub(crate) fn new(admission: Arc<AtomicBool>) -> Arc<Self> {
        Arc::new(Self {
            slots: Mutex::new(Vec::with_capacity(PEERS)),
            admission,
            revision: 0.into(),
        })
    }

    // All writers hold the slots mutex. Saturation permanently disables optimistic reuse.
    fn invalidate(&self) {
        let revision = self.revision.load(Ordering::Relaxed);
        self.revision
            .store(revision.saturating_add(1), Ordering::Release);
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
            if !peers[slot].observe(self, path, now, opens, rst, pending) {
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
                    .filter(|(_, peer)| {
                        peer.holds == 0
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
                holds: 0,
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
        let peer = &mut peers[slot];
        peer.pin(self)?;
        Some(PeerHold {
            authority: Arc::clone(self),
            slot,
            generation: peer.generation,
            address,
            path: peer.path,
        })
    }

    /// A live realm hold pins this exact generation. Other workers can still change its path.
    pub(crate) fn confirm_tcp<'a>(
        &'a self,
        held: &PeerHold,
        scope: ScopeId,
        source: honk_netstack::ValidatedSource,
        path: ReturnPath,
        now: Instant,
        checked: &mut Option<PeerObservation<'a>>,
    ) -> bool {
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
            return false;
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
            return true;
        }
        let mut peers = self.slots.lock();
        let peer = &mut peers[held.slot];
        if peer.scope != scope
            || peer.generation != held.generation
            || !peer.observe(self, path, now, false, false, false)
            || peer.holds == usize::MAX
        {
            return false;
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
        true
    }

    fn pin_fragment(
        self: &Arc<Self>,
        scope: ScopeId,
        address: IpAddr,
        path: ReturnPath,
    ) -> io::Result<Option<PeerHold>> {
        let mut peers = self.slots.lock();
        let Some(slot) = peers
            .iter()
            .position(|peer| peer.scope == scope && peer.address == address)
        else {
            return Ok(Some(PeerHold::unlearned(Arc::clone(self), address, path)));
        };
        let peer = &mut peers[slot];
        if !peer.path.same_identity(path) || peer.conflict.is_some() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        peer.pin(self)
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
                        + size_of::<PeerAuthority>()
                        + PEERS * size_of::<PeerSlot>()
                        + 64 * size_of::<Placement>()
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
#[derive(Clone)]
pub(super) struct Placement {
    pub(super) realm_id: u32,
    pub(super) realm: crate::control::netstack::PacketRealm,
    pub(super) ingress: Ingress,
    pub(super) device: usize,
    pub(super) link: LogicalLink,
}

pub(super) enum Payload {
    Ingress,
    Endpoint {
        owner: PacketScope,
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
    drain: Drain,
    stop: bool,
    exited: bool,
    failure: Option<anyhow::Error>,
}

pub(super) struct Shared {
    pool: Arc<CellPool>,
    senders: [mpsc::Sender<Envelope>; 2],
    states: [Mutex<State>; 2],
    wake: [Arc<Notify>; 2],
    admission: Arc<AtomicBool>,
    closing: AtomicBool,
    peers: Arc<PeerAuthority>,
    pub(super) workers: u8,
    pub(super) placements: Mutex<Vec<Placement>>,
    wakers: [futures::task::AtomicWaker; 2],
    pub(super) diagnostics: Mutex<Option<Arc<Diagnostics>>>,
    contexts: Mutex<[Option<Result<String, &'static str>>; 2]>,
    context_changed: [AtomicBool; 2],
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
                wake: std::array::from_fn(|_| Arc::new(Notify::new())),
                peers: PeerAuthority::new(Arc::clone(&admission)),
                admission,
                closing: AtomicBool::new(false),
                workers,
                placements: Mutex::new(Vec::with_capacity(64)),
                wakers: std::array::from_fn(|_| futures::task::AtomicWaker::new()),
                diagnostics: Mutex::new(None),
                contexts: Mutex::new([None, None]),
                context_changed: std::array::from_fn(|_| AtomicBool::new(true)),
            }),
            [receive0, receive1],
        ))
    }

    // Boxing the returned envelope would allocate when packet dispatch is full.
    #[allow(clippy::result_large_err)]
    pub(super) fn send(&self, destination: usize, mut envelope: Envelope) -> Result<(), Envelope> {
        match self.senders[destination].try_send(envelope) {
            Ok(()) => {
                self.wake[destination].notify_one();
                self.wakers[destination].wake();
                Ok(())
            }
            Err(error) => {
                envelope = error.into_inner();
                Err(envelope)
            }
        }
    }

    pub(super) fn copy(&self, segments: &[&[u8]], metadata: &[u8]) -> io::Result<Cell> {
        let mut cell = self
            .pool
            .take()
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        cell.copy(segments, metadata)?;
        Ok(cell)
    }

    pub(super) fn wake_worker(&self, worker: usize) {
        self.wake[worker].notify_one();
        self.wakers[worker].wake();
    }

    fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }

    pub(super) fn begin_close(&self) {
        self.closing.store(true, Ordering::Release);
        self.admission.store(false, Ordering::Release);
        self.wake_worker(0);
        self.wake_worker(1);
    }

    pub(super) fn close(&self) {
        self.states[1].lock().drain = Drain::Revoked;
        self.begin_close();
    }

    pub(super) fn quiesce(&self, deadline: Instant) {
        let mut state = self.states[1].lock();
        if matches!(state.drain, Drain::Unarmed) {
            state.drain = Drain::Until(deadline);
        }
        drop(state);
        self.begin_close();
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
        self.states[worker as usize]
            .lock()
            .failure
            .get_or_insert(error);
        self.close();
    }
}

pub(super) fn admit(workers: u8, infos: &[DeviceInfo]) -> anyhow::Result<()> {
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

impl Envelope {
    pub(super) fn ip(&self) -> &[u8] {
        match &self.body {
            Some(PacketBody::Core(packet)) => packet.as_ref(),
            Some(PacketBody::Reassembled(packet)) => packet.as_ref(),
            None => &self.cell.packet()[self.l3_offset..self.l3_offset + self.l3_length],
        }
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
    pub(super) fn placement(&self, scope: ScopeId) -> io::Result<Placement> {
        self.placements
            .lock()
            .iter()
            .find(|placement| placement.realm.scope() == scope)
            .cloned()
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
        let previous = wire::packet_addresses(packet)
            .ok()
            .and_then(|(source, _)| owner.peer_hold(source));
        let check_output = previous
            .as_ref()
            .and_then(PeerHold::path)
            .is_some_and(|old| old != path);
        endpoints.receive_on_timed(
            owner,
            packet,
            ingress_at,
            service_at,
            admission,
            check_output,
            |source, pending| {
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
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn endpoint(
        &self,
        worker: usize,
        endpoints: &PacketEndpoints,
        scope: ScopeId,
        packet: &[u8],
        ingress_at: Instant,
        path: ReturnPath,
        admission: Option<EndpointAdmission>,
        cell: Option<Cell>,
    ) -> io::Result<PacketReceive> {
        let realm = endpoints
            .realm(scope)
            .ok_or_else(|| io::Error::other("unregistered physical realm"))?;
        if matches!(wire::parse_ip(packet), Err(wire::ParseError::Fragment)) {
            let peer = self.fragment_peer(scope, packet, path)?;
            let (packet, peer) = match endpoints.reassemble_for_dispatch_on(
                realm.owner(0).expect("owner zero"),
                packet,
                ingress_at,
                Instant::now(),
                peer.clone(),
            ) {
                Ok(Some(packet)) => packet,
                Ok(None) | Err(_) => return Ok(PacketReceive::default()),
            };
            let path = peer.as_ref().map(PeerHold::original_path).unwrap_or(path);
            let ingress_at = packet.completion_ingress();
            let owner =
                &realm.owners()[realm.worker_for_packet(PacketView::from_slice(packet.as_ref()))];
            if owner.worker() == worker {
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
            let cell = cell
                .or_else(|| self.pool.take())
                .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
            let envelope = Envelope {
                ingress: self.placement(scope)?.ingress,
                scope,
                path,
                ingress_at,
                cell,
                body: Some(PacketBody::Reassembled(packet)),
                peer,
                l3_offset: 0,
                l3_length: 0,
                payload: Payload::Endpoint {
                    owner: owner.clone(),
                    admission,
                },
            };
            self.send(owner.worker(), envelope)
                .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            return Ok(PacketReceive::default());
        }
        let owner = &realm.owners()[realm.worker_for_packet(PacketView::from_slice(packet))];
        if owner.worker() == worker {
            return self.receive(
                endpoints,
                owner,
                packet,
                ingress_at,
                Instant::now(),
                path,
                admission,
            );
        }
        let mut cell = match cell {
            Some(cell) => cell,
            None => self
                .pool
                .take()
                .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?,
        };
        cell.copy(&[packet], &[])?;
        let envelope = Envelope {
            ingress: self.placement(scope)?.ingress,
            scope,
            path,
            ingress_at,
            l3_offset: 0,
            l3_length: packet.len(),
            cell,
            body: None,
            peer: None,
            payload: Payload::Endpoint {
                owner: owner.clone(),
                admission,
            },
        };
        self.send(owner.worker(), envelope)
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        Ok(PacketReceive::default())
    }

    pub(super) fn ready(&self, worker: u8) {
        self.states[worker as usize].lock().ready = true;
        self.wake[0].notify_one();
    }

    pub(super) fn all_ready(&self, cx: &mut Context<'_>) -> Poll<anyhow::Result<()>> {
        for state in self.states.iter().take(usize::from(self.workers)) {
            let state = state.lock();
            if state.failure.is_some() || state.exited {
                return Poll::Ready(Err(anyhow::anyhow!("XDP worker failed before readiness")));
            }
            if !state.ready {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        Poll::Ready(Ok(()))
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

fn selected_worker(realm: &crate::control::netstack::PacketRealm, view: PacketView<'_>) -> usize {
    realm.worker_for_packet(view)
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
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        thread_shared.failed(1, error.into());
                        std::mem::forget((owned, realms, endpoints, receiver));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let mut worker = WorkerRuntime {
                        shared: Arc::clone(&thread_shared),
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
                    let result = std::panic::AssertUnwindSafe(worker.run())
                        .catch_unwind()
                        .await;
                    match result {
                        Ok(Ok(())) => {
                            thread_shared.states[1].lock().exited = true;
                            thread_shared.wake_worker(0);
                        }
                        Ok(Err(error)) => {
                            thread_shared.failed(1, error);
                            std::mem::forget(worker);
                            std::future::pending::<()>().await;
                        }
                        Err(_) => {
                            thread_shared.failed(
                                1,
                                anyhow::anyhow!("XDP worker 1 panicked; retaining actual owners"),
                            );
                            std::mem::forget(worker);
                            std::future::pending::<()>().await;
                        }
                    }
                });
            });
        let thread = match thread {
            Ok(thread) => thread,
            Err(error) => {
                std::mem::forget(pending.lock().take());
                return Err(error);
            }
        };
        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }

    pub(super) async fn join(&mut self) -> anyhow::Result<()> {
        {
            let mut state = self.shared.states[1].lock();
            self.shared.closing.store(true, Ordering::Release);
            state.stop = true;
        }
        self.shared.wake_worker(1);
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
        packet: Packet,
        ingress_at: Instant,
        path: ReturnPath,
        admission: Option<EndpointAdmission>,
        cell: Option<Cell>,
        peer: Option<PeerHold>,
    ) -> io::Result<PacketReceive> {
        let owner = endpoints.execution_owner(scope, PacketView::from_slice(packet.as_ref()))?;
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
        let cell = cell
            .or_else(|| self.pool.take())
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        let envelope = Envelope {
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
    ) -> io::Result<PacketReceive> {
        if matches!(
            wire::parse_ip(envelope.ip()),
            Err(wire::ParseError::Fragment)
        ) {
            let placement = self.placement(envelope.scope)?;
            let (packet, peer) = match endpoints.reassemble_for_dispatch_on(
                placement.realm.owner(0).unwrap(),
                envelope.ip(),
                envelope.ingress_at,
                Instant::now(),
                envelope.peer.clone(),
            ) {
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
        let owner =
            endpoints.execution_owner(envelope.scope, PacketView::from_slice(envelope.ip()))?;
        if owner.worker() == 0 {
            return self.receive(
                endpoints,
                owner,
                envelope.ip(),
                envelope.ingress_at,
                Instant::now(),
                envelope.path,
                None,
            );
        }
        envelope.payload = Payload::Endpoint {
            owner: owner.clone(),
            admission: None,
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
            let payload = std::mem::replace(&mut envelope.payload, Payload::Ingress);
            let result = match payload {
                Payload::Endpoint { owner, admission } => self.workers.receive(
                    &self.endpoints,
                    &owner,
                    envelope.ip(),
                    envelope.ingress_at,
                    now,
                    envelope.path,
                    admission,
                ),
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
                        self.workers.dispatch_envelope(&self.endpoints, envelope)
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
            self.admission.store(false, Ordering::Release);
            self.shutdown.request();
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

pub(super) async fn run_coordinator(
    plane: ControlPlane,
    pin_root: &Path,
    admission: Arc<AtomicBool>,
    pname_support: crate::ebpf::PnameSupportCell,
) -> (Option<ControlPlane>, anyhow::Result<()>) {
    let shared_runtime = tokio::runtime::Handle::current();
    let shutdown = plane.shutdown_intent();
    let pin_root = pin_root.to_owned();
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
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = send.send((Some(plane), Err(error.into())));
                    return;
                }
            };
            let result = runtime
                .block_on(
                    std::panic::AssertUnwindSafe(super::run_capture(
                        plane,
                        &pin_root,
                        thread_admission,
                        pname_support,
                        runtime_handle,
                    ))
                    .catch_unwind(),
                )
                .unwrap_or_else(|_| {
                    (
                        None,
                        Err(anyhow::anyhow!(
                            "XDP coordinator panicked; retaining actual owners"
                        )),
                    )
                });
            let retained = result.0.is_none() && result.1.is_err();
            let _ = send.send(result);
            if retained {
                runtime.block_on(std::future::pending::<()>());
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
