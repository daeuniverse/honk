//! Device-owned protocol state. The shared endpoint carries commands and original output receipts.
use super::remote::RemoteChunkPool;
use super::*;
use crate::connection_tracker::CloseSignal;
use crate::sniffing::{MAX_CLIENT_HELLO_SIZE, SNIFF_TIMEOUT, SniffResult};
use crate::xdp::worker::{
    PeerHold,
    direct::{DirectAttach, DirectHandle, DirectReactor},
};
use futures::task::AtomicWaker;
use honk_netstack::{StreamError, TcpState};
use std::collections::{BTreeMap, HashMap, HashSet, LinkedList, VecDeque};
use std::sync::{
    Weak,
    atomic::{AtomicBool, AtomicU8, AtomicU64},
};
use std::task::Wake;
use tokio::sync::oneshot;

const UDP_FRAMES: usize = 256;
const UDP_BYTES: usize = 2 << 20;
const QUOTA: usize = 256 << 10;
const CLOSE: u8 = 1;
const ABORT: u8 = 2;
const ADMITTED: u8 = 4;
const DIRECT_CLAIMED: u8 = 8;
const ESTABLISHED: u8 = 1;
const TERMINAL: u8 = 2;
const RETIRED: u8 = 4;
const CANCELLED: u8 = 8;
const FAILED: u8 = 16;
const FLOW_SIGNAL_BYTES: usize = size_of::<FlowSignal>() + 384;

struct Reply {
    source: SocketAddr,
    client: SocketAddr,
    peer: Option<PeerHold>,
    payload: Box<[u8]>,
    done: oneshot::Sender<io::Result<usize>>,
    _memory: MemoryReservation,
}
struct Replies {
    frames: usize,
    queue: VecDeque<Reply>,
    bytes: usize,
    closed: bool,
}

type Returned = (Queued, Option<Box<[u8]>>);

pub(super) struct LocalShared {
    wake: AtomicWaker,
    admission: AtomicU8,
    shutdown: AtomicU8,
    failed: AtomicBool,
    ready: Mutex<VecDeque<FlowId>>,
    has_ready: AtomicBool,
    returns: Mutex<VecDeque<Returned>>,
    has_returns: AtomicBool,
    callbacks: Mutex<LinkedList<(LocalFlow, Option<RetirementCallback>)>>,
    replies: Mutex<Replies>,
    has_replies: AtomicBool,
    abandoned: Mutex<Option<Box<LocalOwner>>>,
    remote_backpressure: Arc<AtomicU64>,
    pool: Arc<RemoteChunkPool>,
    udp_queue_full: AtomicU64,
    snapshot: Mutex<(Option<StackStats>, bool)>,
    retained: Arc<Mutex<SourceView>>,
    window_growth: OnceLock<MemoryReservation>,
    _memory: MemoryReservation,
}

impl LocalShared {
    pub(super) fn reserve(&self, bytes: usize) -> Option<MemoryReservation> {
        self.pool.reserve(bytes)
    }

    pub(super) fn drain_pool(&self) {
        self.pool.drain();
    }

    pub(super) fn accepting(&self, open: bool) {
        self.admission
            .store(if open { 1 } else { 2 }, Ordering::Release);
        self.wake.wake();
    }
    pub(super) fn shutdown(&self, abort: bool) {
        self.shutdown
            .fetch_max(if abort { 2 } else { 1 }, Ordering::AcqRel);
        let rejected = {
            let mut replies = self.replies.lock();
            replies.closed = true;
            let queued = std::mem::take(&mut replies.queue);
            self.has_replies.store(false, Ordering::Release);
            replies.frames -= queued.len();
            replies.bytes -= queued
                .iter()
                .map(|reply| reply.payload.len())
                .sum::<usize>();
            queued
        };
        drop(rejected);
        self.wake.wake();
    }
    pub(super) fn deliver_callbacks(&self) {
        let mut outcome = Ok(());
        loop {
            let retired = self.callbacks.lock().pop_front();
            let Some((flow, callback)) = retired else {
                break;
            };
            if let Some(cb) = callback {
                outcome = outcome.and(catch_unwind(AssertUnwindSafe(cb.callback)));
            }
            flow.0.status.fetch_or(RETIRED, Ordering::Release);
            flow.0.changed.notify_waiters();
        }
        resume_wake_panic(outcome);
    }
    pub(super) async fn send_udp(
        &self,
        sender: &DatagramSender,
        payload: &[u8],
        client: SocketAddr,
    ) -> io::Result<usize> {
        let (rx, wake) = {
            let mut replies = self.replies.lock();
            if replies.closed {
                return Err(if self.failed() {
                    worker_failed()
                } else {
                    closed()
                });
            }
            if replies.frames == UDP_FRAMES || payload.len() > UDP_BYTES - replies.bytes {
                self.udp_queue_full.fetch_add(1, Ordering::Relaxed);
                return Err(capacity());
            }
            let charge = payload
                .len()
                .checked_add(size_of::<Reply>() + 128)
                .ok_or_else(capacity)?;
            let memory = self.reserve(charge).ok_or_else(capacity)?;
            let (done, rx) = oneshot::channel();
            let was_empty = replies.queue.is_empty();
            replies.bytes += payload.len();
            replies.frames += 1;
            replies.queue.push_back(Reply {
                source: sender.source,
                client,
                peer: sender
                    .packet_source
                    .as_ref()
                    .and_then(SourceWork::peer)
                    .cloned(),
                payload: payload.into(),
                done,
                _memory: memory,
            });
            if was_empty {
                self.has_replies.store(true, Ordering::Release);
            }
            (rx, was_empty)
        };
        if wake {
            self.wake.wake();
        }
        struct ReplyWait<'a> {
            rx: oneshot::Receiver<io::Result<usize>>,
            wake: Option<&'a AtomicWaker>,
        }
        impl Drop for ReplyWait<'_> {
            fn drop(&mut self) {
                if let Some(wake) = self.wake {
                    self.rx.close();
                    wake.wake();
                }
            }
        }
        let mut wait = ReplyWait {
            rx,
            wake: Some(&self.wake),
        };
        let result = (&mut wait.rx).await;
        wait.wake = None;
        result.map_err(|_| {
            if self.failed() {
                worker_failed()
            } else {
                closed()
            }
        })?
    }
}

pub(super) struct SlotIndex {
    active: Box<[Option<(FlowId, usize)>]>,
    retiring_aliases: FlowIdMap<usize>,
    len: usize,
    limit: usize,
}

impl SlotIndex {
    fn new(max_slots: usize, frames: usize) -> Self {
        let limit = max_slots + frames;
        Self {
            active: vec![None; max_slots].into_boxed_slice(),
            retiring_aliases: FlowIdMap::with_capacity_and_hasher(limit, Default::default()),
            len: 0,
            limit,
        }
    }

    fn active(&self, id: &FlowId) -> Option<&usize> {
        let (current, index) = self.active.get(id.index())?.as_ref()?;
        (current == id).then_some(index)
    }

    pub(super) fn get(&self, id: &FlowId) -> Option<&usize> {
        self.active(id).or_else(|| self.retiring_aliases.get(id))
    }

    pub(super) fn insert(&mut self, id: FlowId, index: usize) {
        assert!(self.len < self.limit, "funded flow metadata full");
        if let Some((old, old_index)) = self.active[id.index()].replace((id, index)) {
            // A reused protocol slot can still owe a queued control or an exported frame.
            assert_ne!(old, id);
            assert!(self.retiring_aliases.insert(old, old_index).is_none());
        }
        self.len += 1;
    }

    fn move_to_alias(&mut self, id: FlowId) {
        if let Some(index) = self.active(&id).copied() {
            self.active[id.index()] = None;
            assert!(self.retiring_aliases.insert(id, index).is_none());
        }
    }

    fn remove(&mut self, id: &FlowId) {
        if self.active(id).is_some() {
            self.active[id.index()] = None;
        } else {
            assert!(self.retiring_aliases.remove(id).is_some());
        }
        self.len -= 1;
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }
}

enum FlowWork {
    App,
    Protocol(Ready),
    Deadline,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LocalTurn {
    Idle,
    Armed,
    Unarmed,
}

pub(crate) struct LocalOwner {
    pub(super) inner: Inner,
    pub(super) turn: LocalTurn,
    direct: DirectReactor,
    bindings: Box<[Option<Binding>]>,
    tuples: HashMap<(SocketAddr, SocketAddr), FlowId>,
    retiring: Vec<FlowId>,
    writer_retry: Option<Instant>,
    // Only sniffing and globally credit-blocked remote streams enter this ordered set.
    deadlines: BTreeMap<(Instant, usize), FlowId>,
    // The sole publisher keeps its last exact value. make_local funds the owner inline.
    published_snapshot: (Option<StackStats>, bool),
}

struct Binding {
    handle: LocalFlow,
    remote: Option<remote::RemoteOwner>,
    direct: Option<DirectHandle>,
    closing: bool,
    deadline: Option<Instant>,
    sniff: Option<oneshot::Sender<io::Result<SniffResult>>>,
}

impl Binding {
    fn schedule(
        &mut self,
        deadlines: &mut BTreeMap<(Instant, usize), FlowId>,
        at: Option<Instant>,
    ) {
        if self.deadline == at {
            return;
        }
        // A live binding owns this allocation until its last deadline has been removed.
        let key = Arc::as_ptr(&self.handle.0) as usize;
        if let Some(old) = self.deadline {
            deadlines.remove(&(old, key));
        }
        if let Some(at) = at {
            deadlines.insert((at, key), self.handle.0.id);
        }
        self.deadline = at;
    }
}

enum Request {
    Sniff(oneshot::Sender<io::Result<SniffResult>>),
    Remote(
        Option<remote::RemoteCounters>,
        oneshot::Sender<io::Result<remote::RemoteEndpoint>>,
    ),
    Direct(DirectAttach, Option<oneshot::Sender<io::Result<()>>>),
}

struct LocalRetirement {
    callback: RetirementCallback,
    on_failure: Option<Arc<CloseSignal>>,
}

struct FlowSignal {
    scope: Weak<Shared>,
    id: FlowId,
    flags: AtomicU8,
    status: AtomicU8,
    queued: AtomicBool,
    detached: AtomicBool,
    changed: Notify,
    request: Mutex<Option<Request>>,
    callback: Mutex<Option<LocalRetirement>>,
    _memory: MemoryReservation,
}
impl Wake for FlowSignal {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        if self.detached.load(Ordering::Acquire) || self.queued.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(shared) = self.scope.upgrade()
            && let Some(local) = shared.local.get()
        {
            let mut ready = local.ready.lock();
            if self.detached.load(Ordering::Acquire) {
                return;
            }
            let wake = ready.is_empty();
            ready.push_back(self.id);
            local.has_ready.store(true, Ordering::Release);
            drop(ready);
            if wake {
                local.wake.wake();
            }
        }
    }
}
#[derive(Clone)]
pub(crate) struct LocalFlow(Arc<FlowSignal>);
impl fmt::Debug for LocalFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LocalFlow").field(&self.0.id).finish()
    }
}
impl LocalFlow {
    fn set(&self, bit: u8) {
        self.0.flags.fetch_or(bit, Ordering::Release);
        self.0.wake_by_ref();
    }
    pub(crate) fn abort(&self) {
        self.set(ABORT);
    }
    pub(crate) fn cancel_direct(&self) {
        // Exact retirement also resolves CloseSignal. Never reset a flow whose pump
        // already published its final close, even if that notification wins the race.
        if self
            .0
            .flags
            .try_update(Ordering::AcqRel, Ordering::Acquire, |flags| {
                (flags & (CLOSE | ABORT) == 0).then_some(flags | ABORT)
            })
            .is_ok()
        {
            self.0.wake_by_ref();
        }
    }
    fn claim_direct(&self) -> bool {
        // This transition and cancel_direct's ABORT share one modification order.
        // Only a successful claim may hand the buffered prefix and socket to the pump.
        self.0
            .flags
            .try_update(Ordering::AcqRel, Ordering::Acquire, |flags| {
                (flags & (CLOSE | ABORT | DIRECT_CLAIMED) == 0).then_some(flags | DIRECT_CLAIMED)
            })
            .is_ok()
    }
    pub(crate) fn close(&self) {
        if self.0.flags.fetch_or(CLOSE, Ordering::AcqRel) & CLOSE == 0 {
            self.0.wake_by_ref();
        }
    }
    pub(crate) fn mark_rx_admitted(&self) {
        self.set(ADMITTED);
    }
    pub(crate) fn reserve(&self, bytes: usize) -> Option<MemoryReservation> {
        self.0.scope.upgrade()?.local.get()?.reserve(bytes)
    }
    pub(crate) fn reserve_direct(&self) -> Option<MemoryReservation> {
        DirectAttach::credit(|bytes| self.reserve(bytes))
    }
    pub(super) fn set_retirement_callback(
        &self,
        callback: RetirementCallback,
        on_failure: Option<Arc<CloseSignal>>,
    ) -> io::Result<()> {
        let mut cell = self.0.callback.lock();
        if self.0.status.load(Ordering::Acquire) & FAILED != 0 {
            return Err(worker_failed());
        }
        if self.0.detached.load(Ordering::Acquire) {
            return Err(closed());
        }
        if cell.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "retirement callback already installed",
            ));
        }
        *cell = Some(LocalRetirement {
            callback,
            on_failure,
        });
        Ok(())
    }
    fn mark_terminal(&self) {
        // An established flow's remaining waiters need the exact retirement callback.
        if self.0.status.fetch_or(TERMINAL, Ordering::Release) & (ESTABLISHED | TERMINAL) == 0 {
            self.0.changed.notify_waiters();
        }
    }
    async fn status(&self, bit: u8) -> io::Result<()> {
        loop {
            // notify_waiters is observed from creation, even before the first poll.
            let notified = self.0.changed.notified();
            let state = self.0.status.load(Ordering::Acquire);
            if state & FAILED != 0 {
                return Err(worker_failed());
            }
            if state & bit != 0 {
                return Ok(());
            }
            if bit == ESTABLISHED && state & TERMINAL != 0 {
                return Err(closed());
            }
            notified.await;
        }
    }
    pub(crate) async fn wait_established(&self) -> io::Result<()> {
        self.status(ESTABLISHED).await
    }
    pub(crate) async fn wait(&self) -> io::Result<()> {
        self.status(RETIRED).await
    }
    fn unavailable(&self) -> io::Error {
        if self.0.status.load(Ordering::Acquire) & FAILED != 0 {
            worker_failed()
        } else {
            closed()
        }
    }
    fn can_bind(&self) -> bool {
        let state = self.0.status.load(Ordering::Acquire);
        !self.0.detached.load(Ordering::Acquire)
            && state & (RETIRED | CANCELLED | FAILED) == 0
            && state & ESTABLISHED != 0
    }
    async fn request<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<io::Result<T>>) -> Request,
    ) -> io::Result<T> {
        let rx = {
            let mut request = self.0.request.lock();
            if !self.can_bind() {
                return Err(self.unavailable());
            }
            if request.is_some() {
                return Err(invalid("concurrent TCP binding requests"));
            }
            let (tx, rx) = oneshot::channel();
            *request = Some(make(tx));
            rx
        };
        self.0.wake_by_ref();
        rx.await.map_err(|_| self.unavailable())?
    }
    pub(crate) async fn sniff(&self) -> io::Result<SniffResult> {
        self.request(Request::Sniff).await
    }
    pub(super) async fn attach_remote(
        &self,
        counters: Option<remote::RemoteCounters>,
    ) -> io::Result<remote::RemoteEndpoint> {
        self.request(|done| Request::Remote(counters, done)).await
    }
    pub(crate) fn submit_direct(&self, attach: DirectAttach) -> io::Result<()> {
        self.queue_direct(attach, None)
    }
    #[cfg(test)]
    pub(crate) async fn attach_direct(&self, attach: DirectAttach) -> io::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.queue_direct(attach, Some(tx))?;
        rx.await.map_err(|_| self.unavailable())?
    }
    fn queue_direct(
        &self,
        attach: DirectAttach,
        done: Option<oneshot::Sender<io::Result<()>>>,
    ) -> io::Result<()> {
        let mut request = self.0.request.lock();
        if !self.can_bind() || self.0.flags.load(Ordering::Acquire) & (CLOSE | ABORT) != 0 {
            drop(request);
            attach.cancel();
            return Err(self.unavailable());
        }
        if request.is_some() {
            drop(request);
            attach.reject();
            return Err(io::ErrorKind::WouldBlock.into());
        }
        *request = Some(Request::Direct(attach, done));
        drop(request);
        self.0.wake_by_ref();
        Ok(())
    }
}

fn new_local_ledger(
    config: FrameConfig,
    budget: &Arc<MemoryBudget>,
    pool: &RemoteChunkPool,
) -> Result<FrameLedger<Option<FlowId>>, honk_datapath::buffer::LedgerError> {
    match FrameLedger::new(config, budget) {
        Err(honk_datapath::buffer::LedgerError::BudgetExhausted) => {
            pool.drain();
            FrameLedger::new(config, budget)
        }
        result => result,
    }
}

impl PacketScope {
    pub(crate) fn is_local(&self) -> bool {
        self.0.local.get().is_some()
    }
    pub(crate) fn local_failed(&self) -> bool {
        self.0.local.get().is_some_and(|local| local.failed())
    }
    pub(super) fn local_source_work(&self, address: IpAddr) -> io::Result<Option<SourceWork>> {
        let mut parked = self.0.inner.lock();
        if parked.closing || parked.finished {
            return Ok(None);
        }
        SourceWork::plain(self, &mut parked, address).map(Some)
    }
}

impl OutputOwner {
    pub(super) fn return_local(&mut self) -> bool {
        let Some(local) = self.scope.0.local.get() else {
            return false;
        };
        if let Some(queued) = self.queued.take() {
            self.local_peer.take();
            let mut returns = local.returns.lock();
            returns.push_back((queued, self.bytes.take()));
            local.has_returns.store(true, Ordering::Release);
            drop(returns);
            local.wake.wake();
        }
        true
    }
}

impl PacketDriver {
    pub(crate) fn is_local(&self) -> bool {
        self.local.is_some()
    }
    pub(crate) fn fail_local_applications(&mut self) {
        let Some(owner) = &mut self.local else {
            return;
        };
        if owner.inner.finished {
            return;
        }
        let shared = self.scope.0.local.get().expect("local driver failure");
        if shared.failed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(gate) = &owner.inner.capture_admission {
            gate.store(false, Ordering::Release);
        }
        {
            let mut parked = self.scope.0.inner.lock();
            parked.closing = true;
            parked.rights = Rights::Abandoned;
        }
        shared.pool.close();
        owner.close_direct();
        shared.shutdown(true);
        for binding in owner.bindings.iter_mut().flatten() {
            let state = &binding.handle.0;
            let on_failure = {
                let mut pending = state.callback.lock();
                state.status.fetch_or(TERMINAL | FAILED, Ordering::Release);
                // Failure answers the close request; the callback still owns unreturned output.
                pending.as_mut().and_then(|p| p.on_failure.take())
            };
            if let Some(signal) = on_failure {
                signal.finish(false);
            }
            if let Some(remote) = binding.remote.take() {
                remote.fail(StreamError::Reset);
            }
            let request = state.request.lock().take();
            if let Some(Request::Direct(attach, _)) = request {
                attach.cancel();
            }
            binding.sniff.take();
            state.detached.store(true, Ordering::Release);
            state.changed.notify_waiters();
        }
        self.scope.0.owner_wake.notify_one();
    }
    pub(crate) fn owner_scope(&self) -> &PacketScope {
        &self.scope
    }
    pub(crate) fn complete_local(&mut self, output: &mut OutputOwner) -> bool {
        let Some(owner) = &mut self.local else {
            return false;
        };
        if !self.scope.same_owner(&output.scope) {
            return false;
        }
        if let Some(queued) = output.queued.take() {
            output.local_peer.take();
            owner.complete(queued, output.bytes.take());
        }
        true
    }
    #[cfg(test)]
    pub(crate) fn local_direct_attached(
        &self,
        client: SocketAddr,
        destination: SocketAddr,
    ) -> bool {
        self.local.as_ref().is_some_and(|owner| {
            owner
                .tuples
                .get(&(client, destination))
                .and_then(|id| owner.active_slot(*id))
                .and_then(|index| owner.bindings[index].as_ref())
                .is_some_and(|binding| binding.direct.is_some())
        })
    }
    pub(crate) fn make_local(&mut self, total_pools: usize) -> io::Result<()> {
        let shared = &self.scope.0;
        let mut guard = shared.inner.lock();
        if guard.rights != Rights::Driven
            || guard.closing
            || guard.aborted
            || shared.auxiliary.is_some()
            || guard.finished
            || self.local.is_some()
            || guard
                .capture_admission
                .as_ref()
                .is_some_and(|gate| gate.load(Ordering::Acquire))
            || shared.local.get().is_some()
            || guard
                .resources
                .as_ref()
                .is_none_or(|resources| !resources.tracks_tcp())
            || guard.source_work.is_host()
            || guard.queued != 0
            || guard.slots.iter().any(Option::is_some)
            || !guard.ledger.drain_state().is_drained()
            || guard.waiters.iter().any(Option::is_some)
            || !guard.source_work.is_empty()
            || !guard.stack.as_ref().is_some_and(|s| {
                s.is_quiescent() && s.stats().rx_packets == 0 && s.stats().tx_packets == 0
            })
        {
            return Err(invalid(
                "local handoff requires the original unused physical driver",
            ));
        }
        let budget = &shared.budget;
        let pool = RemoteChunkPool::new(budget, total_pools)?;
        let slots = guard.slots.len();
        let max_slots = guard.half_open.len();
        let frames = guard.frames.len();
        let peers = guard.peers.len();
        let ancillary = guard
            .stack
            .as_ref()
            .expect("checked local stack")
            .pending_source_bound();
        let bytes = window_bytes(slots, frames, peers, ancillary)
            .and_then(|n| {
                n.checked_add(
                    UDP_FRAMES * size_of::<Reply>()
                        + size_of::<LocalOwner>()
                        + size_of::<LocalShared>(),
                )
            })
            .ok_or_else(capacity)?;
        let memory = pool.reserve(bytes).ok_or_else(capacity)?;
        let direct = DirectReactor::new(max_slots, |bytes| pool.reserve(bytes))?;
        // The parked scope still owns plain SourceWork counters and its original join right.
        // A closed ledger refuses all shared output grants while the physical device owns its pool.
        let ledger_config = FrameConfig {
            base_address: 0,
            frame_size: 1,
            rx_frames: 0,
            control_frames: 1,
            bulk_frames: 1,
            fill_capacity: 0,
            rx_capacity: 0,
            control_descriptors: 1,
            bulk_descriptors: 1,
            tx_capacity: 2,
            completion_capacity: 2,
        };
        let mut ledger =
            new_local_ledger(ledger_config, budget, &pool).map_err(io::Error::other)?;
        ledger.close();
        let parked = Inner {
            local_slots: None,
            local_pending: Vec::new(),
            worker: guard.worker,
            rights: Rights::Driven,
            stack: None,
            ledger,
            frames: Box::default(),
            output_peers: Box::default(),
            output_peer_holds: Box::default(),
            source_work: Sources::new(0),
            #[cfg(feature = "packet-ebpf")]
            host_process: None,
            queue: Box::default(),
            head: 0,
            queued: 0,
            exported_cpu: [0; 2],
            frame_size: guard.frame_size,
            cpu_tx_caps: TxCaps::NONE,
            next_tx: TxClass::Control,
            slots: Box::default(),
            half_open: Box::default(),
            resources: guard.resources.clone(),
            capture_admission: guard.capture_admission.clone(),
            peers: Box::default(),
            peer_end: 0,
            local_peers: None,
            fragment_peers: Box::default(),
            fragment_peer_count: 0,
            pending_closes: 0,
            closed_apps: 0,
            reap_pending: false,
            pending_routing: 0,
            waiters: Box::default(),
            credit_waiters: 0,
            tx_waiters: 0,
            output_waker: None,
            turn_needs_scan: None,
            abort_wake_end: 0,
            closing: false,
            aborted: false,
            finished: false,
            endpoint_prepared: guard.endpoint_prepared,
            _storage: pool.reserve(0).ok_or_else(capacity)?,
        };
        let snapshot = (guard.stack.as_ref().map(Stack::stats), true);
        let local = LocalShared {
            wake: AtomicWaker::new(),
            admission: AtomicU8::new(0),
            shutdown: AtomicU8::new(0),
            failed: AtomicBool::new(false),
            ready: Mutex::new(VecDeque::with_capacity(slots)),
            has_ready: AtomicBool::new(false),
            returns: Mutex::new(VecDeque::with_capacity(frames)),
            has_returns: AtomicBool::new(false),
            callbacks: Mutex::new(LinkedList::new()),
            replies: Mutex::new(Replies {
                queue: VecDeque::with_capacity(UDP_FRAMES),
                bytes: 0,
                frames: 0,
                closed: false,
            }),
            has_replies: AtomicBool::new(false),
            abandoned: Mutex::new(None),
            remote_backpressure: Arc::new(AtomicU64::new(0)),
            pool,
            udp_queue_full: AtomicU64::new(0),
            snapshot: Mutex::new(snapshot),
            retained: Arc::new(Mutex::new(SourceView::new(ancillary, frames))),
            window_growth: OnceLock::new(),
            _memory: memory,
        };
        let mut inner = std::mem::replace(&mut *guard, parked);
        std::mem::swap(&mut inner.source_work, &mut guard.source_work);
        inner.local_slots = Some(SlotIndex::new(max_slots, frames));
        inner.local_pending = Vec::with_capacity(inner.half_open.len());
        inner.local_peers = Some(LocalPeers::new(
            peers,
            slots,
            ancillary,
            Arc::clone(&local.retained),
        ));
        self.local = Some(Box::new(LocalOwner {
            inner,
            turn: LocalTurn::Idle,
            direct,
            bindings: (0..slots).map(|_| None).collect(),
            tuples: HashMap::with_capacity(slots),
            retiring: Vec::with_capacity(slots),
            writer_retry: None,
            deadlines: BTreeMap::new(),
            published_snapshot: snapshot,
        }));
        assert!(shared.local.set(Box::new(local)).is_ok());
        Ok(())
    }
    pub(crate) fn local_retains_tcp(&self, client: SocketAddr, destination: SocketAddr) -> bool {
        self.local
            .as_ref()
            .and_then(|owner| owner.inner.stack.as_ref())
            .is_some_and(|stack| stack.retains_tcp_with_lineage(client, destination, None))
    }
    pub(crate) fn local_peer_hold(&self, address: IpAddr) -> Option<PeerHold> {
        let state = &self.local.as_ref()?.inner;
        state.peer_hold_at(address).cloned()
    }
    pub(crate) fn reassemble_for_dispatch_with_peer(
        &mut self,
        packet: &[u8],
        ingress_at: Instant,
        service_at: Instant,
        peer: Option<PeerHold>,
    ) -> Result<Option<(honk_netstack::OwnedPacket, Option<PeerHold>)>, DropReason> {
        let owner = self.local.as_mut().ok_or(DropReason::Stale)?;
        if self.scope.local_failed() {
            return Err(DropReason::Stale);
        }
        owner.prepare_rx(&self.scope, service_at);
        if owner.inner.worker != 0 {
            return Err(DropReason::NotForUs);
        }
        let source = packet_source(packet);
        let shared = self.scope.0.local.get().expect("physical owner");
        let _source_update = shared.source_update(source);
        let result = owner
            .inner
            .reassemble_for_dispatch_with_peer(packet, ingress_at, service_at, peer);
        owner.refresh_pending_source(source);
        result
    }
    pub(in crate::control) fn receive_realm_timed(
        &mut self,
        packet: &[u8],
        ingress_at: Instant,
        service_at: Instant,
        admission: &mut Option<super::super::packet_endpoint::EndpointAdmission>,
        check_output: bool,
        mut on_source: impl FnMut(honk_netstack::ValidatedSource, bool) -> Option<PeerHold>,
    ) -> io::Result<(
        Rx,
        super::super::packet_endpoint::PacketReceive,
        Option<SourceWork>,
    )> {
        let owner = self.local.as_mut().ok_or_else(closed)?;
        if self.scope.local_failed() {
            return Err(worker_failed());
        }
        owner.prepare_rx(&self.scope, service_at);
        let source = packet_source(packet);
        let shared = self.scope.0.local.get().expect("physical owner");
        let _source_update = shared.source_update(source);
        let budget = &self.scope.0.budget;
        let floor = owner
            .inner
            .stack
            .as_ref()
            .map_or(0, Stack::passive_floor_bytes);
        let result = owner.inner.receive_realm_timed(
            &self.scope,
            packet,
            ingress_at,
            service_at,
            admission,
            check_output,
            |source, pending| {
                use honk_netstack::wire::tcp::{ACK, FIN, RST, SYN};

                let peer = on_source(source, pending);
                if peer.is_some()
                    && source
                        .tcp_flags
                        .is_some_and(|flags| flags & (SYN | ACK | RST | FIN) == SYN)
                    && budget.limit().saturating_sub(budget.used()) < floor
                {
                    shared.drain_pool();
                }
                peer
            },
        );
        owner.refresh_pending_source(source);
        result
    }
    pub(crate) fn poll_accept_local(&mut self) -> io::Result<Option<(SynInfo, FlowIo)>> {
        let owner = self.local.as_mut().ok_or_else(closed)?;
        let inner = &mut owner.inner;
        let local = self.scope.0.local.get().expect("local driver");
        if inner.closing || local.shutdown.load(Ordering::Acquire) != 0 {
            return Ok(None);
        }
        let Some(stack) = inner.stack.as_mut() else {
            return Ok(None);
        };
        let Some(syn) = stack.poll_accept() else {
            return Ok(None);
        };
        let Some(memory) = local.reserve(FLOW_SIGNAL_BYTES) else {
            inner.reap_pending = true;
            stack.tcp_refuse(syn.id, honk_netstack::Refuse::Drop);
            return Ok(None);
        };
        if local.shutdown.load(Ordering::Acquire) != 0 {
            inner.reap_pending = true;
            stack.tcp_refuse(syn.id, honk_netstack::Refuse::Drop);
            return Ok(None);
        }
        if stack.tcp_accept(syn.id, AcceptOpts::default()).is_err() {
            stack.tcp_abort(syn.id);
            stack.tcp_close(syn.id);
            inner.reap_pending = true;
            return Ok(None);
        }
        let handle = LocalFlow(Arc::new(FlowSignal {
            scope: Arc::downgrade(&self.scope.0),
            id: syn.id,
            flags: AtomicU8::new(0),
            status: AtomicU8::new(0),
            queued: AtomicBool::new(false),
            detached: AtomicBool::new(false),
            changed: Notify::new(),
            request: Mutex::new(None),
            callback: Mutex::new(None),
            _memory: memory,
        }));
        let index = inner.slot_index(syn.id).expect("admitted original SYN");
        let slot = inner.slots[index].as_mut().expect("funded local flow");
        slot.accepted = true;
        let routing = slot.routing.take();
        let process = slot.process.take();
        inner.pending_routing -= 1;
        if let Some(i) = inner.local_pending.iter().position(|&id| id == syn.id) {
            inner.local_pending.swap_remove(i);
        }
        let mut flow = FlowIo::new_local(self.scope.clone(), syn, handle.clone(), process);
        flow.set_routing(routing);
        owner.tuples.insert((syn.client, syn.original_dst), syn.id);
        let previous = owner.bindings[index].replace(Binding {
            handle,
            remote: None,
            direct: None,
            closing: false,
            deadline: None,
            sniff: None,
        });
        assert!(previous.is_none(), "physical binding slot already occupied");
        Ok(Some((syn, flow)))
    }
    pub(crate) fn begin_local_turn(&mut self, cx: &Context<'_>, now: Instant) {
        if let Some(owner) = &mut self.local {
            owner.start_turn(&self.scope, now, Some(cx));
        }
    }
    pub(crate) fn local_turn_open(&self) -> bool {
        self.local
            .as_ref()
            .is_some_and(|owner| owner.turn != LocalTurn::Idle)
    }
    #[cfg(all(test, feature = "native-api"))]
    pub(crate) fn has_submitted_direct(&self) -> bool {
        self.local.as_ref().is_some_and(|owner| {
            owner.bindings.iter().flatten().any(|binding| {
                matches!(
                    binding.handle.0.request.lock().as_ref(),
                    Some(Request::Direct(_, None))
                )
            })
        })
    }
    #[cfg(all(test, feature = "native-api"))]
    pub(crate) fn close_local_direct(&mut self) {
        self.local.as_mut().expect("local driver").close_direct();
    }
    pub(crate) fn bind_worker_epoll(
        &mut self,
        epoll: Arc<crate::xdp::worker::epoll::BudgetedEpollFd>,
        realm_index: usize,
    ) -> io::Result<()> {
        if let Some(owner) = &mut self.local {
            owner.direct.bind_worker_epoll(epoll, realm_index)?;
        }
        Ok(())
    }
    pub(crate) fn direct_socket_ready(&mut self, token: u64, events: u32) {
        if let Some(owner) = &mut self.local {
            owner.direct.socket_ready(token, events);
        }
    }
    pub(crate) fn direct_epoll_waiters(&self) -> usize {
        self.local
            .as_ref()
            .map_or(0, |owner| owner.direct.epoll_waiters())
    }
    pub(crate) fn poll_local_io(&mut self, cx: &mut Context<'_>, now: Instant) -> io::Result<bool> {
        let ready = match &mut self.local {
            Some(owner) => owner.direct.poll_ready(cx)?,
            None => return Ok(false),
        };
        Ok(self.poll_local_io_sync(cx, now)? || ready)
    }
    pub(crate) fn poll_local_io_sync(
        &mut self,
        cx: &mut Context<'_>,
        now: Instant,
    ) -> io::Result<bool> {
        let Some(owner) = self.local.as_deref_mut() else {
            return Ok(false);
        };
        let shared = self.scope.0.local.get().expect("local driver");
        if shared.failed() {
            return Err(worker_failed());
        }
        let standalone = owner.turn == LocalTurn::Idle;
        owner.start_turn(&self.scope, now, Some(cx));
        let more = owner.dispatch(&self.scope, now);
        let socket = if owner.inner.stack.is_some() {
            let mut turn = owner.direct.begin_service().inspect_err(|_| {
                if standalone {
                    owner.turn = LocalTurn::Idle;
                }
            })?;
            while let Some((id, publish)) = owner.direct.next_finished(
                owner.inner.stack.as_mut().expect("live local stack"),
                now,
                &mut turn,
            ) {
                let index = owner.active_slot(id).expect("attached Direct flow");
                let binding = owner.bindings[index]
                    .as_mut()
                    .expect("attached Direct binding");
                assert!(binding.direct.take().is_some());
                binding.closing = true;
                binding.handle.0.flags.fetch_or(CLOSE, Ordering::Release);
                let slot = owner.inner.slot(id).expect("attached Direct slot");
                if slot.app_open {
                    slot.app_open = false;
                    owner.inner.stack.as_mut().unwrap().tcp_close(id);
                    owner.retiring.push(id);
                    owner.reap_retiring(&self.scope, owner.retiring.len() - 1);
                }
                publish();
            }
            turn.worked
        } else {
            false
        };
        if standalone {
            self.deadline = owner.finish_turn(&self.scope, cx, now);
        }
        Ok(more || socket)
    }
}

impl LocalShared {
    pub(super) fn wake_device(&self) {
        self.wake.wake();
    }
    pub(super) fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
    pub(super) fn stats(&self) -> Option<StackStats> {
        self.snapshot.lock().0
    }
    pub(super) fn quiescent(&self) -> bool {
        self.snapshot.lock().1
    }
    fn source_update(&self, address: Option<IpAddr>) -> SourceUpdate<'_> {
        if let Some(address) = address {
            let mut view = self.retained.lock();
            debug_assert!(view.publishing.is_none());
            view.publishing = Some(address.to_canonical());
        }
        SourceUpdate(address.map(|_| self.retained.as_ref()))
    }
    pub(super) fn retains_source(&self, address: IpAddr) -> bool {
        let view = self.retained.lock();
        view.publishing == Some(address.to_canonical()) || view.contains(address)
    }
    pub(super) async fn finish_abandoned(&self, scope: &PacketScope) {
        if self.failed() {
            self.deliver_callbacks();
            return;
        }
        let owner = self.abandoned.lock().take();
        let Some(mut owner) = owner else {
            self.deliver_callbacks();
            return;
        };
        poll_fn(|cx| {
            let now = Instant::now();
            owner.start_turn(scope, now, Some(cx));
            if owner.dispatch(scope, now) {
                cx.waker().wake_by_ref();
            }
            self.deliver_callbacks();
            owner.finish_turn(scope, cx, now);
            if owner.inner.finished {
                self.deliver_callbacks();
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}

impl PacketScope {
    pub(crate) fn local_counters(&self) -> Option<(u64, u64)> {
        let local = self.0.local.get()?;
        Some((
            local.udp_queue_full.load(Ordering::Relaxed),
            local.remote_backpressure.load(Ordering::Relaxed),
        ))
    }
}

impl PacketDriver {
    pub(crate) fn has_pending_accept_local(&self) -> bool {
        self.local.as_ref().is_some_and(|owner| {
            !owner.inner.closing
                && owner
                    .inner
                    .stack
                    .as_ref()
                    .is_some_and(Stack::has_pending_accept)
        })
    }
}

impl LocalOwner {
    fn refresh_pending_source(&mut self, address: Option<IpAddr>) {
        self.inner.refresh_local_pending();
        if let Some(address) = address {
            self.inner.release_unused_local_peer(address);
        }
    }
    fn complete(&mut self, queued: Queued, bytes: Option<Box<[u8]>>) {
        self.inner.release_output(queued, bytes);
    }
    pub(super) fn start_turn(
        &mut self,
        scope: &PacketScope,
        now: Instant,
        cx: Option<&Context<'_>>,
    ) {
        let shared = scope.0.local.get().expect("local owner");
        if self.turn != LocalTurn::Idle {
            self.observe_shutdown(shared, now);
            return;
        }
        self.turn = match cx {
            Some(cx) => {
                shared.wake.register(cx.waker());
                LocalTurn::Armed
            }
            None => LocalTurn::Unarmed,
        };
        self.begin(shared, now);
    }
    fn prepare_rx(&mut self, scope: &PacketScope, service_at: Instant) {
        let shared = scope.0.local.get().expect("local owner");
        if self.turn == LocalTurn::Idle {
            self.begin(shared, service_at);
        } else if !self.inner.finished {
            self.advance(shared, service_at, false);
        }
    }
    fn begin(&mut self, shared: &LocalShared, now: Instant) {
        if self.inner.finished || shared.failed() {
            return;
        }
        // The actual CQ or an explicit pre-NIC disposal put the unique original receipt here.
        if shared.has_returns.load(Ordering::Acquire) {
            let mut returned = shared.returns.lock();
            while let Some((queued, bytes)) = returned.pop_front() {
                self.complete(queued, bytes);
            }
            shared.has_returns.store(false, Ordering::Release);
        }
        self.advance(shared, now, true);
        if !self.inner.closing {
            self.reply_turn(shared);
        }
    }
    fn observe_shutdown(&mut self, shared: &LocalShared, now: Instant) {
        if !self.inner.aborted && shared.shutdown.load(Ordering::Acquire) != 0 {
            self.advance(shared, now, false);
        }
    }
    fn advance(&mut self, shared: &LocalShared, now: Instant, starting: bool) {
        if shared.admission.load(Ordering::Relaxed) != 0
            && let state @ (1 | 2) = shared.admission.swap(0, Ordering::AcqRel)
            && let Some(stack) = &mut self.inner.stack
        {
            stack.set_accepting(state == 1 && !self.inner.closing);
        }
        let shutdown = shared.shutdown.load(Ordering::Acquire);
        if shutdown != 0 && !self.inner.closing {
            self.inner.closing = true;
            if let Some(stack) = &mut self.inner.stack {
                stack.set_accepting(false);
            }
        }
        let aborting = shutdown == 2 && !self.inner.aborted;
        if aborting {
            self.abort(shared);
        }
        let timed = self
            .inner
            .stack
            .as_ref()
            .and_then(Stack::poll_timeout)
            .is_some_and(|at| at <= now);
        if self.writer_retry.is_some_and(|at| at <= now) {
            self.writer_retry = None;
        }
        // A scalar RX within a turn can carry a later service time or a new shutdown.
        if !starting && !timed && !aborting {
            return;
        }
        self.inner.advance(now);
        if timed || aborting {
            self.inner.refresh_local_pending();
            self.inner.reap_fragment_peers();
        }
    }
    fn reply_turn(&mut self, shared: &LocalShared) {
        for _ in 0..BATCH {
            if !shared.has_replies.load(Ordering::Acquire) {
                return;
            }
            let mut replies = shared.replies.lock();
            let Some(front) = replies.queue.front() else {
                return;
            };
            if front.done.is_closed() {
                let dead = replies.queue.pop_front().expect("cancelled reply");
                if replies.queue.is_empty() {
                    shared.has_replies.store(false, Ordering::Release);
                }
                replies.bytes -= dead.payload.len();
                replies.frames -= 1;
                continue;
            }
            let grant = self.inner.ledger.reserve_tx(TxClass::Bulk);
            if matches!(
                grant,
                Err(honk_datapath::buffer::LedgerError::NoDescriptor
                    | honk_datapath::buffer::LedgerError::NoFrame)
            ) {
                // Cancellation behind a head waiting for CQ must release its byte/frame quota too.
                let mut removed = 0;
                let before = replies.queue.len();
                replies.queue.retain(|r| {
                    if r.done.is_closed() {
                        removed += r.payload.len();
                        false
                    } else {
                        true
                    }
                });
                replies.bytes -= removed;
                replies.frames -= before - replies.queue.len();
                if replies.queue.is_empty() {
                    shared.has_replies.store(false, Ordering::Release);
                }
                return;
            }
            let reply = replies.queue.pop_front().expect("funded reply");
            replies.bytes -= reply.payload.len();
            replies.frames -= 1;
            if replies.queue.is_empty() {
                shared.has_replies.store(false, Ordering::Release);
            }
            drop(replies);
            let _source_update = shared.source_update(Some(reply.client.ip()));
            let result = grant.map_err(io::Error::other).and_then(|lease| {
                if let Some(peer) = &reply.peer {
                    let address = peer.address();
                    if peer.learned() && self.inner.peer_cell(address).is_none() {
                        self.inner
                            .ledger
                            .cancel_tx(lease)
                            .expect("original reply credit");
                        return Err(capacity());
                    }
                    self.inner.remember_peer(peer);
                }
                let result = self.inner.send_reserved_udp(
                    lease,
                    reply.source,
                    reply.client,
                    &reply.payload,
                    None,
                );
                if result
                    .as_ref()
                    .err()
                    .and_then(|error| error.get_ref())
                    .and_then(|error| error.downcast_ref::<UdpError>())
                    == Some(&UdpError::Busy)
                {
                    // Busy consumes no datagram and cancels its unpublished frame grant.
                    shared.drain_pool();
                    let retry = self
                        .inner
                        .ledger
                        .reserve_tx(TxClass::Bulk)
                        .expect("retry keeps the original reply grant available");
                    self.inner.send_reserved_udp(
                        retry,
                        reply.source,
                        reply.client,
                        &reply.payload,
                        None,
                    )
                } else {
                    result
                }
            });
            if result.is_err() {
                self.inner.release_unused_local_peer(reply.client.ip());
            }
            let Reply {
                done,
                payload,
                peer,
                _memory,
                ..
            } = reply;
            drop((payload, peer, _memory));
            let _ = done.send(result);
        }
        if shared.has_replies.load(Ordering::Acquire) {
            shared.wake.wake();
        }
    }
    fn abort(&mut self, shared: &LocalShared) {
        shared.pool.close();
        self.close_direct();
        self.inner.abort();
        for binding in self.bindings.iter_mut().flatten() {
            binding
                .handle
                .0
                .status
                .fetch_or(TERMINAL | CANCELLED, Ordering::Release);
            binding.handle.0.changed.notify_waiters();
            if let Some(remote) = &binding.remote {
                remote.fail(StreamError::Reset);
            }
            binding.handle.0.wake_by_ref();
        }
    }
    fn close_direct(&mut self) {
        for binding in self.bindings.iter_mut().flatten() {
            binding.direct = None;
        }
        self.direct.close();
    }

    fn active_slot(&self, id: FlowId) -> Option<usize> {
        self.inner.local_slots.as_ref()?.active(&id).copied()
    }
    fn dispatch(&mut self, scope: &PacketScope, now: Instant) -> bool {
        let shared = scope.0.local.get().expect("local owner");
        if shared.has_ready.load(Ordering::Acquire) {
            let mut queue = shared.ready.lock();
            if let Some(first) = queue.pop_front() {
                let mut batch = [first; BATCH];
                let rest = queue.len().min(BATCH - 1);
                for (cell, id) in batch[1..1 + rest].iter_mut().zip(queue.drain(..rest)) {
                    *cell = id;
                }
                shared.has_ready.store(!queue.is_empty(), Ordering::Release);
                drop(queue);
                for &id in &batch[..1 + rest] {
                    self.service_flow(scope, id, FlowWork::App, now);
                }
            }
        }
        let mut more = false;
        if self
            .inner
            .stack
            .as_ref()
            .is_some_and(Stack::has_pending_writers)
        {
            // The next event poll promotes pool writers against the refund epoch.
            shared.pool.drain_if_cached();
        }
        for n in 1..=BATCH {
            let Some((id, ready)) = self.inner.stack.as_mut().and_then(Stack::poll_event) else {
                break;
            };
            self.service_flow(scope, id, FlowWork::Protocol(ready), now);
            more |= n == BATCH;
        }
        for n in 1..=BATCH {
            let Some((&(due, _), &id)) = self.deadlines.first_key_value() else {
                break;
            };
            if due > now {
                break;
            }
            self.service_flow(scope, id, FlowWork::Deadline, now);
            more |= n == BATCH;
        }
        self.reap(scope);
        // Servicing a request can re-enqueue it after the batch was detached.
        more || shared.has_ready.load(Ordering::Acquire)
    }
    fn service_flow(&mut self, scope: &PacketScope, id: FlowId, work: FlowWork, now: Instant) {
        let Some(index) = self.active_slot(id) else {
            return;
        };
        let Some(binding) = self.bindings[index].as_mut() else {
            return;
        };
        let (ready, timed) = match work {
            FlowWork::App => {
                binding.handle.0.queued.swap(false, Ordering::AcqRel);
                (Ready::default(), false)
            }
            FlowWork::Protocol(ready) => {
                if let Some(direct) = binding.direct {
                    self.direct.mark_ready(direct);
                    return;
                }
                (ready, false)
            }
            FlowWork::Deadline => (Ready::default(), true),
        };
        let handle = binding.handle.clone();
        let flags = handle
            .0
            .flags
            .fetch_and(CLOSE | DIRECT_CLAIMED, Ordering::AcqRel);
        binding.closing |= flags & CLOSE != 0;
        let state = self.inner.stack.as_ref().and_then(|s| s.tcp_state(id));
        if (ready.contains(Ready::CONNECTED)
            || matches!(state, Some(TcpState::Established | TcpState::CloseWait)))
            && handle.0.status.fetch_or(ESTABLISHED, Ordering::Release) & ESTABLISHED == 0
        {
            handle.0.changed.notify_waiters();
        }
        if flags & ABORT != 0 {
            handle.0.status.fetch_or(CANCELLED, Ordering::Release);
            if let Some(direct) = binding.direct.take() {
                self.direct.abort(direct);
            }
            if let Some(s) = &mut self.inner.stack {
                s.tcp_abort(id);
            }
            if let Some(remote) = &binding.remote {
                remote.fail(StreamError::Reset);
            }
        }
        let terminal = flags & ABORT != 0
            || ready.contains(Ready::ERROR)
            || matches!(state, None | Some(TcpState::Closed | TcpState::TimeWait));
        if terminal {
            handle.mark_terminal();
        }
        if flags & ADMITTED != 0
            && handle.can_bind()
            && !terminal
            && !binding.closing
            && let Some(slot) = self.inner.slots[index].as_mut()
        {
            slot.rx_admitted = true;
        }
        let request = handle.0.request.lock().take();
        let mut due = binding.deadline;
        if let Some(request) = request {
            // A peer reset can follow already-buffered bytes while the shared dial is in flight.
            let readable = terminal
                && self
                    .inner
                    .stack
                    .as_ref()
                    .is_some_and(|s| s.tcp_peek_rx(id, 1).is_ok_and(|(_, n, _)| n != 0));
            let available = handle.can_bind()
                && !binding.closing
                && !self.inner.closing
                && (!terminal || readable)
                && binding.direct.is_none()
                && binding.remote.is_none()
                && binding.sniff.is_none();
            match request {
                Request::Direct(attach, done) => {
                    if available && done.as_ref().is_some_and(oneshot::Sender::is_closed) {
                        // The original waiter withdrew before the socket or any prefix was used.
                        attach.reject();
                    } else if !available || attach.cancelled() || !handle.claim_direct() {
                        attach.cancel();
                        if let Some(done) = done {
                            let _ = done.send(Err(closed()));
                        }
                    } else {
                        match self.direct.attach(id, attach, now) {
                            Ok(direct) => {
                                binding.direct = Some(direct);
                                if let Some(slot) = self.inner.slots[index].as_mut() {
                                    slot.rx_admitted = true;
                                }
                                if done.is_some_and(|done| done.send(Ok(())).is_err()) {
                                    binding.direct = None;
                                    self.direct.abort(direct);
                                    handle.abort();
                                }
                            }
                            Err(attach) => {
                                let flags =
                                    handle.0.flags.fetch_and(!DIRECT_CLAIMED, Ordering::AcqRel);
                                let error = if flags & (ABORT | CLOSE) != 0 {
                                    attach.cancel();
                                    closed()
                                } else {
                                    attach.reject();
                                    io::ErrorKind::WouldBlock.into()
                                };
                                if let Some(done) = done {
                                    let _ = done.send(Err(error));
                                }
                            }
                        }
                    }
                }
                Request::Sniff(done) => {
                    if available {
                        binding.sniff = Some(done);
                        due = Some(now + SNIFF_TIMEOUT);
                    } else {
                        let _ = done.send(Err(closed()));
                    }
                }
                Request::Remote(counters, done) => {
                    let pair = if available && !done.is_closed() {
                        let shared = scope.0.local.get().expect("local owner");
                        remote::pair(
                            id,
                            &scope.0.budget,
                            &shared.pool,
                            Waker::from(handle.0.clone()),
                            shared.remote_backpressure.clone(),
                            counters,
                        )
                    } else {
                        Err(closed())
                    };
                    match pair {
                        Ok((owner, endpoint)) => {
                            if done.send(Ok(endpoint)).is_ok() {
                                binding.remote = Some(owner);
                            } else {
                                handle.abort();
                            }
                        }
                        Err(error) => {
                            let _ = done.send(Err(error));
                        }
                    }
                }
            }
        }
        if let Some(done) = binding.sniff.take() {
            if done.is_closed() || binding.closing {
                due = None;
            } else {
                let ended = terminal
                    || ready.contains(Ready::READ_CLOSED)
                    || state == Some(TcpState::CloseWait)
                    || timed;
                let result = self.inner.stack.as_ref().and_then(|s| {
                    match s.tcp_peek_rx(id, MAX_CLIENT_HELLO_SIZE) {
                        Ok((slices, n, eof)) => sniff_slices(&slices[..n], ended || eof),
                        Err(StreamError::WouldBlock) if !ended => None,
                        _ => Some(SniffResult::unknown()),
                    }
                });
                if let Some(result) = result {
                    let _ = done.send(Ok(result));
                    due = None;
                } else if ended {
                    let _ = done.send(Err(closed()));
                    due = None;
                } else {
                    binding.sniff = Some(done);
                }
            }
        }
        let mut can_close = true;
        if let (Some(remote), Some(stack)) = (&mut binding.remote, &mut self.inner.stack) {
            if timed {
                remote.retry_budget();
                due = None;
            }
            let unread = binding.closing
                && (remote.has_unread_rx()
                    || stack.tcp_peek_rx(id, 1).is_ok_and(|(_, n, _)| n != 0));
            if !unread && handle.0.status.load(Ordering::Acquire) & CANCELLED == 0 {
                let (again, pending) = pump_remote(stack, id, remote, binding.closing, now);
                if again {
                    handle.0.wake_by_ref();
                }
                can_close = !pending;
                if remote.budget_blocked() {
                    due.get_or_insert(now + READINESS_FALLBACK);
                } else {
                    due = None;
                }
            }
        }
        let slot = self.inner.slots[index]
            .as_mut()
            .expect("closing exact flow");
        if binding.closing && can_close && slot.app_open {
            if let Some(direct) = binding.direct.take() {
                self.direct.abort(direct);
            }
            if let Some(stack) = &mut self.inner.stack {
                if binding
                    .remote
                    .as_ref()
                    .is_some_and(remote::RemoteOwner::has_unread_rx)
                {
                    stack.tcp_abort(id);
                }
                stack.tcp_close(id);
            }
            slot.app_open = false;
            self.retiring.push(id);
            self.inner.reap_pending = true;
            binding.remote = None;
            due = None;
        }
        binding.schedule(&mut self.deadlines, due);
    }

    fn reap(&mut self, scope: &PacketScope) {
        // Silent refusal can leave a half-open release without queued output to drain it.
        self.inner.drain_half_open();
        let changed = self
            .inner
            .stack
            .as_mut()
            .is_some_and(Stack::take_tcp_retention_change);
        if !std::mem::take(&mut self.inner.reap_pending) && !changed {
            return;
        }
        if changed {
            self.inner.refresh_local_pending();
        }
        let mut pending = 0;
        while pending < self.inner.local_pending.len() {
            let id = self.inner.local_pending[pending];
            if self
                .inner
                .stack
                .as_ref()
                .is_some_and(|s| s.tcp_retained(id))
            {
                pending += 1;
                continue;
            }
            self.inner.local_pending.swap_remove(pending);
            let slot = self.inner.slot(id).expect("original unaccepted admission");
            slot.app_open = false;
            slot.routing.take();
            self.inner.pending_routing -= 1;
            self.retiring.push(id);
        }
        let mut i = 0;
        while i < self.retiring.len() {
            if !self.reap_retiring(scope, i) {
                i += 1;
            }
        }
    }

    fn reap_retiring(&mut self, scope: &PacketScope, i: usize) -> bool {
        let id = self.retiring[i];
        let slots = self.inner.local_slots.as_mut().expect("physical aliases");
        let index = slots.get(&id).copied().expect("original retiring index");
        let slot = self.inner.slots[index]
            .as_ref()
            .expect("original retiring flow");
        debug_assert!(!slot.app_open);
        if self
            .inner
            .stack
            .as_ref()
            .is_some_and(|s| s.tcp_retained(id))
        {
            return false;
        }
        if slot.outputs != 0 {
            slots.move_to_alias(id);
            return false;
        }
        self.retiring.swap_remove(i);
        slots.remove(&id);
        let slot = self.inner.slots[index].take().expect("original retirement");
        if self.tuples.get(&(slot.client, slot.destination)) == Some(&id) {
            self.tuples.remove(&(slot.client, slot.destination));
        }
        self.inner.unpin_local_tcp(slot.client.ip());
        if let Some(resources) = &self.inner.resources {
            resources.retire_tcp(self.inner.worker, id, slot.client, slot.destination);
        }
        if let Some(mut binding) = self.bindings[index].take() {
            let shared = scope.0.local.get().expect("local owner");
            binding.schedule(&mut self.deadlines, None);
            let flow = binding.handle;
            flow.0.detached.store(true, Ordering::Release);
            if flow.0.queued.swap(false, Ordering::AcqRel) {
                let mut queue = shared.ready.lock();
                if let Some(i) = queue.iter().position(|&queued| queued == id) {
                    queue.remove(i);
                    if queue.is_empty() {
                        shared.has_ready.store(false, Ordering::Release);
                    }
                }
            }
            flow.mark_terminal();
            let request = flow.0.request.lock().take();
            if let Some(Request::Direct(attach, _)) = request {
                attach.cancel();
            }
            let cb = flow.0.callback.lock().take().map(|p| p.callback);
            let mut callbacks = shared.callbacks.lock();
            let wake = callbacks.is_empty();
            callbacks.push_back((flow, cb));
            drop(callbacks);
            if wake {
                scope.0.owner_wake.notify_one();
            }
        }
        true
    }
    fn publish_snapshot(&mut self, shared: &LocalShared, empty: bool) {
        let snapshot = (self.inner.stack.as_ref().map(Stack::stats), empty);
        if self.published_snapshot != snapshot {
            *shared.snapshot.lock() = snapshot;
            self.published_snapshot = snapshot;
        }
    }

    pub(super) fn finish_turn(
        &mut self,
        scope: &PacketScope,
        cx: &Context<'_>,
        now: Instant,
    ) -> Option<Instant> {
        let local = scope.0.local.get().expect("local owner");
        local.wake.register(cx.waker());
        let turn = std::mem::replace(&mut self.turn, LocalTurn::Idle);
        if local.failed() {
            return None;
        }
        if self.inner.finished {
            return None;
        }
        if turn == LocalTurn::Idle {
            self.begin(local, now);
        } else {
            // A shortened RX round may reach finish without the post-RX I/O poll.
            self.observe_shutdown(local, now);
        }
        if turn == LocalTurn::Unarmed
            && (local.has_returns.load(Ordering::Acquire)
                || local.has_replies.load(Ordering::Acquire)
                || local.admission.load(Ordering::Relaxed) != 0
                || local.shutdown.load(Ordering::Acquire) != 0)
        {
            // A standalone begin_turn has no Context. A producer may have raced registration.
            cx.waker().wake_by_ref();
        }
        if self.dispatch(scope, now) || self.direct.has_pending_work() {
            cx.waker().wake_by_ref();
        }
        let rescan = self
            .inner
            .turn_needs_scan
            .take()
            .is_some_and(|classes| classes.contains(&true));
        let queued = self.inner.queued != 0;
        let tx = self.inner.stack.as_mut().is_some_and(|stack| {
            stack.take_tx_wakeup()
                && (queued || stack.may_have_transmit(false) || stack.may_have_transmit(true))
        });
        if rescan || tx {
            cx.waker().wake_by_ref();
        }
        let empty = self
            .inner
            .local_slots
            .as_ref()
            .is_none_or(SlotIndex::is_empty)
            && self.inner.stack.as_ref().is_none_or(Stack::is_quiescent);
        self.publish_snapshot(local, empty);
        if self.inner.closing
            && empty
            && scope.0.inner.lock().source_work.is_empty()
            && self.inner.finish()
        {
            local.pool.close();
            let mut parked = scope.0.inner.lock();
            parked.finished = true;
            parked.source_work = Sources::new(0);
            self.publish_snapshot(local, true);
            debug_assert!(local.retained.lock().outputs.is_empty());
            if parked.rights == Rights::Driven {
                parked.rights = Rights::Returned;
            }
            drop(parked);
            scope.0.owner_wake.notify_one();
            return None;
        }
        self.writer_retry = self
            .inner
            .stack
            .as_ref()
            .is_some_and(Stack::has_pending_writers)
            .then(|| self.writer_retry.unwrap_or(now + READINESS_FALLBACK));
        [
            self.inner.stack.as_ref().and_then(Stack::poll_timeout),
            self.writer_retry,
            self.direct.deadline(),
            self.deadlines.first_key_value().map(|(&(at, _), _)| at),
        ]
        .into_iter()
        .flatten()
        .min()
    }
    pub(super) fn return_right(mut self: Box<Self>, scope: &PacketScope) {
        let local = scope.0.local.get().expect("local owner");
        self.turn = LocalTurn::Idle;
        if !self.inner.finished {
            if local.failed() {
                *local.abandoned.lock() = Some(self);
                return;
            }
            if let Some(gate) = &self.inner.capture_admission {
                gate.store(false, Ordering::Release);
            }
            self.inner.closing = true;
            local.shutdown(true);
            if !self.inner.aborted {
                self.abort(local);
                self.inner.refresh_local_pending();
            }
            // The original joined owner can now drain application and actual CQ receipts. The
            // failed device's Stack and sockets have already been disposed by their sole writer.
            *local.abandoned.lock() = Some(self);
            let mut parked = scope.0.inner.lock();
            parked.closing = true;
            parked.rights = Rights::Abandoned;
        }
        scope.0.owner_wake.notify_one();
    }
}

fn pump_remote(
    stack: &mut Stack,
    id: FlowId,
    remote: &mut remote::RemoteOwner,
    closing: bool,
    now: Instant,
) -> (bool, bool) {
    let mut read = 0;
    let mut wake_reader = false;
    while !closing && read < QUOTA {
        match stack.tcp_peek_rx(id, QUOTA - read) {
            Ok((slices, count, eof)) => {
                let total: usize = slices[..count].iter().map(|slice| slice.len()).sum();
                let (n, wake) = remote.push_rx_deferred(&slices[..count]);
                wake_reader |= wake;
                if eof && n == total {
                    remote.finish_rx(None);
                }
                if n == 0 {
                    break;
                }
                stack
                    .tcp_consume_rx(id, n)
                    .expect("committing exact original RX loan");
                read += n;
            }
            Err(StreamError::WouldBlock) => break,
            Err(error) => {
                remote.finish_rx(Some(error));
                break;
            }
        }
    }
    if wake_reader {
        remote.wake_rx_reader();
    }
    let (full, blocked) = match remote.pump_tx(stack, QUOTA, now) {
        Ok(n) => (n == QUOTA, remote.tx_pending()),
        Err(StreamError::WouldBlock) => (false, true),
        Err(_) => (false, false),
    };
    if remote.shutdown_pending() {
        remote.finish_shutdown(stack.tcp_shutdown(id));
    }
    (read == QUOTA || full, blocked)
}

fn sniff_slices(slices: &[io::IoSlice<'_>], done: bool) -> Option<SniffResult> {
    match slices {
        [] => crate::sniffing::sniff_packet_tcp(&[], done),
        [one] => crate::sniffing::sniff_packet_tcp(one, done),
        several => {
            let mut bytes = [0; MAX_CLIENT_HELLO_SIZE];
            let mut n = 0;
            for slice in several {
                bytes[n..n + slice.len()].copy_from_slice(slice);
                n += slice.len();
            }
            crate::sniffing::sniff_packet_tcp(&bytes[..n], done)
        }
    }
}

impl PacketDriver {
    pub(crate) fn try_local_established<'a>(
        &mut self,
        packet: &[u8],
        (ingress_at, service_at): (Instant, Instant),
        path: crate::xdp::ReturnPath,
        peers: &'a crate::xdp::worker::PeerAuthority,
        checked: &mut Option<crate::xdp::worker::PeerObservation<'a>>,
    ) -> Result<
        Option<super::super::packet_endpoint::PacketReceive>,
        crate::xdp::worker::PeerPathChanged,
    > {
        use honk_netstack::wire::{self, tcp};
        let Some(owner) = self.local.as_mut() else {
            return Ok(None);
        };
        if self
            .scope
            .0
            .local
            .get()
            .is_some_and(|local| local.shutdown.load(Ordering::Acquire) != 0)
        {
            return Ok(None);
        }
        let state = &mut owner.inner;
        if state.closing
            || state
                .capture_admission
                .as_ref()
                .is_some_and(|a| !a.load(Ordering::Acquire))
            || state.pending_routing != 0
        {
            return Ok(None);
        }
        let Ok(ip) = wire::parse_ip(packet) else {
            return Ok(None);
        };
        if ip.proto != wire::PROTO_TCP {
            return Ok(None);
        }
        let Ok((hdr, _)) = tcp::parse(&packet[ip.payload]) else {
            return Ok(None);
        };
        if hdr.flags & (tcp::SYN | tcp::ACK | tcp::FIN | tcp::RST) != tcp::ACK {
            return Ok(None);
        }
        let tuple = (
            SocketAddr::new(ip.src, hdr.src_port),
            SocketAddr::new(ip.dst, hdr.dst_port),
        );
        let Some(&id) = owner.tuples.get(&tuple) else {
            return Ok(None);
        };
        let Some(index) = state
            .local_slots
            .as_ref()
            .and_then(|slots| slots.active(&id))
        else {
            return Ok(None);
        };
        let slot = state.slots[*index]
            .as_ref()
            .expect("original local TCP slot");
        if !slot.rx_admitted || !slot.app_open {
            return Ok(None);
        }
        let Some(peer) = state
            .local_peers
            .as_ref()
            .expect("physical peer index")
            .existing(ip.src)
        else {
            return Ok(None);
        };
        let Some(held) = state.peers[peer]
            .as_ref()
            .filter(|peer| peer.original_path() == path)
        else {
            return Ok(None);
        };
        let Some(stack) = &mut state.stack else {
            return Ok(None);
        };
        if stack.tcp_state(id) != Some(TcpState::Established)
            || stack.poll_timeout().is_some_and(|at| at <= service_at)
        {
            return Ok(None);
        }
        let report = stack.try_receive_realm_tcp(ingress_at, service_at, packet, |source| {
            peers.confirm_tcp::<true>(held, self.scope.scope(), source, path, ingress_at, checked)
        })?;
        let slot =
            (report.outcome == honk_netstack::ReceiveOutcome::TcpAccepted(id)).then_some(slot);
        Ok(Some(Inner::receive_from_slot(report, slot)))
    }
}

pub(super) struct LocalWindowGrowth {
    slots: SlotIndex,
    bindings: Box<[Option<Binding>]>,
    tuples: HashMap<(SocketAddr, SocketAddr), FlowId>,
    retiring: Vec<FlowId>,
    ready: VecDeque<FlowId>,
    returns: VecDeque<Returned>,
    peers: LocalPeers,
    outputs: HashMap<IpAddr, usize>,
    growth: MemoryReservation,
    _overlap: MemoryReservation,
}
impl LocalOwner {
    pub(super) fn prepare_wide(
        &self,
        scope: &PacketScope,
        slots: usize,
        frames: usize,
        peers: usize,
    ) -> Option<LocalWindowGrowth> {
        if scope.0.local.get()?.window_growth.get().is_some()
            || self
                .inner
                .local_slots
                .as_ref()
                .is_some_and(|index| !index.is_empty())
            || !self.inner.stack.as_ref()?.is_quiescent()
        {
            return None;
        }
        let local = scope.0.local.get()?;
        let ancillary = self.inner.stack.as_ref()?.pending_source_bound();
        let old = window_bytes(
            self.inner.slots.len(),
            self.inner.frames.len(),
            self.inner.peers.len(),
            ancillary,
        )?;
        let new = window_bytes(slots, frames, peers, ancillary)?;
        let growth = local.reserve(new.checked_sub(old)?)?;
        let overlap = local.reserve(old)?;
        Some(LocalWindowGrowth {
            slots: SlotIndex::new(self.inner.half_open.len(), frames),
            bindings: (0..slots).map(|_| None).collect(),
            tuples: HashMap::with_capacity(slots),
            retiring: Vec::with_capacity(slots),
            ready: VecDeque::with_capacity(slots),
            returns: VecDeque::with_capacity(frames),
            peers: LocalPeers::new(peers, slots, ancillary, Arc::clone(&local.retained)),
            outputs: HashMap::with_capacity(frames),
            growth,
            _overlap: overlap,
        })
    }
}
impl LocalWindowGrowth {
    pub(super) fn install(mut self, owner: &mut LocalOwner, scope: &PacketScope) {
        let shared = scope.0.local.get().expect("local owner startup");
        owner.inner.local_slots = Some(self.slots);
        owner.bindings = self.bindings;
        owner.tuples = self.tuples;
        owner.retiring = self.retiring;
        owner.inner.local_peers = Some(self.peers);
        {
            let mut ready = shared.ready.lock();
            self.ready.append(&mut ready);
            *ready = self.ready;
            shared.has_ready.store(!ready.is_empty(), Ordering::Release);
        }
        {
            let mut returns = shared.returns.lock();
            self.returns.append(&mut returns);
            *returns = self.returns;
            shared
                .has_returns
                .store(!returns.is_empty(), Ordering::Release);
        }
        shared.retained.lock().outputs = self.outputs;
        assert!(shared.window_growth.set(self.growth).is_ok());
    }
}

// Hashbrown reserves control bytes, a load-factor margin and power-of-two buckets. Four
// buckets per requested item also cover the allocation header and the old/new map peaks.
fn window_bytes(slots: usize, frames: usize, peers: usize, ancillary: usize) -> Option<usize> {
    let maps =
        4 * (size_of::<(FlowId, usize)>() + size_of::<((SocketAddr, SocketAddr), FlowId)>() + 2);
    let per_slot = maps
        + size_of::<Option<Binding>>()
        + size_of::<Option<(FlowId, usize)>>()
        + 3 * size_of::<FlowId>();
    slots
        .checked_mul(per_slot + 4 * (size_of::<(IpAddr, usize)>() + 1))?
        .checked_add(
            frames.checked_mul(size_of::<Returned>() + 4 * (size_of::<(IpAddr, usize)>() + 1))?,
        )?
        .checked_add(
            peers.checked_mul(size_of::<usize>() + 4 * (size_of::<(IpAddr, usize)>() + 1))?,
        )?
        .checked_add(ancillary.checked_mul(8 * (size_of::<IpAddr>() + 1))?)?
        .checked_add(512)
}

#[cfg(test)]
#[derive(Default)]
struct TurnWake(AtomicBool);

#[cfg(test)]
impl Wake for TurnWake {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_netstack::wire::tcp;

    pub(super) fn physical() -> (PacketScope, PacketOwner, PacketDriver) {
        physical_with_bulk(1)
    }

    fn physical_with_bulk(bulk_frames: usize) -> (PacketScope, PacketOwner, PacketDriver) {
        let budget = MemoryBudget::new(32 << 20);
        let (realm, mut owners) = capture_realm(1280, 64, bulk_frames, 1, 1, &budget).unwrap();
        let scope = realm.owner(0).unwrap().clone();
        let owner = owners.pop().unwrap();
        let mut driver = owner.hand_off();
        assert!(scope.0.inner.lock().stack.is_some());
        driver.make_local(1).unwrap();
        assert!(scope.0.inner.lock().stack.is_none());
        assert!(driver.make_local(1).is_err());
        (scope, owner, driver)
    }

    fn take(driver: &mut PacketDriver, class: TxClass) -> OutputLease {
        let mut output = [None];
        assert!(matches!(
            driver.poll_outputs_class(&mut Context::from_waker(Waker::noop()), class, &mut output),
            Poll::Ready(Some(1))
        ));
        output[0].take().unwrap()
    }

    #[tokio::test]
    async fn lost_publication_abandons_right_and_joins_real_output_return() {
        let (scope, owner, mut driver) = physical();
        let now = Instant::now();
        let sender = scope.datagram_sender("203.0.113.2:53".parse().unwrap());
        let client = "192.0.2.1:53001".parse().unwrap();
        let mut reply = Box::pin(sender.send_to(b"dns reply", client));
        assert!(futures::poll!(&mut reply).is_pending());
        driver.service(&mut Context::from_waker(Waker::noop()), now);
        assert_eq!(reply.await.unwrap(), 9);
        let output = take(&mut driver, TxClass::Bulk);
        assert!(output.packet().ends_with(b"dns reply"));
        let (tx, rx) = oneshot::channel();
        drop(rx);
        drop(tx.send(driver).expect_err("original unpublished driver"));
        assert!(!owner.reclaim().await);
        let mut joined = Box::pin(owner.run());
        assert!(futures::poll!(&mut joined).is_pending());
        assert!(!scope.0.inner.lock().finished);
        output.release();
        joined.await;
        assert!(scope.0.inner.lock().finished);
        assert_eq!(
            sender.send_to(b"closed", client).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    fn accept(driver: &mut PacketDriver, now: Instant, port: u16) -> (SynInfo, FlowIo) {
        let peer = crate::xdp::routing_input::test_peer(1, 0, [2; 6], 7);
        accept_with_peer(driver, now, port, |_, _| Some(peer.clone()))
    }

    fn accept_with_peer(
        driver: &mut PacketDriver,
        now: Instant,
        port: u16,
        on_source: impl FnMut(honk_netstack::ValidatedSource, bool) -> Option<PeerHold>,
    ) -> (SynInfo, FlowIo) {
        let client = SocketAddr::from(([192, 0, 2, 1], port));
        let dst: SocketAddr = "203.0.113.2:443".parse().unwrap();
        let mut syn = [0; 128];
        let n = tcp::emit_packet(
            &mut syn,
            client.ip(),
            dst.ip(),
            &tcp::Header {
                src_port: client.port(),
                dst_port: dst.port(),
                seq: 100,
                ack: 0,
                flags: tcp::SYN,
                window: 4096,
                urgent: 0,
                options: Default::default(),
            },
            [&[], &[]],
        )
        .unwrap();
        driver
            .receive_realm_timed(&syn[..n], now, now, &mut None, false, on_source)
            .unwrap();
        driver.poll_accept_local().unwrap().unwrap()
    }

    #[tokio::test]
    async fn cancellation_targets_only_its_shard_and_generation() {
        let budget = MemoryBudget::new(32 << 20);
        let (realm, owners) = capture_realm(1280, 64, 2, 2, 1, &budget).unwrap();
        let mut drivers: Vec<_> = owners.iter().map(PacketOwner::hand_off).collect();
        for driver in &mut drivers {
            driver.make_local(2).unwrap();
        }
        let now = Instant::now();
        let joins: Vec<_> = owners
            .into_iter()
            .map(|owner| {
                tokio::spawn(async move {
                    assert!(owner.reclaim().await);
                    owner.run().await;
                })
            })
            .collect();
        let (one, first) = accept(&mut drivers[0], now, 41700);
        let (two, second) = accept(&mut drivers[1], now, 41701);
        let stale = first.local().unwrap().clone();
        let mut cx = Context::from_waker(Waker::noop());
        stale.abort();
        drop(first);
        drivers[1].service(&mut cx, now);
        assert_eq!(
            drivers[1]
                .local
                .as_ref()
                .unwrap()
                .inner
                .stack
                .as_ref()
                .unwrap()
                .tcp_state(two.id),
            Some(TcpState::SynReceived)
        );
        drivers[0].service(&mut cx, now);
        let cancelled = drivers[0]
            .local
            .as_ref()
            .unwrap()
            .inner
            .stack
            .as_ref()
            .unwrap()
            .tcp_state(one.id);
        assert!(cancelled.is_none() || cancelled == Some(TcpState::Closed));
        loop {
            drivers[0].service(&mut cx, now);
            let mut released = false;
            for class in [TxClass::Control, TxClass::Bulk] {
                let mut slot = [None];
                while let Poll::Ready(Some(1)) =
                    drivers[0].poll_outputs_class(&mut cx, class, &mut slot)
                {
                    let mut output = slot[0].take().unwrap().into_owner();
                    assert!(drivers[0].complete_local(&mut output));
                    released = true;
                }
            }
            if !released {
                break;
            }
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), stale.wait())
            .await
            .unwrap()
            .unwrap();
        let (replacement, next) = accept(&mut drivers[0], now, 41700);
        assert_ne!(replacement.id, one.id);
        stale.abort();
        drivers[0].service(&mut cx, now);
        assert_eq!(
            drivers[0]
                .local
                .as_ref()
                .unwrap()
                .inner
                .stack
                .as_ref()
                .unwrap()
                .tcp_state(replacement.id),
            Some(TcpState::SynReceived)
        );
        drivers[1].service(&mut cx, now);
        assert_eq!(
            drivers[1]
                .local
                .as_ref()
                .unwrap()
                .inner
                .stack
                .as_ref()
                .unwrap()
                .tcp_state(two.id),
            Some(TcpState::SynReceived)
        );
        drop((second, next));
        for scope in realm.owners() {
            scope.shutdown(true);
        }
        for driver in &mut drivers {
            driver.service_closing(&mut cx, now);
        }
        for join in joins {
            join.await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn remote_drain_expiry_aborts_full_tx_after_zero_window_fin() {
        use crate::relay::{self, DrainExpired, RelayProgress};
        use crate::xdp::{ReturnPath, worker::PeerAuthority};
        use honk_netstack::wire::parse_ip;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // The retained FIN acknowledgement may occupy a bulk frame; payload must still have credit.
        let (scope, owner, mut driver) = physical_with_bulk(2);
        let now = Instant::now();
        let mut cx = Context::from_waker(Waker::noop());
        let budget = scope.budget();
        let authority = PeerAuthority::new(Arc::new(AtomicBool::new(true)), &budget).unwrap();
        let path = ReturnPath {
            realm: 1,
            device: 0,
            mac: [2; 6],
            vlan_tci: [7, 0],
            vlan_proto: [0x8100, 0],
            vlan_count: 1,
        };
        let retain = |source, pending| authority.retain(scope.scope(), source, path, now, pending);
        let (syn, mut flow) = accept_with_peer(&mut driver, now, 41322, retain);
        let id = syn.id;
        driver.service(&mut cx, now);
        let syn_ack = take(&mut driver, TxClass::Control);
        let tcp_of = |output: &OutputLease| {
            assert_eq!(output.flow_id(), Some(id));
            assert_eq!(
                output
                    .peer_hold()
                    .filter(PeerHold::learned)
                    .map(|peer| (peer.address(), peer.original_path())),
                Some((syn.client.ip(), path))
            );
            let packet = output.packet();
            let ip = parse_ip(packet).unwrap();
            assert_eq!((ip.src, ip.dst), (syn.original_dst.ip(), syn.client.ip()));
            let segment = &packet[ip.payload];
            assert!(tcp::verify_checksum(ip.src, ip.dst, segment));
            let (header, len) = tcp::parse(segment).unwrap();
            assert_eq!(len, segment.len());
            assert_eq!(header.src_port, syn.original_dst.port());
            assert_eq!(header.dst_port, syn.client.port());
            header
        };
        let header = tcp_of(&syn_ack);
        assert_eq!(header.flags, tcp::SYN | tcp::ACK);
        assert_eq!(header.ack, 101);
        let server_seq = header.seq.wrapping_add(1);
        syn_ack.release();
        let send = |driver: &mut PacketDriver, flags| {
            let mut packet = [0; 80];
            let length = tcp::emit_packet(
                &mut packet,
                syn.client.ip(),
                syn.original_dst.ip(),
                &tcp::Header {
                    src_port: syn.client.port(),
                    dst_port: syn.original_dst.port(),
                    seq: 101,
                    ack: server_seq,
                    flags,
                    window: 0,
                    urgent: 0,
                    options: Default::default(),
                },
                [&[], &[]],
            )
            .unwrap();
            let (rx, report, _) = driver
                .receive_realm_timed(&packet[..length], now, now, &mut None, false, retain)
                .unwrap();
            assert_eq!(rx, Rx::Consumed);
            assert!(report.taken_over);
        };
        {
            let mut established = std::pin::pin!(flow.local().unwrap().wait_established());
            assert!(futures::poll!(&mut established).is_pending());
            send(&mut driver, tcp::ACK);
            driver.finish_turn(&mut cx, now);
            assert!(matches!(
                futures::poll!(&mut established),
                Poll::Ready(Ok(()))
            ));
        }
        {
            let mut attach = std::pin::pin!(flow.attach_remote());
            assert!(futures::poll!(&mut attach).is_pending());
            driver.service(&mut cx, now);
            attach.await.unwrap();
        }
        let poll_packet = |driver: &mut PacketDriver, cx: &mut Context<'_>| {
            for class in [TxClass::Control, TxClass::Bulk] {
                let mut out = [None];
                match driver.poll_outputs_class(cx, class, &mut out) {
                    Poll::Ready(Some(1)) => return Poll::Ready(out[0].take().unwrap()),
                    Poll::Pending => (),
                    other => panic!("unexpected {class:?} output state: {other:?}"),
                }
            }
            Poll::Pending
        };
        async fn on_owner_wake<T>(
            mut service: impl FnMut(&mut Context<'_>) -> Poll<T>,
        ) -> Result<T, tokio::time::error::Elapsed> {
            struct OutputWake(Notify);
            impl Wake for OutputWake {
                fn wake(self: Arc<Self>) {
                    self.wake_by_ref();
                }
                fn wake_by_ref(self: &Arc<Self>) {
                    self.0.notify_one();
                }
            }

            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            for _ in 0..BATCH {
                let signal = Arc::new(OutputWake(Notify::new()));
                let waker = Waker::from(Arc::clone(&signal));
                if let Poll::Ready(output) = service(&mut Context::from_waker(&waker)) {
                    return Ok(output);
                }
                // The deadline may poll the notification, never another device turn.
                tokio::time::timeout_at(deadline, signal.0.notified()).await?;
            }
            panic!("owner woke without producing output");
        }
        let next_packet = async |driver: &mut PacketDriver| {
            on_owner_wake(|cx| {
                driver.service(cx, now);
                poll_packet(driver, cx)
            })
            .await
        };
        send(&mut driver, tcp::FIN | tcp::ACK);
        let held = next_packet(&mut driver).await.expect("FIN acknowledgement");
        let ack = tcp_of(&held);
        assert_eq!((ack.flags, ack.ack), (tcp::ACK, 102));
        assert!(poll_packet(&mut driver, &mut cx).is_pending());
        assert_eq!(
            driver
                .local
                .as_ref()
                .unwrap()
                .inner
                .stack
                .as_ref()
                .unwrap()
                .tcp_state(id),
            Some(TcpState::CloseWait)
        );

        let accepted = flow.remote_progress().unwrap();
        let mut retirement = flow.retirement();
        let before = budget.used();
        let (proxy, mut upstream) = tokio::io::duplex(256 << 10);
        upstream.write_all(&vec![7; 256 << 10]).await.unwrap();
        let progress = RelayProgress {
            upload: Arc::new(AtomicU64::new(0)),
            download: Arc::new(AtomicU64::new(0)),
            outbound: None,
            first_response: None,
            on_transfer: None,
        };
        let committed = {
            let mut relay = std::pin::pin!(relay::relay_remote_tcp(
                &mut flow,
                proxy,
                (syn.client, syn.original_dst),
                &progress,
                || accepted.snapshot().0,
            ));
            assert!(futures::poll!(&mut relay).is_pending());
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), upstream.read_u8())
                    .await
                    .unwrap()
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof,
            );
            // Fill both buffering frontiers without advancing the packet clock or opening the window.
            for _ in 0..4 {
                driver.service(&mut cx, now);
                assert!(futures::poll!(&mut relay).is_pending());
            }
            driver.service(&mut cx, now);
            let committed = accepted.snapshot().0;
            assert!(committed > 0);
            let local = driver.local.as_ref().unwrap();
            let index = local.active_slot(id).unwrap();
            assert!(
                local.bindings[index]
                    .as_ref()
                    .unwrap()
                    .remote
                    .as_ref()
                    .unwrap()
                    .tx_pending()
            );
            assert!(progress.download.load(Ordering::Relaxed) > committed);
            let ledger = &mut driver.local.as_mut().unwrap().inner.ledger;
            let spare = ledger
                .reserve_tx(TxClass::Bulk)
                .expect("independent bulk credit");
            ledger.cancel_tx(spare).unwrap();
            assert!(poll_packet(&mut driver, &mut cx).is_pending());
            assert!(budget.used() > before);
            let error = tokio::time::timeout(Duration::from_secs(2), relay)
                .await
                .unwrap()
                .unwrap_err();
            assert!(error.is::<DrainExpired>());
            committed
        };

        flow.abort();
        let reset = next_packet(&mut driver).await.expect("abort reset");
        assert_ne!(tcp_of(&reset).flags & tcp::RST, 0);
        let owned_outputs = |driver: &PacketDriver| {
            driver
                .local
                .as_ref()
                .unwrap()
                .inner
                .ledger
                .outstanding_tx()
                .filter(|output| output.owner == Some(id))
                .count()
        };
        assert_eq!(owned_outputs(&driver), 2);
        assert!(futures::poll!(std::pin::pin!(retirement.wait())).is_pending());
        reset.release();
        driver.service(&mut cx, now);
        assert_eq!(owned_outputs(&driver), 1);
        assert!(accepted.finished());
        assert_eq!(accepted.snapshot().0, committed);
        scope.0.local.get().unwrap().drain_pool();
        assert!(budget.used() <= before);
        assert!(futures::poll!(std::pin::pin!(retirement.wait())).is_pending());
        held.release();
        driver.service(&mut cx, now);
        scope.0.local.get().unwrap().deliver_callbacks();
        tokio::time::timeout(Duration::from_secs(1), retirement.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(owned_outputs(&driver), 0);
        scope.shutdown(true);
        driver.service_closing(&mut cx, now);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), owner.reclaim())
                .await
                .unwrap()
        );
        owner.run().await;

        let mut silent_turns = 0;
        let silent = on_owner_wake(|_| {
            silent_turns += 1;
            if silent_turns == 1 {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        assert!(silent.is_err(), "deadline supplied a device turn");
        assert_eq!(silent_turns, 1);
    }

    #[tokio::test]
    async fn dropped_tcp_handoff_wakes_only_after_original_output_returns() {
        let (scope, owner, mut driver) = physical();
        let now = Instant::now();
        let (syn, mut flow) = accept(&mut driver, now, 41323);
        let mut guard = flow.retirement();
        let (ack, done) = oneshot::channel();
        flow.set_retirement_callback(move || {
            let _ = ack.send(());
        })
        .unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        driver.service(&mut cx, now);
        let held = take(&mut driver, TxClass::Control);
        assert_eq!(held.flow_id(), Some(syn.id));
        let (publish, rx) = oneshot::channel();
        drop(rx);
        drop(publish.send(flow).unwrap_err());
        scope.shutdown(true);
        driver.service_closing(&mut cx, now);
        assert!(futures::poll!(Box::pin(guard.wait())).is_pending());
        assert!(scope.0.inner.lock().rights == Rights::Driven);
        held.release();
        driver.service_closing(&mut cx, now);
        assert!(owner.reclaim().await);
        done.await.unwrap();
        guard.wait().await.unwrap();
        drop(driver);
        assert!(scope.0.inner.lock().rights == Rights::Task);
        assert!(catch_unwind(AssertUnwindSafe(|| owner.hand_off())).is_err());
        owner.run().await;
    }

    #[tokio::test]
    async fn realm_reply_and_cq_belong_to_the_original_worker() {
        let budget = MemoryBudget::new(32 << 20);
        let (realm, owners) = capture_realm(1280, 64, 2, 2, 1, &budget).unwrap();
        let mut drivers: Vec<_> = owners.iter().map(PacketOwner::hand_off).collect();
        for driver in &mut drivers {
            driver.make_local(2).unwrap();
        }
        let client = (1..=254)
            .map(|n| SocketAddr::from(([192, 0, 2, n], 53001)))
            .find(|a| realm.worker_for_udp(a.ip()) == 1)
            .unwrap();
        let sender = realm.datagram_sender("203.0.113.2:53".parse().unwrap());
        let mut send = Box::pin(sender.send_to(b"owner one", client));
        assert!(futures::poll!(&mut send).is_pending());
        let mut cx = Context::from_waker(Waker::noop());
        let now = Instant::now();
        drivers[0].service(&mut cx, now);
        assert!(futures::poll!(&mut send).is_pending());
        drivers[1].service(&mut cx, now);
        assert_eq!(send.await.unwrap(), 9);
        let mut actual = take(&mut drivers[1], TxClass::Bulk).into_owner();
        assert!(!drivers[0].complete_local(&mut actual));
        assert!(actual.packet().unwrap().ends_with(b"owner one"));
        for scope in realm.owners() {
            scope.shutdown(true);
        }
        for driver in &mut drivers {
            driver.service_closing(&mut cx, now);
        }
        assert!(realm.owners()[0].0.inner.lock().finished);
        assert!(!realm.owners()[1].0.inner.lock().finished);
        assert!(drivers[1].complete_local(&mut actual));
        drivers[1].service_closing(&mut cx, now);
        for owner in owners {
            assert!(owner.reclaim().await);
            owner.run().await;
        }
    }

    #[tokio::test]
    async fn local_turn_wakes_for_late_tx_but_not_drained_tx() {
        let (scope, owner, mut driver) = physical();
        let now = Instant::now();
        let wake = Arc::new(TurnWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut cx = Context::from_waker(&waker);
        let mut packet = [0; 1280];

        driver.begin_local_turn(&cx, now);
        driver.begin_turn(now);
        let (syn, first) = accept(&mut driver, now, 41000);
        let MaterializedOutput::Packet(mut output) = driver
            .materialize_into(now, TxClass::Control, &mut packet)
            .unwrap()
        else {
            panic!("the original SYN-ACK must be emitted");
        };
        assert_eq!(output.owner.flow_id(), Some(syn.id));
        assert_eq!(output.destination, syn.client.ip());
        for class in [TxClass::Control, TxClass::Bulk] {
            assert!(matches!(
                driver.materialize_into(now, class, &mut packet).unwrap(),
                MaterializedOutput::Idle
            ));
        }
        wake.0.store(false, Ordering::Relaxed);
        driver.finish_turn(&mut cx, now);
        assert!(!wake.0.load(Ordering::Relaxed), "drained TX hint");
        assert!(driver.deadline().is_some_and(|due| due > now));
        assert_eq!(scope.stats().unwrap().tx_packets, 1);

        driver.begin_local_turn(&cx, now);
        driver.begin_turn(now);
        for class in [TxClass::Control, TxClass::Bulk] {
            assert!(matches!(
                driver.materialize_into(now, class, &mut packet).unwrap(),
                MaterializedOutput::Idle
            ));
        }
        let (_, late) = accept(&mut driver, now, 41001);
        assert_eq!(scope.stats().unwrap().flows, 1);
        wake.0.store(false, Ordering::Relaxed);
        driver.finish_turn(&mut cx, now);
        assert!(wake.0.load(Ordering::Relaxed), "late SYN-ACK");
        assert_eq!(scope.stats().unwrap().flows, 2);

        assert!(driver.complete_local(&mut output.owner));
        drop((first, late));
        scope.shutdown(true);
        driver.service_closing(&mut cx, now);
        assert!(owner.reclaim().await);
        owner.run().await;
    }

    #[tokio::test]
    async fn local_turn_defers_late_replies_until_the_next_standalone_poll() {
        let (scope, owner, mut driver) = physical();
        let shared = scope.0.local.get().unwrap();
        let now = Instant::now();
        let wake = Arc::new(TurnWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut cx = Context::from_waker(&waker);
        let sender = scope.datagram_sender("203.0.113.9:53".parse().unwrap());
        let client = "192.0.2.1:40000".parse().unwrap();

        driver.begin_local_turn(&cx, now);
        driver.begin_turn(now);
        let mut reply = Box::pin(sender.send_to(b"first", client));
        assert!(futures::poll!(&mut reply).is_pending());
        assert!(wake.0.swap(false, Ordering::Relaxed));
        let (_, first_flow) = accept(&mut driver, now, 41001);
        let fragments = crate::xdp::routing_input::test_fragments();
        assert!(
            driver
                .reassemble_for_dispatch_with_peer(&fragments[0], now, now, None)
                .unwrap()
                .is_none()
        );
        driver.poll_local_io(&mut cx, now).unwrap();
        driver.finish_turn(&mut cx, now);
        assert!(shared.has_replies.load(Ordering::Acquire));
        assert!(futures::poll!(&mut reply).is_pending());
        assert_eq!(scope.stats().unwrap().flows, 1);

        driver.poll_local_io(&mut cx, now).unwrap();
        assert!(matches!(futures::poll!(&mut reply), Poll::Ready(Ok(5))));
        assert!(!shared.has_replies.load(Ordering::Acquire));
        let held = take(&mut driver, TxClass::Bulk);
        let mut next = Box::pin(sender.send_to(b"second", client));
        assert!(futures::poll!(&mut next).is_pending());
        driver.poll_local_io(&mut cx, now).unwrap();
        assert!(shared.has_replies.load(Ordering::Acquire));
        held.release();
        assert!(shared.has_returns.load(Ordering::Acquire));
        driver.poll_local_io(&mut cx, now).unwrap();
        assert!(matches!(futures::poll!(&mut next), Poll::Ready(Ok(6))));
        assert!(!shared.has_replies.load(Ordering::Acquire));
        assert!(!shared.has_returns.load(Ordering::Acquire));
        driver.begin_turn(now);
        take(&mut driver, TxClass::Bulk).release();
        wake.0.store(false, Ordering::Relaxed);
        driver.finish_turn(&mut cx, now);
        assert!(wake.0.load(Ordering::Relaxed));
        assert!(shared.has_returns.load(Ordering::Acquire));

        driver.begin_local_turn(&cx, now);
        assert!(!shared.has_returns.load(Ordering::Acquire));
        let mut interrupted = Box::pin(sender.send_to(b"third", client));
        assert!(futures::poll!(&mut interrupted).is_pending());
        driver.interrupt_turn(&cx);
        driver.poll_local_io(&mut cx, now).unwrap();
        assert!(matches!(
            futures::poll!(&mut interrupted),
            Poll::Ready(Ok(5))
        ));
        take(&mut driver, TxClass::Bulk).release();
        let (_, flow) = accept(&mut driver, now, 41000);
        driver.poll_local_io(&mut cx, now).unwrap();
        assert_eq!(scope.stats().unwrap().flows, 2);
        assert!(!scope.is_protocol_quiescent());
        drop((first_flow, flow));
        scope.shutdown(true);
        driver.service_closing(&mut cx, now);
        assert!(scope.is_protocol_quiescent());
        assert!(owner.reclaim().await);
        owner.run().await;
    }

    #[tokio::test]
    async fn cancelled_replies_refund_bytes_and_frames_without_granting_output() {
        let (scope, owner, mut driver) = physical();
        let shared = scope.0.local.get().unwrap();
        let client: SocketAddr = "192.0.2.1:40000".parse().unwrap();
        let sender = scope.datagram_sender("203.0.113.9:53".parse().unwrap());
        let payload = vec![0; UDP_BYTES / 4];
        let mut pending = Vec::new();
        for _ in 0..4 {
            let mut send = Box::pin(sender.send_to(&payload, client));
            assert!(futures::poll!(&mut send).is_pending());
            pending.push(send);
        }
        assert_eq!(
            sender.send_to(b"full", client).await.unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );
        drop(pending);
        assert!(shared.has_replies.load(Ordering::Acquire));
        driver.service(&mut Context::from_waker(Waker::noop()), Instant::now());
        assert_eq!(driver.local.as_ref().unwrap().inner.queued, 0);
        assert!(!shared.has_replies.load(Ordering::Acquire));
        let mut frames = Vec::new();
        for _ in 0..UDP_FRAMES {
            let mut send = Box::pin(sender.send_to(&[], client));
            assert!(futures::poll!(&mut send).is_pending());
            frames.push(send);
        }
        assert_eq!(
            sender.send_to(&[], client).await.unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );
        scope.shutdown(true);
        assert!(!shared.has_replies.load(Ordering::Acquire));
        for reply in frames {
            assert_eq!(
                reply.await.unwrap_err().kind(),
                io::ErrorKind::ConnectionAborted
            );
        }
        driver.service_closing(&mut Context::from_waker(Waker::noop()), Instant::now());
        assert!(owner.reclaim().await);
        owner.run().await;
    }
}

struct SourceView {
    publishing: Option<IpAddr>,
    pending: HashSet<IpAddr>,
    outputs: HashMap<IpAddr, usize>,
}
impl SourceView {
    fn new(pending: usize, frames: usize) -> Self {
        Self {
            publishing: None,
            pending: HashSet::with_capacity(pending),
            outputs: HashMap::with_capacity(frames),
        }
    }
    fn contains(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        self.pending.contains(&address) || self.outputs.contains_key(&address)
    }
}

pub(super) struct LocalPeers {
    index: HashMap<IpAddr, usize>,
    free: Vec<usize>,
    tcp: HashMap<IpAddr, usize>,
    view: Arc<Mutex<SourceView>>,
    pending_scratch: HashSet<IpAddr>,
    pending_published: bool,
    #[cfg(test)]
    lookup_steps: AtomicUsize,
    #[cfg(test)]
    pending_visits: usize,
}
impl LocalPeers {
    fn new(peers: usize, slots: usize, ancillary: usize, view: Arc<Mutex<SourceView>>) -> Self {
        Self {
            index: HashMap::with_capacity(peers),
            free: (0..peers).rev().collect(),
            tcp: HashMap::with_capacity(slots),
            view,
            pending_scratch: HashSet::with_capacity(ancillary),
            pending_published: false,
            #[cfg(test)]
            lookup_steps: AtomicUsize::new(0),
            #[cfg(test)]
            pending_visits: 0,
        }
    }
    fn existing(&self, address: IpAddr) -> Option<usize> {
        #[cfg(test)]
        self.lookup_steps.fetch_add(1, Ordering::Relaxed);
        self.index.get(&address).copied()
    }
    pub(super) fn install_peer(&mut self, address: IpAddr, index: usize) {
        if let std::collections::hash_map::Entry::Vacant(entry) = self.index.entry(address) {
            assert_eq!(self.free.pop(), Some(index));
            entry.insert(index);
        }
    }
    fn retains(&self, address: IpAddr) -> bool {
        self.tcp.contains_key(&address) || self.view.lock().contains(address)
    }
}

impl Inner {
    pub(super) fn peer_hold_at(&self, address: IpAddr) -> Option<&PeerHold> {
        if let Some(local) = &self.local_peers {
            return self.peers[local.existing(address)?].as_ref();
        }
        self.peers[..self.peer_end]
            .iter()
            .flatten()
            .find(|peer| peer.address() == address)
    }
    pub(super) fn peer_cell(&self, address: IpAddr) -> Option<usize> {
        if let Some(local) = &self.local_peers {
            return local
                .existing(address)
                .or_else(|| local.free.last().copied());
        }
        self.peers
            .iter()
            .position(|cell| cell.as_ref().is_some_and(|peer| peer.address() == address))
            .or_else(|| self.peers.iter().position(Option::is_none))
    }
    pub(super) fn pin_local_tcp(&mut self, address: IpAddr) {
        if let Some(local) = &mut self.local_peers {
            *local.tcp.entry(address).or_default() += 1;
        }
    }
    fn unpin_local_tcp(&mut self, address: IpAddr) {
        let local = self.local_peers.as_mut().expect("local TCP source index");
        decrement(&mut local.tcp, address);
        self.release_unused_local_peer(address);
    }
    pub(super) fn local_flow_accounts_output(&self, flow: Option<FlowId>) -> bool {
        flow.is_some_and(|id| {
            self.local_slots
                .as_ref()
                .is_some_and(|slots| slots.get(&id).is_some())
        })
    }
    pub(super) fn pin_local_output(&mut self, address: IpAddr) {
        if let Some(local) = &mut self.local_peers {
            *local
                .view
                .lock()
                .outputs
                .entry(address.to_canonical())
                .or_default() += 1;
        }
    }
    pub(super) fn unpin_local_output(&mut self, flow: Option<FlowId>, address: Option<IpAddr>) {
        if let Some(address) = address
            && !self.local_flow_accounts_output(flow)
            && let Some(local) = &mut self.local_peers
        {
            decrement(&mut local.view.lock().outputs, address.to_canonical());
            self.release_unused_local_peer(address);
        }
    }
    fn release_unused_local_peer(&mut self, address: IpAddr) {
        let Some(local) = &mut self.local_peers else {
            return;
        };
        release_peer(local, &mut self.peers, address);
    }
    pub(super) fn refresh_local_pending(&mut self) {
        let Some(local) = &mut self.local_peers else {
            return;
        };
        if !local.pending_published && !self.stack.as_ref().is_some_and(Stack::has_pending_sources)
        {
            return;
        }
        local.pending_scratch.clear();
        if let Some(stack) = &self.stack {
            stack.visit_pending_sources(|address| {
                local.pending_scratch.insert(address.to_canonical());
                #[cfg(test)]
                {
                    local.pending_visits += 1;
                }
            });
        }
        {
            let mut retained = local.view.lock();
            local.pending_published = !local.pending_scratch.is_empty();
            std::mem::swap(&mut retained.pending, &mut local.pending_scratch);
        }
        // Only addresses that formerly had ancillary protocol work can lose a pin here.
        // Move the allocation out while releasing old holds, then reuse it next refresh.
        let old = std::mem::take(&mut local.pending_scratch);
        for &address in &old {
            release_peer(local, &mut self.peers, address);
        }
        local.pending_scratch = old;
    }
}

fn decrement(counts: &mut HashMap<IpAddr, usize>, address: IpAddr) {
    let std::collections::hash_map::Entry::Occupied(mut entry) = counts.entry(address) else {
        unreachable!("original source pin");
    };
    if *entry.get() == 1 {
        entry.remove();
    } else {
        *entry.get_mut() -= 1;
    }
}

fn release_peer(local: &mut LocalPeers, peers: &mut [Option<PeerHold>], address: IpAddr) {
    if local.index.contains_key(&address) && !local.retains(address) {
        let index = local.index.remove(&address).expect("indexed peer hold");
        peers[index].take();
        local.free.push(index);
    }
}

fn worker_failed() -> io::Error {
    io::Error::other("physical packet owner failed before proving retirement")
}

#[cfg(test)]
mod source_work_tests {
    use super::*;
    use crate::xdp::{ReturnPath, worker::PeerAuthority};
    use honk_netstack::wire::{self, tcp};
    use std::time::Duration;

    mod bulk_retirement;
    mod pressure;
    mod ready_dispatch;
    mod retirement_aliases;

    fn input(
        client: SocketAddr,
        destination: SocketAddr,
        sequence: u32,
        ack: u32,
        flags: u8,
        data: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0; 60 + data.len()];
        let len = tcp::emit_packet(
            &mut packet,
            client.ip(),
            destination.ip(),
            &tcp::Header {
                src_port: client.port(),
                dst_port: destination.port(),
                seq: sequence,
                ack,
                flags,
                window: 65535,
                urgent: 0,
                options: Default::default(),
            },
            [data, &[]],
        )
        .unwrap();
        packet.truncate(len);
        packet
    }
    fn path() -> ReturnPath {
        ReturnPath {
            realm: 1,
            device: 0,
            mac: [2; 6],
            vlan_tci: [0; 2],
            vlan_proto: [0; 2],
            vlan_count: 0,
        }
    }
    fn receive(
        driver: &mut PacketDriver,
        authority: &Arc<PeerAuthority>,
        packet: &[u8],
        now: Instant,
    ) -> crate::control::packet_endpoint::PacketReceive {
        let scope = driver.scope();
        driver
            .receive_realm_timed(packet, now, now, &mut None, false, |source, pending| {
                authority.retain(scope, source, path(), now, pending)
            })
            .unwrap()
            .1
    }
    fn accept(
        driver: &mut PacketDriver,
        authority: &Arc<PeerAuthority>,
        client: SocketAddr,
        destination: SocketAddr,
        now: Instant,
    ) -> (FlowIo, u32) {
        receive(
            driver,
            authority,
            &input(client, destination, 100, 0, tcp::SYN, b""),
            now,
        );
        let (syn, flow) = driver.poll_accept_local().unwrap().unwrap();
        let mut bytes = [0; 1280];
        let MaterializedOutput::Packet(mut output) = driver
            .materialize_into(now, TxClass::Control, &mut bytes)
            .unwrap()
        else {
            panic!("SYN-ACK");
        };
        assert_eq!(output.owner.flow_id(), Some(syn.id));
        let ip = wire::parse_ip(&bytes[..output.owner.len()]).unwrap();
        let (synack, _) = tcp::parse(&bytes[ip.payload]).unwrap();
        assert_eq!(synack.flags, tcp::SYN | tcp::ACK);
        assert_eq!(synack.ack, 101);
        let ack = synack.seq.wrapping_add(1);
        assert!(driver.complete_local(&mut output.owner));
        (flow, ack)
    }

    #[tokio::test]
    async fn eight_active_sources_do_not_probe_a_thousand_idle_peers() {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let (realm, mut owners) = capture_realm(1280, 1, 16, 1, 1, &budget).unwrap();
        let owner = owners.pop().unwrap();
        let scope = realm.owners()[0].clone();
        let mut driver = owner.hand_off();
        driver.make_local(1).unwrap();
        let now = Instant::now();
        let destination = "203.0.113.2:443".parse().unwrap();
        let authority = PeerAuthority::new(Arc::new(AtomicBool::new(true)), &budget).unwrap();
        let mut flow_peers = Vec::new();
        let mut cx = Context::from_waker(Waker::noop());
        for n in 0..1008 {
            let client = SocketAddr::from(([10, 7, (n / 256) as u8, (n % 256) as u8], 45000));
            let (flow, ack) = accept(&mut driver, &authority, client, destination, now);
            receive(
                &mut driver,
                &authority,
                &input(client, destination, 101, ack, tcp::ACK, b""),
                now,
            );
            flow.mark_rx_admitted();
            driver.finish_turn(&mut cx, now);
            flow_peers.push((flow, ack));
        }
        let before = driver
            .local
            .as_ref()
            .unwrap()
            .inner
            .local_peers
            .as_ref()
            .unwrap();
        assert_eq!(before.index.len(), 1008);
        assert_eq!(before.tcp.len(), 1008);
        before.lookup_steps.store(0, Ordering::Relaxed);
        let mut checked = None;
        for (flow, ack) in &flow_peers[1000..] {
            let packet = input(flow.peer_addr(), destination, 101, *ack, tcp::ACK, b"a");
            let received = driver
                .try_local_established(&packet, (now, now), path(), &authority, &mut checked)
                .unwrap()
                .unwrap();
            assert!(received.taken_over && received.qualified_rx);
        }
        let state = driver
            .local
            .as_ref()
            .unwrap()
            .inner
            .local_peers
            .as_ref()
            .unwrap();
        assert_eq!(
            state.lookup_steps.load(Ordering::Relaxed),
            8,
            "each accepted packet consults its one indexed peer"
        );

        // An actual reassembly timer has one ancillary source. No idle TCP source is visited.
        let fragment = crate::xdp::routing_input::test_fragments();
        driver
            .reassemble_for_dispatch_with_peer(&fragment[0], now, now, None)
            .unwrap();
        let initial = driver
            .local
            .as_ref()
            .unwrap()
            .inner
            .local_peers
            .as_ref()
            .unwrap()
            .pending_visits;
        assert!(scope.retains_source("192.0.2.1".parse().unwrap()));
        driver.begin_turn(now + honk_netstack::FragmentLimits::default().timeout);
        let state = driver
            .local
            .as_ref()
            .unwrap()
            .inner
            .local_peers
            .as_ref()
            .unwrap();
        assert_eq!(
            state.pending_visits - initial,
            1,
            "one pending expiry quote, independent of the idle TCP fanout"
        );
        assert_eq!(state.index.len(), 1008);
        assert_eq!(state.lookup_steps.load(Ordering::Relaxed), 8);
        assert!(scope.retains_source(flow_peers[0].0.peer_addr().ip()));

        drop(flow_peers);
        scope.shutdown(true);
        for _ in 0..(1008_usize.div_ceil(BATCH) + 1) {
            driver.service_closing(
                &mut cx,
                now + honk_netstack::FragmentLimits::default().timeout,
            );
        }
        assert!(scope.0.inner.lock().finished);
        assert!(owner.reclaim().await);
        owner.run().await;
    }

    #[tokio::test]
    async fn udp_validated_during_close_reports_source_without_taking_over() {
        let budget = MemoryBudget::new(32 << 20);
        let (realm, mut owners) = capture_realm(1280, 64, 1, 1, 1, &budget).unwrap();
        let owner = owners.pop().unwrap();
        let scope = realm.owners()[0].clone();
        let mut driver = owner.hand_off();
        driver.make_local(1).unwrap();
        let now = Instant::now();
        let authority = PeerAuthority::new(Arc::new(AtomicBool::new(true)), &budget).unwrap();
        let client = "192.0.2.1:45000".parse().unwrap();
        let destination = "203.0.113.2:53".parse().unwrap();
        let mut packet = [0; 128];
        let len = wire::udp::emit_packet(&mut packet, client, destination, b"in flight").unwrap();
        let (rx, report, work) = driver
            .receive_realm_timed(
                &packet[..len],
                now,
                now,
                &mut None,
                false,
                |source, pending| {
                    let hold = authority
                        .retain(scope.scope(), source, path(), now, pending)
                        .unwrap();
                    scope.shutdown(true);
                    Some(hold)
                },
            )
            .unwrap();
        assert!(matches!(rx, Rx::Dropped(DropReason::Stale)));
        assert_eq!(report.source.unwrap().src, client);
        assert!(!report.taken_over && !report.qualified_rx && work.is_none());
        driver.service_closing(&mut Context::from_waker(Waker::noop()), now);
        assert!(owner.reclaim().await);
        owner.run().await;
    }

    fn direct_pair(
        budget: &Arc<MemoryBudget>,
    ) -> (
        DirectAttach,
        crate::xdp::worker::direct::DirectObserver,
        crate::relay::RelayProgress,
        tokio::net::TcpStream,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        socket.set_nonblocking(true).unwrap();
        server.set_nonblocking(true).unwrap();
        let progress = crate::relay::RelayProgress {
            upload: Arc::new(AtomicU64::new(0)),
            download: Arc::new(AtomicU64::new(0)),
            outbound: None,
            first_response: None,
            on_transfer: None,
        };
        let (binding, observer) = DirectAttach::new(
            socket,
            &progress,
            DirectAttach::credit(|bytes| budget.reserve(bytes)).unwrap(),
            true,
        );
        (
            binding,
            observer,
            progress,
            tokio::net::TcpStream::from_std(server).unwrap(),
        )
    }

    #[tokio::test]
    async fn submit_direct_finishes_and_retires_without_duplicate_close_wake() {
        use crate::xdp::worker::direct::DirectOutcome;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (scope, owner, mut driver) = super::tests::physical();
        let authority = PeerAuthority::new(Arc::new(true.into()), &scope.0.budget).unwrap();
        let now = Instant::now();
        let client = "192.0.2.1:45000".parse().unwrap();
        let dst = "203.0.113.2:443".parse().unwrap();
        let (mut flow, ack) = accept(&mut driver, &authority, client, dst, now);
        let local = flow.local().unwrap().clone();
        let (done, mut retired) = oneshot::channel();
        flow.set_retirement_callback(move || done.send(()).unwrap())
            .unwrap();
        receive(
            &mut driver,
            &authority,
            &input(client, dst, 101, ack, tcp::ACK | tcp::FIN, b"a"),
            now,
        );
        let wake = Arc::new(TurnWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut cx = Context::from_waker(&waker);
        driver.finish_turn(&mut cx, now);
        let (attach, mut observer, progress, mut server) = direct_pair(&scope.0.budget);
        server.shutdown().await.unwrap();
        local.submit_direct(attach).unwrap();
        assert!(observer.poll_update(&mut cx).is_pending());
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| {
                if driver.poll_local_io(cx, now).unwrap() {
                    cx.waker().wake_by_ref();
                }
                while let Poll::Ready((snapshot, outcome)) = observer.poll_update(cx) {
                    if let Some(outcome) = outcome {
                        assert!(snapshot.attached);
                        assert!(matches!(outcome, DirectOutcome::Finished(Ok(_))));
                        return Poll::Ready(());
                    }
                }
                Poll::Pending
            }),
        )
        .await
        .unwrap();
        let mut delivered = Vec::new();
        server.read_to_end(&mut delivered).await.unwrap();
        assert_eq!(delivered, b"a");
        assert_eq!(progress.upload.load(Ordering::Relaxed), 1);
        assert_ne!(local.0.flags.load(Ordering::Acquire) & CLOSE, 0);
        assert!(
            !driver
                .local
                .as_mut()
                .unwrap()
                .inner
                .slot(flow.flow_id())
                .unwrap()
                .app_open
        );
        let shared = scope.0.local.get().unwrap();
        shared.wake.register(&waker);
        wake.0.store(false, Ordering::Relaxed);
        local.cancel_direct();
        assert_eq!(local.0.flags.load(Ordering::Acquire) & ABORT, 0);
        let mut retiring = std::pin::pin!(flow.retire());
        assert!(retiring.as_mut().poll(&mut cx).is_pending());
        assert!(!wake.0.load(Ordering::Relaxed));
        let mut bytes = [0; 1280];
        let mut fin = loop {
            let MaterializedOutput::Packet(output) = driver
                .materialize_into(now, TxClass::Control, &mut bytes)
                .unwrap()
            else {
                panic!("expected TCP FIN");
            };
            let ip = wire::parse_ip(&bytes[..output.owner.len()]).unwrap();
            let (header, _) = tcp::parse(&bytes[ip.payload]).unwrap();
            if header.flags & tcp::FIN != 0 {
                assert_eq!(header.seq, ack);
                break output.owner;
            }
            let mut owner = output.owner;
            driver.complete_local(&mut owner);
        };
        receive(
            &mut driver,
            &authority,
            &input(client, dst, 103, ack.wrapping_add(1), tcp::ACK, b""),
            now,
        );
        driver.finish_turn(&mut cx, now);
        shared.deliver_callbacks();
        assert!(retired.try_recv().is_err());
        assert!(driver.complete_local(&mut fin));
        driver.finish_turn(&mut cx, now);
        shared.deliver_callbacks();
        retired.try_recv().unwrap();
        retiring.await.unwrap();
        scope.shutdown(true);
        driver.service_closing(&mut cx, now);
        assert!(owner.reclaim().await);
        owner.run().await;
    }

    #[tokio::test]
    async fn direct_cancel_after_flag_snapshot_prevents_first_upload() {
        use crate::xdp::worker::direct::DirectOutcome;
        use std::sync::Barrier;
        use tokio::io::AsyncReadExt;

        let (scope, owner, mut driver) = super::tests::physical();
        let budget = &scope.0.budget;
        let authority = PeerAuthority::new(Arc::new(true.into()), budget).unwrap();
        let now = Instant::now();
        let client = "192.0.2.1:45000".parse().unwrap();
        let dst = "203.0.113.2:443".parse().unwrap();
        let (flow, ack) = accept(&mut driver, &authority, client, dst, now);
        let payload = b"already buffered before cancellation";
        receive(
            &mut driver,
            &authority,
            &input(client, dst, 101, ack, tcp::ACK, payload),
            now,
        );
        let mut cx = Context::from_waker(Waker::noop());
        driver.finish_turn(&mut cx, now);
        let id = flow.flow_id();
        let local = flow.local().unwrap();
        let (attach, mut observer, progress, mut peer) = direct_pair(budget);
        local.submit_direct(attach).unwrap();

        let owner_state = driver.local.as_deref_mut().unwrap();
        let gate = Barrier::new(2);
        std::thread::scope(|threads| {
            threads.spawn(|| {
                // Hold the real request until service_flow has consumed the ADMITTED flag.
                // From that instruction to the claim it cannot process a second ABORT.
                let request = local.0.request.lock();
                local.mark_rx_admitted();
                gate.wait();
                let until = Instant::now() + Duration::from_secs(5);
                while local.0.flags.load(Ordering::Acquire) & ADMITTED != 0 {
                    assert!(Instant::now() < until, "worker did not consume its flags");
                    std::thread::yield_now();
                }
                local.cancel_direct();
                drop(request);
            });
            gate.wait();
            owner_state.service_flow(&scope, id, FlowWork::App, now);
        });

        // A request serviced at the last dispatch slot is followed by this pump turn,
        // before any queued cancellation is dispatched. Exercise the actual writev path.
        let stack = owner_state.inner.stack.as_mut().unwrap();
        owner_state.direct.service(stack, now).unwrap();
        assert_eq!(progress.upload.load(Ordering::Relaxed), 0);
        let (parts, count, _) = stack.tcp_peek_rx(id, payload.len()).unwrap();
        assert!(
            parts[..count]
                .iter()
                .flat_map(|part| part.iter())
                .eq(payload)
        );
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(matches!(
            observer.poll_update(&mut cx),
            Poll::Ready((snapshot, Some(DirectOutcome::Cancelled))) if !snapshot.attached
        ));
        assert!(!driver.local_direct_attached(client, dst));
        drop(flow);
        scope.shutdown(true);
        driver.service_closing(&mut cx, now);
        assert!(owner.reclaim().await);
        owner.run().await;
    }

    #[tokio::test]
    async fn busy_submit_and_withdrawn_attach_return_their_original_sockets() {
        use crate::xdp::worker::direct::DirectOutcome;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (scope, owner, mut driver) = super::tests::physical();
        let budget = &scope.0.budget;
        let authority = PeerAuthority::new(Arc::new(true.into()), budget).unwrap();
        let now = Instant::now();
        let client = "192.0.2.1:45000".parse().unwrap();
        let dst = "203.0.113.2:443".parse().unwrap();
        let (flow, ack) = accept(&mut driver, &authority, client, dst, now);
        receive(
            &mut driver,
            &authority,
            &input(client, dst, 101, ack, tcp::ACK, b""),
            now,
        );
        let mut cx = Context::from_waker(Waker::noop());
        driver.finish_turn(&mut cx, now);
        let local = flow.local().unwrap();
        let (attach, first, _, one) = direct_pair(budget);
        let mut waiting = Box::pin(local.attach_direct(attach));
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        let (attach, second, _, two) = direct_pair(budget);
        assert_eq!(
            local.submit_direct(attach).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(waiting);
        driver.poll_local_io(&mut cx, now).unwrap();
        assert!(!driver.local_direct_attached(client, dst));
        for (mut observer, mut peer, byte) in [(first, one, 1), (second, two, 2)] {
            let Poll::Ready((snapshot, Some(DirectOutcome::Fallback(socket)))) =
                observer.poll_update(&mut cx)
            else {
                panic!("lost preattach socket");
            };
            assert!(!snapshot.attached);
            let mut socket = tokio::net::TcpStream::from_std(socket).unwrap();
            socket.write_all(&[byte]).await.unwrap();
            assert_eq!(peer.read_u8().await.unwrap(), byte);
            assert!(observer.poll_update(&mut cx).is_pending());
        }
        drop(flow);
        scope.shutdown(true);
        driver.service_closing(&mut cx, now);
        assert!(owner.reclaim().await);
        owner.run().await;
    }

    #[tokio::test]
    async fn shutdown_during_open_turn_refuses_queued_direct_and_remote_attaches() {
        for abort in [false, true] {
            for post_rx in [false, true] {
                let (scope, owner, mut driver) = super::tests::physical();
                let budget = &scope.0.budget;
                let authority =
                    PeerAuthority::new(Arc::new(AtomicBool::new(true)), budget).unwrap();
                let now = Instant::now();
                let dst = "203.0.113.2:443".parse().unwrap();
                let clients = ["192.0.2.1:45000", "192.0.2.2:45000"].map(|s| s.parse().unwrap());
                let [(direct, direct_ack), (mut remote, remote_ack)] =
                    clients.map(|client| accept(&mut driver, &authority, client, dst, now));
                let ids = [direct.flow_id(), remote.flow_id()];
                for (client, ack) in clients.into_iter().zip([direct_ack, remote_ack]) {
                    receive(
                        &mut driver,
                        &authority,
                        &input(client, dst, 101, ack, tcp::ACK, b""),
                        now,
                    );
                }
                let mut cx = Context::from_waker(Waker::noop());
                driver.finish_turn(&mut cx, now);
                driver.begin_local_turn(&cx, now);
                let (binding, mut observer, _progress, _server) = direct_pair(budget);
                let mut direct_start = Box::pin(direct.local().unwrap().attach_direct(binding));
                let mut remote_start = Box::pin(remote.attach_remote());
                assert!(futures::poll!(&mut direct_start).is_pending());
                assert!(futures::poll!(&mut remote_start).is_pending());
                scope.shutdown(abort);

                if post_rx {
                    driver.poll_local_io(&mut cx, now).unwrap();
                } else {
                    driver.finish_turn(&mut cx, now);
                }
                for result in [
                    futures::poll!(&mut direct_start),
                    futures::poll!(&mut remote_start),
                ] {
                    assert!(
                        matches!(result, Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionAborted)
                    );
                }
                let Poll::Ready((
                    snapshot,
                    Some(crate::xdp::worker::direct::DirectOutcome::Cancelled),
                )) = observer.poll_update(&mut cx)
                else {
                    panic!("rejected Direct socket")
                };
                assert!(!snapshot.attached);
                let inner = &mut driver.local.as_mut().unwrap().inner;
                assert!(inner.closing);
                assert_eq!(inner.aborted, abort);
                if !abort {
                    for id in ids {
                        assert!(!inner.slot(id).unwrap().rx_admitted);
                    }
                }
                drop((direct_start, remote_start));
                drop((direct, remote));
                scope.shutdown(true);
                driver.service_closing(&mut cx, now);
                assert!(owner.reclaim().await);
                owner.run().await;
            }
        }
    }

    #[tokio::test]
    async fn failed_worker_wakes_live_apps_without_returning_device_debt() {
        let budget = MemoryBudget::new(32 << 20);
        let (realm, mut owners) = capture_realm(1280, 64, 1, 1, 1, &budget).unwrap();
        let owner = owners.pop().unwrap();
        let scope = realm.owners()[0].clone();
        let mut driver = owner.hand_off();
        driver.make_local(1).unwrap();
        let now = Instant::now();
        let authority = PeerAuthority::new(Arc::new(AtomicBool::new(true)), &budget).unwrap();
        let client = "192.0.2.1:45000".parse().unwrap();
        let destination = "203.0.113.2:443".parse().unwrap();
        let (mut flow, ack) = accept(&mut driver, &authority, client, destination, now);
        let (pending_flow, _) = accept(
            &mut driver,
            &authority,
            "192.0.2.2:45000".parse().unwrap(),
            destination,
            now,
        );
        let mut pending = Box::pin(pending_flow.local().unwrap().wait_established());
        assert!(futures::poll!(&mut pending).is_pending());
        let local = flow.local().unwrap().clone();
        let (tx, mut retirement) = oneshot::channel();
        flow.set_retirement_callback(move || {
            let _ = tx.send(());
        })
        .unwrap();
        let mut establishing = Box::pin(local.wait_established());
        assert!(futures::poll!(&mut establishing).is_pending());
        // Pull these SYN-ACKs before the first flow's payload queues a data ACK.
        let direct_client = "192.0.2.3:45000".parse().unwrap();
        let remote_client = "192.0.2.4:45000".parse().unwrap();
        let (direct, direct_ack) = accept(&mut driver, &authority, direct_client, destination, now);
        let (mut remote, remote_ack) =
            accept(&mut driver, &authority, remote_client, destination, now);
        receive(
            &mut driver,
            &authority,
            &input(client, destination, 101, ack, tcp::ACK, b"abc"),
            now,
        );
        let mut cx = Context::from_waker(Waker::noop());
        driver.finish_turn(&mut cx, now);
        establishing.await.unwrap();
        receive(
            &mut driver,
            &authority,
            &input(direct_client, destination, 101, direct_ack, tcp::ACK, b""),
            now,
        );
        receive(
            &mut driver,
            &authority,
            &input(remote_client, destination, 101, remote_ack, tcp::ACK, b""),
            now,
        );
        driver.finish_turn(&mut cx, now);

        let (binding, mut observer, progress, mut server) = direct_pair(&budget);
        let mut direct_start = Box::pin(direct.local().unwrap().attach_direct(binding));
        let mut remote_start = Box::pin(remote.attach_remote());
        assert!(futures::poll!(&mut direct_start).is_pending());
        assert!(futures::poll!(&mut remote_start).is_pending());
        let shared = scope.0.local.get().unwrap();
        assert!(shared.has_ready.load(Ordering::Acquire));
        // The requests woke the previous waker. Finishing below BATCH must wake the new
        // device waker for the Direct pump queued by dispatch.
        let wake = Arc::new(TurnWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        driver.finish_turn(&mut Context::from_waker(&waker), now);
        assert!(wake.0.load(Ordering::Relaxed));
        assert!(!shared.has_ready.load(Ordering::Acquire));
        direct_start.await.unwrap();
        remote_start.await.unwrap();
        assert!(driver.local_direct_attached(direct_client, destination));
        wake.0.store(false, Ordering::Relaxed);
        driver.finish_turn(&mut Context::from_waker(&waker), now);
        assert!(wake.0.load(Ordering::Relaxed), "pending Direct work alone");
        remote.mark_rx_admitted();
        driver.begin_local_turn(&cx, now);
        driver.begin_turn(now);
        receive(
            &mut driver,
            &authority,
            &input(direct_client, destination, 101, direct_ack, tcp::ACK, b"rx"),
            now,
        );
        driver.poll_local_io(&mut cx, now).unwrap();
        assert_eq!(progress.upload.load(Ordering::Relaxed), 2);
        driver.finish_turn(&mut cx, now);
        let remote_packet = input(remote_client, destination, 101, remote_ack, tcp::ACK, b"r");
        let report = receive(&mut driver, &authority, &remote_packet, now);
        assert!(report.taken_over && report.qualified_rx);
        driver.poll_local_io(&mut cx, now).unwrap();
        let mut remote_byte = [0];
        tokio::io::AsyncReadExt::read_exact(&mut remote, &mut remote_byte)
            .await
            .unwrap();
        assert_eq!(&remote_byte, b"r");
        let mut delivered = [0; 2];
        tokio::io::AsyncReadExt::read_exact(&mut server, &mut delivered)
            .await
            .unwrap();
        assert_eq!(&delivered, b"rx");
        let mut remote_buf = [0; 1];
        let mut remote_read = Box::pin(tokio::io::AsyncReadExt::read(&mut remote, &mut remote_buf));
        assert!(futures::poll!(&mut remote_read).is_pending());

        let mut attach = Box::pin(flow.attach_remote());
        assert!(futures::poll!(&mut attach).is_pending());
        let sender = scope.datagram_sender("203.0.113.2:53".parse().unwrap());
        let mut reply = Box::pin(sender.send_to(b"funded TX", client));
        assert!(futures::poll!(&mut reply).is_pending());
        driver.begin_turn(now);
        assert_eq!(reply.await.unwrap(), 9);
        let mut exported = [None];
        assert!(matches!(
            driver.poll_outputs_class(&mut cx, TxClass::Bulk, &mut exported),
            Poll::Ready(Some(1))
        ));
        let held = exported[0].take().unwrap();
        driver.fail_local_applications();
        let (_, direct_outcome) = poll_fn(|cx| observer.poll_update(cx)).await;
        assert!(matches!(
            direct_outcome,
            Some(crate::xdp::worker::direct::DirectOutcome::Cancelled)
        ));
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                tokio::io::AsyncReadExt::read(&mut server, &mut byte)
            )
            .await
            .unwrap()
            .unwrap(),
            0
        );
        assert_eq!(
            remote_read.await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(attach.await.unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(pending.await.unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(local.wait().await.unwrap_err().kind(), io::ErrorKind::Other);
        assert!(matches!(
            retirement.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(!owner.reclaim().await);
        assert!(!scope.0.inner.lock().finished);
        assert_eq!(
            driver
                .local
                .as_ref()
                .unwrap()
                .inner
                .ledger
                .outstanding_tx()
                .count(),
            1
        );
        assert!(scope.retains_tcp(client, destination));
        assert!(held.packet().ends_with(b"funded TX"));
        drop((held, pending_flow, flow, direct, remote, driver));
        owner.run().await;
    }
}

fn packet_source(packet: &[u8]) -> Option<IpAddr> {
    honk_netstack::wire::packet_addresses(packet)
        .ok()
        .map(|(source, _)| source)
}

// Collector reads cannot confuse an obligation being created with a retired source. A panic
// leaves the exact source pinned along with the failed owner's other unproven obligations.
struct SourceUpdate<'a>(Option<&'a Mutex<SourceView>>);
impl Drop for SourceUpdate<'_> {
    fn drop(&mut self) {
        if let Some(view) = self.0
            && !std::thread::panicking()
        {
            view.lock().publishing = None;
        }
    }
}
