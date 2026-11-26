//! Bounded L3 termination, not capture/classification or native continuation.
//!
//! One externally joined `PacketOwner` drives timers and queues complete IP packets, unless
//! validated endpoint start hands that right to one device-owned `PacketDriver`. That driver
//! can instead emit into already-reserved device storage. The original owner stays parked in
//! its joined task and resumes for actual finish or abandoned-driver cleanup. `OutputLease`
//! is a CPU-packet capability; both CPU and direct output retain their original scope credit
//! until actual I/O completion or explicit local disposal, never a fabricated NIC CQ.

use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use honk_datapath::ScopeId;
use honk_datapath::buffer::{FrameConfig, FrameLease, FrameLedger, TxClass};
use honk_netstack::{
    AcceptOpts, Config, DropReason, FlowId, MemoryBudget, MemoryReservation, Mode, Ready, Rx,
    RxMeta, SourceContext, Stack, StackStats, SynInfo, Transmit, TxCaps, UdpError,
};
use parking_lot::{Mutex, MutexGuard};
use tokio::sync::Notify;

#[cfg(target_os = "linux")]
mod fragment_peer;
mod realm;
mod realm_receive;
#[cfg(target_os = "linux")]
pub(in crate::control) use fragment_peer::{FragmentPeer, fragment_offset_zero};
#[cfg(target_os = "linux")]
pub(crate) use realm::capture_realm;
use realm::{HalfOpenHold, RealmResources};
pub(crate) use realm::{PacketRealm, PacketRealmPlan, TcpClaim};
#[cfg(target_os = "linux")]
pub(crate) use realm_receive::RealmRxBatch;

mod auxiliary;
use auxiliary::Auxiliary;
pub(in crate::control) use auxiliary::AuxiliaryWork;
#[cfg(target_os = "linux")]
pub(crate) use auxiliary::auxiliary_scope;
mod source;
pub use source::HostIngress;
pub(in crate::control) use source::ProcessMeta;
pub(in crate::control) use source::SourceWork;
use source::Sources;

mod stream;
pub use stream::{FlowIo, FlowRetirement};

#[cfg(test)]
mod tests;

const BATCH: usize = 64;
// Budget refunds in another scope have no protocol event in this Stack.
const READINESS_FALLBACK: std::time::Duration = std::time::Duration::from_millis(100);

#[cfg(target_os = "linux")]
pub(crate) const CAPTURE_MEMORY: usize = 384 << 20;
#[cfg(target_os = "linux")]
const CAPTURE_CONTROL_FRAMES: usize = 32;
#[cfg(target_os = "linux")]
pub(crate) const CAPTURE_WIDE_BULK_FRAMES: usize = 256;

#[cfg(all(target_os = "linux", test))]
pub(crate) fn capture_scope(
    mtu: u32,
    realms: usize,
    bulk_frames: usize,
    budget: &Arc<MemoryBudget>,
) -> anyhow::Result<(PacketScope, PacketOwner)> {
    capture_scope_with_output(
        mtu,
        realms,
        bulk_frames,
        usize::try_from(mtu.max(1280))?,
        TxCaps::NONE,
        budget,
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn capture_scope_with_output(
    mtu: u32,
    realms: usize,
    bulk_frames: usize,
    output_capacity: usize,
    caps: TxCaps,
    budget: &Arc<MemoryBudget>,
) -> anyhow::Result<(PacketScope, PacketOwner)> {
    let (mut scopes, mut owners) = realm::capture_partition(
        mtu,
        realms,
        bulk_frames,
        1,
        output_capacity,
        caps,
        budget,
        0,
    )?;
    Ok((
        scopes.pop().expect("singleton realm scope"),
        owners.pop().expect("singleton realm owner"),
    ))
}

/// Fixed metadata and frame ceilings for one scope, all funded by the supplied shared budget.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeLimits {
    pub max_slots: usize,
    pub control_frames: usize,
    pub bulk_frames: usize,
    pub max_waiters: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            max_slots: 4096,
            control_frames: 16,
            bulk_frames: 64,
            max_waiters: 256,
        }
    }
}

#[derive(Clone)]
pub struct PacketScope(Arc<Shared>);

impl fmt::Debug for PacketScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketScope")
            .field("scope", &self.scope())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct DirectRelayOwner {
    pub(in crate::control) runtime: tokio::runtime::Handle,
    pub(in crate::control) fence: Arc<DirectRelayFence>,
}

const RELAY_CLOSED: usize = 1 << (usize::BITS - 1);

pub(crate) struct DirectRelayFence {
    state: AtomicUsize,
    changed: Notify,
    _memory: MemoryReservation,
}

pub(in crate::control) struct DirectRelayLease<'a>(&'a DirectRelayFence);

impl Drop for DirectRelayLease<'_> {
    fn drop(&mut self) {
        if self.0.state.fetch_sub(1, Ordering::AcqRel) == RELAY_CLOSED + 1 {
            self.0.changed.notify_waiters();
        }
    }
}

impl DirectRelayFence {
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn new(budget: &Arc<MemoryBudget>) -> io::Result<Arc<Self>> {
        let memory = budget
            .reserve(size_of::<Self>() + 2 * size_of::<usize>())
            .ok_or_else(capacity)?;
        Ok(Arc::new(Self {
            state: AtomicUsize::new(0),
            changed: Notify::new(),
            _memory: memory,
        }))
    }

    pub(in crate::control) fn try_join_lease(&self) -> Option<DirectRelayLease<'_>> {
        self.state
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state < RELAY_CLOSED - 1).then(|| state + 1)
            })
            .ok()?;
        Some(DirectRelayLease(self))
    }

    /// Wait while holding an active join lease. Calls after closure return immediately.
    pub(in crate::control) async fn wait_closed(&self) {
        let notified = self.changed.notified();
        if self.state.load(Ordering::Acquire) & RELAY_CLOSED == 0 {
            notified.await;
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn close(&self) {
        let previous = self.state.fetch_or(RELAY_CLOSED, Ordering::AcqRel);
        if previous != 0 && previous & RELAY_CLOSED == 0 {
            self.changed.notify_waiters();
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) async fn join_closed(&self) {
        loop {
            let notified = self.changed.notified();
            if self.state.load(Ordering::Acquire) == RELAY_CLOSED {
                return;
            }
            notified.await;
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) async fn close_and_join(&self) {
        self.close();
        self.join_closed().await;
    }
}

struct Shared {
    scope: ScopeId,
    worker: usize,
    workers: usize,
    budget: Arc<MemoryBudget>,
    auxiliary: Option<Arc<Auxiliary>>,
    inner: Mutex<Inner>,
    owner_wake: Notify,
    #[cfg(target_os = "linux")]
    direct_relay_runtime: OnceLock<DirectRelayOwner>,
    #[cfg(all(test, feature = "native-api"))]
    startup_pause: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
    // Includes the Arc allocation, shared state and the frame-independent arrays.
    _metadata: MemoryReservation,
}

struct FlowSlot {
    id: FlowId,
    client: SocketAddr,
    destination: SocketAddr,
    app_open: bool,
    close_pending: bool,
    retiring: bool,
    outputs: usize,
    rx: Option<Waker>,
    tx: Option<Waker>,
    callback: Option<RetirementCallback>,
    accepted: bool,
    rx_admitted: bool,
    routing: Option<super::packet_endpoint::EndpointAdmission>,
    process: Option<ProcessMeta>,
    source: Option<SourceContext>,
}

struct RetirementCallback {
    callback: Box<dyn FnOnce() + Send>,
    _memory: MemoryReservation,
}

#[derive(Clone, Copy)]
struct Queued {
    lease: FrameLease,
    tx: Transmit,
    class: TxClass,
}

/// The one mutex-protected authority for who may drive this scope and whom mutations wake.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Rights {
    /// The original PacketOwner drives (ordinary, or reclaimed after a driver).
    Task,
    /// The unique PacketDriver drives; the original owner is parked.
    Driven,
    /// The driver irrevocably returned after actual finish.
    Returned,
    /// The driver disappeared without a successful return.
    Abandoned,
}

struct Inner {
    rights: Rights,
    stack: Option<Stack>,
    ledger: FrameLedger<Option<FlowId>>,
    frames: Box<[Option<Box<[u8]>>]>,
    output_peers: Box<[Option<IpAddr>]>,
    #[cfg(target_os = "linux")]
    output_peer_holds: Box<[Option<crate::xdp::worker::PeerHold>]>,
    source_work: Sources,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    host_process: Option<auxiliary::HostProcessBinding>,
    queue: Box<[Option<Queued>]>,
    head: usize,
    queued: usize,
    frame_size: usize,
    cpu_tx_caps: TxCaps,
    next_tx: TxClass,
    slots: Box<[Option<FlowSlot>]>,
    half_open: Box<[Option<(FlowId, HalfOpenHold)>]>,
    resources: Option<Arc<RealmResources>>,
    capture_admission: Option<Arc<std::sync::atomic::AtomicBool>>,
    #[cfg(target_os = "linux")]
    peers: Box<[Option<crate::xdp::worker::PeerHold>]>,
    // All slots at or beyond this bound are vacant; holes inside it retain their indices.
    #[cfg(target_os = "linux")]
    peer_end: usize,
    #[cfg(target_os = "linux")]
    fragment_peers: Box<[Option<FragmentPeer>]>,
    #[cfg(target_os = "linux")]
    fragment_peer_count: usize,
    pending_closes: usize,
    closed_apps: usize,
    reap_pending: bool,
    pending_routing: usize,
    waiters: Box<[Option<Registration>]>,
    credit_waiters: usize,
    tx_waiters: usize,
    output_waker: Option<Waker>,
    // While a generated turn owns service, mutations record a rescan instead of waking it.
    turn_needs_scan: Option<[bool; 2]>,
    // After protocol disposal, each slot below this cursor still needs its terminal wake.
    abort_wake_end: usize,
    closing: bool,
    aborted: bool,
    finished: bool,
    endpoint_prepared: bool,
    // Backs CPU frame bytes and their dependent arrays through the final output return.
    _storage: MemoryReservation,
}

struct ScopeFrameLayout {
    config: FrameConfig,
    aliases: usize,
    #[cfg(target_os = "linux")]
    peer_capacity: usize,
    #[cfg(target_os = "linux")]
    output_peer_capacity: usize,
    metadata_bytes: usize,
    storage_bytes: usize,
}

impl ScopeFrameLayout {
    fn new(
        limits: RuntimeLimits,
        frame_size: usize,
        worker: usize,
        workers: usize,
        capture: bool,
    ) -> io::Result<Self> {
        let frames = limits
            .control_frames
            .checked_add(limits.bulk_frames)
            .ok_or_else(|| invalid("frame count overflow"))?;
        let aliases = limits
            .max_slots
            .checked_add(frames)
            .ok_or_else(|| invalid("flow retention capacity overflow"))?;
        let peer_capacity = if capture {
            aliases
                .checked_mul(2)
                .and_then(|n| n.checked_add(frames))
                .and_then(|n| n.checked_add(128 / workers + usize::from(worker < 128 % workers)))
                .and_then(|n| n.checked_add(if worker == 0 { 64 } else { 0 }))
                .ok_or_else(|| invalid("peer retention capacity overflow"))?
                .min(4096)
        } else {
            0
        };
        let output_peer_capacity = if capture { frames } else { 0 };
        let config = FrameConfig {
            base_address: 0,
            frame_size,
            rx_frames: 0,
            control_frames: limits.control_frames,
            bulk_frames: limits.bulk_frames,
            fill_capacity: 0,
            rx_capacity: 0,
            control_descriptors: limits.control_frames,
            bulk_descriptors: limits.bulk_frames,
            tx_capacity: frames,
            completion_capacity: frames,
        };
        // Validate the ledger before reserving or allocating its backing.
        FrameLedger::<Option<FlowId>>::metadata_bytes(config).map_err(io::Error::other)?;
        let storage_bytes = frame_size
            .checked_mul(frames)
            .filter(|&n| n <= isize::MAX as usize)
            .ok_or_else(|| invalid("frame storage overflow"))?;
        let metadata_bytes = aliases
            .checked_mul(size_of::<Option<FlowSlot>>())
            .and_then(|n| {
                n.checked_add(PacketScope::peer_bytes(
                    peer_capacity.checked_add(output_peer_capacity)?,
                )?)
            })
            .and_then(|n| n.checked_add(frames.checked_mul(size_of::<Option<Box<[u8]>>>())?))
            .and_then(|n| n.checked_add(frames.checked_mul(size_of::<Option<IpAddr>>())?))
            .and_then(|n| n.checked_add(Sources::bytes(aliases)?))
            .and_then(|n| n.checked_add(frames.checked_mul(size_of::<Option<Queued>>())?))
            .filter(|&n| n <= isize::MAX as usize)
            .ok_or_else(|| invalid("runtime metadata overflow"))?;
        Ok(Self {
            config,
            aliases,
            #[cfg(target_os = "linux")]
            peer_capacity,
            #[cfg(target_os = "linux")]
            output_peer_capacity,
            metadata_bytes,
            storage_bytes,
        })
    }

    fn allocate(&self, retained_frames: usize) -> ScopeFrames {
        let frame_count = self.config.tx_capacity;
        let frame_size = self.config.frame_size;
        ScopeFrames {
            frames: (0..retained_frames)
                .map(|_| None)
                .chain(
                    (retained_frames..frame_count)
                        .map(|_| Some(vec![0; frame_size].into_boxed_slice())),
                )
                .collect(),
            output_peers: (0..frame_count).map(|_| None).collect(),
            #[cfg(target_os = "linux")]
            output_peer_holds: (0..self.output_peer_capacity).map(|_| None).collect(),
            source_work: Sources::new(self.aliases),
            queue: (0..frame_count).map(|_| None).collect(),
            slots: (0..self.aliases).map(|_| None).collect(),
            #[cfg(target_os = "linux")]
            peers: (0..self.peer_capacity).map(|_| None).collect(),
        }
    }
}

struct ScopeFrames {
    frames: Box<[Option<Box<[u8]>>]>,
    output_peers: Box<[Option<IpAddr>]>,
    #[cfg(target_os = "linux")]
    output_peer_holds: Box<[Option<crate::xdp::worker::PeerHold>]>,
    source_work: Sources,
    queue: Box<[Option<Queued>]>,
    slots: Box<[Option<FlowSlot>]>,
    #[cfg(target_os = "linux")]
    peers: Box<[Option<crate::xdp::worker::PeerHold>]>,
}

#[cfg(target_os = "linux")]
impl ScopeFrames {
    fn exchange(mut self, inner: &mut Inner) -> Self {
        // Keep the original frame bytes. The closed capture gate guarantees there is no lease.
        self.frames[..inner.frames.len()].swap_with_slice(&mut inner.frames);
        std::mem::swap(&mut self.frames, &mut inner.frames);
        std::mem::swap(&mut self.output_peers, &mut inner.output_peers);
        std::mem::swap(&mut self.output_peer_holds, &mut inner.output_peer_holds);
        std::mem::swap(&mut self.source_work, &mut inner.source_work);
        std::mem::swap(&mut self.queue, &mut inner.queue);
        std::mem::swap(&mut self.slots, &mut inner.slots);
        std::mem::swap(&mut self.peers, &mut inner.peers);
        self
    }
}

struct OutputReservation<'a> {
    inner: &'a mut Inner,
    lease: Option<FrameLease>,
}

impl Drop for OutputReservation<'_> {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            self.inner
                .ledger
                .cancel_tx(lease)
                .expect("unpublished scope output reservation");
        }
    }
}

impl PacketScope {
    /// The returned owner must be run and joined by the embedding endpoint/task owner.
    /// No task is spawned and no network/capture authority is granted here.
    pub fn new(
        cfg: Config,
        budget: Arc<MemoryBudget>,
        limits: RuntimeLimits,
        now: Instant,
    ) -> io::Result<(Self, PacketOwner)> {
        let capacity = usize::from(cfg.mtu.max(1280));
        Self::new_with_output(cfg, budget, limits, now, TxCaps::NONE, capacity)
    }

    pub(crate) fn new_with_output(
        cfg: Config,
        budget: Arc<MemoryBudget>,
        limits: RuntimeLimits,
        now: Instant,
        caps: TxCaps,
        frame_size: usize,
    ) -> io::Result<(Self, PacketOwner)> {
        let scope = ScopeId::allocate().ok_or_else(|| invalid("scope identities exhausted"))?;
        Self::new_partition(
            cfg, budget, limits, now, caps, frame_size, scope, 0, 1, None, false, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_partition(
        mut cfg: Config,
        budget: Arc<MemoryBudget>,
        limits: RuntimeLimits,
        now: Instant,
        caps: TxCaps,
        frame_size: usize,
        scope: ScopeId,
        worker: usize,
        workers: usize,
        resources: Option<Arc<RealmResources>>,
        capture: bool,
        auxiliary: Option<Arc<Auxiliary>>,
    ) -> io::Result<(Self, PacketOwner)> {
        if !matches!(cfg.mode, Mode::Transparent { .. }) {
            return Err(invalid(
                "packet termination requires transparent stack mode",
            ));
        }
        if limits.max_slots == 0 || limits.max_waiters == 0 {
            return Err(invalid("zero runtime metadata capacity"));
        }
        if frame_size < usize::from(cfg.mtu.max(1280)) {
            return Err(invalid("output capacity is below logical MTU"));
        }
        let layout = ScopeFrameLayout::new(limits, frame_size, worker, workers, capture)?;
        let metadata_bytes = size_of::<Shared>()
            .checked_add(2 * size_of::<usize>())
            .and_then(|n| {
                n.checked_add(
                    resources
                        .as_ref()
                        .map_or(0, |_| limits.max_slots)
                        .checked_mul(size_of::<Option<(FlowId, HalfOpenHold)>>())?,
                )
            })
            .and_then(|n| n.checked_add(Self::fragment_peer_bytes(capture && worker == 0)))
            .and_then(|n| {
                n.checked_add(
                    limits
                        .max_waiters
                        .checked_mul(size_of::<Option<Registration>>())?,
                )
            })
            .filter(|&n| {
                n.checked_add(layout.metadata_bytes)
                    .is_some_and(|total| total <= isize::MAX as usize)
            })
            .ok_or_else(|| invalid("runtime metadata overflow"))?;
        let metadata = budget.reserve(metadata_bytes).ok_or_else(capacity)?;
        let storage = budget
            .reserve(layout.storage_bytes + layout.metadata_bytes)
            .ok_or_else(capacity)?;
        let ledger = FrameLedger::new(layout.config, &budget).map_err(io::Error::other)?;
        cfg.shared_budget = Some(Arc::clone(&budget));
        let mut stack = match &resources {
            Some(shared) => Stack::new_accounted_shard(
                cfg,
                now,
                limits.max_slots,
                worker,
                workers,
                Arc::clone(&shared.udp_pending),
            ),
            None => Stack::new_accounted(cfg, now, limits.max_slots),
        }
        .map_err(io::Error::other)?;
        let paused = auxiliary.is_some();
        if paused {
            stack.set_accepting(false);
        }
        let frames = layout.allocate(0);
        let shared = Arc::new(Shared {
            scope,
            worker,
            workers,
            budget,
            auxiliary,
            inner: Mutex::new(Inner {
                rights: Rights::Task,
                stack: Some(stack),
                ledger,
                frames: frames.frames,
                output_peers: frames.output_peers,
                #[cfg(target_os = "linux")]
                output_peer_holds: frames.output_peer_holds,
                source_work: frames.source_work,
                #[cfg(all(target_os = "linux", feature = "ebpf"))]
                host_process: None,
                queue: frames.queue,
                head: 0,
                queued: 0,
                frame_size,
                cpu_tx_caps: caps,
                next_tx: TxClass::Control,
                slots: frames.slots,
                half_open: (0..resources.as_ref().map_or(0, |_| limits.max_slots))
                    .map(|_| None)
                    .collect(),
                #[cfg(target_os = "linux")]
                peers: frames.peers,
                #[cfg(target_os = "linux")]
                peer_end: 0,
                #[cfg(target_os = "linux")]
                fragment_peers: (0..if capture && worker == 0 { 80 } else { 0 })
                    .map(|_| None)
                    .collect(),
                #[cfg(target_os = "linux")]
                fragment_peer_count: 0,
                resources,
                capture_admission: None,
                pending_closes: 0,
                closed_apps: 0,
                reap_pending: false,
                pending_routing: 0,
                waiters: (0..limits.max_waiters).map(|_| None).collect(),
                credit_waiters: 0,
                tx_waiters: 0,
                output_waker: None,
                turn_needs_scan: None,
                abort_wake_end: 0,
                closing: false,
                aborted: paused,
                finished: false,
                endpoint_prepared: false,
                _storage: storage,
            }),
            owner_wake: Notify::new(),
            #[cfg(target_os = "linux")]
            direct_relay_runtime: OnceLock::new(),
            #[cfg(all(test, feature = "native-api"))]
            startup_pause: Mutex::new(None),
            _metadata: metadata,
        });
        let scope = Self(shared);
        Ok((scope.clone(), PacketOwner { scope }))
    }

    pub(in crate::control) fn prepare_endpoint(&self) -> io::Result<usize> {
        self.0.with(|inner| {
            let stack = inner.stack.as_mut().ok_or_else(closed)?;
            if inner.closing
                || !stack.is_quiescent()
                || inner.slots.iter().any(Option::is_some)
                || inner.ledger.outstanding_tx().next().is_some()
            {
                return Err(invalid("packet scope is already in use"));
            }
            stack.set_accepting(false);
            inner.endpoint_prepared = true;
            Ok(inner.slots.len())
        })
    }

    pub(in crate::control) fn open_admission_if(
        &self,
        allowed: impl FnOnce() -> bool,
    ) -> io::Result<()> {
        self.0.with(|inner| {
            if inner.closing || !allowed() {
                return Err(closed());
            }
            if self.auxiliary_active() {
                inner.stack.as_mut().ok_or_else(closed)?.set_accepting(true);
            }
            Ok(())
        })
    }

    #[cfg(all(test, feature = "native-api"))]
    pub(in crate::control) fn pause_startup(
        &self,
        entered: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) {
        *self.0.startup_pause.lock() = Some((entered, release));
    }

    #[cfg(all(test, feature = "native-api"))]
    pub(in crate::control) async fn startup_checkpoint(&self) {
        let pause = self.0.startup_pause.lock().take();
        if let Some((entered, release)) = pause {
            let _ = entered.send(());
            let _ = release.await;
        }
    }

    pub fn scope(&self) -> ScopeId {
        self.0.scope
    }

    pub(crate) fn worker(&self) -> usize {
        self.0.worker
    }

    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn direct_relay_published(&self) -> bool {
        self.0.direct_relay_runtime.get().is_some()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn publish_direct_relay_runtime(
        &self,
        runtime: tokio::runtime::Handle,
        fence: Arc<DirectRelayFence>,
    ) -> io::Result<()> {
        self.0
            .direct_relay_runtime
            .set(DirectRelayOwner { runtime, fence })
            .map_err(|_| invalid("direct relay runtime already published"))
    }

    fn peer_bytes(aliases: usize) -> Option<usize> {
        #[cfg(target_os = "linux")]
        {
            aliases.checked_mul(size_of::<Option<crate::xdp::worker::PeerHold>>())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = aliases;
            Some(0)
        }
    }

    fn fragment_peer_bytes(physical_owner_zero: bool) -> usize {
        #[cfg(target_os = "linux")]
        {
            if physical_owner_zero {
                80 * size_of::<Option<FragmentPeer>>()
            } else {
                0
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = physical_owner_zero;
            0
        }
    }

    pub fn budget(&self) -> Arc<MemoryBudget> {
        Arc::clone(
            self.0
                .auxiliary
                .as_ref()
                .map_or(&self.0.budget, |aux| &aux.root),
        )
    }

    /// Borrowed `Rx` ranges index `packet`: consume/copy them before recycling input storage.
    /// Closing admission does not stop delivery to existing TCP/TIME_WAIT incarnations.
    pub fn receive(&self, packet: &[u8], now: Instant) -> Rx {
        self.0.with(|inner| {
            if inner.aborted {
                return Rx::Dropped(DropReason::Stale);
            }
            if inner.source_work.is_host() {
                return Rx::Dropped(DropReason::NotForUs);
            }
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            if inner.host_process.is_some() {
                return self
                    .receive_process(inner, packet, RxMeta::VERIFY, now, |_| true)
                    .0;
            }
            if inner.resources.is_some() {
                return inner
                    .receive_checked(packet, RxMeta::VERIFY, now, now, |_| true)
                    .0;
            }
            match &mut inner.stack {
                Some(stack) => stack.receive(now, packet),
                None => Rx::Dropped(DropReason::Stale),
            }
        })
    }

    /// The callback runs under the scope's existing output mutex, before protocol
    /// mutation/output wakes. It must not re-enter this scope or block on I/O.
    /// With `check_output`, the callback's second argument reports older unexported
    /// replies under that same mutex; false skips the reclamation-only scan.
    pub fn receive_with_source(
        &self,
        packet: &[u8],
        now: Instant,
        check_output: bool,
        on_source: impl FnMut(honk_netstack::ValidatedSource, bool) -> bool,
    ) -> (Rx, super::packet_endpoint::PacketReceive) {
        self.receive_with_meta_source(packet, RxMeta::VERIFY, now, check_output, on_source)
    }

    /// Applies driver metadata through the same locked source/admission reporting path.
    pub fn receive_with_meta_source(
        &self,
        packet: &[u8],
        meta: RxMeta,
        now: Instant,
        check_output: bool,
        mut on_source: impl FnMut(honk_netstack::ValidatedSource, bool) -> bool,
    ) -> (Rx, super::packet_endpoint::PacketReceive) {
        self.0.with(|inner| {
            if inner.source_work.is_host() {
                return (Rx::Dropped(DropReason::NotForUs), Default::default());
            }
            let pending = check_output && inner.pending_source_output(packet);
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            if inner.host_process.is_some() {
                return self.receive_process(inner, packet, meta, now, |source| {
                    on_source(source, pending)
                });
            }
            let (rx, report) =
                inner.receive_checked(packet, meta, now, now, |source| on_source(source, pending));
            (rx, inner.receive_result(report))
        })
    }

    pub(crate) fn retains_tcp(&self, source: SocketAddr, destination: SocketAddr) -> bool {
        self.retains_tcp_with_lineage(source, destination, None)
    }

    pub(crate) fn retains_source(&self, address: IpAddr) -> bool {
        let inner = self.0.inner.lock();
        inner
            .stack
            .as_ref()
            .is_some_and(|stack| stack.retains_source(address))
            || inner
                .slots
                .iter()
                .flatten()
                .any(|slot| slot.client.ip() == address)
            || inner.output_peers.contains(&Some(address))
            || inner.source_work.retains_address(address)
    }

    #[cfg(test)]
    pub(in crate::control) fn receive_admitted_with_source(
        &self,
        packet: &[u8],
        now: Instant,
        admission: &mut Option<super::packet_endpoint::EndpointAdmission>,
        check_output: bool,
        on_source: impl FnMut(honk_netstack::ValidatedSource, bool) -> bool,
    ) -> (Rx, super::packet_endpoint::PacketReceive) {
        let result = self.receive_admitted_deferred_with_source(
            packet,
            now,
            now,
            admission,
            check_output,
            on_source,
        );
        self.after_receive();
        result
    }

    pub(in crate::control) fn receive_admitted_deferred_with_source(
        &self,
        packet: &[u8],
        now: Instant,
        service_at: Instant,
        admission: &mut Option<super::packet_endpoint::EndpointAdmission>,
        check_output: bool,
        mut on_source: impl FnMut(honk_netstack::ValidatedSource, bool) -> bool,
    ) -> (Rx, super::packet_endpoint::PacketReceive) {
        self.0.with_silent(|inner| {
            if inner.source_work.is_host() {
                return (Rx::Dropped(DropReason::NotForUs), Default::default());
            }
            let pending = check_output && inner.pending_source_output(packet);
            let (rx, report) =
                inner.receive_checked(packet, RxMeta::VERIFY, now, service_at, |source| {
                    on_source(source, pending)
                });
            inner.register_tcp_new(&report, admission, None);
            if inner.resources.is_some() {
                inner.advance(service_at);
            }
            (rx, inner.receive_result(report))
        })
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    fn receive_process(
        &self,
        inner: &mut Inner,
        packet: &[u8],
        meta: RxMeta,
        now: Instant,
        on_source: impl FnMut(honk_netstack::ValidatedSource) -> bool,
    ) -> (Rx, super::packet_endpoint::PacketReceive) {
        let (rx, report) = inner.receive_checked(packet, meta, now, now, on_source);
        inner.bind_host_process(rx, report, |inner, source| {
            inner
                .host_process
                .as_ref()
                .expect("gateway Host binding")
                .process(self.binding(), source.src, source.dst, source.protocol)
        })
    }

    pub(in crate::control) fn has_pending_accept(&self) -> bool {
        let inner = self.0.inner.lock();
        !inner.closing && inner.stack.as_ref().is_some_and(Stack::has_pending_accept)
    }

    /// Accepts with an immediate SYN-ACK. This is not kernel accepted-child evidence.
    pub fn poll_accept(&self) -> Option<(SynInfo, FlowIo)> {
        self.0.with(|inner| {
            if inner.closing {
                return None;
            }
            let vacant = inner.slots.iter().position(Option::is_none);
            if vacant.is_none() && inner.pending_routing == 0 {
                return None;
            }
            let stack = inner.stack.as_mut()?;
            let syn = stack.poll_accept()?;
            let pending = inner
                .slots
                .iter_mut()
                .flatten()
                .find(|slot| slot.id == syn.id);
            if vacant.is_none() && pending.is_none() {
                stack.tcp_refuse(syn.id, honk_netstack::Refuse::Drop);
                return None;
            }
            let process = pending.as_ref().and_then(|slot| slot.process);
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            if inner.host_process.is_some() && process.is_none() {
                stack.tcp_refuse(syn.id, honk_netstack::Refuse::Drop);
                return None;
            }
            if stack.tcp_accept(syn.id, AcceptOpts::default()).is_err() {
                stack.tcp_abort(syn.id);
                return None;
            }
            let source = pending.as_ref().and_then(|slot| slot.source);
            let routing = if let Some(slot) = pending {
                slot.accepted = true;
                inner.pending_routing -= 1;
                slot.routing.take()
            } else {
                let Some(vacant) = vacant else {
                    stack.tcp_abort(syn.id);
                    return None;
                };
                inner.slots[vacant] = Some(FlowSlot {
                    id: syn.id,
                    client: syn.client,
                    destination: syn.original_dst,
                    app_open: true,
                    close_pending: false,
                    retiring: false,
                    outputs: 0,
                    rx: None,
                    tx: None,
                    callback: None,
                    accepted: true,
                    rx_admitted: false,
                    routing: None,
                    process: None,
                    source: None,
                });
                None
            };
            let mut flow = FlowIo::new(self.clone(), syn, process);
            flow.set_routing(routing);
            if let Some(context) = source {
                let work = SourceWork::retained(self, &mut inner.source_work, context)
                    .expect("admitted TCP source owner");
                flow.set_packet_source(work);
            }
            Some((syn, flow))
        })
    }

    pub fn datagram_sender(&self, source: SocketAddr) -> DatagramSender {
        DatagramSender {
            scope: self.clone(),
            binding: self.binding(),
            source,
            packet_source: None,
            realm: None,
        }
    }

    pub fn close_admission(&self) {
        self.0.with(|inner| {
            if let Some(stack) = &mut inner.stack {
                stack.set_accepting(false);
            }
        });
    }

    /// Graceful shutdown preserves protocol timers and existing ingress. Abort explicitly
    /// disposes queued CPU packets/protocol state, but cannot reclaim exported output leases.
    pub fn shutdown(&self, abort: bool) {
        let mut inner = self.0.inner.lock();
        let wake_credit = !inner.closing && inner.credit_waiters != 0;
        inner.closing = true;
        if let Some(aux) = &self.0.auxiliary {
            aux.close();
        }
        if let Some(stack) = &mut inner.stack {
            stack.set_accepting(false);
        }
        let output = if abort {
            inner.turn_needs_scan = None;
            let output = inner.output_waker.take();
            inner.abort();
            output
        } else {
            None
        };
        let mut wakes = Shared::events(&mut inner, None);
        if wake_credit {
            Shared::wake_terminal_waiters(&mut inner, WaitFor::Credit, &mut wakes);
        }
        let device = inner.device_wake();
        let reap = inner.closed_apps != 0;
        drop(inner);
        deliver_wakes(output.into_iter(), &mut wakes);
        wakes = wakes.and(catch_unwind(AssertUnwindSafe(|| self.0.wake_owner(device))));
        if reap {
            wakes = wakes.and(catch_unwind(AssertUnwindSafe(|| self.0.reap())));
        }
        resume_wake_panic(wakes);
    }

    /// Explicit-clock driving for an embedding owner or deterministic packet script.
    /// Do not run this concurrently with `PacketOwner::run` as a second timer owner.
    pub fn drive(&self, now: Instant) {
        self.0.with(|inner| {
            inner.drive(now);
        });
    }

    /// One L3 output consumer per scope. Retain the lease through actual I/O completion.
    pub fn poll_output(&self, cx: &mut Context<'_>) -> Poll<Option<OutputLease>> {
        self.poll_output_from(cx, None)
    }

    /// Oldest queued output of `class`, so a device without bulk credit can still drain control.
    pub fn poll_output_class(
        &self,
        cx: &mut Context<'_>,
        class: TxClass,
    ) -> Poll<Option<OutputLease>> {
        self.poll_output_from(cx, Some(class))
    }

    /// Fill empty lease cells with the oldest outputs of `class`, in queue order.
    /// The destination must contain 1..=64 empty cells; retain leases through actual I/O.
    pub fn poll_outputs_class(
        &self,
        cx: &mut Context<'_>,
        class: TxClass,
        outputs: &mut [Option<OutputLease>],
    ) -> Poll<Option<usize>> {
        self.poll_outputs_from(cx, Some(class), outputs)
    }

    fn poll_output_from(
        &self,
        cx: &mut Context<'_>,
        class: Option<TxClass>,
    ) -> Poll<Option<OutputLease>> {
        let mut outputs = [None];
        self.poll_outputs_from(cx, class, &mut outputs)
            .map(|count| count.map(|_| outputs[0].take().expect("exported output")))
    }

    fn poll_outputs_from(
        &self,
        cx: &mut Context<'_>,
        class: Option<TxClass>,
        outputs: &mut [Option<OutputLease>],
    ) -> Poll<Option<usize>> {
        self.0.with(|inner| inner.export(self, cx, class, outputs))
    }

    pub async fn next_output(&self) -> Option<OutputLease> {
        poll_fn(|cx| self.poll_output(cx)).await
    }

    /// No live TCP/TIME_WAIT/control protocol state and no flow slot; exported leases may remain.
    pub fn is_protocol_quiescent(&self) -> bool {
        let inner = self.0.inner.lock();
        inner.stack.as_ref().is_none_or(Stack::is_quiescent)
            && inner.slots.iter().all(Option::is_none)
    }

    pub fn stats(&self) -> Option<StackStats> {
        self.0.inner.lock().stack.as_ref().map(Stack::stats)
    }
}

fn deliver_wakes(mut wakers: impl Iterator<Item = Waker>, delivered: &mut std::thread::Result<()>) {
    // The iterator advances before calling arbitrary application code. A panicking wake
    // cannot consume its siblings; report the first failure after delivering the rest.
    while let Err(panic) = catch_unwind(AssertUnwindSafe(|| {
        for waker in wakers.by_ref() {
            waker.wake();
        }
    })) {
        if delivered.is_ok() {
            *delivered = Err(panic);
        }
    }
}

fn resume_wake_panic(delivered: std::thread::Result<()>) {
    // Scope or stream Drop may already be unwinding the original actor's panic.
    if let Err(panic) = delivered
        && !std::thread::panicking()
    {
        resume_unwind(panic);
    }
}

impl Shared {
    fn with_silent<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        f(&mut self.inner.lock())
    }

    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let mut inner = self.inner.lock();
        let result = f(&mut inner);
        self.finish_with(inner);
        result
    }

    fn finish_with(&self, inner: MutexGuard<'_, Inner>) {
        self.finish_with_wakers(inner, None);
    }

    fn finish_with_wakers(
        &self,
        mut inner: MutexGuard<'_, Inner>,
        first: Option<[Option<Waker>; 2]>,
    ) {
        let mut wakes = Self::events(&mut inner, first);
        let closed_apps = inner.closed_apps != 0;
        let device = inner.device_wake();
        drop(inner);
        wakes = wakes.and(catch_unwind(AssertUnwindSafe(|| self.wake_owner(device))));
        if closed_apps {
            wakes = wakes.and(catch_unwind(AssertUnwindSafe(|| self.reap())));
        }
        resume_wake_panic(wakes);
    }

    fn events(
        inner: &mut MutexGuard<'_, Inner>,
        mut first: Option<[Option<Waker>; 2]>,
    ) -> std::thread::Result<()> {
        inner.drain_stream_state();
        let mut delivered = Ok(());
        while let Some(first) = first.take().or_else(|| inner.next_stream_wakers()) {
            // Reserve both directions before consuming another coalesced Stack event.
            let mut batch = [const { [None, None] }; BATCH / 2];
            batch[0] = first;
            let mut count = 1;
            for cell in &mut batch[1..] {
                let Some(pair) = inner.next_stream_wakers() else {
                    break;
                };
                *cell = pair;
                count += 1;
            }
            MutexGuard::unlocked(inner, || {
                deliver_wakes(
                    batch.into_iter().take(count).flatten().flatten(),
                    &mut delivered,
                );
            });
            if count < BATCH / 2 {
                break;
            }
        }
        if let Some(stack) = &mut inner.stack {
            stack.take_tx_wakeup();
        }
        delivered
    }

    fn wake_terminal_waiters(
        inner: &mut MutexGuard<'_, Inner>,
        reason: WaitFor,
        wakes: &mut std::thread::Result<()>,
    ) {
        // Each future keeps its cell until it observes completion or cancels, even
        // while an unlocked waker re-enters the scope and registers another wait.
        for start in (0..inner.waiters.len()).step_by(BATCH) {
            let mut matches = inner.waiters[start..]
                .iter()
                .take(BATCH)
                .flatten()
                .filter(|registration| registration.reason == reason);
            let mut batch = [const { None }; BATCH];
            for (cell, registration) in batch.iter_mut().zip(&mut matches) {
                *cell = Some(registration.waker.clone());
            }
            if batch[0].is_some() {
                MutexGuard::unlocked(inner, || deliver_wakes(batch.into_iter().flatten(), wakes));
            }
        }
    }

    fn reap(&self) {
        let mut wakes = Ok(());
        loop {
            let (index, id, callback) = {
                let mut inner = self.inner.lock();
                if inner.closed_apps == 0 {
                    break;
                }
                let protocol_changed = inner
                    .stack
                    .as_mut()
                    .is_some_and(Stack::take_tcp_retention_change);
                if !inner.reap_pending && !protocol_changed {
                    break;
                }
                let found = inner.slots.iter().position(|slot| {
                    slot.as_ref().is_some_and(|slot| {
                        !slot.app_open
                            && !slot.retiring
                            && slot.outputs == 0
                            && !inner
                                .stack
                                .as_ref()
                                .is_some_and(|stack| stack.tcp_retained(slot.id))
                    })
                });
                let Some(index) = found else {
                    inner.reap_pending = false;
                    break;
                };
                // An unlocked callback can re-enter and drain the remaining eligible slots.
                inner.reap_pending = true;
                let slot = inner.slots[index].as_mut().expect("retiring exact slot");
                slot.retiring = true;
                (index, slot.id, slot.callback.take())
            };
            if let Some(callback) = callback {
                wakes = wakes.and(catch_unwind(AssertUnwindSafe(callback.callback)));
            }
            let mut inner = self.inner.lock();
            let slot = inner.slots[index]
                .take()
                .expect("retirement callback owns exact slot");
            assert_eq!(slot.id, id);
            inner.tx_waiters -= usize::from(slot.tx.is_some());
            inner.closed_apps -= 1;
            let device = inner.device_wake();
            Self::wake_terminal_waiters(&mut inner, WaitFor::Retirement(id), &mut wakes);
            drop(inner);
            wakes = wakes.and(catch_unwind(AssertUnwindSafe(|| self.wake_owner(device))));
        }
        resume_wake_panic(wakes);
    }

    /// Applies `Inner::device_wake` after unlocking. Notify carries a permit even if the
    /// owner has not started awaiting yet.
    fn wake_owner(&self, device: Option<Option<Waker>>) {
        match device {
            Some(Some(waker)) => waker.wake(),
            // The driver is scheduled, entering its first service, or recording a turn rescan.
            Some(None) => {}
            None => self.owner_wake.notify_one(),
        }
    }
}

impl Inner {
    fn receive_result(
        &self,
        report: honk_netstack::ReceiveReport,
    ) -> super::packet_endpoint::PacketReceive {
        use honk_netstack::ReceiveOutcome::{TcpAccepted, TcpNew};

        let owner = match report.outcome {
            TcpAccepted(id) | TcpNew(id) if !self.closing && !self.finished => {
                self.slots.iter().flatten().find(|slot| slot.id == id)
            }
            _ => None,
        };
        Self::receive_from_slot(report, owner)
    }

    fn receive_from_slot(
        report: honk_netstack::ReceiveReport,
        owner: Option<&FlowSlot>,
    ) -> super::packet_endpoint::PacketReceive {
        super::packet_endpoint::PacketReceive {
            source: report.source,
            source_context: report.source_context,
            qualified_rx: matches!(
                report.outcome,
                honk_netstack::ReceiveOutcome::TcpAccepted(_)
            ) && owner.is_some_and(|slot| slot.rx_admitted),
            taken_over: owner.is_some(),
        }
    }

    /// Under this mutex: the driving device's wake, or `None` to notify the original owner.
    /// Returned/Abandoned progress goes to the original owner, never a stale device task.
    fn device_wake(&mut self) -> Option<Option<Waker>> {
        (self.rights == Rights::Driven).then(|| self.take_output_wake())
    }

    fn take_output_wake(&mut self) -> Option<Waker> {
        if let Some(rescan) = &mut self.turn_needs_scan {
            *rescan = [true; 2];
            None
        } else {
            self.output_waker.take()
        }
    }

    /// The one CPU-output consumer body, shared by `Shared::with` and the device driver.
    fn export(
        &mut self,
        scope: &PacketScope,
        cx: &Context<'_>,
        class: Option<TxClass>,
        outputs: &mut [Option<OutputLease>],
    ) -> Poll<Option<usize>> {
        assert!(!outputs.is_empty() && outputs.len() <= BATCH);
        assert!(
            outputs.iter().all(Option::is_none),
            "empty output destination"
        );
        let mut count = 0;
        for output in outputs {
            let Some(queued) = self.pop(class) else { break };
            let index = self.index(queued.lease);
            let bytes = self.frames[index]
                .take()
                .expect("queued frame owns storage");
            *output = Some(OutputLease(OutputOwner {
                scope: scope.clone(),
                queued: Some(queued),
                bytes: Some(bytes),
            }));
            count += 1;
        }
        if count != 0 {
            return Poll::Ready(Some(count));
        }
        if self.finished || self.aborted {
            return Poll::Ready(None);
        }
        if self.turn_needs_scan.is_none() {
            register(&mut self.output_waker, cx.waker());
        }
        Poll::Pending
    }

    fn pending_source_output(&self, packet: &[u8]) -> bool {
        let Ok((address, _)) = honk_netstack::wire::packet_addresses(packet) else {
            return false;
        };
        self.stack
            .as_ref()
            .is_some_and(|stack| stack.retains_source_output(address))
            || self
                .queue
                .iter()
                .flatten()
                .any(|queued| self.output_peers[self.index(queued.lease)] == Some(address))
    }

    // ponytail: bounded linear owner lookup; use a fixed index if measured flow counts need it.
    fn slot_index(&self, id: FlowId) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|slot| slot.id == id))
    }

    fn slot(&mut self, id: FlowId) -> Option<&mut FlowSlot> {
        let index = self.slot_index(id)?;
        self.slots[index].as_mut()
    }

    fn register_tx(&mut self, id: FlowId, waker: &Waker) {
        if let Some(slot) = self.slot(id) {
            let new = slot.tx.is_none();
            register(&mut slot.tx, waker);
            self.tx_waiters += usize::from(new);
        }
    }

    fn take_stream_wakers(&mut self, index: usize, read: bool, write: bool) -> [Option<Waker>; 2] {
        let slot = self.slots[index].as_mut().expect("retained stream slot");
        let tx = write.then(|| slot.tx.take()).flatten();
        self.tx_waiters -= usize::from(tx.is_some());
        [read.then(|| slot.rx.take()).flatten(), tx]
    }

    fn index(&self, lease: FrameLease) -> usize {
        lease.address() as usize / self.frame_size
    }

    fn push(&mut self, queued: Queued) {
        assert!(
            self.queued < self.queue.len(),
            "reserved frame funds its output queue cell"
        );
        let tail = (self.head + self.queued) % self.queue.len();
        self.queue[tail] = Some(queued);
        self.queued += 1;
        if let Some(waker) = self.take_output_wake() {
            waker.wake();
        }
    }

    // ponytail: O(queued) shift, bounded by the scope's TX frames; per-class rings if measured.
    fn pop(&mut self, class: Option<TxClass>) -> Option<Queued> {
        let len = self.queue.len();
        let at = (0..self.queued).find(|&i| {
            class.is_none_or(|class| {
                self.queue[(self.head + i) % len].is_some_and(|queued| queued.class == class)
            })
        })?;
        let queued = self.queue[(self.head + at) % len].take();
        for i in (0..at).rev() {
            self.queue[(self.head + i + 1) % len] = self.queue[(self.head + i) % len].take();
        }
        self.head = (self.head + 1) % len;
        self.queued -= 1;
        queued
    }

    fn install(
        &mut self,
        lease: FrameLease,
        index: usize,
        tx: Transmit,
        class: TxClass,
        destination: IpAddr,
        fragment: Option<honk_netstack::FragmentInfo>,
    ) -> io::Result<Queued> {
        #[cfg(not(target_os = "linux"))]
        let _ = fragment;
        if let Some(context) = tx.source {
            assert!(
                self.source_work.facts(context).is_some(),
                "emitted original Host source"
            );
        }
        self.ledger
            .submit_tx(lease, tx.len, tx.flow)
            .map_err(io::Error::other)?;
        self.output_peers[index] = Some(destination);
        #[cfg(target_os = "linux")]
        if let Some(output) = self.output_peer_holds.get_mut(index) {
            *output = match fragment {
                Some(info) if self.fragment_peer_count != 0 => self
                    .fragment_peers
                    .iter()
                    .flatten()
                    .find(|peer| {
                        info.incarnation.is_some() && peer.info.incarnation == info.incarnation
                    })
                    .and_then(|peer| peer.peer.clone()),
                Some(_) => None,
                None => self
                    .peers
                    .iter()
                    .flatten()
                    .find(|peer| peer.address() == destination)
                    .cloned(),
            };
        }
        if let Some(context) = tx.source {
            self.source_work.retain_output(context);
        }
        if let Some(id) = tx.flow
            && let Some(slot) = self.slot(id)
        {
            slot.outputs += 1;
        }
        Ok(Queued { lease, tx, class })
    }

    fn publish(
        &mut self,
        lease: FrameLease,
        tx: Transmit,
        class: TxClass,
        fragment: Option<honk_netstack::FragmentInfo>,
    ) {
        let index = self.index(lease);
        let destination = honk_netstack::wire::packet_addresses(
            &self.frames[index]
                .as_ref()
                .expect("reserved output storage")[..tx.len],
        )
        .expect("stack output has IP addresses")
        .1;
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        if tx.flow.is_none()
            && let Some(binding) = &mut self.host_process
        {
            let bytes = &self.frames[index].as_ref().expect("reserved Host output")[..tx.len];
            binding.outputs[index] = auxiliary::HostOutput::from_packet(bytes, fragment);
        }
        let queued = self
            .install(lease, index, tx, class, destination, fragment)
            .expect("reserved complete output frame");
        self.push(queued);
    }

    fn release(&mut self, queued: Queued) {
        let index = self.index(queued.lease);
        self.output_peers[index] = None;
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        if let Some(binding) = &mut self.host_process {
            binding.outputs[index] = None;
        }
        #[cfg(target_os = "linux")]
        if let Some(peer) = self.output_peer_holds.get_mut(index) {
            peer.take();
        }
        let owner = self
            .ledger
            .release_tx(queued.lease)
            .expect("unique local output lease release");
        assert_eq!(owner, queued.tx.flow);
        if let Some(context) = queued.tx.source {
            self.source_work.release_output(context);
        }
        if let Some(id) = owner
            && let Some(slot) = self.slot(id)
        {
            slot.outputs = slot.outputs.checked_sub(1).expect("original output owner");
            if slot.outputs == 0 && !slot.app_open {
                self.reap_pending = true;
            }
        }
    }

    fn release_output(&mut self, queued: Queued, bytes: Option<Box<[u8]>>) {
        let index = self.index(queued.lease);
        if let Some(bytes) = bytes {
            assert!(
                self.frames[index].replace(bytes).is_none(),
                "exclusive output storage"
            );
        } else {
            assert!(self.frames[index].is_some(), "funded direct output storage");
        }
        self.release(queued);
    }

    fn pull(&mut self, now: Instant, class: TxClass) -> bool {
        let Some(stack) = &mut self.stack else {
            return false;
        };
        let Ok(lease) = self.ledger.reserve_tx(class) else {
            return false;
        };
        let index = lease.address() as usize / self.frame_size;
        let out = self.frames[index]
            .as_mut()
            .expect("free frame owns storage");
        let tx =
            Self::transmit_accounted(stack, &self.resources, now, class, out, self.cpu_tx_caps);
        if let Ok(Some((tx, fragment))) = tx {
            self.publish(lease, tx, class, fragment);
            true
        } else {
            self.ledger
                .cancel_tx(lease)
                .expect("unused output reservation");
            false
        }
    }

    fn advance(&mut self, now: Instant) {
        if let Some(stack) = &mut self.stack {
            stack.handle_timeout(now);
            if self.pending_closes != 0 {
                // Drop may follow a timer-free idle; close needs this owner's fresh clock.
                for slot in self.slots.iter_mut().flatten() {
                    if std::mem::take(&mut slot.close_pending) {
                        stack.tcp_close(slot.id);
                    }
                }
                self.pending_closes = 0;
            }
        }
        self.drain_half_open();
    }

    fn fill(&mut self, now: Instant) -> bool {
        let mut sent = 0;
        for _ in 0..BATCH {
            let first = self.next_tx;
            let second = match first {
                TxClass::Control => TxClass::Bulk,
                TxClass::Bulk => TxClass::Control,
            };
            if self.pull(now, first) {
                self.next_tx = second;
            } else if self.pull(now, second) {
                self.next_tx = first;
            } else {
                break;
            }
            sent += 1;
        }
        if sent != 0 {
            self.wake_credit_waiters();
        }
        sent == BATCH
    }

    fn drive(&mut self, now: Instant) -> bool {
        self.advance(now);
        self.fill(now)
    }

    fn drain_stream_state(&mut self) {
        self.drain_half_open();
        if self.pending_routing != 0 {
            for slot in self.slots.iter_mut().flatten() {
                if !slot.accepted
                    && slot.app_open
                    && !self
                        .stack
                        .as_ref()
                        .is_some_and(|stack| stack.tcp_retained(slot.id))
                {
                    slot.app_open = false;
                    slot.routing.take();
                    self.closed_apps += 1;
                    self.reap_pending = true;
                    self.pending_routing -= 1;
                }
            }
        }
        #[cfg(target_os = "linux")]
        self.reap_peers();
    }

    fn next_stream_wakers(&mut self) -> Option<[Option<Waker>; 2]> {
        while self.abort_wake_end != 0 {
            self.abort_wake_end -= 1;
            if let Some(slot) = &mut self.slots[self.abort_wake_end]
                && (slot.rx.is_some() || slot.tx.is_some())
            {
                return Some(self.take_stream_wakers(self.abort_wake_end, true, true));
            }
        }
        while let Some((id, ready)) = self.stack.as_mut().and_then(Stack::poll_event) {
            let Some(index) = self.slot_index(id) else {
                continue;
            };
            let rx = ready.contains(Ready::READABLE)
                || ready.contains(Ready::READ_CLOSED)
                || ready.contains(Ready::ERROR);
            let tx = ready.contains(Ready::WRITABLE)
                || ready.contains(Ready::CONNECTED)
                || ready.contains(Ready::ERROR);
            let wakers = self.take_stream_wakers(index, rx, tx);
            if wakers.iter().any(Option::is_some) {
                return Some(wakers);
            }
        }
        None
    }

    fn wake_credit_waiters(&self) {
        if self.credit_waiters != 0 && !self.closing {
            for registration in self.waiters.iter().flatten() {
                if registration.reason == WaitFor::Credit {
                    registration.waker.wake_by_ref();
                }
            }
        }
    }

    fn abort(&mut self) {
        if !self.aborted {
            self.abort_wake_end = self.slots.len();
        }
        self.aborted = true;
        // Dropping the stack is explicit protocol disposal, never a fabricated device return.
        self.stack = None;
        self.reap_pending = true;
        for grant in &mut self.half_open {
            grant.take();
        }
        while let Some(queued) = self.pop(None) {
            self.release(queued);
        }
    }

    fn finish(&mut self) -> bool {
        let protocol_empty = self.stack.as_ref().is_none_or(Stack::is_quiescent);
        if self.closing && protocol_empty && self.slots.iter().all(Option::is_none) {
            self.source_work
                .reclaim(self.stack.as_ref(), &self.slots)
                .expect("retained source identities remain valid through close");
        }
        if self.closing
            && protocol_empty
            && self.slots.iter().all(Option::is_none)
            && self.queued == 0
            && self.source_work.is_empty()
            && self.ledger.outstanding_tx().next().is_none()
        {
            self.finished = true;
            self.stack = None;
            for grant in &mut self.half_open {
                grant.take();
            }
            #[cfg(target_os = "linux")]
            self.reap_peers();
            self.ledger.close();
        }
        self.finished
    }
}

/// The timer/output future belongs to the embedding endpoint's joined task set.
/// Dropping/cancelling it explicitly aborts protocol work without reclaiming consumer leases.
pub struct PacketOwner {
    scope: PacketScope,
}

impl PacketOwner {
    pub fn scope(&self) -> ScopeId {
        self.scope.scope()
    }
    pub(crate) async fn shutdown(self) {
        self.scope.shutdown(true);
        self.run().await;
    }

    /// The validated endpoint start's one-time Task → Driven transfer. This original owner
    /// keeps the joined finish obligation: park it in `reclaim`, then run it.
    pub(in crate::control) fn hand_off(&self) -> PacketDriver {
        let mut inner = self.scope.0.inner.lock();
        assert!(
            inner.rights == Rights::Task,
            "one driving right per original owner"
        );
        inner.rights = Rights::Driven;
        drop(inner);
        PacketDriver {
            scope: self.scope.clone(),
            fallback: None,
            deadline: None,
        }
    }

    /// Park while a device drives this scope, then take the right back. True only for a
    /// return after actual finish; either way the caller must still run this owner.
    pub(in crate::control) async fn reclaim(&self) -> bool {
        loop {
            // The state is authoritative; an armed Notify only hints that it changed.
            let notified = self.scope.0.owner_wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut inner = self.scope.0.inner.lock();
                if inner.rights != Rights::Driven {
                    let returned = inner.rights == Rights::Returned && inner.finished;
                    inner.rights = Rights::Task;
                    return returned;
                }
            }
            notified.await;
        }
    }

    pub async fn run(self) {
        loop {
            let notified = self.scope.0.owner_wake.notified();
            tokio::pin!(notified);
            // The owner does not use Shared::with: its own work must not self-notify forever.
            let (more, deadline) = {
                let mut inner = self.scope.0.inner.lock();
                let now = Instant::now();
                let more = inner.drive(now);
                resume_wake_panic(Shared::events(&mut inner, None));
                let mut deadline = inner.stack.as_ref().and_then(Stack::poll_timeout);
                if inner.credit_waiters != 0 || inner.tx_waiters != 0 {
                    let readiness = now + READINESS_FALLBACK;
                    deadline = Some(deadline.map_or(readiness, |due| due.min(readiness)));
                }
                (more, deadline)
            };
            self.scope.0.reap();
            {
                let mut inner = self.scope.0.inner.lock();
                if inner.finish() {
                    let output = inner.output_waker.take();
                    drop(inner);
                    if let Some(waker) = output {
                        waker.wake();
                    }
                    return;
                }
            }
            if more {
                tokio::task::yield_now().await;
                continue;
            }
            if let Some(deadline) = deadline {
                tokio::select! {
                    _ = &mut notified => {},
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                        self.scope.0.inner.lock().wake_credit_waiters();
                    },
                }
            } else {
                notified.await;
            }
        }
    }
}

impl Drop for PacketOwner {
    fn drop(&mut self) {
        let finished = self.scope.0.inner.lock().finished;
        if !finished {
            self.scope.shutdown(true);
        }
    }
}

pub(crate) enum MaterializedOutput {
    Idle,
    Closed,
    CpuQueuePending,
    Packet(DirectOutput),
}

pub(crate) struct DirectOutput {
    pub(crate) owner: OutputOwner,
    #[cfg(target_os = "linux")]
    pub(crate) path: Option<crate::xdp::ReturnPath>,
    #[cfg(target_os = "linux")]
    pub(crate) ipv6: bool,
    #[cfg(all(target_os = "linux", test))]
    pub(crate) destination: IpAddr,
}

/// The exclusive driving right handed to one device owner. Not Clone; only `hand_off` makes
/// one. Keep it in the outer device owner, never inside a scope callback or lock holder.
pub(crate) struct PacketDriver {
    scope: PacketScope,
    // Kept until serviced so frequent unrelated device polls cannot postpone it.
    fallback: Option<Instant>,
    deadline: Option<Instant>,
}

impl PacketDriver {
    #[cfg(target_os = "linux")]
    pub(crate) fn sole_owner(&self) -> Option<&PacketScope> {
        (self.scope.0.workers == 1).then_some(&self.scope)
    }

    pub(crate) fn scope(&self) -> ScopeId {
        self.scope.scope()
    }

    pub(crate) fn worker(&self) -> usize {
        self.scope.worker()
    }

    /// The protocol or conditional refund-readiness deadline found by the last service.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn protocol_deadline(&self) -> Option<Instant> {
        // A deadline shared with the credit retry is not an independent protocol witness.
        self.deadline.filter(|&due| self.fallback != Some(due))
    }

    /// Complete CPU service for startup-only driving and realms using the CPU/SG path.
    pub(crate) fn service(&mut self, cx: &mut Context<'_>, now: Instant) -> bool {
        let more = self.begin(now, |inner| inner.fill(now));
        self.finish_turn(cx, now);
        more
    }

    /// Advance timers and pending closes before a bounded direct-output turn.
    pub(crate) fn begin_turn(&mut self, now: Instant) {
        self.begin(now, |inner| {
            inner.turn_needs_scan.get_or_insert([false; 2]);
            false
        });
    }

    fn begin(&mut self, now: Instant, output: impl FnOnce(&mut Inner) -> bool) -> bool {
        let mut inner = self.scope.0.inner.lock();
        if inner.rights != Rights::Driven {
            self.deadline = None;
            return false;
        }
        let armed = inner.output_waker.take();
        if self.fallback.is_some_and(|due| due <= now) {
            self.fallback = None;
            inner.wake_credit_waiters();
        }
        inner.advance(now);
        let more = output(&mut inner);
        inner.output_waker = armed;
        more
    }

    /// Rearm after the last emission or disposal, preserving any unserviced mutation.
    pub(crate) fn finish_turn(&mut self, cx: &mut Context<'_>, now: Instant) {
        let shared = &self.scope.0;
        let wakes = {
            let mut inner = shared.inner.lock();
            if inner.rights != Rights::Driven {
                self.deadline = None;
                return;
            }
            if inner.turn_needs_scan.is_none() {
                register(&mut inner.output_waker, cx.waker());
            }
            Shared::events(&mut inner, None)
        };
        shared.reap();
        let mut inner = shared.inner.lock();
        let armed = inner.output_waker.take();
        if inner.finish() {
            inner.turn_needs_scan = None;
            inner.rights = Rights::Returned;
            drop(inner);
            drop(armed);
            self.fallback = None;
            self.deadline = None;
            shared.owner_wake.notify_one();
            resume_wake_panic(wakes);
            return;
        }
        inner.output_waker = armed;
        register(&mut inner.output_waker, cx.waker());
        let blocked = inner.credit_waiters != 0 || inner.tx_waiters != 0;
        self.fallback = blocked.then(|| self.fallback.unwrap_or(now + READINESS_FALLBACK));
        self.deadline = [
            inner.stack.as_ref().and_then(Stack::poll_timeout),
            self.fallback,
        ]
        .into_iter()
        .flatten()
        .min();
        // A mutation after either class's last empty pull (or its budget cutoff) needs
        // one more poll. Later producers see the registration under the same mutex.
        if inner
            .turn_needs_scan
            .take()
            .is_some_and(|classes| classes.contains(&true))
        {
            let wake = inner.output_waker.take().expect("armed driving device");
            drop(inner);
            wake.wake();
        }
        resume_wake_panic(wakes);
    }

    /// A failed synchronous device round can enter asynchronous teardown before service resumes.
    #[cfg(target_os = "linux")]
    pub(crate) fn interrupt_turn(&mut self, cx: &Context<'_>) {
        let mut inner = self.scope.0.inner.lock();
        if inner.turn_needs_scan.take().is_some() {
            register(&mut inner.output_waker, cx.waker());
            drop(inner);
            // Even a clean output scan may have advanced a protocol deadline since the last arm.
            cx.waker().wake_by_ref();
        }
    }

    /// Discard only locally queued packets. Exported owners still need their actual CQ.
    #[cfg(target_os = "linux")]
    pub(crate) fn service_closing(&mut self, cx: &mut Context<'_>, now: Instant) -> bool {
        let more = self.begin(now, |inner| {
            for _ in 0..BATCH {
                let Some(queued) = inner.pop(None) else { break };
                inner.release(queued);
            }
            inner.queued != 0
        });
        self.finish_turn(cx, now);
        more
    }

    /// Emit into an already-reserved L3 frame, only after older CPU work of this class.
    pub(crate) fn materialize_into(
        &mut self,
        now: Instant,
        class: TxClass,
        l3: &mut [u8],
    ) -> io::Result<MaterializedOutput> {
        let mut inner = self.scope.0.inner.lock();
        if inner.rights != Rights::Driven
            || inner.aborted
            || inner.finished
            || inner.stack.is_none()
        {
            return Ok(MaterializedOutput::Closed);
        }
        let frame_size = inner.frame_size;
        if l3.len() < frame_size {
            return Err(invalid("short direct output frame"));
        }
        if inner.queued != 0
            && inner
                .queue
                .iter()
                .flatten()
                .any(|queued| queued.class == class)
        {
            if let Some(rescan) = &mut inner.turn_needs_scan {
                rescan[usize::from(class == TxClass::Bulk)] = true;
            } else if let Some(wake) = inner.output_waker.take() {
                drop(inner);
                wake.wake();
            }
            return Ok(MaterializedOutput::CpuQueuePending);
        }
        let lease = match inner.ledger.reserve_tx(class) {
            Ok(lease) => lease,
            Err(
                honk_datapath::buffer::LedgerError::NoFrame
                | honk_datapath::buffer::LedgerError::NoDescriptor,
            ) => return Ok(MaterializedOutput::Idle),
            Err(error) => return Err(io::Error::other(error)),
        };
        let mut reservation = OutputReservation {
            inner: &mut inner,
            lease: Some(lease),
        };
        let packet = &mut l3[..frame_size];
        let state = &mut *reservation.inner;
        let tx = Inner::transmit_accounted(
            state.stack.as_mut().expect("live driven stack"),
            &state.resources,
            now,
            class,
            packet,
            TxCaps::NONE,
        );
        state.drain_half_open();
        let Some((tx, fragment)) = tx? else {
            // The CPU prefix and this protocol class were both checked under this lock.
            // Only advance() can service a newly pending close.
            if reservation.inner.pending_closes == 0
                && !reservation.inner.closing
                && let Some(rescan) = &mut reservation.inner.turn_needs_scan
            {
                rescan[usize::from(class == TxClass::Bulk)] = false;
            }
            return Ok(MaterializedOutput::Idle);
        };
        if tx.len == 0 || tx.len > frame_size {
            return Err(io::Error::other("invalid direct output extent"));
        }
        let destination = honk_netstack::wire::packet_addresses(&packet[..tx.len])
            .map_err(io::Error::other)?
            .1;
        let index = reservation.inner.index(lease);
        let queued = reservation
            .inner
            .install(lease, index, tx, class, destination, fragment)?;
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        if tx.flow.is_none()
            && let Some(binding) = &mut reservation.inner.host_process
        {
            binding.outputs[index] =
                auxiliary::HostOutput::from_packet(&packet[..tx.len], fragment);
        }
        reservation.lease = None;
        #[cfg(target_os = "linux")]
        let path = reservation
            .inner
            .output_peer_holds
            .get(index)
            .and_then(Option::as_ref)
            .filter(|hold| hold.learned())
            .map(|hold| hold.original_path());
        drop(reservation);
        drop(inner);
        Ok(MaterializedOutput::Packet(DirectOutput {
            owner: OutputOwner {
                scope: self.scope.clone(),
                queued: Some(queued),
                bytes: None,
            },
            #[cfg(target_os = "linux")]
            path,
            #[cfg(target_os = "linux")]
            ipv6: destination.is_ipv6(),
            #[cfg(all(target_os = "linux", test))]
            destination,
        }))
    }

    /// `PacketScope::poll_outputs_class` for the driving device, without `Shared::with`.
    pub(crate) fn poll_outputs_class(
        &mut self,
        cx: &mut Context<'_>,
        class: TxClass,
        outputs: &mut [Option<OutputLease>],
    ) -> Poll<Option<usize>> {
        let mut inner = self.scope.0.inner.lock();
        if inner.rights != Rights::Driven {
            return Poll::Ready(None);
        }
        inner.export(&self.scope, cx, Some(class), outputs)
    }
}

impl Drop for PacketDriver {
    /// Only a right change; the parked original owner performs any cleanup.
    fn drop(&mut self) {
        let stale = {
            let mut inner = self.scope.0.inner.lock();
            if inner.rights != Rights::Driven {
                return;
            }
            inner.rights = Rights::Abandoned;
            inner.turn_needs_scan = None;
            inner.output_waker.take()
        };
        drop(stale);
        self.scope.0.owner_wake.notify_one();
    }
}

/// An immutable local output capability, not an AF_XDP completion descriptor.
/// Dropping/releasing it means the actual consumer has finished I/O or explicitly disposed it.
pub struct OutputLease(OutputOwner);

pub(crate) struct OutputOwner {
    scope: PacketScope,
    queued: Option<Queued>,
    bytes: Option<Box<[u8]>>,
}

impl OutputLease {
    pub fn packet(&self) -> &[u8] {
        self.0.packet().expect("CPU output storage")
    }
    pub(crate) fn transmit(&self) -> Transmit {
        self.0.queued.expect("live output lease").tx
    }
    #[cfg(test)]
    pub(crate) fn host_return(&self) -> Option<honk_ebpf_common::host::HostSourceFacts> {
        self.0.host_return()
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn peer_hold(&self) -> Option<crate::xdp::worker::PeerHold> {
        self.0.peer_hold()
    }
    pub fn flow_id(&self) -> Option<FlowId> {
        self.0.flow_id()
    }
    pub fn scope(&self) -> ScopeId {
        self.0.scope()
    }
    pub fn class(&self) -> TxClass {
        self.0.class()
    }
    pub fn release(self) {
        drop(self);
    }

    pub(crate) fn into_owner(self) -> OutputOwner {
        self.0
    }

    /// Return completed or explicitly disposed outputs without moving their owners.
    /// References may belong to several scopes; retirement callbacks run unlocked.
    /// Returned leases are inert: only their later destruction is valid.
    pub fn release_batch(outputs: &mut [Option<&mut OutputLease>]) {
        assert!(outputs.len() <= BATCH);
        let mut owners: [Option<&mut OutputOwner>; BATCH] = std::array::from_fn(|_| None);
        for (owner, output) in owners.iter_mut().zip(outputs.iter_mut()) {
            *owner = output.take().map(|output| &mut output.0);
        }
        OutputOwner::release_batch(&mut owners[..outputs.len()]);
    }
}

impl OutputOwner {
    pub(crate) fn len(&self) -> usize {
        self.queued.expect("live output").tx.len
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn peer_hold(&self) -> Option<crate::xdp::worker::PeerHold> {
        let queued = self.queued?;
        let inner = self.scope.0.inner.lock();
        inner
            .output_peer_holds
            .get(inner.index(queued.lease))
            .and_then(Clone::clone)
    }

    #[cfg(test)]
    pub(crate) fn host_return(&self) -> Option<honk_ebpf_common::host::HostSourceFacts> {
        let context = self.queued.as_ref()?.tx.source?;
        Some(
            *self
                .scope
                .0
                .inner
                .lock()
                .source_work
                .facts(context)
                .expect("output retains original Host source"),
        )
    }

    fn flow_id(&self) -> Option<FlowId> {
        self.queued.expect("live output").tx.flow
    }

    pub(crate) fn scope(&self) -> ScopeId {
        self.scope.scope()
    }

    fn class(&self) -> TxClass {
        self.queued.expect("live output").class
    }

    pub(crate) fn packet(&self) -> Option<&[u8]> {
        self.bytes.as_ref().map(|bytes| &bytes[..self.len()])
    }

    pub(crate) fn release_batch(outputs: &mut [Option<&mut OutputOwner>]) {
        assert!(outputs.len() <= BATCH);
        // ponytail: at most 64x64 scope comparisons; index only if measured batches need it.
        while let Some(shared) = outputs
            .iter()
            .flatten()
            .find_map(|output| output.queued.map(|_| Arc::clone(&output.scope.0)))
        {
            shared.with(|inner| {
                for output in outputs.iter_mut() {
                    if !output.as_ref().is_some_and(|output| {
                        output.queued.is_some() && Arc::ptr_eq(&shared, &output.scope.0)
                    }) {
                        continue;
                    }
                    let output = output.take().expect("matching output scope");
                    let queued = output.queued.take().expect("live output");
                    inner.release_output(queued, output.bytes.take());
                }
                inner.wake_credit_waiters();
            });
        }
    }
}

impl AsRef<[u8]> for OutputLease {
    fn as_ref(&self) -> &[u8] {
        self.packet()
    }
}

impl fmt::Debug for OutputLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutputLease")
            .field("scope", &self.scope())
            .field("flow", &self.flow_id())
            .field("len", &self.packet().len())
            .finish()
    }
}

impl Drop for OutputOwner {
    fn drop(&mut self) {
        if let Some(queued) = self.queued.take() {
            let bytes = self.bytes.take();
            self.scope.0.with(|inner| {
                inner.release_output(queued, bytes);
                inner.wake_credit_waiters();
            });
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("auxiliary packet binding retired")]
pub(in crate::control) struct AuxiliaryBindingRetired;

#[derive(Clone, Debug)]
pub struct DatagramSender {
    scope: PacketScope,
    binding: u64,
    source: SocketAddr,
    packet_source: Option<SourceWork>,
    realm: Option<PacketRealm>,
}

impl DatagramSender {
    pub fn scope(&self) -> ScopeId {
        self.scope.scope()
    }

    pub(in crate::control) fn source_context(&self) -> Option<SourceContext> {
        self.packet_source
            .as_ref()
            .and_then(SourceWork::optional_context)
    }

    /// Acceptance happens once, only after reserving the first frame and descriptor.
    /// Later fragments stay in the accounted stack queue and are never re-sent here.
    /// Fragment-queue/shared-budget exhaustion is a terminal capacity refusal, not acceptance.
    pub async fn send_to(&self, payload: &[u8], client: SocketAddr) -> io::Result<usize> {
        if self
            .packet_source
            .as_ref()
            .and_then(SourceWork::plain_address)
            .is_some_and(|address| address.to_canonical() != client.ip().to_canonical())
        {
            return Err(invalid("exact UDP source belongs to another client"));
        }
        let scope = self.realm.as_ref().map_or(&self.scope, |realm| {
            &realm.owners()[realm.worker_for_udp(client.ip())]
        });
        let mut waiter = Waiter::new(scope);
        poll_fn(|cx| {
            scope.0.with(|inner| {
                let current = scope.binding();
                if self.binding != current || current & 1 != 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        AuxiliaryBindingRetired,
                    )));
                }
                if inner.closing || inner.aborted {
                    return Poll::Ready(Err(closed()));
                }
                if self.packet_source.is_none() && inner.source_work.is_host() {
                    return Poll::Ready(Err(invalid("Host output requires original source")));
                }
                #[cfg(target_os = "linux")]
                if let Some(peer) = self.packet_source.as_ref().and_then(SourceWork::peer) {
                    inner.remember_peer(peer);
                }
                let lease = match inner.ledger.reserve_tx(TxClass::Bulk) {
                    Ok(lease) => lease,
                    Err(
                        honk_datapath::buffer::LedgerError::NoFrame
                        | honk_datapath::buffer::LedgerError::NoDescriptor,
                    ) => {
                        return waiter.pending(inner, cx, WaitFor::Credit);
                    }
                    Err(error) => return Poll::Ready(Err(io::Error::other(error))),
                };
                let index = inner.index(lease);
                let stack = inner.stack.as_mut().expect("open scope stack");
                let out = inner.frames[index]
                    .as_mut()
                    .expect("reserved frame storage");
                let result = if let Some(context) = self
                    .packet_source
                    .as_ref()
                    .and_then(SourceWork::optional_context)
                {
                    stack.udp_send_from_with_context(self.source, client, payload, context, out)
                } else {
                    stack
                        .udp_send_from(self.source, client, payload, out)
                        .map(|len| Transmit {
                            len,
                            gso: None,
                            csum: honk_netstack::TxCsum::Full,
                            flow: None,
                            source: None,
                        })
                };
                match result {
                    Ok(tx) => {
                        inner.publish(lease, tx, TxClass::Bulk, None);
                        Poll::Ready(Ok(payload.len()))
                    }
                    Err(error) => {
                        inner
                            .ledger
                            .cancel_tx(lease)
                            .expect("failed datagram consumed no output");
                        let kind = if error == UdpError::Busy {
                            io::ErrorKind::OutOfMemory
                        } else {
                            io::ErrorKind::InvalidInput
                        };
                        Poll::Ready(Err(io::Error::new(kind, error)))
                    }
                }
            })
        })
        .await
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WaitFor {
    Credit,
    Retirement(FlowId),
}

struct Registration {
    reason: WaitFor,
    waker: Waker,
}

struct Waiter<'a> {
    scope: &'a PacketScope,
    index: Option<usize>,
}

impl<'a> Waiter<'a> {
    fn new(scope: &'a PacketScope) -> Self {
        Self { scope, index: None }
    }

    fn pending<T>(
        &mut self,
        inner: &mut Inner,
        cx: &Context<'_>,
        reason: WaitFor,
    ) -> Poll<io::Result<T>> {
        if let Some(index) = self.index {
            let registration = inner.waiters[index].as_mut().expect("registered waiter");
            registration.waker.clone_from(cx.waker());
        } else {
            let Some(index) = inner.waiters.iter().position(Option::is_none) else {
                return Poll::Ready(Err(capacity()));
            };
            inner.waiters[index] = Some(Registration {
                reason,
                waker: cx.waker().clone(),
            });
            inner.credit_waiters += usize::from(reason == WaitFor::Credit);
            self.index = Some(index);
        }
        Poll::Pending
    }
}

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        if let Some(index) = self.index {
            let mut inner = self.scope.0.inner.lock();
            let registration = inner.waiters[index].take().expect("registered waiter");
            inner.credit_waiters -= usize::from(registration.reason == WaitFor::Credit);
            let device = (inner.aborted && !inner.closing).then(|| inner.device_wake());
            let terminal = inner.closing;
            drop(inner);
            drop(registration);
            if let Some(device) = device {
                self.scope.0.wake_owner(device);
            }
            if terminal && let Some(aux) = &self.scope.0.auxiliary {
                aux.released.notify_one();
            }
        }
    }
}

fn register(slot: &mut Option<Waker>, waker: &Waker) {
    if !slot
        .as_ref()
        .is_some_and(|previous| previous.will_wake(waker))
    {
        *slot = Some(waker.clone());
    }
}
fn capacity() -> io::Error {
    io::Error::new(io::ErrorKind::OutOfMemory, "packet runtime capacity")
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "packet scope closed")
}
