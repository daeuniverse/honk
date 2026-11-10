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
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use honk_datapath::ScopeId;
use honk_datapath::buffer::{FrameConfig, FrameLease, FrameLedger, TxClass};
use honk_netstack::{
    AcceptOpts, Config, DropReason, FlowId, MemoryBudget, MemoryReservation, Mode, Ready, Rx,
    Stack, StackStats, SynInfo, Transmit, TxCaps, UdpError,
};
use parking_lot::Mutex;
use tokio::sync::Notify;

mod stream;
pub use stream::{FlowIo, FlowRetirement};

#[cfg(test)]
mod tests;

const BATCH: usize = 64;
// Budget refunds in another scope have no protocol event in this Stack.
const READINESS_FALLBACK: std::time::Duration = std::time::Duration::from_millis(100);

#[cfg(target_os = "linux")]
pub(crate) const CAPTURE_MEMORY: usize = 256 << 20;

#[cfg(target_os = "linux")]
pub(crate) fn capture_scope(
    mtu: u32,
    realms: usize,
    bulk_frames: usize,
    budget: &Arc<MemoryBudget>,
) -> anyhow::Result<(PacketScope, PacketOwner)> {
    // ponytail: fixed per-realm partitions; rebalance only if measured tenant skew needs it.
    let slots = (4096 / realms).min(1024);
    let mut stack = Config::new(rand::random());
    stack.mode = Mode::Transparent {
        exclude: Default::default(),
    };
    stack.mtu = u16::try_from(mtu)?;
    stack.max_flows = slots as u32;
    stack.memory_limit = CAPTURE_MEMORY / 2 / realms;
    Ok(PacketScope::new(
        stack,
        Arc::clone(budget),
        RuntimeLimits {
            max_slots: slots,
            control_frames: 32,
            bulk_frames,
            max_waiters: 256,
        },
        Instant::now(),
    )?)
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

struct Shared {
    scope: ScopeId,
    budget: Arc<MemoryBudget>,
    inner: Mutex<Inner>,
    owner_wake: Notify,
    #[cfg(all(test, feature = "native-api"))]
    startup_pause: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
    // Includes the Arc allocation, mutex/notify, slots, queues and frame pointer array.
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
    source_work: Box<[Option<(IpAddr, usize)>]>,
    queue: Box<[Option<Queued>]>,
    head: usize,
    queued: usize,
    frame_size: usize,
    next_tx: TxClass,
    slots: Box<[Option<FlowSlot>]>,
    pending_closes: usize,
    closed_apps: usize,
    pending_routing: usize,
    waiters: Box<[Option<Waker>]>,
    output_waker: Option<Waker>,
    closing: bool,
    aborted: bool,
    finished: bool,
    // Frame bytes are freed before this reservation, including bytes returned by OutputLease.
    _storage: MemoryReservation,
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
        mut cfg: Config,
        budget: Arc<MemoryBudget>,
        limits: RuntimeLimits,
        now: Instant,
    ) -> io::Result<(Self, PacketOwner)> {
        if !matches!(cfg.mode, Mode::Transparent { .. }) {
            return Err(invalid(
                "packet termination requires transparent stack mode",
            ));
        }
        if limits.max_slots == 0 || limits.max_waiters == 0 {
            return Err(invalid("zero runtime metadata capacity"));
        }
        let tx_frames = limits
            .control_frames
            .checked_add(limits.bulk_frames)
            .ok_or_else(|| invalid("frame count overflow"))?;
        let frame_count = tx_frames;
        let aliases = limits
            .max_slots
            .checked_add(tx_frames)
            .ok_or_else(|| invalid("flow retention capacity overflow"))?;
        let frame_size = usize::from(cfg.mtu.max(1280));
        let frame_config = FrameConfig {
            base_address: 0,
            frame_size,
            rx_frames: 0,
            control_frames: limits.control_frames,
            bulk_frames: limits.bulk_frames,
            fill_capacity: 0,
            rx_capacity: 0,
            control_descriptors: limits.control_frames,
            bulk_descriptors: limits.bulk_frames,
            tx_capacity: tx_frames,
            completion_capacity: tx_frames,
        };
        // Validate the ledger before allocating any runtime backing.
        FrameLedger::<Option<FlowId>>::metadata_bytes(frame_config).map_err(io::Error::other)?;
        let storage_bytes = frame_size
            .checked_mul(frame_count)
            .filter(|&n| n <= isize::MAX as usize)
            .ok_or_else(|| invalid("frame storage overflow"))?;
        let metadata_bytes = size_of::<Shared>()
            .checked_add(2 * size_of::<usize>())
            .and_then(|n| n.checked_add(aliases.checked_mul(size_of::<Option<FlowSlot>>())?))
            .and_then(|n| n.checked_add(frame_count.checked_mul(size_of::<Option<Box<[u8]>>>())?))
            .and_then(|n| n.checked_add(frame_count.checked_mul(size_of::<Option<IpAddr>>())?))
            .and_then(|n| n.checked_add(aliases.checked_mul(size_of::<Option<(IpAddr, usize)>>())?))
            .and_then(|n| n.checked_add(tx_frames.checked_mul(size_of::<Option<Queued>>())?))
            .and_then(|n| {
                n.checked_add(limits.max_waiters.checked_mul(size_of::<Option<Waker>>())?)
            })
            .filter(|&n| n <= isize::MAX as usize)
            .ok_or_else(|| invalid("runtime metadata overflow"))?;
        let metadata = budget.reserve(metadata_bytes).ok_or_else(capacity)?;
        let storage = budget.reserve(storage_bytes).ok_or_else(capacity)?;
        let ledger = FrameLedger::new(frame_config, &budget).map_err(io::Error::other)?;
        cfg.shared_budget = Some(Arc::clone(&budget));
        let stack = Stack::new_accounted(cfg, now, limits.max_slots).map_err(io::Error::other)?;
        let scope =
            ScopeId::allocate().ok_or_else(|| io::Error::other("scope identities exhausted"))?;
        let frames = (0..frame_count)
            .map(|_| Some(vec![0; frame_size].into_boxed_slice()))
            .collect();
        let shared = Arc::new(Shared {
            scope,
            budget,
            inner: Mutex::new(Inner {
                rights: Rights::Task,
                stack: Some(stack),
                ledger,
                frames,
                output_peers: (0..frame_count).map(|_| None).collect(),
                source_work: (0..aliases).map(|_| None).collect(),
                queue: (0..tx_frames).map(|_| None).collect(),
                head: 0,
                queued: 0,
                frame_size,
                next_tx: TxClass::Control,
                slots: (0..aliases).map(|_| None).collect(),
                pending_closes: 0,
                closed_apps: 0,
                pending_routing: 0,
                waiters: (0..limits.max_waiters).map(|_| None).collect(),
                output_waker: None,
                closing: false,
                aborted: false,
                finished: false,
                _storage: storage,
            }),
            owner_wake: Notify::new(),
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
            inner.stack.as_mut().ok_or_else(closed)?.set_accepting(true);
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

    pub fn budget(&self) -> Arc<MemoryBudget> {
        Arc::clone(&self.0.budget)
    }

    /// Borrowed `Rx` ranges index `packet`: consume/copy them before recycling input storage.
    /// Closing admission does not stop delivery to existing TCP/TIME_WAIT incarnations.
    pub fn receive(&self, packet: &[u8], now: Instant) -> Rx {
        self.0.with(|inner| match &mut inner.stack {
            Some(stack) => stack.receive(now, packet),
            None => Rx::Dropped(DropReason::Stale),
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
        mut on_source: impl FnMut(honk_netstack::ValidatedSource, bool) -> bool,
    ) -> (Rx, super::packet_endpoint::PacketReceive) {
        self.0.with(|inner| {
            let pending = check_output && inner.pending_source_output(packet);
            let Some(stack) = &mut inner.stack else {
                return (Rx::Dropped(DropReason::Stale), Default::default());
            };
            let (rx, report) =
                stack.receive_with_tcp_admission(now, packet, |source| on_source(source, pending));
            (rx, inner.receive_result(report))
        })
    }

    pub(in crate::control) fn retains_tcp(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> bool {
        let inner = self.0.inner.lock();
        inner
            .stack
            .as_ref()
            .is_some_and(|stack| stack.retains_tcp(source, destination))
            || inner
                .slots
                .iter()
                .flatten()
                .any(|slot| slot.client == source && slot.destination == destination)
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
            || inner
                .source_work
                .iter()
                .flatten()
                .any(|(peer, _)| *peer == address)
    }

    pub(in crate::control) fn hold_source(&self, address: IpAddr) -> io::Result<SourceWork> {
        let mut inner = self.0.inner.lock();
        if inner.closing || inner.finished {
            return Err(closed());
        }
        let index = inner
            .source_work
            .iter()
            .position(|entry| entry.is_some_and(|(peer, _)| peer == address))
            .or_else(|| inner.source_work.iter().position(Option::is_none))
            .ok_or_else(capacity)?;
        let entry = inner.source_work[index].get_or_insert((address, 0));
        entry.1 = entry.1.checked_add(1).ok_or_else(capacity)?;
        Ok(SourceWork {
            scope: self.clone(),
            index,
        })
    }

    pub(in crate::control) fn receive_admitted_with_source(
        &self,
        packet: &[u8],
        now: Instant,
        admission: &mut Option<super::packet_endpoint::EndpointAdmission>,
        check_output: bool,
        mut on_source: impl FnMut(honk_netstack::ValidatedSource, bool) -> bool,
    ) -> (Rx, super::packet_endpoint::PacketReceive) {
        self.0.with(|inner| {
            let pending = check_output && inner.pending_source_output(packet);
            let Some(stack) = &mut inner.stack else {
                return (Rx::Dropped(DropReason::Stale), Default::default());
            };
            let (rx, report) =
                stack.receive_with_tcp_admission(now, packet, |source| on_source(source, pending));
            if let honk_netstack::ReceiveOutcome::TcpNew(id) = report.outcome {
                if let Some(vacant) = inner.slots.iter().position(Option::is_none) {
                    let source = report
                        .source
                        .expect("new TCP admission has a validated tuple");
                    inner.slots[vacant] = Some(FlowSlot {
                        id,
                        client: source.src,
                        destination: source.dst,
                        app_open: true,
                        close_pending: false,
                        retiring: false,
                        outputs: 0,
                        rx: None,
                        tx: None,
                        callback: None,
                        accepted: false,
                        rx_admitted: false,
                        routing: admission.take(),
                    });
                    inner.pending_routing += 1;
                } else {
                    stack.tcp_refuse(id, honk_netstack::Refuse::Drop);
                }
            }
            (rx, inner.receive_result(report))
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
            if vacant.is_none() && !inner.slots.iter().flatten().any(|slot| slot.id == syn.id) {
                stack.tcp_refuse(syn.id, honk_netstack::Refuse::Drop);
                return None;
            }
            if stack.tcp_accept(syn.id, AcceptOpts::default()).is_err() {
                stack.tcp_abort(syn.id);
                return None;
            }
            let routing = if let Some(slot) = inner
                .slots
                .iter_mut()
                .flatten()
                .find(|slot| slot.id == syn.id)
            {
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
                });
                None
            };
            let mut flow = FlowIo::new(self.clone(), syn);
            flow.set_routing(routing);
            Some((syn, flow))
        })
    }

    pub fn datagram_sender(&self, source: SocketAddr) -> DatagramSender {
        DatagramSender {
            scope: self.clone(),
            source,
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
        self.0.with(|inner| {
            inner.closing = true;
            if let Some(stack) = &mut inner.stack {
                stack.set_accepting(false);
            }
            if abort {
                inner.abort();
            }
        });
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

impl Shared {
    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let (result, closed_apps, device) = {
            let mut inner = self.inner.lock();
            let result = f(&mut inner);
            inner.events();
            if let Some(stack) = &mut inner.stack {
                stack.take_tx_wakeup();
            }
            // Every reapable slot is a closed app, and its transition's actor reaps it.
            (result, inner.closed_apps != 0, inner.device_wake())
        };
        self.wake_owner(device);
        if closed_apps {
            self.reap();
        }
        result
    }

    fn reap(&self) {
        loop {
            let (index, id, callback) = {
                let mut inner = self.inner.lock();
                if inner.closed_apps == 0 {
                    return;
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
                let Some(index) = found else { return };
                let slot = inner.slots[index].as_mut().expect("retiring exact slot");
                slot.retiring = true;
                (index, slot.id, slot.callback.take())
            };
            let completion = RetirementCompletion {
                shared: self,
                index,
                id,
            };
            if let Some(callback) = callback {
                (callback.callback)();
            }
            drop(completion);
        }
    }

    /// Applies `Inner::device_wake` after unlocking. Notify carries a permit even if the
    /// owner has not started awaiting yet.
    fn wake_owner(&self, device: Option<Option<Waker>>) {
        match device {
            Some(Some(waker)) => waker.wake(),
            // Already woken, or not armed before its first service: it will rescan anyway.
            Some(None) => {}
            None => self.owner_wake.notify_one(),
        }
    }
}

struct RetirementCompletion<'a> {
    shared: &'a Shared,
    index: usize,
    id: FlowId,
}

impl Drop for RetirementCompletion<'_> {
    fn drop(&mut self) {
        let device = {
            let mut inner = self.shared.inner.lock();
            let slot = inner.slots[self.index]
                .take()
                .expect("retirement callback owns exact slot");
            assert_eq!(slot.id, self.id);
            inner.closed_apps -= 1;
            inner.wake_waiters();
            inner.device_wake()
        };
        self.shared.wake_owner(device);
    }
}

impl Inner {
    fn receive_result(
        &self,
        report: honk_netstack::ReceiveReport,
    ) -> super::packet_endpoint::PacketReceive {
        let qualified_rx = !self.closing
            && !self.finished
            && matches!(report.outcome, honk_netstack::ReceiveOutcome::TcpAccepted(id)
                if self.slots.iter().flatten().any(|slot| slot.id == id && slot.rx_admitted));
        super::packet_endpoint::PacketReceive {
            source: report.source,
            qualified_rx,
        }
    }

    /// Under this mutex: the driving device's wake, or `None` to notify the original owner.
    /// Returned/Abandoned progress goes to the original owner, never a stale device task.
    fn device_wake(&mut self) -> Option<Option<Waker>> {
        (self.rights == Rights::Driven).then(|| self.output_waker.take())
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
        register(&mut self.output_waker, cx.waker());
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
    fn slot(&mut self, id: FlowId) -> Option<&mut FlowSlot> {
        self.slots.iter_mut().flatten().find(|slot| slot.id == id)
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
        if let Some(waker) = self.output_waker.take() {
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
        tx: Transmit,
        class: TxClass,
        destination: IpAddr,
    ) -> io::Result<Queued> {
        let index = self.index(lease);
        self.ledger
            .submit_tx(lease, tx.len, tx.flow)
            .map_err(io::Error::other)?;
        self.output_peers[index] = Some(destination);
        if let Some(id) = tx.flow
            && let Some(slot) = self.slot(id)
        {
            slot.outputs += 1;
        }
        Ok(Queued { lease, tx, class })
    }

    fn publish(&mut self, lease: FrameLease, tx: Transmit, class: TxClass) {
        let index = self.index(lease);
        let destination = honk_netstack::wire::packet_addresses(
            &self.frames[index]
                .as_ref()
                .expect("reserved output storage")[..tx.len],
        )
        .expect("stack output has IP addresses")
        .1;
        let queued = self
            .install(lease, tx, class, destination)
            .expect("reserved complete output frame");
        self.push(queued);
    }

    fn release(&mut self, queued: Queued) {
        let index = self.index(queued.lease);
        self.output_peers[index] = None;
        let owner = self
            .ledger
            .release_tx(queued.lease)
            .expect("unique local output lease release");
        assert_eq!(owner, queued.tx.flow);
        if let Some(id) = owner
            && let Some(slot) = self.slot(id)
        {
            slot.outputs = slot.outputs.checked_sub(1).expect("original output owner");
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
        let tx = match class {
            TxClass::Control => stack.poll_control_transmit(now, out),
            TxClass::Bulk => stack.poll_transmit_with(now, out, TxCaps::NONE),
        };
        if let Some(tx) = tx {
            self.publish(lease, tx, class);
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
            self.wake_waiters();
        }
        sent == BATCH
    }

    fn drive(&mut self, now: Instant) -> bool {
        self.advance(now);
        let more = self.fill(now);
        self.events();
        more
    }

    fn events(&mut self) {
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
                    self.pending_routing -= 1;
                }
            }
        }
        while let Some((id, ready)) = self.stack.as_mut().and_then(Stack::poll_event) {
            if let Some(slot) = self.slot(id) {
                if (ready.contains(Ready::READABLE)
                    || ready.contains(Ready::READ_CLOSED)
                    || ready.contains(Ready::ERROR))
                    && let Some(waker) = slot.rx.take()
                {
                    waker.wake();
                }
                if (ready.contains(Ready::WRITABLE)
                    || ready.contains(Ready::CONNECTED)
                    || ready.contains(Ready::ERROR))
                    && let Some(waker) = slot.tx.take()
                {
                    waker.wake();
                }
            }
        }
    }

    fn wake_waiters(&mut self) {
        for waker in self.waiters.iter_mut().flatten() {
            waker.wake_by_ref();
        }
    }

    fn abort(&mut self) {
        self.aborted = true;
        // Dropping the stack is explicit protocol disposal, never a fabricated device return.
        self.stack = None;
        while let Some(queued) = self.pop(None) {
            self.release(queued);
        }
        for slot in self.slots.iter_mut().flatten() {
            if let Some(waker) = slot.rx.take() {
                waker.wake();
            }
            if let Some(waker) = slot.tx.take() {
                waker.wake();
            }
        }
        self.wake_waiters();
        if let Some(waker) = self.output_waker.take() {
            waker.wake();
        }
    }

    fn finish(&mut self) -> bool {
        let protocol_empty = self.stack.as_ref().is_none_or(Stack::is_quiescent);
        if self.closing
            && protocol_empty
            && self.slots.iter().all(Option::is_none)
            && self.queued == 0
            && self.source_work.iter().all(Option::is_none)
            && self.ledger.outstanding_tx().next().is_none()
        {
            self.finished = true;
            self.stack = None;
            self.ledger.close();
            if let Some(waker) = self.output_waker.take() {
                waker.wake();
            }
            self.wake_waiters();
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
                if let Some(stack) = &mut inner.stack {
                    stack.take_tx_wakeup();
                }
                let mut deadline = inner.stack.as_ref().and_then(Stack::poll_timeout);
                if inner.waiters.iter().any(Option::is_some)
                    || inner.slots.iter().flatten().any(|slot| slot.tx.is_some())
                {
                    let readiness = now + READINESS_FALLBACK;
                    deadline = Some(deadline.map_or(readiness, |due| due.min(readiness)));
                }
                (more, deadline)
            };
            self.scope.0.reap();
            if self.scope.0.inner.lock().finish() {
                return;
            }
            if more {
                tokio::task::yield_now().await;
                continue;
            }
            if let Some(deadline) = deadline {
                tokio::select! {
                    _ = &mut notified => {},
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                        self.scope.0.inner.lock().wake_waiters();
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

/// The exclusive driving right handed to one device owner. Not Clone; only `hand_off` makes
/// one. Keep it in the outer device owner, never inside a scope callback or lock holder.
pub(crate) struct PacketDriver {
    scope: PacketScope,
    // Kept until serviced so frequent unrelated device polls cannot postpone it.
    fallback: Option<Instant>,
    deadline: Option<Instant>,
}

impl PacketDriver {
    pub(crate) fn scope(&self) -> ScopeId {
        self.scope.scope()
    }

    /// The protocol or conditional refund-readiness deadline found by the last service.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Complete CPU service for startup-only driving and realms using the CPU/SG path.
    pub(crate) fn service(&mut self, cx: &mut Context<'_>, now: Instant) -> bool {
        let more = self.begin(now, true);
        self.finish_turn(cx, now);
        more
    }

    /// Advance timers and pending closes before a bounded direct-output turn.
    pub(crate) fn begin_turn(&mut self, now: Instant) {
        self.begin(now, false);
    }

    fn begin(&mut self, now: Instant, cpu_output: bool) -> bool {
        let mut inner = self.scope.0.inner.lock();
        if inner.rights != Rights::Driven {
            self.deadline = None;
            return false;
        }
        let armed = inner.output_waker.take();
        if self.fallback.is_some_and(|due| due <= now) {
            self.fallback = None;
            inner.wake_waiters();
        }
        inner.advance(now);
        let more = cpu_output && inner.fill(now);
        inner.output_waker = armed;
        more
    }

    /// Finalize after the last emission, including None and local disposal. Do not self-wake.
    pub(crate) fn finish_turn(&mut self, cx: &mut Context<'_>, now: Instant) {
        let shared = &self.scope.0;
        {
            let mut inner = shared.inner.lock();
            if inner.rights != Rights::Driven {
                self.deadline = None;
                return;
            }
            let armed = inner.output_waker.take();
            inner.events();
            if let Some(stack) = &mut inner.stack {
                stack.take_tx_wakeup();
            }
            inner.output_waker = armed;
            register(&mut inner.output_waker, cx.waker());
        }
        shared.reap();
        let mut inner = shared.inner.lock();
        let armed = inner.output_waker.take();
        if inner.finish() {
            inner.rights = Rights::Returned;
            drop(inner);
            drop(armed);
            self.fallback = None;
            self.deadline = None;
            shared.owner_wake.notify_one();
            return;
        }
        inner.output_waker = armed;
        register(&mut inner.output_waker, cx.waker());
        let blocked = inner.waiters.iter().any(Option::is_some)
            || inner.slots.iter().flatten().any(|slot| slot.tx.is_some());
        self.fallback = blocked.then(|| self.fallback.unwrap_or(now + READINESS_FALLBACK));
        self.deadline = [
            inner.stack.as_ref().and_then(Stack::poll_timeout),
            self.fallback,
        ]
        .into_iter()
        .flatten()
        .min();
    }

    /// Emit into the device's already-reserved full L3 frame; never finish L2 under this lock.
    pub(crate) fn materialize_into(
        &mut self,
        now: Instant,
        class: TxClass,
        l3: &mut [u8],
    ) -> io::Result<Option<OutputOwner>> {
        let mut inner = self.scope.0.inner.lock();
        if inner.rights != Rights::Driven || inner.aborted || inner.finished {
            return Ok(None);
        }
        if inner.stack.is_none() {
            return Ok(None);
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
            let wake = inner.output_waker.take();
            drop(inner);
            if let Some(wake) = wake {
                wake.wake();
            }
            return Ok(None);
        }
        let lease = match inner.ledger.reserve_tx(class) {
            Ok(lease) => lease,
            Err(
                honk_datapath::buffer::LedgerError::NoFrame
                | honk_datapath::buffer::LedgerError::NoDescriptor,
            ) => return Ok(None),
            Err(error) => return Err(io::Error::other(error)),
        };
        let mut reservation = OutputReservation {
            inner: &mut inner,
            lease: Some(lease),
        };
        let stack = reservation.inner.stack.as_mut().expect("live driven stack");
        let packet = &mut l3[..frame_size];
        let tx = match class {
            TxClass::Control => stack.poll_control_transmit(now, packet),
            TxClass::Bulk => stack.poll_transmit_with(now, packet, TxCaps::NONE),
        };
        let Some(tx) = tx else { return Ok(None) };
        if tx.len == 0 || tx.len > frame_size {
            return Err(io::Error::other("invalid direct output extent"));
        }
        let destination = honk_netstack::wire::packet_addresses(&packet[..tx.len])
            .map_err(io::Error::other)?
            .1;
        let queued = reservation.inner.install(lease, tx, class, destination)?;
        reservation.lease = None;
        drop(reservation);
        drop(inner);
        Ok(Some(OutputOwner {
            scope: self.scope.clone(),
            queued: Some(queued),
            bytes: None,
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
                inner.wake_waiters();
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
                inner.wake_waiters();
            });
        }
    }
}

pub(in crate::control) struct SourceWork {
    scope: PacketScope,
    index: usize,
}

impl Drop for SourceWork {
    fn drop(&mut self) {
        self.scope.0.with(|inner| {
            let count = &mut inner.source_work[self.index]
                .as_mut()
                .expect("retained source work")
                .1;
            *count -= 1;
            if *count == 0 {
                inner.source_work[self.index] = None;
            }
        });
    }
}

#[derive(Clone, Debug)]
pub struct DatagramSender {
    scope: PacketScope,
    source: SocketAddr,
}

impl DatagramSender {
    pub fn scope(&self) -> ScopeId {
        self.scope.scope()
    }

    /// Acceptance happens once, only after reserving the first frame and descriptor.
    /// Later fragments stay in the accounted stack queue and are never re-sent here.
    /// Fragment-queue/shared-budget exhaustion is a terminal capacity refusal, not acceptance.
    pub async fn send_to(&self, payload: &[u8], client: SocketAddr) -> io::Result<usize> {
        let mut waiter = Waiter::new(self.scope.clone());
        poll_fn(|cx| {
            self.scope.0.with(|inner| {
                if inner.closing {
                    return Poll::Ready(Err(closed()));
                }
                let lease = match inner.ledger.reserve_tx(TxClass::Bulk) {
                    Ok(lease) => lease,
                    Err(
                        honk_datapath::buffer::LedgerError::NoFrame
                        | honk_datapath::buffer::LedgerError::NoDescriptor,
                    ) => {
                        return waiter.pending(inner, cx);
                    }
                    Err(error) => return Poll::Ready(Err(io::Error::other(error))),
                };
                let index = inner.index(lease);
                let result = inner
                    .stack
                    .as_mut()
                    .expect("open scope stack")
                    .udp_send_from(
                        self.source,
                        client,
                        payload,
                        inner.frames[index]
                            .as_mut()
                            .expect("reserved frame storage"),
                    );
                match result {
                    Ok(len) => {
                        inner.publish(
                            lease,
                            Transmit {
                                len,
                                gso: None,
                                csum: honk_netstack::TxCsum::Full,
                                flow: None,
                            },
                            TxClass::Bulk,
                        );
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

struct Waiter {
    scope: PacketScope,
    index: Option<usize>,
}

impl Waiter {
    fn new(scope: PacketScope) -> Self {
        Self { scope, index: None }
    }

    fn pending<T>(&mut self, inner: &mut Inner, cx: &Context<'_>) -> Poll<io::Result<T>> {
        let index = match self.index {
            Some(index) => index,
            None => {
                let Some(index) = inner.waiters.iter().position(Option::is_none) else {
                    return Poll::Ready(Err(capacity()));
                };
                self.index = Some(index);
                index
            }
        };
        register(&mut inner.waiters[index], cx.waker());
        Poll::Pending
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        if let Some(index) = self.index {
            self.scope.0.with(|inner| inner.waiters[index] = None);
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
