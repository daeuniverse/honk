//! Bounded L3 termination, not capture/classification or native continuation.
//!
//! One externally joined `PacketOwner` drives timers and queues complete IP packets. An
//! `OutputLease` owns its actual frame bytes and credit until the consumer releases it.
//! A backend must retain that lease through real I/O completion; local disposal is not a NIC CQ.

use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
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
    // Includes the Arc allocation, mutex/notify, slots, queues and frame pointer array.
    _metadata: MemoryReservation,
}

struct FlowSlot {
    id: FlowId,
    app_open: bool,
    close_pending: bool,
    retiring: bool,
    outputs: usize,
    rx: Option<Waker>,
    tx: Option<Waker>,
    callback: Option<RetirementCallback>,
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

struct Inner {
    stack: Option<Stack>,
    ledger: FrameLedger<Option<FlowId>>,
    frames: Box<[Option<Box<[u8]>>]>,
    queue: Box<[Option<Queued>]>,
    head: usize,
    queued: usize,
    frame_size: usize,
    next_tx: TxClass,
    slots: Box<[Option<FlowSlot>]>,
    pending_closes: usize,
    closed_apps: usize,
    waiters: Box<[Option<Waker>]>,
    output_waker: Option<Waker>,
    closing: bool,
    aborted: bool,
    finished: bool,
    // Frame bytes are freed before this reservation, including bytes returned by OutputLease.
    _storage: MemoryReservation,
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
                stack: Some(stack),
                ledger,
                frames,
                queue: (0..tx_frames).map(|_| None).collect(),
                head: 0,
                queued: 0,
                frame_size,
                next_tx: TxClass::Control,
                slots: (0..aliases).map(|_| None).collect(),
                pending_closes: 0,
                closed_apps: 0,
                waiters: (0..limits.max_waiters).map(|_| None).collect(),
                output_waker: None,
                closing: false,
                aborted: false,
                finished: false,
                _storage: storage,
            }),
            owner_wake: Notify::new(),
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

    pub(in crate::control) fn open_admission(&self) -> io::Result<()> {
        self.0.with(|inner| {
            if inner.closing {
                return Err(closed());
            }
            inner.stack.as_mut().ok_or_else(closed)?.set_accepting(true);
            Ok(())
        })
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

    /// Accepts with an immediate SYN-ACK. This is not kernel accepted-child evidence.
    pub fn poll_accept(&self) -> Option<(SynInfo, FlowIo)> {
        self.0.with(|inner| {
            if inner.closing {
                return None;
            }
            let vacant = inner.slots.iter().position(Option::is_none)?;
            let stack = inner.stack.as_mut()?;
            let syn = stack.poll_accept()?;
            if stack.tcp_accept(syn.id, AcceptOpts::default()).is_err() {
                stack.tcp_abort(syn.id);
                return None;
            }
            inner.slots[vacant] = Some(FlowSlot {
                id: syn.id,
                app_open: true,
                close_pending: false,
                retiring: false,
                outputs: 0,
                rx: None,
                tx: None,
                callback: None,
            });
            Some((syn, FlowIo::new(self.clone(), syn)))
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
        self.0.with(|inner| {
            if let Some(queued) = inner.pop() {
                let index = inner.index(queued.lease);
                let bytes = inner.frames[index]
                    .take()
                    .expect("queued frame owns storage");
                return Poll::Ready(Some(OutputLease {
                    scope: self.clone(),
                    queued: Some(queued),
                    bytes: Some(bytes),
                }));
            }
            if inner.finished || inner.aborted {
                return Poll::Ready(None);
            }
            register(&mut inner.output_waker, cx.waker());
            Poll::Pending
        })
    }

    pub async fn next_output(&self) -> Option<OutputLease> {
        poll_fn(|cx| self.poll_output(cx)).await
    }

    pub fn stats(&self) -> Option<StackStats> {
        self.0.with(|inner| inner.stack.as_ref().map(Stack::stats))
    }
}

impl Shared {
    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let result = {
            let mut inner = self.inner.lock();
            let result = f(&mut inner);
            inner.events();
            if let Some(stack) = &mut inner.stack {
                stack.take_tx_wakeup();
            }
            result
        };
        // Notify carries a permit even if the owner has not started awaiting yet.
        self.owner_wake.notify_one();
        self.reap();
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
}

struct RetirementCompletion<'a> {
    shared: &'a Shared,
    index: usize,
    id: FlowId,
}

impl Drop for RetirementCompletion<'_> {
    fn drop(&mut self) {
        {
            let mut inner = self.shared.inner.lock();
            let slot = inner.slots[self.index]
                .take()
                .expect("retirement callback owns exact slot");
            assert_eq!(slot.id, self.id);
            inner.closed_apps -= 1;
            inner.wake_waiters();
        }
        self.shared.owner_wake.notify_one();
    }
}

impl Inner {
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

    fn pop(&mut self) -> Option<Queued> {
        if self.queued == 0 {
            return None;
        }
        let queued = self.queue[self.head].take();
        self.head = (self.head + 1) % self.queue.len();
        self.queued -= 1;
        queued
    }

    fn publish(&mut self, lease: FrameLease, tx: Transmit, class: TxClass) {
        self.ledger
            .submit_tx(lease, tx.len, tx.flow)
            .expect("reserved complete output frame");
        if let Some(id) = tx.flow
            && let Some(slot) = self.slot(id)
        {
            slot.outputs += 1;
        }
        self.push(Queued { lease, tx, class });
    }

    fn release(&mut self, queued: Queued) {
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
        self.wake_waiters();
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

    fn drive(&mut self, now: Instant) -> bool {
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
        self.events();
        sent == BATCH
    }

    fn events(&mut self) {
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
        while let Some(queued) = self.pop() {
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
                // Budget refunds in another scope have no protocol event in this Stack.
                if inner.waiters.iter().any(Option::is_some)
                    || inner.slots.iter().flatten().any(|slot| slot.tx.is_some())
                {
                    let readiness = now + std::time::Duration::from_millis(100);
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

/// An immutable local output capability, not an AF_XDP completion descriptor.
/// Dropping/releasing it means the actual consumer has finished I/O or explicitly disposed it.
pub struct OutputLease {
    scope: PacketScope,
    queued: Option<Queued>,
    bytes: Option<Box<[u8]>>,
}

impl OutputLease {
    pub fn packet(&self) -> &[u8] {
        &self.bytes.as_ref().expect("live output storage")
            [..self.queued.expect("live output").tx.len]
    }
    pub fn flow_id(&self) -> Option<FlowId> {
        self.queued.expect("live output").tx.flow
    }
    pub fn scope(&self) -> ScopeId {
        self.scope.scope()
    }
    pub fn class(&self) -> TxClass {
        self.queued.expect("live output").class
    }
    pub fn release(self) {
        drop(self);
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

impl Drop for OutputLease {
    fn drop(&mut self) {
        if let Some(queued) = self.queued.take() {
            let bytes = self.bytes.take().expect("live output storage");
            self.scope.0.with(|inner| {
                let index = inner.index(queued.lease);
                assert!(
                    inner.frames[index].replace(bytes).is_none(),
                    "exclusive output storage"
                );
                inner.release(queued);
            });
        }
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
