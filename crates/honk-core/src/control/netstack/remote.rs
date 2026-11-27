//! One queue in each direction, with one writer and one reader for the life of the attachment.

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering, fence};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use crossbeam_utils::atomic::AtomicCell;
use futures::task::AtomicWaker;
use honk_netstack::{FlowId, MemoryBudget, MemoryReservation, Stack, StreamError};
use parking_lot::Mutex;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use super::{capacity, stream_error};

const SMALL_CHUNK: usize = 4 << 10;
pub(super) const BULK_CHUNK: usize = 16 << 10;
const SLOTS: usize = 32;
const WAKE_LOW_WATERMARK: usize = SLOTS / 4;
const ARC_HEADER: usize = 2 * size_of::<usize>();
const PROGRESS_REPORT_INTERVAL: Duration = Duration::from_millis(100);

type Slot = AtomicCell<Option<Box<Chunk>>>;
const _: () = assert!(Slot::is_lock_free());
const MAX_CACHED: usize = 64;

struct Chunk {
    bytes: Vec<u8>,
    memory: MemoryReservation,
}

impl Chunk {
    fn target(&self) -> usize {
        self.memory.bytes() - size_of::<Self>()
    }

    fn append(&mut self, source: &[u8]) -> usize {
        // Allocator slack does not extend the reservation, including on a small fallback.
        let n = source.len().min(self.target() - self.bytes.len());
        self.bytes.extend_from_slice(&source[..n]);
        n
    }
}

pub(super) struct RemoteChunkPool {
    budget: Arc<MemoryBudget>,
    #[expect(clippy::vec_box, reason = "SPSC slots exchange the same boxed chunks")]
    free: Mutex<Vec<Box<Chunk>>>,
    cap: usize,
    closed: AtomicBool,
    drains: AtomicU64,
    _memory: MemoryReservation,
}

impl RemoteChunkPool {
    pub(super) fn new(budget: &Arc<MemoryBudget>, total_pools: usize) -> io::Result<Arc<Self>> {
        let cap = (budget.limit() / 16 / total_pools.max(1) / BULK_CHUNK).min(MAX_CACHED);
        let memory = budget
            .reserve(ARC_HEADER + size_of::<Self>() + cap * size_of::<Box<Chunk>>())
            .ok_or_else(capacity)?;
        Ok(Arc::new(Self {
            budget: Arc::clone(budget),
            free: Mutex::new(Vec::with_capacity(cap)),
            cap,
            closed: AtomicBool::new(false),
            drains: AtomicU64::new(0),
            _memory: memory,
        }))
    }

    pub(super) fn reserve(&self, bytes: usize) -> Option<MemoryReservation> {
        self.budget.reserve(bytes).or_else(|| {
            self.drain();
            self.budget.reserve(bytes)
        })
    }

    pub(super) fn drain(&self) {
        if !self.drain_if_cached() {
            self.drains.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn drain_if_cached(&self) -> bool {
        let mut free = self.free.lock();
        if free.is_empty() {
            return false;
        }
        let mut dropped = [const { None }; MAX_CACHED];
        for (slot, chunk) in dropped.iter_mut().zip(free.drain(..)) {
            *slot = Some(chunk);
        }
        drop(free);
        drop(dropped);
        self.drains.fetch_add(1, Ordering::Relaxed);
        true
    }

    #[cfg(test)]
    pub(super) fn drains(&self) -> u64 {
        self.drains.load(Ordering::Relaxed)
    }

    pub(super) fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.drain();
        }
    }

    fn take(&self) -> Option<Box<Chunk>> {
        if self.cap == 0 || self.closed.load(Ordering::Acquire) {
            return None;
        }
        self.free.lock().pop()
    }

    fn recycle(&self, chunk: Box<Chunk>) {
        if self.cap == 0 || chunk.target() != BULK_CHUNK || chunk.bytes.capacity() != BULK_CHUNK {
            return;
        }
        let mut free = self.free.lock();
        if !self.closed.load(Ordering::Acquire) && free.len() < self.cap {
            free.push(chunk);
        }
        // When full or closed, release the lock before dropping the caller's chunk.
        drop(free);
    }
}

struct Ring {
    slots: [Slot; SLOTS],
    // Includes the partially consumed chunk held exclusively by the reader.
    occupied: AtomicUsize,
    // Set when a producer stops because every slot is occupied.
    full: AtomicBool,
}

impl Ring {
    fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| Slot::new(None)),
            occupied: AtomicUsize::new(0),
            full: AtomicBool::new(false),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pressure {
    None,
    Full,
    Budget,
}

#[derive(Default)]
struct Writer {
    next: usize,
    bulk: bool,
}

impl Writer {
    fn push(
        &mut self,
        ring: &Ring,
        slices: &[IoSlice<'_>],
        pool: &RemoteChunkPool,
    ) -> (usize, Pressure, bool) {
        let total: usize = slices.iter().map(|slice| slice.len()).sum();
        if total > SMALL_CHUNK {
            self.bulk = true;
        }
        let mut slices = slices.iter().filter(|slice| !slice.is_empty());
        let mut source = slices.next().map_or(&[][..], |s| &s[..]);
        let mut written = 0;
        let mut wake_reader = false;
        while !source.is_empty() {
            if ring.occupied.load(Ordering::Acquire) == SLOTS {
                ring.full.store(true, Ordering::Release);
                fence(Ordering::SeqCst);
                if ring.occupied.load(Ordering::Acquire) == SLOTS {
                    return (written, Pressure::Full, wake_reader);
                }
                ring.full.store(false, Ordering::Relaxed);
            }
            let target = if self.bulk { BULK_CHUNK } else { SMALL_CHUNK };
            let reused = if target == BULK_CHUNK {
                pool.take()
            } else {
                None
            };
            let mut chunk = match reused {
                Some(mut chunk) => {
                    chunk.bytes.clear();
                    chunk
                }
                None => {
                    let (cap, memory) = match pool.reserve(size_of::<Chunk>() + target) {
                        Some(memory) => (target, memory),
                        None if target > SMALL_CHUNK => {
                            let Some(memory) = pool.reserve(size_of::<Chunk>() + SMALL_CHUNK)
                            else {
                                return (written, Pressure::Budget, wake_reader);
                            };
                            (SMALL_CHUNK, memory)
                        }
                        None => return (written, Pressure::Budget, wake_reader),
                    };
                    Box::new(Chunk {
                        bytes: Vec::with_capacity(cap),
                        memory,
                    })
                }
            };
            while !source.is_empty() {
                let n = chunk.append(source);
                source = &source[n..];
                if !source.is_empty() {
                    break;
                }
                source = slices.next().map_or(&[][..], |s| &s[..]);
            }
            if !self.bulk && chunk.bytes.len() == SMALL_CHUNK {
                self.bulk = true;
            }
            written += chunk.bytes.len();
            ring.slots[self.next].store(Some(chunk));
            self.next = (self.next + 1) % SLOTS;
            if ring.occupied.fetch_add(1, Ordering::AcqRel) == 0 {
                wake_reader = true;
            }
        }
        (written, Pressure::None, wake_reader)
    }
}

#[derive(Default)]
struct Reader {
    next: usize,
    chunk: Option<Box<Chunk>>,
    offset: usize,
}

impl Reader {
    fn front(&mut self, ring: &Ring) -> Option<&[u8]> {
        if self.chunk.is_none() {
            if ring.occupied.load(Ordering::Acquire) == 0 {
                return None;
            }
            self.chunk = Some(ring.slots[self.next].take().expect("published SPSC chunk"));
        }
        let chunk = self.chunk.as_ref().unwrap();
        Some(&chunk.bytes[self.offset..])
    }

    fn consume(&mut self, ring: &Ring, len: usize, wire: &Wire, pressured: bool) -> Option<usize> {
        self.offset += len;
        if self.offset < self.chunk.as_ref().unwrap().bytes.len() {
            return None;
        }
        Some(self.release_chunk(ring, wire, pressured))
    }

    // An allocation refund/recycle and a descriptor credit occur at the same frontier.
    fn release_chunk(&mut self, ring: &Ring, wire: &Wire, pressured: bool) -> usize {
        let chunk = self.chunk.take().expect("active SPSC chunk");
        self.offset = 0;
        self.next = (self.next + 1) % SLOTS;
        if !pressured && wire.budget.used() <= (wire.budget.limit() / 4) * 3 {
            wire.pool.recycle(chunk);
        } else {
            drop(chunk);
        }
        ring.occupied.fetch_sub(1, Ordering::AcqRel)
    }

    fn consume_rx(&mut self, wire: &Wire, amt: usize) {
        if amt == 0 {
            return;
        }
        let len = self
            .chunk
            .as_ref()
            .map_or(0, |chunk| chunk.bytes.len() - self.offset);
        assert!(
            amt <= len,
            "consumed {amt} bytes from a {len}-byte receive buffer"
        );
        if amt < len {
            self.offset += amt;
        } else {
            let before = self.release_chunk(&wire.rx, wire, wire.budget_blocked());
            wire.wake_rx_consumed(before);
        }
    }
}

struct Wire {
    rx: Ring,
    tx: Ring,
    reader: AtomicWaker,
    writer: AtomicWaker,
    owner: Waker,
    rx_end: OnceLock<Option<StreamError>>,
    tx_error: OnceLock<StreamError>,
    shutdown: AtomicBool,
    shutdown_done: AtomicBool,
    tx_flushing: AtomicBool,
    rx_budget: AtomicBool,
    tx_budget: AtomicBool,
    budget: Arc<MemoryBudget>,
    pool: Arc<RemoteChunkPool>,
    backpressure: Arc<AtomicU64>,
    _memory: MemoryReservation,
}

pub(in crate::control) struct RemoteCounters {
    pub(in crate::control) download: Arc<AtomicU64>,
    pub(in crate::control) outbound: Option<Arc<crate::stats::OutboundTracker>>,
    pub(in crate::control) observe_live: bool,
}

struct ProgressState {
    sequence: AtomicU64,
    bytes: AtomicU64,
    first: OnceLock<Instant>,
    last_nanos: AtomicU64,
    finished: AtomicBool,
    changed: AtomicWaker,
    counters: Option<RemoteCounters>,
    _memory: MemoryReservation,
}

/// The owner publishes only bytes committed to the original TCP retransmission queue.
/// One shared-runtime observer can await changes; snapshots may have any number of readers.
#[derive(Clone)]
pub(in crate::control) struct RemoteProgress(Arc<ProgressState>);

impl RemoteProgress {
    fn accept(&self, count: usize, now: Instant, last_report: &mut Option<Instant>) {
        let p = &self.0;
        let was_zero = p.bytes.load(Ordering::Relaxed) == 0;
        if let Some(counters) = &p.counters {
            counters.download.fetch_add(count as u64, Ordering::Relaxed);
            if let Some(outbound) = &counters.outbound {
                outbound.rx_bytes.fetch_add(count as u64, Ordering::Relaxed);
            }
        }
        let seq = p.sequence.load(Ordering::Relaxed);
        p.sequence.store(seq.wrapping_add(1), Ordering::Relaxed);
        // Seeing any new field must also expose the in-progress version to the final read.
        fence(Ordering::Release);
        let first = *p.first.get_or_init(|| now);
        p.last_nanos.store(
            u64::try_from(now.saturating_duration_since(first).as_nanos()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        p.bytes.store(
            p.bytes.load(Ordering::Relaxed).saturating_add(count as u64),
            Ordering::Release,
        );
        p.sequence.store(seq.wrapping_add(2), Ordering::Release);
        let observe_live = p.counters.as_ref().is_some_and(|c| c.observe_live);
        if observe_live
            && (was_zero
                || last_report
                    .is_none_or(|at| now.saturating_duration_since(at) >= PROGRESS_REPORT_INTERVAL))
        {
            *last_report = Some(now);
            p.changed.wake();
        }
    }

    pub(in crate::control) fn accepted(&self) -> u64 {
        self.0.bytes.load(Ordering::Acquire)
    }

    pub(in crate::control) fn snapshot(&self) -> (u64, Option<Instant>, Option<Instant>) {
        let p = &self.0;
        loop {
            let seq = p.sequence.load(Ordering::Acquire);
            if seq & 1 == 0 {
                let bytes = p.bytes.load(Ordering::Relaxed);
                let first = p.first.get().copied();
                let nanos = p.last_nanos.load(Ordering::Relaxed);
                fence(Ordering::Acquire);
                if p.sequence.load(Ordering::Relaxed) == seq {
                    return (bytes, first, first.map(|t| t + Duration::from_nanos(nanos)));
                }
            }
            std::hint::spin_loop();
        }
    }

    pub(in crate::control) fn finished(&self) -> bool {
        self.0.finished.load(Ordering::Acquire)
    }

    pub(in crate::control) fn poll_changed(&self, cx: &mut Context<'_>, observed: u64) -> Poll<()> {
        self.0.changed.register(cx.waker());
        if self.finished() || self.0.bytes.load(Ordering::Acquire) != observed {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    pub(in crate::control) fn poll_finished(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.0.changed.register(cx.waker());
        if self.finished() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn finish(&self) {
        self.0.finished.store(true, Ordering::Release);
        self.0.changed.wake();
    }
}

pub(in crate::control) struct RemoteOwner {
    id: FlowId,
    wire: Arc<Wire>,
    progress: RemoteProgress,
    last_report: Option<Instant>,
    rx: Writer,
    tx: Reader,
}

pub(in crate::control) struct RemoteEndpoint(Box<Application>);

pub(in crate::control) struct RemoteReadHalf<'a> {
    wire: &'a Wire,
    rx: &'a mut Reader,
}

pub(in crate::control) struct RemoteWriteHalf<'a> {
    wire: &'a Wire,
    tx: &'a mut Writer,
}

struct Application {
    wire: Arc<Wire>,
    progress: RemoteProgress,
    rx: Reader,
    tx: Writer,
}

impl std::fmt::Debug for RemoteEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteEndpoint").finish_non_exhaustive()
    }
}

pub(super) fn pair(
    id: FlowId,
    budget: &Arc<MemoryBudget>,
    pool: &Arc<RemoteChunkPool>,
    wake_owner: Waker,
    backpressure: Arc<AtomicU64>,
    counters: Option<RemoteCounters>,
) -> io::Result<(RemoteOwner, RemoteEndpoint)> {
    assert!(Arc::ptr_eq(&pool.budget, budget));
    let memory = pool
        .reserve(ARC_HEADER + size_of::<Wire>() + size_of::<Application>())
        .ok_or_else(capacity)?;
    let progress_memory = pool
        .reserve(ARC_HEADER + size_of::<ProgressState>())
        .ok_or_else(capacity)?;
    let progress = RemoteProgress(Arc::new(ProgressState {
        sequence: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
        first: OnceLock::new(),
        last_nanos: AtomicU64::new(0),
        finished: AtomicBool::new(false),
        changed: AtomicWaker::new(),
        counters,
        _memory: progress_memory,
    }));
    let wire = Arc::new(Wire {
        rx: Ring::new(),
        tx: Ring::new(),
        reader: AtomicWaker::new(),
        writer: AtomicWaker::new(),
        owner: wake_owner,
        rx_end: OnceLock::new(),
        tx_error: OnceLock::new(),
        shutdown: AtomicBool::new(false),
        shutdown_done: AtomicBool::new(false),
        tx_flushing: AtomicBool::new(false),
        rx_budget: AtomicBool::new(false),
        tx_budget: AtomicBool::new(false),
        budget: Arc::clone(budget),
        pool: Arc::clone(pool),
        backpressure,
        _memory: memory,
    });
    Ok((
        RemoteOwner {
            id,
            wire: Arc::clone(&wire),
            progress: progress.clone(),
            last_report: None,
            rx: Writer::default(),
            tx: Reader::default(),
        },
        RemoteEndpoint(Box::new(Application {
            wire,
            progress,
            rx: Reader::default(),
            tx: Writer::default(),
        })),
    ))
}

impl RemoteOwner {
    #[cfg(test)]
    pub(super) fn push_rx(&mut self, slices: &[IoSlice<'_>]) -> usize {
        let (n, wake) = self.push_rx_deferred(slices);
        if wake {
            self.wake_rx_reader();
        }
        n
    }

    pub(super) fn push_rx_deferred(&mut self, slices: &[IoSlice<'_>]) -> (usize, bool) {
        let wire = &self.wire;
        if wire.rx_end.get().is_some() {
            return (0, false);
        }
        let (n, pressure, wake_reader) = self.rx.push(&wire.rx, slices, &wire.pool);
        wire.rx_budget
            .store(pressure == Pressure::Budget, Ordering::Release);
        if pressure != Pressure::None {
            wire.backpressure.fetch_add(1, Ordering::Relaxed);
        }
        (n, wake_reader)
    }

    pub(super) fn wake_rx_reader(&self) {
        self.wire.reader.wake();
    }

    pub(super) fn finish_rx(&self, error: Option<StreamError>) {
        if error != Some(StreamError::WouldBlock) && self.wire.rx_end.set(error).is_ok() {
            self.wire.reader.wake();
        }
    }

    pub(super) fn has_unread_rx(&self) -> bool {
        self.wire.rx.occupied.load(Ordering::Acquire) != 0
    }

    pub(super) fn tx_pending(&self) -> bool {
        self.wire.tx.occupied.load(Ordering::Acquire) != 0
    }

    pub(super) fn pump_tx(
        &mut self,
        stack: &mut Stack,
        limit: usize,
        now: Instant,
    ) -> Result<usize, StreamError> {
        let mut written = 0;
        let mut freed = false;
        let mut remaining = SLOTS;
        let mut error = None;
        while written < limit {
            if let Some(&err) = self.wire.tx_error.get() {
                return Err(err);
            }
            let Some(data) = self.tx.front(&self.wire.tx) else {
                break;
            };
            let offered = data.len().min(limit - written);
            let commit = stack.tcp_reserve_tx(self.id, offered, |spare| {
                let mut src = &data[..offered];
                for part in spare {
                    let n = src.len().min(part.len());
                    part[..n].copy_from_slice(&src[..n]);
                    src = &src[n..];
                    if src.is_empty() {
                        break;
                    }
                }
                Ok(offered - src.len())
            });
            match commit {
                Ok(result) => {
                    let n = result.expect("copying into a bounded TCP loan cannot fail");
                    if n == 0 {
                        break;
                    }
                    let pressured = self.wire.budget_blocked();
                    if let Some(before) = self.tx.consume(&self.wire.tx, n, &self.wire, pressured) {
                        freed = true;
                        remaining = before - 1;
                    }
                    written += n;
                }
                Err(StreamError::WouldBlock) if written != 0 => break,
                Err(err) => {
                    error = Some(err);
                    break;
                }
            }
        }
        if written != 0 {
            self.progress.accept(written, now, &mut self.last_report);
        }
        if freed {
            fence(Ordering::SeqCst);
            let wake_full =
                remaining <= WAKE_LOW_WATERMARK && self.wire.tx.full.swap(false, Ordering::AcqRel);
            let wake_flush = remaining == 0 && self.wire.tx_flushing.swap(false, Ordering::AcqRel);
            let wake_budget = self.wire.tx_budget.load(Ordering::Acquire);
            if wake_full || wake_flush || wake_budget {
                self.wire.writer.wake();
            }
        }
        if let Some(err) = error {
            self.fail_tx(err);
            return Err(err);
        }
        Ok(written)
    }

    pub(super) fn shutdown_pending(&self) -> bool {
        self.wire.shutdown.load(Ordering::Acquire)
            && !self.wire.shutdown_done.load(Ordering::Acquire)
            && self.wire.tx_error.get().is_none()
            && !self.tx_pending()
    }

    pub(super) fn finish_shutdown(&self, result: Result<(), StreamError>) {
        match result {
            Ok(()) => {
                self.wire.shutdown_done.store(true, Ordering::Release);
                self.progress.finish();
                self.wire.writer.wake();
            }
            Err(error) => self.fail_tx(error),
        }
    }

    fn fail_tx(&self, error: StreamError) {
        if error != StreamError::WouldBlock && self.wire.tx_error.set(error).is_ok() {
            self.progress.finish();
            self.wire.writer.wake();
        }
    }

    pub(super) fn fail(&self, error: StreamError) {
        self.finish_rx(Some(error));
        self.fail_tx(error);
    }

    pub(super) fn budget_blocked(&self) -> bool {
        self.wire.budget_blocked()
    }

    pub(super) fn retry_budget(&self) {
        if self.wire.tx_budget.swap(false, Ordering::AcqRel) {
            self.wire.writer.wake();
        }
    }
}

impl Drop for RemoteOwner {
    fn drop(&mut self) {
        self.fail(StreamError::Closed);
    }
}

impl RemoteEndpoint {
    pub(super) fn progress(&self) -> RemoteProgress {
        self.0.progress.clone()
    }

    pub(super) fn split_mut(&mut self) -> (RemoteReadHalf<'_>, RemoteWriteHalf<'_>) {
        let app = self.0.as_mut();
        let wire = app.wire.as_ref();
        (
            RemoteReadHalf {
                wire,
                rx: &mut app.rx,
            },
            RemoteWriteHalf {
                wire,
                tx: &mut app.tx,
            },
        )
    }
}

impl Reader {
    fn poll_read(
        &mut self,
        wire: &Wire,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let terminal = wire.read_terminal(cx);
        let mut read = false;
        let mut freed_from = None;
        while buf.remaining() != 0 {
            let Some(data) = self.front(&wire.rx) else {
                break;
            };
            let n = data.len().min(buf.remaining());
            buf.put_slice(&data[..n]);
            read = true;
            if let Some(before) = self.consume(&wire.rx, n, wire, wire.budget_blocked()) {
                freed_from = Some(before);
            }
        }
        if let Some(before) = freed_from {
            wire.wake_rx_consumed(before);
        }
        if read || buf.remaining() == 0 {
            Poll::Ready(Ok(()))
        } else if let Some(error) = terminal {
            Poll::Ready(error.map_or(Ok(()), |e| Err(stream_error(e))))
        } else {
            Poll::Pending
        }
    }

    fn poll_fill_buf(&mut self, wire: &Wire, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let terminal = wire.read_terminal(cx);
        if let Some(bytes) = self.front(&wire.rx) {
            Poll::Ready(Ok(bytes))
        } else if let Some(error) = terminal {
            Poll::Ready(error.map_or(Ok(&[][..]), |e| Err(stream_error(e))))
        } else {
            Poll::Pending
        }
    }
}

impl Wire {
    fn read_terminal(&self, cx: &Context<'_>) -> Option<Option<StreamError>> {
        self.reader.register(cx.waker());
        // Observing the terminal state before the front also observes the final payload
        // publication when both raced this poll.
        self.rx_end.get().copied()
    }

    fn budget_blocked(&self) -> bool {
        self.rx_budget.load(Ordering::Acquire) || self.tx_budget.load(Ordering::Acquire)
    }

    fn wake_rx_consumed(&self, before: usize) {
        fence(Ordering::SeqCst);
        let remaining = before - 1;
        let wake_full =
            remaining <= WAKE_LOW_WATERMARK && self.rx.full.swap(false, Ordering::AcqRel);
        let wake_rx_budget = self.rx_budget.load(Ordering::Acquire);
        if wake_full || wake_rx_budget {
            self.owner.wake_by_ref();
        }
        if self.tx_budget.load(Ordering::Acquire) {
            self.writer.wake();
        }
    }

    fn poll_write(
        &self,
        tx: &mut Writer,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writer.register(cx.waker());
        if let Some(&error) = self.tx_error.get() {
            return Poll::Ready(Err(stream_error(error)));
        }
        if self.shutdown.load(Ordering::Acquire) {
            return Poll::Ready(Err(stream_error(StreamError::Closed)));
        }
        let (n, pressure, wake_owner) = tx.push(&self.tx, &[IoSlice::new(bytes)], &self.pool);
        if wake_owner {
            self.owner.wake_by_ref();
        }
        if pressure != Pressure::None {
            self.backpressure.fetch_add(1, Ordering::Relaxed);
        }
        if pressure == Pressure::Budget && !self.tx_budget.swap(true, Ordering::AcqRel) {
            self.owner.wake_by_ref();
        }
        if n != 0 || bytes.is_empty() {
            Poll::Ready(Ok(n))
        } else {
            Poll::Pending
        }
    }

    fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.writer.register(cx.waker());
        if let Some(&error) = self.tx_error.get() {
            return Poll::Ready(Err(stream_error(error)));
        }
        if self.tx.occupied.load(Ordering::Acquire) == 0 {
            return Poll::Ready(Ok(()));
        }
        self.tx_flushing.store(true, Ordering::Release);
        fence(Ordering::SeqCst);
        if self.tx.occupied.load(Ordering::Acquire) == 0 {
            self.tx_flushing.store(false, Ordering::Relaxed);
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.writer.register(cx.waker());
        if self.shutdown_done.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }
        if let Some(&error) = self.tx_error.get() {
            return Poll::Ready(Err(stream_error(error)));
        }
        if !self.shutdown.swap(true, Ordering::AcqRel) {
            self.owner.wake_by_ref();
        }
        Poll::Pending
    }
}

impl AsyncRead for RemoteEndpoint {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let app = self.get_mut().0.as_mut();
        app.rx.poll_read(&app.wire, cx, buf)
    }
}

impl AsyncRead for RemoteReadHalf<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let half = self.get_mut();
        half.rx.poll_read(half.wire, cx, buf)
    }
}

impl AsyncBufRead for RemoteEndpoint {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let app = self.get_mut().0.as_mut();
        app.rx.poll_fill_buf(&app.wire, cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let app = self.get_mut().0.as_mut();
        app.rx.consume_rx(&app.wire, amt);
    }
}

impl AsyncBufRead for RemoteReadHalf<'_> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let half = self.get_mut();
        half.rx.poll_fill_buf(half.wire, cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let half = self.get_mut();
        half.rx.consume_rx(half.wire, amt);
    }
}

impl AsyncWrite for RemoteEndpoint {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let app = self.get_mut().0.as_mut();
        app.wire.poll_write(&mut app.tx, cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.wire.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.wire.poll_shutdown(cx)
    }
}

impl AsyncWrite for RemoteWriteHalf<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let half = self.get_mut();
        half.wire.poll_write(half.tx, cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.wire.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.wire.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
