//! One AF_XDP socket and ledger owner. CQ returns retained outputs, not delivery receipts.
//!
//! UMEM and its reservation survive in-process close/drop. Outstanding RX custody and TX
//! sidecars also survive drop: socket close is not a completion or deferred-DMA-release fence.

use std::alloc::Layout;
use std::cell::Cell;
use std::io;
use std::mem::ManuallyDrop;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use honk_datapath::buffer::{
    DrainState, FrameConfig, FrameLease, FrameLedger, LedgerError, OutstandingTx, TxClass,
};
use honk_netstack::{MemoryBudget, MemoryReservation};

#[path = "ring.rs"]
mod ring;

use ring::{Descriptor, Rings, Umem};

pub const FRAME_SIZE: usize = 4096;
pub const MAX_SEGMENTS: usize = 18;
pub const METADATA_SIZE: usize = 32;

pub(crate) fn rx_frame_capacity(metadata_len: usize) -> io::Result<usize> {
    if !matches!(metadata_len, 0 | 32 | 64 | 128) {
        return Err(invalid_config(
            "RX metadata length must be 0, 32, 64, or 128",
        ));
    }
    Ok(FRAME_SIZE - 256 - metadata_len)
}

static NEXT_PORT: AtomicU64 = AtomicU64::new(1);
const NO_RX_SLOT: usize = usize::MAX;
const RETAINED_RX_SLOT_BYTES: usize = 1024;

/// Packet identity only; copies never release or expose frame storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedRxHandle {
    port: u64,
    port_generation: u64,
    slot: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedRxIdentity {
    pub port: u64,
    pub port_generation: u64,
    pub slot: u64,
    pub slot_generation: u64,
}

impl RetainedRxHandle {
    pub fn receipt_identity(&self) -> RetainedRxIdentity {
        RetainedRxIdentity {
            port: self.port,
            port_generation: self.port_generation,
            slot: self.slot,
            slot_generation: self.generation,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxDisposition {
    Release,
    Retain,
}

/// Released frame custody with the packet generation still pinned in its original slot.
#[derive(Debug)]
#[must_use = "acknowledge this exact completion through complete_retained_rx"]
pub struct RxCompletion {
    handle: RetainedRxHandle,
}

impl RxCompletion {
    pub fn handle(&self) -> RetainedRxHandle {
        self.handle
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RxPhase {
    Free,
    Held,
    CompletionPending,
}

struct RetainedRxSlot {
    leases: [Option<FrameLease>; MAX_SEGMENTS],
    lengths: [u32; MAX_SEGMENTS],
    count: usize,
    metadata_len: usize,
    length: usize,
    generation: u64,
    next_free: usize,
    phase: RxPhase,
}

const _: () = {
    assert!(size_of::<RetainedRxHandle>() <= 32);
    assert!(size_of::<RxCompletion>() <= 32);
    assert!(size_of::<RetainedRxSlot>() <= RETAINED_RX_SLOT_BYTES);
    assert!(align_of::<RetainedRxSlot>() <= align_of::<u64>());
};

struct RetainedRxSlots {
    slots: Box<[RetainedRxSlot]>,
    free: usize,
    port: u64,
    port_generation: u64,
    held: usize,
    completions: usize,
    reservation: Option<MemoryReservation>,
}

impl RetainedRxSlots {
    fn layout(config: PortConfig) -> io::Result<(usize, usize)> {
        let count = config.rx_frames.min(config.ring_size as usize);
        let layout = Layout::array::<RetainedRxSlot>(count)
            .map_err(|_| invalid_config("retained RX array extent overflow"))?;
        let bytes = count
            .checked_mul(RETAINED_RX_SLOT_BYTES)
            .filter(|&bytes| bytes <= isize::MAX as usize)
            .ok_or_else(|| invalid_config("retained RX reservation overflow"))?;
        if count == 0 || layout.size() > bytes || layout.align() > align_of::<u64>() {
            return Err(invalid_config("invalid retained RX layout"));
        }
        Ok((count, bytes))
    }

    fn new(config: PortConfig, budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let (count, bytes) = Self::layout(config)?;
        let reservation = reserve(budget, bytes)?;
        let port = NEXT_PORT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| invalid_config("Port identity exhausted"))?;
        let mut slots = Vec::new();
        slots.try_reserve_exact(count).map_err(|_| {
            io::Error::new(io::ErrorKind::OutOfMemory, "retained RX allocation failed")
        })?;
        for index in 0..count {
            slots.push(RetainedRxSlot {
                leases: [None; MAX_SEGMENTS],
                lengths: [0; MAX_SEGMENTS],
                count: 0,
                metadata_len: 0,
                length: 0,
                generation: 0,
                next_free: if index + 1 == count {
                    NO_RX_SLOT
                } else {
                    index + 1
                },
                phase: RxPhase::Free,
            });
        }
        Ok(Self {
            slots: slots.into_boxed_slice(),
            free: 0,
            port,
            port_generation: 1,
            held: 0,
            completions: 0,
            reservation: Some(reservation),
        })
    }

    fn check(&self, handle: RetainedRxHandle, phase: RxPhase) -> io::Result<usize> {
        let index = usize::try_from(handle.slot).ok();
        if handle.port != self.port
            || handle.port_generation != self.port_generation
            || index
                .and_then(|index| self.slots.get(index))
                .is_none_or(|slot| slot.generation != handle.generation || slot.phase != phase)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "foreign or stale retained RX handle",
            ));
        }
        Ok(index.expect("checked retained RX index"))
    }
}

impl Drop for RetainedRxSlots {
    fn drop(&mut self) {
        if self.held != 0 || self.completions != 0 {
            // Dropping tokens or closing the socket is not a custody/completion acknowledgment.
            std::mem::forget(std::mem::replace(&mut self.slots, Box::new([])));
            std::mem::forget(self.reservation.take());
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindMode {
    ZeroCopy,
    Copy,
}

impl BindMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ZeroCopy => "zerocopy",
            Self::Copy => "copy",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PortConfig {
    pub rx_frames: usize,
    pub control_frames: usize,
    pub bulk_frames: usize,
    pub ring_size: u32,
}

impl PortConfig {
    pub fn umem_bytes(self) -> io::Result<usize> {
        self.rx_frames
            .checked_add(self.control_frames)
            .and_then(|n| n.checked_add(self.bulk_frames))
            .and_then(|n| n.checked_mul(FRAME_SIZE))
            .filter(|&n| n <= isize::MAX as usize && u64::try_from(n).is_ok())
            .ok_or_else(|| invalid_config("UMEM extent overflow"))
    }

    pub fn validate(self) -> io::Result<()> {
        if self.rx_frames == 0 || self.control_frames == 0 || self.bulk_frames == 0 {
            return Err(invalid_config(
                "RX, control, and bulk partitions must be nonempty",
            ));
        }
        if !self.ring_size.is_power_of_two() || self.ring_size > i32::MAX as u32 {
            return Err(invalid_config(
                "ring size must be a power of two below 2^31",
            ));
        }
        let tx_frames = self
            .control_frames
            .checked_add(self.bulk_frames)
            .ok_or_else(|| invalid_config("TX partition extent overflow"))?;
        if tx_frames > self.ring_size as usize {
            return Err(invalid_config(
                "TX class commitments exceed TX/CQ ring capacity",
            ));
        }
        self.umem_bytes()?;
        FrameLedger::<u32>::metadata_bytes(self.frame_config()).map_err(io::Error::other)?;
        RetainedRxSlots::layout(self)?;
        Ok(())
    }

    fn frame_config(self) -> FrameConfig {
        let rx_capacity = self.rx_frames.min(self.ring_size as usize);
        FrameConfig {
            base_address: 0,
            frame_size: FRAME_SIZE,
            rx_frames: self.rx_frames,
            control_frames: self.control_frames,
            bulk_frames: self.bulk_frames,
            fill_capacity: rx_capacity,
            rx_capacity,
            control_descriptors: self.control_frames,
            bulk_descriptors: self.bulk_frames,
            tx_capacity: self.ring_size as usize,
            completion_capacity: self.ring_size as usize,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortCounters {
    pub submitted: u64,
    pub completed: u64,
    /// Complete packets released to the TX producer, independent of descriptor count.
    pub published_packets: u64,
    /// Sticky overflow: publication and DMA ownership cannot be rolled back.
    pub publication_count_unavailable: bool,
    pub rx: u64,
    pub fill: u64,
    pub invalid: u64,
    pub rx_kicks: u64,
    pub tx_kicks: u64,
    pub wakeup_errors: u64,
}

impl PortCounters {
    fn published(&mut self) {
        if let Some(next) = self.published_packets.checked_add(1) {
            self.published_packets = next;
        } else {
            self.publication_count_unavailable = true;
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketStats {
    pub rx_dropped: u64,
    pub rx_invalid_descs: u64,
    pub tx_invalid_descs: u64,
    pub rx_ring_full: u64,
    pub rx_fill_ring_empty_descs: u64,
    pub tx_ring_empty_descs: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RingSnapshot {
    pub rx_producer: u32,
    pub rx_consumer: u32,
    pub tx_producer: u32,
    pub tx_consumer: u32,
    pub fill_producer: u32,
    pub fill_consumer: u32,
    pub cq_producer: u32,
    pub cq_consumer: u32,
}

fn invalid_config(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn reserve(budget: &Arc<MemoryBudget>, bytes: usize) -> io::Result<MemoryReservation> {
    budget
        .reserve(bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::OutOfMemory, "AF_XDP memory budget exhausted"))
}

fn class_index(class: TxClass) -> usize {
    match class {
        TxClass::Control => 0,
        TxClass::Bulk => 1,
    }
}

const NO_TX_OWNER: u32 = u32::MAX;
const _: () = assert!(MAX_SEGMENTS <= u8::MAX as usize);

// Keep the tag and count together in front of the aligned owner.
#[repr(u8)]
enum TxOwnerSlot<L> {
    Free(u32),
    Occupied { remaining: u8, retained: L },
}

struct Sidecar<L> {
    slots: Box<[TxOwnerSlot<L>]>,
    free: u32,
    reservation: Option<MemoryReservation>,
}

impl<L> Sidecar<L> {
    fn new(config: PortConfig, budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let count = config.control_frames + config.bulk_frames;
        let bytes = Layout::array::<TxOwnerSlot<L>>(count)
            .map_err(|_| invalid_config("TX sidecar extent overflow"))?
            .size();
        let reservation = reserve(budget, bytes)?;
        let slots = (1..count as u32)
            .chain([NO_TX_OWNER])
            .map(TxOwnerSlot::Free)
            .collect();
        Ok(Self {
            slots,
            free: 0,
            reservation: Some(reservation),
        })
    }

    fn occupy(&mut self, retained: L, remaining: u8) -> u32 {
        let index = self.free;
        let slot = &mut self.slots[index as usize];
        let TxOwnerSlot::Free(next) = slot else {
            unreachable!("TX sidecar free list points to an occupied slot");
        };
        self.free = *next;
        *slot = TxOwnerSlot::Occupied {
            remaining,
            retained,
        };
        index
    }

    fn release(&mut self, index: u32) {
        let next = self.free;
        self.free = index;
        self.slots[index as usize] = TxOwnerSlot::Free(next);
    }

    #[cfg(test)]
    fn occupied(&self) -> impl Iterator<Item = (&L, u8)> {
        self.slots.iter().filter_map(|slot| match slot {
            TxOwnerSlot::Free(_) => None,
            TxOwnerSlot::Occupied {
                remaining,
                retained,
            } => Some((retained, *remaining)),
        })
    }
}

impl<L> Drop for Sidecar<L> {
    fn drop(&mut self) {
        if self
            .slots
            .iter()
            .any(|slot| matches!(slot, TxOwnerSlot::Occupied { .. }))
        {
            // No CQ or device-release fence: dropping retained values would falsely dispose
            // core outputs. Keep their separately funded storage through process exit too.
            std::mem::forget(std::mem::replace(&mut self.slots, Box::new([])));
            std::mem::forget(self.reservation.take());
        }
    }
}

struct CompletedOwners<'a, L> {
    sidecar: &'a mut Sidecar<L>,
    indices: &'a [u32],
}

impl<L> Drop for CompletedOwners<'_, L> {
    fn drop(&mut self) {
        for &index in self.indices {
            self.sidecar.release(index);
        }
    }
}

struct RxPacket<'a, const N: usize> {
    descriptors: &'a [Descriptor],
    length: usize,
    pointers: [*mut u8; N],
    metadata: Option<(*mut u8, usize)>,
}

impl<const N: usize> RxPacket<'_, N> {
    /// # Safety
    /// Every checked extent must remain leased to RX for the entire callback.
    unsafe fn with_slices<R>(&self, f: impl FnOnce(&[&[u8]], &[u8]) -> R) -> R {
        let metadata = self.metadata.map_or(&[][..], |(pointer, length)| {
            // SAFETY: the checked prefix belongs to the first leased RX frame.
            unsafe { std::slice::from_raw_parts(pointer, length) }
        });
        let mut segments = [&[][..]; N];
        for (index, descriptor) in self.descriptors.iter().enumerate() {
            // SAFETY: each checked extent belongs to a distinct leased RX frame.
            segments[index] = unsafe {
                std::slice::from_raw_parts(self.pointers[index], descriptor.len as usize)
            };
        }
        f(&segments[..self.descriptors.len()], metadata)
    }
}

struct PreparedTx {
    lease: FrameLease,
    length: u32,
    class: TxClass,
}

pub struct Port<L> {
    socket: Option<OwnedFd>,
    config: PortConfig,
    zerocopy: bool,
    mtu: u32,
    scatter_gather: bool,
    metadata_len: usize,
    umem: Umem,
    rings: Rings,
    ledger: ManuallyDrop<FrameLedger<u32>>,
    retained_rx: RetainedRxSlots,
    sidecar: Sidecar<L>,
    rx_consumer: u32,
    tx_producer: u32,
    fill_producer: u32,
    fill_consumer: u32,
    cq_consumer: u32,
    tx_free: [usize; 2],
    closed: Cell<bool>,
    tx_batch_active: bool,
    counters: PortCounters,
    _bookkeeping: Option<MemoryReservation>,
}

struct TxReservation<'a, L> {
    port: &'a mut Port<L>,
    prepared: Option<PreparedTx>,
}

impl<L> TxReservation<'_, L> {
    fn publish(mut self, retained: L) -> io::Result<()> {
        // Publication owns fatal retention from submission onward, including a failed kick.
        let prepared = self.prepared.take().expect("unpublished TX reservation");
        self.port.publish_tx(prepared, retained)
    }
}

impl<L> Drop for TxReservation<'_, L> {
    fn drop(&mut self) {
        if let Some(prepared) = self.prepared.take()
            && self.port.ledger.cancel_tx(prepared.lease).is_err()
        {
            self.port.counters.invalid += 1;
            self.port.close();
        }
    }
}

struct TxBatchGuard<'a, L> {
    port: &'a mut Port<L>,
}

impl<L> Drop for TxBatchGuard<'_, L> {
    fn drop(&mut self) {
        if self.port.tx_batch_active {
            self.port.tx_batch_active = false;
            self.port.close();
        }
    }
}

struct RxCallbackGuard<'a, L> {
    port: &'a mut Port<L>,
}

impl<L> Drop for RxCallbackGuard<'_, L> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.port.close();
        }
    }
}

struct RxBorrowGuard<'a>(&'a Cell<bool>);

impl Drop for RxBorrowGuard<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.set(true);
        }
    }
}

impl<L> Drop for Port<L> {
    fn drop(&mut self) {
        if self.retained_rx.held == 0
            && self.retained_rx.completions == 0
            && (!self.closed.get() || self.ledger.drain_state().rx_leased == 0)
        {
            // SAFETY: this is the sole ledger owner and all CPU RX custody was relinquished.
            unsafe { ManuallyDrop::drop(&mut self.ledger) };
        } else {
            std::mem::forget(self._bookkeeping.take());
        }
    }
}

impl<L> Port<L> {
    pub fn open(
        ifindex: u32,
        queue: u32,
        mode: BindMode,
        config: PortConfig,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Self> {
        Self::open_device(
            ifindex,
            queue,
            mode,
            config,
            1500,
            false,
            METADATA_SIZE,
            budget,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "device-negotiated metadata is not a configurable buffer capacity"
    )]
    pub fn open_device(
        ifindex: u32,
        queue: u32,
        mode: BindMode,
        config: PortConfig,
        mtu: u32,
        scatter_gather: bool,
        metadata_len: usize,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Self> {
        let capacity = rx_frame_capacity(metadata_len)?;
        let required = (mtu as usize + 22).div_ceil(capacity);
        if !(68..=65535).contains(&mtu) || (required > 1 && !scatter_gather) {
            return Err(invalid_config("MTU requires negotiated scatter/gather"));
        }
        config.validate()?;
        if required > MAX_SEGMENTS
            || config.rx_frames < required
            || config.control_frames < required
            || config.bulk_frames < required
            || (config.ring_size as usize) < required
        {
            return Err(invalid_config(
                "whole-packet commitments cannot cover device MTU",
            ));
        }
        if ifindex == 0 {
            return Err(invalid_config("AF_XDP requires a nonzero ifindex"));
        }
        crate::device::validate_queue(ifindex, queue)?;
        let bookkeeping = reserve(budget, size_of::<Self>() - size_of::<FrameLedger<u32>>())?;
        let retained_rx = RetainedRxSlots::new(config, budget)?;
        let ledger = FrameLedger::new(config.frame_config(), budget).map_err(io::Error::other)?;
        let sidecar = Sidecar::new(config, budget)?;
        let umem = Umem::map(config.umem_bytes()?, budget)?;
        let (socket, rings, zerocopy) = ring::open(
            ifindex,
            queue,
            mode,
            config,
            scatter_gather,
            metadata_len,
            &umem,
            budget,
        )?;
        Ok(Self {
            socket: Some(socket),
            config,
            zerocopy,
            mtu,
            scatter_gather,
            metadata_len,
            umem,
            rings,
            ledger: ManuallyDrop::new(ledger),
            retained_rx,
            sidecar,
            rx_consumer: 0,
            tx_producer: 0,
            fill_producer: 0,
            fill_consumer: 0,
            cq_consumer: 0,
            tx_free: [config.control_frames, config.bulk_frames],
            closed: Cell::new(false),
            tx_batch_active: false,
            counters: PortCounters::default(),
            _bookkeeping: Some(bookkeeping),
        })
    }

    /// Borrow a packet with exactly 0, 32, 64, or 128 bytes of selected producer metadata.
    /// `Ok(0)` may leave RX queued pending FILL consumer publication; callers must retry later.
    pub fn receive_segments(
        &mut self,
        batch: usize,
        metadata_len: usize,
        mut f: impl FnMut(&[&[u8]], &[u8]),
    ) -> io::Result<usize> {
        self.receive_segments_with(batch, metadata_len, move |segments, metadata, _| {
            f(segments, metadata)
        })
    }

    /// The restricted sink permits same-port forwarding without releasing borrowed RX frames.
    /// `Ok(0)` may leave RX queued pending FILL consumer publication; callers must retry later.
    /// Zero exports no metadata; a nonzero length must match the admitted UMEM headroom.
    /// The owned callback is dropped before publishing the RX consumer or refilling FILL.
    pub fn receive_segments_with(
        &mut self,
        batch: usize,
        metadata_len: usize,
        mut f: impl FnMut(&[&[u8]], &[u8], &mut TxSink<'_, L>),
    ) -> io::Result<usize> {
        let start = self.rx_consumer;
        let result: io::Result<usize> = {
            let guard = RxCallbackGuard { port: self };
            let port = &mut *guard.port;
            let result = port
                .rx_batch_available(metadata_len)
                .and_then(|mut remaining| {
                    let mut packets = 0;
                    while remaining != 0 && packets < batch && !port.closed.get() {
                        let first = port.rings.rx.read(port.rx_consumer);
                        let count = if first.options == 1 && port.scatter_gather {
                            port.receive_borrowed_packet::<MAX_SEGMENTS>(
                                remaining,
                                metadata_len,
                                first,
                                &mut f,
                            )?
                        } else {
                            port.receive_borrowed_packet::<1>(
                                remaining,
                                metadata_len,
                                first,
                                &mut f,
                            )?
                        };
                        if count == 0 {
                            break;
                        }
                        remaining -= count;
                        packets += 1;
                    }
                    Ok(packets)
                });
            drop(f);
            result
        };
        // The cached cursor includes admitted callbacks. Publish the prefix even on an
        // ordinary error. Unwind keeps the shared cursor and FILL at their last publication.
        if self.rx_consumer != start {
            self.rings.rx.publish_consumer(self.rx_consumer);
        }
        let packets = result?;
        if !self.closed.get() {
            self.refill()?;
        }
        Ok(packets)
    }

    fn receive_borrowed_packet<const N: usize>(
        &mut self,
        available: u32,
        metadata_len: usize,
        first: Descriptor,
        f: &mut impl FnMut(&[&[u8]], &[u8], &mut TxSink<'_, L>),
    ) -> io::Result<u32> {
        let mut descriptors = [first; N];
        let Some(packet) = self.read_rx_packet(
            available,
            metadata_len,
            self.scatter_gather,
            &mut descriptors,
        )?
        else {
            return Ok(0);
        };
        let count = packet.descriptors.len();
        let mut leases = [None; N];
        for (lease, descriptor) in leases.iter_mut().zip(packet.descriptors) {
            *lease = Some(
                self.ledger
                    .receive_rx(descriptor.addr, descriptor.len as usize)
                    .map_err(io::Error::other)
                    .map_err(|error| self.rx_invalid(error))?,
            );
        }
        self.rx_consumer = self.rx_consumer.wrapping_add(count as u32);
        self.counters.rx += 1;
        // SAFETY: the whole chain is leased until the slices expire. TxSink only reserves
        // and writes the TX partitions of the stable UMEM mapping.
        unsafe {
            packet.with_slices(|segments, metadata| {
                f(segments, metadata, &mut TxSink { port: self })
            });
        }
        for lease in &leases[..count] {
            self.ledger
                .relinquish_rx(lease.expect("leased RX packet"))
                .map_err(io::Error::other)
                .map_err(|error| self.rx_invalid(error))?;
        }
        Ok(count as u32)
    }

    /// Install whole-chain custody before calling the synchronous packet consumer.
    pub fn receive_segments_owned(
        &mut self,
        batch: usize,
        metadata_len: usize,
        f: impl FnMut(RetainedRxHandle, &[&[u8]], &[u8], &mut TxSink<'_, L>) -> RxDisposition,
    ) -> io::Result<usize> {
        self.receive_segments_inner(batch, metadata_len, self.scatter_gather, f)
    }

    fn receive_segments_inner(
        &mut self,
        batch: usize,
        metadata_len: usize,
        scatter_gather: bool,
        mut f: impl FnMut(RetainedRxHandle, &[&[u8]], &[u8], &mut TxSink<'_, L>) -> RxDisposition,
    ) -> io::Result<usize> {
        let mut available = self.rx_batch_available(metadata_len)?;
        let mut packets = 0;
        while available != 0 && packets < batch && !self.closed.get() {
            let first = self.rings.rx.read(self.rx_consumer);
            let mut descriptors = [first; MAX_SEGMENTS];
            let Some(packet) =
                self.read_rx_packet(available, metadata_len, scatter_gather, &mut descriptors)?
            else {
                break;
            };
            if self.retained_rx.free == NO_RX_SLOT {
                break;
            }
            let count = packet.descriptors.len();
            let index = self.retained_rx.free;
            let slot = &mut self.retained_rx.slots[index];
            let Some(generation) = slot.generation.checked_add(1) else {
                return Err(self.rx_invalid(io::Error::other("retained RX generation exhausted")));
            };
            self.retained_rx.free = slot.next_free;
            slot.generation = generation;
            slot.phase = RxPhase::Held;
            slot.count = count;
            slot.metadata_len = metadata_len;
            slot.length = packet.length;
            self.retained_rx.held += 1;
            let handle = RetainedRxHandle {
                port: self.retained_rx.port,
                port_generation: self.retained_rx.port_generation,
                slot: index as u64,
                generation,
            };
            for (part, descriptor) in packet.descriptors.iter().enumerate() {
                let lease = self
                    .ledger
                    .receive_rx(descriptor.addr, descriptor.len as usize)
                    .map_err(io::Error::other)
                    .map_err(|error| self.rx_invalid(error))?;
                self.retained_rx.slots[index].leases[part] = Some(lease);
                self.retained_rx.slots[index].lengths[part] = descriptor.len;
            }
            self.rx_consumer = self.rx_consumer.wrapping_add(count as u32);
            available -= count as u32;
            self.counters.rx += 1;
            packets += 1;
            self.rings.rx.publish_consumer(self.rx_consumer);
            let disposition = {
                let guard = RxCallbackGuard { port: self };
                // SAFETY: the installed slot owns the checked chain through the callback,
                // including unwind. TxSink can only write disjoint TX frames.
                unsafe {
                    packet.with_slices(|segments, metadata| {
                        f(handle, segments, metadata, &mut TxSink { port: guard.port })
                    })
                }
            };
            if disposition == RxDisposition::Release {
                let completion = self.relinquish_retained_rx(handle)?;
                if !self.closed.get() {
                    self.refill()?;
                }
                self.complete_retained_rx(completion)?;
            }
        }
        if !self.closed.get() {
            self.refill()?;
        }
        Ok(packets)
    }

    fn rx_batch_available(&mut self, metadata_len: usize) -> io::Result<u32> {
        rx_frame_capacity(metadata_len)?;
        if metadata_len != 0 && metadata_len != self.metadata_len {
            return Err(invalid_config(
                "RX metadata length differs from admitted headroom",
            ));
        }
        // A borrowed callback can unwind with its cached consumer ahead of the shared ring.
        if self.closed.get() {
            return Ok(0);
        }
        self.observe_fill()?;
        let available = ring::distance(
            self.rings.rx.producer(),
            self.rx_consumer,
            self.config.ring_size,
        )
        .map_err(|error| self.invalid(error))?;
        self.observe_fill()?;
        Ok(available)
    }

    fn read_rx_packet<'a, const N: usize>(
        &mut self,
        available: u32,
        metadata_len: usize,
        scatter_gather: bool,
        descriptors: &'a mut [Descriptor; N],
    ) -> io::Result<Option<RxPacket<'a, N>>> {
        let mut descriptor = descriptors[0];
        let mut count = 0;
        let mut length = 0u64;
        let mut ready = true;
        loop {
            if descriptor.len == 0
                || descriptor.options & !1 != 0
                || (descriptor.options != 0 && !scatter_gather)
            {
                return Err(self.rx_invalid(io::Error::other("invalid RX chain descriptor")));
            }
            length += u64::from(descriptor.len);
            if length > u64::from(self.mtu) + 22 {
                return Err(self.rx_invalid(io::Error::other("RX chain exceeds device MTU")));
            }
            if descriptors[..count].iter().any(|previous| {
                previous.addr / FRAME_SIZE as u64 == descriptor.addr / FRAME_SIZE as u64
            }) {
                return Err(self.rx_invalid(io::Error::other("duplicate RX frame in chain")));
            }
            // xsk_flush publishes RX before the corresponding FILL consumer advance.
            ready &= self
                .ledger
                .rx_ready(descriptor.addr, descriptor.len as usize)
                .map_err(io::Error::other)
                .map_err(|error| self.rx_invalid(error))?;
            if count == 0 && descriptor.addr % (FRAME_SIZE as u64) < metadata_len as u64 {
                return Err(self.rx_invalid(io::Error::other("RX metadata headroom missing")));
            }
            descriptors[count] = descriptor;
            count += 1;
            if descriptor.options == 0 {
                break;
            }
            if count as u32 == available {
                if available == self.config.ring_size {
                    return Err(
                        self.rx_invalid(io::Error::other("unterminated RX chain fills ring"))
                    );
                }
                return Ok(None);
            }
            if count == N {
                return Err(self.rx_invalid(io::Error::other("RX chain exceeds segment limit")));
            }
            descriptor = self
                .rings
                .rx
                .read(self.rx_consumer.wrapping_add(count as u32));
        }
        let descriptors = &descriptors[..count];
        let metadata = if metadata_len == 0 {
            None
        } else {
            let pointer = self
                .umem
                .frame_pointer(descriptors[0].addr - metadata_len as u64, metadata_len)
                .map_err(|error| self.rx_invalid(error))?;
            Some((pointer, metadata_len))
        };
        let mut pointers = [std::ptr::null_mut(); N];
        for (pointer, descriptor) in pointers.iter_mut().zip(descriptors) {
            *pointer = self
                .umem
                .frame_pointer(descriptor.addr, descriptor.len as usize)
                .map_err(|error| self.rx_invalid(error))?;
        }
        if !ready || self.ledger.rx_credit() < count {
            return Ok(None);
        }
        Ok(Some(RxPacket {
            descriptors,
            length: length as usize,
            pointers,
            metadata,
        }))
    }

    /// The callback and its result cannot carry a borrow of the retained packet.
    pub fn with_retained_rx<R>(
        &self,
        handle: RetainedRxHandle,
        f: impl FnOnce(&[&[u8]], &[u8]) -> R,
    ) -> io::Result<R> {
        let index = self
            .retained_rx
            .check(handle, RxPhase::Held)
            .map_err(|error| self.retained_rx_invalid(error))?;
        let slot = &self.retained_rx.slots[index];
        if slot.count == 0
            || slot.count > MAX_SEGMENTS
            || slot.lengths[..slot.count]
                .iter()
                .map(|&length| length as usize)
                .sum::<usize>()
                != slot.length
        {
            return Err(self.retained_rx_invalid(io::Error::other("invalid retained RX extent")));
        }
        let mut segments: [&[u8]; MAX_SEGMENTS] = [&[]; MAX_SEGMENTS];
        for (part, segment) in segments[..slot.count].iter_mut().enumerate() {
            let lease = slot.leases[part].ok_or_else(|| {
                self.retained_rx_invalid(io::Error::other("incomplete retained RX custody"))
            })?;
            *segment = self
                .umem
                .frame(lease.address(), slot.lengths[part] as usize)
                .map_err(|error| self.retained_rx_invalid(error))?;
        }
        let metadata = if slot.metadata_len == 0 {
            &[][..]
        } else {
            let first = slot.leases[0]
                .expect("checked complete retained chain")
                .address();
            let address = first.checked_sub(slot.metadata_len as u64).ok_or_else(|| {
                self.retained_rx_invalid(io::Error::other("invalid retained metadata extent"))
            })?;
            self.umem
                .frame(address, slot.metadata_len)
                .map_err(|error| self.retained_rx_invalid(error))?
        };
        let _guard = RxBorrowGuard(&self.closed);
        Ok(f(&segments[..slot.count], metadata))
    }

    /// Release the frame chain while pinning its identity until exact completion acknowledgment.
    pub fn release_retained_rx(&mut self, handle: RetainedRxHandle) -> io::Result<RxCompletion> {
        let completion = self.relinquish_retained_rx(handle)?;
        self.refill()?;
        Ok(completion)
    }

    fn relinquish_retained_rx(&mut self, handle: RetainedRxHandle) -> io::Result<RxCompletion> {
        let index = self
            .retained_rx
            .check(handle, RxPhase::Held)
            .map_err(|error| self.rx_invalid(error))?;
        for part in 0..self.retained_rx.slots[index].count {
            let lease = self.retained_rx.slots[index].leases[part].ok_or_else(|| {
                self.rx_invalid(io::Error::other("incomplete retained RX custody"))
            })?;
            self.ledger
                .relinquish_rx(lease)
                .map_err(io::Error::other)
                .map_err(|error| self.rx_invalid(error))?;
            self.retained_rx.slots[index].leases[part] = None;
        }
        self.retained_rx.slots[index].phase = RxPhase::CompletionPending;
        self.retained_rx.held -= 1;
        self.retained_rx.completions += 1;
        Ok(RxCompletion { handle })
    }

    pub fn complete_retained_rx(&mut self, completion: RxCompletion) -> io::Result<()> {
        let index = self
            .retained_rx
            .check(completion.handle, RxPhase::CompletionPending)
            .map_err(|error| self.rx_invalid(error))?;
        let slot = &mut self.retained_rx.slots[index];
        slot.phase = RxPhase::Free;
        slot.count = 0;
        slot.next_free = self.retained_rx.free;
        self.retained_rx.free = index;
        self.retained_rx.completions -= 1;
        Ok(())
    }

    pub fn retained_rx_count(&self) -> usize {
        self.retained_rx.held
    }

    pub fn rx_completion_count(&self) -> usize {
        self.retained_rx.completions
    }

    fn retained_rx_invalid(&self, error: io::Error) -> io::Error {
        self.closed.set(true);
        io::Error::new(io::ErrorKind::InvalidData, error)
    }

    fn rx_invalid(&mut self, error: io::Error) -> io::Error {
        self.invalid(io::Error::new(io::ErrorKind::InvalidData, error))
    }

    /// Defer per-packet wakeups only until this synchronous operation returns.
    /// Work and final wakeup results are independent, including after work fails.
    /// Panicking work closes admission without I/O or releasing published owners.
    /// Scopes on the same Port must not nest or span an asynchronous suspension.
    pub fn transmit_batch<R>(&mut self, work: impl FnOnce(&mut Self) -> R) -> (R, io::Result<()>) {
        assert!(!self.tx_batch_active, "nested Port transmit scope");
        self.tx_batch_active = true;
        let guard = TxBatchGuard { port: self };
        let result = work(guard.port);
        let kick = guard.port.kick();
        guard.port.tx_batch_active = false;
        (result, kick)
    }

    /// Copy borrowed L2 segments directly to reserved UMEM chunks, then publish once.
    pub fn transmit_segments(
        &mut self,
        class: TxClass,
        segments: &[&[u8]],
        retained: L,
    ) -> io::Result<()> {
        let length = segments
            .iter()
            .try_fold(0usize, |sum, part| sum.checked_add(part.len()))
            .ok_or_else(|| invalid_config("invalid TX packet extent"))?;
        self.transmit_with(class, length, retained, |_, output| {
            let mut part = 0;
            let mut offset = 0;
            for chunk in output {
                let mut written = 0;
                while written < chunk.len() {
                    if offset == segments[part].len() {
                        part += 1;
                        offset = 0;
                        continue;
                    }
                    let bytes = (chunk.len() - written).min(segments[part].len() - offset);
                    chunk[written..written + bytes]
                        .copy_from_slice(&segments[part][offset..offset + bytes]);
                    written += bytes;
                    offset += bytes;
                }
            }
            Ok(())
        })
    }

    /// Reserve every frame/descriptor before materialization; writer failure publishes nothing.
    pub fn transmit_with(
        &mut self,
        class: TxClass,
        length: usize,
        retained: L,
        writer: impl FnOnce(&L, &mut [&mut [u8]]) -> io::Result<()>,
    ) -> io::Result<()> {
        let (wire_length, count) = self.tx_packet_layout(length)?;
        let used = ring::distance(
            self.tx_producer,
            self.rings.tx.consumer(),
            self.config.ring_size,
        )
        .map_err(|error| self.invalid(error))?;
        if !self.tx_chain_credit(class, count, used) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "whole TX chain unavailable",
            ));
        }
        if self.sidecar.free == NO_TX_OWNER {
            return Err(io::Error::other("no TX sidecar"));
        }
        let mut leases = [None; MAX_SEGMENTS];
        for index in 0..count {
            match self.ledger.reserve_tx(class) {
                Ok(lease) => leases[index] = Some(lease),
                Err(error) => {
                    for lease in leases[..index].iter_mut() {
                        self.ledger
                            .cancel_tx(lease.take().expect("reserved chain"))
                            .map_err(io::Error::other)?;
                    }
                    return Err(io::Error::other(error));
                }
            }
        }
        let materialized = (|| {
            let mut chunks: [&mut [u8]; MAX_SEGMENTS] =
                std::array::from_fn(|_| &mut [] as &mut [u8]);
            for index in 0..count {
                let bytes = (wire_length - index * FRAME_SIZE).min(FRAME_SIZE);
                let address = leases[index].expect("reserved chain").address();
                let pointer = self.umem.frame_pointer(address, bytes)?;
                // SAFETY: distinct reserved ledger leases identify nonoverlapping TX chunks;
                // no descriptor is published and RX occupies a disjoint UMEM partition.
                let chunk = unsafe { std::slice::from_raw_parts_mut(pointer, bytes) };
                let packet_bytes = (length - index * FRAME_SIZE).min(bytes);
                chunk[packet_bytes..].fill(0);
                chunks[index] = &mut chunk[..packet_bytes];
            }
            writer(&retained, &mut chunks[..count])
        })();
        if let Err(error) = materialized {
            for lease in leases[..count].iter_mut().filter_map(Option::take) {
                self.ledger.cancel_tx(lease).map_err(io::Error::other)?;
            }
            return Err(error);
        }
        let owner = self.sidecar.occupy(retained, count as u8);
        for (index, lease) in leases[..count].iter_mut().enumerate() {
            let bytes = (wire_length - index * FRAME_SIZE).min(FRAME_SIZE);
            let address = self
                .ledger
                .submit_tx(lease.take().expect("reserved chain"), bytes, owner)
                .map_err(io::Error::other)
                .map_err(|error| self.invalid(error))?;
            self.rings.tx.write(
                self.tx_producer.wrapping_add(index as u32),
                Descriptor {
                    addr: address,
                    len: bytes as u32,
                    options: u32::from(index + 1 < count),
                },
            );
        }
        self.tx_free[class_index(class)] -= count;
        self.tx_producer = self.tx_producer.wrapping_add(count as u32);
        self.counters.submitted += count as u64;
        self.rings.tx.publish_producer(self.tx_producer);
        self.counters.published();
        if self.tx_batch_active {
            Ok(())
        } else {
            self.kick_tx()
        }
    }

    /// Generate one complete L2 packet directly in an unpublished UMEM frame.
    /// Resource shortage returns WouldBlock without calling `generate`; None publishes nothing.
    /// Only the returned actual extent (with minimum Ethernet padding) is submitted.
    /// The callback receives exactly `max_length` bytes and must return 14..=max_length.
    /// None, errors and panics cancel unpublished storage, without I/O.
    /// A kick error after publication still retains the submitted packet and its owner.
    pub fn transmit_generated(
        &mut self,
        class: TxClass,
        max_length: usize,
        generate: impl FnOnce(&mut [u8]) -> io::Result<Option<(usize, L)>>,
    ) -> io::Result<bool> {
        let (padded_max, count) = self.tx_packet_layout(max_length)?;
        if count != 1 {
            return Err(invalid_config("generated TX must fit one UMEM frame"));
        }
        let prepared = self.reserve_single_tx(class)?;
        let address = prepared.lease.address();
        let mut reservation = TxReservation {
            port: self,
            prepared: Some(prepared),
        };
        let pointer = reservation
            .port
            .umem
            .frame_pointer(address, padded_max)
            .map_err(|error| reservation.port.invalid(error))?;
        // SAFETY: this checked extent belongs to the sole unpublished TX reservation,
        // disjoint from RX and outstanding TX. The borrow ends before submission.
        let frame = unsafe { std::slice::from_raw_parts_mut(pointer, padded_max) };
        let Some((actual_length, retained)) = generate(&mut frame[..max_length])? else {
            return Ok(false);
        };
        if !(14..=max_length).contains(&actual_length) {
            return Err(invalid_config("invalid generated TX packet extent"));
        }
        let (wire_length, _) = reservation.port.tx_packet_layout(actual_length)?;
        frame[actual_length..wire_length].fill(0);
        reservation.prepared.as_mut().expect("reserved TX").length = wire_length as u32;
        reservation.publish(retained)?;
        Ok(true)
    }

    pub fn zerocopy(&self) -> bool {
        self.zerocopy
    }

    pub fn config(&self) -> PortConfig {
        self.config
    }

    pub fn umem_bytes(&self) -> usize {
        self.umem.bytes()
    }

    fn invalid(&mut self, error: io::Error) -> io::Error {
        self.counters.invalid += 1;
        self.close();
        error
    }

    pub fn observe_fill(&mut self) -> io::Result<usize> {
        let consumer = self.rings.fill.consumer();
        let count = ring::distance(consumer, self.fill_consumer, self.config.ring_size)
            .map_err(|error| self.invalid(error))?;
        ring::distance(self.fill_producer, consumer, self.config.ring_size)
            .map_err(|error| self.invalid(error))?;
        self.ledger
            .consume_fill(count as usize)
            .map_err(io::Error::other)
            .map_err(|error| self.invalid(error))?;
        self.fill_consumer = consumer;
        Ok(count as usize)
    }

    pub fn refill(&mut self) -> io::Result<usize> {
        self.observe_fill()?;
        if self.closed.get() {
            return Ok(0);
        }
        let used = ring::distance(
            self.fill_producer,
            self.fill_consumer,
            self.config.ring_size,
        )
        .map_err(|error| self.invalid(error))?;
        let mut count = 0;
        for _ in used..self.config.ring_size {
            let lease = match self.ledger.reserve_fill() {
                Ok(lease) => lease,
                Err(LedgerError::NoFrame | LedgerError::NoFillCredit) => break,
                Err(error) => {
                    self.rings.fill.publish_producer(self.fill_producer);
                    return Err(self.invalid(io::Error::other(error)));
                }
            };
            let address = match self.ledger.submit_fill(lease) {
                Ok(address) => address,
                Err(error) => {
                    self.rings.fill.publish_producer(self.fill_producer);
                    return Err(self.invalid(io::Error::other(error)));
                }
            };
            self.rings.fill.write(self.fill_producer, address);
            self.fill_producer = self.fill_producer.wrapping_add(1);
            self.counters.fill += 1;
            count += 1;
        }
        self.rings.fill.publish_producer(self.fill_producer);
        self.kick_rx()?;
        Ok(count)
    }

    /// Borrow single-buffer packets, recycling their frames after the callback returns.
    /// `Ok(0)` may leave RX queued pending FILL consumer publication; callers must retry later.
    pub fn receive(&mut self, batch: usize, mut f: impl FnMut(&[u8])) -> io::Result<usize> {
        self.receive_segments_inner(batch, 0, false, |_, segments, _, _| {
            f(segments[0]);
            RxDisposition::Release
        })
    }

    pub fn tx_credit(&self, class: TxClass) -> bool {
        self.tx_packet_credit(class, 60)
    }

    /// Check the entire packet before taking its output owner; one task owns every mutation.
    pub fn tx_packet_credit(&self, class: TxClass, length: usize) -> bool {
        let Ok((_, count)) = self.tx_packet_layout(length) else {
            return false;
        };
        ring::distance(
            self.tx_producer,
            self.rings.tx.consumer(),
            self.config.ring_size,
        )
        .is_ok_and(|used| self.tx_chain_credit(class, count, used))
    }

    /// Conservative packet count for this port's largest admitted Ethernet frame.
    /// A zero count can still leave credit for one shorter packet.
    pub fn tx_packet_capacity(&mut self, class: TxClass) -> io::Result<usize> {
        let (_, count) = self.tx_packet_layout(self.mtu as usize + 22)?;
        let used = ring::distance(
            self.tx_producer,
            self.rings.tx.consumer(),
            self.config.ring_size,
        )
        .map_err(|error| self.invalid(error))?;
        Ok(if self.closed.get() {
            0
        } else {
            self.tx_free[class_index(class)].min(self.config.ring_size as usize - used as usize)
                / count
        })
    }

    fn tx_packet_layout(&self, length: usize) -> io::Result<(usize, usize)> {
        if length < 14 || length > self.mtu as usize + 22 {
            return Err(invalid_config("invalid TX packet extent"));
        }
        let wire_length = length.max(60);
        let count = wire_length.div_ceil(FRAME_SIZE);
        if count > MAX_SEGMENTS || (count > 1 && !self.scatter_gather) {
            return Err(invalid_config("TX requires negotiated scatter/gather"));
        }
        Ok((wire_length, count))
    }

    fn tx_chain_credit(&self, class: TxClass, count: usize, used: u32) -> bool {
        !self.closed.get()
            && self.tx_free[class_index(class)] >= count
            && self.config.ring_size as usize - used as usize >= count
    }

    fn reserve_single_tx(&mut self, class: TxClass) -> io::Result<PreparedTx> {
        let used = ring::distance(
            self.tx_producer,
            self.rings.tx.consumer(),
            self.config.ring_size,
        )
        .map_err(|error| self.invalid(error))?;
        let blocked = || io::Error::new(io::ErrorKind::WouldBlock, "single TX frame unavailable");
        if !self.tx_chain_credit(class, 1, used) || self.sidecar.free == NO_TX_OWNER {
            return Err(blocked());
        }
        let lease = match self.ledger.reserve_tx(class) {
            Ok(lease) => lease,
            Err(LedgerError::NoFrame | LedgerError::NoDescriptor) => return Err(blocked()),
            Err(error) => return Err(self.invalid(io::Error::other(error))),
        };
        Ok(PreparedTx {
            lease,
            length: 0,
            class,
        })
    }

    fn prepare_tx(
        &mut self,
        class: TxClass,
        header: &[u8; 14],
        l3: &[u8],
    ) -> io::Result<PreparedTx> {
        if header.len().checked_add(l3.len()).is_none_or(|n| n > 1514) {
            return Err(invalid_config("TX frame exceeds Ethernet MTU 1500"));
        }
        let prepared = self.reserve_single_tx(class)?;
        let address = prepared.lease.address();
        let mut reservation = TxReservation {
            port: self,
            prepared: Some(prepared),
        };
        let length = reservation
            .port
            .umem
            .write_frame(address, header, l3)
            .map_err(|error| reservation.port.invalid(error))?;
        reservation.prepared.as_mut().expect("reserved TX").length = length;
        Ok(reservation.prepared.take().expect("prepared TX"))
    }

    fn publish_tx(&mut self, prepared: PreparedTx, retained: L) -> io::Result<()> {
        let owner = self.sidecar.occupy(retained, 1);
        let address = self
            .ledger
            .submit_tx(prepared.lease, prepared.length as usize, owner)
            .map_err(io::Error::other)
            .map_err(|error| self.invalid(error))?;
        self.rings.tx.write(
            self.tx_producer,
            Descriptor {
                addr: address,
                len: prepared.length,
                options: 0,
            },
        );
        self.tx_producer = self.tx_producer.wrapping_add(1);
        self.tx_free[class_index(prepared.class)] -= 1;
        self.counters.submitted += 1;
        self.rings.tx.publish_producer(self.tx_producer);
        self.counters.published();
        if self.tx_batch_active {
            Ok(())
        } else {
            self.kick_tx()
        }
    }

    pub fn transmit(
        &mut self,
        class: TxClass,
        header: &[u8; 14],
        l3: &[u8],
        retained: L,
    ) -> io::Result<()> {
        let prepared = self.prepare_tx(class, header, l3)?;
        self.publish_tx(prepared, retained)
    }

    /// Borrow the packet before moving its owner into the same preallocated TX sidecar.
    pub fn transmit_retained(
        &mut self,
        class: TxClass,
        header: &[u8; 14],
        retained: L,
    ) -> io::Result<()>
    where
        L: AsRef<[u8]>,
    {
        let prepared = self.prepare_tx(class, header, retained.as_ref())?;
        self.publish_tx(prepared, retained)
    }

    /// Lend only owners whose final descriptor returned; sidecars are dropped afterward.
    /// A later invalid CQ still commits and releases the validated prefix.
    pub fn complete(&mut self, release: impl FnOnce(&mut [Option<&mut L>])) -> io::Result<usize> {
        ring::distance(
            self.tx_producer,
            self.rings.tx.consumer(),
            self.config.ring_size,
        )
        .map_err(|error| self.invalid(error))?;
        let producer = self.rings.cq.producer();
        let count = ring::distance(producer, self.cq_consumer, self.config.ring_size)
            .map_err(|error| self.invalid(error))?
            .min(64);
        let mut indices = [0; 64];
        let mut owners = 0;
        let mut completed = 0;
        let mut failure = None;
        for _ in 0..count {
            let address = self.rings.cq.read(self.cq_consumer);
            let owner = match self.ledger.complete_tx(address) {
                Ok(owner) => owner,
                Err(error) => {
                    failure = Some(self.invalid(io::Error::other(error)));
                    break;
                }
            };
            let Some(TxOwnerSlot::Occupied { remaining, .. }) =
                self.sidecar.slots.get_mut(owner as usize)
            else {
                failure =
                    Some(self.invalid(io::Error::other("CQ owner has no retained TX sidecar")));
                break;
            };
            *remaining -= 1;
            if *remaining == 0 {
                indices[owners] = owner;
                owners += 1;
            }
            let slot = address as usize / FRAME_SIZE - self.config.rx_frames;
            self.tx_free[usize::from(slot >= self.config.control_frames)] += 1;
            self.cq_consumer = self.cq_consumer.wrapping_add(1);
            self.counters.completed += 1;
            completed += 1;
        }
        self.rings.cq.publish_consumer(self.cq_consumer);
        let indices = &mut indices[..owners];
        indices.sort_unstable();
        let cleanup = CompletedOwners {
            sidecar: &mut self.sidecar,
            indices,
        };
        {
            let mut outputs: [Option<&mut L>; 64] = std::array::from_fn(|_| None);
            let mut slots = &mut *cleanup.sidecar.slots;
            let mut start = 0;
            for (output, &index) in outputs.iter_mut().zip(cleanup.indices) {
                let index = index as usize;
                let (_, suffix) = slots.split_at_mut(index - start);
                let (slot, suffix) = suffix.split_first_mut().expect("completed sidecar index");
                let TxOwnerSlot::Occupied { retained, .. } = slot else {
                    unreachable!("completed TX sidecar");
                };
                *output = Some(retained);
                slots = suffix;
                start = index + 1;
            }
            release(&mut outputs[..owners]);
        }
        drop(cleanup);
        match failure {
            Some(error) => Err(error),
            None => Ok(completed),
        }
    }

    fn wakeup_result(&mut self, result: io::Result<()>) -> io::Result<()> {
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                self.counters.wakeup_errors += 1;
                match error.raw_os_error() {
                    Some(libc::EAGAIN | libc::EBUSY | libc::ENOBUFS | libc::EINTR) => Ok(()),
                    _ => {
                        self.close();
                        Err(error)
                    }
                }
            }
        }
    }

    fn kick_rx(&mut self) -> io::Result<()> {
        if !self.rings.fill.needs_wakeup() {
            return Ok(());
        }
        self.counters.rx_kicks += 1;
        let result = self
            .socket
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
            .and_then(|fd| ring::kick_rx(fd.as_fd()));
        self.wakeup_result(result)
    }

    fn kick_tx(&mut self) -> io::Result<()> {
        if !self.rings.tx.needs_wakeup() {
            return Ok(());
        }
        self.counters.tx_kicks += 1;
        let result = self
            .socket
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
            .and_then(|fd| ring::kick_tx(fd.as_fd()));
        self.wakeup_result(result)
    }

    /// Reinspect both NEED_WAKEUP flags even when no new descriptors were published.
    pub fn kick(&mut self) -> io::Result<()> {
        let rx = self.kick_rx();
        let tx = self.kick_tx();
        rx.and(tx)
    }

    /// Service only TX NEED_WAKEUP after consuming available CQ entries.
    /// Published descriptors awaiting completion remain eligible after [`Self::close`].
    pub fn kick_outstanding_tx(&mut self) -> io::Result<()> {
        if self.counters.submitted == self.counters.completed {
            return Ok(());
        }
        self.kick_tx()
    }

    pub fn outstanding(&self) -> impl Iterator<Item = OutstandingTx<u32>> + '_ {
        self.ledger.outstanding_tx()
    }

    pub fn drain_state(&self) -> DrainState {
        let mut state = self.ledger.drain_state();
        state.closed |= self.closed.get();
        state.rx_completions = self.retained_rx.completions;
        state
    }

    pub fn close(&mut self) -> DrainState {
        self.closed.set(true);
        self.ledger.close();
        self.drain_state()
    }

    pub fn counters(&self) -> PortCounters {
        self.counters
    }

    /// RX was published after this owner last consumed the ring.
    pub fn has_pending_rx(&self) -> bool {
        self.rings.rx.producer() != self.rx_consumer
    }

    /// Retry published TX/CQ work or RX blocked by a partial chain/FILL visibility.
    /// A populated FILL ring without queued RX is an ordinary idle receive reservation.
    pub fn needs_service_retry(&self) -> bool {
        self.counters.submitted != self.counters.completed
            || self.tx_producer != self.rings.tx.consumer()
            || self.has_pending_rx()
    }

    pub fn stats(&self) -> io::Result<SocketStats> {
        self.socket
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
            .and_then(|fd| ring::stats(fd.as_fd()))
    }

    pub fn rings(&self) -> RingSnapshot {
        self.rings.snapshot()
    }

    /// Close only the socket. This does not unmap/refund UMEM or dispose outstanding TX.
    pub fn close_socket(&mut self) {
        self.socket.take();
    }
}

impl<L> AsFd for Port<L> {
    /// Panics after close_socket; AsRawFd instead returns -1 for a closed socket.
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket
            .as_ref()
            .expect("AF_XDP socket is closed")
            .as_fd()
    }
}

impl<L> AsRawFd for Port<L> {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }
}

/// TX-only access during a borrowed receive callback; never releases or mutates RX storage.
pub struct TxSink<'a, L> {
    port: &'a mut Port<L>,
}

impl<L> TxSink<'_, L> {
    pub fn tx_credit(&self, class: TxClass) -> bool {
        self.port.tx_credit(class)
    }

    pub fn tx_packet_credit(&self, class: TxClass, length: usize) -> bool {
        self.port.tx_packet_credit(class, length)
    }

    pub fn transmit_segments(
        &mut self,
        class: TxClass,
        segments: &[&[u8]],
        retained: L,
    ) -> io::Result<()> {
        self.port.transmit_segments(class, segments, retained)
    }

    pub fn transmit_with(
        &mut self,
        class: TxClass,
        length: usize,
        retained: L,
        writer: impl FnOnce(&L, &mut [&mut [u8]]) -> io::Result<()>,
    ) -> io::Result<()> {
        self.port.transmit_with(class, length, retained, writer)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn config() -> PortConfig {
        PortConfig {
            rx_frames: 2,
            control_frames: 1,
            bulk_frames: 1,
            ring_size: 4,
        }
    }

    fn fake<L>(config: PortConfig, budget: &Arc<MemoryBudget>) -> Port<L> {
        config.validate().unwrap();
        let bookkeeping =
            reserve(budget, size_of::<Port<L>>() - size_of::<FrameLedger<u32>>()).unwrap();
        let retained_rx = RetainedRxSlots::new(config, budget).unwrap();
        Port {
            socket: None,
            config,
            zerocopy: false,
            mtu: 1500,
            scatter_gather: false,
            metadata_len: METADATA_SIZE,
            umem: Umem::fake(config.umem_bytes().unwrap(), budget),
            rings: Rings::fake(config.ring_size, budget),
            ledger: ManuallyDrop::new(FrameLedger::new(config.frame_config(), budget).unwrap()),
            retained_rx,
            sidecar: Sidecar::new(config, budget).unwrap(),
            rx_consumer: 0,
            tx_producer: 0,
            fill_producer: 0,
            fill_consumer: 0,
            cq_consumer: 0,
            tx_free: [config.control_frames, config.bulk_frames],
            closed: Cell::new(false),
            tx_batch_active: false,
            counters: PortCounters::default(),
            _bookkeeping: Some(bookkeeping),
        }
    }

    fn queue_rx(port: &mut Port<()>, lengths: &[usize], metadata_len: usize) {
        let producer = stage_rx(port, lengths, metadata_len);
        port.rings.rx.publish_producer(producer);
    }

    fn stage_rx(port: &mut Port<()>, lengths: &[usize], metadata_len: usize) -> u32 {
        let fill = port.rings.fill.consumer();
        let rx = port.rings.rx.producer();
        for (part, &length) in lengths.iter().enumerate() {
            let address =
                port.rings.fill.read(fill.wrapping_add(part as u32)) + 256 + metadata_len as u64;
            if part == 0 && metadata_len != 0 {
                port.umem
                    .write_bytes(address - metadata_len as u64, &[0xa5; 128][..metadata_len]);
            }
            port.umem
                .write_bytes(address, &[(part + 1) as u8; FRAME_SIZE][..length]);
            port.rings.rx.write(
                rx.wrapping_add(part as u32),
                Descriptor {
                    addr: address,
                    len: length as u32,
                    options: u32::from(part + 1 != lengths.len()),
                },
            );
        }
        port.rings
            .fill
            .publish_consumer(fill.wrapping_add(lengths.len() as u32));
        rx.wrapping_add(lengths.len() as u32)
    }

    fn retain_rx(port: &mut Port<()>, metadata_len: usize) -> RetainedRxHandle {
        let mut handle = None;
        assert_eq!(
            port.receive_segments_owned(1, metadata_len, |owned, _, _, tx| {
                assert_eq!(tx.port.retained_rx_count(), 1);
                handle = Some(owned);
                RxDisposition::Retain
            })
            .unwrap(),
            1
        );
        handle.unwrap()
    }

    #[test]
    fn retained_rx_whole_chain_credit_precedes_first_lease() {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(
            PortConfig {
                rx_frames: 4,
                control_frames: 4,
                bulk_frames: 4,
                ring_size: 8,
            },
            &budget,
        );
        let mut frames = port.config.frame_config();
        frames.rx_capacity = 2;
        // SAFETY: this fixture has not posted frames or acquired any leases.
        unsafe { ManuallyDrop::drop(&mut port.ledger) };
        port.ledger = ManuallyDrop::new(FrameLedger::new(frames, &budget).unwrap());
        port.mtu = 9000;
        port.scatter_gather = true;
        port.metadata_len = 64;
        port.refill().unwrap();
        queue_rx(&mut port, &[60], 64);
        let first = retain_rx(&mut port, 64);
        queue_rx(&mut port, &[3000, 3000], 64);
        let consumer = port.rings().rx_consumer;
        let fill = port.rings().fill_producer;
        let free = port.retained_rx.free;
        assert_eq!(port.ledger.rx_credit(), 1);
        assert_eq!(
            port.receive_segments(1, 64, |_, _| panic!("half-leased borrowed RX chain"))
                .unwrap(),
            0
        );
        assert_eq!(
            port.receive_segments_owned(1, 64, |_, _, _, _| { panic!("half-leased RX chain") })
                .unwrap(),
            0
        );
        assert_eq!(port.rings().rx_consumer, consumer);
        assert_eq!(port.rings().fill_producer, fill);
        assert_eq!(port.drain_state().rx_leased, 1);
        assert_eq!(port.retained_rx.free, free);
        assert!(!port.drain_state().closed);
        let first_done = port.release_retained_rx(first).unwrap();
        assert_eq!(port.rx_completion_count(), 1);
        let second = retain_rx(&mut port, 64);
        assert_ne!(first.slot, second.slot);
        assert_eq!(port.drain_state().rx_leased, 2);
        port.with_retained_rx(second, |parts, metadata| {
            assert_eq!(parts, &[&[1; 3000][..], &[2; 3000][..]]);
            assert_eq!(metadata, &[0xa5; 64]);
        })
        .unwrap();
        let second_done = port.release_retained_rx(second).unwrap();
        port.complete_retained_rx(second_done).unwrap();
        port.complete_retained_rx(first_done).unwrap();

        let mut port = fake::<()>(config(), &budget);
        port.scatter_gather = true;
        port.refill().unwrap();
        let mut completions = Vec::new();
        for _ in 0..2 {
            queue_rx(&mut port, &[60], 0);
            let handle = retain_rx(&mut port, 0);
            completions.push(port.release_retained_rx(handle).unwrap());
        }
        assert_eq!(port.retained_rx.free, NO_RX_SLOT);
        assert_eq!(port.ledger.rx_credit(), 2);
        queue_rx(&mut port, &[60, 60], 0);
        let consumer = port.rings().rx_consumer;
        assert_eq!(
            port.receive_segments_owned(1, 0, |_, _, _, _| panic!("slot full"))
                .unwrap(),
            0
        );
        assert_eq!(port.rings().rx_consumer, consumer);
        assert_eq!(port.drain_state().rx_leased, 0);
        assert_eq!(port.rx_completion_count(), 2);
        port.complete_retained_rx(completions.pop().unwrap())
            .unwrap();
        let handle = retain_rx(&mut port, 0);
        let done = port.release_retained_rx(handle).unwrap();
        queue_rx(&mut port, &[60, 60], 0);
        assert_eq!(
            port.receive_segments(1, 0, |parts, _| assert_eq!(parts.len(), 2))
                .unwrap(),
            1
        );
        assert_eq!(port.rx_completion_count(), 2);
        assert_eq!(port.retained_rx.free, NO_RX_SLOT);
        port.complete_retained_rx(done).unwrap();
        port.complete_retained_rx(completions.pop().unwrap())
            .unwrap();

        let mut port = fake::<()>(
            PortConfig {
                rx_frames: 4,
                control_frames: 2,
                bulk_frames: 2,
                ring_size: 4,
            },
            &budget,
        );
        port.scatter_gather = true;
        port.refill().unwrap();
        queue_rx(&mut port, &[60; 4], 0);
        for index in 0..4 {
            let mut descriptor = port.rings.rx.read(index);
            descriptor.options = u32::from(index == 3);
            port.rings.rx.write(index, descriptor);
        }
        assert_eq!(
            port.receive_segments_owned(4, 0, |_, _, _, _| RxDisposition::Release)
                .unwrap(),
            3
        );
        assert_eq!(port.rings().rx_consumer, 3);
        assert_eq!(port.drain_state().rx_leased, 0);
        assert!(!port.drain_state().closed);
        queue_rx(&mut port, &[60], 0);
        assert_eq!(
            port.receive_segments_owned(1, 0, |_, parts, _, _| {
                assert_eq!(parts.len(), 2);
                RxDisposition::Release
            })
            .unwrap(),
            1
        );
        assert_eq!(port.rings().rx_consumer, 5);
    }

    #[test]
    fn retained_rx_generation_survives_completion_and_callback_panic() {
        for panic_on_borrow in [false, true] {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(config(), &budget);
            port.mtu = 9000;
            port.scatter_gather = true;
            port.metadata_len = 64;
            port.refill().unwrap();
            queue_rx(&mut port, &[3000, 3000], 64);
            let fill = port.rings().fill_producer;
            let mut handle = None;
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                port.receive_segments_owned(1, 64, |owned, parts, metadata, tx| {
                    handle = Some(owned);
                    assert_eq!(tx.port.retained_rx_count(), 1);
                    assert_eq!(tx.port.drain_state().rx_leased, 2);
                    assert_eq!(parts.len(), 2);
                    assert_eq!(metadata, &[0xa5; 64]);
                    if !panic_on_borrow {
                        panic!("RX callback unwind");
                    }
                    RxDisposition::Retain
                })
                .unwrap();
                port.with_retained_rx(handle.unwrap(), |_, _| panic!("writev unwind"))
                    .unwrap();
            }));
            assert!(panic.is_err());
            let handle = handle.unwrap();
            assert!(port.drain_state().closed);
            assert!(!port.tx_credit(TxClass::Bulk));
            assert_eq!(port.rings().rx_consumer, 2);
            assert_eq!(port.rings().fill_producer, fill);
            assert_eq!(port.retained_rx_count(), 1);
            assert_eq!(port.rx_completion_count(), 0);
            port.with_retained_rx(handle, |parts, metadata| {
                assert_eq!(parts, &[&[1; 3000][..], &[2; 3000][..]]);
                assert_eq!(metadata, &[0xa5; 64]);
            })
            .unwrap();
            let completion = port.release_retained_rx(handle).unwrap();
            assert_eq!(completion.handle(), handle);
            assert_eq!(port.retained_rx_count(), 0);
            assert_eq!(port.rx_completion_count(), 1);
            assert_eq!(port.drain_state().rx_leased, 0);
            assert!(!port.close().ready_for_backend_teardown());
            drop(completion);
            let retained = port.umem_bytes()
                + port.ledger.charged_bytes()
                + port.retained_rx.reservation.as_ref().unwrap().bytes()
                + port._bookkeeping.as_ref().unwrap().bytes();
            drop(port);
            assert_eq!(budget.used(), retained);
        }
        {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(config(), &budget);
            port.refill().unwrap();
            queue_rx(&mut port, &[60], 32);
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                port.receive(1, |_| panic!("single-buffer RX unwind"))
                    .unwrap();
            }));
            assert!(panic.is_err());
            assert!(port.drain_state().closed);
            assert_eq!(port.retained_rx_count(), 1);
            assert_eq!(port.drain_state().rx_leased, 1);
            assert_eq!(port.rings().rx_consumer, 1);
            assert_eq!(port.rings().fill_producer, 2);
            assert!(!port.close().ready_for_backend_teardown());
        }

        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.refill().unwrap();
        queue_rx(&mut port, &[60], 0);
        let handle = retain_rx(&mut port, 0);
        port.rings.fill.set_wakeup();
        assert_eq!(
            port.release_retained_rx(handle).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
        assert_eq!(port.retained_rx_count(), 0);
        assert_eq!(port.rx_completion_count(), 1);
        assert!(!port.close().ready_for_backend_teardown());
        assert_eq!(
            port.release_retained_rx(handle).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        for invalid in ["borrow", "release", "completion"] {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(config(), &budget);
            port.refill().unwrap();
            queue_rx(&mut port, &[60], 0);
            let first = retain_rx(&mut port, 0);
            let first_done = port.release_retained_rx(first).unwrap();
            assert_eq!(first_done.handle(), first);
            queue_rx(&mut port, &[60], 0);
            let second = retain_rx(&mut port, 0);
            assert_ne!(first.slot, second.slot);
            let second_done = port.release_retained_rx(second).unwrap();
            port.complete_retained_rx(second_done).unwrap();
            port.complete_retained_rx(first_done).unwrap();
            queue_rx(&mut port, &[60], 0);
            let current = retain_rx(&mut port, 0);
            assert_eq!(current.slot, first.slot);
            assert_ne!(current, first);
            assert_eq!(
                current.receipt_identity(),
                RetainedRxIdentity {
                    port: current.port,
                    port_generation: current.port_generation,
                    slot: current.slot,
                    slot_generation: current.generation,
                }
            );
            let pending = if invalid == "completion" {
                Some(port.release_retained_rx(current).unwrap())
            } else {
                None
            };
            let error = match invalid {
                "borrow" => port
                    .with_retained_rx(first, |_, _| panic!("stale borrow"))
                    .unwrap_err(),
                "release" => port.release_retained_rx(first).unwrap_err(),
                "completion" => port
                    .complete_retained_rx(RxCompletion { handle: first })
                    .unwrap_err(),
                _ => unreachable!(),
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(port.drain_state().closed);
            assert_eq!(port.retained_rx_count(), usize::from(pending.is_none()));
            assert_eq!(port.drain_state().rx_leased, usize::from(pending.is_none()));
            let completion = pending.unwrap_or_else(|| port.release_retained_rx(current).unwrap());
            assert_eq!(
                port.release_retained_rx(current).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(port.rx_completion_count(), 1);
            port.complete_retained_rx(completion).unwrap();
            assert_eq!(port.rx_completion_count(), 0);
            assert!(port.close().ready_for_backend_teardown());
        }

        for operation in ["borrow", "release", "completion"] {
            for identity in ["port", "port-generation"] {
                let budget = MemoryBudget::new(1 << 20);
                let mut port = fake::<()>(config(), &budget);
                let mut foreign = fake::<()>(config(), &budget);
                port.refill().unwrap();
                foreign.refill().unwrap();
                queue_rx(&mut port, &[60], 0);
                queue_rx(&mut foreign, &[60], 0);
                let source = retain_rx(&mut port, 0);
                let destination = retain_rx(&mut foreign, 0);
                assert_eq!(source.slot, destination.slot);
                assert_eq!(source.generation, destination.generation);
                assert_eq!(source.port_generation, destination.port_generation);
                assert_ne!(source.port, destination.port);
                let token = if identity == "port" {
                    source
                } else {
                    RetainedRxHandle {
                        port_generation: destination.port_generation + 1,
                        ..destination
                    }
                };
                let completions = if operation == "completion" {
                    Some((
                        port.release_retained_rx(source).unwrap(),
                        foreign.release_retained_rx(destination).unwrap(),
                    ))
                } else {
                    None
                };
                let phase = if completions.is_some() {
                    RxPhase::CompletionPending
                } else {
                    RxPhase::Held
                };
                assert!(port.retained_rx.slots[source.slot as usize].phase == phase);
                assert!(foreign.retained_rx.slots[destination.slot as usize].phase == phase);
                let error = match operation {
                    "borrow" => foreign.with_retained_rx(token, |_, _| ()).unwrap_err(),
                    "release" => foreign.release_retained_rx(token).unwrap_err(),
                    "completion" => foreign
                        .complete_retained_rx(RxCompletion { handle: token })
                        .unwrap_err(),
                    _ => unreachable!(),
                };
                assert_eq!(
                    error.kind(),
                    io::ErrorKind::InvalidData,
                    "{operation}/{identity}"
                );
                assert!(foreign.drain_state().closed);
                assert!(foreign.retained_rx.slots[destination.slot as usize].phase == phase);
                let (source_done, destination_done) = completions.unwrap_or_else(|| {
                    (
                        port.release_retained_rx(source).unwrap(),
                        foreign.release_retained_rx(destination).unwrap(),
                    )
                });
                port.complete_retained_rx(source_done).unwrap();
                foreign.complete_retained_rx(destination_done).unwrap();
                assert!(port.close().ready_for_backend_teardown());
                assert!(foreign.close().ready_for_backend_teardown());
            }
        }

        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.retained_rx.slots[0].generation = u64::MAX;
        port.refill().unwrap();
        queue_rx(&mut port, &[60], 0);
        assert_eq!(
            port.receive_segments_owned(1, 0, |_, _, _, _| panic!("wrapped slot generation"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(port.rings().rx_consumer, 0);
        assert_eq!(port.drain_state().rx_leased, 0);
        assert_eq!(port.retained_rx.slots[0].generation, u64::MAX);
        assert!(port.drain_state().closed);
    }

    #[test]
    fn retained_rx_reserves_layout_before_umem() {
        for (rx_frames, ring_size) in [(2, 4), (256, 512), (512, 256)] {
            let config = PortConfig {
                rx_frames,
                ring_size,
                control_frames: 1,
                bulk_frames: 1,
            };
            let count = rx_frames.min(ring_size as usize);
            let bytes = count * 1024;
            assert_eq!(RetainedRxSlots::layout(config).unwrap(), (count, bytes));
            let layout = Layout::array::<RetainedRxSlot>(count).unwrap();
            assert!(layout.size() <= bytes);
            assert_eq!(layout.align(), align_of::<RetainedRxSlot>());
            assert!(size_of::<RetainedRxHandle>() <= 32);
            assert!(size_of::<RxCompletion>() <= 32);
            let budget = MemoryBudget::new(bytes - 1);
            assert_eq!(
                RetainedRxSlots::new(config, &budget).err().unwrap().kind(),
                io::ErrorKind::OutOfMemory
            );
            assert_eq!(budget.used(), 0);
            let budget = MemoryBudget::new(bytes);
            let slots = RetainedRxSlots::new(config, &budget).unwrap();
            assert_eq!(slots.slots.len(), count);
            assert_eq!(budget.used(), bytes);
            assert_eq!(slots.slots.as_ptr() as usize % layout.align(), 0);
            drop(slots);
            assert_eq!(budget.used(), 0);
        }
        // SAFETY: the name is a static NUL-terminated string.
        let ifindex = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        assert_ne!(ifindex, 0);
        let bytes = size_of::<Port<()>>() - size_of::<FrameLedger<u32>>() + 2 * 1024 - 1;
        let budget = MemoryBudget::new(bytes);
        assert_eq!(
            Port::<()>::open_device(
                ifindex,
                0,
                BindMode::Copy,
                config(),
                1500,
                false,
                64,
                &budget
            )
            .err()
            .unwrap()
            .kind(),
            io::ErrorKind::OutOfMemory
        );
        assert_eq!(budget.used(), 0);
        assert!(
            PortConfig {
                rx_frames: usize::MAX,
                ..config()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn native_metadata64_sg_capacity_rejects_48() {
        assert_eq!(rx_frame_capacity(64).unwrap(), 3776);
        assert_eq!(
            rx_frame_capacity(48).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            (65535usize + 22).div_ceil(rx_frame_capacity(64).unwrap()),
            MAX_SEGMENTS
        );
        let budget = MemoryBudget::new(1 << 20);
        let config = PortConfig {
            rx_frames: 32,
            control_frames: 18,
            bulk_frames: 18,
            ring_size: 64,
        };
        let mut port = fake::<()>(config, &budget);
        port.mtu = 65535;
        port.scatter_gather = true;
        port.metadata_len = 64;
        port.refill().unwrap();
        let mut lengths = [3776; MAX_SEGMENTS];
        lengths[MAX_SEGMENTS - 1] = 65535 + 22 - 3776 * (MAX_SEGMENTS - 1);
        queue_rx(&mut port, &lengths, 64);
        assert_eq!(
            port.receive_segments_owned(1, 48, |_, _, _, _| panic!("legacy metadata"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(port.rings().rx_consumer, 0);
        let handle = retain_rx(&mut port, 64);
        port.with_retained_rx(handle, |parts, metadata| {
            assert_eq!(parts.len(), MAX_SEGMENTS);
            assert_eq!(parts.iter().map(|part| part.len()).sum::<usize>(), 65557);
            for (part, bytes) in parts.iter().enumerate() {
                assert_eq!(bytes.len(), lengths[part]);
                assert!(bytes.iter().all(|&byte| byte == (part + 1) as u8));
            }
            assert_eq!(metadata, &[0xa5; 64]);
        })
        .unwrap();
        let completion = port.release_retained_rx(handle).unwrap();
        port.complete_retained_rx(completion).unwrap();

        for malformed in ["metadata", "frame", "mtu", "segments", "duplicate", "sg"] {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(config, &budget);
            port.mtu = 65535;
            port.scatter_gather = true;
            port.metadata_len = 64;
            port.refill().unwrap();
            let lengths = if malformed == "segments" {
                &[60; 19][..]
            } else {
                &[60, 60][..]
            };
            queue_rx(&mut port, lengths, 64);
            let mut first = port.rings.rx.read(0);
            match malformed {
                "metadata" => first.addr = first.addr / FRAME_SIZE as u64 * FRAME_SIZE as u64 + 48,
                "frame" => first.len = 3777,
                "mtu" => {
                    port.mtu = 68;
                    first.len = 60;
                }
                "segments" => {}
                "duplicate" => {
                    let mut second = port.rings.rx.read(1);
                    second.addr = first.addr;
                    port.rings.rx.write(1, second);
                }
                "sg" => port.scatter_gather = false,
                _ => unreachable!(),
            }
            port.rings.rx.write(0, first);
            assert_eq!(
                port.receive_segments_owned(1, 64, |_, _, _, _| panic!("{malformed} admitted"))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(port.rings().rx_consumer, 0);
            assert_eq!(port.drain_state().rx_leased, 0);
            assert_eq!(port.retained_rx_count(), 0);
            assert!(port.drain_state().closed);
        }
    }

    #[test]
    fn packet_count_overflow_never_rolls_back_publication() {
        for writer in [false, true] {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(config(), &budget);
            port.counters.published_packets = u64::MAX;
            if writer {
                port.transmit_with(TxClass::Bulk, 60, (), |_, chunks| {
                    chunks[0].fill(0);
                    Ok(())
                })
                .unwrap();
            } else {
                port.transmit(TxClass::Bulk, &[0; 14], &[0; 28], ())
                    .unwrap();
            }
            assert_eq!(port.rings().tx_producer, 1);
            assert_eq!(port.outstanding().count(), 1);
            assert_eq!(port.counters().submitted, 1);
            assert_eq!(port.counters().published_packets, u64::MAX);
            assert!(port.counters().publication_count_unavailable);
            port.rings.tx.publish_consumer(1);
            port.rings.cq.write(0, port.rings.tx.read(0).addr);
            port.rings.cq.publish_producer(1);
            assert_eq!(port.complete(|_| {}).unwrap(), 1);
            assert!(port.counters().publication_count_unavailable);
            assert!(port.close().ready_for_backend_teardown());
        }
    }

    struct Retained {
        bytes: [u8; 28],
        drops: Arc<AtomicUsize>,
    }

    impl Retained {
        fn new(drops: &Arc<AtomicUsize>) -> Self {
            Self {
                bytes: [7; 28],
                drops: Arc::clone(drops),
            }
        }
    }

    impl AsRef<[u8]> for Retained {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for Retained {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn validates_partitions_ring_commitments_and_umem_extent() {
        assert_eq!(config().umem_bytes().unwrap(), 4 * FRAME_SIZE);
        assert_eq!(BindMode::ZeroCopy.as_str(), "zerocopy");
        assert_eq!(BindMode::Copy.as_str(), "copy");
        for invalid in [
            PortConfig {
                rx_frames: 0,
                ..config()
            },
            PortConfig {
                control_frames: 0,
                ..config()
            },
            PortConfig {
                bulk_frames: 0,
                ..config()
            },
            PortConfig {
                ring_size: 0,
                ..config()
            },
            PortConfig {
                ring_size: 3,
                ..config()
            },
            PortConfig {
                ring_size: 1 << 31,
                ..config()
            },
            PortConfig {
                bulk_frames: 4,
                ..config()
            },
            PortConfig {
                rx_frames: usize::MAX,
                ..config()
            },
        ] {
            assert!(invalid.validate().is_err());
        }
    }

    #[test]
    fn missing_bidirectional_queue_is_refused_before_retaining_umem() {
        // SAFETY: the interface name is a static NUL-terminated string.
        let ifindex = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        assert_ne!(ifindex, 0);
        let budget = MemoryBudget::new(1 << 20);
        assert!(Port::<()>::open(ifindex, u32::MAX, BindMode::Copy, config(), &budget).is_err());
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn exact_metadata_lengths_preserve_whole_sg_callback_leases() {
        for metadata_len in [0, 32, 64, 128] {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(config(), &budget);
            port.metadata_len = metadata_len;
            port.mtu = 9000;
            port.scatter_gather = true;
            port.refill().unwrap();
            let first = port.rings.fill.read(0) + 256;
            let second = port.rings.fill.read(1) + 256;
            let expected = [9; 128];
            if metadata_len != 0 {
                port.umem.write_bytes(first, &expected[..metadata_len]);
            }
            port.umem
                .write_bytes(first + metadata_len as u64, &[1; 3000]);
            port.umem
                .write_bytes(second + metadata_len as u64, &[2; 3000]);
            for (index, address) in [first, second].into_iter().enumerate() {
                port.rings.rx.write(
                    index as u32,
                    Descriptor {
                        addr: address + metadata_len as u64,
                        len: 3000,
                        options: u32::from(index == 0),
                    },
                );
            }
            port.rings.rx.publish_producer(2);
            assert_eq!(
                port.receive_segments(1, metadata_len, |_, _| {
                    panic!("FILL still owns the complete chain")
                })
                .unwrap(),
                0
            );
            port.rings.fill.publish_consumer(2);
            let mut callbacks = 0;
            assert_eq!(
                port.receive_segments_with(1, metadata_len, |parts, metadata, _| {
                    assert_eq!(parts, &[&[1; 3000][..], &[2; 3000][..]]);
                    assert_eq!(metadata, &expected[..metadata_len]);
                    callbacks += 1;
                })
                .unwrap(),
                1
            );
            assert_eq!(callbacks, 1);
            assert_eq!(port.rings().rx_consumer, 2);
            assert_eq!(port.drain_state().rx_leased, 0);
        }
    }

    #[test]
    fn host_metadata_never_falls_back_to_shorter_headroom() {
        for prefix in [0, 32, 127] {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(config(), &budget);
            port.metadata_len = 128;
            port.refill().unwrap();
            let base = port.rings.fill.read(0);
            port.rings.rx.write(
                0,
                Descriptor {
                    addr: base + prefix,
                    len: 3,
                    options: 0,
                },
            );
            port.rings.rx.publish_producer(1);
            port.rings.fill.publish_consumer(1);
            assert!(
                port.receive_segments(1, 128, |_, _| {
                    panic!("missing Host metadata was admitted")
                })
                .is_err()
            );
            assert_eq!(port.rings().rx_consumer, 0);
            assert_eq!(port.drain_state().rx_leased, 0);
            assert!(port.drain_state().closed);
        }
        for (admitted, requested) in [(0, 32), (32, 128), (128, 32), (128, 127)] {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(config(), &budget);
            port.metadata_len = admitted;
            assert_eq!(
                port.receive_segments(1, requested, |_, _| {
                    panic!("wrong metadata contract reached callback")
                })
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(port.rings().rx_consumer, 0);
        }
        for metadata_len in [1, 31, 127, 129, usize::MAX] {
            let budget = MemoryBudget::new(1 << 20);
            assert!(
                Port::<()>::open_device(
                    0,
                    0,
                    BindMode::Copy,
                    config(),
                    1500,
                    false,
                    metadata_len,
                    &budget,
                )
                .is_err()
            );
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn wire_only_receive_neither_requires_nor_exports_a_metadata_prefix() {
        for prefix in [0, METADATA_SIZE] {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(config(), &budget);
            port.refill().unwrap();
            let base = port.rings.fill.read(0);
            if prefix != 0 {
                port.umem.write_bytes(base, &[0xff; METADATA_SIZE]);
            }
            port.umem.write_bytes(base + prefix as u64, &[1, 2, 3]);
            port.rings.rx.write(
                0,
                Descriptor {
                    addr: base + prefix as u64,
                    len: 3,
                    options: 0,
                },
            );
            port.rings.rx.publish_producer(1);
            assert_eq!(
                port.receive_segments(1, 0, |_, _| panic!("FILL still owns the frame"))
                    .unwrap(),
                0
            );
            port.rings.fill.publish_consumer(1);
            assert_eq!(
                port.receive_segments(1, 0, |segments, metadata| {
                    assert_eq!(segments.len(), 1);
                    assert_eq!(segments[0], &[1, 2, 3]);
                    assert!(metadata.is_empty());
                })
                .unwrap(),
                1
            );
            assert_eq!(port.counters().rx, 1);
            assert_eq!(port.drain_state().rx_leased, 0);
        }
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.refill().unwrap();
        let base = port.rings.fill.read(0);
        port.umem.write_bytes(base, &[1, 2, 3]);
        port.rings.rx.write(
            0,
            Descriptor {
                addr: base,
                len: 3,
                options: 0,
            },
        );
        port.rings.rx.publish_producer(1);
        port.rings.fill.publish_consumer(1);
        assert!(
            port.receive_segments(1, METADATA_SIZE, |_, _| panic!("missing required metadata"))
                .is_err()
        );
        assert_eq!(port.counters().rx, 0);
        assert_eq!(port.rings().rx_consumer, 0);
        assert!(port.drain_state().closed);
    }

    #[test]
    fn observes_fill_once_and_recycles_actual_rx_offset() {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        assert_eq!(port.refill().unwrap(), 2);
        assert_eq!(port.drain_state().fill_queued, 2);
        let base = port.rings.fill.read(0);
        let address = base + 128;
        port.umem.write_bytes(address, &[1, 2, 3]);
        port.rings.fill.publish_consumer(1);
        assert_eq!(port.observe_fill().unwrap(), 1);
        assert_eq!(port.observe_fill().unwrap(), 0);
        assert_eq!(port.drain_state().fill_posted, 2);
        assert_eq!(port.drain_state().fill_queued, 1);
        port.rings.rx.write(
            0,
            Descriptor {
                addr: address,
                len: 3,
                options: 0,
            },
        );
        port.rings.rx.publish_producer(1);
        let mut called = 0;
        assert_eq!(
            port.receive(64, |frame| {
                assert_eq!(frame, &[1, 2, 3]);
                called += 1;
            })
            .unwrap(),
            1
        );
        assert_eq!(called, 1);
        assert_eq!(port.rings().rx_consumer, 1);
        assert_eq!(port.rings().fill_producer, 3);
        assert_eq!(port.drain_state().rx_leased, 0);
        assert_eq!(port.drain_state().fill_posted, 2);
        assert_eq!(port.drain_state().fill_queued, 2);
        assert_eq!(port.receive(64, |_| panic!("duplicate RX")).unwrap(), 0);
        assert_eq!(port.counters().rx, 1);
        assert_eq!(port.counters().fill, 3);
    }

    #[test]
    fn receive_defers_rx_until_fill_consumer_publication_and_counts_only_deliveries() {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        assert!(!port.needs_service_retry());
        assert_eq!(port.refill().unwrap(), 2);
        assert!(
            !port.needs_service_retry(),
            "posted FILL alone must stay event-driven"
        );
        let first = port.rings.fill.read(0);
        let second = port.rings.fill.read(1);
        port.umem.write_bytes(first + 128, &[1, 2, 3]);
        port.umem.write_bytes(second + 128, &[4, 5, 6]);
        port.rings.rx.write(
            0,
            Descriptor {
                addr: first + 128,
                len: 3,
                options: 0,
            },
        );
        port.rings.rx.write(
            1,
            Descriptor {
                addr: second + 128,
                len: 3,
                options: 0,
            },
        );
        port.rings.rx.publish_producer(2);
        assert_eq!(
            port.receive(2, |_| panic!("FILL consumer not published"))
                .unwrap(),
            0
        );
        assert!(
            port.needs_service_retry(),
            "late FILL publication has no reliable event"
        );
        assert_ne!(port.rings().rx_producer, port.rings().rx_consumer);
        assert_eq!(port.rings().rx_consumer, 0);
        assert_eq!(port.drain_state().rx_leased, 0);
        assert_eq!(port.drain_state().fill_queued, 2);
        assert!(!port.drain_state().closed);
        assert_eq!(port.counters().invalid, 0);
        port.transmit(TxClass::Control, &[0; 14], &[7; 28], ())
            .unwrap();
        let tx_address = port.rings.tx.read(0).addr;
        assert!(tx_address >= (config().rx_frames * FRAME_SIZE) as u64);
        port.rings.tx.publish_consumer(1);
        port.rings.cq.write(0, tx_address);
        port.rings.cq.publish_producer(1);
        assert_eq!(port.complete(|_| {}).unwrap(), 1);
        assert!(port.tx_credit(TxClass::Control));
        port.rings.fill.publish_consumer(1);
        let mut delivered = 0;
        assert_eq!(
            port.receive(2, |frame| {
                assert_eq!(frame, &[1, 2, 3]);
                delivered += 1;
            })
            .unwrap(),
            1
        );
        assert_eq!(port.rings().rx_consumer, 1);
        assert_eq!(port.rings().fill_producer, 3);
        assert_eq!(port.rings.fill.read(2), first);
        assert_eq!(port.drain_state().rx_leased, 0);
        assert_eq!(port.counters().rx, 1);
        port.rings.fill.publish_consumer(2);
        assert_eq!(
            port.receive(2, |frame| {
                assert_eq!(frame, &[4, 5, 6]);
                delivered += 1;
            })
            .unwrap(),
            1
        );
        assert_eq!(delivered, 2);
        assert_eq!(port.rings().rx_consumer, 2);
        assert_eq!(port.rings().fill_producer, 4);
        assert_eq!(port.rings.fill.read(3), second);
        assert_eq!(port.drain_state().rx_leased, 0);
        assert_eq!(port.drain_state().fill_queued, 2);
        assert!(!port.needs_service_retry());
        assert!(!port.drain_state().closed);
        assert_eq!(port.counters().invalid, 0);
        assert_eq!(port.counters().rx, 2);
        assert_eq!(port.counters().fill, 4);
        assert_eq!(port.receive(2, |_| panic!("duplicate RX")).unwrap(), 0);
        assert_eq!(port.rings().fill_producer, 4);
    }

    #[test]
    fn generated_standalone_fatal_kick_retains_actual_bytes_and_owner_credit() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        port.rings.tx.set_wakeup();
        let error = port
            .transmit_generated(TxClass::Bulk, 80, |frame| {
                frame.fill(0xa5);
                frame[..42].fill(4);
                Ok(Some((42, Retained::new(&drops))))
            })
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        let descriptor = port.rings.tx.read(0);
        assert_eq!(descriptor.len, 60);
        assert_eq!(descriptor.options, 0);
        let frame = port.umem.frame(descriptor.addr, 80).unwrap();
        assert_eq!(&frame[..42], &[4; 42]);
        assert_eq!(&frame[42..60], &[0; 18]);
        assert_eq!(&frame[60..], &[0xa5; 20]);
        assert!(port.drain_state().closed);
        assert_eq!(port.drain_state().bulk_reserved, 0);
        assert_eq!(port.drain_state().bulk_outstanding, 1);
        assert_eq!(port.counters().submitted, 1);
        assert_eq!(port.counters().tx_kicks, 1);
        assert_eq!(port.tx_free, [1, 0]);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        port.rings.tx.publish_consumer(1);
        assert_eq!(
            port.complete(|owners| assert!(owners.is_empty())).unwrap(),
            0
        );
        for errno in [libc::EAGAIN, libc::EBUSY, libc::ENOBUFS, libc::EINTR] {
            port.wakeup_result(Err(io::Error::from_raw_os_error(errno)))
                .unwrap();
        }
        port.close_socket();
        assert_eq!(port.outstanding().count(), 1);
        assert_eq!(port.umem.frame(descriptor.addr, 42).unwrap(), &[4; 42]);
        assert_eq!(port.umem.frame(descriptor.addr + 42, 18).unwrap(), &[0; 18]);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        let charge = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
        drop(port);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(budget.used(), charge);
    }

    #[test]
    fn generated_published_prefix_survives_every_unpublished_suffix_failure() {
        for suffix in [
            "none",
            "error",
            "short",
            "long",
            "panic_before",
            "panic_after",
            "close",
        ] {
            let budget = MemoryBudget::new(1 << 20);
            let drops = Arc::new(AtomicUsize::new(0));
            let mut port = fake(config(), &budget);
            port.rings.tx.set_wakeup();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                port.transmit_batch(|port| {
                    assert!(port.transmit_generated(TxClass::Bulk, 60, |frame| {
                        frame.fill(9);
                        let mut owner = Retained::new(&drops);
                        owner.bytes.fill(9);
                        Ok(Some((60, owner)))
                    })?);
                    if suffix == "close" {
                        port.close();
                        return port.transmit_generated(TxClass::Control, 80, |_| {
                            panic!("closed generator ran")
                        });
                    }
                    port.transmit_generated(TxClass::Control, 80, |frame| {
                        frame.fill(5);
                        if suffix == "panic_before" {
                            panic!("before suffix owner");
                        }
                        let owner = Retained::new(&drops);
                        match suffix {
                            "none" => Ok(None),
                            "error" => Err(io::Error::other("suffix generation failed")),
                            "short" => Ok(Some((13, owner))),
                            "long" => Ok(Some((81, owner))),
                            "panic_after" => panic!("after suffix owner"),
                            _ => unreachable!(),
                        }
                    })
                })
            }));
            if suffix.starts_with("panic") {
                assert!(result.is_err());
                assert_eq!(port.counters().tx_kicks, 0);
            } else {
                let (work, kick) = result.unwrap();
                if suffix == "none" {
                    assert!(!work.unwrap());
                } else {
                    assert_eq!(
                        work.unwrap_err().kind(),
                        match suffix {
                            "close" => io::ErrorKind::WouldBlock,
                            "error" => io::ErrorKind::Other,
                            _ => io::ErrorKind::InvalidInput,
                        }
                    );
                }
                assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
                assert_eq!(port.counters().tx_kicks, 1);
            }
            let disposed = usize::from(!matches!(suffix, "panic_before" | "close"));
            assert_eq!(drops.load(Ordering::Relaxed), disposed);
            assert!(port.drain_state().closed);
            assert!(!port.tx_batch_active);
            assert_eq!(port.drain_state().control_reserved, 0);
            assert_eq!(port.drain_state().bulk_reserved, 0);
            assert_eq!(port.drain_state().bulk_outstanding, 1);
            assert_eq!(port.tx_free, [1, 0]);
            assert_eq!(port.rings().tx_producer, 1);
            assert_eq!(port.counters().submitted, 1);
            assert_eq!(port.sidecar.occupied().count(), 1);
            let prefix = port.rings.tx.read(0);
            assert_eq!(port.umem.frame(prefix.addr, 60).unwrap(), &[9; 60]);
            port.rings.tx.publish_consumer(1);
            assert_eq!(
                port.complete(|owners| assert!(owners.is_empty())).unwrap(),
                0
            );
            port.close_socket();
            assert_eq!(port.outstanding().count(), 1);
            assert_eq!(drops.load(Ordering::Relaxed), disposed);
            assert_eq!(port.umem.frame(prefix.addr, 60).unwrap(), &[9; 60]);
            port.rings.cq.write(0, prefix.addr);
            port.rings.cq.publish_producer(1);
            assert_eq!(
                port.complete(|owners| {
                    assert_eq!(owners.len(), 1);
                    assert_eq!(owners[0].as_ref().unwrap().bytes, [9; 28]);
                })
                .unwrap(),
                1
            );
            assert_eq!(drops.load(Ordering::Relaxed), disposed + 1);
            assert_eq!(port.tx_free, [1, 1]);
            assert!(port.drain_state().ready_for_backend_teardown());
        }
    }

    #[test]
    fn generated_mixed_cq_valid_prefix_keeps_partial_sg_and_invalid_suffix_retained() {
        for invalid in ["duplicate", "foreign", "shifted"] {
            let budget = MemoryBudget::new(1 << 20);
            let drops = Arc::new(AtomicUsize::new(0));
            let mut port = fake(
                PortConfig {
                    bulk_frames: 5,
                    ring_size: 8,
                    ..config()
                },
                &budget,
            );
            port.mtu = 9000;
            port.scatter_gather = true;
            assert!(
                port.transmit_generated(TxClass::Bulk, 80, |frame| {
                    frame.fill(1);
                    let mut owner = Retained::new(&drops);
                    owner.bytes.fill(1);
                    Ok(Some((80, owner)))
                })
                .unwrap()
            );
            let mut cpu = Retained::new(&drops);
            cpu.bytes.fill(2);
            port.transmit_retained(TxClass::Control, &[2; 14], cpu)
                .unwrap();
            let mut sg = Retained::new(&drops);
            sg.bytes.fill(3);
            port.transmit_with(TxClass::Bulk, 6000, sg, |owner, chunks| {
                for chunk in chunks {
                    chunk.fill(owner.bytes[0]);
                }
                Ok(())
            })
            .unwrap();
            assert!(
                port.transmit_generated(TxClass::Bulk, 60, |frame| {
                    frame.fill(4);
                    let mut owner = Retained::new(&drops);
                    owner.bytes.fill(4);
                    Ok(Some((60, owner)))
                })
                .unwrap()
            );
            let pending = port.rings.tx.read(4);
            let direct = port.rings.tx.read(0);
            let first = port.rings.tx.read(2);
            let last = port.rings.tx.read(3);
            assert_eq!((first.options, last.options), (1, 0));
            assert_eq!(first.len + last.len, 6000);
            port.rings.tx.publish_consumer(5);
            port.kick().unwrap();
            assert_eq!(
                port.complete(|owners| assert!(owners.is_empty())).unwrap(),
                0
            );
            assert_eq!(port.outstanding().count(), 5);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(port.umem.frame(direct.addr, 80).unwrap(), &[1; 80]);
            assert_eq!(port.umem.frame(pending.addr, 60).unwrap(), &[4; 60]);
            assert_eq!(
                port.umem.frame(first.addr, FRAME_SIZE).unwrap(),
                &[3; FRAME_SIZE]
            );
            for (index, descriptor) in [3, 1, 0].into_iter().enumerate() {
                port.rings
                    .cq
                    .write(index as u32, port.rings.tx.read(descriptor).addr);
            }
            port.rings.cq.write(
                3,
                match invalid {
                    "duplicate" => direct.addr,
                    "foreign" => 0,
                    "shifted" => pending.addr + 1,
                    _ => unreachable!(),
                },
            );
            port.rings.cq.write(4, first.addr);
            port.rings.cq.write(5, pending.addr);
            port.rings.cq.publish_producer(6);
            let mut released = Vec::new();
            assert!(
                port.complete(|owners| {
                    for owner in owners.iter().flatten() {
                        released.push(owner.bytes[0]);
                    }
                })
                .is_err()
            );
            assert_eq!(released, [1, 2]);
            assert_eq!(port.rings().cq_consumer, 3);
            assert_eq!(port.counters().completed, 3);
            assert_eq!(drops.load(Ordering::Relaxed), 2);
            assert_eq!(port.tx_free, [1, 3]);
            assert_eq!(port.outstanding().count(), 2);
            assert!(port.outstanding().any(|tx| tx.address == first.addr));
            assert!(port.outstanding().any(|tx| tx.address == pending.addr));
            assert_eq!(port.sidecar.occupied().count(), 2);
            let pending_owner = port.sidecar.occupied().last().unwrap();
            assert_eq!(pending_owner.0.bytes, [4; 28]);
            assert_eq!(pending_owner.1, 1);
            let retained = port.sidecar.occupied().next().unwrap();
            assert_eq!(retained.0.bytes, [3; 28]);
            assert_eq!(retained.1, 1);
            assert_eq!(
                port.umem.frame(first.addr, FRAME_SIZE).unwrap(),
                &[3; FRAME_SIZE]
            );
            assert_eq!(port.umem.frame(pending.addr, 60).unwrap(), &[4; 60]);
            assert!(port.complete(|owners| assert!(owners.is_empty())).is_err());
            assert!(
                port.transmit_generated(TxClass::Bulk, 60, |_| panic!("fatal port reused TX"))
                    .is_err()
            );
            assert_eq!(port.close().bulk_outstanding, 2);
            port.close_socket();
            assert_eq!(
                port.umem.frame(first.addr, FRAME_SIZE).unwrap(),
                &[3; FRAME_SIZE]
            );
            assert_eq!(port.umem.frame(pending.addr, 60).unwrap(), &[4; 60]);
            let charge = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
            drop(port);
            assert_eq!(drops.load(Ordering::Relaxed), 2);
            assert_eq!(budget.used(), charge);
        }
    }

    #[test]
    fn generated_submit_invariant_failure_transfers_to_fatal_retention() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        let mut prepared = port.reserve_single_tx(TxClass::Bulk).unwrap();
        let address = prepared.lease.address();
        port.umem.write_bytes(address, &[9; 60]);
        prepared.length = FRAME_SIZE as u32 + 1;
        let reservation = TxReservation {
            port: &mut port,
            prepared: Some(prepared),
        };
        assert!(reservation.publish(Retained::new(&drops)).is_err());
        assert!(port.drain_state().closed);
        assert_eq!(port.drain_state().bulk_reserved, 1);
        assert_eq!(port.outstanding().count(), 0);
        assert_eq!(port.rings().tx_producer, 0);
        assert_eq!(port.counters().submitted, 0);
        assert_eq!(port.sidecar.occupied().count(), 1);
        assert_eq!(port.umem.frame(address, 60).unwrap(), &[9; 60]);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert!(
            port.transmit_generated(TxClass::Bulk, 60, |_| panic!("failed submit reused TX"))
                .is_err()
        );
        let charge = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
        drop(port);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(budget.used(), charge);
    }

    #[test]
    fn generated_publication_survives_future_cancellation_and_close_without_cq() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        let mut future = Box::pin(async {
            let (work, kick) = port.transmit_batch(|port| {
                port.transmit_generated(TxClass::Bulk, 60, |frame| {
                    frame.fill(6);
                    Ok(Some((60, Retained::new(&drops))))
                })
            });
            assert!(work.unwrap());
            kick.unwrap();
            std::future::pending::<()>().await;
        });
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(future.as_mut().poll(&mut cx).is_pending());
        drop(future);
        let descriptor = port.rings.tx.read(0);
        assert_eq!(port.umem.frame(descriptor.addr, 60).unwrap(), &[6; 60]);
        port.rings.tx.publish_consumer(1);
        port.kick().unwrap();
        assert_eq!(
            port.complete(|owners| assert!(owners.is_empty())).unwrap(),
            0
        );
        assert_eq!(port.close().bulk_outstanding, 1);
        assert_eq!(port.tx_free, [1, 0]);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        port.close_socket();
        assert_eq!(port.umem.frame(descriptor.addr, 60).unwrap(), &[6; 60]);
        let charge = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
        drop(port);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(budget.used(), charge);
    }

    #[test]
    fn generated_reserve_shortages_preserve_the_original_unsent_packet() {
        for shortage in ["class", "ledger", "descriptor", "sidecar", "ring"] {
            let budget = MemoryBudget::new(1 << 20);
            let drops = Arc::new(AtomicUsize::new(0));
            let mut port = fake(
                PortConfig {
                    ring_size: if shortage == "ring" { 2 } else { 4 },
                    bulk_frames: if shortage == "descriptor" { 2 } else { 1 },
                    ..config()
                },
                &budget,
            );
            if shortage == "descriptor" {
                let mut frames = port.config.frame_config();
                frames.bulk_descriptors = 1;
                // SAFETY: no RX custody exists in this credit-shortage fixture.
                unsafe { ManuallyDrop::drop(&mut port.ledger) };
                port.ledger = ManuallyDrop::new(FrameLedger::new(frames, &budget).unwrap());
            }
            let mut held = None;
            match shortage {
                "class" => port
                    .transmit_generated(TxClass::Bulk, 60, |frame| {
                        frame.fill(1);
                        Ok(Some((60, Retained::new(&drops))))
                    })
                    .map(|sent| assert!(sent))
                    .unwrap(),
                "ledger" | "descriptor" => {
                    held = Some(port.ledger.reserve_tx(TxClass::Bulk).unwrap());
                }
                "sidecar" => {
                    for _ in 0..port.sidecar.slots.len() {
                        port.sidecar.occupy(Retained::new(&drops), 1);
                    }
                }
                "ring" => {
                    for class in [TxClass::Control, TxClass::Bulk] {
                        port.transmit_generated(class, 60, |frame| {
                            frame.fill(1);
                            Ok(Some((60, Retained::new(&drops))))
                        })
                        .unwrap();
                    }
                    for index in 0..2 {
                        port.rings.cq.write(index, port.rings.tx.read(index).addr);
                    }
                    port.rings.cq.publish_producer(2);
                    assert_eq!(
                        port.complete(|owners| assert_eq!(owners.len(), 2)).unwrap(),
                        2
                    );
                    assert_eq!(port.outstanding().count(), 0);
                    assert_eq!(port.tx_free, [1, 1]);
                }
                _ => unreachable!(),
            }
            let before = port.counters();
            let mut unsent = Some([0x5a; 60]);
            let error = port
                .transmit_generated(TxClass::Bulk, 60, |frame| {
                    frame.copy_from_slice(&unsent.take().expect("original packet"));
                    Ok(Some((60, Retained::new(&drops))))
                })
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{shortage}");
            assert_eq!(unsent, Some([0x5a; 60]));
            assert_eq!(port.counters(), before);
            assert!(!port.drain_state().closed);
            match shortage {
                "class" | "ledger" | "descriptor" => {
                    assert!(
                        port.transmit_generated(TxClass::Control, 60, |frame| {
                            frame.fill(2);
                            Ok(Some((60, Retained::new(&drops))))
                        })
                        .unwrap()
                    );
                    if let Some(lease) = held {
                        port.ledger.cancel_tx(lease).unwrap();
                    } else {
                        port.rings.cq.write(0, port.rings.tx.read(0).addr);
                        port.rings.cq.publish_producer(1);
                        assert_eq!(
                            port.complete(|owners| assert_eq!(owners.len(), 1)).unwrap(),
                            1
                        );
                        assert_eq!(
                            port.umem.frame(port.rings.tx.read(1).addr, 60).unwrap(),
                            &[2; 60]
                        );
                    }
                }
                "sidecar" => port.sidecar.release(0),
                "ring" => port.rings.tx.publish_consumer(1),
                _ => unreachable!(),
            }
            let index = port.tx_producer;
            assert!(
                port.transmit_generated(TxClass::Bulk, 60, |frame| {
                    frame.copy_from_slice(&unsent.take().expect("still unsent"));
                    Ok(Some((60, Retained::new(&drops))))
                })
                .unwrap()
            );
            assert!(unsent.is_none());
            let descriptor = port.rings.tx.read(index);
            assert_eq!(descriptor.len, 60);
            assert_eq!(descriptor.options, 0);
            assert_eq!(port.umem.frame(descriptor.addr, 60).unwrap(), &[0x5a; 60]);
            assert_eq!(
                port.counters().submitted,
                before.submitted
                    + 1
                    + u64::from(matches!(shortage, "class" | "ledger" | "descriptor"))
            );
            assert_eq!(port.drain_state().bulk_reserved, 0);
            if shortage == "sidecar" {
                port.sidecar.release(1);
            }
            port.rings.tx.publish_consumer(port.tx_producer);
            let cq = port.cq_consumer;
            let addresses: Vec<_> = port.outstanding().map(|tx| tx.address).collect();
            for (index, address) in addresses.iter().enumerate() {
                port.rings.cq.write(cq + index as u32, *address);
            }
            port.rings.cq.publish_producer(cq + addresses.len() as u32);
            assert_eq!(port.complete(|_| {}).unwrap(), addresses.len());
            assert_eq!(port.outstanding().count(), 0);
            assert_eq!(port.tx_free, [1, port.config.bulk_frames]);
            assert!(port.sidecar.occupied().next().is_none());
        }
    }

    #[test]
    fn generated_closed_corrupt_and_unmapped_reserves_never_call_the_emitter() {
        for failure in ["closed", "ring", "ledger", "extent"] {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(config(), &budget);
            match failure {
                "closed" => {
                    port.close();
                }
                "ring" => port.rings.tx.publish_consumer(1),
                "ledger" => {
                    port.ledger.close();
                }
                "extent" => {
                    let mut frames = config().frame_config();
                    frames.base_address = port.umem_bytes() as u64;
                    // SAFETY: no RX custody exists in this invalid-extent fixture.
                    unsafe { ManuallyDrop::drop(&mut port.ledger) };
                    port.ledger = ManuallyDrop::new(FrameLedger::new(frames, &budget).unwrap());
                }
                _ => unreachable!(),
            }
            assert!(
                port.transmit_generated(TxClass::Bulk, 60, |_| panic!("{failure} emitter ran"))
                    .is_err()
            );
            assert!(port.drain_state().closed);
            assert_eq!(port.drain_state().bulk_reserved, 0);
            assert_eq!(port.rings().tx_producer, 0);
            assert_eq!(port.outstanding().count(), 0);
            assert_eq!(port.tx_free, [1, 1]);
            assert!(port.sidecar.occupied().next().is_none());
            assert_eq!(port.counters().invalid, u64::from(failure != "closed"));
        }
    }

    #[test]
    fn generated_unpublished_none_errors_lengths_and_panics_restore_credit() {
        for outcome in [
            "none",
            "error",
            "zero",
            "short",
            "long",
            "overflow",
            "panic_before",
            "panic_after",
        ] {
            let budget = MemoryBudget::new(1 << 20);
            let drops = Arc::new(AtomicUsize::new(0));
            let mut port = fake(config(), &budget);
            let funded = budget.used();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                port.transmit_generated(TxClass::Bulk, 80, |frame| {
                    assert_eq!(frame.len(), 80);
                    frame.fill(0xa5);
                    if outcome == "panic_before" {
                        panic!("before owner");
                    }
                    let owner = Retained::new(&drops);
                    match outcome {
                        "none" => Ok(None),
                        "error" => Err(io::Error::other("generator failed")),
                        "zero" => Ok(Some((0, owner))),
                        "short" => Ok(Some((13, owner))),
                        "long" => Ok(Some((81, owner))),
                        "overflow" => Ok(Some((usize::MAX, owner))),
                        "panic_after" => panic!("after owner"),
                        _ => unreachable!(),
                    }
                })
            }));
            if outcome.starts_with("panic") {
                assert!(result.is_err());
            } else if outcome == "none" {
                assert!(!result.unwrap().unwrap());
            } else {
                let error = result.unwrap().unwrap_err();
                assert_eq!(
                    error.kind(),
                    if outcome == "error" {
                        io::ErrorKind::Other
                    } else {
                        io::ErrorKind::InvalidInput
                    }
                );
            }
            let disposed = usize::from(outcome != "panic_before");
            assert_eq!(drops.load(Ordering::Relaxed), disposed);
            assert_eq!(budget.used(), funded);
            assert_eq!(port.rings().tx_producer, 0);
            assert_eq!(port.outstanding().count(), 0);
            assert_eq!(port.drain_state().bulk_reserved, 0);
            assert_eq!(port.tx_free, [1, 1]);
            assert!(port.sidecar.occupied().next().is_none());
            assert!(!port.drain_state().closed);
            assert!(!port.needs_service_retry());
            assert!(
                port.transmit_generated(TxClass::Bulk, 80, |frame| {
                    frame[..42].fill(7);
                    Ok(Some((42, Retained::new(&drops))))
                })
                .unwrap()
            );
            let descriptor = port.rings.tx.read(0);
            assert_eq!(descriptor.len, 60);
            let frame = port.umem.frame(descriptor.addr, 80).unwrap();
            assert_eq!(&frame[..42], &[7; 42]);
            assert_eq!(&frame[42..60], &[0; 18]);
            assert_eq!(&frame[60..], &[0xa5; 20]);
            port.rings.tx.publish_consumer(1);
            port.rings.cq.write(0, descriptor.addr);
            port.rings.cq.publish_producer(1);
            assert_eq!(
                port.complete(|owners| assert_eq!(owners.len(), 1)).unwrap(),
                1
            );
            assert_eq!(drops.load(Ordering::Relaxed), disposed + 1);
            assert_eq!(port.tx_free, [1, 1]);
        }
    }

    #[test]
    fn generated_all_none_turns_leave_both_classes_reusable_without_publication() {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        for _ in 0..8 {
            for class in [TxClass::Control, TxClass::Bulk] {
                assert!(
                    !port
                        .transmit_generated(class, 42, |frame| {
                            assert_eq!(frame.len(), 42);
                            frame.fill(9);
                            Ok(None)
                        })
                        .unwrap()
                );
            }
        }
        assert_eq!(port.tx_free, [1, 1]);
        assert_eq!(port.drain_state().control_reserved, 0);
        assert_eq!(port.drain_state().bulk_reserved, 0);
        assert_eq!(port.rings().tx_producer, 0);
        assert_eq!(port.counters().submitted, 0);
        assert!(port.sidecar.occupied().next().is_none());
        for class in [TxClass::Control, TxClass::Bulk] {
            assert!(
                port.transmit_generated(class, 14, |frame| {
                    frame.fill(3);
                    Ok(Some((14, ())))
                })
                .unwrap()
            );
        }
        assert_eq!(port.outstanding().count(), 2);
        for index in 0..2 {
            let descriptor = port.rings.tx.read(index);
            assert_eq!(descriptor.len, 60);
            let frame = port.umem.frame(descriptor.addr, 60).unwrap();
            assert_eq!(&frame[..14], &[3; 14]);
            assert_eq!(&frame[14..], &[0; 46]);
            port.rings.cq.write(index, descriptor.addr);
        }
        port.rings.tx.publish_consumer(2);
        port.rings.cq.publish_producer(2);
        assert_eq!(
            port.complete(|owners| assert_eq!(owners.len(), 2)).unwrap(),
            2
        );
        assert_eq!(port.tx_free, [1, 1]);
    }

    #[test]
    fn generated_extent_uses_actual_padding_and_the_unshifted_single_frame_base() {
        for actual in [14, 42, 59, 60, 61, FRAME_SIZE] {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(config(), &budget);
            port.mtu = 9000;
            assert!(
                port.transmit_generated(TxClass::Bulk, FRAME_SIZE, |frame| {
                    assert_eq!(frame.len(), FRAME_SIZE);
                    frame.fill(0xa5);
                    frame[..actual].fill(7);
                    Ok(Some((actual, ())))
                })
                .unwrap()
            );
            let descriptor = port.rings.tx.read(0);
            assert_eq!(
                descriptor.addr,
                ((config().rx_frames + config().control_frames) * FRAME_SIZE) as u64
            );
            assert_eq!(descriptor.options, 0);
            assert_eq!(descriptor.len as usize, actual.max(60));
            assert_eq!(port.rings().tx_producer, 1);
            assert_eq!(port.counters().submitted, 1);
            let frame = port.umem.frame(descriptor.addr, FRAME_SIZE).unwrap();
            assert!(frame[..actual].iter().all(|&byte| byte == 7));
            assert!(frame[actual..actual.max(60)].iter().all(|&byte| byte == 0));
            assert!(frame[actual.max(60)..].iter().all(|&byte| byte == 0xa5));
            port.rings.tx.publish_consumer(1);
            port.rings.cq.write(0, descriptor.addr);
            port.rings.cq.publish_producer(1);
            assert_eq!(port.complete(|_| {}).unwrap(), 1);
        }
        for (mtu, sg, maximum) in [
            (1500, false, 0),
            (1500, false, 13),
            (1500, false, 1523),
            (9000, false, FRAME_SIZE + 1),
            (9000, true, FRAME_SIZE + 1),
            (9000, true, usize::MAX),
        ] {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(config(), &budget);
            port.mtu = mtu;
            port.scatter_gather = sg;
            assert_eq!(
                port.transmit_generated(TxClass::Bulk, maximum, |_| {
                    panic!("invalid maximum invoked generator")
                })
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(port.drain_state().bulk_reserved, 0);
            assert_eq!(port.tx_free, [1, 1]);
            assert_eq!(port.rings().tx_producer, 0);
            assert!(!port.drain_state().closed);
        }
    }

    #[test]
    fn retains_class_credit_and_padded_packet_until_real_fake_cq() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        let header = [3; 14];
        port.transmit_retained(TxClass::Bulk, &header, Retained::new(&drops))
            .unwrap();
        assert!(!port.tx_credit(TxClass::Bulk));
        assert!(port.tx_credit(TxClass::Control));
        let bulk = port.rings.tx.read(0);
        assert_eq!(bulk.options, 0);
        assert_eq!(bulk.len, 60);
        let frame = port.umem.frame(bulk.addr, bulk.len as usize).unwrap();
        assert_eq!(&frame[..14], &header);
        assert_eq!(&frame[14..42], &[7; 28]);
        assert_eq!(&frame[42..], &[0; 18]);
        port.transmit(TxClass::Control, &header, &[8; 28], Retained::new(&drops))
            .unwrap();
        let control = port.rings.tx.read(1);
        assert_eq!(port.outstanding().count(), 2);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        port.rings.tx.publish_consumer(2);
        assert_eq!(port.complete(|_| {}).unwrap(), 0);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        port.rings.cq.write(0, bulk.addr);
        port.rings.cq.write(1, control.addr);
        port.rings.cq.publish_producer(2);
        assert_eq!(port.complete(|_| {}).unwrap(), 2);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        assert_eq!(port.outstanding().count(), 0);
        assert!(port.tx_credit(TxClass::Control));
        assert!(port.tx_credit(TxClass::Bulk));
        let state = port.close();
        assert!(state.ready_for_backend_teardown());
        assert!(!port.tx_credit(TxClass::Control));
        assert_eq!(port.counters().submitted, 2);
        assert_eq!(port.counters().completed, 2);
        assert_eq!(port.counters().published_packets, 2);
        assert!(!port.counters().publication_count_unavailable);
    }

    #[test]
    fn completes_at_most_sixty_four_cq_entries_per_turn() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let config = PortConfig {
            rx_frames: 1,
            control_frames: 1,
            bulk_frames: 65,
            ring_size: 128,
        };
        let mut port = fake(config, &budget);
        for index in 0..65 {
            port.transmit_retained(TxClass::Bulk, &[0; 14], Retained::new(&drops))
                .unwrap();
            port.rings.cq.write(index, port.rings.tx.read(index).addr);
        }
        port.rings.tx.publish_consumer(65);
        port.rings.cq.publish_producer(65);
        assert_eq!(
            port.complete(|owners| assert_eq!(owners.len(), 64))
                .unwrap(),
            64
        );
        assert_eq!(drops.load(Ordering::Relaxed), 64);
        assert_eq!(port.outstanding().count(), 1);
        assert_eq!(port.rings().cq_consumer, 64);
        assert_eq!(
            port.complete(|owners| assert_eq!(owners.len(), 1)).unwrap(),
            1
        );
        assert_eq!(drops.load(Ordering::Relaxed), 65);
    }

    #[test]
    fn publication_and_drop_keep_sidecar_across_fatal_kick_error() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        port.rings.tx.set_wakeup();
        let error = port
            .transmit_retained(TxClass::Bulk, &[0; 14], Retained::new(&drops))
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        assert_eq!(port.rings().tx_producer, 1);
        assert_eq!(port.counters().submitted, 1);
        assert_eq!(port.counters().completed, 0);
        assert_eq!(port.outstanding().count(), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert!(port.kick().is_err());
        assert_eq!(port.counters().tx_kicks, 2);
        assert_eq!(port.counters().wakeup_errors, 2);
        assert_eq!(port.counters().published_packets, 1);
        port.close_socket();
        assert_eq!(port.as_raw_fd(), -1);
        assert_eq!(port.outstanding().count(), 1);
        let retained_bytes = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
        drop(port);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(budget.used(), retained_bytes);
    }

    #[test]
    fn retryable_wakeup_errors_never_complete_or_dispose_tx() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        port.transmit_retained(TxClass::Bulk, &[0; 14], Retained::new(&drops))
            .unwrap();
        for errno in [libc::EAGAIN, libc::EBUSY, libc::ENOBUFS, libc::EINTR] {
            port.wakeup_result(Err(io::Error::from_raw_os_error(errno)))
                .unwrap();
        }
        assert_eq!(port.counters().wakeup_errors, 4);
        assert_eq!(port.counters().completed, 0);
        assert_eq!(port.outstanding().count(), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        let ((), kick) = port.transmit_batch(|_| ());
        kick.unwrap();
        port.rings.tx.set_wakeup();
        let ((), kick) = port.transmit_batch(|_| ());
        assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert_eq!(port.counters().submitted, 1);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        let address = port.rings.tx.read(0).addr;
        port.rings.cq.write(0, address);
        port.rings.cq.publish_producer(1);
        assert_eq!(port.complete(|_| {}).unwrap(), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn outstanding_tx_kick_follows_cq_debt_and_skips_rx_wakeup() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        for class in [TxClass::Bulk, TxClass::Control] {
            port.transmit_retained(class, &[0; 14], Retained::new(&drops))
                .unwrap();
        }
        port.close();
        port.rings.tx.publish_consumer(2);
        port.rings.cq.write(0, port.rings.tx.read(0).addr);
        port.rings.cq.publish_producer(1);
        assert_eq!(
            port.complete(|owners| assert_eq!(owners.len(), 1)).unwrap(),
            1
        );

        port.rings.fill.set_wakeup();
        port.kick_outstanding_tx().unwrap();
        port.rings.tx.set_wakeup();
        assert_eq!(
            port.kick_outstanding_tx().unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
        assert_eq!(port.counters().rx_kicks, 0);
        assert_eq!(port.counters().tx_kicks, 1);
        assert_eq!(port.counters().wakeup_errors, 1);
        assert_eq!(port.counters().completed, 1);
        assert_eq!(port.outstanding().count(), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 1);

        port.rings.cq.write(1, port.rings.tx.read(1).addr);
        port.rings.cq.publish_producer(2);
        assert_eq!(
            port.complete(|owners| assert_eq!(owners.len(), 1)).unwrap(),
            1
        );
        let drained = port.counters();
        port.kick_outstanding_tx().unwrap();
        assert_eq!(port.counters(), drained);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn unknown_and_duplicate_cq_entries_are_fatal_not_disposals() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        port.transmit_retained(TxClass::Bulk, &[0; 14], Retained::new(&drops))
            .unwrap();
        let address = port.rings.tx.read(0).addr;
        port.rings.cq.write(0, 0);
        port.rings.cq.publish_producer(1);
        assert!(port.complete(|_| {}).is_err());
        assert_eq!(port.counters().invalid, 1);
        assert_eq!(port.rings().cq_consumer, 0);
        assert_eq!(port.outstanding().count(), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        port.rings.cq.write(0, address);
        assert_eq!(port.complete(|_| {}).unwrap(), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        port.rings.cq.write(1, address);
        port.rings.cq.publish_producer(2);
        assert!(port.complete(|_| {}).is_err());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(port.counters().completed, 1);
        assert_eq!(port.rings().cq_consumer, 1);
    }

    #[test]
    fn fatal_cq_after_progress_retains_only_unreturned_outputs_and_charge() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(
            PortConfig {
                rx_frames: 1,
                control_frames: 1,
                bulk_frames: 4,
                ring_size: 8,
            },
            &budget,
        );
        port.mtu = 9000;
        port.scatter_gather = true;
        for (class, length, id) in [
            (TxClass::Bulk, 6000, 1),
            (TxClass::Control, 60, 2),
            (TxClass::Bulk, 6000, 3),
        ] {
            let mut owner = Retained::new(&drops);
            owner.bytes.fill(id);
            port.transmit_with(class, length, owner, |owner, chunks| {
                for chunk in chunks {
                    chunk.fill(owner.bytes[0]);
                }
                Ok(())
            })
            .unwrap();
        }
        port.rings.tx.publish_consumer(5);
        for (index, descriptor) in [0, 2, 3, 1].into_iter().enumerate() {
            port.rings
                .cq
                .write(index as u32, port.rings.tx.read(descriptor).addr);
        }
        port.rings.cq.write(4, port.rings.tx.read(4).addr + 1);
        port.rings.cq.write(5, port.rings.tx.read(4).addr);
        port.rings.cq.publish_producer(6);
        let mut released = Vec::new();
        assert!(
            port.complete(|owners| {
                for owner in owners.iter().flatten() {
                    released.push(owner.bytes[0]);
                }
            })
            .is_err()
        );
        released.sort_unstable();
        assert_eq!(released, [1, 2]);
        assert_eq!(port.rings().cq_consumer, 4);
        assert_eq!(
            (port.counters().submitted, port.counters().completed),
            (5, 4)
        );
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        assert_eq!(port.outstanding().count(), 1);
        assert!(port.complete(|owners| assert!(owners.is_empty())).is_err());
        assert_eq!(port.sidecar.occupied().count(), 1);
        assert_eq!(port.sidecar.occupied().next().unwrap().1, 1);
        let retained = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
        port.close_socket();
        drop(port);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        assert_eq!(budget.used(), retained);
    }

    #[test]
    fn completion_callback_unwind_disposes_only_proven_owners() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        for class in [TxClass::Control, TxClass::Bulk] {
            port.transmit_retained(class, &[0; 14], Retained::new(&drops))
                .unwrap();
        }
        port.rings.tx.publish_consumer(2);
        port.rings.cq.write(0, port.rings.tx.read(0).addr);
        port.rings.cq.publish_producer(1);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            port.complete(|owners| {
                assert_eq!(owners.len(), 1);
                panic!("retirement callback failed");
            })
        }));
        assert!(result.is_err());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(port.counters().completed, 1);
        assert_eq!(port.rings().cq_consumer, 1);
        assert_eq!(port.outstanding().count(), 1);
        let retained = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
        port.close_socket();
        drop(port);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(budget.used(), retained);
    }

    #[test]
    fn refuses_invalid_rx_geometry_without_publishing_consumer() {
        for descriptor in [
            Descriptor {
                addr: 0,
                len: 1,
                options: 1,
            },
            Descriptor {
                addr: 0,
                len: 0,
                options: 0,
            },
            Descriptor {
                addr: (4 * FRAME_SIZE) as u64,
                len: 1,
                options: 0,
            },
            Descriptor {
                addr: (FRAME_SIZE - 1) as u64,
                len: 2,
                options: 0,
            },
            Descriptor {
                addr: (2 * FRAME_SIZE) as u64,
                len: 1,
                options: 0,
            },
        ] {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(config(), &budget);
            port.refill().unwrap();
            port.rings.rx.write(0, descriptor);
            port.rings.rx.publish_producer(1);
            assert!(
                port.receive(64, |_| panic!("invalid RX was borrowed"))
                    .is_err()
            );
            assert_eq!(port.counters().invalid, 1);
            assert_eq!(port.counters().rx, 0);
            assert_eq!(port.rings().rx_consumer, 0);
            assert!(!port.tx_credit(TxClass::Control));
        }
    }

    #[test]
    fn rejects_oversize_tx_before_reserving_or_copying() {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        assert!(
            port.transmit(TxClass::Bulk, &[0; 14], &[0; 1501], ())
                .is_err()
        );
        assert_eq!(port.outstanding().count(), 0);
        assert_eq!(port.counters().submitted, 0);
        assert!(port.tx_credit(TxClass::Bulk));
        port.transmit(TxClass::Bulk, &[0; 14], &[0; 1500], ())
            .unwrap();
        assert_eq!(port.rings.tx.read(0).len, 1514);
    }

    #[test]
    fn port_indices_wrap_without_repeating_fill_rx_or_cq_ownership() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        let initial = u32::MAX;
        port.fill_producer = initial;
        port.fill_consumer = initial;
        port.rx_consumer = initial;
        port.tx_producer = initial;
        port.cq_consumer = initial;
        port.rings.fill.publish_producer(initial);
        port.rings.fill.publish_consumer(initial);
        port.rings.rx.publish_producer(initial);
        port.rings.rx.publish_consumer(initial);
        port.rings.tx.publish_producer(initial);
        port.rings.tx.publish_consumer(initial);
        port.rings.cq.publish_producer(initial);
        port.rings.cq.publish_consumer(initial);
        assert_eq!(port.refill().unwrap(), 2);
        let rx_address = port.rings.fill.read(initial);
        port.umem.write_bytes(rx_address, &[9]);
        port.rings.fill.publish_consumer(0);
        port.rings.rx.write(
            initial,
            Descriptor {
                addr: rx_address,
                len: 1,
                options: 0,
            },
        );
        port.rings.rx.publish_producer(0);
        assert_eq!(port.receive(1, |frame| assert_eq!(frame, &[9])).unwrap(), 1);
        assert_eq!(port.rings().rx_consumer, 0);
        assert_eq!(port.rings().fill_producer, 2);
        assert_eq!(port.observe_fill().unwrap(), 0);
        port.transmit_retained(TxClass::Control, &[0; 14], Retained::new(&drops))
            .unwrap();
        let tx_address = port.rings.tx.read(initial).addr;
        assert_eq!(port.rings().tx_producer, 0);
        port.rings.tx.publish_consumer(0);
        port.rings.cq.write(initial, tx_address);
        port.rings.cq.publish_producer(0);
        assert_eq!(port.complete(|_| {}).unwrap(), 1);
        assert_eq!(port.rings().cq_consumer, 0);
        assert_eq!(port.complete(|_| {}).unwrap(), 0);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(port.counters().submitted, 1);
        assert_eq!(port.counters().completed, 1);
        assert_eq!(port.counters().rx, 1);
        assert_eq!(port.counters().fill, 3);
    }

    #[test]
    fn sg_receive_defers_the_whole_chain_until_fill_consumer_publication() {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(
            PortConfig {
                rx_frames: 4,
                control_frames: 4,
                bulk_frames: 4,
                ring_size: 8,
            },
            &budget,
        );
        port.mtu = 9000;
        port.scatter_gather = true;
        assert_eq!(port.refill().unwrap(), 4);
        let first = port.rings.fill.read(0);
        let second = port.rings.fill.read(1);
        port.umem.write_bytes(first, &[9; METADATA_SIZE]);
        port.umem.write_bytes(first + 32, &[1; 3000]);
        port.umem.write_bytes(second + 32, &[2; 3000]);
        port.rings.rx.write(
            0,
            Descriptor {
                addr: first + 32,
                len: 3000,
                options: 1,
            },
        );
        port.rings.rx.write(
            1,
            Descriptor {
                addr: second + 32,
                len: 3000,
                options: 0,
            },
        );
        port.rings.rx.publish_producer(2);
        assert_eq!(
            port.receive_segments_with(1, METADATA_SIZE, |_, _, _| panic!(
                "FILL consumer not published"
            ))
            .unwrap(),
            0
        );
        assert_ne!(port.rings().rx_producer, port.rings().rx_consumer);
        assert_eq!(port.rings().rx_consumer, 0);
        assert_eq!(port.drain_state().rx_leased, 0);
        assert_eq!(port.drain_state().fill_queued, 4);
        assert!(!port.drain_state().closed);
        port.rings.fill.publish_consumer(1);
        assert_eq!(
            port.receive_segments(1, METADATA_SIZE, |_, _| panic!(
                "only part of FILL consumption published"
            ))
            .unwrap(),
            0
        );
        assert_eq!(port.rings().rx_consumer, 0);
        assert_eq!(port.drain_state().rx_leased, 0);
        assert_eq!(port.drain_state().fill_queued, 3);
        assert_eq!(port.rings().fill_producer, 4);
        assert_eq!(port.counters().rx, 0);
        assert_eq!(port.counters().invalid, 0);
        assert!(!port.drain_state().closed);
        port.rings.fill.publish_consumer(2);
        let mut delivered = 0;
        assert_eq!(
            port.receive_segments_with(1, METADATA_SIZE, |parts, metadata, tx| {
                assert_eq!(parts.len(), 2);
                assert_eq!(parts[0], &[1; 3000]);
                assert_eq!(parts[1], &[2; 3000]);
                assert_eq!(metadata, &[9; METADATA_SIZE]);
                tx.transmit_segments(TxClass::Bulk, parts, ()).unwrap();
                delivered += 1;
            })
            .unwrap(),
            1
        );
        assert_eq!(delivered, 1);
        assert_eq!(port.rings().rx_consumer, 2);
        assert_eq!(port.rings().fill_producer, 6);
        assert_eq!(
            [port.rings.fill.read(4), port.rings.fill.read(5)],
            [second, first]
        );
        assert_eq!(port.drain_state().rx_leased, 0);
        assert_eq!(port.drain_state().fill_queued, 4);
        assert_eq!(port.counters().rx, 1);
        assert_eq!(port.counters().fill, 6);
        assert_eq!(port.counters().invalid, 0);
        assert!(!port.drain_state().closed);
        assert_eq!(
            port.receive_segments(1, METADATA_SIZE, |_, _| panic!("duplicate RX chain"))
                .unwrap(),
            0
        );
        assert_eq!(port.rings().fill_producer, 6);
        assert_eq!(port.rings().tx_producer, 2);
        for index in 0..2 {
            let address = port.rings.tx.read(index).addr;
            assert!(address >= (port.config().rx_frames * FRAME_SIZE) as u64);
            port.rings.cq.write(index, address);
        }
        port.rings.tx.publish_consumer(2);
        port.rings.cq.publish_producer(2);
        assert_eq!(port.complete(|_| {}).unwrap(), 2);
    }

    #[test]
    fn sg_receive_rejects_invalid_chains_before_waiting_or_leasing() {
        for invalid in 0..8 {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(
                PortConfig {
                    rx_frames: 4,
                    control_frames: 4,
                    bulk_frames: 4,
                    ring_size: 8,
                },
                &budget,
            );
            port.mtu = 9000;
            port.scatter_gather = true;
            port.refill().unwrap();
            let mut first = port.rings.fill.read(0) + 32;
            let second = port.rings.fill.read(1) + 32;
            let descriptor = match invalid {
                0 => Descriptor {
                    addr: u64::MAX,
                    len: 1,
                    options: 0,
                },
                1 => Descriptor {
                    addr: (port.config().rx_frames * FRAME_SIZE) as u64 + 32,
                    len: 1,
                    options: 0,
                },
                2 => Descriptor {
                    addr: first + 64,
                    len: 1,
                    options: 0,
                },
                3 => Descriptor {
                    addr: second + FRAME_SIZE as u64 - 33,
                    len: 2,
                    options: 0,
                },
                4 => {
                    port.rings.fill.publish_consumer(1);
                    port.observe_fill().unwrap();
                    let lease = port.ledger.receive_rx(first, 64).unwrap();
                    port.ledger.relinquish_rx(lease).unwrap();
                    let free = first;
                    first = port.rings.fill.read(2) + 32;
                    Descriptor {
                        addr: free,
                        len: 64,
                        options: 0,
                    }
                }
                5 => Descriptor {
                    addr: second,
                    len: 1,
                    options: 2,
                },
                6 => Descriptor {
                    addr: second,
                    len: 0,
                    options: 0,
                },
                7 => {
                    first -= 1;
                    Descriptor {
                        addr: second,
                        len: 1,
                        options: 0,
                    }
                }
                _ => unreachable!(),
            };
            port.rings.rx.write(
                0,
                Descriptor {
                    addr: first,
                    len: 64,
                    options: 1,
                },
            );
            port.rings.rx.write(1, descriptor);
            port.rings.rx.publish_producer(2);
            assert!(
                port.receive_segments_with(1, METADATA_SIZE, |_, _, _| panic!(
                    "invalid RX chain borrowed"
                ))
                .is_err()
            );
            assert_eq!(port.rings().rx_consumer, 0);
            assert_eq!(port.drain_state().rx_leased, 0);
            assert_eq!(port.counters().rx, 0);
            assert_eq!(port.counters().invalid, 1);
            assert!(port.drain_state().closed);
        }
    }

    #[test]
    fn borrowed_rx_batch_matches_single_packets_across_a_partial_chain() {
        let run = |batch, expected_counts: &[usize]| {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(
                PortConfig {
                    rx_frames: 4,
                    ..config()
                },
                &budget,
            );
            port.scatter_gather = true;
            port.refill().unwrap();
            queue_rx(&mut port, &[60], METADATA_SIZE);
            queue_rx(&mut port, &[61], METADATA_SIZE);
            let end = stage_rx(&mut port, &[62, 63], METADATA_SIZE);
            port.rings.rx.publish_producer(end - 1);

            let mut lengths = Vec::new();
            for &expected in expected_counts {
                let before = port.rings();
                let mut descriptors = 0;
                let received = port
                    .receive_segments_with(batch, METADATA_SIZE, |parts, metadata, tx| {
                        assert_eq!(tx.port.rings.rx.consumer(), before.rx_consumer);
                        assert_eq!(tx.port.rings.fill.producer(), before.fill_producer);
                        assert_eq!(metadata, &[0xa5; METADATA_SIZE]);
                        if lengths.is_empty() {
                            tx.port.rings.rx.publish_producer(end);
                        }
                        for (index, bytes) in parts.iter().enumerate() {
                            assert!(bytes.iter().all(|&byte| byte == index as u8 + 1));
                        }
                        descriptors += parts.len() as u32;
                        lengths.push(parts.iter().map(|bytes| bytes.len()).collect::<Vec<_>>());
                    })
                    .unwrap();
                assert_eq!(received, expected);
                assert_eq!(port.rings().rx_consumer, before.rx_consumer + descriptors);
                assert_eq!(
                    port.rings().fill_producer,
                    before.fill_producer + descriptors
                );
            }
            (lengths, port.rings(), port.counters(), port.drain_state())
        };
        let batch = run(4, &[2, 1, 0]);
        assert_eq!(batch, run(1, &[1, 1, 1, 0]));
        assert_eq!(batch.0, [vec![60], vec![61], vec![62, 63]]);
        assert_eq!(batch.2.rx, 3);
        assert_eq!(batch.3.rx_leased, 0);
    }

    #[test]
    fn borrowed_rx_drops_callback_before_refilling_a_partial_chain() {
        struct PanicOnDrop;

        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                std::panic::panic_any("borrowed RX capture dropped");
            }
        }

        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.scatter_gather = true;
        port.refill().unwrap();
        let end = stage_rx(&mut port, &[60, 60], 0);
        port.rings.rx.publish_producer(end - 1);
        port.rings.fill.set_wakeup();
        let capture = PanicOnDrop;
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            port.receive_segments(2, 0, move |_, _| {
                std::hint::black_box(&capture);
            })
            .unwrap();
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"borrowed RX capture dropped")
        );
        assert!(port.drain_state().closed);
        assert_eq!(port.rings().rx_consumer, 0);
        assert_eq!(port.counters().rx, 0);
        assert_eq!(port.counters().rx_kicks, 0);
    }

    #[test]
    fn sg_receive_waits_for_terminal_descriptor_and_can_transmit_same_port() {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(
            PortConfig {
                rx_frames: 4,
                control_frames: 4,
                bulk_frames: 4,
                ring_size: 8,
            },
            &budget,
        );
        port.mtu = 9000;
        port.scatter_gather = true;
        port.refill().unwrap();
        port.rings.fill.publish_consumer(2);
        let first = port.rings.fill.read(0);
        let second = port.rings.fill.read(1);
        port.umem.write_bytes(first, &[9; METADATA_SIZE]);
        port.umem.write_bytes(first + 32, &[1; 3000]);
        port.umem.write_bytes(second + 32, &[2; 3000]);
        port.rings.rx.write(
            0,
            Descriptor {
                addr: first + 32,
                len: 3000,
                options: 1,
            },
        );
        port.rings.rx.publish_producer(1);
        assert_eq!(
            port.receive_segments(1, METADATA_SIZE, |_, _| panic!("partial RX packet"))
                .unwrap(),
            0
        );
        assert!(
            port.needs_service_retry(),
            "partial RX chains retain a retry obligation"
        );
        assert_eq!(port.rings().rx_consumer, 0);
        port.rings.rx.write(
            1,
            Descriptor {
                addr: second + 32,
                len: 3000,
                options: 0,
            },
        );
        port.rings.rx.publish_producer(2);
        assert_eq!(
            port.receive_segments_with(1, METADATA_SIZE, |parts, metadata, tx| {
                assert_eq!(parts.len(), 2);
                assert_eq!(metadata, &[9; METADATA_SIZE]);
                tx.transmit_segments(TxClass::Bulk, parts, ()).unwrap();
            })
            .unwrap(),
            1
        );
        assert_eq!(port.rings().rx_consumer, 2);
        assert_eq!(port.rings().tx_producer, 2);
        let first = port.rings.tx.read(0);
        let last = port.rings.tx.read(1);
        assert_eq!(first.options, 1);
        assert_eq!(last.options, 0);
        assert_eq!(first.len + last.len, 6000);
        let bytes = port.umem.frame(first.addr, first.len as usize).unwrap();
        assert_eq!(&bytes[..3000], &[1; 3000]);
        assert!(bytes[3000..].iter().all(|&byte| byte == 2));
    }

    #[test]
    fn sg_tx_cancels_writer_failure_and_retains_until_every_completion() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(
            PortConfig {
                rx_frames: 4,
                control_frames: 4,
                bulk_frames: 4,
                ring_size: 8,
            },
            &budget,
        );
        port.mtu = 9000;
        port.scatter_gather = true;
        assert!(port.tx_packet_credit(TxClass::Bulk, 9000));
        assert!(!port.tx_packet_credit(TxClass::Bulk, 13));
        assert!(!port.tx_packet_credit(TxClass::Bulk, 9023));
        assert!(
            port.transmit_with(TxClass::Bulk, 9000, Retained::new(&drops), |owner, _| {
                assert_eq!(owner.as_ref(), &[7; 28]);
                Err(io::Error::other("writer failed"))
            })
            .is_err()
        );
        assert_eq!(port.rings().tx_producer, 0);
        assert_eq!(port.counters().published_packets, 0);
        assert_eq!(port.tx_free[1], 4);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert!(
            !port.needs_service_retry(),
            "unpublished writer failure owes no CQ"
        );
        port.transmit_segments(TxClass::Bulk, &[&[7; 9000]], Retained::new(&drops))
            .unwrap();
        assert!(port.needs_service_retry());
        assert_eq!(port.rings().tx_producer, 3);
        assert_eq!(port.counters().submitted, 3);
        assert_eq!(port.counters().published_packets, 1);
        assert!(port.tx_credit(TxClass::Bulk));
        assert!(!port.tx_packet_credit(TxClass::Bulk, 9000));
        port.rings.tx.publish_consumer(3);
        for (completion, descriptor) in [1, 0, 2].into_iter().enumerate() {
            port.rings
                .cq
                .write(completion as u32, port.rings.tx.read(descriptor).addr);
            port.rings.cq.publish_producer(completion as u32 + 1);
            assert_eq!(
                port.complete(|owners| {
                    assert_eq!(owners.len(), usize::from(completion == 2));
                })
                .unwrap(),
                1
            );
            assert_eq!(port.needs_service_retry(), completion != 2);
            assert_eq!(
                drops.load(Ordering::Relaxed),
                if completion == 2 { 2 } else { 1 }
            );
        }
        assert_eq!(port.tx_free[1], 4);
        assert!(port.sidecar.occupied().next().is_none());
        assert!(port.tx_packet_credit(TxClass::Bulk, 9000));
        assert_eq!(port.counters().published_packets, 1);
    }

    #[test]
    fn sg_owner_survives_first_frame_reuse_after_out_of_order_cq() {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake(
            PortConfig {
                bulk_frames: 3,
                ..config()
            },
            &budget,
        );
        port.mtu = 9000;
        port.scatter_gather = true;
        port.transmit_segments(TxClass::Bulk, &[&[1; 9000]], 1u8)
            .unwrap();
        let [first, middle, last] =
            std::array::from_fn(|index| port.rings.tx.read(index as u32).addr);
        port.rings.tx.publish_consumer(3);
        port.rings.cq.write(0, first);
        port.rings.cq.publish_producer(1);
        assert_eq!(
            port.complete(|owners| assert!(owners.is_empty())).unwrap(),
            1
        );

        assert!(
            port.transmit_generated(TxClass::Bulk, 60, |frame| {
                frame.fill(2);
                Ok(Some((60, 2)))
            })
            .unwrap()
        );
        assert_eq!(port.rings.tx.read(3).addr, first);
        port.rings.tx.publish_consumer(4);
        port.rings.cq.write(1, last);
        port.rings.cq.write(2, first);
        port.rings.cq.publish_producer(3);
        assert_eq!(
            port.complete(|owners| assert!(matches!(owners, [Some(v)] if **v == 2)))
                .unwrap(),
            2
        );
        port.rings.cq.write(3, middle);
        port.rings.cq.publish_producer(4);
        assert_eq!(
            port.complete(|owners| assert!(matches!(owners, [Some(v)] if **v == 1)))
                .unwrap(),
            1
        );

        for class in [
            TxClass::Control,
            TxClass::Bulk,
            TxClass::Bulk,
            TxClass::Bulk,
        ] {
            port.transmit_segments(class, &[&[3; 60]], 3).unwrap();
        }
        for index in 4..8 {
            port.rings.cq.write(index, port.rings.tx.read(index).addr);
        }
        port.rings.tx.publish_consumer(8);
        port.rings.cq.publish_producer(8);
        assert_eq!(
            port.complete(|owners| assert_eq!(owners.len(), 4)).unwrap(),
            4
        );
    }

    #[test]
    fn packet_capacity_uses_actual_mtu_class_frames_and_tx_ring_space() {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(
            PortConfig {
                rx_frames: 1,
                control_frames: 1,
                bulk_frames: 7,
                ring_size: 8,
            },
            &budget,
        );
        assert_eq!(port.tx_packet_capacity(TxClass::Bulk).unwrap(), 7);
        assert_eq!(port.tx_packet_capacity(TxClass::Control).unwrap(), 1);
        port.mtu = 9000;
        port.scatter_gather = true;
        assert_eq!(port.tx_packet_capacity(TxClass::Bulk).unwrap(), 2);
        assert_eq!(port.tx_packet_capacity(TxClass::Control).unwrap(), 0);
        assert!(port.tx_packet_credit(TxClass::Control, 60));
        port.transmit_segments(TxClass::Control, &[&[1; 60]], ())
            .unwrap();
        for _ in 0..2 {
            port.transmit_segments(TxClass::Bulk, &[&[7; 9022]], ())
                .unwrap();
        }
        assert_eq!(port.counters().submitted, 7);
        assert_eq!(port.tx_packet_capacity(TxClass::Bulk).unwrap(), 0);
        assert_eq!(
            port.transmit_segments(TxClass::Bulk, &[&[7; 9022]], ())
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        for index in 0..7 {
            port.rings.cq.write(index, port.rings.tx.read(index).addr);
        }
        port.rings.cq.publish_producer(7);
        assert_eq!(port.complete(|_| {}).unwrap(), 7);
        assert_eq!(port.tx_packet_capacity(TxClass::Bulk).unwrap(), 0);
        port.rings.tx.publish_consumer(7);
        assert_eq!(port.tx_packet_capacity(TxClass::Bulk).unwrap(), 2);
        port.close();
        assert_eq!(port.tx_packet_capacity(TxClass::Bulk).unwrap(), 0);
        port.rings.tx.publish_consumer(8);
        assert!(port.tx_packet_capacity(TxClass::Bulk).is_err());
        assert_eq!(port.counters().invalid, 1);
    }

    #[test]
    fn returned_cq_still_retries_until_tx_ring_credit_is_visible() {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(
            PortConfig {
                ring_size: 2,
                ..config()
            },
            &budget,
        );
        for class in [TxClass::Control, TxClass::Bulk] {
            port.transmit_segments(class, &[&[1; 60]], ()).unwrap();
        }
        for index in 0..2 {
            port.rings.cq.write(index, port.rings.tx.read(index).addr);
        }
        port.rings.cq.publish_producer(2);
        assert_eq!(port.complete(|_| {}).unwrap(), 2);
        assert!(port.outstanding().next().is_none());
        assert!(!port.tx_credit(TxClass::Bulk));
        assert!(port.needs_service_retry());
        port.rings.tx.publish_consumer(2);
        assert!(port.tx_credit(TxClass::Bulk));
        assert!(!port.needs_service_retry());
    }

    fn transmit_entry(
        port: &mut Port<Retained>,
        entry: usize,
        drops: &Arc<AtomicUsize>,
    ) -> io::Result<()> {
        let owner = Retained::new(drops);
        match entry {
            0 => port.transmit(TxClass::Bulk, &[3; 14], &[7; 28], owner),
            1 => port.transmit_retained(TxClass::Bulk, &[3; 14], owner),
            2 => port.transmit_segments(TxClass::Bulk, &[&[3; 14], &[7; 28]], owner),
            3 => port.transmit_with(TxClass::Bulk, 42, owner, |_, target| {
                target[0][..14].fill(3);
                target[0][14..].fill(7);
                Ok(())
            }),
            4 => port
                .transmit_generated(TxClass::Bulk, 42, |target| {
                    target[..14].fill(3);
                    target[14..].copy_from_slice(owner.as_ref());
                    Ok(Some((42, owner)))
                })
                .map(|sent| assert!(sent)),
            _ => unreachable!(),
        }
    }

    #[test]
    fn batch_tx_entries_publish_the_whole_prefix_before_terminal_wakeup() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(
            PortConfig {
                bulk_frames: 5,
                ring_size: 8,
                ..config()
            },
            &budget,
        );
        port.rings.tx.set_wakeup();
        let (work, kick) = port.transmit_batch(|port| {
            for entry in 0..5 {
                transmit_entry(port, entry, &drops)?;
                assert_eq!(port.counters().published_packets, entry as u64 + 1);
            }
            assert!(!port.drain_state().closed);
            assert_eq!(port.rings().tx_producer, 5);
            Ok::<_, io::Error>(())
        });
        work.unwrap();
        assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert!(port.drain_state().closed);
        assert!(!port.tx_batch_active);
        assert_eq!(port.outstanding().count(), 5);
        for index in 0..5 {
            let descriptor = port.rings.tx.read(index);
            assert_eq!(descriptor.len, 60);
            assert_eq!(descriptor.options, 0);
            let frame = port.umem.frame(descriptor.addr, 60).unwrap();
            assert_eq!(&frame[..14], &[3; 14]);
            assert_eq!(&frame[14..42], &[7; 28]);
            assert_eq!(&frame[42..], &[0; 18]);
        }
        port.rings.tx.publish_consumer(5);
        assert_eq!(port.complete(|_| {}).unwrap(), 0);
        assert_eq!(port.counters().published_packets, 5);
        assert!(!port.counters().publication_count_unavailable);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        let retained = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
        drop(port);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(budget.used(), retained);
    }

    #[test]
    fn batch_writer_errors_and_credit_pressure_keep_the_final_kick_separate() {
        for suffix in 0..3 {
            let budget = MemoryBudget::new(1 << 20);
            let drops = Arc::new(AtomicUsize::new(0));
            let mut port = fake(config(), &budget);
            port.rings.tx.set_wakeup();
            let (work, kick) = port.transmit_batch(|port| {
                transmit_entry(port, 1, &drops)?;
                if suffix == 2 {
                    return transmit_entry(port, 2, &drops);
                }
                port.transmit_with(TxClass::Control, 60, Retained::new(&drops), |_, _| {
                    Err(io::Error::new(
                        if suffix == 0 {
                            io::ErrorKind::InvalidData
                        } else {
                            io::ErrorKind::WouldBlock
                        },
                        "unpublished writer suffix",
                    ))
                })
            });
            assert_eq!(
                work.unwrap_err().kind(),
                if suffix == 0 {
                    io::ErrorKind::InvalidData
                } else {
                    io::ErrorKind::WouldBlock
                }
            );
            assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
            assert!(port.drain_state().closed);
            assert_eq!(port.drain_state().control_reserved, 0);
            assert_eq!(port.drain_state().bulk_reserved, 0);
            assert_eq!(port.rings().tx_producer, 1);
            assert_eq!(port.counters().published_packets, 1);
            assert_eq!(port.outstanding().count(), 1);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            port.rings.cq.write(0, port.rings.tx.read(0).addr);
            port.rings.cq.publish_producer(1);
            assert_eq!(port.complete(|_| {}).unwrap(), 1);
            assert_eq!(port.counters().published_packets, 1);
            assert_eq!(drops.load(Ordering::Relaxed), 2);
        }
    }

    #[test]
    fn batch_early_and_pending_returns_reinspect_wakeup_without_new_publication() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        let (pending, kick) = port.transmit_batch(|_| std::task::Poll::<()>::Pending);
        assert!(pending.is_pending());
        kick.unwrap();
        assert!(!port.tx_batch_active);
        port.rings.tx.set_wakeup();
        let (work, kick) = port.transmit_batch(|port| {
            transmit_entry(port, 0, &drops)?;
            if !port.tx_credit(TxClass::Bulk) {
                return Ok::<_, io::Error>(7);
            }
            panic!("one-frame bulk commitment was exceeded");
        });
        assert_eq!(work.unwrap(), 7);
        assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
        let ((), kick) = port.transmit_batch(|_| ());
        assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert_eq!(port.counters().submitted, 1);
        assert_eq!(port.counters().completed, 0);
        assert_eq!(port.counters().published_packets, 1);
        assert_eq!(port.outstanding().count(), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn borrowed_tx_sink_prefix_is_finalized_after_a_later_rx_error() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        port.refill().unwrap();
        port.rings.fill.publish_consumer(2);
        let rx = port.rings.fill.read(0);
        port.umem.write_bytes(rx, &[7; 60]);
        port.rings.rx.write(
            0,
            Descriptor {
                addr: rx,
                len: 60,
                options: 0,
            },
        );
        port.rings.rx.write(
            1,
            Descriptor {
                addr: port.rings.fill.read(1),
                len: 0,
                options: 0,
            },
        );
        port.rings.rx.publish_producer(2);
        port.rings.tx.set_wakeup();
        let (work, kick) = port.transmit_batch(|port| {
            port.receive_segments_with(2, 0, |parts, _, tx| {
                tx.transmit_segments(TxClass::Bulk, parts, Retained::new(&drops))
                    .unwrap();
                tx.transmit_with(TxClass::Control, 60, Retained::new(&drops), |_, target| {
                    target[0].copy_from_slice(parts[0]);
                    Ok(())
                })
                .unwrap();
            })
        });
        assert!(
            work.unwrap_err()
                .to_string()
                .contains("invalid RX chain descriptor")
        );
        assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert_eq!(port.rings().rx_consumer, 1);
        assert_eq!(port.rings().fill_producer, 2);
        assert_eq!(port.counters().rx, 1);
        assert_eq!(port.counters().invalid, 1);
        assert_eq!(port.drain_state().rx_leased, 0);
        assert_eq!(port.rings().tx_producer, 2);
        assert_eq!(port.outstanding().count(), 2);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        for index in 0..2 {
            let descriptor = port.rings.tx.read(index);
            assert_eq!(port.umem.frame(descriptor.addr, 60).unwrap(), &[7; 60]);
            assert!(descriptor.addr >= (config().rx_frames * FRAME_SIZE) as u64);
        }
    }

    #[test]
    fn borrowed_rx_rejects_a_second_packet_in_the_released_prefix_frame() {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.refill().unwrap();
        queue_rx(&mut port, &[60], 0);
        queue_rx(&mut port, &[61], 0);
        let mut duplicate = port.rings.rx.read(1);
        duplicate.addr = port.rings.rx.read(0).addr + 1;
        port.rings.rx.write(1, duplicate);
        let error = port
            .receive_segments(2, 0, |parts, _| assert_eq!(parts[0], &[1; 60]))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(port.rings().rx_consumer, 1);
        assert_eq!(port.rings().fill_producer, 2);
        assert_eq!(port.counters().rx, 1);
        let state = port.drain_state();
        assert!(state.closed);
        assert_eq!(state.rx_free, 1);
        assert_eq!(state.rx_leased, 0);
        assert_eq!(state.fill_posted, 1);
    }

    #[test]
    fn retained_rx_stops_on_a_fatal_same_port_tx_kick() {
        for disposition in [RxDisposition::Release, RxDisposition::Retain] {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(
                PortConfig {
                    rx_frames: 3,
                    ..config()
                },
                &budget,
            );
            port.refill().unwrap();
            queue_rx(&mut port, &[60], 0);
            queue_rx(&mut port, &[61], 0);
            port.rings.tx.set_wakeup();
            let mut admitted = None;
            let received = port
                .receive_segments_owned(2, 0, |handle, parts, _, tx| {
                    assert!(admitted.replace(handle).is_none());
                    let error = tx.transmit_segments(TxClass::Bulk, parts, ()).unwrap_err();
                    assert_eq!(error.raw_os_error(), Some(libc::EBADF));
                    tx.port.rings.fill.publish_consumer(3);
                    disposition
                })
                .unwrap();
            assert_eq!(received, 1);
            assert!(port.drain_state().closed);
            assert_eq!(port.rings().rx_consumer, 1);
            assert_eq!(port.rings().fill_producer, 3);
            assert_eq!(port.fill_consumer, 2);
            assert_eq!(port.counters().rx, 1);
            assert_eq!(port.drain_state().bulk_outstanding, 1);
            if disposition == RxDisposition::Retain {
                let completion = port.release_retained_rx(admitted.unwrap()).unwrap();
                port.complete_retained_rx(completion).unwrap();
            }
            assert_eq!(port.retained_rx_count(), 0);
            assert_eq!(port.rx_completion_count(), 0);
            assert_eq!(port.drain_state().rx_leased, 0);
        }
    }

    #[test]
    fn borrowed_rx_callback_panic_keeps_whole_chain_and_tx_prefix() {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(
            PortConfig {
                rx_frames: 5,
                ring_size: 8,
                ..config()
            },
            &budget,
        );
        port.scatter_gather = true;
        port.refill().unwrap();
        queue_rx(&mut port, &[59], METADATA_SIZE);
        queue_rx(&mut port, &[60, 61], METADATA_SIZE);
        queue_rx(&mut port, &[62], METADATA_SIZE);
        port.rings.fill.set_wakeup();
        port.rings.tx.set_wakeup();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (work, kick) = port.transmit_batch(|port| {
                port.receive_segments_with(4, METADATA_SIZE, |parts, metadata, tx| {
                    assert_eq!(metadata, &[0xa5; METADATA_SIZE]);
                    if parts.len() == 1 {
                        assert_eq!(parts[0], &[1; 59]);
                        return;
                    }
                    assert_eq!(parts, &[&[1; 60][..], &[2; 61][..]]);
                    tx.transmit_segments(TxClass::Bulk, parts, ()).unwrap();
                    std::panic::panic_any("borrowed RX callback");
                })
            });
            work.unwrap();
            kick.unwrap();
        }))
        .unwrap_err();
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"borrowed RX callback"));
        let state = port.drain_state();
        assert!(state.closed);
        assert!(!state.ready_for_backend_teardown());
        assert_eq!(state.rx_free, 1);
        assert_eq!(state.rx_leased, 2);
        assert_eq!(state.fill_posted, 2);
        assert_eq!(state.fill_queued, 1);
        assert_eq!(port.retained_rx_count(), 0);
        assert_eq!(port.rx_completion_count(), 0);
        assert_eq!(port.rx_consumer, 3);
        assert_eq!(port.rings().rx_consumer, 0);
        assert_eq!(port.rings().fill_producer, 5);
        assert_eq!(port.counters().rx, 2);
        assert_eq!(port.counters().wakeup_errors, 0);
        assert_eq!(port.counters().published_packets, 1);
        assert_eq!(state.bulk_outstanding, 1);
        let descriptor = port.rings.tx.read(0);
        let bytes = port
            .umem
            .frame(descriptor.addr, descriptor.len as usize)
            .unwrap();
        assert_eq!(&bytes[..60], &[1; 60]);
        assert_eq!(&bytes[60..], &[2; 61]);
        // The peer consumed the spare FILL entry after the unwind. Closed admission must
        // leave even this legitimate advance unobserved across every receive entry point.
        port.rings.fill.publish_consumer(5);
        let rings = port.rings();
        let counters = port.counters();
        let charge = budget.used();
        for batch in [0, 4] {
            let counts = [
                port.receive_segments(batch, 0, |_, _| panic!("closed RX admitted"))
                    .unwrap(),
                port.receive_segments_with(batch, 0, |_, _, _| panic!("closed sink RX admitted"))
                    .unwrap(),
                port.receive_segments_owned(batch, 0, |_, _, _, _| {
                    panic!("closed retained RX admitted")
                })
                .unwrap(),
                port.receive(batch, |_| panic!("closed single RX admitted"))
                    .unwrap(),
            ];
            assert_eq!(counts, [0; 4]);
            assert_eq!(port.rx_consumer, 3);
            assert_eq!(port.fill_consumer, 4);
            assert_eq!(port.rings(), rings);
            assert_eq!(port.drain_state(), state);
            assert_eq!(port.counters(), counters);
            assert_eq!(port.retained_rx_count(), 0);
            assert_eq!(budget.used(), charge);
        }
        let retained = port.umem_bytes()
            + port.ledger.charged_bytes()
            + port._bookkeeping.as_ref().unwrap().bytes()
            + port.sidecar.reservation.as_ref().unwrap().bytes();
        drop(port);
        assert_eq!(budget.used(), retained);
    }

    #[test]
    fn batch_panic_closes_admission_and_retains_published_and_reserved_ownership() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        port.rings.tx.set_wakeup();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = port.transmit_batch(|port| {
                transmit_entry(port, 1, &drops).unwrap();
                port.transmit_with(TxClass::Control, 60, Retained::new(&drops), |_, _| {
                    panic!("writer unwound after a published prefix")
                })
                .unwrap();
            });
        }));
        assert!(panic.is_err());
        let state = port.drain_state();
        assert!(state.closed);
        assert_eq!(state.control_reserved, 1);
        assert_eq!(state.bulk_outstanding, 1);
        assert!(!state.ready_for_backend_teardown());
        assert!(!port.tx_batch_active);
        assert!(!port.tx_credit(TxClass::Control));
        assert_eq!(port.counters().wakeup_errors, 0);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        let retained = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
        drop(port);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(budget.used(), retained);
    }

    #[test]
    fn batch_is_finalized_before_the_owning_future_can_suspend_and_be_cancelled() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        port.rings.tx.set_wakeup();
        let mut future = Box::pin(async {
            let (work, kick) = port.transmit_batch(|port| transmit_entry(port, 3, &drops));
            work.unwrap();
            assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
            std::future::pending::<()>().await;
        });
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(future.as_mut().poll(&mut cx).is_pending());
        drop(future);
        assert!(port.drain_state().closed);
        assert!(!port.tx_batch_active);
        assert_eq!(port.outstanding().count(), 1);
        assert_eq!(port.counters().completed, 0);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        port.rings.cq.write(0, port.rings.tx.read(0).addr);
        port.rings.cq.publish_producer(1);
        assert_eq!(port.complete(|_| {}).unwrap(), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn distinct_device_scopes_finalize_both_orderings_after_inner_credit_failure() {
        for egress_first in [false, true] {
            let budget = MemoryBudget::new(1 << 20);
            let drops = Arc::new(AtomicUsize::new(0));
            let mut ports = [fake(config(), &budget), fake(config(), &budget)];
            let (first, second) = ports.split_at_mut(1);
            let (current, egress) = if egress_first {
                (&mut second[0], &mut first[0])
            } else {
                (&mut first[0], &mut second[0])
            };
            current.rings.tx.set_wakeup();
            egress.rings.tx.set_wakeup();
            let ((work, egress_kick), current_kick) = current.transmit_batch(|current| {
                transmit_entry(current, 1, &drops).unwrap();
                egress.transmit_batch(|egress| {
                    transmit_entry(egress, 2, &drops)?;
                    transmit_entry(egress, 3, &drops)
                })
            });
            assert_eq!(work.unwrap_err().kind(), io::ErrorKind::WouldBlock);
            for kick in [egress_kick, current_kick] {
                assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
            }
            for port in &ports {
                assert!(port.drain_state().closed);
                assert!(!port.tx_batch_active);
                assert_eq!(port.outstanding().count(), 1);
                assert_eq!(port.counters().submitted, 1);
                assert_eq!(port.counters().completed, 0);
            }
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn batch_rx_wakeup_failure_does_not_skip_the_published_tx_obligation() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        port.rings.fill.set_wakeup();
        port.rings.tx.set_wakeup();
        let (work, kick) = port.transmit_batch(|port| transmit_entry(port, 1, &drops));
        work.unwrap();
        assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert_eq!(port.counters().wakeup_errors, 2);
        assert_eq!(port.outstanding().count(), 1);
        assert_eq!(port.counters().completed, 0);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert!(!port.drain_state().ready_for_backend_teardown());
    }

    #[test]
    fn batch_close_and_socket_close_do_not_retire_a_partial_sg_completion() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(
            PortConfig {
                bulk_frames: 3,
                ring_size: 4,
                ..config()
            },
            &budget,
        );
        port.mtu = 9000;
        port.scatter_gather = true;
        let (work, kick) = port.transmit_batch(|port| {
            port.transmit_segments(TxClass::Bulk, &[&[7; 9000]], Retained::new(&drops))?;
            assert_eq!(port.close().bulk_outstanding, 3);
            port.close_socket();
            Ok::<_, io::Error>(())
        });
        work.unwrap();
        kick.unwrap();
        assert_eq!(port.counters().completed, 0);
        for index in 0..3 {
            port.rings.cq.write(index, port.rings.tx.read(index).addr);
            port.rings.cq.publish_producer(index + 1);
            assert_eq!(port.complete(|_| {}).unwrap(), 1);
            assert_eq!(drops.load(Ordering::Relaxed), usize::from(index == 2));
            assert_eq!(port.drain_state().ready_for_backend_teardown(), index == 2);
        }
    }
}
