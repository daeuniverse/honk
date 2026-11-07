//! One AF_XDP socket and ledger owner. CQ returns retained outputs, not delivery receipts.
//!
//! UMEM and its reservation survive in-process close/drop. Occupied TX sidecars also survive
//! drop: socket close is not an observed deferred-DMA-release fence (B-UMEM-RELEASE).

use std::alloc::Layout;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::sync::Arc;

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
    pub rx: u64,
    pub fill: u64,
    pub invalid: u64,
    pub rx_kicks: u64,
    pub tx_kicks: u64,
    pub wakeup_errors: u64,
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
        .ok_or_else(|| io::Error::other("AF_XDP memory budget exhausted"))
}

fn class_index(class: TxClass) -> usize {
    match class {
        TxClass::Control => 0,
        TxClass::Bulk => 1,
    }
}

struct Sidecar<L> {
    slots: Box<[Option<(L, usize)>]>,
    reservation: Option<MemoryReservation>,
}

impl<L> Sidecar<L> {
    fn new(config: PortConfig, budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let count = config.control_frames + config.bulk_frames;
        let bytes = Layout::array::<Option<(L, usize)>>(count)
            .map_err(|_| invalid_config("TX sidecar extent overflow"))?
            .size();
        let reservation = reserve(budget, bytes)?;
        let slots = (0..count).map(|_| None).collect();
        Ok(Self {
            slots,
            reservation: Some(reservation),
        })
    }
}

impl<L> Drop for Sidecar<L> {
    fn drop(&mut self) {
        if self.slots.iter().any(Option::is_some) {
            // No CQ or device-release fence: dropping retained values would falsely dispose
            // core outputs. Keep their separately funded storage through process exit too.
            std::mem::forget(std::mem::replace(&mut self.slots, Box::new([])));
            std::mem::forget(self.reservation.take());
        }
    }
}

struct CompletedOwners<'a, L> {
    slots: &'a mut [Option<(L, usize)>],
    indices: &'a [usize],
}

impl<L> Drop for CompletedOwners<'_, L> {
    fn drop(&mut self) {
        for &index in self.indices {
            self.slots[index] = None;
        }
    }
}

struct PreparedTx {
    lease: FrameLease,
    slot: usize,
    length: u32,
    class: TxClass,
}

pub struct Port<L> {
    socket: Option<OwnedFd>,
    config: PortConfig,
    zerocopy: bool,
    mtu: u32,
    scatter_gather: bool,
    umem: Umem,
    rings: Rings,
    ledger: FrameLedger<u32>,
    sidecar: Sidecar<L>,
    rx_consumer: u32,
    tx_producer: u32,
    fill_producer: u32,
    fill_consumer: u32,
    cq_consumer: u32,
    tx_free: [usize; 2],
    closed: bool,
    tx_batch_active: bool,
    counters: PortCounters,
    _bookkeeping: MemoryReservation,
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

impl<L> Port<L> {
    pub fn open(
        ifindex: u32,
        queue: u32,
        mode: BindMode,
        config: PortConfig,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Self> {
        Self::open_device(ifindex, queue, mode, config, 1500, false, budget)
    }

    pub fn open_device(
        ifindex: u32,
        queue: u32,
        mode: BindMode,
        config: PortConfig,
        mtu: u32,
        scatter_gather: bool,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Self> {
        if !(68..=65535).contains(&mtu)
            || (mtu as usize + 22 > FRAME_SIZE - 256 - METADATA_SIZE && !scatter_gather)
        {
            return Err(invalid_config("MTU requires negotiated scatter/gather"));
        }
        config.validate()?;
        if ifindex == 0 {
            return Err(invalid_config("AF_XDP requires a nonzero ifindex"));
        }
        crate::device::validate_queue(ifindex, queue)?;
        let bookkeeping = reserve(budget, size_of::<Self>() - size_of::<FrameLedger<u32>>())?;
        let ledger = FrameLedger::new(config.frame_config(), budget).map_err(io::Error::other)?;
        let sidecar = Sidecar::new(config, budget)?;
        let umem = Umem::map(config.umem_bytes()?, budget)?;
        let (socket, rings, zerocopy) =
            ring::open(ifindex, queue, mode, config, scatter_gather, &umem, budget)?;
        Ok(Self {
            socket: Some(socket),
            config,
            zerocopy,
            mtu,
            scatter_gather,
            umem,
            rings,
            ledger,
            sidecar,
            rx_consumer: 0,
            tx_producer: 0,
            fill_producer: 0,
            fill_consumer: 0,
            cq_consumer: 0,
            tx_free: [config.control_frames, config.bulk_frames],
            closed: false,
            tx_batch_active: false,
            counters: PortCounters::default(),
            _bookkeeping: bookkeeping,
        })
    }

    /// Borrow a packet and, when required by the selected capture mode, its producer metadata.
    /// `Ok(0)` may leave RX queued pending FILL consumer publication; callers must retry later.
    pub fn receive_segments(
        &mut self,
        batch: usize,
        require_metadata: bool,
        mut f: impl FnMut(&[&[u8]], &[u8]),
    ) -> io::Result<usize> {
        self.receive_segments_with(batch, require_metadata, |segments, metadata, _| {
            f(segments, metadata)
        })
    }

    /// The restricted sink permits same-port forwarding without releasing borrowed RX frames.
    /// `Ok(0)` may leave RX queued pending FILL consumer publication; callers must retry later.
    /// A wire-only capture must select false up front; missing metadata is never a fallback.
    pub fn receive_segments_with(
        &mut self,
        batch: usize,
        require_metadata: bool,
        mut f: impl FnMut(&[&[u8]], &[u8], &mut TxSink<'_, L>),
    ) -> io::Result<usize> {
        self.observe_fill()?;
        let available = ring::distance(
            self.rings.rx.producer(),
            self.rx_consumer,
            self.config.ring_size,
        )
        .map_err(|error| self.invalid(error))?;
        self.observe_fill()?;
        let mut consumed = 0;
        let mut packets = 0;
        while consumed < available && packets < batch {
            let mut descriptors = [Descriptor {
                addr: 0,
                len: 0,
                options: 0,
            }; MAX_SEGMENTS];
            let mut count = 0;
            let mut length = 0usize;
            let mut ready = true;
            loop {
                if consumed + count as u32 == available {
                    if available == self.config.ring_size {
                        return Err(
                            self.invalid(io::Error::other("unterminated RX chain fills ring"))
                        );
                    }
                    self.rings.rx.publish_consumer(self.rx_consumer);
                    self.refill()?;
                    return Ok(packets);
                }
                if count == MAX_SEGMENTS {
                    return Err(self.invalid(io::Error::other("RX chain exceeds segment limit")));
                }
                let descriptor = self
                    .rings
                    .rx
                    .read(self.rx_consumer.wrapping_add(count as u32));
                if descriptor.len == 0
                    || descriptor.options & !1 != 0
                    || (descriptor.options != 0 && !self.scatter_gather)
                {
                    return Err(self.invalid(io::Error::other("invalid RX chain descriptor")));
                }
                length += descriptor.len as usize;
                if length > self.mtu as usize + 22 {
                    return Err(self.invalid(io::Error::other("RX chain exceeds device MTU")));
                }
                if descriptors[..count].iter().any(|previous| {
                    previous.addr / FRAME_SIZE as u64 == descriptor.addr / FRAME_SIZE as u64
                }) {
                    return Err(self.invalid(io::Error::other("duplicate RX frame in chain")));
                }
                // xsk_flush publishes RX before the corresponding FILL consumer advance.
                ready &= self
                    .ledger
                    .rx_ready(descriptor.addr, descriptor.len as usize)
                    .map_err(io::Error::other)
                    .map_err(|error| self.invalid(error))?;
                if require_metadata
                    && count == 0
                    && descriptor.addr % (FRAME_SIZE as u64) < METADATA_SIZE as u64
                {
                    return Err(self.invalid(io::Error::other("RX metadata headroom missing")));
                }
                descriptors[count] = descriptor;
                count += 1;
                if descriptor.options & 1 == 0 {
                    break;
                }
            }
            let first = descriptors[0].addr;
            let metadata_ptr = if require_metadata {
                Some(
                    self.umem
                        .frame_pointer(first - METADATA_SIZE as u64, METADATA_SIZE)
                        .map_err(|error| self.invalid(error))?,
                )
            } else {
                None
            };
            if !ready {
                break;
            }
            let result = (|| {
                let mut leases = [None; MAX_SEGMENTS];
                for (index, descriptor) in descriptors[..count].iter().enumerate() {
                    leases[index] = Some(
                        self.ledger
                            .receive_rx(descriptor.addr, descriptor.len as usize)
                            .map_err(io::Error::other)?,
                    );
                }
                // SAFETY: every RX chunk is ledger-leased until this callback returns. TxSink
                // can write only the disjoint TX partition and cannot receive/refill/release RX.
                let metadata = match metadata_ptr {
                    Some(pointer) => unsafe { std::slice::from_raw_parts(pointer, METADATA_SIZE) },
                    None => &[],
                };
                let mut segments: [&[u8]; MAX_SEGMENTS] = [&[]; MAX_SEGMENTS];
                for (index, descriptor) in descriptors[..count].iter().enumerate() {
                    let pointer = self
                        .umem
                        .frame_pointer(descriptor.addr, descriptor.len as usize)?;
                    // SAFETY: the complete RX chain was acquired above, disjoint from TX storage.
                    segments[index] =
                        unsafe { std::slice::from_raw_parts(pointer, descriptor.len as usize) };
                }
                f(&segments[..count], metadata, &mut TxSink { port: self });
                for lease in leases[..count].iter_mut() {
                    self.ledger
                        .relinquish_rx(lease.take().expect("acquired chain"))
                        .map_err(io::Error::other)?;
                }
                Ok(())
            })();
            if let Err(error) = result {
                return Err(self.invalid(error));
            }
            self.rx_consumer = self.rx_consumer.wrapping_add(count as u32);
            consumed += count as u32;
            self.counters.rx += 1;
            packets += 1;
        }
        self.rings.rx.publish_consumer(self.rx_consumer);
        self.refill()?;
        Ok(packets)
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
        let owner = self
            .sidecar
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| io::Error::other("no TX sidecar"))?;
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
        self.sidecar.slots[owner] = Some((retained, count));
        for (index, lease) in leases[..count].iter_mut().enumerate() {
            let bytes = (wire_length - index * FRAME_SIZE).min(FRAME_SIZE);
            let address = self
                .ledger
                .submit_tx(lease.take().expect("reserved chain"), bytes, owner as u32)
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
        if self.tx_batch_active {
            Ok(())
        } else {
            self.kick_tx()
        }
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
        if self.closed {
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
        self.observe_fill()?;
        let producer = self.rings.rx.producer();
        let available = ring::distance(producer, self.rx_consumer, self.config.ring_size)
            .map_err(|error| self.invalid(error))?;
        self.observe_fill()?;
        let mut count = 0;
        for _ in 0..(available as usize).min(batch) {
            let descriptor = self.rings.rx.read(self.rx_consumer);
            match self.receive_one(descriptor, &mut f) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    self.rings.rx.publish_consumer(self.rx_consumer);
                    return Err(self.invalid(error));
                }
            }
            self.rx_consumer = self.rx_consumer.wrapping_add(1);
            self.counters.rx += 1;
            count += 1;
        }
        self.rings.rx.publish_consumer(self.rx_consumer);
        self.refill()?;
        Ok(count)
    }

    fn receive_one(
        &mut self,
        descriptor: Descriptor,
        f: &mut impl FnMut(&[u8]),
    ) -> io::Result<bool> {
        if descriptor.options != 0 || descriptor.len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported or empty RX descriptor",
            ));
        }
        let length = usize::try_from(descriptor.len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "RX length overflow"))?;
        if !self
            .ledger
            .rx_ready(descriptor.addr, length)
            .map_err(io::Error::other)?
        {
            return Ok(false);
        }
        let lease = self
            .ledger
            .receive_rx(descriptor.addr, length)
            .map_err(io::Error::other)?;
        f(self.umem.frame(descriptor.addr, length)?);
        self.ledger.relinquish_rx(lease).map_err(io::Error::other)?;
        Ok(true)
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
        Ok(if self.closed {
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
        !self.closed
            && self.tx_free[class_index(class)] >= count
            && self.config.ring_size as usize - used as usize >= count
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
        let used = ring::distance(
            self.tx_producer,
            self.rings.tx.consumer(),
            self.config.ring_size,
        )
        .map_err(|error| self.invalid(error))?;
        if used == self.config.ring_size {
            return Err(io::Error::other(LedgerError::NoDescriptor));
        }
        let lease = self.ledger.reserve_tx(class).map_err(io::Error::other)?;
        let slot = self
            .sidecar
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| io::Error::other("no TX sidecar"));
        let result = (|| {
            let slot = slot?;
            let length = self.umem.write_frame(lease.address(), header, l3)?;
            Ok(PreparedTx {
                lease,
                slot,
                length,
                class,
            })
        })();
        match result {
            Ok(prepared) => Ok(prepared),
            Err(error) => {
                self.ledger.cancel_tx(lease).map_err(io::Error::other)?;
                Err(self.invalid(error))
            }
        }
    }

    fn publish_tx(&mut self, prepared: PreparedTx, retained: L) -> io::Result<()> {
        self.sidecar.slots[prepared.slot] = Some((retained, 1));
        let owner = u32::try_from(prepared.slot)
            .map_err(|_| self.invalid(io::Error::other("TX sidecar index overflow")))?;
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
                Ok(owner) => owner as usize,
                Err(error) => {
                    failure = Some(self.invalid(io::Error::other(error)));
                    break;
                }
            };
            let Some((_, remaining)) = self.sidecar.slots.get_mut(owner).and_then(Option::as_mut)
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
            slots: &mut self.sidecar.slots,
            indices,
        };
        {
            let mut outputs: [Option<&mut L>; 64] = std::array::from_fn(|_| None);
            let mut slots = &mut *cleanup.slots;
            let mut start = 0;
            for (output, &index) in outputs.iter_mut().zip(cleanup.indices) {
                let (_, suffix) = slots.split_at_mut(index - start);
                let (slot, suffix) = suffix.split_first_mut().expect("completed sidecar index");
                *output = Some(&mut slot.as_mut().expect("completed TX sidecar").0);
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

    pub fn outstanding(&self) -> impl Iterator<Item = OutstandingTx<u32>> + '_ {
        self.ledger.outstanding_tx()
    }

    pub fn drain_state(&self) -> DrainState {
        self.ledger.drain_state()
    }

    pub fn close(&mut self) -> DrainState {
        self.closed = true;
        self.ledger.close()
    }

    pub fn counters(&self) -> PortCounters {
        self.counters
    }

    /// Retry published TX/CQ work or RX blocked by a partial chain/FILL visibility.
    /// A populated FILL ring without queued RX is an ordinary idle receive reservation.
    pub fn needs_service_retry(&self) -> bool {
        self.counters.submitted != self.counters.completed
            || self.tx_producer != self.rings.tx.consumer()
            || self.rings.rx.producer() != self.rx_consumer
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
        Port {
            socket: None,
            config,
            zerocopy: false,
            mtu: 1500,
            scatter_gather: false,
            umem: Umem::fake(config.umem_bytes().unwrap(), budget),
            rings: Rings::fake(config.ring_size, budget),
            ledger: FrameLedger::new(config.frame_config(), budget).unwrap(),
            sidecar: Sidecar::new(config, budget).unwrap(),
            rx_consumer: 0,
            tx_producer: 0,
            fill_producer: 0,
            fill_consumer: 0,
            cq_consumer: 0,
            tx_free: [config.control_frames, config.bulk_frames],
            closed: false,
            tx_batch_active: false,
            counters: PortCounters::default(),
            _bookkeeping: bookkeeping,
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
                port.receive_segments(1, false, |_, _| panic!("FILL still owns the frame"))
                    .unwrap(),
                0
            );
            port.rings.fill.publish_consumer(1);
            assert_eq!(
                port.receive_segments(1, false, |segments, metadata| {
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
            port.receive_segments(1, true, |_, _| panic!("missing required metadata"))
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
        assert_eq!(port.sidecar.slots.iter().flatten().count(), 1);
        assert_eq!(port.sidecar.slots.iter().flatten().next().unwrap().1, 1);
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
            port.receive_segments_with(1, true, |_, _, _| panic!("FILL consumer not published"))
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
            port.receive_segments(1, true, |_, _| panic!(
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
            port.receive_segments_with(1, true, |parts, metadata, tx| {
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
            port.receive_segments(1, true, |_, _| panic!("duplicate RX chain"))
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
                port.receive_segments_with(1, true, |_, _, _| panic!("invalid RX chain borrowed"))
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
            port.receive_segments(1, true, |_, _| panic!("partial RX packet"))
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
            port.receive_segments_with(1, true, |parts, metadata, tx| {
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
        assert!(port.sidecar.slots.iter().all(Option::is_none));
        assert!(port.tx_packet_credit(TxClass::Bulk, 9000));
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
            _ => unreachable!(),
        }
    }

    #[test]
    fn batch_tx_entries_publish_the_whole_prefix_before_terminal_wakeup() {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(
            PortConfig {
                bulk_frames: 4,
                ring_size: 8,
                ..config()
            },
            &budget,
        );
        port.rings.tx.set_wakeup();
        let (work, kick) = port.transmit_batch(|port| {
            for entry in 0..4 {
                transmit_entry(port, entry, &drops)?;
            }
            assert!(!port.drain_state().closed);
            assert_eq!(port.rings().tx_producer, 4);
            Ok::<_, io::Error>(())
        });
        work.unwrap();
        assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert!(port.drain_state().closed);
        assert!(!port.tx_batch_active);
        assert_eq!(port.outstanding().count(), 4);
        port.rings.tx.publish_consumer(4);
        assert_eq!(port.complete(|_| {}).unwrap(), 0);
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
            assert_eq!(port.outstanding().count(), 1);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            port.rings.cq.write(0, port.rings.tx.read(0).addr);
            port.rings.cq.publish_producer(1);
            assert_eq!(port.complete(|_| {}).unwrap(), 1);
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
            port.receive_segments_with(2, false, |parts, _, tx| {
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
