use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

static NEXT_PORT: AtomicU64 = AtomicU64::new(1);
pub(super) const NO_RX_SLOT: usize = usize::MAX;
const RETAINED_RX_SLOT_BYTES: usize = 1024;

/// Packet identity only; copies never release or expose frame storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedRxHandle {
    pub(super) port: u64,
    pub(super) port_generation: u64,
    pub(super) slot: u64,
    pub(super) generation: u64,
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
    pub(super) handle: RetainedRxHandle,
}

impl RxCompletion {
    pub fn handle(&self) -> RetainedRxHandle {
        self.handle
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RxPhase {
    Free,
    Held,
    CompletionPending,
}

pub(super) struct RetainedRxSlot {
    leases: [Option<FrameLease>; MAX_SEGMENTS],
    lengths: [u32; MAX_SEGMENTS],
    count: usize,
    metadata_len: usize,
    length: usize,
    pub(super) generation: u64,
    next_free: usize,
    pub(super) phase: RxPhase,
}

const _: () = {
    assert!(size_of::<RetainedRxHandle>() <= 32);
    assert!(size_of::<RxCompletion>() <= 32);
    assert!(size_of::<RetainedRxSlot>() <= RETAINED_RX_SLOT_BYTES);
    assert!(align_of::<RetainedRxSlot>() <= align_of::<u64>());
};

pub(super) struct RetainedRxSlots {
    pub(super) slots: Box<[RetainedRxSlot]>,
    pub(super) free: usize,
    port: u64,
    port_generation: u64,
    pub(super) held: usize,
    pub(super) completions: usize,
    pub(super) reservation: Option<MemoryReservation>,
}

impl RetainedRxSlots {
    pub(super) fn layout(config: PortConfig) -> io::Result<(usize, usize)> {
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

    pub(super) fn new(config: PortConfig, budget: &Arc<MemoryBudget>) -> io::Result<Self> {
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

impl<L> Port<L> {
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
}
