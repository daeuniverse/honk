use super::*;

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
pub(super) enum TxOwnerSlot<L> {
    Free(u32),
    Occupied { remaining: u8, retained: L },
}

pub(super) struct Sidecar<L> {
    pub(super) slots: Box<[TxOwnerSlot<L>]>,
    free: u32,
    pub(super) reservation: Option<MemoryReservation>,
}

impl<L> Sidecar<L> {
    pub(super) fn new(config: PortConfig, budget: &Arc<MemoryBudget>) -> io::Result<Self> {
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

    pub(super) fn occupy(&mut self, retained: L, remaining: u8) -> u32 {
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

    pub(super) fn release(&mut self, index: u32) {
        let next = self.free;
        self.free = index;
        self.slots[index as usize] = TxOwnerSlot::Free(next);
    }

    #[cfg(test)]
    pub(super) fn occupied(&self) -> impl Iterator<Item = (&L, u8)> {
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

pub(super) struct PreparedTx {
    pub(super) lease: FrameLease,
    pub(super) length: u32,
    class: TxClass,
}

pub(super) struct TxReservation<'a, L> {
    pub(super) port: &'a mut Port<L>,
    pub(super) prepared: Option<PreparedTx>,
}

impl<L> TxReservation<'_, L> {
    pub(super) fn publish(mut self, retained: L) -> io::Result<()> {
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
            self.port.publish_tx_prefix();
            self.port.tx_batch_active = false;
            self.port.close();
        }
    }
}

impl<L> Port<L> {
    /// Publish complete TX chains at the batch boundary or an intervening observation.
    /// Work and final wakeup results are independent, including after work fails.
    /// Panicking work closes admission without I/O or releasing published owners.
    /// Scopes on the same Port must not nest or span an asynchronous suspension.
    pub fn transmit_batch<R>(&mut self, work: impl FnOnce(&mut Self) -> R) -> (R, io::Result<()>) {
        assert!(!self.tx_batch_active, "nested Port transmit scope");
        self.tx_cached_consumer.set(self.rings.tx.consumer());
        self.tx_batch_active = true;
        let guard = TxBatchGuard { port: self };
        let result = work(guard.port);
        guard.port.publish_tx_prefix();
        let rx = guard.port.kick_rx();
        let tx = if guard.port.counters.submitted != guard.port.counters.completed {
            guard.port.kick_tx()
        } else {
            Ok(())
        };
        guard.port.tx_batch_active = false;
        (result, rx.and(tx))
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
        let used = self.tx_used(count).map_err(|error| self.invalid(error))?;
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
        self.commit_tx_packet(class, count)
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

    pub fn tx_credit(&self, class: TxClass) -> bool {
        self.tx_packet_credit(class, 60)
    }

    /// Check the entire packet before taking its output owner; one task owns every mutation.
    pub fn tx_packet_credit(&self, class: TxClass, length: usize) -> bool {
        let Ok((_, count)) = self.tx_packet_layout(length) else {
            return false;
        };
        self.tx_used(count)
            .is_ok_and(|used| self.tx_chain_credit(class, count, used))
    }

    /// Conservative packet count for this port's largest admitted Ethernet frame.
    /// A zero count can still leave credit for one shorter packet.
    pub fn tx_packet_capacity(&mut self, class: TxClass) -> io::Result<usize> {
        let (_, count) = self.tx_packet_layout(self.mtu as usize + 22)?;
        let used = self.tx_used(count).map_err(|error| self.invalid(error))?;
        Ok(if self.closed.get() {
            0
        } else {
            self.tx_free[class_index(class)].min(self.config.ring_size as usize - used as usize)
                / count
        })
    }

    fn tx_used(&self, count: usize) -> io::Result<u32> {
        let size = self.config.ring_size;
        if self.tx_batch_active {
            let used = ring::distance(self.tx_producer, self.tx_cached_consumer.get(), size)?;
            if count <= (size - used) as usize {
                return Ok(used);
            }
        }
        let consumer = self.rings.tx.consumer();
        if self.tx_batch_active {
            self.tx_cached_consumer.set(consumer);
        }
        ring::distance(self.tx_producer, consumer, size)
    }

    pub(super) fn publish_tx_prefix(&self) {
        if self.tx_unpublished.get() {
            self.rings.tx.publish_producer(self.tx_producer);
            self.tx_unpublished.set(false);
        }
    }

    fn commit_tx_packet(&mut self, class: TxClass, count: usize) -> io::Result<()> {
        self.tx_free[class_index(class)] -= count;
        self.tx_producer = self.tx_producer.wrapping_add(count as u32);
        self.counters.submitted += count as u64;
        self.counters.published();
        if self.tx_batch_active {
            self.tx_unpublished.set(true);
            Ok(())
        } else {
            self.rings.tx.publish_producer(self.tx_producer);
            self.kick_tx()
        }
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

    pub(super) fn reserve_single_tx(&mut self, class: TxClass) -> io::Result<PreparedTx> {
        let used = self.tx_used(1).map_err(|error| self.invalid(error))?;
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
        self.commit_tx_packet(prepared.class, 1)
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
        self.publish_tx_prefix();
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
        let mut sorted = true;
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
                if owners != 0 && owner <= indices[owners - 1] {
                    sorted = false;
                }
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
        if !sorted {
            indices.sort_unstable();
        }
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
}

/// TX-only access during a borrowed receive callback; never releases or mutates RX storage.
pub struct TxSink<'a, L> {
    pub(super) port: &'a mut Port<L>,
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
