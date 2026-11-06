//! Bounded ownership bookkeeping for backend-owned frames, not a device driver.
//!
//! The backend owns and separately charges frame bytes/UMEM, validates packet lengths and
//! platform descriptor metadata, and performs ring I/O. This ledger charges only its fixed
//! metadata. Reserve TX credit before pulling protocol output; cancel an unused reservation
//! or submit it exactly once with the original owner. A CQ address returns that saved owner,
//! not evidence of peer delivery. CQ has no generation: an invented stale completion after
//! address reuse cannot be distinguished from a real completion of the new submission.
//! Route completions from the original backend CQ; addresses alone do not identify a pool.

use std::alloc::Layout;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use honk_netstack::{MemoryBudget, MemoryReservation};

static NEXT_POOL: AtomicU64 = AtomicU64::new(1);

/// Contiguous backend frame slots, partitioned as RX, control TX, then bulk TX.
/// Addresses are backend descriptor-domain offsets, not automatically userspace pointers.
/// Platform-specific metadata decoding and multi-buffer/SG handling stay outside this ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameConfig {
    pub base_address: u64,
    pub frame_size: usize,
    pub rx_frames: usize,
    pub control_frames: usize,
    pub bulk_frames: usize,
    pub fill_capacity: usize,
    pub rx_capacity: usize,
    pub control_descriptors: usize,
    pub bulk_descriptors: usize,
    pub tx_capacity: usize,
    pub completion_capacity: usize,
}

impl FrameConfig {
    fn validate(self) -> Result<usize, LedgerError> {
        if self.frame_size == 0 {
            return Err(LedgerError::InvalidConfig("zero frame size"));
        }
        if self.control_frames == 0 || self.bulk_frames == 0 {
            return Err(LedgerError::InvalidConfig("empty frame partition"));
        }
        if (self.fill_capacity == 0) != (self.rx_frames == 0) || self.fill_capacity > self.rx_frames
        {
            return Err(LedgerError::InvalidConfig(
                "FILL capacity exceeds RX partition",
            ));
        }
        if (self.rx_capacity == 0) != (self.rx_frames == 0) || self.rx_capacity > self.rx_frames {
            return Err(LedgerError::InvalidConfig(
                "RX capacity exceeds RX partition",
            ));
        }
        if self.control_descriptors == 0 || self.control_descriptors > self.control_frames {
            return Err(LedgerError::InvalidConfig("control descriptor capacity"));
        }
        if self.bulk_descriptors == 0 || self.bulk_descriptors > self.bulk_frames {
            return Err(LedgerError::InvalidConfig("bulk descriptor capacity"));
        }
        let descriptors = self
            .control_descriptors
            .checked_add(self.bulk_descriptors)
            .ok_or(LedgerError::InvalidConfig("descriptor count overflow"))?;
        if descriptors > self.tx_capacity || descriptors > self.completion_capacity {
            return Err(LedgerError::InvalidConfig(
                "TX/CQ capacity below descriptor commitments",
            ));
        }
        let frames = self
            .rx_frames
            .checked_add(self.control_frames)
            .and_then(|n| n.checked_add(self.bulk_frames))
            .ok_or(LedgerError::InvalidConfig("frame count overflow"))?;
        let bytes = frames
            .checked_mul(self.frame_size)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(LedgerError::InvalidConfig("frame address extent overflow"))?;
        self.base_address
            .checked_add(bytes)
            .ok_or(LedgerError::InvalidConfig("frame address extent overflow"))?;
        Ok(frames)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxClass {
    Control,
    Bulk,
}

impl TxClass {
    fn index(self) -> usize {
        match self {
            Self::Control => 0,
            Self::Bulk => 1,
        }
    }
}

/// A CPU-side capability. Copies are harmless: each transition checks pool, generation and state.
/// Dropping it does not cancel a reservation or release backend ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "relinquish RX, or submit/cancel the reservation explicitly"]
pub struct FrameLease {
    pool: u64,
    index: usize,
    generation: u64,
    address: u64,
    capacity: usize,
}

impl FrameLease {
    /// TX/FILL slot base, or the actual RX data address after backend headroom.
    pub fn address(self) -> u64 {
        self.address
    }

    /// Remaining bytes in this slot from `address()`, not the received packet length.
    pub fn capacity(self) -> usize {
        self.capacity
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerError {
    InvalidConfig(&'static str),
    BudgetExhausted,
    PoolIdentityExhausted,
    Closed,
    NoFrame,
    NoDescriptor,
    NoFillCredit,
    InvalidFillConsumption,
    NoRxCredit,
    InvalidAddress,
    InvalidLength,
    ForeignLease,
    StaleLease,
    WrongState,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for LedgerError {}

/// Local ownership only. Posted FILL frames still belong to the backend until returned as RX.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DrainState {
    pub closed: bool,
    pub rx_free: usize,
    pub fill_reserved: usize,
    /// Backend-owned RX frames, including both queued and consumed FILL descriptors.
    pub fill_posted: usize,
    /// Published FILL descriptors not yet observed consumed; a subset of `fill_posted`.
    pub fill_queued: usize,
    pub rx_leased: usize,
    pub control_free: usize,
    pub control_reserved: usize,
    pub control_outstanding: usize,
    pub bulk_free: usize,
    pub bulk_reserved: usize,
    pub bulk_outstanding: usize,
    pub exhausted_frames: usize,
}

impl DrainState {
    /// No CPU leases, reservations or device-owned frames remain; not a delivery receipt.
    pub fn is_drained(self) -> bool {
        self.cpu_tx_drained() && self.fill_posted == 0
    }

    /// Admission closed and CPU/TX drained. Posted FILL may remain until backend unregister.
    /// This does not itself authorize dropping backend storage or prove unregister completed.
    pub fn ready_for_backend_teardown(self) -> bool {
        self.closed && self.cpu_tx_drained()
    }

    fn cpu_tx_drained(self) -> bool {
        self.fill_reserved == 0
            && self.rx_leased == 0
            && self.control_reserved == 0
            && self.control_outstanding == 0
            && self.bulk_reserved == 0
            && self.bulk_outstanding == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutstandingTx<O> {
    pub address: u64,
    pub class: TxClass,
    pub owner: O,
}

#[derive(Clone, Copy)]
enum Phase<O> {
    Free,
    FillReserved,
    FillPosted,
    FillConsumed,
    RxLeased,
    TxReserved,
    TxOutstanding(O),
    Exhausted,
}

#[derive(Clone, Copy)]
struct Slot<O> {
    generation: u64,
    phase: Phase<O>,
}

#[derive(Clone, Copy)]
struct FreePartition {
    start: usize,
    len: usize,
}

/// Fixed-capacity ledger. All mutation requires exclusive access; no packet-path allocation.
/// Drop releases metadata only, even when `drain_state()` still reports backend ownership.
/// Keep backend storage and its separate reservation alive until the backend actually drains.
pub struct FrameLedger<O: Copy> {
    config: FrameConfig,
    pool: u64,
    slots: Box<[Slot<O>]>,
    free_indices: Box<[usize]>,
    fill_queue: Box<[usize]>,
    fill_head: usize,
    fill_len: usize,
    free: [FreePartition; 3],
    fill_used: usize,
    rx_leased: usize,
    tx_used: [usize; 2],
    closed: bool,
    // Declared after the arrays so their storage is freed before its charge is refunded.
    metadata: MemoryReservation,
}

impl<O: Copy> FrameLedger<O> {
    /// Includes this ledger and its fixed arrays, never the backend's frame storage.
    pub fn metadata_bytes(config: FrameConfig) -> Result<usize, LedgerError> {
        let frames = config.validate()?;
        let states = Layout::array::<Slot<O>>(frames)
            .map_err(|_| LedgerError::InvalidConfig("state array size overflow"))?;
        let free = Layout::array::<usize>(frames)
            .map_err(|_| LedgerError::InvalidConfig("free array size overflow"))?;
        let fill = Layout::array::<usize>(config.fill_capacity)
            .map_err(|_| LedgerError::InvalidConfig("FILL queue size overflow"))?;
        states
            .size()
            .checked_add(free.size())
            .and_then(|n| n.checked_add(fill.size()))
            .and_then(|n| n.checked_add(size_of::<Self>()))
            .ok_or(LedgerError::InvalidConfig("metadata size overflow"))
    }

    pub fn new(config: FrameConfig, budget: &Arc<MemoryBudget>) -> Result<Self, LedgerError> {
        let bytes = Self::metadata_bytes(config)?;
        let frames = config.rx_frames + config.control_frames + config.bulk_frames;
        let metadata = budget.reserve(bytes).ok_or(LedgerError::BudgetExhausted)?;
        let pool = allocate_pool(&NEXT_POOL).ok_or(LedgerError::PoolIdentityExhausted)?;
        let slots = vec![
            Slot {
                generation: 0,
                phase: Phase::Free
            };
            frames
        ]
        .into_boxed_slice();
        let free_indices = (0..frames).collect();
        let fill_queue = vec![0; config.fill_capacity].into_boxed_slice();
        Ok(Self {
            config,
            pool,
            slots,
            free_indices,
            fill_queue,
            fill_head: 0,
            fill_len: 0,
            free: [
                FreePartition {
                    start: 0,
                    len: config.rx_frames,
                },
                FreePartition {
                    start: config.rx_frames,
                    len: config.control_frames,
                },
                FreePartition {
                    start: config.rx_frames + config.control_frames,
                    len: config.bulk_frames,
                },
            ],
            fill_used: 0,
            rx_leased: 0,
            tx_used: [0; 2],
            closed: false,
            metadata,
        })
    }

    pub fn charged_bytes(&self) -> usize {
        self.metadata.bytes()
    }

    /// Reserve a receive frame and FILL credit before writing a backend FILL descriptor.
    pub fn reserve_fill(&mut self) -> Result<FrameLease, LedgerError> {
        self.check_open()?;
        if self.fill_used == self.config.fill_capacity {
            return Err(LedgerError::NoFillCredit);
        }
        let lease = self.reserve_frame(0, Phase::FillReserved)?;
        self.fill_used += 1;
        Ok(lease)
    }

    /// Call only when the backend will publish this reserved frame to FILL.
    pub fn submit_fill(&mut self, lease: FrameLease) -> Result<u64, LedgerError> {
        let index = self.check_lease(lease)?;
        if !matches!(self.slots[index].phase, Phase::FillReserved) {
            return Err(LedgerError::WrongState);
        }
        let tail = (self.fill_head + self.fill_len) % self.fill_queue.len();
        self.fill_queue[tail] = index;
        self.fill_len += 1;
        self.slots[index].phase = Phase::FillPosted;
        Ok(lease.address)
    }

    /// Observe this backend's actual FILL consumer advance, in published FIFO order.
    /// Return descriptor credit only: consumed frames remain backend-owned until actual RX.
    /// The caller must report each advance once; this is not an RX or teardown observation.
    pub fn consume_fill(&mut self, count: usize) -> Result<(), LedgerError> {
        if count > self.fill_len {
            return Err(LedgerError::InvalidFillConsumption);
        }
        for _ in 0..count {
            let index = self.fill_queue[self.fill_head];
            self.slots[index].phase = Phase::FillConsumed;
            self.fill_head += 1;
            if self.fill_head == self.fill_queue.len() {
                self.fill_head = 0;
            }
        }
        self.fill_len -= count;
        self.fill_used -= count;
        Ok(())
    }

    /// Only an unpublished FILL reservation can be cancelled.
    pub fn cancel_fill(&mut self, lease: FrameLease) -> Result<(), LedgerError> {
        let index = self.check_lease(lease)?;
        if !matches!(self.slots[index].phase, Phase::FillReserved) {
            return Err(LedgerError::WrongState);
        }
        self.fill_used -= 1;
        self.release_frame(index);
        Ok(())
    }

    /// Validate RX geometry and ownership without acquiring a lease or spending RX credit.
    /// `false` means this valid frame still awaits observed FILL consumer publication.
    pub fn rx_ready(&self, address: u64, length: usize) -> Result<bool, LedgerError> {
        let (index, headroom) = self.address_parts(address)?;
        if length == 0 || length > self.config.frame_size - headroom {
            return Err(LedgerError::InvalidLength);
        }
        match self.slots[index].phase {
            Phase::FillPosted => Ok(false),
            Phase::FillConsumed => Ok(true),
            _ => Err(LedgerError::WrongState),
        }
    }

    /// Accept one actual backend RX descriptor, including any data headroom within its slot.
    /// Observe its FILL consumption first. On error, retain the RX entry.
    pub fn receive_rx(&mut self, address: u64, length: usize) -> Result<FrameLease, LedgerError> {
        let (index, headroom) = self.address_parts(address)?;
        let capacity = self.config.frame_size - headroom;
        if length == 0 || length > capacity {
            return Err(LedgerError::InvalidLength);
        }
        if !matches!(self.slots[index].phase, Phase::FillConsumed) {
            return Err(LedgerError::WrongState);
        }
        if self.rx_leased == self.config.rx_capacity {
            return Err(LedgerError::NoRxCredit);
        }
        // reserve_frame leaves this generation available before a frame can reach FILL.
        self.slots[index].generation = self.slots[index]
            .generation
            .checked_add(1)
            .expect("RX generation reserved before FILL publication");
        self.slots[index].phase = Phase::RxLeased;
        self.rx_leased += 1;
        Ok(FrameLease {
            address,
            capacity,
            ..self.lease(index)
        })
    }

    /// Recycle only after the receiver has relinquished every use of this backend frame.
    pub fn relinquish_rx(&mut self, lease: FrameLease) -> Result<(), LedgerError> {
        let index = self.check_lease(lease)?;
        if !matches!(self.slots[index].phase, Phase::RxLeased) {
            return Err(LedgerError::WrongState);
        }
        self.rx_leased -= 1;
        self.release_frame(index);
        Ok(())
    }

    /// Reserve both a class-owned frame and descriptor before pulling protocol output.
    pub fn reserve_tx(&mut self, class: TxClass) -> Result<FrameLease, LedgerError> {
        self.check_open()?;
        let class_index = class.index();
        let limit = match class {
            TxClass::Control => self.config.control_descriptors,
            TxClass::Bulk => self.config.bulk_descriptors,
        };
        if self.tx_used[class_index] == limit {
            return Err(LedgerError::NoDescriptor);
        }
        let lease = self.reserve_frame(class_index + 1, Phase::TxReserved)?;
        self.tx_used[class_index] += 1;
        Ok(lease)
    }

    /// Cancel a pull which produced nothing, never a submitted backend descriptor.
    pub fn cancel_tx(&mut self, lease: FrameLease) -> Result<(), LedgerError> {
        let index = self.check_lease(lease)?;
        if !matches!(self.slots[index].phase, Phase::TxReserved) {
            return Err(LedgerError::WrongState);
        }
        let class = self.tx_class(index).index();
        self.tx_used[class] -= 1;
        self.release_frame(index);
        Ok(())
    }

    /// Save the original incarnation owner when publishing one nonempty single-buffer TX.
    /// A publication failure after this transition cannot be treated as cancellation.
    pub fn submit_tx(
        &mut self,
        lease: FrameLease,
        length: usize,
        owner: O,
    ) -> Result<u64, LedgerError> {
        let index = self.check_lease(lease)?;
        if !matches!(self.slots[index].phase, Phase::TxReserved) {
            return Err(LedgerError::WrongState);
        }
        if length == 0 || length > lease.capacity {
            return Err(LedgerError::InvalidLength);
        }
        self.slots[index].phase = Phase::TxOutstanding(owner);
        Ok(lease.address)
    }

    /// Process an actual CQ address once. There is no CQ generation to validate.
    pub fn complete_tx(&mut self, address: u64) -> Result<O, LedgerError> {
        let index = self.address_index(address)?;
        self.release_outstanding(index)
    }

    /// Release a CPU consumer's output lease after its actual I/O or disposal.
    /// This is not a CQ observation; device adapters must retain the lease until safe.
    pub fn release_tx(&mut self, lease: FrameLease) -> Result<O, LedgerError> {
        let index = self.check_lease(lease)?;
        self.release_outstanding(index)
    }

    fn release_outstanding(&mut self, index: usize) -> Result<O, LedgerError> {
        let Phase::TxOutstanding(owner) = self.slots[index].phase else {
            return Err(LedgerError::WrongState);
        };
        let class = self.tx_class(index).index();
        self.tx_used[class] -= 1;
        self.release_frame(index);
        Ok(owner)
    }

    /// Stop new reservations without cancelling admitted work or inventing completions.
    /// Existing reservations may still be submitted or cancelled while the backend drains.
    pub fn close(&mut self) -> DrainState {
        self.closed = true;
        self.drain_state()
    }

    pub fn drain_state(&self) -> DrainState {
        let mut state = DrainState {
            closed: self.closed,
            ..DrainState::default()
        };
        for (index, slot) in self.slots.iter().enumerate() {
            match slot.phase {
                Phase::Free => match self.partition(index) {
                    0 => state.rx_free += 1,
                    1 => state.control_free += 1,
                    _ => state.bulk_free += 1,
                },
                Phase::FillReserved => state.fill_reserved += 1,
                Phase::FillPosted => {
                    state.fill_posted += 1;
                    state.fill_queued += 1;
                }
                Phase::FillConsumed => state.fill_posted += 1,
                Phase::RxLeased => state.rx_leased += 1,
                Phase::TxReserved => match self.tx_class(index) {
                    TxClass::Control => state.control_reserved += 1,
                    TxClass::Bulk => state.bulk_reserved += 1,
                },
                Phase::TxOutstanding(_) => match self.tx_class(index) {
                    TxClass::Control => state.control_outstanding += 1,
                    TxClass::Bulk => state.bulk_outstanding += 1,
                },
                Phase::Exhausted => state.exhausted_frames += 1,
            }
        }
        state
    }

    /// Bounded inspection of owners still held by actual submitted TX, without reclaiming them.
    pub fn outstanding_tx(&self) -> impl Iterator<Item = OutstandingTx<O>> + '_ {
        self.slots.iter().enumerate().filter_map(|(index, slot)| {
            let Phase::TxOutstanding(owner) = slot.phase else {
                return None;
            };
            Some(OutstandingTx {
                address: self.address(index),
                class: self.tx_class(index),
                owner,
            })
        })
    }

    fn check_open(&self) -> Result<(), LedgerError> {
        if self.closed {
            Err(LedgerError::Closed)
        } else {
            Ok(())
        }
    }

    fn check_lease(&self, lease: FrameLease) -> Result<usize, LedgerError> {
        if lease.pool != self.pool {
            return Err(LedgerError::ForeignLease);
        }
        let slot = self.slots.get(lease.index).ok_or(LedgerError::StaleLease)?;
        if slot.generation != lease.generation {
            return Err(LedgerError::StaleLease);
        }
        Ok(lease.index)
    }

    fn reserve_frame(
        &mut self,
        partition: usize,
        phase: Phase<O>,
    ) -> Result<FrameLease, LedgerError> {
        let required_generations = if partition == 0 { 2 } else { 1 };
        while self.free[partition].len != 0 {
            self.free[partition].len -= 1;
            let index = self.free_indices[self.free[partition].start + self.free[partition].len];
            let slot = &mut self.slots[index];
            if slot.generation.checked_add(required_generations).is_none() {
                slot.phase = Phase::Exhausted;
                continue;
            }
            slot.generation += 1;
            slot.phase = phase;
            return Ok(self.lease(index));
        }
        Err(LedgerError::NoFrame)
    }

    fn release_frame(&mut self, index: usize) {
        let partition = self.partition(index);
        let required_generations = if partition == 0 { 2 } else { 1 };
        if self.slots[index]
            .generation
            .checked_add(required_generations)
            .is_none()
        {
            self.slots[index].phase = Phase::Exhausted;
        } else {
            self.slots[index].phase = Phase::Free;
            let free = &mut self.free[partition];
            self.free_indices[free.start + free.len] = index;
            free.len += 1;
        }
    }

    fn lease(&self, index: usize) -> FrameLease {
        FrameLease {
            pool: self.pool,
            index,
            generation: self.slots[index].generation,
            address: self.address(index),
            capacity: self.config.frame_size,
        }
    }

    fn address(&self, index: usize) -> u64 {
        self.config.base_address + (index * self.config.frame_size) as u64
    }

    fn address_index(&self, address: u64) -> Result<usize, LedgerError> {
        let (index, headroom) = self.address_parts(address)?;
        if headroom != 0 {
            return Err(LedgerError::InvalidAddress);
        }
        Ok(index)
    }

    fn address_parts(&self, address: u64) -> Result<(usize, usize), LedgerError> {
        let offset = address
            .checked_sub(self.config.base_address)
            .ok_or(LedgerError::InvalidAddress)?;
        let offset = usize::try_from(offset).map_err(|_| LedgerError::InvalidAddress)?;
        let index = offset / self.config.frame_size;
        if index >= self.slots.len() {
            return Err(LedgerError::InvalidAddress);
        }
        Ok((index, offset % self.config.frame_size))
    }

    fn partition(&self, index: usize) -> usize {
        if index < self.config.rx_frames {
            0
        } else if index < self.config.rx_frames + self.config.control_frames {
            1
        } else {
            2
        }
    }

    fn tx_class(&self, index: usize) -> TxClass {
        match self.partition(index) {
            1 => TxClass::Control,
            2 => TxClass::Bulk,
            _ => unreachable!("TX transitions exclude RX frames"),
        }
    }
}

fn allocate_pool(next: &AtomicU64) -> Option<u64> {
    next.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> FrameConfig {
        FrameConfig {
            base_address: 4096,
            frame_size: 2048,
            rx_frames: 3,
            control_frames: 2,
            bulk_frames: 3,
            fill_capacity: 2,
            rx_capacity: 1,
            control_descriptors: 1,
            bulk_descriptors: 2,
            tx_capacity: 3,
            completion_capacity: 3,
        }
    }

    fn ledger() -> FrameLedger<u64> {
        FrameLedger::new(config(), &MemoryBudget::new(1 << 20)).unwrap()
    }

    #[test]
    fn validates_extents_partitions_and_ring_commitments_before_charging() {
        let budget = MemoryBudget::new(usize::MAX);
        let invalid = [
            FrameConfig {
                frame_size: 0,
                ..config()
            },
            FrameConfig {
                rx_frames: 0,
                ..config()
            },
            FrameConfig {
                control_frames: 0,
                ..config()
            },
            FrameConfig {
                bulk_frames: 0,
                ..config()
            },
            FrameConfig {
                fill_capacity: 0,
                ..config()
            },
            FrameConfig {
                fill_capacity: 4,
                ..config()
            },
            FrameConfig {
                rx_capacity: 0,
                ..config()
            },
            FrameConfig {
                rx_capacity: 4,
                ..config()
            },
            FrameConfig {
                control_descriptors: 0,
                ..config()
            },
            FrameConfig {
                control_descriptors: 3,
                ..config()
            },
            FrameConfig {
                bulk_descriptors: 0,
                ..config()
            },
            FrameConfig {
                bulk_descriptors: 4,
                ..config()
            },
            FrameConfig {
                tx_capacity: 2,
                ..config()
            },
            FrameConfig {
                completion_capacity: 2,
                ..config()
            },
            FrameConfig {
                base_address: u64::MAX,
                ..config()
            },
            FrameConfig {
                frame_size: usize::MAX,
                ..config()
            },
            FrameConfig {
                rx_frames: usize::MAX,
                control_frames: 1,
                bulk_frames: 1,
                ..config()
            },
            FrameConfig {
                base_address: 0,
                frame_size: 1,
                rx_frames: isize::MAX as usize / size_of::<Slot<u64>>() + 1,
                ..config()
            },
        ];
        for config in invalid {
            assert!(matches!(
                FrameLedger::<u64>::new(config, &budget),
                Err(LedgerError::InvalidConfig(_))
            ));
            assert_eq!(budget.used(), 0);
        }
        let non_linux_sizes = FrameConfig {
            frame_size: 1501,
            base_address: 7,
            ..config()
        };
        assert!(FrameLedger::<u64>::new(non_linux_sizes, &budget).is_ok());
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn charges_only_metadata_and_does_not_release_separately_owned_storage() {
        let bytes = FrameLedger::<u64>::metadata_bytes(config()).unwrap();
        let denied = MemoryBudget::new(bytes - 1);
        assert!(matches!(
            FrameLedger::<u64>::new(config(), &denied),
            Err(LedgerError::BudgetExhausted)
        ));
        assert_eq!(denied.used(), 0);

        let storage_bytes = 8 * config().frame_size;
        let budget = MemoryBudget::new(bytes + storage_bytes);
        let storage = budget.reserve(storage_bytes).unwrap();
        let mut ledger = FrameLedger::<u64>::new(config(), &budget).unwrap();
        assert_eq!(ledger.charged_bytes(), bytes);
        assert_eq!(budget.used(), bytes + storage_bytes);
        assert!(matches!(
            FrameLedger::<u64>::new(config(), &budget),
            Err(LedgerError::BudgetExhausted)
        ));
        let tx = ledger.reserve_tx(TxClass::Bulk).unwrap();
        ledger.submit_tx(tx, 64, 77).unwrap();
        drop(ledger);
        assert_eq!(budget.used(), storage_bytes);
        drop(storage);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn local_release_cannot_return_a_reused_or_foreign_frame() {
        let mut ledger = ledger();
        let first = ledger.reserve_tx(TxClass::Bulk).unwrap();
        assert_eq!(ledger.release_tx(first), Err(LedgerError::WrongState));
        ledger.submit_tx(first, 64, 41).unwrap();
        assert_eq!(ledger.release_tx(first), Ok(41));
        let next = ledger.reserve_tx(TxClass::Bulk).unwrap();
        assert_eq!(next.address(), first.address());
        ledger.submit_tx(next, 64, 42).unwrap();
        assert_eq!(ledger.release_tx(first), Err(LedgerError::StaleLease));
        let mut foreign = FrameLedger::<u64>::new(config(), &MemoryBudget::new(1 << 20)).unwrap();
        assert_eq!(foreign.release_tx(next), Err(LedgerError::ForeignLease));
        assert_eq!(ledger.release_tx(next), Ok(42));
        assert!(ledger.drain_state().is_drained());
    }

    #[test]
    fn bulk_cannot_spend_control_fill_or_reserved_descriptor_credit() {
        let mut ledger = ledger();
        let bulk1 = ledger.reserve_tx(TxClass::Bulk).unwrap();
        let bulk2 = ledger.reserve_tx(TxClass::Bulk).unwrap();
        assert_eq!(
            ledger.reserve_tx(TxClass::Bulk),
            Err(LedgerError::NoDescriptor)
        );
        assert_eq!(ledger.drain_state().bulk_free, 1);
        let control = ledger.reserve_tx(TxClass::Control).unwrap();
        assert_eq!(
            ledger.reserve_tx(TxClass::Control),
            Err(LedgerError::NoDescriptor)
        );
        let fill1 = ledger.reserve_fill().unwrap();
        let fill2 = ledger.reserve_fill().unwrap();
        assert_eq!(ledger.reserve_fill(), Err(LedgerError::NoFillCredit));
        assert!(fill1.address() < control.address());
        assert!(control.address() < bulk1.address());
        assert_eq!(bulk1.capacity(), config().frame_size);
        ledger.cancel_tx(bulk1).unwrap();
        let reused = ledger.reserve_tx(TxClass::Bulk).unwrap();
        assert_eq!(reused.address(), bulk1.address());
        assert_eq!(ledger.cancel_tx(bulk1), Err(LedgerError::StaleLease));
        ledger.cancel_tx(reused).unwrap();
        ledger.cancel_tx(bulk2).unwrap();
        ledger.cancel_tx(control).unwrap();
        ledger.cancel_fill(fill1).unwrap();
        ledger.cancel_fill(fill2).unwrap();
        assert!(ledger.drain_state().is_drained());
    }

    #[test]
    fn fill_consumption_frees_ring_credit_without_recycling_backend_frames() {
        let config = FrameConfig {
            rx_frames: 512,
            fill_capacity: 128,
            ..config()
        };
        let bytes = FrameLedger::<u64>::metadata_bytes(config).unwrap();
        let budget = MemoryBudget::new(bytes);
        let mut ledger = FrameLedger::<u64>::new(config, &budget).unwrap();
        let queue = ledger.fill_queue.as_ptr();
        let mut leases = [None; 512];
        for batch in 0..4 {
            for slot in &mut leases[batch * 128..(batch + 1) * 128] {
                let lease = ledger.reserve_fill().unwrap();
                ledger.submit_fill(lease).unwrap();
                *slot = Some(lease);
            }
            let posted = ledger.drain_state();
            assert_eq!(posted.fill_queued, 128);
            assert_eq!(posted.fill_posted, (batch + 1) * 128);
            assert_eq!(posted.rx_free, 512 - (batch + 1) * 128);
            assert_eq!(ledger.reserve_fill(), Err(LedgerError::NoFillCredit));
            assert_eq!(
                ledger.consume_fill(129),
                Err(LedgerError::InvalidFillConsumption)
            );
            assert_eq!(ledger.drain_state(), posted);
            ledger.consume_fill(128).unwrap();
            let consumed = ledger.drain_state();
            assert_eq!(consumed.fill_queued, 0);
            assert_eq!(consumed.fill_posted, posted.fill_posted);
            assert_eq!(consumed.rx_free, posted.rx_free);
            assert_eq!(ledger.fill_queue.as_ptr(), queue);
            assert_eq!(budget.used(), bytes);
        }
        assert_eq!(ledger.reserve_fill(), Err(LedgerError::NoFrame));
        assert_eq!(
            ledger.consume_fill(1),
            Err(LedgerError::InvalidFillConsumption)
        );
        let last = leases[511].unwrap();
        for lease in leases.into_iter().flatten() {
            assert_eq!(ledger.cancel_fill(lease), Err(LedgerError::WrongState));
            let rx = ledger.receive_rx(lease.address() + 128, 64).unwrap();
            ledger.relinquish_rx(rx).unwrap();
            assert_eq!(ledger.submit_fill(lease), Err(LedgerError::StaleLease));
        }
        let recycled = ledger.reserve_fill().unwrap();
        assert_eq!(recycled.address(), last.address());
        assert_eq!(ledger.cancel_fill(last), Err(LedgerError::StaleLease));
        ledger.cancel_fill(recycled).unwrap();
        assert!(ledger.close().is_drained());
        assert_eq!(budget.used(), bytes);
    }

    #[test]
    fn fill_consumption_tracks_publication_order_across_queue_wrap() {
        let mut ledger = ledger();
        let first = ledger.reserve_fill().unwrap();
        let second = ledger.reserve_fill().unwrap();
        assert_eq!(ledger.consume_fill(0), Ok(()));
        assert_eq!(
            ledger.consume_fill(1),
            Err(LedgerError::InvalidFillConsumption)
        );
        ledger.submit_fill(second).unwrap();
        assert_eq!(
            ledger.receive_rx(second.address(), 64),
            Err(LedgerError::WrongState)
        );
        ledger.consume_fill(1).unwrap();
        assert_eq!(
            ledger.receive_rx(first.address(), 64),
            Err(LedgerError::WrongState)
        );
        assert_eq!(ledger.cancel_fill(second), Err(LedgerError::WrongState));
        let rx = ledger.receive_rx(second.address(), 64).unwrap();
        ledger.relinquish_rx(rx).unwrap();
        let reused = ledger.reserve_fill().unwrap();
        assert_eq!(reused.address(), second.address());
        assert_eq!(ledger.submit_fill(second), Err(LedgerError::StaleLease));
        ledger.submit_fill(first).unwrap();
        ledger.submit_fill(reused).unwrap();
        ledger.consume_fill(1).unwrap();
        assert_eq!(
            ledger.receive_rx(reused.address(), 64),
            Err(LedgerError::WrongState)
        );
        let rx = ledger.receive_rx(first.address(), 64).unwrap();
        ledger.relinquish_rx(rx).unwrap();
        ledger.consume_fill(1).unwrap();
        let rx = ledger.receive_rx(reused.address(), 64).unwrap();
        ledger.relinquish_rx(rx).unwrap();
        assert_eq!(ledger.consume_fill(0), Ok(()));
        assert!(ledger.drain_state().is_drained());
    }

    #[test]
    fn rx_readiness_defers_only_valid_posted_frames_without_taking_ownership() {
        let mut ledger = ledger();
        let fill = ledger.reserve_fill().unwrap();
        let tx = ledger.reserve_tx(TxClass::Bulk).unwrap();
        assert_eq!(
            ledger.rx_ready(fill.address(), 64),
            Err(LedgerError::WrongState)
        );
        assert_eq!(
            ledger.rx_ready(tx.address(), 64),
            Err(LedgerError::WrongState)
        );
        assert_eq!(
            ledger.rx_ready(config().base_address, 64),
            Err(LedgerError::WrongState)
        );
        ledger.submit_fill(fill).unwrap();
        let address = fill.address() + 128;
        let capacity = fill.capacity() - 128;
        let before = ledger.drain_state();
        assert_eq!(ledger.rx_ready(address, capacity), Ok(false));
        for length in [0, capacity + 1, usize::MAX] {
            assert_eq!(
                ledger.rx_ready(address, length),
                Err(LedgerError::InvalidLength)
            );
        }
        assert_eq!(
            ledger.rx_ready(u64::MAX, 1),
            Err(LedgerError::InvalidAddress)
        );
        assert_eq!(ledger.drain_state(), before);
        assert_eq!(ledger.receive_rx(address, 64), Err(LedgerError::WrongState));
        ledger.consume_fill(1).unwrap();
        let before = ledger.drain_state();
        assert_eq!(ledger.rx_ready(address, capacity), Ok(true));
        assert_eq!(ledger.drain_state(), before);
        let rx = ledger.receive_rx(address, capacity).unwrap();
        assert_eq!(ledger.rx_ready(address, 1), Err(LedgerError::WrongState));
        ledger.relinquish_rx(rx).unwrap();
        assert_eq!(ledger.rx_ready(address, 1), Err(LedgerError::WrongState));
        ledger.cancel_tx(tx).unwrap();
        assert!(ledger.drain_state().is_drained());
    }

    #[test]
    fn validates_lengths_without_spending_or_releasing_reserved_credit() {
        let mut ledger = ledger();
        let tx = ledger.reserve_tx(TxClass::Bulk).unwrap();
        let before = ledger.drain_state();
        for length in [0, tx.capacity() + 1, usize::MAX] {
            assert_eq!(
                ledger.submit_tx(tx, length, 123),
                Err(LedgerError::InvalidLength)
            );
            assert_eq!(ledger.drain_state(), before);
        }
        ledger.submit_tx(tx, tx.capacity(), 123).unwrap();
        assert_eq!(
            ledger.complete_tx(tx.address() + 1),
            Err(LedgerError::InvalidAddress)
        );
        assert_eq!(ledger.complete_tx(tx.address()), Ok(123));

        let fill = ledger.reserve_fill().unwrap();
        ledger.submit_fill(fill).unwrap();
        ledger.consume_fill(1).unwrap();
        let before = ledger.drain_state();
        let address = fill.address() + 128;
        let capacity = fill.capacity() - 128;
        for length in [0, capacity + 1, usize::MAX] {
            assert_eq!(
                ledger.receive_rx(address, length),
                Err(LedgerError::InvalidLength)
            );
            assert_eq!(ledger.drain_state(), before);
        }
        let rx = ledger.receive_rx(address, capacity).unwrap();
        assert_eq!(rx.address(), address);
        assert_eq!(rx.capacity(), capacity);
        assert_eq!(ledger.relinquish_rx(fill), Err(LedgerError::StaleLease));
        ledger.relinquish_rx(rx).unwrap();
        let recycled = ledger.reserve_fill().unwrap();
        assert_eq!(recycled.address(), fill.address());
        assert_eq!(recycled.capacity(), fill.capacity());
        ledger.cancel_fill(recycled).unwrap();
        assert!(ledger.drain_state().is_drained());
    }

    #[test]
    fn reuse_keeps_fixed_metadata_and_accounting_bounded() {
        let bytes = FrameLedger::<(u64, u32)>::metadata_bytes(config()).unwrap();
        let budget = MemoryBudget::new(bytes);
        let mut ledger = FrameLedger::<(u64, u32)>::new(config(), &budget).unwrap();
        let states = ledger.slots.as_ptr();
        let free = ledger.free_indices.as_ptr();
        let fill_queue = ledger.fill_queue.as_ptr();
        for incarnation in 0..1024 {
            let tx = ledger.reserve_tx(TxClass::Bulk).unwrap();
            let control = ledger.reserve_tx(TxClass::Control).unwrap();
            ledger.submit_tx(tx, 1, (9, incarnation)).unwrap();
            ledger
                .submit_tx(control, control.capacity(), (7, incarnation))
                .unwrap();
            let fill = ledger.reserve_fill().unwrap();
            ledger.submit_fill(fill).unwrap();
            ledger.consume_fill(1).unwrap();
            let rx = ledger
                .receive_rx(fill.address() + fill.capacity() as u64 - 1, 1)
                .unwrap();
            assert_eq!(rx.capacity(), 1);
            ledger.relinquish_rx(rx).unwrap();
            assert_eq!(ledger.complete_tx(control.address()), Ok((7, incarnation)));
            assert_eq!(ledger.complete_tx(tx.address()), Ok((9, incarnation)));
            assert_eq!(ledger.slots.as_ptr(), states);
            assert_eq!(ledger.free_indices.as_ptr(), free);
            assert_eq!(ledger.fill_queue.as_ptr(), fill_queue);
            assert_eq!(budget.used(), bytes);
            assert!(ledger.drain_state().is_drained());
        }
        drop(ledger);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn receive_owns_frame_until_explicit_relinquishment() {
        let mut ledger = ledger();
        let fill1 = ledger.reserve_fill().unwrap();
        let fill2 = ledger.reserve_fill().unwrap();
        assert_eq!(
            ledger.receive_rx(fill1.address(), 64),
            Err(LedgerError::WrongState)
        );
        ledger.submit_fill(fill1).unwrap();
        ledger.submit_fill(fill2).unwrap();
        assert_eq!(ledger.submit_fill(fill1), Err(LedgerError::WrongState));
        assert_eq!(ledger.cancel_fill(fill1), Err(LedgerError::WrongState));
        assert_eq!(
            ledger.complete_tx(fill1.address()),
            Err(LedgerError::WrongState)
        );
        assert_eq!(
            ledger.receive_rx(fill1.address(), 64),
            Err(LedgerError::WrongState)
        );
        ledger.consume_fill(2).unwrap();
        let rx1 = ledger.receive_rx(fill1.address(), 64).unwrap();
        assert_eq!(ledger.relinquish_rx(fill1), Err(LedgerError::StaleLease));
        assert_eq!(
            ledger.receive_rx(fill1.address(), 64),
            Err(LedgerError::WrongState)
        );
        assert_eq!(
            ledger.receive_rx(fill2.address(), 64),
            Err(LedgerError::NoRxCredit)
        );
        assert_eq!(ledger.drain_state().fill_posted, 1);
        let other = ledger.reserve_fill().unwrap();
        assert_ne!(other.address(), rx1.address());
        ledger.cancel_fill(other).unwrap();
        ledger.relinquish_rx(rx1).unwrap();
        assert_eq!(ledger.relinquish_rx(rx1), Err(LedgerError::WrongState));
        let reused = ledger.reserve_fill().unwrap();
        assert_eq!(reused.address(), rx1.address());
        assert_eq!(ledger.relinquish_rx(rx1), Err(LedgerError::StaleLease));
        let rx2 = ledger.receive_rx(fill2.address(), 64).unwrap();
        ledger.relinquish_rx(rx2).unwrap();
        ledger.cancel_fill(reused).unwrap();
        assert!(ledger.drain_state().is_drained());
    }

    #[test]
    fn completion_returns_saved_owner_once_and_only_for_actual_outstanding_tx() {
        let mut ledger = ledger();
        let tx1 = ledger.reserve_tx(TxClass::Bulk).unwrap();
        let tx2 = ledger.reserve_tx(TxClass::Bulk).unwrap();
        let control = ledger.reserve_tx(TxClass::Control).unwrap();
        assert_eq!(
            ledger.complete_tx(tx1.address()),
            Err(LedgerError::WrongState)
        );
        assert_eq!(ledger.submit_tx(tx1, 64, 101), Ok(tx1.address()));
        ledger.submit_tx(tx2, 64, 202).unwrap();
        ledger.submit_tx(control, 64, 303).unwrap();
        assert_eq!(ledger.submit_tx(tx1, 64, 999), Err(LedgerError::WrongState));
        assert_eq!(ledger.cancel_tx(tx1), Err(LedgerError::WrongState));
        assert_eq!(ledger.complete_tx(tx2.address()), Ok(202));
        assert_eq!(
            ledger.complete_tx(tx2.address()),
            Err(LedgerError::WrongState)
        );
        assert_eq!(ledger.complete_tx(control.address()), Ok(303));
        assert_eq!(ledger.complete_tx(tx1.address()), Ok(101));
        let reused = ledger.reserve_tx(TxClass::Bulk).unwrap();
        assert_eq!(reused.address(), tx1.address());
        assert_eq!(ledger.submit_tx(tx1, 64, 999), Err(LedgerError::StaleLease));
        ledger.submit_tx(reused, 64, 404).unwrap();
        assert_eq!(ledger.complete_tx(reused.address()), Ok(404));
        assert!(ledger.drain_state().is_drained());
    }

    #[test]
    fn rejects_foreign_leases_and_non_slot_or_non_owned_addresses() {
        let mut first = ledger();
        let mut second = ledger();
        let tx = first.reserve_tx(TxClass::Bulk).unwrap();
        let fill = first.reserve_fill().unwrap();
        assert_eq!(second.submit_tx(tx, 64, 7), Err(LedgerError::ForeignLease));
        assert_eq!(second.cancel_tx(tx), Err(LedgerError::ForeignLease));
        assert_eq!(second.submit_fill(fill), Err(LedgerError::ForeignLease));
        assert_eq!(second.cancel_fill(fill), Err(LedgerError::ForeignLease));
        assert_eq!(second.relinquish_rx(fill), Err(LedgerError::ForeignLease));
        let base = config().base_address;
        let end = base + 8 * config().frame_size as u64;
        for address in [0, base - 1, end, u64::MAX] {
            assert_eq!(first.complete_tx(address), Err(LedgerError::InvalidAddress));
            assert_eq!(
                first.receive_rx(address, 64),
                Err(LedgerError::InvalidAddress)
            );
        }
        assert_eq!(
            first.complete_tx(base + 1),
            Err(LedgerError::InvalidAddress)
        );
        assert_eq!(first.submit_tx(fill, 64, 7), Err(LedgerError::WrongState));
        assert_eq!(first.relinquish_rx(tx), Err(LedgerError::WrongState));
        assert_eq!(first.submit_fill(tx), Err(LedgerError::WrongState));
        assert_eq!(
            second.complete_tx(tx.address()),
            Err(LedgerError::WrongState)
        );
        first.cancel_tx(tx).unwrap();
        first.cancel_fill(fill).unwrap();
        assert!(first.drain_state().is_drained());
        assert!(second.drain_state().is_drained());
    }

    #[test]
    fn close_preserves_admitted_work_and_exposes_original_owners_until_drain() {
        let mut ledger = ledger();
        let fill = ledger.reserve_fill().unwrap();
        let tx = ledger.reserve_tx(TxClass::Control).unwrap();
        let unused = ledger.reserve_tx(TxClass::Bulk).unwrap();
        let state = ledger.close();
        assert!(state.closed);
        assert_eq!(state.fill_reserved, 1);
        assert_eq!(state.control_reserved, 1);
        assert_eq!(state.bulk_reserved, 1);
        assert!(!state.is_drained());
        assert_eq!(ledger.reserve_fill(), Err(LedgerError::Closed));
        assert_eq!(
            ledger.reserve_tx(TxClass::Control),
            Err(LedgerError::Closed)
        );
        assert_eq!(ledger.reserve_tx(TxClass::Bulk), Err(LedgerError::Closed));
        ledger.submit_fill(fill).unwrap();
        ledger.submit_tx(tx, 64, 88).unwrap();
        ledger.cancel_tx(unused).unwrap();
        let mut outstanding = ledger.outstanding_tx();
        assert_eq!(
            outstanding.next(),
            Some(OutstandingTx {
                address: tx.address(),
                class: TxClass::Control,
                owner: 88
            })
        );
        assert_eq!(outstanding.next(), None);
        drop(outstanding);
        assert_eq!(ledger.close().control_outstanding, 1);
        assert_eq!(ledger.drain_state().fill_posted, 1);
        ledger.consume_fill(1).unwrap();
        let rx = ledger.receive_rx(fill.address(), 64).unwrap();
        assert!(!ledger.drain_state().is_drained());
        ledger.relinquish_rx(rx).unwrap();
        assert_eq!(ledger.complete_tx(tx.address()), Ok(88));
        assert!(ledger.close().is_drained());
    }

    #[test]
    fn unused_posted_fill_requires_backend_teardown_not_fake_rx() {
        let mut ledger = ledger();
        assert!(ledger.drain_state().is_drained());
        assert!(!ledger.drain_state().ready_for_backend_teardown());
        let fill = ledger.reserve_fill().unwrap();
        ledger.submit_fill(fill).unwrap();
        let tx = ledger.reserve_tx(TxClass::Bulk).unwrap();
        ledger.submit_tx(tx, 1, 55).unwrap();
        let closed = ledger.close();
        assert!(!closed.ready_for_backend_teardown());
        assert_eq!(closed.fill_posted, 1);
        assert_eq!(ledger.complete_tx(tx.address()), Ok(55));
        let drained = ledger.drain_state();
        assert!(drained.ready_for_backend_teardown());
        assert!(!drained.is_drained());
        assert_eq!(drained.fill_posted, 1);
        assert_eq!(ledger.cancel_fill(fill), Err(LedgerError::WrongState));
        assert_eq!(
            ledger.complete_tx(fill.address()),
            Err(LedgerError::WrongState)
        );
        assert_eq!(ledger.close(), drained);
        ledger.consume_fill(1).unwrap();
        let consumed = ledger.drain_state();
        assert_eq!(consumed.fill_posted, 1);
        assert_eq!(consumed.fill_queued, 0);
        assert!(consumed.ready_for_backend_teardown());
        assert!(!consumed.is_drained());
        assert_eq!(ledger.cancel_fill(fill), Err(LedgerError::WrongState));
        assert_eq!(
            ledger.consume_fill(1),
            Err(LedgerError::InvalidFillConsumption)
        );
        assert_eq!(ledger.close(), consumed);
    }

    #[test]
    fn pool_ids_and_cpu_lease_generations_never_wrap() {
        let next = AtomicU64::new(u64::MAX - 1);
        assert_eq!(allocate_pool(&next), Some(u64::MAX - 1));
        assert_eq!(allocate_pool(&next), None);
        assert_eq!(allocate_pool(&next), None);

        let mut ledger = ledger();
        let bulk = ledger.reserve_tx(TxClass::Bulk).unwrap();
        ledger.cancel_tx(bulk).unwrap();
        ledger.slots[bulk.index].generation = u64::MAX - 1;
        let last = ledger.reserve_tx(TxClass::Bulk).unwrap();
        assert_eq!(last.generation, u64::MAX);
        ledger.submit_tx(last, 64, 91).unwrap();
        assert_eq!(ledger.complete_tx(last.address()), Ok(91));
        assert_eq!(ledger.drain_state().exhausted_frames, 1);
        assert_eq!(ledger.cancel_tx(bulk), Err(LedgerError::StaleLease));
        let another = ledger.reserve_tx(TxClass::Bulk).unwrap();
        assert_ne!(another.address(), last.address());
        ledger.cancel_tx(another).unwrap();

        let fill = ledger.reserve_fill().unwrap();
        ledger.cancel_fill(fill).unwrap();
        ledger.slots[fill.index].generation = u64::MAX - 2;
        let last_fill = ledger.reserve_fill().unwrap();
        assert_eq!(last_fill.generation, u64::MAX - 1);
        ledger.submit_fill(last_fill).unwrap();
        ledger.consume_fill(1).unwrap();
        let last_rx = ledger.receive_rx(last_fill.address(), 64).unwrap();
        assert_eq!(last_rx.generation, u64::MAX);
        ledger.relinquish_rx(last_rx).unwrap();
        assert_eq!(ledger.drain_state().exhausted_frames, 2);
        let next_fill = ledger.reserve_fill().unwrap();
        assert_ne!(next_fill.address(), last_fill.address());
        ledger.cancel_fill(next_fill).unwrap();
        assert!(ledger.drain_state().is_drained());
    }

    #[test]
    fn exhausted_partitions_refuse_without_spending_other_credits() {
        let mut ledger = ledger();
        let rx_end = ledger.config.rx_frames;
        let control_end = rx_end + ledger.config.control_frames;
        for slot in &mut ledger.slots[..rx_end] {
            slot.generation = u64::MAX - 1;
        }
        for slot in &mut ledger.slots[rx_end..control_end] {
            slot.generation = u64::MAX;
        }
        assert_eq!(ledger.reserve_fill(), Err(LedgerError::NoFrame));
        assert_eq!(
            ledger.reserve_tx(TxClass::Control),
            Err(LedgerError::NoFrame)
        );
        assert_eq!(ledger.fill_used, 0);
        assert_eq!(ledger.tx_used, [0, 0]);
        let state = ledger.drain_state();
        assert_eq!(state.exhausted_frames, control_end);
        assert_eq!(state.rx_free, 0);
        assert_eq!(state.control_free, 0);
        let bulk = ledger.reserve_tx(TxClass::Bulk).unwrap();
        ledger.cancel_tx(bulk).unwrap();
        assert!(ledger.close().is_drained());
    }
}
