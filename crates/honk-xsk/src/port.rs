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

use honk_datapath::buffer::{
    DrainState, FrameConfig, FrameLease, FrameLedger, LedgerError, OutstandingTx, TxClass,
};
use honk_netstack::{MemoryBudget, MemoryReservation};

#[path = "ring.rs"]
mod ring;
mod rx;
#[cfg(test)]
mod tests;
mod tx;

use ring::{Descriptor, Rings, Umem};
use rx::RetainedRxSlots;
#[cfg(test)]
use rx::{NO_RX_SLOT, RetainedRxSlot, RxPhase};
pub use rx::{RetainedRxHandle, RetainedRxIdentity, RxCompletion, RxDisposition};
use tx::Sidecar;
#[cfg(test)]
use tx::TxReservation;
pub use tx::TxSink;

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
    tx_unpublished: Cell<bool>,
    tx_cached_consumer: Cell<u32>,
    fill_producer: u32,
    fill_consumer: u32,
    cq_consumer: u32,
    tx_free: [usize; 2],
    closed: Cell<bool>,
    tx_batch_active: bool,
    counters: PortCounters,
    _bookkeeping: Option<MemoryReservation>,
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
            tx_unpublished: Cell::new(false),
            tx_cached_consumer: Cell::new(0),
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
        self.publish_tx_prefix();
        let rx = self.kick_rx();
        let tx = self.kick_tx();
        rx.and(tx)
    }

    /// Service only TX NEED_WAKEUP after consuming available CQ entries.
    /// Published descriptors awaiting completion remain eligible after [`Self::close`].
    pub fn kick_outstanding_tx(&mut self) -> io::Result<()> {
        self.publish_tx_prefix();
        if self.counters.submitted == self.counters.completed {
            return Ok(());
        }
        self.kick_tx()
    }

    pub fn outstanding(&self) -> impl Iterator<Item = OutstandingTx<u32>> + '_ {
        self.publish_tx_prefix();
        self.ledger.outstanding_tx()
    }

    pub fn drain_state(&self) -> DrainState {
        self.publish_tx_prefix();
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
        self.publish_tx_prefix();
        self.counters
    }

    /// RX was published after this owner last consumed the ring.
    pub fn has_pending_rx(&self) -> bool {
        self.rings.rx.producer() != self.rx_consumer
    }

    /// Retry published TX/CQ work or RX blocked by a partial chain/FILL visibility.
    /// A populated FILL ring without queued RX is an ordinary idle receive reservation.
    pub fn needs_service_retry(&self) -> bool {
        self.publish_tx_prefix();
        self.counters.submitted != self.counters.completed
            || self.tx_producer != self.rings.tx.consumer()
            || self.has_pending_rx()
    }

    pub fn stats(&self) -> io::Result<SocketStats> {
        self.publish_tx_prefix();
        self.socket
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
            .and_then(|fd| ring::stats(fd.as_fd()))
    }

    pub fn rings(&self) -> RingSnapshot {
        self.publish_tx_prefix();
        self.rings.snapshot()
    }

    /// Close only the socket. This does not unmap/refund UMEM or dispose outstanding TX.
    pub fn close_socket(&mut self) {
        self.publish_tx_prefix();
        self.socket.take();
    }
}

impl<L> AsFd for Port<L> {
    /// Panics after close_socket; AsRawFd instead returns -1 for a closed socket.
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.publish_tx_prefix();
        self.socket
            .as_ref()
            .expect("AF_XDP socket is closed")
            .as_fd()
    }
}

impl<L> AsRawFd for Port<L> {
    fn as_raw_fd(&self) -> RawFd {
        self.publish_tx_prefix();
        self.socket.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }
}
