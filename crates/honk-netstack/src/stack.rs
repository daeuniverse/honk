//! Public sans-I/O API and the single-owner scheduler.

use std::collections::{HashMap, VecDeque};
use std::io::{self, IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU64;
use std::ops::{BitOr, BitOrAssign, Range};
use std::sync::Arc;
use std::time::Instant;

use crate::accept::Refuse;
use crate::flow::{self, Flow, FourTuple, Ports, Table, TimeWait};
use crate::fragment::{FragmentLimits, Push};
use crate::icmp_out::IcmpLimits;
use crate::mode::{Mode, is_unicast};
use crate::offload::{RxMeta, SourceContext, Transmit, TxCaps, TxCsum};
use crate::tcp::output::Output;
use crate::tcp::ring::{self, Pool};
use crate::tcp::{Tcb, TcpState, TcpStats};
use crate::timer::Timers;
use crate::wire::{self, ParseError};
use crate::{MemoryBudget, MemoryReservation, OwnedPacket};

mod retention;
mod rx;
mod tcp;
mod transmit_iov;
mod tx;

pub(crate) use rx::SourceReport;
pub use transmit_iov::IovTransmit;

#[derive(Clone, Debug)]
pub struct Config {
    pub mtu: u16,
    pub local_v4: Option<Ipv4Addr>,
    pub local_v6: Option<Ipv6Addr>,
    pub secret: [u8; 32],
    pub memory_limit: usize,
    pub max_flows: u32,
    pub tcp_rcv_buf_max: usize,
    pub tcp_snd_buf_max: usize,
    /// Whom the stack answers for; the default, [`Mode::Endpoint`], answers for `local_v4`/`local_v6`.
    pub mode: Mode,
    /// Transparent mode: half-open (SYN received, handshake unfinished) flows in total; further
    /// SYNs are dropped and counted, never answered.
    pub half_open_max: u32,
    /// Transparent mode: half-open flows per client address.
    pub half_open_per_source: u32,
    /// Process-wide limit on top of `memory_limit`: floors and shared commitments are charged to
    /// both. Stacks sharing one budget cannot exceed it together; a dropped stack returns its share.
    pub shared_budget: Option<Arc<MemoryBudget>>,
    /// Transparent mode: ICMP error generation limits.
    pub icmp_limits: IcmpLimits,
    /// Transparent mode: IP fragment reassembly limits.
    pub fragment_limits: FragmentLimits,
    /// TCP buffer chunk size in bytes (clamped to 4..=64 KiB). `None`: 16 KiB in
    /// [`Mode::Endpoint`], 4 KiB in [`Mode::Transparent`], so a transparent flow's funded floor
    /// (two chunks plus the descriptor floor, about 9 KiB) stays small; the floor is accounting
    /// only, an idle flow holds no chunk.
    pub tcp_chunk: Option<usize>,
}

impl Config {
    pub fn new(secret: [u8; 32]) -> Config {
        Config {
            mtu: 1420,
            local_v4: None,
            local_v6: None,
            secret,
            memory_limit: 256 * 1024 * 1024,
            max_flows: 4096,
            tcp_rcv_buf_max: 8 * 1024 * 1024,
            tcp_snd_buf_max: 6 * 1024 * 1024,
            shared_budget: None,
            icmp_limits: IcmpLimits::default(),
            fragment_limits: FragmentLimits::default(),
            tcp_chunk: None,
            mode: Mode::Endpoint,
            half_open_max: 1024,
            half_open_per_source: 128,
        }
    }
    /// The effective chunk size.
    pub fn chunk(&self) -> usize {
        ring::clamp_chunk(self.tcp_chunk.unwrap_or(match self.mode {
            Mode::Endpoint => ring::CHUNK,
            Mode::Transparent { .. } => ring::TRANSPARENT_CHUNK,
        }))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FlowId {
    pub(crate) idx: u32,
    pub(crate) generation: u32,
}

impl FlowId {
    /// Stack-local slot index. Compare the complete handle after indexing a slot.
    pub fn index(self) -> usize {
        self.idx as usize
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ready(u8);

impl Ready {
    pub const CONNECTED: Ready = Ready(1);
    pub const READABLE: Ready = Ready(2);
    pub const WRITABLE: Ready = Ready(4);
    pub const READ_CLOSED: Ready = Ready(8);
    pub const ERROR: Ready = Ready(16);
    pub fn contains(self, other: Ready) -> bool {
        self.0 & other.0 == other.0
    }
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}
impl BitOr for Ready {
    type Output = Ready;
    fn bitor(self, other: Ready) -> Ready {
        Ready(self.0 | other.0)
    }
}
impl BitOrAssign for Ready {
    fn bitor_assign(&mut self, other: Ready) {
        self.0 |= other.0;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Rx {
    Consumed,
    Datagram {
        flow: FlowId,
        src: SocketAddr,
        payload: Range<usize>,
    },
    /// Transparent-mode UDP: stateless, no flow; `payload` indexes the input packet.
    Transparent {
        src: SocketAddr,
        dst: SocketAddr,
        dscp: u8,
        payload: Range<usize>,
    },
    /// A transparent datagram that was reassembled from fragments; `payload` indexes `packet`.
    TransparentOwned {
        src: SocketAddr,
        dst: SocketAddr,
        dscp: u8,
        packet: OwnedPacket,
        payload: Range<usize>,
    },
    /// A transparent USO super-packet ([`Stack::receive_with`]): `payload` indexes the input
    /// packet and holds consecutive datagrams of `size` bytes each, the last possibly shorter;
    /// every `size`-byte chunk is one datagram (boundaries preserved, at most 128 of them). Like
    /// [`Rx::Transparent`] it borrows the input packet.
    TransparentSplit {
        src: SocketAddr,
        dst: SocketAddr,
        dscp: u8,
        payload: Range<usize>,
        size: u16,
    },
    Dropped(DropReason),
}

/// Current packet header/checksum provenance, never handshake or accepted-child authority.
/// A fragmented input produces this only on its successfully validated completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedSource {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub protocol: u8,
    /// Verified header flags for TCP; never protocol admission evidence.
    pub tcp_flags: Option<u8>,
}

/// Protocol evidence for this input, not routing or application admission.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReceiveOutcome {
    #[default]
    Unqualified,
    TcpAccepted(FlowId),
    TcpNew(FlowId),
    DatagramValidated,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReceiveReport {
    pub source: Option<ValidatedSource>,
    pub source_context: Option<SourceContext>,
    pub outcome: ReceiveOutcome,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    Malformed,
    Checksum,
    Fragment,
    NotForUs,
    NoFlow,
    Unsupported,
    Stale,
    /// Transparent mode: a SYN beyond the half-open caps.
    HalfOpen,
    /// A flow admission or reassembly allocation the available capacity could not fund.
    Capacity,
}

impl From<ParseError> for DropReason {
    fn from(e: ParseError) -> DropReason {
        match e {
            ParseError::Malformed => DropReason::Malformed,
            ParseError::Checksum => DropReason::Checksum,
            ParseError::Fragment => DropReason::Fragment,
            ParseError::Unsupported => DropReason::Unsupported,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConnectError {
    #[error("address family has no local tunnel address")]
    NoLocalAddress,
    #[error("no available source port")]
    AddrInUse,
    #[error("flow admission limit reached")]
    FlowLimit,
    #[error("per-flow memory floor cannot be honored")]
    Memory,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    #[error("operation would block")]
    WouldBlock,
    #[error("write side is shut down")]
    Closed,
    #[error("connection reset")]
    Reset,
    #[error("connection timed out")]
    TimedOut,
    #[error("destination unreachable")]
    Unreachable,
    #[error("stale flow handle")]
    Stale,
}

/// A receive prefix could not be consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TcpConsumeError {
    #[error("stale flow handle")]
    Stale,
    #[error("receive prefix exceeds the contiguous readable bytes")]
    OutOfRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BindError {
    #[error("no local tunnel address")]
    NoLocalAddress,
    #[error("UDP port is in use")]
    AddrInUse,
    #[error("flow admission limit reached")]
    FlowLimit,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UdpError {
    #[error("output buffer is too small")]
    BufferTooSmall,
    #[error("address family has no local tunnel address")]
    NoLocalAddress,
    #[error("stale flow handle")]
    Stale,
    #[error("datagram exceeds the path MTU")]
    TooLarge,
    #[error("pending fragment queue or memory budget is full")]
    Busy,
    #[error("source and destination address families differ")]
    FamilyMismatch,
    #[error("UDP segmentation offload is not available")]
    Offload,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StackStats {
    /// Indexed by the discriminant of [`DropReason`].
    pub drops: [u64; 16],
    pub memory_committed: usize,
    pub memory_allocated: usize,
    pub flows: u32,
    /// Transparent mode: flows between SYN and the end of the handshake.
    pub half_open: u32,
    pub timewait_entries: usize,
    pub control_dropped: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct Control {
    pub(crate) tuple: FourTuple,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: u8,
    /// An ICMP error for a refused SYN instead of a TCP segment.
    pub(crate) icmp: Option<Refuse>,
    pub(crate) flow: Option<FlowId>,
    pub(crate) source: Option<SourceContext>,
}
const CONTROL_LIMIT: usize = 128;

/// A sharded owner borrows its realm's ICMP limiter only for actual ICMP output.
pub enum AccountedTransmit {
    Packet(Transmit),
    NeedsIcmp,
    /// Pending output needs a larger frame. No packet was consumed by the short write.
    BufferTooSmall,
    Idle,
}

struct ShardResources {
    control_limit: usize,
    release_limit: usize,
    icmp_class: Option<u8>,
    reassembly_owner: bool,
    fragment_output: Option<crate::FragmentInfo>,
    half_open_released: VecDeque<FlowId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConstructionError {
    #[error("accounted stacks require a shared memory budget")]
    MissingBudget,
    #[error("stack capacity bound overflows")]
    Overflow,
    #[error("shared memory budget cannot fund stack capacity")]
    Capacity,
    #[error("source context preparation requires an unused stack")]
    InUse,
}

pub struct Stack {
    pub(crate) cfg: Config,
    pub(crate) now: Instant,
    pub(crate) epoch: Instant,
    pub(crate) table: Table,
    ports: Ports,
    pub(crate) pool: Pool,
    pub(crate) floor_cap: u32,
    timers: Timers,
    /// Queue elements `purge_stale` has visited; lets tests assert teardown stays amortized O(1).
    #[cfg(test)]
    purge_visits: usize,
    #[cfg(test)]
    writer_visits: usize,
    events: VecDeque<FlowId>,
    ready: VecDeque<FlowId>,
    control_ready: Option<VecDeque<FlowId>>,
    writers: VecDeque<FlowId>,
    seen_release_epochs: (u64, u64),
    timewait_ready: VecDeque<FlowId>,
    controls: VecDeque<Control>,
    pub(crate) tx_wakeup: bool,
    class: u8,
    control_class: u8,
    cache: Option<(FourTuple, FlowId)>,
    /// Passive flows whose SYN `poll_accept` has not yet reported.
    pub(crate) accept_q: VecDeque<FlowId>,
    pub(crate) half_open: u32,
    pub(crate) half_open_by_source: HashMap<IpAddr, u32>,
    pub(crate) udp_tx: crate::udp_t::UdpTx,
    pub(crate) icmp_out: crate::icmp_out::IcmpOut,
    pub(crate) counters: StackStats,
    pub(crate) reasm: crate::fragment::Reassembler,
    pub(crate) accepting: bool,
    shard: Option<Box<ShardResources>>,
    // Declared last: every funded collection and the TCP pool are dropped before the refund.
    overhead: Option<MemoryReservation>,
}

impl Stack {
    pub fn new(mut cfg: Config, now: Instant) -> Stack {
        let transparent = matches!(cfg.mode, Mode::Transparent { .. });
        cfg.mtu = cfg.mtu.max(if cfg.local_v6.is_some() || transparent {
            1280
        } else {
            68
        });
        let floor = ring::floor(cfg.chunk());
        let floor_cap = cfg
            .max_flows
            .min((cfg.memory_limit / floor).min(u32::MAX as usize) as u32);
        let reserved = floor_cap as usize * floor;
        let pool = Pool::with_limits(cfg.memory_limit.saturating_sub(reserved), cfg.memory_limit)
            .with_chunk(cfg.chunk())
            .with_budget(cfg.shared_budget.clone());
        let ports = Ports::new(&cfg.secret);
        Stack {
            udp_tx: crate::udp_t::UdpTx::new(&cfg.secret, cfg.shared_budget.clone()),
            icmp_out: crate::icmp_out::IcmpOut::new(cfg.icmp_limits),
            reasm: crate::fragment::Reassembler::new(cfg.fragment_limits)
                .with_budget(cfg.shared_budget.clone()),
            cfg,
            now,
            epoch: now,
            table: Table::new(),
            ports,
            pool,
            floor_cap,
            timers: Timers::new(),
            #[cfg(test)]
            purge_visits: 0,
            #[cfg(test)]
            writer_visits: 0,
            events: VecDeque::new(),
            ready: VecDeque::new(),
            control_ready: None,
            writers: VecDeque::new(),
            seen_release_epochs: (0, 0),
            timewait_ready: VecDeque::new(),
            controls: VecDeque::new(),
            tx_wakeup: false,
            class: 0,
            control_class: 0,
            cache: None,
            accept_q: VecDeque::new(),
            half_open: 0,
            half_open_by_source: HashMap::new(),
            counters: StackStats::default(),
            accepting: true,
            shard: None,
            overhead: None,
        }
    }

    /// Reserves conservative metadata and allocation peaks from the supplied process budget.
    /// `max_slots` includes live, free, TIME_WAIT and permanently exhausted slab slots.
    pub fn new_accounted(
        cfg: Config,
        now: Instant,
        max_slots: usize,
    ) -> Result<Self, ConstructionError> {
        Self::new_accounted_inner(cfg, now, max_slots, None)
    }

    /// Creates one exact owner of a realm. Flow, slot and TCP-memory shares are supplied
    /// by the caller; control capacity is partitioned here and only owner zero reassembles.
    pub fn new_accounted_shard(
        mut cfg: Config,
        now: Instant,
        max_slots: usize,
        worker: usize,
        workers: usize,
        udp_pending: Arc<MemoryBudget>,
    ) -> Result<Self, ConstructionError> {
        if !matches!(workers, 1 | 2)
            || worker >= workers
            || udp_pending.limit() != crate::udp_t::MAX_PENDING_BYTES
        {
            return Err(ConstructionError::Capacity);
        }
        if worker != 0 {
            cfg.fragment_limits.max_entries = 0;
            cfg.fragment_limits.max_bytes = 0;
        }
        let shard = ShardResources {
            control_limit: CONTROL_LIMIT / workers + usize::from(worker < CONTROL_LIMIT % workers),
            release_limit: max_slots,
            icmp_class: None,
            reassembly_owner: worker == 0,
            fragment_output: None,
            half_open_released: VecDeque::new(),
        };
        let mut stack = Self::new_accounted_inner(cfg, now, max_slots, Some(shard))?;
        stack.udp_tx.with_pending_budget(udp_pending);
        Ok(stack)
    }

    fn new_accounted_inner(
        cfg: Config,
        now: Instant,
        max_slots: usize,
        shard: Option<ShardResources>,
    ) -> Result<Self, ConstructionError> {
        let budget = cfg
            .shared_budget
            .as_ref()
            .ok_or(ConstructionError::MissingBudget)?;
        let bound = Self::overhead_bound(&cfg, max_slots, shard.as_ref())
            .ok_or(ConstructionError::Overflow)?;
        let overhead = budget.reserve(bound).ok_or(ConstructionError::Capacity)?;
        let mut stack = Self::new(cfg, now);
        stack.shard = shard.map(|mut shard| {
            shard.half_open_released = VecDeque::with_capacity(shard.release_limit);
            Box::new(shard)
        });
        stack.table = Table::bounded(max_slots);
        stack.floor_cap = stack.floor_cap.min(max_slots as u32);
        let floors = stack.floor_cap as usize * ring::floor(stack.cfg.chunk());
        stack.pool = Pool::with_limits(stack.cfg.memory_limit - floors, stack.cfg.memory_limit)
            .with_chunk(stack.cfg.chunk())
            .with_budget(stack.cfg.shared_budget.clone())
            .with_index_accounting();
        stack.overhead = Some(overhead);
        Ok(stack)
    }

    /// Exact lifecycle deltas; drain before admitting another SYN or reaping adapter slots.
    pub fn poll_half_open_released(&mut self) -> Option<FlowId> {
        self.shard.as_mut()?.half_open_released.pop_front()
    }

    pub(crate) fn half_open_release_room(&self) -> bool {
        self.shard.as_ref().is_none_or(|shard| {
            shard.half_open_released.len() + (self.half_open as usize) < shard.release_limit
        })
    }

    pub(crate) fn has_realm_resources(&self) -> bool {
        self.shard.is_some()
    }

    /// Fixed conservative capacity reservation, not measured resident memory or RSS.
    pub fn overhead_reserved(&self) -> usize {
        self.overhead.as_ref().map_or(0, MemoryReservation::bytes) + self.table.source_reserved()
    }

    /// Gates only new passive TCP admission; existing delivery and output remain active.
    pub fn set_accepting(&mut self, accepting: bool) {
        self.accepting = accepting;
    }

    /// Budget bytes charged when a new passive TCP flow is admitted.
    pub fn passive_floor_bytes(&self) -> usize {
        self.pool.floor()
    }

    /// No live protocol owner or stack-internal output/reassembly obligation remains.
    /// Driver-owned packets and application tasks require their own completion proof.
    pub fn is_quiescent(&self) -> bool {
        self.table.active == 0 && self.table.timewait.is_empty() && !self.has_pending_sources()
    }

    fn overhead_bound(
        cfg: &Config,
        max_slots: usize,
        shard: Option<&ShardResources>,
    ) -> Option<usize> {
        use crate::budget::collection_peak;
        u32::try_from(max_slots).ok()?;
        let tcp = max_slots
            .min(cfg.max_flows as usize)
            .min(cfg.memory_limit / ring::floor(cfg.chunk()));
        let transparent = matches!(cfg.mode, Mode::Transparent { .. });
        let mtu = cfg.mtu.max(if transparent || cfg.local_v6.is_some() {
            1280
        } else {
            68
        });
        let prefixes = match &cfg.mode {
            Mode::Transparent { exclude } => exclude.overhead_bound()?,
            Mode::Endpoint => 0,
        };
        let queues = max_slots.max(16).checked_mul(3)?;
        std::mem::size_of::<Self>()
            .checked_add(Table::overhead_bound(max_slots)?)?
            .checked_add(tcp.checked_mul(Tcb::overhead_bound()?)?)?
            .checked_add(collection_peak::<FlowId>(queues)?.checked_mul(6)?)?
            .checked_add(Timers::overhead_bound(max_slots)?)?
            .checked_add(collection_peak::<Control>(
                shard.map_or(CONTROL_LIMIT, |s| s.control_limit),
            )?)?
            .checked_add(if shard.is_none() {
                crate::icmp_out::IcmpOut::overhead_bound(cfg.icmp_limits)?
            } else {
                std::mem::size_of::<ShardResources>()
                    .checked_add(collection_peak::<FlowId>(max_slots)?)?
            })?
            .checked_add(if shard.is_some_and(|shard| !shard.reassembly_owner) {
                0
            } else {
                crate::fragment::Reassembler::overhead_bound(cfg.fragment_limits)?.checked_add(
                    crate::fragment::Reassembler::scratch_bound(cfg.fragment_limits)?,
                )?
            })?
            .checked_add(crate::udp_t::UdpTx::overhead_bound(usize::from(mtu))?)?
            .checked_add(Pool::overhead_bound(cfg.memory_limit)?)?
            .checked_add(prefixes)
            .filter(|&bytes| bytes <= isize::MAX as usize)
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        [
            self.timers.next(),
            self.timers.pending(&self.table),
            self.reasm.poll_timeout(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        self.now = now;
        self.reasm.expire(now);
        // Flushed before every pop: a timer that fires can arm another one that is already due.
        loop {
            self.timers.flush(&mut self.table);
            let Some((deadline, index, generation)) = self.timers.pop_due(now) else {
                break;
            };
            let slot = &mut self.table.slots[index as usize];
            if slot.generation != generation || slot.scheduled != Some(deadline) {
                continue;
            }
            slot.scheduled = None;
            match slot.flow.as_mut() {
                Some(Flow::Tcp(t)) => t.timer(now),
                Some(Flow::TimeWait(t)) if t.expiry <= now && !t.ack_due => {
                    self.table.remove(index);
                    self.purge_stale();
                    continue;
                }
                Some(Flow::TimeWait(t)) if t.expiry <= now => {
                    t.expiry = now + crate::tcp::TIME_WAIT;
                }
                _ => {}
            }
            self.sync(index, now);
        }
        self.wake_writers();
    }

    pub fn poll_event(&mut self) -> Option<(FlowId, Ready)> {
        self.wake_writers();
        while let Some(id) = self.events.pop_front() {
            let slot = self.table.slots.get_mut(id.idx as usize)?;
            if slot.generation != id.generation || !slot.on_event {
                continue;
            }
            slot.on_event = false;
            let ready = std::mem::take(&mut slot.ready);
            if matches!(&slot.flow, Some(Flow::Tcp(t)) if t.app_open) && !ready.is_empty() {
                return Some((id, ready));
            }
        }
        None
    }

    pub fn take_tx_wakeup(&mut self) -> bool {
        std::mem::take(&mut self.tx_wakeup)
    }

    pub fn stats(&self) -> StackStats {
        StackStats {
            memory_committed: self.table.tcp_active as usize * self.pool.floor()
                + self.pool.shared_bytes(),
            memory_allocated: self.pool.allocated_bytes(),
            flows: self.table.active,
            half_open: self.half_open,
            timewait_entries: self.table.timewait.len(),
            ..self.counters
        }
    }

    /// Cross-checks every incrementally maintained structure against a recount; the fuzz targets
    /// run it after each operation.
    #[cfg(feature = "fuzz-checks")]
    pub(crate) fn check(&self) {
        self.table.check();
        self.pool.check_held(self.table.tcp_active as usize);
        let (mut half_open, mut by_source) = (0u32, HashMap::<IpAddr, u32>::new());
        for slot in &self.table.slots {
            if let Some(Flow::Tcp(t)) = &slot.flow
                && t.half_open
            {
                half_open += 1;
                *by_source.entry(t.tuple.remote.ip()).or_default() += 1;
            }
        }
        assert_eq!(half_open, self.half_open);
        assert_eq!(by_source, self.half_open_by_source);
        assert!(self.half_open <= self.cfg.half_open_max);
        let wake = self.poll_timeout();
        for slot in &self.table.slots {
            let deadline = match &slot.flow {
                Some(Flow::Tcp(t)) => {
                    t.check_invariants();
                    t.next_deadline()
                }
                Some(Flow::TimeWait(t)) => Some(t.expiry),
                _ => None,
            };
            if let Some(deadline) = deadline {
                assert!(
                    slot.dirty || slot.scheduled.is_some_and(|s| s <= deadline),
                    "a flow deadline is not covered by a timer entry, so the owner could oversleep it"
                );
                assert!(
                    wake.is_some_and(|t| t <= deadline),
                    "poll_timeout is later than a flow deadline"
                );
            }
        }
        self.timers.check_dirty(&self.table);
        let bound = 3 * self.table.slots.len().max(16);
        for queue in [
            &self.events,
            &self.ready,
            &self.writers,
            &self.timewait_ready,
            &self.accept_q,
        ]
        .into_iter()
        .chain(self.control_ready.iter())
        {
            assert!(
                queue.len() <= bound,
                "stale queue nodes outgrew the sweep bound"
            );
        }
        let mut control_seen = vec![false; self.table.slots.len()];
        if let Some(queue) = &self.control_ready {
            for id in queue {
                let slot = &self.table.slots[id.idx as usize];
                if slot.generation != id.generation {
                    continue;
                }
                assert!(slot.on_control && matches!(slot.flow, Some(Flow::Tcp(_))));
                assert!(!std::mem::replace(&mut control_seen[id.idx as usize], true));
            }
        }
        for (slot, seen) in self.table.slots.iter().zip(control_seen) {
            assert_eq!(slot.on_control, seen);
        }
        assert!(
            self.timers.len() <= 2 * self.table.slots.len().max(16) + 1,
            "the timer heap outgrew its rebuild bound"
        );
        assert!(self.controls.len() <= self.control_limit());
        if let Some(shard) = &self.shard {
            assert!(
                shard.half_open_released.len() + self.half_open as usize <= shard.release_limit
            );
            for (index, id) in shard.half_open_released.iter().enumerate() {
                assert!(
                    !shard
                        .half_open_released
                        .iter()
                        .skip(index + 1)
                        .any(|other| other == id)
                );
            }
        }
        self.reasm.check();
        self.udp_tx.check();
        assert!(self.stats().memory_committed <= self.cfg.memory_limit);
    }

    /// After protocol release, only this Stack's retained fixed metadata may remain charged.
    #[cfg(feature = "fuzz-checks")]
    pub(crate) fn assert_released(&self) {
        self.check();
        assert_eq!(self.table.active, 0);
        assert_eq!(self.table.timewait.len(), 0);
        self.reasm.assert_idle();
        assert_eq!(self.half_open, 0);
        assert!(self.half_open_by_source.is_empty());
        assert!(
            self.accept_q
                .iter()
                .all(|id| { self.table.slots[id.idx as usize].generation != id.generation })
        );
        assert_eq!(self.stats().memory_committed, 0);
        self.pool.assert_idle();
        if let Some(budget) = &self.cfg.shared_budget {
            assert_eq!(
                budget.used(),
                self.overhead_reserved(),
                "the shared budget still holds dynamic work"
            );
        }
    }

    pub(crate) fn local_for(&self, remote: IpAddr) -> Option<IpAddr> {
        match remote {
            IpAddr::V4(_) => self.cfg.local_v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.cfg.local_v6.map(IpAddr::V6),
        }
    }

    pub(crate) fn transparent(&self) -> bool {
        matches!(self.cfg.mode, Mode::Transparent { .. })
    }

    pub(crate) fn allocate_udp_port(&mut self) -> Result<u16, BindError> {
        let local = self
            .cfg
            .local_v4
            .map(IpAddr::V4)
            .or_else(|| self.cfg.local_v6.map(IpAddr::V6))
            .ok_or(BindError::NoLocalAddress)?;
        let mut port = self
            .ports
            .start(&self.cfg.secret, local, SocketAddr::new(local, 0));
        for _ in 0..32768 {
            if !self.table.udp.contains_key(&port) {
                return Ok(port);
            }
            port = flow::next_port(port);
        }
        Err(BindError::AddrInUse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod accounted;
    mod fragments;
    mod retention;
    mod writers;

    #[test]
    fn abandoned_opens_do_not_accumulate_stale_ready_nodes() {
        let now = Instant::now();
        let mut cfg = Config::new([3; 32]);
        cfg.local_v4 = Some(Ipv4Addr::new(192, 0, 2, 1));
        cfg.max_flows = 1;
        let mut stack = Stack::new(cfg, now);
        let remote = "198.51.100.1:443".parse().unwrap();
        let first = stack.tcp_connect(now, remote).unwrap();
        stack.tcp_abort(first);
        for _ in 0..1000 {
            let id = stack.tcp_connect(now, remote).unwrap();
            assert_ne!(id, first);
            stack.tcp_close(id);
            // Stale nodes are swept lazily, but never beyond twice the (here one-slot) floor.
            assert!(stack.ready.len() <= 33, "{}", stack.ready.len());
            assert!(stack.events.len() <= 33);
            assert!(stack.writers.len() <= 33);
        }
        assert_eq!(stack.table.slots.len(), 1);
        assert_eq!(stack.tcp_write(first, b"stale"), Err(StreamError::Stale));
        assert!(
            std::mem::size_of::<Tcb>() <= 1024,
            "idle state excludes rings' separately allocated storage ({} bytes)",
            std::mem::size_of::<Tcb>()
        );
    }

    #[test]
    fn mass_teardown_does_not_rescan_the_queues_per_flow() {
        let now = Instant::now();
        let mut cfg = Config::new([3; 32]);
        cfg.local_v4 = Some(Ipv4Addr::new(192, 0, 2, 1));
        let mut stack = Stack::new(cfg, now);
        let remote = "198.51.100.1:443".parse().unwrap();
        let ids: Vec<_> = (0..3000)
            .map(|_| stack.tcp_connect(now, remote).unwrap())
            .collect();
        assert_eq!(stack.ready.len(), 3000);
        for id in ids {
            stack.tcp_abort(id);
        }
        assert_eq!(stack.stats().flows, 0);
        assert!(
            stack.purge_visits <= 2 * 3000,
            "{} queue visits for 3000 removals",
            stack.purge_visits
        );
    }
}
