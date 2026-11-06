//! Public sans-I/O API and the single-owner scheduler.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::{BitOr, BitOrAssign, Range};
use std::sync::Arc;
use std::time::Instant;

use crate::accept::Refuse;
use crate::flow::{self, Flow, FourTuple, Ports, Table, TimeWait};
use crate::fragment::{FragmentLimits, Push};
use crate::icmp_out::IcmpLimits;
use crate::mode::{Mode, is_unicast};
use crate::offload::{RxMeta, Transmit, TxCaps};
use crate::tcp::output::Output;
use crate::tcp::ring::{self, Pool};
use crate::tcp::{Tcb, TcpState, TcpStats};
use crate::timer::Timers;
use crate::wire::{self, ParseError};
use crate::{MemoryBudget, MemoryReservation, OwnedPacket};

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

pub(crate) struct SourceReport<F> {
    source: Option<ValidatedSource>,
    tcp_admission: Option<FlowId>,
    accept: F,
}

impl<F: FnMut(ValidatedSource) -> bool> SourceReport<F> {
    fn new(accept: F) -> Self {
        Self {
            source: None,
            tcp_admission: None,
            accept,
        }
    }

    pub(crate) fn record<const REPORT: bool>(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        protocol: u8,
        tcp_flags: Option<u8>,
    ) -> bool {
        if REPORT {
            let source = ValidatedSource {
                src,
                dst,
                protocol,
                tcp_flags,
            };
            self.source = Some(source);
            (self.accept)(source)
        } else {
            true
        }
    }
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

#[derive(Clone, Copy, Debug, Default)]
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
}
const CONTROL_LIMIT: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConstructionError {
    #[error("accounted stacks require a shared memory budget")]
    MissingBudget,
    #[error("stack capacity bound overflows")]
    Overflow,
    #[error("shared memory budget cannot fund stack capacity")]
    Capacity,
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
    events: VecDeque<FlowId>,
    ready: VecDeque<FlowId>,
    control_ready: Option<VecDeque<FlowId>>,
    writers: VecDeque<FlowId>,
    timewait_ready: VecDeque<FlowId>,
    pub(crate) controls: VecDeque<Control>,
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
            events: VecDeque::new(),
            ready: VecDeque::new(),
            control_ready: None,
            writers: VecDeque::new(),
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
        let budget = cfg
            .shared_budget
            .as_ref()
            .ok_or(ConstructionError::MissingBudget)?;
        let bound = Self::overhead_bound(&cfg, max_slots).ok_or(ConstructionError::Overflow)?;
        let overhead = budget.reserve(bound).ok_or(ConstructionError::Capacity)?;
        let mut stack = Self::new(cfg, now);
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

    /// Fixed conservative capacity reservation, not measured resident memory or RSS.
    pub fn overhead_reserved(&self) -> usize {
        self.overhead.as_ref().map_or(0, MemoryReservation::bytes)
    }

    /// Gates only new passive TCP admission; existing delivery and output remain active.
    pub fn set_accepting(&mut self, accepting: bool) {
        self.accepting = accepting;
    }

    /// No live protocol owner or stack-internal output/reassembly obligation remains.
    /// Driver-owned packets and application tasks require their own completion proof.
    pub fn is_quiescent(&self) -> bool {
        self.table.active == 0
            && self.table.timewait.is_empty()
            && self.controls.is_empty()
            && !self.udp_tx.pending()
            && self.reasm.is_quiescent()
    }

    fn overhead_bound(cfg: &Config, max_slots: usize) -> Option<usize> {
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
            .checked_add(collection_peak::<Control>(CONTROL_LIMIT)?)?
            .checked_add(crate::icmp_out::IcmpOut::overhead_bound(cfg.icmp_limits)?)?
            .checked_add(crate::fragment::Reassembler::overhead_bound(
                cfg.fragment_limits,
            )?)?
            .checked_add(crate::fragment::Reassembler::scratch_bound(
                cfg.fragment_limits,
            )?)?
            .checked_add(crate::udp_t::UdpTx::overhead_bound(usize::from(mtu))?)?
            .checked_add(Pool::overhead_bound(cfg.memory_limit)?)?
            .checked_add(prefixes)
            .filter(|&bytes| bytes <= isize::MAX as usize)
    }

    /// Receives one IP packet whose checksum the stack verifies. Same as
    /// [`Stack::receive_with`] with [`RxMeta::VERIFY`].
    pub fn receive(&mut self, now: Instant, packet: &[u8]) -> Rx {
        self.now = now;
        self.counters.rx_packets += 1;
        self.receive_packet::<false>(
            now,
            packet,
            RxMeta::VERIFY,
            &mut SourceReport::new(|_| true),
        )
    }

    /// Reports only this input's completed, checksum-verified TCP/UDP identity. The
    /// callback runs before protocol state mutation/UDP dispatch; false refuses this
    /// packet as NotForUs. A receipt is still a validity fact, not admission evidence.
    pub fn receive_with_source(
        &mut self,
        now: Instant,
        packet: &[u8],
        on_source: impl FnMut(ValidatedSource) -> bool,
    ) -> (Rx, Option<ValidatedSource>) {
        let (rx, source, _) = self.receive_with_tcp_admission(now, packet, on_source);
        (rx, source)
    }

    /// Also returns the new passive incarnation created by this exact receive, never
    /// a later accept-queue occupant. Retransmits and existing-flow input return None.
    pub fn receive_with_tcp_admission(
        &mut self,
        now: Instant,
        packet: &[u8],
        on_source: impl FnMut(ValidatedSource) -> bool,
    ) -> (Rx, Option<ValidatedSource>, Option<FlowId>) {
        self.now = now;
        self.counters.rx_packets += 1;
        let mut report = SourceReport::new(on_source);
        let rx = self.receive_packet::<true>(now, packet, RxMeta::VERIFY, &mut report);
        (rx, report.source, report.tcp_admission)
    }

    /// Receives one IP packet with what the driver knows about it: a trusted L4 checksum
    /// ([`Csum::Valid`], [`Csum::Partial`]) and/or a GRO or USO super-packet. Offload metadata is
    /// accepted only in [`Mode::Transparent`]; an endpoint stack drops any packet that carries it
    /// as [`DropReason::Unsupported`], so a WireGuard driver can never skip verification. A claim
    /// the packet contradicts (a `Partial` that does not point at the L4 checksum field, a segment
    /// size of 0, a TCP size on a UDP packet, super-packet metadata on a fragment or ICMP) is
    /// [`DropReason::Malformed`]. The IP header checksum and every ICMP checksum are always
    /// verified, and so is a datagram reassembled from fragments.
    ///
    /// A TCP super-packet enters the receive ring as one contiguous segment; only the delayed-ACK
    /// cadence counts `ceil(len / size)` full frames (see `Tcb::receive_data`). A UDP super-packet
    /// surfaces as one [`Rx::TransparentSplit`].
    pub fn receive_with(&mut self, now: Instant, packet: &[u8], meta: RxMeta) -> Rx {
        self.now = now;
        self.counters.rx_packets += 1;
        if meta != RxMeta::VERIFY && !self.transparent() {
            return self.drop_packet(DropReason::Unsupported);
        }
        self.receive_packet::<false>(now, packet, meta, &mut SourceReport::new(|_| true))
    }

    fn receive_packet<const REPORT: bool>(
        &mut self,
        now: Instant,
        packet: &[u8],
        meta: RxMeta,
        report: &mut SourceReport<impl FnMut(ValidatedSource) -> bool>,
    ) -> Rx {
        let ip = match wire::parse_ip(packet) {
            Ok(ip) => ip,
            Err(ParseError::Fragment) if self.transparent() => {
                if meta.gso.is_some() {
                    return self.drop_packet(DropReason::Malformed);
                }
                let fragment = match wire::frag::parse(packet) {
                    Ok(fragment) => fragment,
                    Err(e) => return self.drop_packet(e.into()),
                };
                if let Some(reason) = self.refuses(fragment.src, fragment.dst) {
                    return self.drop_packet(reason);
                }
                return match self.reasm.push(now, fragment) {
                    Push::Pending => Rx::Consumed,
                    Push::Dropped(reason) => self.drop_packet(reason),
                    // The whole datagram goes through the normal checks, destination included,
                    // and its checksum is verified: no fragment's metadata vouches for the rest.
                    Push::Complete(r) => {
                        let rx = match wire::parse_ip(&r.packet) {
                            Ok(ip) => self.receive_ip::<REPORT>(
                                now,
                                ip,
                                &r.packet,
                                RxMeta::VERIFY,
                                report,
                            ),
                            Err(e) => self.drop_packet(e.into()),
                        };
                        r.wrap(rx)
                    }
                };
            }
            Err(e) => return self.drop_packet(e.into()),
        };
        self.receive_ip::<REPORT>(now, ip, packet, meta, report)
    }

    fn receive_ip<const REPORT: bool>(
        &mut self,
        now: Instant,
        ip: wire::IpPacket,
        packet: &[u8],
        meta: RxMeta,
        report: &mut SourceReport<impl FnMut(ValidatedSource) -> bool>,
    ) -> Rx {
        if let Some(reason) = self.refuses(ip.src, ip.dst) {
            return self.drop_packet(reason);
        }
        match ip.proto {
            wire::PROTO_TCP => self.receive_tcp::<REPORT>(now, &ip, packet, meta, report),
            wire::PROTO_UDP if self.transparent() => {
                let rx = crate::udp_t::receive_transparent(self, &ip, packet, meta);
                if let Rx::Transparent { src, dst, .. } | Rx::TransparentSplit { src, dst, .. } =
                    &rx
                    && !report.record::<REPORT>(*src, *dst, wire::PROTO_UDP, None)
                {
                    return self.drop_packet(DropReason::NotForUs);
                }
                rx
            }
            wire::PROTO_UDP => self.receive_udp::<REPORT>(&ip, packet, report),
            wire::PROTO_ICMP | wire::PROTO_ICMPV6 if meta.gso.is_some() => {
                self.drop_packet(DropReason::Malformed)
            }
            wire::PROTO_ICMP | wire::PROTO_ICMPV6 => self.receive_icmp(now, &ip, packet),
            _ => self.drop_packet(DropReason::Unsupported),
        }
    }

    fn receive_tcp<const REPORT: bool>(
        &mut self,
        now: Instant,
        ip: &wire::IpPacket,
        packet: &[u8],
        meta: RxMeta,
        report: &mut SourceReport<impl FnMut(ValidatedSource) -> bool>,
    ) -> Rx {
        let seg = &packet[ip.payload.clone()];
        let (h, off) = match wire::tcp::parse(seg) {
            Ok(v) => v,
            Err(e) => return self.drop_packet(e.into()),
        };
        let (verify, gso) = match meta.l4(wire::PROTO_TCP, ip.payload.start, 16) {
            Ok(v) => v,
            Err(reason) => return self.drop_packet(reason),
        };
        if verify && !wire::tcp::verify_checksum(ip.src, ip.dst, seg) {
            return self.drop_packet(DropReason::Checksum);
        }
        if !report.record::<REPORT>(
            SocketAddr::new(ip.src, h.src_port),
            SocketAddr::new(ip.dst, h.dst_port),
            wire::PROTO_TCP,
            Some(h.flags),
        ) {
            return self.drop_packet(DropReason::NotForUs);
        }
        let tuple = FourTuple {
            local: SocketAddr::new(ip.dst, h.dst_port),
            remote: SocketAddr::new(ip.src, h.src_port),
        };
        let index = self
            .cache
            .filter(|(key, id)| {
                *key == tuple
                    && self.table.slots.get(id.idx as usize).is_some_and(|s| {
                        s.generation == id.generation && matches!(s.flow, Some(Flow::Tcp(_)))
                    })
            })
            .map(|(_, id)| id.idx)
            .or_else(|| self.table.tcp.get(&tuple).copied());
        if let Some(index) = index {
            let slot = &mut self.table.slots[index as usize];
            let id = FlowId {
                idx: index,
                generation: slot.generation,
            };
            self.cache = Some((tuple, id));
            if let Some(Flow::Tcp(t)) = slot.flow.as_mut()
                && let Some((seq, ack, flags)) = t.input(now, &h, &seg[off..], gso, &mut self.pool)
            {
                self.control(tuple, seq, ack, flags, Some(id));
            }
            self.sync(index, now);
            return Rx::Consumed;
        }
        let reopen = self.timewait_reopen(tuple, &h);
        if reopen.is_none()
            && let Some(&index) = self.table.timewait.get(&tuple)
        {
            let slot = &mut self.table.slots[index as usize];
            if let Some(Flow::TimeWait(t)) = slot.flow.as_mut() {
                let args = (
                    seg.len() - off,
                    t.snd_nxt,
                    t.rcv_nxt,
                    t.max_snd_wnd,
                    t.ts_recent,
                );
                let fin =
                    crate::tcp::valid_timewait_fin(&h, args.0, args.1, args.2, args.3, args.4);
                if fin {
                    t.expiry = now + crate::tcp::TIME_WAIT;
                    if t.ts_recent.is_some() {
                        t.ts_recent = h.options.timestamps.map(|v| v.0);
                    }
                }
                if (fin
                    || crate::tcp::valid_timewait_old_data(
                        &h, args.0, args.1, args.2, args.3, args.4,
                    ))
                    && !t.ack_due
                {
                    t.ack_due = true;
                    self.timewait_ready.push_back(FlowId {
                        idx: index,
                        generation: slot.generation,
                    });
                }
            }
            self.timers.refresh(&mut self.table, index);
            return Rx::Consumed;
        }
        if self.transparent()
            && let Some(rx) = self.passive_open(now, tuple, &h, ip.dscp, reopen)
        {
            if REPORT && matches!(rx, Rx::Consumed) {
                report.tcp_admission = self.table.tcp.get(&tuple).map(|&index| FlowId {
                    idx: index,
                    generation: self.table.slots[index as usize].generation,
                });
            }
            return rx;
        }
        if h.flags & wire::tcp::RST == 0 {
            if h.flags & wire::tcp::ACK != 0 {
                self.control(tuple, h.ack, 0, wire::tcp::RST, None);
            } else {
                let ack = h.seq.wrapping_add(
                    (seg.len() - off) as u32
                        + u32::from(h.flags & wire::tcp::SYN != 0)
                        + u32::from(h.flags & wire::tcp::FIN != 0),
                );
                self.control(tuple, 0, ack, wire::tcp::RST | wire::tcp::ACK, None);
            }
        }
        self.drop_packet(DropReason::NoFlow)
    }

    pub fn poll_transmit(&mut self, now: Instant, out: &mut [u8]) -> Option<usize> {
        self.poll_transmit_with(now, out, TxCaps::NONE)
            .map(|t| t.len)
    }

    /// [`Stack::poll_transmit`] for a driver that can take segmentation offload. With `caps.tso4`
    /// / `tso6` a TCP flow may emit one packet of up to 64 KiB of payload: one header, several
    /// MSS-sized segments ([`Transmit::gso`]), the checksum field holding only the pseudo-header
    /// sum ([`TxCsum::Partial`]). Packets of every other class, and every packet from an
    /// endpoint-mode stack (which ignores `caps`), are ordinary, complete ones.
    ///
    /// How much a packet carries follows the congestion and receive windows, the pacer (a burst is
    /// at most two milliseconds of traffic) and about a millisecond of the pacing rate, as TSO
    /// autosizing; the output buffer bounds it too, so any buffer that holds one MTU-sized packet
    /// works. Every segment keeps its own send descriptor, and a run of lost segments is
    /// retransmitted in one TSO packet too.
    pub fn poll_transmit_with(
        &mut self,
        now: Instant,
        out: &mut [u8],
        caps: TxCaps,
    ) -> Option<Transmit> {
        self.poll_transmit_filtered(now, out, caps, false)
    }

    /// Pulls only protocol control output: no TCP payload or UDP datagrams/fragments.
    /// A driver reserves control credit before this call; payload readiness stays queued.
    pub fn poll_control_transmit(&mut self, now: Instant, out: &mut [u8]) -> Option<Transmit> {
        if self.control_ready.is_none() {
            let mut queue = VecDeque::with_capacity(self.ready.len());
            for &id in &self.ready {
                let slot = &mut self.table.slots[id.idx as usize];
                if slot.generation == id.generation
                    && slot.on_tx
                    && matches!(slot.flow, Some(Flow::Tcp(_)))
                {
                    slot.on_control = true;
                    queue.push_back(id);
                }
            }
            self.control_ready = Some(queue);
        }
        self.poll_transmit_filtered(now, out, TxCaps::NONE, true)
    }

    fn poll_transmit_filtered(
        &mut self,
        now: Instant,
        out: &mut [u8],
        caps: TxCaps,
        control_only: bool,
    ) -> Option<Transmit> {
        self.now = now;
        let caps = if self.transparent() && !control_only {
            caps
        } else {
            TxCaps::NONE
        };
        let mut tx = Transmit::plain(0);
        let first_class = if control_only {
            self.control_class
        } else {
            self.class
        };
        for step in 0..5 {
            let class = (first_class + step) % 5;
            let result = match class {
                0 => self.emit_control(now, out, &mut tx),
                1 => self.emit_timewait(now, out, &mut tx),
                2 => self.emit_flow(now, out, caps, &mut tx, control_only),
                3 if !control_only => self.poll_udp_frag(out),
                3 => Output::None,
                _ => self.reasm.poll_icmp(now, &mut self.icmp_out, out),
            };
            match result {
                Output::Sent(n) => {
                    if control_only {
                        self.control_class = (class + 1) % 5;
                    } else {
                        self.class = (class + 1) % 5;
                    }
                    if class != 3 {
                        // `poll_udp_frag` counts its own packets.
                        self.counters.tx_packets += 1;
                    }
                    tx.len = n;
                    return Some(tx);
                }
                Output::Blocked => return None,
                Output::Deferred | Output::None => {}
            }
        }
        None
    }

    fn emit_control(&mut self, now: Instant, out: &mut [u8], tx: &mut Transmit) -> Output {
        while let Some(c) = self.controls.front().copied() {
            if let Some(how) = c.icmp {
                match self.emit_refusal(now, &c, how, out) {
                    Output::None => continue,
                    Output::Sent(n) => {
                        tx.flow = c.flow;
                        return Output::Sent(n);
                    }
                    result => return result,
                }
            }
            let h = wire::tcp::Header {
                src_port: c.tuple.local.port(),
                dst_port: c.tuple.remote.port(),
                seq: c.seq,
                ack: c.ack,
                flags: c.flags,
                window: 0,
                urgent: 0,
                options: wire::tcp::Options::default(),
            };
            return match wire::tcp::emit_packet(
                out,
                c.tuple.local.ip(),
                c.tuple.remote.ip(),
                &h,
                [&[], &[]],
            ) {
                Some(n) => {
                    self.controls.pop_front();
                    tx.flow = c.flow;
                    Output::Sent(n)
                }
                None => Output::Blocked,
            };
        }
        Output::None
    }

    fn emit_timewait(&mut self, now: Instant, out: &mut [u8], tx: &mut Transmit) -> Output {
        while let Some(id) = self.timewait_ready.front().copied() {
            let slot = &mut self.table.slots[id.idx as usize];
            if slot.generation != id.generation || !matches!(slot.flow, Some(Flow::TimeWait(_))) {
                self.timewait_ready.pop_front();
                continue;
            }
            let Some(Flow::TimeWait(t)) = slot.flow.as_mut() else {
                unreachable!()
            };
            if !t.ack_due {
                self.timewait_ready.pop_front();
                continue;
            }
            let mut options = wire::tcp::Options::default();
            if let Some(recent) = t.ts_recent {
                options.timestamps = Some((
                    t.ts_offset
                        .wrapping_add(now.saturating_duration_since(self.epoch).as_millis() as u32),
                    recent,
                ));
            }
            let h = wire::tcp::Header {
                src_port: t.tuple.local.port(),
                dst_port: t.tuple.remote.port(),
                seq: t.snd_nxt,
                ack: t.rcv_nxt,
                flags: wire::tcp::ACK,
                window: t.window,
                urgent: 0,
                options,
            };
            return match wire::tcp::emit_packet(
                out,
                t.tuple.local.ip(),
                t.tuple.remote.ip(),
                &h,
                [&[], &[]],
            ) {
                Some(n) => {
                    tx.flow = Some(FlowId {
                        idx: id.idx,
                        generation: t.handle_generation,
                    });
                    t.ack_due = false;
                    self.timewait_ready.pop_front();
                    Output::Sent(n)
                }
                None => Output::Blocked,
            };
        }
        Output::None
    }

    fn emit_flow(
        &mut self,
        now: Instant,
        out: &mut [u8],
        caps: TxCaps,
        tx: &mut Transmit,
        control_only: bool,
    ) -> Output {
        let ready = if control_only {
            self.control_ready.as_ref().unwrap().len()
        } else {
            self.ready.len()
        };
        for _ in 0..ready {
            let id = if control_only {
                self.control_ready.as_mut().unwrap().pop_front()
            } else {
                self.ready.pop_front()
            };
            let Some(id) = id else { break };
            let slot = &mut self.table.slots[id.idx as usize];
            let queued = if control_only {
                slot.on_control
            } else {
                slot.on_tx
            };
            if slot.generation != id.generation || !queued {
                continue;
            }
            if control_only {
                slot.on_control = false;
            } else {
                slot.on_tx = false;
            }
            let Some(Flow::Tcp(t)) = slot.flow.as_mut() else {
                continue;
            };
            let quantum = u32::from(self.cfg.mtu);
            let deficit = slot.deficit;
            if !control_only && slot.deficit < quantum {
                slot.deficit += quantum;
            }
            let tso = if caps.tso(t.tuple.local.is_ipv6()) {
                usize::from(u16::MAX)
            } else {
                0
            };
            let result = t.output_with(now, out, &mut self.pool, tso, tx, !control_only);
            match result {
                Output::Sent(n) => {
                    tx.flow = Some(id);
                    if control_only {
                        slot.on_control = true;
                        self.control_ready.as_mut().unwrap().push_back(id);
                        self.sync_without_tx(id.idx, now);
                    } else {
                        slot.deficit = slot.deficit.saturating_sub(n as u32);
                        slot.on_tx = true;
                        if slot.deficit >= quantum {
                            self.ready.push_front(id);
                        } else {
                            self.ready.push_back(id);
                        }
                        self.sync(id.idx, now);
                    }
                    return Output::Sent(n);
                }
                Output::Blocked | Output::Deferred if control_only => {
                    slot.on_control = true;
                    self.control_ready.as_mut().unwrap().push_back(id);
                    self.sync_without_tx(id.idx, now);
                }
                Output::Blocked => {
                    slot.on_tx = true;
                    self.ready.push_front(id);
                    return Output::Blocked;
                }
                Output::Deferred => {
                    slot.deficit = deficit;
                    slot.on_tx = true;
                    self.ready.push_back(id);
                    self.sync_without_tx(id.idx, now);
                }
                Output::None => self.sync_without_tx(id.idx, now),
            }
        }
        Output::None
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

    pub fn tcp_connect(
        &mut self,
        now: Instant,
        remote: SocketAddr,
    ) -> Result<FlowId, ConnectError> {
        self.now = now;
        let local_ip = self
            .local_for(remote.ip())
            .ok_or(ConnectError::NoLocalAddress)?;
        if self.table.active >= self.cfg.max_flows {
            return Err(ConnectError::FlowLimit);
        }
        if self.table.tcp_active >= self.floor_cap {
            return Err(ConnectError::Memory);
        }
        let mut port = self.ports.start(&self.cfg.secret, local_ip, remote);
        let offset = flow::ts_offset(&self.cfg.secret, local_ip, remote.ip());
        let stamp =
            offset.wrapping_add(now.saturating_duration_since(self.epoch).as_millis() as u32);
        let mut choice = None;
        for _ in 0..32768 {
            let tuple = FourTuple {
                local: SocketAddr::new(local_ip, port),
                remote,
            };
            let iss = flow::isn(
                &self.cfg.secret,
                tuple,
                now.saturating_duration_since(self.epoch),
            );
            if !self.table.tcp.contains_key(&tuple) {
                if let Some(&index) = self.table.timewait.get(&tuple) {
                    let can_reuse = matches!(&self.table.slots[index as usize].flow, Some(Flow::TimeWait(tw)) if tw.reusable(iss, stamp));
                    if can_reuse && self.table.can_insert(Some(index)) {
                        choice = Some((tuple, iss, Some(index)));
                        break;
                    }
                } else if self.table.can_insert(None) {
                    choice = Some((tuple, iss, None));
                    break;
                }
            }
            port = flow::next_port(port);
        }
        let (tuple, iss, replacing) = choice.ok_or_else(|| {
            if self.table.can_insert(None) {
                ConnectError::AddrInUse
            } else {
                ConnectError::FlowLimit
            }
        })?;
        if !self.pool.admit_floor() {
            return Err(ConnectError::Memory);
        }
        if let Some(index) = replacing {
            self.table.remove(index);
            self.purge_stale();
        }
        let mut t = Tcb::new(tuple, &self.cfg, now, self.epoch, iss, offset);
        t.init_window(&mut self.pool);
        let id = self.table.insert(Flow::Tcp(Box::new(t)));
        self.sync(id.idx, now);
        self.tx_wakeup = true;
        Ok(id)
    }

    pub fn tcp_write(&mut self, id: FlowId, data: &[u8]) -> Result<usize, StreamError> {
        let Some(Flow::Tcp(t)) = self.table.get_mut(id) else {
            return Err(StreamError::Stale);
        };
        let result = t.write(&mut self.pool, data);
        if result == Err(StreamError::WouldBlock)
            && !t.write_wait_queued
            && t.tx.tail_room(&self.pool) == 0
        {
            t.write_wait_queued = true;
            self.writers.push_back(id);
        }
        if result.as_ref().is_ok_and(|&n| n != 0) {
            self.tx_wakeup = true;
            self.sync(id.idx, self.now);
        }
        result
    }

    pub fn tcp_read(&mut self, id: FlowId, out: &mut [u8]) -> Result<usize, StreamError> {
        let Some(Flow::Tcp(t)) = self.table.get_mut(id) else {
            return Err(StreamError::Stale);
        };
        let result = t.read(&mut self.pool, out, self.now);
        if t.ack_due != 0 {
            self.tx_wakeup = true;
        }
        self.sync(id.idx, self.now);
        result
    }

    pub fn tcp_shutdown(&mut self, id: FlowId) -> Result<(), StreamError> {
        let Some(Flow::Tcp(t)) = self.table.get_mut(id) else {
            return Err(StreamError::Stale);
        };
        let result = t.shutdown();
        if result.is_ok() {
            self.tx_wakeup = true;
            self.sync(id.idx, self.now);
        }
        result
    }

    /// Releases the handle immediately. Unread data aborts with RST, as on Linux.
    pub fn tcp_close(&mut self, id: FlowId) {
        if let Some(Flow::Tcp(t)) = self.table.get_mut(id) {
            t.close(self.now);
            self.tx_wakeup = true;
            self.sync(id.idx, self.now);
        }
    }

    pub fn tcp_abort(&mut self, id: FlowId) {
        if let Some(Flow::Tcp(t)) = self.table.get_mut(id) {
            t.abort();
            self.tx_wakeup = true;
            self.sync(id.idx, self.now);
        }
    }

    pub fn tcp_state(&self, id: FlowId) -> Option<TcpState> {
        match self.table.get(id)? {
            Flow::Tcp(t) => Some(t.state),
            _ => None,
        }
    }

    /// Whether this Stack still owns application, protocol or queued-control obligations for
    /// the original TCP handle, including after close and TIME_WAIT compaction.
    ///
    /// The handle must come from this Stack. A false result does not release packets already
    /// returned by `poll_transmit_with`: the driver must separately drain their saved `flow`
    /// ownership, other producers and application tasks before retiring the scoped flow.
    pub fn tcp_retained(&self, id: FlowId) -> bool {
        if id.generation == 0 {
            return false;
        }
        self.table
            .slots
            .get(id.idx as usize)
            .is_some_and(|slot| match &slot.flow {
                Some(Flow::Tcp(_)) => slot.generation == id.generation,
                Some(Flow::TimeWait(t)) => t.handle_generation == id.generation,
                _ => false,
            })
            || self.controls.iter().any(|control| control.flow == Some(id))
    }

    /// Read-only execution ownership through pending TCP, TIME_WAIT and flow-owned
    /// control output. This is not packet validation or admission authority.
    pub fn retains_tcp(&self, source: SocketAddr, destination: SocketAddr) -> bool {
        let tuple = FourTuple {
            local: destination,
            remote: source,
        };
        self.table.tcp.contains_key(&tuple)
            || self.table.timewait.contains_key(&tuple)
            || self
                .controls
                .iter()
                .any(|control| control.flow.is_some() && control.tuple == tuple)
    }

    /// Whether this peer still owns protocol state or an unpulled reply. Packets already
    /// exported to an adapter and its application work need separate retention there.
    pub fn retains_source(&self, address: IpAddr) -> bool {
        self.table
            .tcp
            .keys()
            .chain(self.table.timewait.keys())
            .any(|tuple| tuple.remote.ip() == address)
            || self
                .controls
                .iter()
                .any(|control| control.tuple.remote.ip() == address)
            || self.udp_tx.retains_destination(address)
            || self
                .reasm
                .obligations()
                .any(|(source, _, _)| source == address)
    }

    /// Reply materialization still pending inside the Stack, before adapter ownership.
    pub fn retains_source_output(&self, address: IpAddr) -> bool {
        self.table.slots.iter().any(|slot| match &slot.flow {
            Some(Flow::Tcp(t)) => t.tuple.remote.ip() == address && (slot.on_tx || slot.on_control),
            Some(Flow::TimeWait(t)) => t.tuple.remote.ip() == address && t.ack_due,
            _ => false,
        }) || self
            .controls
            .iter()
            .any(|control| control.tuple.remote.ip() == address)
            || self.udp_tx.retains_destination(address)
            || self
                .reasm
                .obligations()
                .any(|(source, _, _)| source == address)
    }
    pub fn tcp_stats(&self, id: FlowId) -> Option<TcpStats> {
        match self.table.get(id)? {
            Flow::Tcp(t) => Some(t.stats(self.pool.chunk())),
            _ => None,
        }
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

    pub(crate) fn sync(&mut self, index: u32, now: Instant) {
        self.collect(index, now, true);
    }
    fn sync_without_tx(&mut self, index: u32, now: Instant) {
        self.collect(index, now, false);
    }

    fn collect(&mut self, index: u32, now: Instant, tx: bool) {
        let slot = &mut self.table.slots[index as usize];
        let id = FlowId {
            idx: index,
            generation: slot.generation,
        };
        let mut remove = false;
        let mut compact = None;
        let mut left_half_open = None;
        if let Some(Flow::Tcp(t)) = slot.flow.as_mut() {
            t.check();
            if t.half_open && t.state != TcpState::SynReceived {
                t.half_open = false;
                left_half_open = Some(t.tuple.remote.ip());
            }
            if !t.app_open {
                if t.state == TcpState::Closed && !t.rst_pending {
                    remove = true;
                } else if t.state == TcpState::TimeWait && t.available() == 0 && t.ack_due == 0 {
                    compact = Some(TimeWait::from_tcb(t, now, id.generation));
                }
            }
            if !remove && compact.is_none() {
                let ready = std::mem::take(&mut t.ready);
                if t.app_open && !ready.is_empty() {
                    slot.ready |= ready;
                    if !slot.on_event {
                        slot.on_event = true;
                        self.events.push_back(id);
                    }
                }
                if tx && !slot.on_tx {
                    slot.on_tx = true;
                    self.ready.push_back(id);
                }
                if tx
                    && !slot.on_control
                    && let Some(queue) = &mut self.control_ready
                {
                    slot.on_control = true;
                    queue.push_back(id);
                }
            }
        }
        if let Some(source) = left_half_open {
            self.leave_half_open(source);
        }
        let retired = remove || compact.is_some();
        if remove {
            if let Some(Flow::Tcp(mut t)) = self.table.remove(index) {
                t.release(&mut self.pool);
                self.pool.release_floor();
            }
        } else if let Some(tw) = compact {
            if let Some(Flow::Tcp(t)) = self.table.slots[index as usize].flow.as_mut() {
                t.release(&mut self.pool);
                self.pool.release_floor();
            }
            self.table.compact(index, tw);
        }
        if retired {
            self.purge_stale();
        }
        self.timers.mark(&mut self.table, index);
        self.wake_writers();
    }

    fn wake_writers(&mut self) {
        let count = self.writers.len();
        for _ in 0..count {
            let Some(id) = self.writers.pop_front() else {
                break;
            };
            let slot = &mut self.table.slots[id.idx as usize];
            if slot.generation != id.generation {
                continue;
            }
            let Some(Flow::Tcp(t)) = slot.flow.as_mut() else {
                continue;
            };
            if !t.write_blocked || !t.app_open {
                t.write_wait_queued = false;
            } else if t.can_write(&self.pool) {
                t.write_wait_queued = false;
                t.write_blocked = false;
                slot.ready |= Ready::WRITABLE;
                if !slot.on_event {
                    slot.on_event = true;
                    self.events.push_back(id);
                }
            } else {
                self.writers.push_back(id);
            }
        }
    }

    /// Drops queue nodes of removed flows. Every pop already skips them by generation, so this only
    /// bounds growth: a queue is swept once it holds twice what the live slots could, which costs
    /// O(1) amortized per removal where sweeping on each removal made mass teardown quadratic.
    pub(crate) fn purge_stale(&mut self) {
        let limit = 2 * self.table.slots.len().max(16);
        let slots = &self.table.slots;
        for queue in [
            &mut self.events,
            &mut self.ready,
            &mut self.writers,
            &mut self.timewait_ready,
            &mut self.accept_q,
        ]
        .into_iter()
        .chain(self.control_ready.iter_mut())
        {
            if queue.len() > limit {
                #[cfg(test)]
                {
                    self.purge_visits += queue.len();
                }
                queue.retain(|id| slots[id.idx as usize].generation == id.generation);
            }
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
        assert!(self.controls.len() <= CONTROL_LIMIT);
        self.reasm.check();
        self.udp_tx.check();
        assert!(self.stats().memory_committed <= self.cfg.memory_limit);
    }

    /// After every flow, handle and TIME_WAIT entry is gone, nothing may remain charged.
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
            assert_eq!(budget.used(), 0, "the shared budget still holds a charge");
        }
    }

    pub(crate) fn control(
        &mut self,
        tuple: FourTuple,
        seq: u32,
        ack: u32,
        flags: u8,
        flow: Option<FlowId>,
    ) {
        self.queue_control(Control {
            tuple,
            seq,
            ack,
            flags,
            icmp: None,
            flow,
        });
    }

    pub(crate) fn queue_control(&mut self, c: Control) {
        if self.controls.len() == CONTROL_LIMIT {
            self.counters.control_dropped += 1;
            return;
        }
        self.controls.push_back(c);
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

    /// Why a packet is not ours, if it is not. A transparent stack answers for every unicast
    /// destination except the excluded ones, and refuses mapped IPv6 wire endpoints.
    fn refuses(&self, src: IpAddr, dst: IpAddr) -> Option<DropReason> {
        match &self.cfg.mode {
            Mode::Endpoint => (self.local_for(dst) != Some(dst)).then_some(DropReason::NotForUs),
            Mode::Transparent { exclude } => {
                // Mapped addresses represent IPv4 sockets, not IPv6 wire endpoints.
                if matches!(src, IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some())
                    || matches!(dst, IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some())
                    || !is_unicast(dst)
                {
                    Some(DropReason::Unsupported)
                } else {
                    exclude.contains(dst).then_some(DropReason::NotForUs)
                }
            }
        }
    }

    /// A TIME_WAIT entry that `h`, a plain SYN, may replace: its index and `snd_nxt`.
    fn timewait_reopen(&self, tuple: FourTuple, h: &wire::tcp::Header) -> Option<(u32, u32)> {
        if !self.transparent()
            || h.flags & (wire::tcp::SYN | wire::tcp::ACK | wire::tcp::RST | wire::tcp::FIN)
                != wire::tcp::SYN
        {
            return None;
        }
        let &index = self.table.timewait.get(&tuple)?;
        let Some(Flow::TimeWait(tw)) = &self.table.slots[index as usize].flow else {
            return None;
        };
        tw.syn_reopens(h.seq, h.options.timestamps.map(|v| v.0))
            .then_some((index, tw.snd_nxt))
    }
    pub(crate) fn drop_packet(&mut self, reason: DropReason) -> Rx {
        self.counters.drops[reason as usize] += 1;
        Rx::Dropped(reason)
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
