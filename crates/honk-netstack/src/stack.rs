//! Public sans-I/O API and the single-owner scheduler.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::{BitOr, BitOrAssign, Range};
use std::sync::Arc;
use std::time::Instant;

use crate::MemoryBudget;
use crate::flow::{self, Flow, FourTuple, Ports, Table, TimeWait};
use crate::tcp::output::Output;
use crate::tcp::ring::{FLOOR, Pool};
use crate::tcp::{Tcb, TcpState, TcpStats};
use crate::timer::Timers;
use crate::wire::{self, ParseError};

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
    /// Process-wide limit on top of `memory_limit`: floors and shared commitments are charged to
    /// both. Stacks sharing one budget cannot exceed it together; a dropped stack returns its share.
    pub shared_budget: Option<Arc<MemoryBudget>>,
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
        }
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
        payload: Range<usize>,
    },
    /// A transparent datagram that was reassembled from fragments; `payload` indexes `packet`.
    TransparentOwned {
        src: SocketAddr,
        dst: SocketAddr,
        packet: Vec<u8>,
        payload: Range<usize>,
    },
    Dropped(DropReason),
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
    #[error("pending fragment queue is full")]
    Busy,
    #[error("source and destination address families differ")]
    FamilyMismatch,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StackStats {
    /// Indexed by the discriminant of [`DropReason`].
    pub drops: [u64; 8],
    pub memory_committed: usize,
    pub memory_allocated: usize,
    pub flows: u32,
    pub timewait_entries: usize,
    pub control_dropped: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Clone, Copy)]
struct Control {
    tuple: FourTuple,
    seq: u32,
    ack: u32,
    flags: u8,
}
const CONTROL_LIMIT: usize = 128;

pub struct Stack {
    pub(crate) cfg: Config,
    pub(crate) now: Instant,
    pub(crate) epoch: Instant,
    pub(crate) table: Table,
    ports: Ports,
    pool: Pool,
    floor_cap: u32,
    timers: Timers,
    /// Queue elements `purge_stale` has visited; lets tests assert teardown stays amortized O(1).
    #[cfg(test)]
    purge_visits: usize,
    events: VecDeque<FlowId>,
    ready: VecDeque<FlowId>,
    writers: VecDeque<FlowId>,
    timewait_ready: VecDeque<FlowId>,
    controls: VecDeque<Control>,
    pub(crate) tx_wakeup: bool,
    class: u8,
    cache: Option<(FourTuple, FlowId)>,
    pub(crate) counters: StackStats,
    pub(crate) udp_tx: crate::udp_t::UdpTx,
    #[allow(dead_code)] // read once transparent mode is wired
    pub(crate) icmp_out: crate::icmp_out::IcmpOut,
    #[allow(dead_code)]
    pub(crate) reasm: crate::fragment::Reassembler,
}

impl Stack {
    pub fn new(mut cfg: Config, now: Instant) -> Stack {
        cfg.mtu = cfg.mtu.max(if cfg.local_v6.is_some() { 1280 } else { 68 });
        let floor_cap = cfg
            .max_flows
            .min((cfg.memory_limit / FLOOR).min(u32::MAX as usize) as u32);
        let reserved = floor_cap as usize * FLOOR;
        let pool = Pool::with_limits(cfg.memory_limit.saturating_sub(reserved), cfg.memory_limit)
            .with_budget(cfg.shared_budget.clone());
        let ports = Ports::new(&cfg.secret);
        Stack {
            udp_tx: crate::udp_t::UdpTx::new(&cfg.secret),
            icmp_out: crate::icmp_out::IcmpOut::default(),
            reasm: crate::fragment::Reassembler::default(),
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
            writers: VecDeque::new(),
            timewait_ready: VecDeque::new(),
            controls: VecDeque::new(),
            tx_wakeup: false,
            class: 0,
            cache: None,
            counters: StackStats::default(),
        }
    }

    pub fn receive(&mut self, now: Instant, packet: &[u8]) -> Rx {
        self.now = now;
        self.counters.rx_packets += 1;
        let ip = match wire::parse_ip(packet) {
            Ok(ip) => ip,
            Err(e) => return self.drop_packet(e.into()),
        };
        if !self.is_local(ip.dst) {
            return self.drop_packet(DropReason::NotForUs);
        }
        match ip.proto {
            wire::PROTO_TCP => self.receive_tcp(now, &ip, packet),
            wire::PROTO_UDP => self.receive_udp(&ip, packet),
            wire::PROTO_ICMP | wire::PROTO_ICMPV6 => self.receive_icmp(now, &ip, packet),
            _ => self.drop_packet(DropReason::Unsupported),
        }
    }

    fn receive_tcp(&mut self, now: Instant, ip: &wire::IpPacket, packet: &[u8]) -> Rx {
        let seg = &packet[ip.payload.clone()];
        let (h, off) = match wire::tcp::parse(seg) {
            Ok(v) => v,
            Err(e) => return self.drop_packet(e.into()),
        };
        if !wire::tcp::verify_checksum(ip.src, ip.dst, seg) {
            return self.drop_packet(DropReason::Checksum);
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
            self.cache = Some((
                tuple,
                FlowId {
                    idx: index,
                    generation: slot.generation,
                },
            ));
            if let Some(Flow::Tcp(t)) = slot.flow.as_mut()
                && let Some((seq, ack, flags)) = t.input(now, &h, &seg[off..], &mut self.pool)
            {
                self.control(tuple, seq, ack, flags);
            }
            self.sync(index, now);
            return Rx::Consumed;
        }
        if let Some(&index) = self.table.timewait.get(&tuple) {
            let slot = &mut self.table.slots[index as usize];
            if let Some(Flow::TimeWait(t)) = slot.flow.as_mut()
                && crate::tcp::valid_timewait_fin(
                    &h,
                    seg.len() - off,
                    t.snd_nxt,
                    t.rcv_nxt,
                    t.max_snd_wnd,
                    t.ts_recent,
                )
            {
                t.expiry = now + crate::tcp::TIME_WAIT;
                if t.ts_recent.is_some() {
                    t.ts_recent = h.options.timestamps.map(|v| v.0);
                }
                if !t.ack_due {
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
        if h.flags & wire::tcp::RST == 0 {
            if h.flags & wire::tcp::ACK != 0 {
                self.control(tuple, h.ack, 0, wire::tcp::RST);
            } else {
                let ack = h.seq.wrapping_add(
                    (seg.len() - off) as u32
                        + u32::from(h.flags & wire::tcp::SYN != 0)
                        + u32::from(h.flags & wire::tcp::FIN != 0),
                );
                self.control(tuple, 0, ack, wire::tcp::RST | wire::tcp::ACK);
            }
        }
        self.drop_packet(DropReason::NoFlow)
    }

    pub fn poll_transmit(&mut self, now: Instant, out: &mut [u8]) -> Option<usize> {
        self.now = now;
        for step in 0..3 {
            let class = (self.class + step) % 3;
            let result = match class {
                0 => self.emit_control(out),
                1 => self.emit_timewait(now, out),
                _ => self.emit_flow(now, out),
            };
            match result {
                Output::Sent(n) => {
                    self.class = (class + 1) % 3;
                    self.counters.tx_packets += 1;
                    return Some(n);
                }
                Output::Blocked => return None,
                Output::None => {}
            }
        }
        None
    }

    fn emit_control(&mut self, out: &mut [u8]) -> Output {
        let Some(c) = self.controls.front() else {
            return Output::None;
        };
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
        match wire::tcp::emit_packet(out, c.tuple.local.ip(), c.tuple.remote.ip(), &h, [&[], &[]]) {
            Some(n) => {
                self.controls.pop_front();
                Output::Sent(n)
            }
            None => Output::Blocked,
        }
    }

    fn emit_timewait(&mut self, now: Instant, out: &mut [u8]) -> Output {
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
                    t.ack_due = false;
                    self.timewait_ready.pop_front();
                    Output::Sent(n)
                }
                None => Output::Blocked,
            };
        }
        Output::None
    }

    fn emit_flow(&mut self, now: Instant, out: &mut [u8]) -> Output {
        while let Some(id) = self.ready.pop_front() {
            let slot = &mut self.table.slots[id.idx as usize];
            if slot.generation != id.generation || !slot.on_tx {
                continue;
            }
            slot.on_tx = false;
            let Some(Flow::Tcp(t)) = slot.flow.as_mut() else {
                continue;
            };
            let quantum = usize::from(self.cfg.mtu);
            if slot.deficit < quantum {
                slot.deficit += quantum;
            }
            let result = t.output(now, out, &mut self.pool);
            match result {
                Output::Sent(n) => {
                    slot.deficit = slot.deficit.saturating_sub(n);
                    slot.on_tx = true;
                    if slot.deficit >= quantum {
                        self.ready.push_front(id);
                    } else {
                        self.ready.push_back(id);
                    }
                    self.sync(id.idx, now);
                    return Output::Sent(n);
                }
                Output::Blocked => {
                    slot.on_tx = true;
                    self.ready.push_front(id);
                    return Output::Blocked;
                }
                Output::None => {
                    self.sync_without_tx(id.idx, now);
                }
            }
        }
        Output::None
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        self.timers.next()
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        self.now = now;
        while let Some((deadline, index, generation)) = self.timers.pop_due(now) {
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
    }

    pub fn poll_event(&mut self) -> Option<(FlowId, Ready)> {
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
                    if can_reuse {
                        self.table.remove(index);
                        self.purge_stale();
                        choice = Some((tuple, iss));
                        break;
                    }
                } else {
                    choice = Some((tuple, iss));
                    break;
                }
            }
            port = flow::next_port(port);
        }
        let (tuple, iss) = choice.ok_or(ConnectError::AddrInUse)?;
        if !self.pool.admit_floor() {
            return Err(ConnectError::Memory);
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
            && self.pool.shared_free() == 0
            && t.tx.tail_room() == 0
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
    pub fn tcp_stats(&self, id: FlowId) -> Option<TcpStats> {
        match self.table.get(id)? {
            Flow::Tcp(t) => Some(t.stats()),
            _ => None,
        }
    }

    pub fn stats(&self) -> StackStats {
        StackStats {
            memory_committed: self.table.tcp_active as usize * FLOOR + self.pool.shared_bytes(),
            memory_allocated: self.pool.allocated_bytes(),
            flows: self.table.active,
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
        if let Some(Flow::Tcp(t)) = slot.flow.as_mut() {
            t.check();
            if !t.app_open {
                if t.state == TcpState::Closed && !t.rst_pending {
                    remove = true;
                } else if t.state == TcpState::TimeWait && t.available() == 0 && t.ack_due == 0 {
                    compact = Some(TimeWait::from_tcb(t, now));
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
            }
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
        self.timers.refresh(&mut self.table, index);
        self.wake_writers();
    }

    fn wake_writers(&mut self) {
        if self.pool.shared_free() == 0 {
            return;
        }
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
                t.write_wait_queued = false;
            }
        }
    }

    /// Drops queue nodes of removed flows. Every pop already skips them by generation, so this only
    /// bounds growth: a queue is swept once it holds twice what the live slots could, which costs
    /// O(1) amortized per removal where sweeping on each removal made mass teardown quadratic.
    fn purge_stale(&mut self) {
        let limit = 2 * self.table.slots.len().max(16);
        let slots = &self.table.slots;
        for queue in [
            &mut self.events,
            &mut self.ready,
            &mut self.writers,
            &mut self.timewait_ready,
        ] {
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
                    slot.scheduled.is_some_and(|s| s <= deadline),
                    "a flow deadline is not covered by a timer entry, so the owner could oversleep it"
                );
            }
        }
        let bound = 3 * self.table.slots.len().max(16);
        for queue in [
            &self.events,
            &self.ready,
            &self.writers,
            &self.timewait_ready,
        ] {
            assert!(
                queue.len() <= bound,
                "stale queue nodes outgrew the sweep bound"
            );
        }
        assert!(
            self.timers.len() <= 2 * self.table.slots.len().max(16) + 1,
            "the timer heap outgrew its rebuild bound"
        );
        assert!(self.controls.len() <= CONTROL_LIMIT);
        assert!(self.stats().memory_committed <= self.cfg.memory_limit);
    }

    /// After every flow, handle and TIME_WAIT entry is gone, nothing may remain charged.
    #[cfg(feature = "fuzz-checks")]
    pub(crate) fn assert_released(&self) {
        self.check();
        assert_eq!(self.table.active, 0);
        assert_eq!(self.table.timewait.len(), 0);
        assert_eq!(self.stats().memory_committed, 0);
        self.pool.assert_idle();
        if let Some(budget) = &self.cfg.shared_budget {
            assert_eq!(budget.used(), 0, "the shared budget still holds a charge");
        }
    }

    fn control(&mut self, tuple: FourTuple, seq: u32, ack: u32, flags: u8) {
        if self.controls.len() == CONTROL_LIMIT {
            self.counters.control_dropped += 1;
            return;
        }
        self.controls.push_back(Control {
            tuple,
            seq,
            ack,
            flags,
        });
    }

    pub(crate) fn local_for(&self, remote: IpAddr) -> Option<IpAddr> {
        match remote {
            IpAddr::V4(_) => self.cfg.local_v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.cfg.local_v6.map(IpAddr::V6),
        }
    }
    fn is_local(&self, addr: IpAddr) -> bool {
        self.local_for(addr) == Some(addr)
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
            "idle state excludes rings' separately allocated storage"
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
