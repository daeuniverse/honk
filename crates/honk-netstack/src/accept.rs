//! Passive TCP open for [`crate::Mode::Transparent`]: a SYN creates a pending flow, the
//! application admits or refuses it, and only then does anything leave the stack.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::flow::{self, Flow, FourTuple};
use crate::icmp_out::{IcmpEmit, Reject};
use crate::stack::Control;
use crate::tcp::Tcb;
use crate::tcp::output::Output;
use crate::tcp::passive::Gate;
use crate::wire;
use crate::{DropReason, FlowId, Rx, Stack, StreamError};

/// Longest a SYN may stay undecided or deferred. The edge classifier's handoff expires at 30 s;
/// deciding within 25 s keeps the stack's answer from racing it.
pub const MAX_DEFERRED: Duration = Duration::from_secs(25);

/// A new connection the application has not decided on yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynInfo {
    pub id: FlowId,
    pub client: SocketAddr,
    /// The destination the client dialed; replies are sourced from it.
    pub original_dst: SocketAddr,
    /// The client's MSS option (536/1220 when absent).
    pub mss: u16,
    pub wscale: Option<u8>,
    pub sack: bool,
    pub timestamps: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptWhen {
    /// Send the SYN-ACK now.
    Now,
    /// Hold the SYN-ACK until [`Stack::tcp_complete`]; the flow is refused silently when `deadline`
    /// (never beyond [`MAX_DEFERRED`] after the SYN) passes first.
    Deferred { deadline: Duration },
}

/// Per-flow TCP keepalive. Idle for `idle`, then `probes` empty segments `interval` apart; a
/// flow whose probes all go unanswered fails with [`StreamError::TimedOut`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keepalive {
    pub idle: Duration,
    pub interval: Duration,
    pub probes: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptOpts {
    pub when: AcceptWhen,
    /// Upper bound for the connection's MSS in both directions (the client's real egress MTU
    /// minus headers); the tun MTU says nothing about it.
    pub max_mss: Option<u16>,
    /// Off unless set.
    pub keepalive: Option<Keepalive>,
}

impl Default for AcceptOpts {
    fn default() -> AcceptOpts {
        AcceptOpts {
            when: AcceptWhen::Now,
            max_mss: None,
            keepalive: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refuse {
    /// RST|ACK for the SYN.
    Rst,
    /// Forget the SYN silently.
    Drop,
    /// ICMP host unreachable (subject to the ICMP rate limits).
    IcmpUnreachable,
    /// ICMP administratively prohibited (v4 code 13, v6 code 1).
    IcmpAdminProhibited,
}

impl Stack {
    /// Next new connection, once. Nothing has been sent for it.
    pub fn poll_accept(&mut self) -> Option<SynInfo> {
        while let Some(id) = self.accept_q.pop_front() {
            let slot = &mut self.table.slots[id.idx as usize];
            if slot.generation != id.generation {
                continue;
            }
            let Some(Flow::Tcp(t)) = slot.flow.as_mut() else {
                continue;
            };
            if t.gate != Gate::Queued {
                continue;
            }
            t.gate = Gate::Pending;
            return Some(SynInfo {
                id,
                client: t.tuple.remote,
                original_dst: t.tuple.local,
                mss: t.peer_mss,
                wscale: t.wscale.then_some(t.snd_shift),
                sack: t.sack,
                timestamps: t.timestamps,
            });
        }
        None
    }

    /// Admits a pending flow. `Now` queues the SYN-ACK; `Deferred` holds it until
    /// [`Stack::tcp_complete`]. Fails with the flow's error if it already died (for example when
    /// the deferred deadline passed), or [`StreamError::Closed`] if it was already decided.
    pub fn tcp_accept(&mut self, id: FlowId, opts: AcceptOpts) -> Result<(), StreamError> {
        let now = self.now;
        let Some(Flow::Tcp(t)) = self.table.get_mut(id) else {
            return Err(StreamError::Stale);
        };
        if let Some(error) = t.error {
            return Err(error);
        }
        if !matches!(t.gate, Gate::Queued | Gate::Pending) {
            return Err(StreamError::Closed);
        }
        t.accept(&opts, now, &mut self.pool);
        self.tx_wakeup = true;
        self.sync(id.idx, now);
        Ok(())
    }

    /// Lets the SYN-ACK of a deferred flow go, after the upstream dial succeeded.
    pub fn tcp_complete(&mut self, id: FlowId) -> Result<(), StreamError> {
        let Some(Flow::Tcp(t)) = self.table.get_mut(id) else {
            return Err(StreamError::Stale);
        };
        if let Some(error) = t.error {
            return Err(error);
        }
        if t.gate != Gate::Held {
            return Err(StreamError::Closed);
        }
        t.open_gate();
        self.tx_wakeup = true;
        self.sync(id.idx, self.now);
        Ok(())
    }

    /// Declines a flow that is still waiting for its SYN-ACK and forgets it; the handle is
    /// released. Ignored for stale handles and flows that were already answered (use
    /// [`Stack::tcp_abort`] for those).
    pub fn tcp_refuse(&mut self, id: FlowId, how: Refuse) {
        let Some(Flow::Tcp(t)) = self.table.get_mut(id) else {
            return;
        };
        if t.gate == Gate::Open {
            return;
        }
        let (tuple, seq) = (t.tuple, t.irs);
        t.abort();
        let ack = seq.wrapping_add(1);
        match how {
            Refuse::Drop => {}
            Refuse::Rst => self.control(tuple, 0, ack, wire::tcp::RST | wire::tcp::ACK),
            Refuse::IcmpUnreachable | Refuse::IcmpAdminProhibited => {
                self.refusal(tuple, seq, how);
            }
        }
        self.tx_wakeup = true;
        self.sync(id.idx, self.now);
    }

    /// A SYN for a tuple without a flow. Returns `None` when the packet is not a plain SYN that
    /// transparent mode would open a flow for, so the caller answers it like any stray segment.
    pub(crate) fn passive_open(
        &mut self,
        now: Instant,
        tuple: FourTuple,
        h: &wire::tcp::Header,
        reopen: Option<(u32, u32)>,
    ) -> Option<Rx> {
        if h.flags & (wire::tcp::SYN | wire::tcp::ACK | wire::tcp::RST | wire::tcp::FIN)
            != wire::tcp::SYN
            || !crate::mode::is_unicast(tuple.remote.ip())
            || tuple.remote.ip() == tuple.local.ip()
            || tuple.remote.port() == 0
            || tuple.local.port() == 0
        {
            return None;
        }
        let source = tuple.remote.ip();
        if self.half_open >= self.cfg.half_open_max
            || self
                .half_open_by_source
                .get(&source)
                .is_some_and(|&n| n >= self.cfg.half_open_per_source)
        {
            return Some(self.drop_packet(DropReason::HalfOpen));
        }
        if self.table.active >= self.cfg.max_flows
            || self.table.tcp_active >= self.floor_cap
            || !self.pool.admit_floor()
        {
            return Some(self.drop_packet(DropReason::Capacity));
        }
        let mut iss = flow::isn(
            &self.cfg.secret,
            tuple,
            now.saturating_duration_since(self.epoch),
        );
        if let Some((index, snd_nxt)) = reopen {
            // The old incarnation's tombstone gives way; the new ISS must lie beyond it.
            self.table.remove(index);
            self.purge_stale();
            if !crate::tcp::seq::gt(iss, snd_nxt) {
                iss = snd_nxt.wrapping_add(65_537);
            }
        }
        let offset = flow::ts_offset(&self.cfg.secret, tuple.local.ip(), source);
        let t = Tcb::new_passive(tuple, &self.cfg, now, self.epoch, iss, offset, h);
        let id = self.table.insert(Flow::Tcp(Box::new(t)));
        self.half_open += 1;
        *self.half_open_by_source.entry(source).or_default() += 1;
        self.accept_q.push_back(id);
        self.sync(id.idx, now);
        Some(Rx::Consumed)
    }

    /// Writes the ICMP error for a refused SYN. `Output::None` means it was suppressed or rate
    /// limited and has been dropped from the queue.
    pub(crate) fn emit_refusal(
        &mut self,
        now: Instant,
        c: &Control,
        how: Refuse,
        out: &mut [u8],
    ) -> Output {
        let mut quote = [0u8; 64];
        let kind = match how {
            Refuse::IcmpAdminProhibited => Reject::AdminProhibited,
            _ => Reject::HostUnreachable,
        };
        let result = match quote_syn(c.tuple, c.seq, &mut quote) {
            Some(n) => self.icmp_out.emit(now, kind, &quote[..n], out),
            None => IcmpEmit::Suppressed,
        };
        if result == IcmpEmit::TooSmall {
            return Output::Blocked;
        }
        self.controls.pop_front();
        match result {
            IcmpEmit::Sent(n) => Output::Sent(n),
            _ => Output::None,
        }
    }

    /// Called when a flow stops being half-open (handshake done, or the flow died).
    pub(crate) fn leave_half_open(&mut self, source: IpAddr) {
        self.half_open -= 1;
        if let Some(n) = self.half_open_by_source.get_mut(&source) {
            *n -= 1;
            if *n == 0 {
                self.half_open_by_source.remove(&source);
            }
        }
    }

    /// Queues the ICMP error for a refused SYN.
    fn refusal(&mut self, tuple: FourTuple, seq: u32, how: Refuse) {
        self.queue_control(Control {
            tuple,
            seq,
            ack: 0,
            flags: 0,
            icmp: Some(how),
        });
    }
}

/// The SYN a refused flow answers, rebuilt as the packet an ICMP error quotes.
pub(crate) fn quote_syn(tuple: FourTuple, seq: u32, out: &mut [u8]) -> Option<usize> {
    let h = wire::tcp::Header {
        src_port: tuple.remote.port(),
        dst_port: tuple.local.port(),
        seq,
        ack: 0,
        flags: wire::tcp::SYN,
        window: 0,
        urgent: 0,
        options: wire::tcp::Options::default(),
    };
    wire::tcp::emit_packet(out, tuple.remote.ip(), tuple.local.ip(), &h, [&[], &[]])
}
