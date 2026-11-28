use std::convert::Infallible;
use std::time::Instant;

use crate::IovTransmit;
use crate::flow::FourTuple;
use crate::offload::{GsoKind, GsoTx, Transmit, TxCaps, TxCsum};
use crate::wire::{
    self,
    tcp::{self as wire_tcp, ACK, FIN, Header, Options, PSH, RST, SYN},
};

use super::pacing::Pacer;
use super::ring::Pool;
use super::sent::{APP_LIMITED, Descriptor, FIN as SENT_FIN, Stamp};
use super::{Room, Tcb, TcpState};

pub enum Output {
    Sent(usize),
    /// The caller's output buffer is too short.
    Blocked,
    /// This flow needs capacity; other output may still progress.
    Deferred,
    None,
}

#[derive(Clone, Copy)]
enum Kind {
    Reset,
    Syn,
    Ack,
    Probe,
    New {
        data: usize,
        fin: bool,
        /// MSS-sized segments `data` is cut into: more than one is a TSO packet.
        segs: usize,
    },
    Retransmit {
        index: usize,
        start: u32,
        data: usize,
        fin: bool,
        /// Consecutive whole lost descriptors from `index` this packet resends.
        segs: usize,
    },
}

struct Request {
    now: Instant,
    max_len: usize,
    caps: TxCaps,
    payload_allowed: bool,
}

struct Selection {
    pacer: Option<Pacer>,
    pacing_deadline: Option<Instant>,
    retrans_cursor: u32,
    cwnd_limited: bool,
    tlp_due: bool,
    refused: bool,
    probe: bool,
    pipe: u32,
    unsent_left: usize,
}

impl Selection {
    fn new(t: &Tcb) -> Self {
        Self {
            pacer: None,
            pacing_deadline: t.pacing_deadline,
            retrans_cursor: t.sent.retrans_cursor,
            cwnd_limited: t.cwnd_limited,
            tlp_due: t.tlp_due,
            refused: false,
            probe: false,
            pipe: 0,
            unsent_left: 0,
        }
    }

    fn apply(&self, t: &mut Tcb) {
        if let Some(pacer) = self.pacer {
            t.pacer = pacer;
        }
        t.pacing_deadline = self.pacing_deadline;
        t.sent.retrans_cursor = self.retrans_cursor;
        t.cwnd_limited = self.cwnd_limited;
        t.tlp_due = self.tlp_due;
    }

    fn room<const IOV: bool>(&mut self, room: Room) -> Result<bool, ()> {
        match room {
            Room::Grew if IOV => Err(()),
            Room::Ready | Room::Grew => Ok(true),
            Room::Refused => {
                self.refused = true;
                Ok(false)
            }
        }
    }

    /// `tso_max` can raise the burst to one full TSO packet, within the two millisecond cap.
    fn pace_ok(
        &mut self,
        t: &Tcb,
        now: Instant,
        bytes: u32,
        mss: u32,
        tso_max: usize,
        rate: Option<u64>,
    ) -> bool {
        self.pacing_deadline = rate.and_then(|rate| {
            let burst = (tso_max as u64).max(super::pacing::BURST_SEGMENTS);
            self.pacer
                .get_or_insert(t.pacer)
                .check(now, bytes.min(mss), rate, mss, burst)
        });
        self.pacing_deadline.is_none()
    }

    /// Start a segment against the congestion budget as for plain TCP. Pacing also bounds the
    /// run by the tokens from `pace_ok` and roughly one millisecond of traffic at that rate.
    fn tso_segs(&self, cap: usize, max: usize, budget: usize, rate: Option<u64>) -> usize {
        let mut n = max.min(budget.div_ceil(cap));
        if let Some(rate) = rate {
            let tokens = self.pacer.as_ref().expect("TSO has passed pacing").tokens();
            let by_tokens = usize::try_from(tokens / cap as u64).unwrap_or(usize::MAX);
            let by_size = usize::try_from(rate / 1000 / cap as u64).unwrap_or(usize::MAX);
            n = n.min(by_tokens).min(by_size.max(2));
        }
        n.max(1)
    }
}

impl Tcb {
    #[cfg(test)]
    pub fn output(&mut self, now: Instant, out: &mut [u8], pool: &mut Pool) -> Output {
        self.output_with(now, out, pool, TxCaps::NONE, &mut Transmit::plain(0), true)
    }

    /// A TSO packet still owns one send descriptor per wire segment.
    pub fn output_with(
        &mut self,
        now: Instant,
        out: &mut [u8],
        pool: &mut Pool,
        caps: TxCaps,
        tx: &mut Transmit,
        payload_allowed: bool,
    ) -> Output {
        let request = Request {
            now,
            max_len: out.len(),
            caps,
            payload_allowed,
        };
        match self.output_to::<false, Infallible>(
            request,
            pool,
            *tx,
            |tuple, hdr, parts, info, _| {
                let src = tuple.local.ip();
                let dst = tuple.remote.ip();
                let n = if info.csum == TxCsum::Full {
                    wire_tcp::emit_packet_parts(out, src, dst, hdr, parts)
                } else {
                    wire_tcp::emit_partial_parts(out, src, dst, hdr, parts)
                };
                Ok(n.is_some())
            },
        ) {
            Ok(IovTransmit::Packet(info)) => {
                *tx = info;
                Output::Sent(info.len)
            }
            Ok(IovTransmit::BufferTooSmall) => Output::Blocked,
            Ok(IovTransmit::Deferred) => Output::Deferred,
            Ok(IovTransmit::Idle) => Output::None,
            Ok(IovTransmit::Progress | IovTransmit::NeedsIcmp) => unreachable!(),
            Err(never) => match never {},
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn output_iov<E>(
        &mut self,
        now: Instant,
        max_len: usize,
        pool: &mut Pool,
        caps: TxCaps,
        payload_allowed: bool,
        identity: Transmit,
        emit: &mut impl FnMut(&[u8], &[&[u8]], Transmit) -> Result<(), E>,
    ) -> Result<IovTransmit, E> {
        let request = Request {
            now,
            max_len,
            caps,
            payload_allowed,
        };
        self.output_to::<true, E>(
            request,
            pool,
            identity,
            |tuple, hdr, parts, info, data_len| {
                let mut header = [0; 128];
                let Some(len) = wire_tcp::emit_header_only(
                    &mut header,
                    tuple.local.ip(),
                    tuple.remote.ip(),
                    hdr,
                    data_len,
                    parts,
                    info.csum != TxCsum::Full,
                ) else {
                    return Ok(false);
                };
                emit(&header[..len], parts, info)?;
                Ok(true)
            },
        )
    }

    fn output_to<const IOV: bool, E>(
        &mut self,
        request: Request,
        pool: &mut Pool,
        mut tx: Transmit,
        send: impl FnOnce(&FourTuple, &Header, &[&[u8]], Transmit, usize) -> Result<bool, E>,
    ) -> Result<IovTransmit, E> {
        let now = request.now;
        let syn = matches!(self.state, TcpState::SynSent | TcpState::SynReceived);
        let mut options = self.options(now, syn);
        let mut selection = Selection::new(self);
        let kind = if self.rst_pending {
            Some(Kind::Reset)
        } else if syn && self.syn_due {
            Some(Kind::Syn)
        } else if !syn && self.state != TcpState::Closed {
            let Ok(kind) = self.select::<IOV>(&request, pool, &options, &mut selection) else {
                return Ok(IovTransmit::Progress);
            };
            kind
        } else {
            None
        };
        if !IOV {
            // Contiguous pulls have always published selection state even on a short buffer.
            selection.apply(self);
        }
        let Some(kind) = kind else {
            if IOV {
                return Ok(self.finish_idle(now, selection));
            }
            self.rearm(now);
            return Ok(IovTransmit::Idle);
        };
        if matches!(kind, Kind::Reset) {
            options = Options::default();
        }
        let (seq_no, mut flags, off, data_len, fin) = match kind {
            Kind::Reset => (self.snd_nxt, RST | ACK, 0, 0, false),
            Kind::Syn => (
                self.iss,
                SYN | if self.state == TcpState::SynReceived {
                    ACK
                } else {
                    0
                },
                0,
                0,
                false,
            ),
            Kind::Ack => (self.snd_nxt, ACK, 0, 0, false),
            Kind::Probe => (self.snd_una.wrapping_sub(1), ACK, 0, 0, false),
            Kind::New { data, fin, .. } => (
                self.snd_nxt,
                ACK,
                self.snd_nxt.wrapping_sub(self.snd_una) as usize,
                data,
                fin,
            ),
            Kind::Retransmit {
                start, data, fin, ..
            } => (
                start,
                ACK,
                start.wrapping_sub(self.snd_una) as usize,
                data,
                fin,
            ),
        };
        if fin {
            flags |= FIN;
        }
        if data_len != 0 && off + data_len == self.tx.len() {
            flags |= PSH;
        }
        let hdr = Header {
            src_port: self.tuple.local.port(),
            dst_port: self.tuple.remote.port(),
            seq: seq_no,
            ack: if flags & ACK != 0 { self.rcv_nxt } else { 0 },
            flags,
            window: self.wire_window(flags & SYN != 0),
            urgent: 0,
            options,
        };
        let v6 = self.tuple.local.is_ipv6();
        let ip_len = wire::ip_header_len(v6);
        let header_len = ip_len + wire_tcp::header_len(&hdr.options, flags & SYN != 0);
        let need = header_len + data_len;
        if request.max_len < need {
            return Ok(IovTransmit::BufferTooSmall);
        }
        let segs = match kind {
            Kind::New { segs, .. } | Kind::Retransmit { segs, .. } => segs,
            _ => 1,
        };
        if self.sack && matches!(kind, Kind::Retransmit { .. }) {
            match self.recovery.rack.ensure_room::<IOV>(pool, segs) {
                Room::Grew if IOV => return Ok(IovTransmit::Progress),
                Room::Refused => return Ok(IovTransmit::Deferred),
                Room::Ready | Room::Grew => {}
            }
        }
        // Every segment but the last is a full payload; they share one header.
        let seg_size = if segs > 1 {
            self.payload_cap(&hdr.options)
        } else {
            data_len
        };
        tx.len = need;
        tx.gso = (segs > 1).then_some(GsoTx {
            kind: GsoKind::Tcp,
            size: seg_size as u16,
            hdr_len: header_len as u16,
        });
        tx.csum = if segs > 1 || request.caps.csum(v6) {
            TxCsum::Partial {
                start: ip_len as u16,
                offset: 16,
            }
        } else {
            TxCsum::Full
        };
        let mut short;
        let mut large;
        let parts: &mut [&[u8]] = if data_len <= pool.chunk() {
            short = [&[][..]; 2];
            &mut short
        } else {
            large = [&[][..]; super::ring::MAX_PARTS];
            &mut large
        };
        let payload = self.tx.slices_into(off, data_len, parts);
        if !send(&self.tuple, &hdr, payload, tx, data_len)? {
            return Ok(IovTransmit::BufferTooSmall);
        }
        if IOV {
            selection.apply(self);
        }
        let Selection {
            probe,
            pipe,
            unsent_left,
            ..
        } = selection;
        if flags & (ACK | SYN) != 0 && flags & RST == 0 {
            let right = self.wire_right(flags & SYN != 0);
            self.max_adv_right = super::seq::max(self.max_adv_right, right);
            self.last_adv_right = right;
        }
        match kind {
            Kind::Reset => self.rst_pending = false,
            Kind::Syn => {
                self.syn_due = false;
                self.syn_sent.get_or_insert(now);
                self.snd_nxt = self.iss.wrapping_add(1);
                if self.rto_deadline.is_none() {
                    self.rto_deadline = Some(now + self.rtt.rto());
                }
            }
            Kind::Ack => {}
            Kind::Probe => self.probe_due = false,
            Kind::New { data, fin, .. } => {
                let first = self.snd_nxt;
                if self.sent.outstanding == 0 {
                    if now.saturating_duration_since(self.last_data_tx) >= self.rtt.rto() {
                        self.cc.restart_idle(self.send_mss());
                    }
                    // Nothing in flight: a new delivery-rate interval starts here, and a probe
                    // from an earlier burst can no longer be judged by this one's ACKs.
                    self.first_tx_ts = now;
                    self.delivered_ts = now;
                    self.recovery.rack.tlp = None;
                }
                if fin {
                    self.fin_seq = Some(self.snd_nxt.wrapping_add(data as u32));
                }
                self.snd_nxt = self.snd_nxt.wrapping_add(data as u32 + u32::from(fin));
                // Less than a segment left to send and room in the window: the sender, not the
                // path, limits this sample (draft-cheng-iccrg-delivery-rate-estimation §3.4).
                let mss = self.send_mss();
                let flight = self.recovery.pipe(&self.sent, self.sack) + data as u32;
                if !probe
                    && !fin
                    && unsent_left < mss as usize
                    && flight + mss <= self.cc.cwnd()
                    && self.sent.lost == 0
                {
                    self.app_limited_until = (self.delivered + u64::from(flight)).max(1);
                }
                for k in 1..=segs {
                    // The last segment ends at the FIN too, which takes one sequence number.
                    let end = if k == segs {
                        first.wrapping_add(data as u32 + u32::from(fin))
                    } else {
                        first.wrapping_add((k * seg_size) as u32)
                    };
                    self.sent.push(Descriptor {
                        end_seq: end,
                        xmit_ts: now,
                        flags: if fin && k == segs { SENT_FIN } else { 0 }
                            | if self.app_limited_until != 0 {
                                APP_LIMITED
                            } else {
                                0
                            },
                        delivered: self.delivered,
                        delivered_ts: self.delivered_ts,
                        first_tx_ts: self.first_tx_ts,
                    });
                }
                self.pacer.sent(data as u32);
                let ts = self.timestamp(now);
                self.recovery.sent_bytes(data as u32, false, ts);
                if !probe {
                    let pipe = self.recovery.pipe(&self.sent, self.sack);
                    if pipe + self.send_mss() > self.cc.cwnd() {
                        self.cwnd_limited = true;
                    }
                    self.rearm_pto(now);
                } else {
                    self.recovery.rack.start_tlp(self.snd_nxt, false);
                }
                self.last_data_tx = now;
            }
            Kind::Retransmit {
                index,
                start,
                data,
                fin,
                ..
            } => {
                if pipe == 0 {
                    self.first_tx_ts = now;
                    self.delivered_ts = now;
                }
                let end = start.wrapping_add(data as u32 + u32::from(fin));
                if segs == 1 {
                    self.sent.split(index, end);
                }
                let stamp = Stamp {
                    delivered: self.delivered,
                    delivered_ts: self.delivered_ts,
                    first_tx_ts: self.first_tx_ts,
                    app_limited: self.app_limited_until != 0,
                };
                for i in index..index + segs {
                    self.sent.retransmitted(i, now, &stamp);
                    if self.sack {
                        self.recovery
                            .rack
                            .on_retransmit(self.sent.queue[i].end_seq, now);
                    }
                }
                self.pacer.sent(data as u32);
                let ts = self.timestamp(now);
                self.recovery
                    .sent_bytes(data as u32 + u32::from(fin), true, ts);
                self.stats.retrans_bytes += data as u64;
                self.stats.retrans_segments += segs as u32;
                if probe {
                    self.recovery.rack.start_tlp(self.snd_nxt, true);
                } else {
                    self.rearm_pto(now);
                }
                self.last_data_tx = now;
            }
        }
        if probe {
            self.tlp_due = false;
            self.recovery.counters.tlp_probes += 1;
            self.rto_deadline = Some(now + self.rtt.rto());
        }
        if flags & ACK != 0 && !matches!(kind, Kind::Probe | Kind::Reset) {
            self.ack_due = 0;
            self.delack_deadline = None;
            self.ooo.reported(&hdr.options.sack);
            self.last_ack_sent = self.rcv_nxt;
            self.full_segments = 0;
            self.dsack = None;
            if self.ooo_acks != 0 {
                self.ooo_acks -= 1;
                if self.ooo_acks != 0 {
                    self.ack_due |= super::OOO;
                }
            }
        }
        self.rearm(now);
        Ok(IovTransmit::Packet(tx))
    }

    fn select<const IOV: bool>(
        &mut self,
        request: &Request,
        pool: &mut Pool,
        options: &Options,
        sel: &mut Selection,
    ) -> Result<Option<Kind>, ()> {
        let now = request.now;
        let payload_allowed = request.payload_allowed;
        let cap = self.payload_cap(options);
        let mss = self.send_mss();
        sel.pipe = self.recovery.pipe(&self.sent, self.sack);
        let budget = self.recovery.budget(sel.pipe, self.cc.cwnd()) as usize;
        let can_send_new = self.may_send_new();
        let flight = self.snd_nxt.wrapping_sub(self.snd_una);
        let unsent = self.tx.len().saturating_sub(flight as usize);
        let rwnd = self.snd_wnd.saturating_sub(flight) as usize;
        let v6 = self.tuple.local.is_ipv6();
        let tso_max = if !request.caps.tso(v6) || cap == 0 {
            1
        } else {
            let headers = wire::ip_header_len(v6) + wire_tcp::header_len(options, false);
            (request
                .max_len
                .min(usize::from(u16::MAX))
                .saturating_sub(headers)
                / cap)
                .max(1)
        };

        if self.tlp_due {
            let new = if can_send_new && payload_allowed {
                unsent.min(cap).min(rwnd)
            } else {
                0
            };
            let kind = self.tlp_kind::<IOV>(pool, cap, new, payload_allowed, sel)?;
            if kind.is_some() {
                sel.probe = true;
                return Ok(kind);
            }
            if payload_allowed && (!IOV || !sel.refused) {
                sel.tlp_due = false;
            }
        }
        if !self.recovery.hold_retransmits()
            && let Some((i, start, len, fin)) = self
                .sent
                .scan_retransmit(payload_allowed, &mut sel.retrans_cursor)
        {
            let data = (len as usize - usize::from(fin)).min(cap);
            let fin = fin && data as u32 + 1 == len;
            if budget > 0
                && (data != 0 || fin)
                && (data as u32 + u32::from(fin) == len
                    || sel.room::<IOV>(self.sent.ensure_room(pool, 1))?)
            {
                let rate = Pacer::rate(self.cc.cwnd(), self.rtt.srtt(), self.cc.pacing_gain());
                if sel.pace_ok(self, now, data as u32, mss, tso_max, rate) {
                    let (mut data, mut segs) = (data, 1);
                    // A run of lost whole segments goes out as one TSO packet.
                    if tso_max >= 2 && !fin && data == cap && data as u32 == len {
                        let n = sel.tso_segs(cap, tso_max, budget, rate);
                        if n > 1 {
                            let (count, end) = self.sent.lost_run(i, cap as u32, n);
                            segs = count;
                            data = end.wrapping_sub(start) as usize;
                        }
                    }
                    return Ok(Some(Kind::Retransmit {
                        index: i,
                        start,
                        data,
                        fin,
                        segs,
                    }));
                }
            }
        }
        if can_send_new && (payload_allowed || unsent == 0) {
            let data = unsent.min(cap).min(rwnd);
            let fin = self.fin_requested
                && self.fin_seq.is_none()
                && data == unsent
                && rwnd > data
                && budget > 0;
            if unsent == 0 {
                sel.cwnd_limited = false;
            } else if data != 0 && budget == 0 {
                sel.cwnd_limited = true;
            }
            if budget > 0
                && (data != 0 || fin)
                && sel.room::<IOV>(self.sent.ensure_room(pool, 2))?
            {
                let rate = Pacer::rate(self.cc.cwnd(), self.rtt.srtt(), self.cc.pacing_gain());
                if sel.pace_ok(self, now, data as u32, mss, tso_max, rate) {
                    let (mut data, mut fin, mut segs) = (data, fin, 1);
                    if tso_max >= 2 && data == cap && unsent > data && rwnd > data {
                        let n = sel
                            .tso_segs(cap, tso_max, budget, rate)
                            .min(unsent.min(rwnd).div_ceil(cap));
                        if n > 1 && sel.room::<IOV>(self.sent.ensure_room(pool, n + 1))? {
                            data = unsent.min(rwnd).min(n * cap);
                            segs = data.div_ceil(cap);
                            fin = self.fin_requested
                                && self.fin_seq.is_none()
                                && data == unsent
                                && rwnd > data;
                        }
                    }
                    sel.unsent_left = unsent - data;
                    return Ok(Some(Kind::New { data, fin, segs }));
                }
            }
        }
        if self.ack_due != 0 {
            return Ok(Some(Kind::Ack));
        }
        Ok(self.probe_due.then_some(Kind::Probe))
    }

    fn finish_idle(&mut self, now: Instant, mut selection: Selection) -> IovTransmit {
        let before = (self.persist, self.rto_deadline);
        self.rearm(now);
        let timer_changed = before != (self.persist, self.rto_deadline);
        if selection.refused {
            // Keep the cursor for a later retry, while allowing timers for other work to arm.
            selection.retrans_cursor = self.sent.retrans_cursor;
        }
        if self
            .pacing_deadline
            .zip(selection.pacing_deadline)
            .is_some_and(|(armed, proposed)| now < armed && armed <= proposed)
        {
            // Keep the earlier wakeup. Token refills before it alone are not progress.
            selection.pacing_deadline = self.pacing_deadline;
            selection.pacer = None;
        }
        if selection.pacing_deadline != self.pacing_deadline
            || selection.retrans_cursor != self.sent.retrans_cursor
            || selection.cwnd_limited != self.cwnd_limited
            || selection.tlp_due != self.tlp_due
            || selection.pacer.is_some_and(|p| p != self.pacer)
        {
            selection.apply(self);
            return IovTransmit::Progress;
        }
        if timer_changed {
            IovTransmit::Progress
        } else if selection.refused {
            IovTransmit::Deferred
        } else {
            IovTransmit::Idle
        }
    }

    /// The segment a tail loss probe sends: new data if there is any and the peer allows it,
    /// otherwise the newest unacknowledged one (RFC 8985 §7.3).
    fn tlp_kind<const IOV: bool>(
        &mut self,
        pool: &mut Pool,
        cap: usize,
        new: usize,
        payload_allowed: bool,
        sel: &mut Selection,
    ) -> Result<Option<Kind>, ()> {
        // `cap` can be zero (tiny path MTU under large options): an empty segment is no probe.
        if new != 0 && sel.room::<IOV>(self.sent.ensure_room(pool, 2))? {
            return Ok(Some(Kind::New {
                data: new,
                fin: false,
                segs: 1,
            }));
        }
        let Some((index, start, len, fin)) = self.sent.last_unsacked() else {
            return Ok(None);
        };
        let data = (len as usize - usize::from(fin)).min(cap);
        let fin = fin && data as u32 + 1 == len;
        let can_send = (payload_allowed || data == 0)
            && (data != 0 || fin)
            && (data as u32 + u32::from(fin) == len
                || sel.room::<IOV>(self.sent.ensure_room(pool, 1))?);
        Ok(can_send.then_some(Kind::Retransmit {
            index,
            start,
            data,
            fin,
            segs: 1,
        }))
    }

    /// Whether queued data and our FIN may still leave. CLOSING counts: the peer's FIN can arrive
    /// while ours is still queued behind a closed window, and that data is owed.
    pub(super) fn may_send_new(&self) -> bool {
        matches!(
            self.state,
            TcpState::Established
                | TcpState::CloseWait
                | TcpState::FinWait1
                | TcpState::Closing
                | TcpState::LastAck
        )
    }

    /// F-RTO step 2b holds retransmissions only while new data can go out in their place. When the
    /// ACK just processed leaves none (nothing unsent, or no window for it) the sender falls back to
    /// conventional recovery instead of idling until the next timeout (RFC 5682 §3, Linux
    /// `tcp_process_loss`). A full congestion window just waits.
    pub(super) fn frto_gate(&mut self) {
        if !self.recovery.hold_retransmits() {
            return;
        }
        let flight = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
        let can_send_new = self.may_send_new();
        if !(can_send_new && self.tx.len() > flight && self.snd_wnd as usize > flight) {
            self.recovery.end_frto();
        }
    }

    fn options(&self, now: Instant, syn: bool) -> Options {
        let mut o = Options::default();
        if syn {
            o.mss = Some(self.local_mss);
            o.wscale = if self.state == TcpState::SynSent || self.wscale {
                Some(self.rcv_shift)
            } else {
                None
            };
            o.sack_permitted = self.state == TcpState::SynSent || self.sack;
            if self.state == TcpState::SynSent || self.timestamps {
                o.timestamps = Some((self.timestamp(now), self.ts_recent.map_or(0, |t| t.0)));
            }
        } else {
            if self.timestamps {
                o.timestamps = Some((self.timestamp(now), self.ts_recent.map_or(0, |t| t.0)));
            }
            if self.sack {
                let slots = if self.timestamps { 3 } else { 4 };
                if let Some(dsack) = self.dsack {
                    o.sack.push(dsack.0, dsack.1);
                }
                for &(left, right) in self.ooo.blocks(slots - o.sack.len()).as_slice() {
                    o.sack.push(left, right);
                }
            }
        }
        while wire::ip_header_len(self.tuple.local.is_ipv6()) + wire_tcp::header_len(&o, syn)
            > usize::from(self.pmtu)
            && !o.sack.is_empty()
        {
            let old = o.sack;
            o.sack = Default::default();
            for &(left, right) in &old.as_slice()[..old.len() - 1] {
                o.sack.push(left, right);
            }
        }
        o
    }

    fn payload_cap(&self, options: &Options) -> usize {
        let tcp_len = wire_tcp::header_len(options, false);
        let peer_cap = usize::from(self.peer_mss)
            .saturating_sub(tcp_len - 20)
            .max(1);
        let mtu_cap = usize::from(self.pmtu)
            .saturating_sub(wire::ip_header_len(self.tuple.local.is_ipv6()) + tcp_len);
        peer_cap.min(mtu_cap)
    }
}

#[cfg(test)]
mod tests;
