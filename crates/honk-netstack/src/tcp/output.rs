use std::time::Instant;

use crate::offload::{GsoKind, GsoTx, Transmit, TxCsum};
use crate::wire::{
    self,
    tcp::{self as wire_tcp, ACK, FIN, Header, Options, PSH, RST, SYN},
};

use super::pacing::Pacer;
use super::sent::{APP_LIMITED, Descriptor, FIN as SENT_FIN, Stamp};
use super::{Tcb, TcpState};

pub enum Output {
    Sent(usize),
    Blocked,
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

impl Tcb {
    #[cfg(test)]
    pub fn output(&mut self, now: Instant, out: &mut [u8], pool: &mut super::ring::Pool) -> Output {
        self.output_with(now, out, pool, 0, &mut Transmit::plain(0))
    }

    /// [`Tcb::output`] that may build one TSO packet: up to `tso` payload bytes (`0`: never) as
    /// several MSS-sized segments behind one header, with `tx` describing it. The packet keeps one
    /// send descriptor per segment, so SACK, RACK and retransmission see ordinary segments.
    pub fn output_with(
        &mut self,
        now: Instant,
        out: &mut [u8],
        pool: &mut super::ring::Pool,
        tso: usize,
        tx: &mut Transmit,
    ) -> Output {
        let syn = matches!(self.state, TcpState::SynSent | TcpState::SynReceived);
        let mut options = self.options(now, syn);
        let mut kind = if self.rst_pending {
            Some(Kind::Reset)
        } else if syn && self.syn_due {
            Some(Kind::Syn)
        } else {
            None
        };
        let mut probe = false;
        let mut pipe = 0;
        let mut unsent_left = 0;
        if kind.is_none() && !syn && self.state != TcpState::Closed {
            let cap = self.payload_cap(&options);
            let mss = self.send_mss();
            pipe = self.recovery.pipe(&self.sent, self.sack);
            let budget = self.recovery.budget(pipe, self.cc.cwnd()) as usize;
            let can_send_new = self.may_send_new();
            let sent_offset = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
            let unsent = self.tx.len().saturating_sub(sent_offset);
            let rwnd = self
                .snd_wnd
                .saturating_sub(self.snd_nxt.wrapping_sub(self.snd_una))
                as usize;
            // Segments one TSO packet may hold at most: the 64 KiB IP limit and the caller's buffer.
            let tso_max = if tso == 0 || cap == 0 {
                1
            } else {
                let headers = wire::ip_header_len(self.tuple.local.is_ipv6())
                    + wire_tcp::header_len(&options, false);
                (tso.min(usize::from(u16::MAX).saturating_sub(headers))
                    .min(out.len().saturating_sub(headers))
                    / cap)
                    .max(1)
            };
            if self.tlp_due {
                self.tlp_due = false;
                kind = self.tlp_kind(pool, cap, unsent, rwnd, can_send_new);
                probe = kind.is_some();
            }
            if kind.is_none()
                && !self.recovery.hold_retransmits()
                && let Some((i, start, len, fin)) = self.sent.next_retransmit()
            {
                let data = (len as usize - usize::from(fin)).min(cap);
                let fin = fin && data as u32 + 1 == len;
                if budget > 0
                    && (data != 0 || fin)
                    && (data as u32 + u32::from(fin) == len || self.sent.ensure_room(pool, 1))
                    && self.pace_ok(now, data as u32, mss, tso_max)
                {
                    let (mut data, mut segs) = (data, 1);
                    // A run of lost whole segments goes out as one TSO packet.
                    if tso_max >= 2 && !fin && data == cap && data as u32 == len {
                        let n = self.tso_segs(cap, tso_max, budget);
                        if n > 1 {
                            let (count, end) = self.sent.lost_run(i, cap as u32, n);
                            segs = count;
                            data = end.wrapping_sub(start) as usize;
                        }
                    }
                    kind = Some(Kind::Retransmit {
                        index: i,
                        start,
                        data,
                        fin,
                        segs,
                    });
                }
            }
            if kind.is_none() && can_send_new {
                let data = unsent.min(cap).min(rwnd);
                let fin = self.fin_requested
                    && self.fin_seq.is_none()
                    && data == unsent
                    && rwnd > data
                    && budget > 0;
                if unsent == 0 {
                    self.cwnd_limited = false;
                } else if data != 0 && budget == 0 {
                    self.cwnd_limited = true;
                }
                if budget > 0
                    && (data != 0 || fin)
                    && self.sent.ensure_room(pool, 2)
                    && self.pace_ok(now, data as u32, mss, tso_max)
                {
                    let (mut data, mut fin, mut segs) = (data, fin, 1);
                    if tso_max >= 2 && data == cap && unsent > data && rwnd > data {
                        let n = self
                            .tso_segs(cap, tso_max, budget)
                            .min(unsent.min(rwnd).div_ceil(cap));
                        if n > 1 && self.sent.ensure_room(pool, n + 1) {
                            data = unsent.min(rwnd).min(n * cap);
                            segs = data.div_ceil(cap);
                            fin = self.fin_requested
                                && self.fin_seq.is_none()
                                && data == unsent
                                && rwnd > data;
                        }
                    }
                    unsent_left = unsent - data;
                    kind = Some(Kind::New { data, fin, segs });
                }
            }
            if kind.is_none() && self.ack_due != 0 {
                kind = Some(Kind::Ack);
            }
            if kind.is_none() && self.probe_due {
                kind = Some(Kind::Probe);
            }
        }
        let Some(kind) = kind else {
            self.rearm(now);
            return Output::None;
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
        let need = wire::ip_header_len(self.tuple.local.is_ipv6())
            + wire_tcp::header_len(&hdr.options, flags & SYN != 0)
            + data_len;
        if out.len() < need {
            return Output::Blocked;
        }
        let segs = match kind {
            Kind::New { segs, .. } | Kind::Retransmit { segs, .. } => segs,
            _ => 1,
        };
        // Every segment but the last is a full payload; they share one header.
        let seg_size = if segs > 1 {
            self.payload_cap(&hdr.options)
        } else {
            data_len
        };
        let (payload, parts) = self.tx.slices(off, data_len);
        let ips = (self.tuple.local.ip(), self.tuple.remote.ip());
        let Some(n) = (if segs > 1 {
            wire_tcp::emit_partial_parts(out, ips.0, ips.1, &hdr, &payload[..parts])
        } else {
            wire_tcp::emit_packet_parts(out, ips.0, ips.1, &hdr, &payload[..parts])
        }) else {
            return Output::Blocked;
        };
        if segs > 1 {
            *tx = Transmit {
                len: n,
                gso: Some(GsoTx {
                    kind: GsoKind::Tcp,
                    size: seg_size as u16,
                    hdr_len: (n - data_len) as u16,
                }),
                csum: TxCsum::Partial {
                    start: wire::ip_header_len(self.tuple.local.is_ipv6()) as u16,
                    offset: 16,
                },
            };
        }
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
                self.rto_deadline = Some(now + self.rtt.rto());
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
        Output::Sent(n)
    }

    /// The segment a tail loss probe sends: new data if there is any and the peer allows it,
    /// otherwise the newest unacknowledged one (RFC 8985 §7.3).
    fn tlp_kind(
        &mut self,
        pool: &mut super::ring::Pool,
        cap: usize,
        unsent: usize,
        rwnd: usize,
        can_send_new: bool,
    ) -> Option<Kind> {
        // `cap` can be zero (tiny path MTU under large options): an empty segment is no probe.
        let new = unsent.min(cap).min(rwnd);
        if can_send_new && new != 0 && self.sent.ensure_room(pool, 2) {
            return Some(Kind::New {
                data: new,
                fin: false,
                segs: 1,
            });
        }
        let (index, start, len, fin) = self.sent.last_unsacked()?;
        let data = (len as usize - usize::from(fin)).min(cap);
        let fin = fin && data as u32 + 1 == len;
        ((data != 0 || fin)
            && (data as u32 + u32::from(fin) == len || self.sent.ensure_room(pool, 1)))
        .then_some(Kind::Retransmit {
            index,
            start,
            data,
            fin,
            segs: 1,
        })
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

    /// Pacing gate; records when the next segment may leave if it may not leave now. With TSO
    /// (`tso_max` segments per packet) the bucket holds up to one full TSO packet, still bounded
    /// by two milliseconds of traffic.
    fn pace_ok(&mut self, now: Instant, bytes: u32, mss: u32, tso_max: usize) -> bool {
        let Some(rate) = Pacer::rate(self.cc.cwnd(), self.rtt.srtt(), self.cc.pacing_gain()) else {
            self.pacing_deadline = None;
            return true;
        };
        let burst = (tso_max as u64).max(super::pacing::BURST_SEGMENTS);
        match self.pacer.check(now, bytes.min(mss), rate, mss, burst) {
            None => {
                self.pacing_deadline = None;
                true
            }
            Some(at) => {
                self.pacing_deadline = Some(at);
                false
            }
        }
    }

    /// How many `cap`-byte segments one TSO packet may carry now, at most `max` (always at least
    /// one): bounded by the congestion `budget` (a started segment counts, as for single
    /// segments), by the pacer's tokens (called right after `pace_ok` admitted the first segment),
    /// and by roughly one millisecond of traffic at the pacing rate, as Linux's TSO autosizing.
    fn tso_segs(&self, cap: usize, max: usize, budget: usize) -> usize {
        let mut n = max.min(budget.div_ceil(cap));
        if let Some(rate) = Pacer::rate(self.cc.cwnd(), self.rtt.srtt(), self.cc.pacing_gain()) {
            let by_tokens = usize::try_from(self.pacer.tokens() / cap as u64).unwrap_or(usize::MAX);
            let by_size = usize::try_from(rate / 1000 / cap as u64).unwrap_or(usize::MAX);
            n = n.min(by_tokens).min(by_size.max(2));
        }
        n.max(1)
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
