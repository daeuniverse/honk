use std::time::{Duration, Instant};

use crate::wire::tcp::{ACK, FIN, Header, RST, SYN};
use crate::{Ready, StreamError};

use super::cc::CcAck;
use super::passive::Gate;
use super::recovery;
use super::ring::Pool;
use super::sack::Insert;
use super::sent::Acked;
use super::{DATA, DELAY_ACK, FIN_ACK, OOO, PROBE_RESPONSE, Tcb, TcpState, seq};

impl Tcb {
    /// Returns a reset reply for an unacceptable handshake ACK.
    pub fn input(
        &mut self,
        now: Instant,
        h: &Header,
        data: &[u8],
        pool: &mut Pool,
    ) -> Option<(u32, u32, u8)> {
        if self.state == TcpState::Closed {
            return None;
        }
        if self.gate != Gate::Open {
            // Before the application decides nothing is answered: retransmitted SYNs are absorbed.
            return None;
        }
        if self.state == TcpState::SynSent {
            return self.syn_sent_input(now, h, data, pool);
        }
        if self.state == TcpState::SynReceived
            && h.flags & SYN != 0
            && h.flags & RST == 0
            && h.seq == self.irs
        {
            if h.flags & ACK == 0 {
                self.syn_due = true;
                return None;
            }
            if h.ack != self.snd_nxt {
                return Some((h.ack, 0, RST));
            }
            if !self.paws(now, h) {
                return None;
            }
            self.snd_una = h.ack;
            self.syn_due = false;
            self.established(now);
            self.ack_due |= DATA;
            self.snd_wnd = u32::from(h.window);
            self.snd_wnd_max = self.snd_wnd_max.max(self.snd_wnd);
            self.snd_wl1 = h.seq;
            self.snd_wl2 = h.ack;
            if self.timestamps
                && let Some((ts, _)) = h.options.timestamps
            {
                self.ts_recent = Some((ts, now));
            }
            if !data.is_empty() || h.flags & FIN != 0 {
                let mut established = *h;
                established.seq = established.seq.wrapping_add(1);
                established.flags &= !SYN;
                self.receive_data(now, &established, data, pool);
            }
            self.rearm(now);
            return None;
        }
        if self.state == TcpState::TimeWait {
            if valid_timewait_fin(
                h,
                data.len(),
                self.snd_nxt,
                self.rcv_nxt,
                self.snd_wnd_max,
                self.ts_recent.map(|v| v.0),
            ) {
                self.ack_due |= FIN_ACK;
                self.close_deadline = Some(now + super::TIME_WAIT);
                if self.timestamps
                    && let Some((ts, _)) = h.options.timestamps
                {
                    self.ts_recent = Some((ts, now));
                }
            }
            return None;
        }
        if h.flags & SYN != 0 && h.flags & RST == 0 {
            self.challenge(now);
            return None;
        }
        if h.flags & RST == 0 && !self.paws(now, h) {
            return None;
        }
        let seg_len =
            data.len() as u32 + u32::from(h.flags & FIN != 0) + u32::from(h.flags & SYN != 0);
        if !self.acceptable(h.seq, seg_len) {
            if h.flags & RST == 0 {
                if self.sack && !data.is_empty() && seq::lt(h.seq, self.rcv_nxt) {
                    self.dsack = Some((
                        h.seq,
                        seq::min(h.seq.wrapping_add(data.len() as u32), self.rcv_nxt),
                    ));
                }
                self.ack_due |= if self.receive_window() == 0 {
                    PROBE_RESPONSE
                } else {
                    OOO
                };
            }
            return None;
        }
        self.ka_activity(now);
        if h.flags & RST != 0 {
            if h.seq == self.rcv_nxt {
                self.fail(StreamError::Reset);
            } else {
                self.challenge(now);
            }
            return None;
        }
        if h.flags & ACK == 0 {
            return None;
        }
        if self.state == TcpState::SynReceived {
            if h.ack != self.snd_nxt || !seq::gt(h.ack, self.iss) {
                return Some((h.ack, 0, RST));
            }
            self.snd_una = h.ack;
            self.established(now);
        }
        if seq::gt(h.ack, self.snd_nxt)
            || seq::lt(h.ack, self.snd_una.wrapping_sub(self.snd_wnd_max))
        {
            self.challenge(now);
            return None;
        }
        let old_wnd = self.snd_wnd;
        self.update_send_window(h);
        self.persist_probes = 0;
        self.process_ack(
            now,
            h,
            data.is_empty() && h.flags & FIN == 0 && old_wnd == self.snd_wnd,
            pool,
        );
        if self.state == TcpState::Closed {
            return None;
        }
        if self.timestamps
            && let Some((ts, _)) = h.options.timestamps
            && seq::le(h.seq, self.last_ack_sent)
        {
            self.ts_recent = Some((ts, now));
        }
        if !data.is_empty() || h.flags & FIN != 0 {
            if matches!(
                self.state,
                TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
            ) {
                if !self.app_open && !data.is_empty() {
                    self.abort();
                    return None;
                }
                self.receive_data(now, h, data, pool);
            } else {
                self.ack_due |= FIN_ACK;
            }
        }
        self.rearm(now);
        None
    }

    pub fn init_window(&mut self, pool: &mut Pool) {
        self.grow_window(pool);
    }

    fn syn_sent_input(
        &mut self,
        now: Instant,
        h: &Header,
        data: &[u8],
        pool: &mut Pool,
    ) -> Option<(u32, u32, u8)> {
        if h.flags & ACK != 0 && (!seq::gt(h.ack, self.iss) || seq::gt(h.ack, self.snd_nxt)) {
            return if h.flags & RST == 0 {
                Some((h.ack, 0, RST))
            } else {
                None
            };
        }
        if h.flags & RST != 0 {
            if h.flags & ACK != 0 {
                self.fail(StreamError::Reset);
            }
            return None;
        }
        if h.flags & SYN == 0 {
            return None;
        }
        self.irs = h.seq;
        let width = self.committed_right.wrapping_sub(self.rcv_nxt);
        let advertised = self.receive_window();
        self.rcv_nxt = h.seq.wrapping_add(1);
        self.rx.rd_seq = self.rcv_nxt;
        self.committed_right = self.rcv_nxt.wrapping_add(width);
        self.max_adv_right = self.rcv_nxt.wrapping_add(advertised);
        self.last_adv_right = self.max_adv_right;
        self.last_ack_sent = self.rcv_nxt;
        self.peer_mss = h
            .options
            .mss
            .unwrap_or(if self.tuple.local.is_ipv6() {
                1220
            } else {
                536
            })
            // Linux's `tcp_min_snd_mss`: a hostile server must not buy one packet per byte.
            .max(48);
        self.snd_shift = h.options.wscale.unwrap_or(0);
        self.wscale = h.options.wscale.is_some();
        if !self.wscale {
            self.rcv_shift = 0;
        }
        self.sack = h.options.sack_permitted;
        self.timestamps = h.options.timestamps.is_some();
        self.cc = super::cc::Cc::new(self.send_mss());
        self.rcv_mss = self.send_mss().min(536) as usize;
        if let Some((ts, _)) = h.options.timestamps {
            self.ts_recent = Some((ts, now));
        }
        self.snd_wnd = h.window.into();
        self.snd_wnd_max = self.snd_wnd;
        self.snd_wl1 = h.seq;
        self.snd_wl2 = h.ack;
        self.syn_due = false;
        if h.flags & ACK != 0 {
            self.snd_una = h.ack;
            if self.syn_retries == 0
                && let Some(sent) = self.syn_sent
            {
                self.rtt.sample(now.saturating_duration_since(sent));
            }
            self.established(now);
            self.ack_due |= DATA;
            if !data.is_empty() || h.flags & FIN != 0 {
                let mut h = *h;
                h.seq = h.seq.wrapping_add(1);
                h.flags &= !SYN;
                self.receive_data(now, &h, data, pool);
            }
        } else {
            self.state = TcpState::SynReceived;
            self.syn_due = true;
        }
        None
    }

    fn established(&mut self, now: Instant) {
        self.state = TcpState::Established;
        self.ka_activity(now);
        self.arm_keepalive(now);
        // SYN retransmission backoff belongs to the handshake, not to the first data timeout.
        self.rtt.backoff = 0;
        self.rto_deadline = None;
        self.rcv_rtt_seq = self.max_adv_right;
        self.rcv_rtt_time = now;
        self.drs_time = now;
        self.ready |= Ready::CONNECTED | Ready::WRITABLE;
    }

    fn acceptable(&self, seq_no: u32, len: u32) -> bool {
        let wnd = self.receive_window();
        if wnd == 0 {
            return len == 0 && seq_no == self.rcv_nxt;
        }
        if len == 0 {
            return seq::ge(seq_no, self.rcv_nxt) && seq::lt(seq_no, self.max_adv_right);
        }
        // Any overlap with the window, as on Linux: `receive_data` trims both ends, so a
        // retransmission straddling `rcv_nxt` is not lost to a window narrower than the segment.
        seq::gt(seq_no.wrapping_add(len), self.rcv_nxt) && seq::lt(seq_no, self.max_adv_right)
    }

    fn paws(&mut self, now: Instant, h: &Header) -> bool {
        if !self.timestamps {
            return true;
        }
        let Some((ts, _)) = h.options.timestamps else {
            return false;
        };
        if let Some((recent, stamp)) = self.ts_recent
            && now.saturating_duration_since(stamp) < Duration::from_secs(24 * 24 * 60 * 60)
            && seq::lt(ts, recent)
        {
            self.challenge(now);
            return false;
        }
        true
    }

    fn update_send_window(&mut self, h: &Header) {
        if seq::gt(h.seq, self.snd_wl1) || (h.seq == self.snd_wl1 && seq::ge(h.ack, self.snd_wl2)) {
            self.snd_wnd = u32::from(h.window) << self.snd_shift;
            self.snd_wnd_max = self.snd_wnd_max.max(self.snd_wnd);
            self.snd_wl1 = h.seq;
            self.snd_wl2 = h.ack;
            if self.snd_wnd != 0 {
                self.persist_probes = 0;
                self.persist_backoff = 0;
                if self.persist {
                    self.rto_deadline = None;
                    self.persist = false;
                }
            }
        }
    }

    fn process_ack(
        &mut self,
        now: Instant,
        h: &Header,
        duplicate_candidate: bool,
        pool: &mut Pool,
    ) {
        if seq::lt(h.ack, self.snd_una) {
            return;
        }
        let acked = h.ack.wrapping_sub(self.snd_una);
        let flight_before = self.sent.outstanding;
        let was_recovery = self.recovery.in_recovery();
        let mut info = Acked::new(now, self.rtt.min_rtt().unwrap_or_default());
        if acked != 0 {
            let data_acked = (acked as usize).min(self.tx.len());
            self.tx.consume(pool, data_acked);
            self.sent.ack(h.ack, &mut info);
            self.sent.shrink_idle(pool);
            self.snd_una = h.ack;
        }
        let dsack = if self.sack {
            self.apply_sack(h, &mut info)
        } else {
            0
        };
        self.delivered += u64::from(info.delivered);
        if info.delivered != 0 {
            self.sample_rate(now, &info);
            self.delivered_ts = now;
        }
        if acked != 0 {
            if let Some(sample) = info.rtt {
                self.rtt.sample(sample);
            } else if self.timestamps
                && let Some((_, echo)) = h.options.timestamps
            {
                let delta = self.timestamp(now).wrapping_sub(echo);
                if echo != 0 && delta < 120_000 {
                    self.rtt
                        .sample(Duration::from_millis(u64::from(delta.max(1))));
                }
            }
            if self.write_blocked && self.can_write(pool) {
                self.write_blocked = false;
                self.ready |= Ready::WRITABLE;
            }
        }
        let mss = self.send_mss();
        // Eifel (RFC 3522): an ACK echoing a timestamp older than the first retransmission
        // acknowledges the original transmission.
        let eifel = acked != 0
            && self.timestamps
            && h.options.timestamps.is_some_and(|(_, echo)| {
                echo != 0
                    && self
                        .recovery
                        .retrans_stamp()
                        .is_some_and(|st| seq::lt(echo, st))
            });
        let srtt = self.rtt.srtt().unwrap_or_default();
        self.recovery.ack(
            &mut self.sent,
            &mut self.cc,
            &recovery::AckCtx {
                now,
                ack: h.ack,
                acked,
                dup: acked == 0 && duplicate_candidate,
                info: &info,
                dsack,
                eifel,
                snd_nxt: self.snd_nxt,
                mss,
                flight_before,
                sack: self.sack,
                srtt,
                min_rtt: self.rtt.min_rtt().unwrap_or(srtt),
            },
        );
        if acked != 0 || info.delivered != 0 {
            // New data left the network: the timer measures the next one. After a NewReno partial
            // ACK it keeps running (RFC 6582 "impatient"), see `Recovery::keep_rto`.
            if self.sent.outstanding == 0 {
                self.rto_deadline = None;
            } else if !self.recovery.keep_rto() || self.rto_deadline.is_none() {
                self.rto_deadline = Some(now + self.rtt.rto());
            }
            self.rearm_pto(now);
        }
        self.frto_gate();
        let limited =
            self.cwnd_limited || (self.cc.in_slow_start() && 2 * flight_before >= self.cc.cwnd());
        self.cc.on_ack(&CcAck {
            now,
            bytes: acked,
            mss,
            cwnd_limited: limited,
            in_recovery: was_recovery || self.recovery.in_recovery(),
            rtt: info.rtt,
            srtt,
            snd_una: self.snd_una,
            snd_nxt: self.snd_nxt,
        });
        if let Some(fin) = self.fin_seq
            && seq::gt(h.ack, fin)
        {
            match self.state {
                TcpState::FinWait1 => {
                    self.state = TcpState::FinWait2;
                    if !self.app_open {
                        self.close_deadline = Some(now + super::TIME_WAIT);
                    }
                }
                TcpState::Closing => self.enter_timewait(now),
                TcpState::LastAck => {
                    self.state = TcpState::Closed;
                    self.close_deadline = None;
                }
                _ => {}
            }
        }
    }

    /// Applies the SACK blocks in ascending order and returns the length of a DSACK block.
    fn apply_sack(&mut self, h: &Header, info: &mut Acked) -> u32 {
        let blocks = h.options.sack.as_slice();
        let mut dsack = 0;
        let mut ordered = [(0u32, 0u32); 4];
        let mut n = 0;
        for (i, &(left, right)) in blocks.iter().enumerate() {
            // RFC 2883: below the cumulative ACK, or inside the second block.
            let duplicate = i == 0
                && (seq::le(right, h.ack)
                    || blocks
                        .get(1)
                        .is_some_and(|&(l, r)| seq::ge(left, l) && seq::le(right, r)));
            if duplicate {
                // A DSACK describes one duplicated segment; a reversed, oversized or unsent block
                // would otherwise inflate the count to ~2^32 and force an undo.
                if seq::lt(left, right)
                    && seq::le(right, self.snd_nxt)
                    && right.wrapping_sub(left) <= u32::from(u16::MAX)
                {
                    dsack = right.wrapping_sub(left);
                }
            } else if n < ordered.len() {
                ordered[n] = (left, right);
                n += 1;
            }
        }
        ordered[..n].sort_unstable_by_key(|&(left, _)| left.wrapping_sub(h.ack));
        for &(left, right) in &ordered[..n] {
            self.sent.sack(left, right, self.snd_nxt, info);
        }
        dsack
    }

    /// Delivery-rate sample (draft-cheng-iccrg-delivery-rate-estimation §3.3).
    fn sample_rate(&mut self, now: Instant, info: &Acked) {
        let Some(src) = info.sample else { return };
        self.first_tx_ts = src.xmit_ts;
        let interval = now
            .saturating_duration_since(src.delivered_ts)
            .max(src.xmit_ts.saturating_duration_since(src.first_tx_ts));
        // Shorter than the path RTT means ACK compression, not a measurement.
        if !interval.is_zero() && interval >= self.rtt.min_rtt().unwrap_or_default() {
            let rate = self
                .delivered
                .saturating_sub(src.prior_delivered)
                .saturating_mul(1_000_000)
                / (interval.as_micros().min(u128::from(u64::MAX)) as u64).max(1);
            // An app-limited sample can only raise the estimate.
            if !src.app_limited || rate > self.stats.delivery_rate {
                self.stats.delivery_rate = rate;
            }
        }
        if self.app_limited_until != 0 && self.delivered > self.app_limited_until {
            self.app_limited_until = 0;
        }
    }

    fn receive_data(&mut self, now: Instant, h: &Header, data: &[u8], pool: &mut Pool) {
        if now.saturating_duration_since(self.last_rx) > self.rtt.rto() {
            self.quickack = 16;
            self.rcv_mss = self.send_mss().min(536) as usize;
            self.rcv_last_size = 0;
        }
        self.last_rx = now;
        let original_end = h.seq.wrapping_add(data.len() as u32);
        let mut start = h.seq;
        let mut bytes = data;
        if seq::lt(start, self.rcv_nxt) {
            let dup = self.rcv_nxt.wrapping_sub(start) as usize;
            if self.sack {
                self.dsack = Some((start, seq::min(original_end, self.rcv_nxt)));
            }
            let n = dup.min(bytes.len());
            bytes = &bytes[n..];
            start = start.wrapping_add(n as u32);
        }
        if seq::lt(start, self.max_adv_right) {
            bytes = &bytes[..bytes
                .len()
                .min(self.max_adv_right.wrapping_sub(start) as usize)];
        } else {
            bytes = &[];
        }
        if let Some(fin) = self.peer_fin {
            // Nothing follows the peer's FIN; accepting it would carry `rcv_nxt` past the FIN.
            let room = if seq::lt(start, fin) {
                fin.wrapping_sub(start) as usize
            } else {
                0
            };
            bytes = &bytes[..bytes.len().min(room)];
        }
        let had_ooo = !self.ooo.is_empty();
        let mut advanced = false;
        if !bytes.is_empty() {
            let end = start.wrapping_add(bytes.len() as u32);
            if start == self.rcv_nxt {
                self.rx.write_at(pool, start, bytes);
                self.rcv_nxt = self.ooo.advance(end);
                advanced = true;
                self.ready |= Ready::READABLE;
                // Variable SACK option bytes must not stretch ACKs for full frames.
                let options = crate::wire::tcp::header_len(&h.options, false) - 20;
                let size =
                    bytes.len() + options.saturating_sub(if self.timestamps { 12 } else { 0 });
                if size >= self.rcv_mss {
                    self.rcv_mss = size;
                } else if size >= 48 && size == self.rcv_last_size {
                    // Two equal frames detect smaller paths without mistaking tiny app writes for MSS.
                    self.rcv_mss = size;
                    if self.rcv_nxt.wrapping_sub(self.last_ack_sent) as usize >= 2 * size {
                        self.full_segments = self.full_segments.max(1);
                    }
                }
                self.rcv_last_size = size;
                if size >= self.rcv_mss {
                    self.full_segments = self.full_segments.saturating_add(1);
                }
                if self.quickack != 0 {
                    self.quickack -= 1;
                    self.ack_due |= DATA;
                }
                if self.full_segments >= 2 || had_ooo {
                    self.ack_due |= DATA;
                }
                if self.ack_due == 0 {
                    self.delack_deadline.get_or_insert(now + DELAY_ACK);
                }
            } else {
                match self.ooo.insert(start, end) {
                    Insert::Added => self.rx.write_at(pool, start, bytes),
                    Insert::Duplicate => {
                        if self.sack {
                            self.dsack = Some((start, end));
                        }
                    }
                    Insert::Full => self.stats.ooo_drops += 1,
                }
                self.ack_due |= OOO;
                if !self.sack {
                    self.ooo_acks = self.ooo_acks.saturating_add(1);
                }
            }
        } else if !data.is_empty() {
            self.ack_due |= OOO;
        }
        if h.flags & FIN != 0
            && seq::ge(original_end, self.rcv_nxt)
            && seq::lt(original_end, self.max_adv_right)
        {
            self.peer_fin.get_or_insert(original_end);
        }
        if self.peer_fin == Some(self.rcv_nxt) && !self.peer_fin_seen {
            self.peer_fin_seen = true;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.ack_due |= FIN_ACK;
            self.delack_deadline = None;
            self.ready |= Ready::READ_CLOSED | Ready::READABLE;
            match self.state {
                TcpState::Established => self.state = TcpState::CloseWait,
                TcpState::FinWait1 => {
                    if self.fin_seq.is_some_and(|s| seq::gt(self.snd_una, s)) {
                        self.enter_timewait(now);
                    } else {
                        self.state = TcpState::Closing;
                    }
                }
                TcpState::FinWait2 => self.enter_timewait(now),
                _ => {}
            }
        }
        if advanced && seq::ge(self.rcv_nxt, self.rcv_rtt_seq) {
            let sample = now.saturating_duration_since(self.rcv_rtt_time);
            if !sample.is_zero() {
                self.rcv_rtt = (self.rcv_rtt * 7 + sample) / 8;
            }
            self.rcv_rtt_seq = self.max_adv_right;
            self.rcv_rtt_time = now;
        }
    }
}

pub(crate) fn valid_timewait_fin(
    h: &Header,
    data_len: usize,
    snd_nxt: u32,
    rcv_nxt: u32,
    max_snd_wnd: u32,
    ts_recent: Option<u32>,
) -> bool {
    h.flags & (FIN | ACK) == (FIN | ACK)
        && h.flags & (RST | SYN) == 0
        && h.seq.wrapping_add(data_len as u32) == rcv_nxt.wrapping_sub(1)
        && seq::le(h.ack, snd_nxt)
        && seq::ge(h.ack, snd_nxt.wrapping_sub(max_snd_wnd))
        && ts_recent.is_none_or(|recent| {
            h.options
                .timestamps
                .is_some_and(|(ts, _)| seq::ge(ts, recent))
        })
}
