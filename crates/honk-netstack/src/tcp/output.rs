use std::time::Instant;

use crate::wire::{
    self,
    tcp::{self as wire_tcp, ACK, FIN, Header, Options, PSH, RST, SYN},
};

use super::sent::{Descriptor, FIN as SENT_FIN};
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
    },
    Retransmit {
        index: usize,
        start: u32,
        data: usize,
        fin: bool,
    },
}

impl Tcb {
    pub fn output(&mut self, now: Instant, out: &mut [u8], pool: &mut super::ring::Pool) -> Output {
        let syn = matches!(self.state, TcpState::SynSent | TcpState::SynReceived);
        let mut options = self.options(now, syn);
        let mut kind = if self.rst_pending {
            Some(Kind::Reset)
        } else if syn && self.syn_due {
            Some(Kind::Syn)
        } else {
            None
        };
        if kind.is_none() && !syn && self.state != TcpState::Closed {
            let cap = self.payload_cap(&options);
            let pipe = self.recovery.pipe(&self.sent, self.sack);
            if let Some((i, start, len, fin)) = self.sent.next_retransmit() {
                let data = (len as usize - usize::from(fin)).min(cap);
                let fin = fin && data as u32 + 1 == len;
                if self.recovery.can_retransmit(pipe, self.cc.cwnd())
                    && (data != 0 || fin)
                    && (data as u32 + u32::from(fin) == len || self.sent.ensure_room(pool, 1))
                {
                    kind = Some(Kind::Retransmit {
                        index: i,
                        start,
                        data,
                        fin,
                    });
                }
            }
            if kind.is_none()
                && matches!(
                    self.state,
                    TcpState::Established
                        | TcpState::CloseWait
                        | TcpState::FinWait1
                        | TcpState::LastAck
                )
            {
                let sent_offset = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
                let unsent = self.tx.len().saturating_sub(sent_offset);
                let rwnd = self
                    .snd_wnd
                    .saturating_sub(self.snd_nxt.wrapping_sub(self.snd_una))
                    as usize;
                let cwnd = self.cc.cwnd().saturating_sub(pipe) as usize;
                let data = unsent.min(cap).min(rwnd).min(cwnd);
                let fin = self.fin_requested
                    && self.fin_seq.is_none()
                    && data == unsent
                    && rwnd > data
                    && cwnd > data;
                if (data != 0 || fin) && self.sent.ensure_room(pool, 2) {
                    kind = Some(Kind::New { data, fin });
                }
                if unsent > data && cwnd < cap {
                    self.cwnd_limited = true;
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
            Kind::New { data, fin } => (
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
        let (payload, parts) = self.tx.slices(off, data_len);
        let Some(n) = wire_tcp::emit_packet_parts(
            out,
            self.tuple.local.ip(),
            self.tuple.remote.ip(),
            &hdr,
            &payload[..parts],
        ) else {
            return Output::Blocked;
        };
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
            Kind::New { data, fin } => {
                if self.sent.outstanding == 0 {
                    if now.saturating_duration_since(self.last_tx) >= self.rtt.rto() {
                        self.cc.restart_idle(self.send_mss());
                    }
                    self.first_tx_ts = now;
                }
                if fin {
                    self.fin_seq = Some(self.snd_nxt.wrapping_add(data as u32));
                }
                self.snd_nxt = self.snd_nxt.wrapping_add(data as u32 + u32::from(fin));
                self.sent.push(Descriptor {
                    end_seq: self.snd_nxt,
                    xmit_ts: now,
                    flags: if fin { SENT_FIN } else { 0 },
                    delivered: self.delivered,
                    delivered_ts: self.delivered_ts,
                    first_tx_ts: self.first_tx_ts,
                });
                if self.sent.pipe().saturating_add(self.send_mss()) >= self.cc.cwnd() {
                    self.cwnd_limited = true;
                }
            }
            Kind::Retransmit {
                index,
                start,
                data,
                fin,
            } => {
                self.recovery.retransmitted();
                let end = start.wrapping_add(data as u32 + u32::from(fin));
                self.sent.split(index, end);
                self.sent.retransmitted(index, start, now);
                self.stats.retrans_bytes += data as u64;
                self.stats.retrans_segments += 1;
            }
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
        self.last_tx = now;
        self.rearm(now);
        Output::Sent(n)
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
