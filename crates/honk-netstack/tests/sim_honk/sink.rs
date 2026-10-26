//! A scripted TCP receiver for the simulator: ACKs every segment at once, reports SACK, DSACK and
//! timestamp echoes the way Linux does, and can be made to forget out-of-order data. smoltcp does
//! none of the first three, so recovery behaviour that depends on them needs this peer.

use super::sim::engine::{Host, epoch};
use honk_netstack::wire::{
    self,
    tcp::{ACK, FIN, Header, Options, SYN},
};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::Instant;

#[derive(Clone, Copy)]
pub struct SinkConfig {
    pub sack: bool,
    /// Most out-of-order ranges kept; a segment that would need one more is dropped (smoltcp: 4).
    pub max_ranges: usize,
    /// Drop every out-of-order segment (a receiver without reassembly storage).
    pub drop_ooo: bool,
}

pub struct Sink {
    cfg: SinkConfig,
    me: IpAddr,
    peer: Option<(IpAddr, u16, u16)>,
    iss: u32,
    snd_nxt: u32,
    irs: u32,
    rcv_nxt: u32,
    /// Out-of-order ranges, most recently touched first (the SACK block order).
    ooo: Vec<(u32, u32)>,
    ts_recent: u32,
    ts: bool,
    fin_sent: bool,
    /// Sequence number of the peer's FIN once seen (it may overtake data).
    fin_at: Option<u32>,
    out: VecDeque<Vec<u8>>,
    /// Payload bytes accepted in order so far.
    pub received: u64,
    pub dropped_ooo: u64,
}

fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

impl Sink {
    pub fn new(me: IpAddr, cfg: SinkConfig) -> Self {
        Sink {
            cfg,
            me,
            peer: None,
            iss: 7000,
            snd_nxt: 7000,
            irs: 0,
            rcv_nxt: 0,
            ooo: Vec::new(),
            ts_recent: 0,
            ts: false,
            fin_sent: false,
            fin_at: None,
            out: VecDeque::new(),
            received: 0,
            dropped_ooo: 0,
        }
    }

    fn emit(&mut self, now: Instant, seq: u32, flags: u8, sack: &[(u32, u32)], syn: bool) {
        let (ip, sport, cport) = self.peer.expect("peer");
        let mut options = Options::default();
        if syn {
            options.mss = Some(1380);
            options.wscale = Some(7);
            options.sack_permitted = self.cfg.sack;
        }
        if self.ts {
            let tsval = 1 + now.saturating_duration_since(epoch()).as_millis() as u32;
            options.timestamps = Some((tsval, self.ts_recent));
        }
        for &(l, r) in sack {
            options.sack.push(l, r);
        }
        let h = Header {
            src_port: cport,
            dst_port: sport,
            seq,
            ack: self.rcv_nxt,
            flags,
            window: u16::MAX,
            urgent: 0,
            options,
        };
        let mut buf = vec![0u8; 128];
        let n = wire::tcp::emit_packet(&mut buf, self.me, ip, &h, [&[], &[]]).unwrap();
        buf.truncate(n);
        self.out.push_back(buf);
    }

    /// Merges `[s, e)` into the range list and returns whether it added anything new.
    fn insert(&mut self, s: u32, e: u32) -> Option<bool> {
        let (mut lo, mut hi) = (s, e);
        let mut merged = false;
        let mut covered = false;
        let mut i = 0;
        while i < self.ooo.len() {
            let (l, r) = self.ooo[i];
            if !lt(r, lo) && !lt(hi, l) {
                covered |= !lt(lo, l) && !lt(r, hi);
                if lt(l, lo) {
                    lo = l;
                }
                if lt(hi, r) {
                    hi = r;
                }
                self.ooo.remove(i);
                merged = true;
            } else {
                i += 1;
            }
        }
        if !merged && self.ooo.len() >= self.cfg.max_ranges {
            return None;
        }
        self.ooo.insert(0, (lo, hi));
        Some(!covered)
    }

    fn deliver_in_order(&mut self) {
        while let Some(i) = self.ooo.iter().position(|&(l, _)| !lt(self.rcv_nxt, l)) {
            let (_, r) = self.ooo.remove(i);
            if lt(self.rcv_nxt, r) {
                self.received += u64::from(r.wrapping_sub(self.rcv_nxt));
                self.rcv_nxt = r;
            }
        }
    }

    fn on_segment(&mut self, now: Instant, h: &Header, len: u32) {
        if h.flags & SYN != 0 {
            self.irs = h.seq;
            self.rcv_nxt = h.seq.wrapping_add(1);
            self.ts = h.options.timestamps.is_some();
            if let Some((tsval, _)) = h.options.timestamps {
                self.ts_recent = tsval;
            }
            self.emit(now, self.iss, SYN | ACK, &[], true);
            self.snd_nxt = self.iss.wrapping_add(1);
            return;
        }
        let seq = h.seq;
        let fin = h.flags & FIN != 0;
        if len == 0 && !fin {
            return;
        }
        let end = seq.wrapping_add(len);
        let was = self.rcv_nxt;
        let mut dsack = None;
        if len != 0 {
            if !lt(was, end) {
                dsack = Some((seq, end));
            } else if lt(seq, was) {
                // Partly old: the new tail is handled below.
                dsack = Some((seq, was));
                self.received += u64::from(end.wrapping_sub(was));
                self.rcv_nxt = end;
                self.deliver_in_order();
            } else if seq == was {
                self.received += u64::from(len);
                self.rcv_nxt = end;
                self.deliver_in_order();
            } else if self.cfg.drop_ooo {
                self.dropped_ooo += 1;
            } else {
                match self.insert(seq, end) {
                    Some(true) => {}
                    Some(false) => dsack = Some((seq, end)),
                    None => self.dropped_ooo += 1,
                }
            }
        }
        if fin {
            self.fin_at = Some(end);
        }
        let fin_consumed = self.fin_at == Some(self.rcv_nxt);
        if fin_consumed {
            self.fin_at = None;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        }
        // RFC 7323 §4.3: only a segment that is not beyond the ACK point updates TS.Recent.
        if let Some((tsval, _)) = h.options.timestamps
            && !lt(tsval, self.ts_recent)
            && !lt(self.rcv_nxt, seq)
        {
            self.ts_recent = tsval;
        }
        let mut blocks = Vec::new();
        if self.cfg.sack {
            blocks.extend(dsack);
            let room = if self.ts { 3 } else { 4 };
            blocks.extend(self.ooo.iter().copied().take(room - blocks.len()));
        }
        self.emit(now, self.snd_nxt, ACK, &blocks, false);
        if fin_consumed && !self.fin_sent {
            self.fin_sent = true;
            let fin_seq = self.snd_nxt;
            self.snd_nxt = fin_seq.wrapping_add(1);
            self.emit(now, fin_seq, FIN | ACK, &[], false);
        }
    }
}

impl Host for Sink {
    fn receive(&mut self, now: Instant, packet: &[u8]) {
        let Ok(ip) = wire::parse_ip(packet) else {
            return;
        };
        let seg = &packet[ip.payload.clone()];
        let Ok((h, off)) = wire::tcp::parse(seg) else {
            return;
        };
        self.peer = Some((ip.src, h.src_port, h.dst_port));
        self.on_segment(now, &h, (seg.len() - off) as u32);
    }

    fn poll_transmit(&mut self, _now: Instant, out: &mut [u8]) -> Option<usize> {
        let p = self.out.pop_front()?;
        out[..p.len()].copy_from_slice(&p);
        Some(p.len())
    }

    fn poll_timeout(&self) -> Option<Instant> {
        None
    }

    fn handle_timeout(&mut self, _now: Instant) {}

    fn poll_app(&mut self, _now: Instant) {}
}
