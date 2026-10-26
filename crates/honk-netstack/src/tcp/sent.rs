//! Ordered send descriptors and incremental scoreboard counters.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::seq;

pub const SACKED: u8 = 1;
pub const LOST: u8 = 2;
pub const RETRANS: u8 = 4;
pub const FIN: u8 = 8;
const EVER_RETRANS: u8 = 16;

#[derive(Clone, Debug)]
pub struct Descriptor {
    pub end_seq: u32,
    pub xmit_ts: Instant,
    pub flags: u8,
    pub delivered: u64,
    pub delivered_ts: Instant,
    pub first_tx_ts: Instant,
}

pub const FLOOR_SLOTS: usize = 16;
pub const FLOOR_BYTES: usize = FLOOR_SLOTS * std::mem::size_of::<Descriptor>();

#[derive(Default, Debug)]
pub struct Acked {
    pub delivered: u32,
    pub rtt: Option<Duration>,
    pub prior_delivered: u64,
    pub interval: Option<Duration>,
}

pub struct Sent {
    pub queue: VecDeque<Descriptor>,
    pub start: u32,
    pub outstanding: u32,
    pub sacked: u32,
    pub lost: u32,
    pub retrans: u32,
    pub highest_sacked: u32,
    lost_cursor: u32,
    sacked_before_cursor: u32,
    retrans_cursor: u32,
    capacity_charged: usize,
}

impl Sent {
    pub fn new(start: u32) -> Sent {
        Sent {
            queue: VecDeque::new(),
            start,
            outstanding: 0,
            sacked: 0,
            lost: 0,
            retrans: 0,
            highest_sacked: start,
            lost_cursor: start,
            sacked_before_cursor: 0,
            retrans_cursor: start,
            capacity_charged: 0,
        }
    }

    pub fn ensure_room(&mut self, pool: &mut super::ring::Pool, extra: usize) -> bool {
        if self.queue.len() + extra <= self.queue.capacity() {
            return true;
        }
        let old = self.capacity_charged;
        let new = self
            .queue
            .capacity()
            .saturating_mul(2)
            .max(FLOOR_SLOTS)
            .max(self.queue.len() + extra);
        let size = std::mem::size_of::<Descriptor>();
        let shared_extra =
            (new.saturating_sub(FLOOR_SLOTS) - old.saturating_sub(FLOOR_SLOTS)) * size;
        if !pool.reserve_bytes(shared_extra) {
            return false;
        }
        self.queue.reserve_exact(new - self.queue.len());
        debug_assert_eq!(self.queue.capacity(), new);
        pool.metadata_grow((new - old) * size);
        self.capacity_charged = new;
        true
    }

    pub fn shrink_idle(&mut self, pool: &mut super::ring::Pool) {
        if !self.queue.is_empty() || self.capacity_charged <= FLOOR_SLOTS {
            return;
        }
        self.queue.shrink_to(FLOOR_SLOTS);
        let released =
            (self.capacity_charged - self.queue.capacity()) * std::mem::size_of::<Descriptor>();
        pool.release_bytes(released);
        pool.metadata_shrink(released);
        self.capacity_charged = self.queue.capacity();
    }

    pub fn release(&mut self, pool: &mut super::ring::Pool) {
        let size = std::mem::size_of::<Descriptor>();
        pool.release_bytes(self.capacity_charged.saturating_sub(FLOOR_SLOTS) * size);
        pool.metadata_shrink(self.capacity_charged * size);
        self.capacity_charged = 0;
        self.queue = VecDeque::new();
    }

    pub fn pipe(&self) -> u32 {
        self.outstanding
            .saturating_sub(self.sacked)
            .saturating_sub(self.lost)
            .saturating_add(self.retrans)
    }

    pub fn push(&mut self, d: Descriptor) {
        let prev = self.queue.back().map_or(self.start, |d| d.end_seq);
        self.outstanding += d.end_seq.wrapping_sub(prev);
        self.queue.push_back(d);
    }

    fn remove_flags(&mut self, flags: u8, n: u32, end: u32) {
        if flags & SACKED != 0 {
            self.sacked -= n;
            if seq::le(end, self.lost_cursor) {
                self.sacked_before_cursor = self.sacked_before_cursor.saturating_sub(n);
            }
        }
        if flags & LOST != 0 {
            self.lost -= n;
        }
        if flags & RETRANS != 0 {
            self.retrans -= n;
        }
    }

    pub fn ack(&mut self, ack: u32, now: Instant) -> Acked {
        let mut info = Acked::default();
        while let Some(front) = self.queue.front() {
            if !seq::lt(self.start, ack) {
                break;
            }
            let end = seq::min(front.end_seq, ack);
            let n = end.wrapping_sub(self.start);
            let flags = front.flags;
            let xmit = front.xmit_ts;
            let complete = end == front.end_seq;
            info.prior_delivered = front.delivered;
            info.interval = Some(
                now.saturating_duration_since(front.delivered_ts)
                    .max(front.xmit_ts.saturating_duration_since(front.first_tx_ts)),
            );
            if flags & SACKED == 0 {
                info.delivered += n;
            }
            if complete && flags & EVER_RETRANS == 0 {
                info.rtt = Some(now.saturating_duration_since(xmit));
            }
            self.remove_flags(flags, n, end);
            self.outstanding -= n;
            self.start = end;
            if complete {
                self.queue.pop_front();
            } else {
                break;
            }
        }
        if seq::lt(self.lost_cursor, self.start) {
            self.lost_cursor = self.start;
        }
        if seq::lt(self.retrans_cursor, self.start) {
            self.retrans_cursor = self.start;
        }
        self.check();
        info
    }

    /// Partially covered descriptors stay unsacked (SACK is allowed to renege).
    pub fn sack(&mut self, left: u32, right: u32, snd_nxt: u32) -> u32 {
        if !seq::lt(left, right) || seq::gt(right, snd_nxt) || seq::le(right, self.start) {
            return 0;
        }
        let mut i = self.queue.partition_point(|d| seq::le(d.end_seq, left));
        let mut start = if i == 0 {
            self.start
        } else {
            self.queue[i - 1].end_seq
        };
        let mut delivered = 0;
        while i < self.queue.len() {
            let d = &mut self.queue[i];
            if seq::gt(d.end_seq, right) {
                break;
            }
            let n = d.end_seq.wrapping_sub(start);
            if seq::ge(start, left) && d.flags & SACKED == 0 {
                self.sacked += n;
                delivered += n;
                if seq::le(d.end_seq, self.lost_cursor) {
                    self.sacked_before_cursor += n;
                }
                if d.flags & LOST != 0 {
                    self.lost -= n;
                }
                if d.flags & RETRANS != 0 {
                    self.retrans -= n;
                }
                d.flags = (d.flags | SACKED) & !(LOST | RETRANS);
                self.highest_sacked = seq::max(self.highest_sacked, d.end_seq);
            }
            start = d.end_seq;
            i += 1;
        }
        self.check();
        delivered
    }

    fn mark_lost_index(&mut self, i: usize, start: u32) {
        let d = &mut self.queue[i];
        if d.flags & (SACKED | LOST) == 0 {
            self.lost += d.end_seq.wrapping_sub(start);
            d.flags |= LOST;
            self.retrans_cursor = seq::min(self.retrans_cursor, start);
        }
    }

    pub fn mark_first_lost(&mut self) {
        if !self.queue.is_empty() {
            self.mark_lost_index(0, self.start);
        }
        self.check();
    }

    /// RFC 6675 IsLost's byte threshold; the cursor avoids rescanning resolved prefixes.
    pub fn mark_sack_losses(&mut self, mss: u32) {
        let mut i = self
            .queue
            .partition_point(|d| seq::le(d.end_seq, self.lost_cursor));
        let mut start = if i == 0 {
            self.start
        } else {
            self.queue[i - 1].end_seq
        };
        while i < self.queue.len() {
            let d = &self.queue[i];
            let n = d.end_seq.wrapping_sub(start);
            let sacked = d.flags & SACKED != 0;
            let above = self
                .sacked
                .saturating_sub(self.sacked_before_cursor)
                .saturating_sub(if sacked { n } else { 0 });
            if !sacked && d.flags & LOST == 0 && above < 3 * mss {
                break;
            }
            if sacked {
                self.sacked_before_cursor += n;
            } else {
                self.mark_lost_index(i, start);
            }
            start = self.queue[i].end_seq;
            self.lost_cursor = start;
            i += 1;
        }
        self.check();
    }

    pub fn mark_all_lost(&mut self) {
        self.lost = 0;
        self.retrans = 0;
        self.sacked = 0;
        for d in &mut self.queue {
            d.flags &= !(SACKED | LOST | RETRANS);
        }
        let mut start = self.start;
        for d in &mut self.queue {
            if d.flags & SACKED == 0 {
                d.flags |= LOST;
                self.lost += d.end_seq.wrapping_sub(start);
            }
            start = d.end_seq;
        }
        self.retrans_cursor = self.start;
        self.lost_cursor = self.queue.back().map_or(self.start, |d| d.end_seq);
        self.sacked_before_cursor = self.sacked;
        self.check();
    }

    pub fn pmtu_changed(&mut self, cap: u32) {
        let mut start = self.start;
        for i in 0..self.queue.len() {
            if self.queue[i].end_seq.wrapping_sub(start) > cap {
                self.mark_lost_index(i, start);
            }
            start = self.queue[i].end_seq;
        }
    }

    pub fn next_retransmit(&mut self) -> Option<(usize, u32, u32, bool)> {
        let mut i = self
            .queue
            .partition_point(|d| seq::le(d.end_seq, self.retrans_cursor));
        let mut start = if i == 0 {
            self.start
        } else {
            self.queue[i - 1].end_seq
        };
        while i < self.queue.len() {
            let d = &self.queue[i];
            if d.flags & (SACKED | LOST | RETRANS) == LOST {
                self.retrans_cursor = start;
                return Some((i, start, d.end_seq.wrapping_sub(start), d.flags & FIN != 0));
            }
            start = d.end_seq;
            self.retrans_cursor = start;
            i += 1;
        }
        None
    }

    pub fn split(&mut self, i: usize, at: u32) {
        let d = &mut self.queue[i];
        if d.end_seq == at {
            return;
        }
        let tail = d.clone();
        d.end_seq = at;
        d.flags &= !FIN;
        self.queue.insert(i + 1, tail);
    }

    pub fn retransmitted(&mut self, i: usize, start: u32, now: Instant) {
        let d = &mut self.queue[i];
        debug_assert!(d.flags & (LOST | RETRANS | SACKED) == LOST);
        d.flags |= RETRANS | EVER_RETRANS;
        d.xmit_ts = now;
        self.retrans += d.end_seq.wrapping_sub(start);
        self.retrans_cursor = d.end_seq;
        self.check();
    }

    pub fn check(&self) {
        #[cfg(debug_assertions)]
        {
            let (mut s, mut l, mut r, mut o) = (0, 0, 0, 0);
            let mut start = self.start;
            for d in &self.queue {
                let n = d.end_seq.wrapping_sub(start);
                o += n;
                if d.flags & SACKED != 0 {
                    s += n;
                }
                if d.flags & LOST != 0 {
                    l += n;
                }
                if d.flags & RETRANS != 0 {
                    r += n;
                }
                start = d.end_seq;
            }
            debug_assert_eq!(
                (self.outstanding, self.sacked, self.lost, self.retrans),
                (o, s, l, r)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sent(n: usize) -> (Sent, Instant) {
        let now = Instant::now();
        let mut s = Sent::new(1000);
        for i in 0..n {
            s.push(Descriptor {
                end_seq: 1000 + (i as u32 + 1) * 100,
                xmit_ts: now,
                flags: 0,
                delivered: 0,
                delivered_ts: now,
                first_tx_ts: now,
            });
        }
        (s, now)
    }

    #[test]
    fn partial_ack_and_sack_counters() {
        let (mut s, now) = sent(5);
        assert_eq!(
            s.sack(1150, 1400, 1500),
            200,
            "partial descriptor is not sacked"
        );
        assert_eq!((s.outstanding, s.sacked, s.pipe()), (500, 200, 300));
        let a = s.ack(1050, now + Duration::from_millis(50));
        assert_eq!(a.delivered, 50);
        assert_eq!(s.outstanding, 450);
        s.ack(1400, now + Duration::from_millis(60));
        assert_eq!((s.outstanding, s.sacked, s.lost, s.retrans), (100, 0, 0, 0));
    }

    #[test]
    fn retransmission_split_preserves_counters() {
        let (mut s, now) = sent(3);
        s.mark_first_lost();
        assert_eq!(s.next_retransmit(), Some((0, 1000, 100, false)));
        s.split(0, 1040);
        s.retransmitted(0, 1000, now);
        assert_eq!(
            (s.outstanding, s.lost, s.retrans, s.pipe()),
            (300, 100, 40, 240)
        );
        assert_eq!(s.next_retransmit(), Some((1, 1040, 60, false)));
        s.retransmitted(1, 1040, now);
        assert!(s.next_retransmit().is_none());
        s.ack(1100, now + Duration::from_secs(1));
        assert_eq!((s.outstanding, s.lost, s.retrans), (200, 0, 0));
    }

    #[test]
    fn sack_threshold_and_reneging_safe_storage() {
        let (mut s, _) = sent(6);
        s.sack(1300, 1600, 1600);
        s.mark_sack_losses(100);
        assert_eq!((s.lost, s.sacked, s.pipe()), (300, 300, 0));
        assert_eq!(s.queue.len(), 6, "SACK never frees data descriptors");
        s.mark_all_lost();
        assert_eq!((s.lost, s.sacked), (600, 0), "RTO tolerates SACK reneging");
    }

    #[test]
    fn descriptor_capacity_is_budgeted_and_floor_survives_pressure() {
        let mut pool =
            super::super::ring::Pool::with_limits(0, 2 * super::super::ring::CHUNK + FLOOR_BYTES);
        let mut s = Sent::new(1000);
        assert!(s.ensure_room(&mut pool, 2));
        assert_eq!(pool.allocated_bytes(), FLOOR_BYTES);
        let now = Instant::now();
        for i in 0..FLOOR_SLOTS - 1 {
            s.push(Descriptor {
                end_seq: 1001 + i as u32,
                xmit_ts: now,
                flags: 0,
                delivered: 0,
                delivered_ts: now,
                first_tx_ts: now,
            });
        }
        assert!(
            !s.ensure_room(&mut pool, 2),
            "descriptor growth must respect the shared limit"
        );
        s.release(&mut pool);
        assert_eq!(pool.allocated_bytes(), 0);
        assert_eq!(pool.shared_bytes(), 0);
    }
}
