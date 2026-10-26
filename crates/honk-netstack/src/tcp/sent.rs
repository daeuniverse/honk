//! Ordered send descriptors and incremental scoreboard counters.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::seq;

pub const SACKED: u8 = 1;
pub const LOST: u8 = 2;
pub const RETRANS: u8 = 4;
pub const FIN: u8 = 8;
pub const EVER_RETRANS: u8 = 16;
/// The delivery-rate sample taken from this segment is app-limited (draft-cheng-iccrg §3.3).
pub const APP_LIMITED: u8 = 32;

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

/// What a single ACK delivered, gathered across the cumulative ACK and every SACK block.
#[derive(Debug)]
pub struct Acked {
    now: Instant,
    min_rtt: Duration,
    /// Newly delivered bytes (cumulative plus SACK).
    pub delivered: u32,
    /// Karn-safe RTT from a completely acknowledged, never-retransmitted segment.
    pub rtt: Option<Duration>,
    /// Rate-sample source: the newly delivered segment sent last.
    pub sample: Option<RateSource>,
    /// The most recently transmitted newly delivered segment that RACK may trust.
    pub newest: Option<Newest>,
    /// End of the newest never-retransmitted segment delivered (F-RTO step 3).
    pub orig_end: Option<u32>,
    /// A never-retransmitted segment below the highest SACK arrived: reordering, not loss.
    pub reordered: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct RateSource {
    pub prior_delivered: u64,
    pub delivered_ts: Instant,
    pub first_tx_ts: Instant,
    pub xmit_ts: Instant,
    pub app_limited: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Newest {
    pub xmit_ts: Instant,
    pub end_seq: u32,
}

impl Acked {
    pub fn new(now: Instant, min_rtt: Duration) -> Acked {
        Acked {
            now,
            min_rtt,
            delivered: 0,
            rtt: None,
            sample: None,
            newest: None,
            orig_end: None,
            reordered: false,
        }
    }

    /// `n` bytes of `d` were newly delivered; `complete` means all of it.
    fn deliver(
        &mut self,
        d: &Descriptor,
        n: u32,
        complete: bool,
        below_highest_sack: bool,
        cum: bool,
    ) {
        self.delivered += n;
        if !complete {
            return;
        }
        let retransmitted = d.flags & EVER_RETRANS != 0;
        if !retransmitted {
            self.orig_end = Some(self.orig_end.map_or(d.end_seq, |e| seq::max(e, d.end_seq)));
            self.reordered |= below_highest_sack;
            if cum {
                self.rtt = Some(self.now.saturating_duration_since(d.xmit_ts));
            }
        }
        // A retransmission acknowledged sooner than the minimum RTT answers the original.
        let ambiguous =
            retransmitted && self.now.saturating_duration_since(d.xmit_ts) < self.min_rtt;
        if !ambiguous
            && self.newest.is_none_or(|v| {
                d.xmit_ts > v.xmit_ts || (d.xmit_ts == v.xmit_ts && seq::gt(d.end_seq, v.end_seq))
            })
        {
            self.newest = Some(Newest {
                xmit_ts: d.xmit_ts,
                end_seq: d.end_seq,
            });
        }
        if self.sample.is_none_or(|v| d.delivered >= v.prior_delivered) {
            self.sample = Some(RateSource {
                prior_delivered: d.delivered,
                delivered_ts: d.delivered_ts,
                first_tx_ts: d.first_tx_ts,
                xmit_ts: d.xmit_ts,
                app_limited: d.flags & APP_LIMITED != 0,
            });
        }
    }
}

/// Remembered fully-SACKed spans (see [`Sent::sack`]).
const RUNS: usize = 4;

/// Spans `[lo, hi)` known to be entirely SACKed, so the blocks a peer repeats on every ACK are
/// not walked again; `lo == hi` marks an empty entry. Boxed: a flow without SACK pays a pointer.
#[derive(Default)]
struct Runs {
    spans: [(u32, u32); RUNS],
    next: usize,
    /// Descriptors `sack` has visited; lets tests assert that repeated blocks cost O(1).
    #[cfg(test)]
    scanned: usize,
}

pub struct Sent {
    pub queue: VecDeque<Descriptor>,
    pub start: u32,
    pub outstanding: u32,
    pub sacked: u32,
    pub lost: u32,
    pub retrans: u32,
    pub highest_sacked: u32,
    retrans_cursor: u32,
    capacity_charged: usize,
    runs: Option<Box<Runs>>,
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
            retrans_cursor: start,
            capacity_charged: 0,
            runs: None,
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

    /// Nothing in flight: give the storage back, floor included. The floor is reserved at
    /// admission, so regrowing to it later cannot fail; it just must not stay resident per idle flow.
    pub fn shrink_idle(&mut self, pool: &mut super::ring::Pool) {
        if self.queue.is_empty() && self.capacity_charged != 0 {
            self.release(pool);
            self.check();
        }
    }

    pub fn release(&mut self, pool: &mut super::ring::Pool) {
        let size = std::mem::size_of::<Descriptor>();
        pool.release_bytes(self.capacity_charged.saturating_sub(FLOOR_SLOTS) * size);
        pool.metadata_shrink(self.capacity_charged * size);
        self.capacity_charged = 0;
        self.queue = VecDeque::new();
        self.runs = None;
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
        self.check();
    }

    /// Start sequence of descriptor `i`.
    pub fn start_of(&self, i: usize) -> u32 {
        if i == 0 {
            self.start
        } else {
            self.queue[i - 1].end_seq
        }
    }

    /// Index of the descriptor ending exactly at `end`.
    pub fn find_end(&self, end: u32) -> Option<usize> {
        let i = self.queue.partition_point(|d| seq::lt(d.end_seq, end));
        (i < self.queue.len() && self.queue[i].end_seq == end).then_some(i)
    }

    fn remove_flags(&mut self, flags: u8, n: u32) {
        if flags & SACKED != 0 {
            self.sacked -= n;
        }
        if flags & LOST != 0 {
            self.lost -= n;
        }
        if flags & RETRANS != 0 {
            self.retrans -= n;
        }
    }

    /// Cumulative ACK: frees descriptors and reports what became newly delivered.
    pub fn ack(&mut self, ack: u32, acked: &mut Acked) {
        while let Some(front) = self.queue.front() {
            if !seq::lt(self.start, ack) {
                break;
            }
            let end = seq::min(front.end_seq, ack);
            let n = end.wrapping_sub(self.start);
            let flags = front.flags;
            let complete = end == front.end_seq;
            if flags & SACKED == 0 {
                let below = seq::lt(front.end_seq, self.highest_sacked);
                acked.deliver(front, n, complete, below, true);
            }
            self.remove_flags(flags, n);
            self.outstanding -= n;
            self.start = end;
            if complete {
                self.queue.pop_front();
            } else {
                break;
            }
        }
        if seq::lt(self.highest_sacked, self.start) {
            self.highest_sacked = self.start;
        }
        if seq::lt(self.retrans_cursor, self.start) {
            self.retrans_cursor = self.start;
        }
        if let Some(runs) = &mut self.runs {
            for run in runs.spans.iter_mut().filter(|r| r.0 != r.1) {
                if seq::le(run.1, self.start) {
                    *run = (0, 0);
                } else if seq::lt(run.0, self.start) {
                    run.0 = self.start;
                }
            }
        }
        self.check();
    }

    /// Partially covered descriptors stay unsacked (SACK is allowed to renege). Blocks must be
    /// applied in ascending order so that only genuinely late segments look reordered.
    pub fn sack(&mut self, left: u32, right: u32, snd_nxt: u32, acked: &mut Acked) {
        if !seq::lt(left, right) || seq::gt(right, snd_nxt) || seq::le(right, self.start) {
            return;
        }
        // Skip what an earlier ACK already SACKed: peers repeat their blocks on every ACK, and
        // walking a wide one each time would cost O(outstanding) per ACK.
        // Nothing below `start` is queued, and a block reaching under it must still find its run.
        let mut from = seq::max(left, self.start);
        let mut run_lo = None;
        while let Some(&(lo, hi)) = self.runs.as_ref().and_then(|runs| {
            runs.spans
                .iter()
                .find(|r| seq::le(r.0, from) && seq::lt(from, r.1))
        }) {
            run_lo.get_or_insert(lo);
            from = hi;
        }
        if seq::ge(from, right) {
            return;
        }
        let highest = self.highest_sacked;
        let mut i = self.queue.partition_point(|d| seq::le(d.end_seq, from));
        let mut start = self.start_of(i);
        #[cfg(test)]
        let first = i;
        let mut run_end = from;
        while i < self.queue.len() {
            let d = &mut self.queue[i];
            if seq::gt(d.end_seq, right) {
                break;
            }
            let n = d.end_seq.wrapping_sub(start);
            if seq::ge(start, from) && d.flags & SACKED == 0 {
                self.sacked += n;
                if d.flags & LOST != 0 {
                    self.lost -= n;
                }
                if d.flags & RETRANS != 0 {
                    self.retrans -= n;
                }
                acked.deliver(d, n, true, seq::lt(d.end_seq, highest), false);
                d.flags = (d.flags | SACKED) & !(LOST | RETRANS);
                self.highest_sacked = seq::max(self.highest_sacked, d.end_seq);
            }
            if d.flags & SACKED != 0 {
                run_lo.get_or_insert(start);
                run_end = d.end_seq;
            } else {
                run_lo = None;
            }
            start = d.end_seq;
            i += 1;
        }
        #[cfg(test)]
        {
            self.runs.get_or_insert_default().scanned += i - first;
        }
        if let Some(lo) = run_lo
            && seq::lt(lo, run_end)
        {
            let runs = self.runs.get_or_insert_default();
            for run in &mut runs.spans {
                if seq::ge(run.0, lo) && seq::le(run.1, run_end) {
                    *run = (0, 0);
                }
            }
            let slot = runs
                .spans
                .iter()
                .position(|r| r.0 == r.1)
                .unwrap_or_else(|| {
                    runs.next = (runs.next + 1) % RUNS;
                    runs.next
                });
            runs.spans[slot] = (lo, run_end);
        }
        self.check();
    }

    pub fn mark_lost_index(&mut self, i: usize) {
        let start = self.start_of(i);
        let d = &mut self.queue[i];
        if d.flags & (SACKED | LOST) == 0 {
            self.lost += d.end_seq.wrapping_sub(start);
            d.flags |= LOST;
            self.retrans_cursor = seq::min(self.retrans_cursor, start);
        }
    }

    /// A retransmission is presumed lost: it must be sent again.
    pub fn mark_retransmission_lost(&mut self, i: usize) {
        let start = self.start_of(i);
        let d = &mut self.queue[i];
        debug_assert!(d.flags & (RETRANS | SACKED) == RETRANS);
        let n = d.end_seq.wrapping_sub(start);
        self.retrans -= n;
        if d.flags & LOST == 0 {
            self.lost += n;
        }
        d.flags = (d.flags | LOST) & !RETRANS;
        self.retrans_cursor = seq::min(self.retrans_cursor, start);
    }

    pub fn mark_first_lost(&mut self) {
        if !self.queue.is_empty() {
            self.mark_lost_index(0);
        }
        self.check();
    }

    /// Retransmission timeout: every unSACKed segment is lost. SACKed data stays delivered (Linux
    /// `tcp_timeout_mark_lost`) unless the head is SACKed yet unacknowledged: that is reneging, and
    /// then no SACK state is trusted.
    pub fn mark_all_lost(&mut self) {
        let renege = self.queue.front().is_some_and(|d| d.flags & SACKED != 0);
        self.lost = 0;
        self.retrans = 0;
        let mut start = self.start;
        for d in &mut self.queue {
            if renege {
                d.flags &= !SACKED;
            }
            if d.flags & SACKED == 0 {
                d.flags = (d.flags & !RETRANS) | LOST;
                self.lost += d.end_seq.wrapping_sub(start);
            }
            start = d.end_seq;
        }
        if renege {
            self.sacked = 0;
            self.highest_sacked = self.start;
            self.runs = None;
        }
        self.retrans_cursor = self.start;
        self.check();
    }

    /// Undo of a spurious loss event: nothing is lost any more, retransmissions stay in flight.
    pub fn unmark_lost(&mut self) {
        for d in &mut self.queue {
            d.flags &= !LOST;
        }
        self.lost = 0;
        self.check();
    }

    /// The path MTU shrank: every segment now too big is presumed dropped, including one that was
    /// already retransmitted at the old size.
    pub fn pmtu_changed(&mut self, cap: u32) {
        let mut start = self.start;
        for i in 0..self.queue.len() {
            if self.queue[i].end_seq.wrapping_sub(start) > cap {
                if self.queue[i].flags & (SACKED | RETRANS) == RETRANS {
                    self.mark_retransmission_lost(i);
                } else {
                    self.mark_lost_index(i);
                }
            }
            start = self.queue[i].end_seq;
        }
        self.check();
    }

    pub fn next_retransmit(&mut self) -> Option<(usize, u32, u32, bool)> {
        let mut i = self
            .queue
            .partition_point(|d| seq::le(d.end_seq, self.retrans_cursor));
        let mut start = self.start_of(i);
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

    /// Extends the whole `cap`-byte lost descriptor `i` over its successors that one TSO packet
    /// can resend with it: each still LOST (neither SACKed nor retransmitted), without FIN, at most
    /// `cap` bytes, and only the last one shorter. Returns the descriptor count (at most `max`) and
    /// the end sequence of the run.
    pub fn lost_run(&self, i: usize, cap: u32, max: usize) -> (usize, u32) {
        let mut n = 1;
        let mut end = self.queue[i].end_seq;
        while n < max
            && let Some(d) = self.queue.get(i + n)
        {
            let len = d.end_seq.wrapping_sub(end);
            if d.flags & (SACKED | LOST | RETRANS | FIN) != LOST || len == 0 || len > cap {
                break;
            }
            n += 1;
            end = d.end_seq;
            if len < cap {
                break;
            }
        }
        (n, end)
    }

    /// The newest segment that is neither SACKed nor already retransmitted: the probe a tail loss
    /// probe resends.
    pub fn last_unsacked(&self) -> Option<(usize, u32, u32, bool)> {
        let i = self
            .queue
            .iter()
            .rposition(|d| d.flags & (SACKED | RETRANS) == 0)?;
        let start = self.start_of(i);
        let d = &self.queue[i];
        Some((i, start, d.end_seq.wrapping_sub(start), d.flags & FIN != 0))
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
        self.check();
    }

    /// `d` was sent again at `now` with the connection's current delivery state.
    pub fn retransmitted(&mut self, i: usize, now: Instant, stamp: &Stamp) {
        let start = self.start_of(i);
        let d = &mut self.queue[i];
        debug_assert!(d.flags & (RETRANS | SACKED) == 0);
        d.flags = (d.flags | RETRANS | EVER_RETRANS) & !APP_LIMITED;
        if stamp.app_limited {
            d.flags |= APP_LIMITED;
        }
        d.xmit_ts = now;
        d.delivered = stamp.delivered;
        d.delivered_ts = stamp.delivered_ts;
        d.first_tx_ts = stamp.first_tx_ts;
        self.retrans += d.end_seq.wrapping_sub(start);
        self.retrans_cursor = seq::max(self.retrans_cursor, d.end_seq);
        self.check();
    }

    /// Recomputes every incremental counter from the descriptors and asserts they agree
    /// (debug builds), together with ordering, cursor and hint invariants. gVisor #14092 leaked
    /// `Outstanding` and stalled for 15 s.
    pub fn check(&self) {
        #[cfg(debug_assertions)]
        {
            let (mut s, mut l, mut r, mut o) = (0, 0, 0, 0);
            let mut start = self.start;
            for d in &self.queue {
                let n = d.end_seq.wrapping_sub(start);
                assert!(
                    n != 0 && n < 1 << 31,
                    "descriptors are non-empty and ascending"
                );
                o += n;
                if d.flags & SACKED != 0 {
                    s += n;
                    assert!(
                        d.flags & (LOST | RETRANS) == 0,
                        "SACKed data is neither lost nor retransmitted"
                    );
                    assert!(
                        seq::le(d.end_seq, self.highest_sacked),
                        "highest_sacked covers every SACKed descriptor"
                    );
                }
                if d.flags & LOST != 0 {
                    l += n;
                }
                if d.flags & RETRANS != 0 {
                    r += n;
                }
                for &(lo, hi) in self.runs.iter().flat_map(|runs| &runs.spans) {
                    assert!(
                        d.flags & SACKED != 0 || !(seq::lt(lo, d.end_seq) && seq::lt(start, hi)),
                        "a remembered SACK run covers only SACKed descriptors"
                    );
                }
                start = d.end_seq;
            }
            assert_eq!(
                (self.outstanding, self.sacked, self.lost, self.retrans),
                (o, s, l, r)
            );
            assert!(
                seq::ge(self.highest_sacked, self.start) && seq::le(self.highest_sacked, start),
                "highest_sacked stays inside the queue"
            );
            assert!(
                seq::ge(self.retrans_cursor, self.start) && seq::le(self.retrans_cursor, start),
                "the retransmit cursor stays inside the queue"
            );
            assert!(
                self.capacity_charged == 0 || self.queue.len() <= self.capacity_charged,
                "descriptors never outgrow their pool charge"
            );
        }
    }

    /// The scoreboard spans exactly `snd_una..snd_nxt` of a synchronized connection.
    pub fn check_bounds(&self, snd_una: u32, snd_nxt: u32) {
        debug_assert_eq!(self.start, snd_una, "scoreboard starts at snd_una");
        debug_assert_eq!(
            self.queue.back().map_or(self.start, |d| d.end_seq),
            snd_nxt,
            "scoreboard ends at snd_nxt"
        );
    }
}

/// Connection delivery state copied into a descriptor when it is (re)transmitted.
#[derive(Clone, Copy)]
pub struct Stamp {
    pub delivered: u64,
    pub delivered_ts: Instant,
    pub first_tx_ts: Instant,
    pub app_limited: bool,
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

    fn acked(now: Instant) -> Acked {
        Acked::new(now, Duration::ZERO)
    }

    fn stamp(now: Instant) -> Stamp {
        Stamp {
            delivered: 0,
            delivered_ts: now,
            first_tx_ts: now,
            app_limited: false,
        }
    }

    #[test]
    fn partial_ack_and_sack_counters() {
        let (mut s, now) = sent(5);
        let mut a = acked(now);
        s.sack(1150, 1400, 1500, &mut a);
        assert_eq!(a.delivered, 200, "partial descriptor is not sacked");
        assert_eq!((s.outstanding, s.sacked, s.pipe()), (500, 200, 300));
        let mut a = acked(now + Duration::from_millis(50));
        s.ack(1050, &mut a);
        assert_eq!(a.delivered, 50);
        assert_eq!(a.rtt, None, "a partially acknowledged segment gives no RTT");
        assert_eq!(s.outstanding, 450);
        let mut a = acked(now + Duration::from_millis(60));
        s.ack(1400, &mut a);
        assert_eq!(a.delivered, 150, "SACKed bytes are not delivered twice");
        assert_eq!((s.outstanding, s.sacked, s.lost, s.retrans), (100, 0, 0, 0));
    }

    #[test]
    fn retransmission_split_preserves_counters() {
        let (mut s, now) = sent(3);
        s.mark_first_lost();
        assert_eq!(s.next_retransmit(), Some((0, 1000, 100, false)));
        s.split(0, 1040);
        s.retransmitted(0, now, &stamp(now));
        assert_eq!(
            (s.outstanding, s.lost, s.retrans, s.pipe()),
            (300, 100, 40, 240)
        );
        assert_eq!(s.next_retransmit(), Some((1, 1040, 60, false)));
        s.retransmitted(1, now, &stamp(now));
        assert!(s.next_retransmit().is_none());
        let mut a = acked(now + Duration::from_secs(1));
        s.ack(1100, &mut a);
        assert_eq!((s.outstanding, s.lost, s.retrans), (200, 0, 0));
        assert_eq!(a.rtt, None, "Karn: no RTT from a retransmitted segment");
    }

    #[test]
    fn sack_never_frees_descriptors_and_rto_keeps_sacked_data_delivered() {
        let (mut s, now) = sent(6);
        s.sack(1300, 1600, 1600, &mut acked(now));
        s.mark_lost_index(0);
        s.mark_lost_index(1);
        assert_eq!((s.lost, s.sacked, s.pipe()), (200, 300, 100));
        assert_eq!(s.queue.len(), 6, "SACK never frees data descriptors");
        s.mark_all_lost();
        assert_eq!(
            (s.lost, s.sacked, s.pipe()),
            (300, 300, 0),
            "only the unSACKed bytes are lost; SACKed ones stay delivered"
        );
        // Delivered once: the later cumulative ACK must not count the SACKed bytes again.
        let mut a = acked(now);
        s.ack(1600, &mut a);
        assert_eq!(a.delivered, 300);
    }

    #[test]
    fn rto_with_a_sacked_head_is_reneging_and_trusts_no_sack_state() {
        let (mut s, now) = sent(6);
        s.sack(1000, 1100, 1600, &mut acked(now));
        s.sack(1300, 1600, 1600, &mut acked(now));
        s.mark_all_lost();
        assert_eq!((s.lost, s.sacked), (600, 0));
        assert_eq!(s.highest_sacked, s.start);
    }

    #[test]
    fn a_repeated_sack_block_is_not_walked_again() {
        let (mut s, now) = sent(3000);
        let end = 1000 + 3000 * 100;
        s.sack(1100, end, end, &mut acked(now));
        let scanned = |s: &Sent| s.runs.as_ref().map_or(0, |r| r.scanned);
        assert_eq!(scanned(&s), 2999);
        s.sack(1100, end, end, &mut acked(now));
        s.sack(5000, end - 5000, end, &mut acked(now));
        s.sack(1100, 1100 + 100 * 700, end, &mut acked(now));
        assert_eq!(
            scanned(&s),
            2999,
            "everything inside a known run is skipped"
        );
        // New data beyond the run costs only the new descriptors.
        for i in 0..10 {
            s.push(Descriptor {
                end_seq: end + (i + 1) * 100,
                xmit_ts: now,
                flags: 0,
                delivered: 0,
                delivered_ts: now,
                first_tx_ts: now,
            });
        }
        s.sack(1100, end + 1000, end + 1000, &mut acked(now));
        assert_eq!(scanned(&s), 3009);
        // The cumulative ACK trims the run without losing what is still SACKed.
        s.ack(2000, &mut acked(now));
        s.sack(1500, end + 1000, end + 1000, &mut acked(now));
        assert_eq!(scanned(&s), 3009);
        assert_eq!(s.sacked, s.outstanding, "every outstanding byte is SACKed");
    }

    #[test]
    fn pmtu_drop_makes_an_already_retransmitted_oversize_segment_sendable() {
        let (mut s, now) = sent(3);
        s.mark_first_lost();
        let (i, ..) = s.next_retransmit().unwrap();
        s.retransmitted(i, now, &stamp(now));
        assert!(s.next_retransmit().is_none(), "in flight at the old size");
        s.pmtu_changed(60);
        assert_eq!(s.next_retransmit(), Some((0, 1000, 100, false)));
        assert_eq!((s.retrans, s.lost), (0, 300));
    }

    #[test]
    fn reordering_is_a_never_retransmitted_segment_below_the_highest_sack() {
        let (mut s, now) = sent(5);
        let mut a = acked(now);
        s.sack(1300, 1400, 1500, &mut a);
        assert!(!a.reordered, "the first SACK is just the highest one");
        let mut a = acked(now);
        s.sack(1100, 1200, 1500, &mut a);
        assert!(a.reordered, "a lower segment arriving later is reordering");
        s.mark_lost_index(0);
        s.retransmitted(0, now, &stamp(now));
        let mut a = acked(now + Duration::from_millis(5));
        s.sack(1000, 1100, 1500, &mut a);
        assert!(
            !a.reordered,
            "a retransmission proves nothing about the network"
        );
        assert_eq!(a.newest.map(|n| n.end_seq), Some(1100));
    }

    #[test]
    fn delivery_sample_comes_from_the_segment_sent_last() {
        let (mut s, now) = sent(3);
        s.queue[0].delivered = 0;
        s.queue[1].delivered = 100;
        s.queue[2].delivered = 200;
        s.queue[2].xmit_ts = now + Duration::from_millis(7);
        let mut a = acked(now + Duration::from_millis(50));
        s.ack(1300, &mut a);
        let src = a.sample.unwrap();
        assert_eq!(
            (src.prior_delivered, src.xmit_ts),
            (200, now + Duration::from_millis(7))
        );
        assert_eq!(a.rtt, Some(Duration::from_millis(43)));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic]
    fn recount_catches_a_leaked_counter() {
        let (mut s, _) = sent(3);
        s.outstanding += 1;
        s.check();
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "highest_sacked covers")]
    fn check_catches_a_stale_highest_sacked() {
        let (mut s, now) = sent(3);
        s.sack(1100, 1200, 1300, &mut acked(now));
        s.highest_sacked = 1100;
        s.check();
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "retransmit cursor")]
    fn check_catches_a_cursor_past_the_queue() {
        let (mut s, _) = sent(3);
        s.retrans_cursor = 1400;
        s.check();
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "remembered SACK run")]
    fn check_catches_a_run_over_unsacked_data() {
        let (mut s, now) = sent(3);
        s.sack(1100, 1200, 1300, &mut acked(now));
        s.runs.as_mut().unwrap().spans[0] = (1000, 1200);
        s.check();
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic]
    fn push_rejects_a_descriptor_that_ends_before_the_previous_one() {
        let (mut s, now) = sent(2);
        s.push(Descriptor {
            end_seq: 1150,
            xmit_ts: now,
            flags: 0,
            delivered: 0,
            delivered_ts: now,
            first_tx_ts: now,
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "ascending")]
    fn split_checks_that_the_cut_stays_inside_the_descriptor() {
        let (mut s, _) = sent(2);
        s.split(0, 1500);
    }

    /// Random scoreboard operations: after each, `check` recomputes every counter from the
    /// descriptors, and the sacked/lost/retransmitted flags keep their exclusion rules.
    #[test]
    fn counters_survive_random_scoreboard_operations() {
        let mut rng = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move |n: u32| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            (rng >> 33) as u32 % n
        };
        let (mut s, now) = sent(1);
        let mut end = 1100;
        for step in 0..20_000 {
            let mut a = acked(now);
            match next(10) {
                0 | 1 => {
                    end += 100 * (1 + next(3));
                    s.push(Descriptor {
                        end_seq: end,
                        xmit_ts: now,
                        flags: 0,
                        delivered: 0,
                        delivered_ts: now,
                        first_tx_ts: now,
                    });
                }
                2 => {
                    let l = s.start + 50 * next(40);
                    s.sack(l, l + 50 * (1 + next(8)), end, &mut a);
                }
                3 => {
                    let to = s.start + 50 * next(12);
                    if seq::le(to, end) {
                        s.ack(to, &mut a);
                    }
                }
                4 if !s.queue.is_empty() => s.mark_lost_index(next(s.queue.len() as u32) as usize),
                5 => {
                    if let Some((i, start, len, _)) = s.next_retransmit() {
                        s.split(i, start + len.min(1 + next(len)));
                        s.retransmitted(i, now, &stamp(now));
                    }
                }
                6 if next(40) == 0 => s.mark_all_lost(),
                7 if next(10) == 0 => s.unmark_lost(),
                9 if next(20) == 0 => s.pmtu_changed(50 + 50 * next(3)),
                8 if !s.queue.is_empty() => {
                    let i = next(s.queue.len() as u32) as usize;
                    if s.queue[i].flags & (SACKED | RETRANS) == RETRANS {
                        s.mark_retransmission_lost(i);
                    }
                }
                _ => {}
            }
            s.check();
            assert!(s.pipe() <= s.outstanding + s.retrans, "step {step}");
            if s.queue.len() > 200 {
                s.ack(s.queue[100].end_seq, &mut acked(now));
            }
        }
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
