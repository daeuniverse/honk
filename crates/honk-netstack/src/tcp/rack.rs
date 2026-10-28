//! RACK-TLP (RFC 8985): time-based loss detection for SACK peers.
//!
//! RACK compares send times. Every unsacked, not yet lost segment sent before the newest delivered
//! one is lost once `rack.rtt + reo_wnd` has passed since it was sent. Segments that were never
//! retransmitted are in send order already, so a sequence cursor walks them; only retransmissions
//! need the lazy FIFO keyed by transmit time (stale entries are skipped when they reach the head).
//! Each segment is therefore visited O(1) times instead of once per ACK.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::sent::{EVER_RETRANS, LOST, Newest, RETRANS, SACKED, Sent};
use super::seq;

const FIFO_FLOOR: usize = super::sent::FLOOR_SLOTS;
type Retransmit = (u32, Instant);

#[derive(Default)]
struct Retransmits {
    entries: VecDeque<Retransmit>,
    reservation: Option<crate::MemoryReservation>,
}

impl std::ops::Deref for Retransmits {
    type Target = VecDeque<Retransmit>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl std::ops::DerefMut for Retransmits {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entries
    }
}

/// Linux's `TCP_DELACK_MAX`: a lone segment may wait this long for its ACK.
pub const MAX_ACK_DELAY: Duration = Duration::from_millis(200);
/// Reorder-window growth is bounded by SRTT; this bounds the multiplier itself.
const MAX_STEPS: u8 = 16;
/// Recoveries without DSACK before the reorder window shrinks back to min_rtt/4.
const PERSIST: u8 = 16;
const DUPTHRESH: u32 = 3;

#[derive(Default)]
pub struct Rack {
    /// Transmit time, end sequence and RTT of the newest segment known delivered.
    newest: Option<(Instant, u32)>,
    rtt_us: u32,
    /// Reordering has been observed, so the reorder window stays non-zero.
    reord_seen: bool,
    steps: u8,
    persist: u8,
    /// `snd_nxt` when the window last grew: DSACKs raise it at most once per round trip.
    step_seq: u32,
    /// Reorder timer, as the time it was computed for (not when it is processed).
    pub timer: Option<Instant>,
    cursor: u32,
    retransmits: Option<Box<Retransmits>>,
    pub tlp: Option<Tlp>,
    /// A DSACK arrived since the probe was sent.
    tlp_dsack: bool,
}

/// The one outstanding tail loss probe.
#[derive(Clone, Copy)]
pub struct Tlp {
    pub high_seq: u32,
    pub retransmit: bool,
}

/// How an ACK of a tail loss probe is to be interpreted (RFC 8985 §7.4).
#[derive(PartialEq, Eq, Debug)]
pub enum TlpOutcome {
    Pending,
    /// The probe repaired a loss the sender had not yet noticed: one congestion event.
    Loss,
    Done,
}

impl Rack {
    pub(super) fn overhead_bound() -> usize {
        std::mem::size_of::<Retransmits>() + 3 * FIFO_FLOOR * std::mem::size_of::<Retransmit>()
    }

    pub(super) fn ensure_room(&mut self, pool: &super::ring::Pool, extra: usize) -> bool {
        let Some(budget) = pool.index_budget() else {
            return true;
        };
        let q = self.retransmits.get_or_insert_default();
        let Some(needed) = q.len().checked_add(extra) else {
            return false;
        };
        if needed <= q.capacity() {
            return true;
        }
        let Some(capacity) = needed.max(FIFO_FLOOR).checked_next_power_of_two() else {
            return false;
        };
        let Some(bytes) = capacity
            .saturating_sub(FIFO_FLOOR)
            .checked_mul(std::mem::size_of::<Retransmit>())
            .and_then(|n| n.checked_mul(3))
        else {
            return false;
        };
        let Some(reservation) = budget.reserve(bytes) else {
            return false;
        };
        let len = q.len();
        q.reserve_exact(capacity - len);
        assert!(q.capacity() <= capacity, "unfunded RACK FIFO capacity");
        q.reservation = Some(reservation);
        true
    }

    pub fn new(start: u32) -> Rack {
        Rack {
            steps: 1,
            step_seq: start,
            cursor: start,
            ..Rack::default()
        }
    }

    /// Feeds the newest delivered segment and reordering evidence of one ACK.
    pub fn on_delivery(
        &mut self,
        now: Instant,
        newest: Option<Newest>,
        reordered: bool,
        dsack: bool,
        ack: u32,
        snd_nxt: u32,
    ) {
        if let Some(n) = newest {
            let newer = self.newest.is_none_or(|(ts, end)| {
                n.xmit_ts > ts || (n.xmit_ts == ts && seq::gt(n.end_seq, end))
            });
            if newer {
                self.newest = Some((n.xmit_ts, n.end_seq));
                self.rtt_us = now
                    .saturating_duration_since(n.xmit_ts)
                    .as_micros()
                    .min(u128::from(u32::MAX)) as u32;
            }
        }
        self.reord_seen |= reordered;
        if dsack {
            self.reord_seen = true;
            if seq::ge(ack, self.step_seq) {
                self.steps = (self.steps + 1).min(MAX_STEPS);
                self.step_seq = snd_nxt;
            }
            self.persist = PERSIST;
            if self.tlp.is_some() {
                self.tlp_dsack = true;
            }
        }
    }

    /// Each loss recovery without a DSACK in between ages the enlarged window.
    pub fn on_recovery(&mut self) {
        if self.persist > 0 {
            self.persist -= 1;
            if self.persist == 0 {
                self.steps = 1;
            }
        }
    }

    /// Reorder window (RFC 8985 §6.2 step 4). Zero while no reordering has been seen and either a
    /// recovery is under way or DupThresh segments are SACKed, as Linux does.
    pub fn reo_wnd(
        &self,
        min_rtt: Duration,
        srtt: Duration,
        recovering: bool,
        sacked: u32,
        mss: u32,
    ) -> Duration {
        if !self.reord_seen && (recovering || sacked >= DUPTHRESH * mss) {
            return Duration::ZERO;
        }
        (min_rtt / 4 * u32::from(self.steps.max(1))).min(srtt)
    }

    fn older(&self, ts: Instant, end: u32) -> bool {
        self.newest
            .is_some_and(|(nts, nend)| ts < nts || (ts == nts && seq::lt(end, nend)))
    }

    /// Marks lost everything RACK deems lost at time `at`, and arms the reorder timer for the
    /// earliest segment that is merely overdue-to-be. Returns whether anything was newly marked.
    pub fn detect(&mut self, sent: &mut Sent, at: Instant, reo_wnd: Duration) -> bool {
        let mut timer: Option<Instant> = None;
        let mut marked = false;
        let wait = Duration::from_micros(u64::from(self.rtt_us)) + reo_wnd;
        let mut cursor = self.cursor;
        if seq::lt(cursor, sent.start) {
            cursor = sent.start;
        }
        let mut i = sent.queue.partition_point(|d| seq::le(d.end_seq, cursor));
        while i < sent.queue.len() {
            let d = &sent.queue[i];
            if d.flags & (SACKED | LOST | EVER_RETRANS) != 0 {
                cursor = d.end_seq;
                i += 1;
                continue;
            }
            if !self.older(d.xmit_ts, d.end_seq) {
                break;
            }
            let due = d.xmit_ts + wait;
            if due > at {
                timer = Some(due);
                break;
            }
            cursor = d.end_seq;
            sent.mark_lost_index(i);
            marked = true;
            i += 1;
        }
        self.cursor = cursor;
        while let Some(&(end, ts)) = self.retransmits.as_ref().and_then(|q| q.front()) {
            let Some(i) = sent.find_end(end).filter(|&i| {
                sent.queue[i].xmit_ts == ts && sent.queue[i].flags & (RETRANS | SACKED) == RETRANS
            }) else {
                self.pop_retransmit();
                continue;
            };
            if !self.older(ts, end) {
                break;
            }
            let due = ts + wait;
            if due > at {
                timer = Some(timer.map_or(due, |t| t.min(due)));
                break;
            }
            self.pop_retransmit();
            sent.mark_retransmission_lost(i);
            marked = true;
        }
        self.timer = timer;
        sent.check();
        marked
    }

    /// Everything unsacked is lost again and the scan restarts (RTO, or undo of a loss mark).
    pub fn reset(&mut self, sent: &Sent) {
        self.cursor = sent.start;
        self.retransmits = None;
        self.timer = None;
    }

    /// After an RTO every outstanding segment is marked lost, so there is nothing for the cursor.
    pub fn reset_after_rto(&mut self, sent: &Sent) {
        self.cursor = sent.queue.back().map_or(sent.start, |d| d.end_seq);
        self.retransmits = None;
        self.timer = None;
    }

    pub fn on_retransmit(&mut self, end: u32, now: Instant) {
        self.retransmits
            .get_or_insert_default()
            .push_back((end, now));
    }

    #[cfg(test)]
    pub fn pending_retransmits(&self) -> usize {
        self.retransmits.as_ref().map_or(0, |q| q.len())
    }

    fn pop_retransmit(&mut self) {
        if let Some(q) = &mut self.retransmits {
            q.pop_front();
            if q.is_empty() {
                self.retransmits = None;
            }
        }
    }

    /// Releases entries the cumulative ACK has passed so the FIFO stays bounded.
    pub fn trim(&mut self, start: u32) {
        while self
            .retransmits
            .as_ref()
            .and_then(|q| q.front())
            .is_some_and(|&(end, _)| seq::le(end, start))
        {
            self.pop_retransmit();
        }
    }

    pub fn start_tlp(&mut self, high_seq: u32, retransmit: bool) {
        self.tlp = Some(Tlp {
            high_seq,
            retransmit,
        });
        self.tlp_dsack = false;
    }

    /// RFC 8985 §7.4 as implemented by Linux `tcp_process_tlp_ack`.
    pub fn on_tlp_ack(&mut self, ack: u32, advanced: bool, pure_dup: bool) -> TlpOutcome {
        let Some(tlp) = self.tlp else {
            return TlpOutcome::Done;
        };
        if seq::lt(ack, tlp.high_seq) {
            return TlpOutcome::Pending;
        }
        let outcome = if !tlp.retransmit || self.tlp_dsack {
            TlpOutcome::Done
        } else if seq::gt(ack, tlp.high_seq) {
            TlpOutcome::Loss
        } else if pure_dup && !advanced {
            TlpOutcome::Done
        } else {
            return TlpOutcome::Pending;
        };
        self.tlp = None;
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::sent::{Acked, Descriptor, Stamp};

    fn setup(n: u32) -> (Sent, Instant) {
        let t0 = Instant::now();
        let mut s = Sent::new(1000);
        for i in 0..n {
            s.push(Descriptor {
                end_seq: 1100 + i * 100,
                xmit_ts: t0 + Duration::from_millis(u64::from(i)),
                flags: 0,
                delivered: 0,
                delivered_ts: t0,
                first_tx_ts: t0,
            });
        }
        (s, t0)
    }

    fn deliver(s: &mut Sent, rack: &mut Rack, left: u32, right: u32, now: Instant) {
        let mut a = Acked::new(now, Duration::from_millis(10));
        s.sack(left, right, s.queue.back().unwrap().end_seq, &mut a);
        rack.on_delivery(now, a.newest, a.reordered, false, 1000, 1500);
    }

    #[test]
    fn segments_sent_before_the_newest_delivered_are_lost_after_the_reorder_window() {
        let (mut s, t0) = setup(5);
        let mut rack = Rack::new(1000);
        let ms = Duration::from_millis;
        let now = t0 + ms(104);
        deliver(&mut s, &mut rack, 1400, 1500, now); // segment 4, sent at +4 ms: rack.rtt = 100 ms
        rack.detect(&mut s, now, ms(10));
        assert_eq!(s.lost, 0, "nothing is overdue inside the reorder window");
        assert_eq!(
            rack.timer,
            Some(t0 + ms(110)),
            "segment 0: sent + rtt + reo_wnd"
        );
        // The timer is processed late; only what was overdue at its own target time is marked.
        rack.detect(&mut s, t0 + ms(110), ms(10));
        assert_eq!(s.lost, 100);
        assert_eq!(rack.timer, Some(t0 + ms(111)));
        rack.detect(&mut s, t0 + ms(500), ms(10));
        assert_eq!(s.lost, 400, "segments 0-3, never the delivered one");
        assert_eq!(rack.timer, None);
    }

    #[test]
    fn zero_reorder_window_marks_everything_older_immediately() {
        let (mut s, t0) = setup(4);
        let mut rack = Rack::new(1000);
        let now = t0 + Duration::from_millis(103);
        deliver(&mut s, &mut rack, 1300, 1400, now);
        rack.detect(&mut s, now, Duration::ZERO);
        assert_eq!((s.lost, s.sacked), (300, 100));
    }

    #[test]
    fn lost_retransmission_is_found_through_the_fifo_and_stale_entries_are_skipped() {
        let (mut s, t0) = setup(3);
        let mut rack = Rack::new(1000);
        let stamp = Stamp {
            delivered: 0,
            delivered_ts: t0,
            first_tx_ts: t0,
            app_limited: false,
        };
        s.mark_first_lost();
        let t1 = t0 + Duration::from_millis(50);
        s.retransmitted(0, t1, &stamp);
        rack.on_retransmit(1100, t1);
        rack.on_retransmit(1100, t0); // stale: older timestamp for the same end
        // Later data delivered after the retransmission: the retransmission is overdue.
        let t2 = t0 + Duration::from_millis(60);
        s.push(Descriptor {
            end_seq: 1400,
            xmit_ts: t2,
            flags: 0,
            delivered: 0,
            delivered_ts: t0,
            first_tx_ts: t0,
        });
        let now = t0 + Duration::from_millis(80);
        deliver(&mut s, &mut rack, 1300, 1400, now);
        rack.detect(&mut s, now, Duration::ZERO);
        assert_eq!(
            s.retrans, 0,
            "the lost retransmission is no longer in flight"
        );
        assert_eq!(s.next_retransmit(true).map(|v| v.1), Some(1000));
    }

    #[test]
    fn reorder_window_grows_on_dsack_once_per_srtt_and_decays_over_recoveries() {
        let mut rack = Rack::new(1000);
        let (min, srtt) = (Duration::from_millis(40), Duration::from_millis(100));
        let t = Instant::now();
        assert_eq!(
            rack.reo_wnd(min, srtt, false, 0, 100),
            Duration::from_millis(10)
        );
        rack.on_delivery(t, None, false, true, 1000, 1500);
        rack.on_delivery(t, None, false, true, 1100, 1600);
        assert_eq!(
            rack.reo_wnd(min, srtt, false, 0, 100),
            Duration::from_millis(20),
            "same round"
        );
        rack.on_delivery(t, None, false, true, 1500, 1800);
        assert_eq!(
            rack.reo_wnd(min, srtt, false, 0, 100),
            Duration::from_millis(30)
        );
        assert_eq!(
            rack.reo_wnd(min, Duration::from_millis(15), false, 0, 100),
            Duration::from_millis(15)
        );
        assert_eq!(
            rack.reo_wnd(min, srtt, true, 0, 100),
            Duration::from_millis(30),
            "reordering was seen"
        );
        for _ in 0..PERSIST {
            rack.on_recovery();
        }
        assert_eq!(
            rack.reo_wnd(min, srtt, false, 0, 100),
            Duration::from_millis(10)
        );
    }

    #[test]
    fn aggressive_window_only_before_reordering_is_seen() {
        let rack = Rack::new(1000);
        let (min, srtt) = (Duration::from_millis(40), Duration::from_millis(100));
        assert_eq!(
            rack.reo_wnd(min, srtt, false, 299, 100),
            Duration::from_millis(10)
        );
        assert_eq!(rack.reo_wnd(min, srtt, false, 300, 100), Duration::ZERO);
        assert_eq!(rack.reo_wnd(min, srtt, true, 0, 100), Duration::ZERO);
    }

    #[test]
    fn tlp_ack_interpretation() {
        let mut rack = Rack::new(1000);
        rack.start_tlp(2000, true);
        assert_eq!(rack.on_tlp_ack(1500, true, false), TlpOutcome::Pending);
        assert_eq!(
            rack.on_tlp_ack(2000, true, false),
            TlpOutcome::Pending,
            "ambiguous: wait"
        );
        assert_eq!(rack.on_tlp_ack(2100, true, false), TlpOutcome::Loss);
        rack.start_tlp(2000, true);
        rack.on_delivery(Instant::now(), None, false, true, 1000, 1500);
        assert_eq!(
            rack.on_tlp_ack(2100, true, false),
            TlpOutcome::Done,
            "DSACK: both copies arrived"
        );
        rack.start_tlp(2000, false);
        assert_eq!(
            rack.on_tlp_ack(2100, true, false),
            TlpOutcome::Done,
            "new-data probe is never a loss"
        );
    }

    #[test]
    fn fifo_growth_is_funded_before_retransmission_and_refunded_after_storage_drop() {
        let budget = crate::MemoryBudget::new(64 * 1024);
        let pool = super::super::ring::Pool::with_limits(0, 0)
            .with_budget(Some(budget.clone()))
            .with_index_accounting();
        let mut rack = Rack::new(1000);
        let now = Instant::now();
        assert!(rack.ensure_room(&pool, FIFO_FLOOR));
        for end in 0..FIFO_FLOOR {
            rack.on_retransmit(end as u32, now);
        }
        assert_eq!(budget.used(), 0, "fixed FIFO floor is in stack overhead");
        let held = budget.reserve(budget.limit()).unwrap();
        assert!(!rack.ensure_room(&pool, 1));
        assert_eq!(rack.pending_retransmits(), FIFO_FLOOR);
        drop(held);
        assert!(rack.ensure_room(&pool, 1));
        rack.on_retransmit(100, now);
        assert!(budget.used() >= FIFO_FLOOR * std::mem::size_of::<Retransmit>());
        rack.trim(99);
        assert!(
            budget.used() != 0,
            "a partially drained backing retains its charge"
        );
        rack.trim(100);
        assert_eq!(budget.used(), 0);
    }
}
