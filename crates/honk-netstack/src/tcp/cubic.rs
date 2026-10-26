//! CUBIC (RFC 9438) in fixed point with HyStart++ (RFC 9406) slow start.
//!
//! Windows in the cubic equations are in segments; only time needs fractions, kept as seconds
//! with 10 fractional bits (Linux's resolution). No floating point: the constants are exact
//! rationals (beta 7/10, C 2/5, alpha 9/17).

use std::time::{Duration, Instant};

use super::cc::{CcAck, Snapshot};
use super::seq;

const FRAC: u32 = 10;
/// `K^3 = (w_max - cwnd) / C`; with `K` in Q10 that is `(w_max - cwnd) * 5/2 * 2^30`.
const K_CUBE_PER_SEGMENT: u128 = (5u128 << (3 * FRAC)) / 2;

/// RFC 9406 §4.2.
const MIN_RTT_THRESH_US: u32 = 4_000;
const MAX_RTT_THRESH_US: u32 = 16_000;
const MIN_RTT_DIVISOR: u32 = 8;
const N_RTT_SAMPLE: u8 = 8;
const CSS_GROWTH_DIVISOR: u32 = 4;
const CSS_ROUNDS: u8 = 5;
/// Linux `hystart_low_window`: below this, RTT jitter outweighs queueing.
const HYSTART_LOW_WINDOW_SEGMENTS: u32 = 16;
/// RFC 9406 `L`: slow-start growth per ACK is capped at this many segments.
const SLOW_START_LIMIT: u32 = 8;

pub struct Cubic {
    cwnd: u32,
    ssthresh: u32,
    /// Window (segments) at the last congestion event, after fast convergence.
    w_max: u32,
    /// `K` in Q10 seconds: time for the cubic to climb back to `w_max`.
    k: u32,
    /// Window (segments) before the last reduction; where the Reno-friendly slope flattens.
    cwnd_prior: u32,
    /// Reno-friendly estimate, in segments.
    w_est: u32,
    epoch: Option<Instant>,
    cubic_credit: u32,
    est_credit: u32,
    hystart: HyStart,
}

#[derive(Default)]
struct HyStart {
    window_end: Option<u32>,
    // Microseconds: they only ever compare RTTs, and 32 bits keep the idle flow small.
    last_round_min: Option<u32>,
    current_min: Option<u32>,
    samples: u8,
    css_baseline: Option<u32>,
    css_rounds: u8,
}

fn cbrt(v: u128) -> u64 {
    if v == 0 {
        return 0;
    }
    let mut x = 1u128 << (128 - v.leading_zeros()).div_ceil(3);
    loop {
        let next = (2 * x + v / (x * x)) / 3;
        if next >= x {
            return x as u64;
        }
        x = next;
    }
}

fn q10(d: Duration) -> u64 {
    ((d.as_nanos() << FRAC) / 1_000_000_000).min(u128::from(u64::MAX)) as u64
}

impl Cubic {
    pub fn new(cwnd: u32) -> Cubic {
        Cubic {
            cwnd,
            ssthresh: u32::MAX,
            w_max: 0,
            k: 0,
            cwnd_prior: 0,
            w_est: 0,
            epoch: None,
            cubic_credit: 0,
            est_credit: 0,
            hystart: HyStart::default(),
        }
    }

    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    pub fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            cwnd: self.cwnd,
            ssthresh: self.ssthresh,
            w_max: self.w_max,
            cwnd_prior: self.cwnd_prior,
        }
    }

    pub fn restore(&mut self, s: Snapshot) {
        self.cwnd = self.cwnd.max(s.cwnd);
        self.ssthresh = s.ssthresh;
        self.w_max = s.w_max;
        self.cwnd_prior = s.cwnd_prior;
        self.epoch = None;
        self.cubic_credit = 0;
        self.est_credit = 0;
    }

    pub fn restart_idle(&mut self, initial: u32) {
        self.cwnd = self.cwnd.min(initial);
        self.epoch = None;
        // A finished HyStart++ exit must not survive the restart: its stale CSS round count
        // would end the next slow start at the initial window.
        self.hystart = HyStart::default();
    }

    /// W_cubic(t) in segments.
    fn w_cubic(&self, t: u64) -> u32 {
        let diff = u128::from(t.abs_diff(u64::from(self.k)));
        // C * diff^3 / 2^30 with C = 2/5.
        let delta =
            ((2 * diff * diff * diff) / (5u128 << (3 * FRAC))).min(u128::from(u32::MAX)) as u32;
        if t < u64::from(self.k) {
            self.w_max.saturating_sub(delta)
        } else {
            self.w_max.saturating_add(delta)
        }
    }

    pub fn on_ack(&mut self, ev: &CcAck) {
        if self.cwnd < self.ssthresh {
            self.hystart_ack(ev);
        }
        if !ev.cwnd_limited || ev.in_recovery || ev.bytes == 0 {
            return;
        }
        if self.cwnd < self.ssthresh {
            let mut inc = ev.bytes.min(SLOW_START_LIMIT * ev.mss);
            if self.hystart.css_baseline.is_some() {
                inc = (inc / CSS_GROWTH_DIVISOR).max(1);
            }
            self.cwnd = self.cwnd.saturating_add(inc);
            if self.cwnd < self.ssthresh {
                return;
            }
            // Bytes beyond ssthresh belong to congestion avoidance.
            let over = self.cwnd - self.ssthresh;
            self.cwnd = self.ssthresh;
            if over == 0 {
                return;
            }
            self.congestion_avoidance(ev, over);
            return;
        }
        self.congestion_avoidance(ev, ev.bytes);
    }

    fn congestion_avoidance(&mut self, ev: &CcAck, bytes: u32) {
        let mss = ev.mss.max(1);
        let cwnd_seg = (self.cwnd / mss).max(1);
        let epoch = match self.epoch {
            Some(e) => e,
            None => {
                if self.w_max > cwnd_seg {
                    self.k = cbrt(u128::from(self.w_max - cwnd_seg) * K_CUBE_PER_SEGMENT)
                        .min(u64::from(u32::MAX)) as u32;
                } else {
                    // Slow start ended without loss (HyStart++): the plateau is the current window
                    // (RFC 9438 §4.10).
                    self.k = 0;
                    self.w_max = cwnd_seg;
                    self.cwnd_prior = cwnd_seg;
                }
                self.w_est = cwnd_seg;
                self.epoch = Some(ev.now);
                ev.now
            }
        };
        let t = q10(ev.now.saturating_duration_since(epoch)).saturating_add(q10(ev.srtt));
        let target = self
            .w_cubic(t)
            .clamp(cwnd_seg, cwnd_seg.saturating_add(cwnd_seg / 2));
        self.cubic_credit = self.cubic_credit.saturating_add(bytes);
        let mut cubic_seg = cwnd_seg;
        if target > cwnd_seg {
            let per_segment = (cwnd_seg * mss / (target - cwnd_seg)).max(1);
            let inc = (self.cubic_credit / per_segment).min(target - cwnd_seg);
            cubic_seg += inc;
            self.cubic_credit -= (inc * per_segment).min(self.cubic_credit);
        }
        // Reno-friendly region: W_est grows by alpha segments per window, 1 once it has caught up
        // with the pre-reduction window.
        self.est_credit = self.est_credit.saturating_add(bytes);
        let window = if self.w_est >= self.cwnd_prior {
            self.cwnd
        } else {
            self.cwnd / 9 * 17
        }
        .max(1);
        self.w_est = self.w_est.saturating_add(self.est_credit / window);
        self.est_credit %= window;
        // Never below the window already held: `on_loss` leaves `cwnd` between whole segments.
        self.cwnd = cubic_seg.max(self.w_est).saturating_mul(mss).max(self.cwnd);
    }

    /// HyStart++ (RFC 9406): leave slow start early when RTT inflation shows a queue building.
    fn hystart_ack(&mut self, ev: &CcAck) {
        let h = &mut self.hystart;
        if h.window_end.is_none_or(|end| seq::ge(ev.snd_una, end)) {
            // A round ends when the data outstanding at its start has been acknowledged.
            if h.window_end.is_some() {
                h.last_round_min = h.current_min.or(h.last_round_min);
                if h.css_baseline.is_some() {
                    h.css_rounds += 1;
                }
            }
            h.window_end = Some(ev.snd_nxt);
            h.current_min = None;
            h.samples = 0;
            if h.css_rounds >= CSS_ROUNDS {
                // Queue confirmed: slow start is over without having lost a packet.
                self.ssthresh = self.cwnd;
                h.css_baseline = None;
                h.css_rounds = 0;
                return;
            }
        }
        if let Some(rtt) = ev
            .rtt
            .map(|d| d.as_micros().min(u128::from(u32::MAX)) as u32)
        {
            h.current_min = Some(h.current_min.map_or(rtt, |m| m.min(rtt)));
            h.samples = h.samples.saturating_add(1);
        }
        let (Some(cur), true) = (h.current_min, h.samples >= N_RTT_SAMPLE) else {
            return;
        };
        if let Some(base) = h.css_baseline {
            if cur < base {
                // The inflation was transient: back to regular slow start.
                h.css_baseline = None;
                h.css_rounds = 0;
            }
        } else if let Some(last) = h.last_round_min
            && self.cwnd >= HYSTART_LOW_WINDOW_SEGMENTS * ev.mss
        {
            let eta = (last / MIN_RTT_DIVISOR).clamp(MIN_RTT_THRESH_US, MAX_RTT_THRESH_US);
            if cur >= last.saturating_add(eta) {
                h.css_baseline = Some(cur);
                h.css_rounds = 0;
            }
        }
    }

    pub fn on_loss(&mut self, mss: u32) {
        let seg = (self.cwnd / mss.max(1)).max(1);
        self.cwnd_prior = seg;
        // Fast convergence (RFC 9438 §4.7): a flow that lost below its old peak yields room.
        self.w_max = if seg < self.w_max { seg * 17 / 20 } else { seg };
        self.ssthresh = (self.cwnd / 10 * 7).max(2 * mss);
        self.cwnd = self.ssthresh;
        self.epoch = None;
        self.cubic_credit = 0;
        self.est_credit = 0;
        self.hystart = HyStart::default();
    }

    pub fn on_rto(&mut self, mss: u32, first: bool) {
        if first {
            self.on_loss(mss);
        }
        self.cwnd = mss;
        self.epoch = None;
        self.hystart = HyStart::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: u32 = 1000;

    fn ack(now: Instant, bytes: u32, rtt: Option<Duration>, una: u32, nxt: u32) -> CcAck {
        CcAck {
            now,
            bytes,
            mss: MSS,
            cwnd_limited: true,
            in_recovery: false,
            rtt,
            srtt: rtt.unwrap_or(Duration::from_millis(50)),
            snd_una: una,
            snd_nxt: nxt,
        }
    }

    /// One window of ACKs, each reporting `rtt`, with a full window of new data in flight.
    fn round(c: &mut Cubic, now: Instant, rtt: Duration, una: &mut u32) {
        let end = *una + c.cwnd();
        while *una < end {
            *una += MSS;
            c.on_ack(&ack(now, MSS, Some(rtt), *una, *una + c.cwnd()));
        }
    }

    #[test]
    fn cube_root_and_curve_follow_rfc_9438() {
        assert_eq!(cbrt(27 << 30), 3 << 10);
        assert_eq!(cbrt(1_000_000_000), 1000);
        let mut c = Cubic::new(100 * MSS);
        c.on_loss(MSS); // w_max 100, cwnd 70 segments
        assert_eq!((c.w_max, c.cwnd), (100, 70_000));
        // K = cbrt((100 - 70) / 0.4) = 4.217 s.
        c.k = cbrt(30 * K_CUBE_PER_SEGMENT) as u32;
        assert!((4300..4330).contains(&c.k), "K = {}", c.k);
        assert!(
            (c.w_cubic(0) as i64 - 70).abs() <= 1,
            "the curve starts at beta * w_max"
        );
        assert_eq!(c.w_cubic(u64::from(c.k)), 100, "and plateaus at w_max");
        assert!(
            (c.w_cubic(2 * u64::from(c.k)) as i64 - 130).abs() <= 1,
            "convex probing mirrors it"
        );
    }

    #[test]
    fn fast_convergence_shrinks_w_max_when_losing_below_the_previous_peak() {
        let mut c = Cubic::new(80 * MSS);
        c.w_max = 100;
        c.on_loss(MSS);
        assert_eq!(c.w_max, 68, "80 * (1 + 0.7) / 2");
        let mut c = Cubic::new(120 * MSS);
        c.w_max = 100;
        c.on_loss(MSS);
        assert_eq!(c.w_max, 120);
    }

    #[test]
    fn window_returns_to_w_max_after_k_and_grows_cubically() {
        let mut c = Cubic::new(100 * MSS);
        c.on_loss(MSS);
        let t0 = Instant::now();
        let rtt = Duration::from_millis(50);
        let mut nxt = 0u32;
        let mut reached = None;
        for step in 0..1000u32 {
            let now = t0 + rtt * step;
            // One RTT worth of ACKs per step.
            for _ in 0..(c.cwnd() / MSS) {
                nxt += MSS;
                c.on_ack(&ack(now, MSS, Some(rtt), nxt - MSS, nxt));
            }
            if reached.is_none() && c.cwnd() >= 100 * MSS {
                reached = Some(step);
            }
            if reached.is_some_and(|r| step > r + 40) {
                break;
            }
        }
        let r = reached.expect("window recovers to w_max");
        // K is ~4.2 s = 84 RTTs of 50 ms, but the Reno-friendly region may get there sooner and
        // the 1.5x target clamp can only slow it.
        assert!((20..=90).contains(&r), "recovered after {r} RTTs");
        assert!(c.cwnd() > 100 * MSS, "keeps probing beyond the old peak");
    }

    #[test]
    fn reno_friendly_region_never_grows_slower_than_reno() {
        // Small window, tiny RTT: the cubic curve is flat, so W_est must carry the window.
        let mut c = Cubic::new(20 * MSS);
        c.on_loss(MSS);
        let start = c.cwnd();
        let t0 = Instant::now();
        let mut nxt = 0;
        for round in 0..30u32 {
            let now = t0 + Duration::from_millis(u64::from(round));
            for _ in 0..(c.cwnd() / MSS) {
                nxt += MSS;
                c.on_ack(&ack(now, MSS, None, nxt - MSS, nxt));
            }
        }
        assert!(c.cwnd() >= start + 12 * MSS, "{} -> {}", start, c.cwnd());
    }

    #[test]
    fn hystart_enters_css_on_rtt_inflation_then_leaves_slow_start_without_loss() {
        let mut c = Cubic::new(32 * MSS);
        let t0 = Instant::now();
        let base = Duration::from_millis(80);
        let mut una = 0;
        let mut cwnds = vec![c.cwnd()];
        for r in 0..3u32 {
            round(&mut c, t0 + base * r, base, &mut una);
            cwnds.push(c.cwnd());
        }
        assert_eq!(c.ssthresh(), u32::MAX, "no inflation, no exit");
        // RTT inflates by more than eta (10 ms).
        let inflated = base + Duration::from_millis(12);
        for r in 3..14u32 {
            round(&mut c, t0 + base * r, inflated, &mut una);
            cwnds.push(c.cwnd());
            if c.ssthresh() != u32::MAX {
                break;
            }
        }
        assert_ne!(
            c.ssthresh(),
            u32::MAX,
            "left slow start after {CSS_ROUNDS} CSS rounds"
        );
        assert!(
            c.cwnd().abs_diff(c.ssthresh()) <= 2 * MSS,
            "ssthresh is the window at exit"
        );
        let growth: Vec<f64> = cwnds
            .windows(2)
            .map(|w| f64::from(w[1]) / f64::from(w[0]))
            .collect();
        assert!(
            growth[..3].iter().all(|g| *g > 1.9),
            "slow start doubles: {growth:?}"
        );
        assert!(
            growth[4..].iter().all(|g| *g < 1.35),
            "CSS grows by a quarter, not double: {growth:?}"
        );
    }

    #[test]
    fn hystart_resumes_slow_start_if_inflation_was_transient() {
        let mut c = Cubic::new(32 * MSS);
        let t0 = Instant::now();
        let base = Duration::from_millis(80);
        let mut una = 0;
        for (r, extra) in [0, 0, 0, 12, 0].into_iter().enumerate() {
            round(
                &mut c,
                t0 + base * r as u32,
                base + Duration::from_millis(extra),
                &mut una,
            );
            if extra == 12 {
                assert!(c.hystart.css_baseline.is_some(), "inflation detected");
            }
        }
        assert_eq!(c.ssthresh(), u32::MAX);
        assert!(
            c.hystart.css_baseline.is_none(),
            "RTT fell back below the CSS baseline"
        );
    }

    #[test]
    fn rto_collapses_to_one_segment_and_keeps_the_first_threshold() {
        let mut c = Cubic::new(50 * MSS);
        c.on_rto(MSS, true);
        assert_eq!((c.cwnd(), c.ssthresh()), (MSS, 35 * MSS));
        c.on_rto(MSS, false);
        assert_eq!((c.cwnd(), c.ssthresh()), (MSS, 35 * MSS));
    }

    #[test]
    fn idle_restart_after_a_hystart_exit_keeps_slow_start() {
        let mut c = Cubic::new(32 * MSS);
        let t0 = Instant::now();
        let base = Duration::from_millis(80);
        let mut una = 0;
        for r in 0..3u32 {
            round(&mut c, t0 + base * r, base, &mut una);
        }
        let inflated = base + Duration::from_millis(12);
        for r in 3..14u32 {
            round(&mut c, t0 + base * r, inflated, &mut una);
            if c.ssthresh() != u32::MAX {
                break;
            }
        }
        assert_ne!(c.ssthresh(), u32::MAX, "HyStart++ ended slow start");
        c.restart_idle(10 * MSS);
        let now = t0 + base * 20;
        c.on_ack(&ack(now, MSS, Some(base), una + MSS, una + 11 * MSS));
        assert!(
            c.ssthresh() > 10 * MSS,
            "slow start must resume towards the old exit point, not end at the initial window"
        );
    }

    #[test]
    fn congestion_avoidance_never_shrinks_the_window_below_the_reduced_threshold() {
        let mut c = Cubic::new(100 * MSS + 500);
        c.on_loss(MSS); // ssthresh 70350: between whole segments
        let t0 = Instant::now();
        c.on_ack(&ack(
            t0,
            MSS,
            Some(Duration::from_millis(50)),
            MSS,
            70 * MSS,
        ));
        assert!(
            c.cwnd() >= c.ssthresh(),
            "{} < {}: the flow would re-enter slow start",
            c.cwnd(),
            c.ssthresh()
        );
    }
}
