//! Token-bucket pacer in the style of quinn's `pacing.rs`, with an integer rate.
//!
//! Sending is smoothed at `gain * cwnd / srtt`. The bucket holds a burst: 10 segments, but never
//! more than 2 ms worth of traffic at the current rate, and never less than one segment so that a
//! full bucket always admits a packet (the time cap wins over the segment target, as in quinn).

use std::time::{Duration, Instant};

pub const BURST_SEGMENTS: u64 = 10;
const BURST_TIME: Duration = Duration::from_millis(2);

pub struct Pacer {
    tokens: u64,
    last: Instant,
}

impl Pacer {
    pub fn new(now: Instant) -> Pacer {
        Pacer {
            tokens: u64::MAX,
            last: now,
        }
    }

    /// Bytes per second for `cwnd` over `srtt` scaled by `gain`; `None` before an RTT is known.
    pub fn rate(cwnd: u32, srtt: Option<Duration>, gain: (u32, u32)) -> Option<u64> {
        let srtt_ns = srtt?.as_nanos().max(1);
        let bytes_per_s =
            u128::from(cwnd) * u128::from(gain.0) * 1_000_000_000 / (srtt_ns * u128::from(gain.1));
        Some(bytes_per_s.clamp(1, u128::from(u64::MAX)) as u64)
    }

    fn capacity(rate: u64, mss: u32, burst: u64) -> u64 {
        let by_time = (u128::from(rate) * BURST_TIME.as_nanos() / 1_000_000_000) as u64;
        (burst * u64::from(mss)).min(by_time).max(u64::from(mss))
    }

    /// Tokens in the bucket as of the last `check`.
    pub fn tokens(&self) -> u64 {
        self.tokens
    }

    /// `None` if `bytes` may leave now; otherwise when enough tokens will have accumulated. The
    /// bucket holds `burst` segments (TSO raises it from [`BURST_SEGMENTS`]), never more than 2 ms
    /// of traffic.
    pub fn check(
        &mut self,
        now: Instant,
        bytes: u32,
        rate: u64,
        mss: u32,
        burst: u64,
    ) -> Option<Instant> {
        let capacity = Self::capacity(rate, mss, burst);
        // A fresh or idle bucket starts full; a shrunk window never holds more than its capacity.
        self.tokens = self.tokens.min(capacity);
        let elapsed = now.saturating_duration_since(self.last).as_nanos();
        let added = (elapsed * u128::from(rate) / 1_000_000_000).min(u128::from(capacity)) as u64;
        if added > 0 {
            self.tokens = (self.tokens + added).min(capacity);
            self.last = now;
        }
        let need = u64::from(bytes);
        if self.tokens >= need {
            return None;
        }
        let deficit = u128::from(need - self.tokens);
        // Rounded up so the refill at the deadline is guaranteed to cover the deficit.
        let wait = (deficit * 1_000_000_000).div_ceil(u128::from(rate)).max(1);
        Some(now + Duration::from_nanos(wait.min(u128::from(u64::MAX)) as u64))
    }

    pub fn sent(&mut self, bytes: u32) {
        self.tokens = self.tokens.saturating_sub(u64::from(bytes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: u32 = 1000;

    #[test]
    fn rate_is_gain_times_cwnd_over_srtt_and_absent_without_rtt() {
        let rtt = Some(Duration::from_millis(100));
        assert_eq!(Pacer::rate(100_000, rtt, (2, 1)), Some(2_000_000));
        assert_eq!(Pacer::rate(100_000, rtt, (6, 5)), Some(1_200_000));
        assert_eq!(Pacer::rate(100_000, None, (2, 1)), None);
    }

    #[test]
    fn burst_is_ten_segments_unless_two_milliseconds_hold_fewer() {
        let t = Instant::now();
        // 100 MB/s: 2 ms = 200 kB, so the 10-segment target applies.
        let mut p = Pacer::new(t);
        let mut sent = 0;
        while p.check(t, MSS, 100_000_000, MSS, BURST_SEGMENTS).is_none() {
            p.sent(MSS);
            sent += 1;
            assert!(sent < 100);
        }
        assert_eq!(sent, 10);
        // 2.5 MB/s: 2 ms = 5 kB, the time cap wins.
        let mut p = Pacer::new(t);
        let mut sent = 0;
        while p.check(t, MSS, 2_500_000, MSS, BURST_SEGMENTS).is_none() {
            p.sent(MSS);
            sent += 1;
        }
        assert_eq!(sent, 5);
        // A very slow rate still admits one segment per full bucket.
        let mut p = Pacer::new(t);
        assert!(p.check(t, MSS, 1000, MSS, BURST_SEGMENTS).is_none());
        p.sent(MSS);
        assert!(p.check(t, MSS, 1000, MSS, BURST_SEGMENTS).is_some());
    }

    #[test]
    fn deadline_is_when_the_deficit_has_been_refilled_and_it_then_passes() {
        let t = Instant::now();
        let mut p = Pacer::new(t);
        let rate = 1_000_000;
        while p.check(t, MSS, rate, MSS, BURST_SEGMENTS).is_none() {
            p.sent(MSS);
        }
        let at = p.check(t, MSS, rate, MSS, BURST_SEGMENTS).unwrap();
        assert!(at > t);
        assert!(
            p.check(at, MSS, rate, MSS, BURST_SEGMENTS).is_none(),
            "the promised deadline is sufficient"
        );
        p.sent(MSS);
        let next = p.check(at, MSS, rate, MSS, BURST_SEGMENTS).unwrap();
        assert_eq!(
            next.duration_since(at),
            Duration::from_millis(1),
            "1000 B at 1 MB/s"
        );
    }

    #[test]
    fn idle_time_refills_only_one_burst() {
        let t = Instant::now();
        let mut p = Pacer::new(t);
        while p.check(t, MSS, 100_000_000, MSS, BURST_SEGMENTS).is_none() {
            p.sent(MSS);
        }
        let later = t + Duration::from_secs(60);
        let mut n = 0;
        while p
            .check(later, MSS, 100_000_000, MSS, BURST_SEGMENTS)
            .is_none()
        {
            p.sent(MSS);
            n += 1;
        }
        assert_eq!(n, 10);
    }
}
