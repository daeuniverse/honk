//! RFC 6298 estimator; the intentional 200 ms lower bound matches Linux.

use std::time::Duration;

pub const MIN_RTO: Duration = Duration::from_millis(200);
pub const MAX_RTO: Duration = Duration::from_secs(120);

pub struct Rtt {
    pub srtt_us: Option<u64>,
    pub rttvar_us: u64,
    pub min_rtt: Option<Duration>,
    rto: Duration,
    pub backoff: u8,
}

impl Default for Rtt {
    fn default() -> Self {
        Self {
            srtt_us: None,
            rttvar_us: 0,
            min_rtt: None,
            rto: Duration::from_secs(1),
            backoff: 0,
        }
    }
}

impl Rtt {
    pub fn sample(&mut self, sample: Duration) {
        let us = sample.as_micros().min(u64::MAX as u128) as u64;
        let us = us.max(1);
        self.min_rtt = Some(self.min_rtt.map_or(sample, |v| v.min(sample)));
        match self.srtt_us {
            None => {
                self.srtt_us = Some(us);
                self.rttvar_us = us / 2;
            }
            Some(srtt) => {
                self.rttvar_us = (3 * self.rttvar_us + srtt.abs_diff(us)) / 4;
                self.srtt_us = Some((7 * srtt + us) / 8);
            }
        }
        let srtt = self.srtt_us.unwrap_or(us);
        self.rto = Duration::from_micros(srtt.saturating_add((4 * self.rttvar_us).max(1000)))
            .clamp(MIN_RTO, MAX_RTO);
        self.backoff = 0;
    }

    pub fn rto(&self) -> Duration {
        self.rto
            .saturating_mul(1u32 << self.backoff.min(16))
            .min(MAX_RTO)
    }

    pub fn timeout(&mut self) {
        self.backoff = self.backoff.saturating_add(1);
    }

    pub fn srtt(&self) -> Option<Duration> {
        self.srtt_us.map(Duration::from_micros)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6298_and_bounds() {
        let mut r = Rtt::default();
        assert_eq!(r.rto(), Duration::from_secs(1));
        r.sample(Duration::from_millis(100));
        assert_eq!(r.srtt(), Some(Duration::from_millis(100)));
        assert_eq!(r.rto(), Duration::from_millis(300));
        r.sample(Duration::from_millis(100));
        assert_eq!(r.rttvar_us, 37500);
        assert_eq!(r.rto(), Duration::from_millis(250));
        for _ in 0..20 {
            r.sample(Duration::from_millis(5));
        }
        assert_eq!(r.rto(), MIN_RTO);
        r.timeout();
        assert_eq!(r.rto(), Duration::from_millis(400));
        for _ in 0..20 {
            r.timeout();
        }
        assert_eq!(r.rto(), MAX_RTO);
        r.sample(Duration::from_millis(50));
        assert_eq!(r.backoff, 0);
    }
}
