//! RFC 6298 estimator; the intentional 200 ms lower bound matches Linux.

use std::time::Duration;

pub const MIN_RTO: Duration = Duration::from_millis(200);
pub const MAX_RTO: Duration = Duration::from_secs(120);

/// Microseconds in 32 bits (71 minutes of range), 0 meaning "no sample yet": a flow carries this
/// for its whole life, so it is kept small.
pub struct Rtt {
    srtt_us: u32,
    rttvar_us: u32,
    min_rtt_us: u32,
    rto_us: u32,
    pub backoff: u8,
}

impl Default for Rtt {
    fn default() -> Self {
        Self {
            srtt_us: 0,
            rttvar_us: 0,
            min_rtt_us: 0,
            rto_us: 1_000_000,
            backoff: 0,
        }
    }
}

impl Rtt {
    pub fn sample(&mut self, sample: Duration) {
        let us = sample.as_micros().clamp(1, u128::from(u32::MAX)) as u32;
        self.min_rtt_us = if self.min_rtt_us == 0 {
            us
        } else {
            self.min_rtt_us.min(us)
        };
        if self.srtt_us == 0 {
            self.srtt_us = us;
            self.rttvar_us = us / 2;
        } else {
            let srtt = u64::from(self.srtt_us);
            self.rttvar_us =
                ((3 * u64::from(self.rttvar_us) + srtt.abs_diff(u64::from(us))) / 4) as u32;
            self.srtt_us = ((7 * srtt + u64::from(us)) / 8) as u32;
        }
        let rto = u64::from(self.srtt_us) + (4 * u64::from(self.rttvar_us)).max(1000);
        self.rto_us = rto.clamp(MIN_RTO.as_micros() as u64, MAX_RTO.as_micros() as u64) as u32;
        self.backoff = 0;
    }

    pub fn rto(&self) -> Duration {
        Duration::from_micros(u64::from(self.rto_us))
            .saturating_mul(1u32 << self.backoff.min(16))
            .min(MAX_RTO)
    }

    pub fn timeout(&mut self) {
        self.backoff = self.backoff.saturating_add(1);
    }

    pub fn srtt(&self) -> Option<Duration> {
        (self.srtt_us != 0).then(|| Duration::from_micros(u64::from(self.srtt_us)))
    }

    pub fn min_rtt(&self) -> Option<Duration> {
        (self.min_rtt_us != 0).then(|| Duration::from_micros(u64::from(self.min_rtt_us)))
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
