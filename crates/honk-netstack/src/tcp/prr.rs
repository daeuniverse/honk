//! Proportional Rate Reduction (RFC 6937, SSRB variant) as run by Linux.

#[derive(Default, Clone, Copy)]
pub struct Prr {
    delivered: u64,
    out: u64,
    /// Flight size when the recovery began.
    recover_fs: u64,
    /// Bytes that may still be sent on the strength of the last ACK.
    allow: u32,
}

impl Prr {
    pub fn new(recover_fs: u32, mss: u32) -> Prr {
        Prr {
            recover_fs: u64::from(recover_fs.max(1)),
            // The fast retransmit itself is always allowed.
            allow: mss,
            ..Prr::default()
        }
    }

    pub fn allow(&self) -> u32 {
        self.allow
    }

    pub fn sent(&mut self, n: u32) {
        self.out += u64::from(n);
        self.allow = self.allow.saturating_sub(n);
    }

    /// Recomputes the allowance after an ACK delivered `delivered` bytes and left `pipe` in flight.
    pub fn on_ack(&mut self, delivered: u32, pipe: u32, ssthresh: u32, mss: u32) {
        self.delivered += u64::from(delivered);
        let sndcnt = if pipe > ssthresh {
            // Proportional part: spread the reduction over the delivered data.
            (self.delivered * u64::from(ssthresh))
                .div_ceil(self.recover_fs)
                .saturating_sub(self.out)
        } else {
            // Slow-start reduction bound: catch up to ssthresh, but no faster than one more
            // segment than what was just delivered.
            let limit = self
                .delivered
                .saturating_sub(self.out)
                .max(u64::from(delivered))
                + u64::from(mss);
            limit.min(u64::from(ssthresh - pipe))
        };
        // Always allow the first retransmission of the episode.
        let floor = if self.out == 0 { u64::from(mss) } else { 0 };
        self.allow = sndcnt.max(floor).min(u64::from(u32::MAX)) as u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proportional_phase_sends_ssthresh_over_flight_per_delivered_byte() {
        // Flight 20 segments, ssthresh 14: every 10 delivered segments permit 7 sent.
        let mss = 100;
        let mut p = Prr::new(2000, mss);
        assert_eq!(p.allow(), mss, "fast retransmit is immediate");
        p.sent(mss);
        let mut sent = 1;
        // 20 segments in flight, one of them lost; the retransmission restores the pipe.
        let mut pipe = 2000;
        for _ in 0..10 {
            pipe -= mss;
            p.on_ack(mss, pipe, 1400, mss);
            while p.allow() > 0 {
                p.sent(mss);
                pipe += mss;
                sent += 1;
            }
        }
        assert_eq!(
            sent, 7,
            "ssthresh/flight = 7/10 of what was delivered, retransmit included"
        );
        assert_eq!(pipe, 1600, "the pipe is still draining towards ssthresh");
    }

    #[test]
    fn slow_start_phase_rebuilds_the_pipe_without_exceeding_ssthresh() {
        let mss = 100;
        let mut p = Prr::new(2000, mss);
        p.sent(mss);
        // The pipe collapsed far below ssthresh (burst loss): up to delivered + 1 MSS per ACK.
        p.on_ack(200, 300, 1400, mss);
        assert_eq!(
            p.allow(),
            300,
            "max(delivered - out, delivered) + mss, capped by room"
        );
        p.sent(300);
        p.on_ack(0, 1390, 1400, mss);
        assert_eq!(p.allow(), 10, "capped by ssthresh - pipe");
    }
}
