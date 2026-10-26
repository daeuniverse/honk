//! Congestion-control seam. Packet accounting and loss detection live outside CC.

pub enum Cc {
    Reno(Reno),
}

pub struct Reno {
    cwnd: u32,
    ssthresh: u32,
    credit: u64,
}

impl Cc {
    pub fn new(mss: u32) -> Cc {
        Cc::Reno(Reno {
            cwnd: initial_window(mss),
            ssthresh: u32::MAX,
            credit: 0,
        })
    }

    pub fn cwnd(&self) -> u32 {
        match self {
            Cc::Reno(r) => r.cwnd,
        }
    }
    pub fn ssthresh(&self) -> u32 {
        match self {
            Cc::Reno(r) => r.ssthresh,
        }
    }

    pub fn ack(&mut self, bytes: u32, mss: u32, cwnd_limited: bool, in_recovery: bool) {
        if !cwnd_limited || in_recovery {
            return;
        }
        match self {
            Cc::Reno(r) => {
                if r.cwnd < r.ssthresh {
                    r.cwnd = r.cwnd.saturating_add(bytes.min(2 * mss));
                } else {
                    r.credit += u64::from(bytes) * u64::from(mss);
                    let add = (r.credit / u64::from(r.cwnd.max(1))) as u32;
                    r.credit %= u64::from(r.cwnd.max(1));
                    r.cwnd = r.cwnd.saturating_add(add);
                }
            }
        }
    }

    pub fn loss(&mut self, flight: u32, mss: u32) {
        match self {
            Cc::Reno(r) => {
                r.ssthresh = (flight / 2).max(2 * mss);
                r.cwnd = r.ssthresh;
                r.credit = 0;
            }
        }
    }

    pub fn rto(&mut self, flight: u32, mss: u32, first: bool) {
        if first {
            self.loss(flight, mss);
        }
        match self {
            Cc::Reno(r) => r.cwnd = mss,
        }
    }

    pub fn exit_recovery(&mut self, flight: u32, mss: u32) {
        match self {
            Cc::Reno(r) => r.cwnd = r.ssthresh.min(flight.saturating_add(mss).max(mss)),
        }
    }

    pub fn restart_idle(&mut self, mss: u32) {
        match self {
            Cc::Reno(r) => r.cwnd = r.cwnd.min(initial_window(mss)),
        }
    }
}

pub fn initial_window(mss: u32) -> u32 {
    (10 * mss).min((2 * mss).max(14600))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_start_loss_avoidance() {
        let mut c = Cc::new(1000);
        assert_eq!(c.cwnd(), 10000);
        c.ack(1000, 1000, true, false);
        assert_eq!(c.cwnd(), 11000);
        c.loss(10000, 1000);
        assert_eq!((c.cwnd(), c.ssthresh()), (5000, 5000));
        c.ack(5000, 1000, true, false);
        assert_eq!(c.cwnd(), 6000);
        c.ack(1000, 1000, false, false);
        assert_eq!(c.cwnd(), 6000, "app-limited ACKs cannot grow cwnd");
        c.rto(8000, 1000, true);
        assert_eq!((c.cwnd(), c.ssthresh()), (1000, 4000));
    }
}
