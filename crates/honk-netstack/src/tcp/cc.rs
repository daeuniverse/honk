//! Congestion-control seam. Packet accounting and loss detection live outside CC; a controller
//! only sees ACK, congestion-event and RTO notifications and reports `cwnd` and pacing gain.

use std::time::{Duration, Instant};

use super::cubic::Cubic;

pub enum Cc {
    Cubic(Cubic),
    /// Alternative controller kept behind the seam (and for the reference tests); production
    /// connections run CUBIC like honk's QUIC transports.
    #[allow(dead_code)]
    Reno(Reno),
}

pub struct Reno {
    cwnd: u32,
    ssthresh: u32,
    credit: u64,
}

#[derive(Clone, Copy)]
pub struct Snapshot {
    pub cwnd: u32,
    pub ssthresh: u32,
    pub w_max: u32,
    pub cwnd_prior: u32,
}

/// One ACK as the controller sees it.
pub struct CcAck {
    pub now: Instant,
    /// Bytes newly acknowledged by the cumulative ACK.
    pub bytes: u32,
    pub mss: u32,
    /// The sender used its window: growth is only valid then (RFC 7661).
    pub cwnd_limited: bool,
    pub in_recovery: bool,
    /// Karn-safe RTT sample of this ACK, if any.
    pub rtt: Option<Duration>,
    pub srtt: Duration,
    pub snd_una: u32,
    pub snd_nxt: u32,
}

impl Cc {
    pub fn new(mss: u32) -> Cc {
        Cc::Cubic(Cubic::new(initial_window(mss)))
    }

    #[allow(dead_code)]
    pub fn reno(mss: u32) -> Cc {
        Cc::Reno(Reno {
            cwnd: initial_window(mss),
            ssthresh: u32::MAX,
            credit: 0,
        })
    }

    pub fn cwnd(&self) -> u32 {
        match self {
            Cc::Cubic(c) => c.cwnd(),
            Cc::Reno(r) => r.cwnd,
        }
    }

    pub fn ssthresh(&self) -> u32 {
        match self {
            Cc::Cubic(c) => c.ssthresh(),
            Cc::Reno(r) => r.ssthresh,
        }
    }

    pub fn in_slow_start(&self) -> bool {
        self.cwnd() < self.ssthresh()
    }

    /// Pacing rate as cwnd/SRTT times this ratio: Linux's 2.0 in slow start and 1.2 afterwards.
    pub fn pacing_gain(&self) -> (u32, u32) {
        if self.in_slow_start() { (2, 1) } else { (6, 5) }
    }

    pub fn on_ack(&mut self, ev: &CcAck) {
        match self {
            Cc::Cubic(c) => c.on_ack(ev),
            Cc::Reno(r) => {
                if !ev.cwnd_limited || ev.in_recovery {
                    return;
                }
                if r.cwnd < r.ssthresh {
                    r.cwnd = r.cwnd.saturating_add(ev.bytes.min(2 * ev.mss));
                } else {
                    r.credit += u64::from(ev.bytes) * u64::from(ev.mss);
                    let add = (r.credit / u64::from(r.cwnd.max(1))) as u32;
                    r.credit %= u64::from(r.cwnd.max(1));
                    r.cwnd = r.cwnd.saturating_add(add);
                }
            }
        }
    }

    /// A congestion event (one per loss episode): `ssthresh` and `cwnd` drop to the new target.
    pub fn on_loss(&mut self, mss: u32) {
        match self {
            Cc::Cubic(c) => c.on_loss(mss),
            Cc::Reno(r) => {
                r.ssthresh = (r.cwnd / 2).max(2 * mss);
                r.cwnd = r.ssthresh;
                r.credit = 0;
            }
        }
    }

    /// `first` is the first timeout of the episode; later ones keep the threshold.
    pub fn on_rto(&mut self, mss: u32, first: bool) {
        match self {
            Cc::Cubic(c) => c.on_rto(mss, first),
            Cc::Reno(r) => {
                if first {
                    r.ssthresh = (r.cwnd / 2).max(2 * mss);
                }
                r.cwnd = mss;
                r.credit = 0;
            }
        }
    }

    pub fn restart_idle(&mut self, mss: u32) {
        match self {
            Cc::Cubic(c) => c.restart_idle(initial_window(mss)),
            Cc::Reno(r) => r.cwnd = r.cwnd.min(initial_window(mss)),
        }
    }

    /// What a spurious congestion event must give back.
    pub fn snapshot(&self) -> Snapshot {
        match self {
            Cc::Cubic(c) => c.snapshot(),
            Cc::Reno(r) => Snapshot {
                cwnd: r.cwnd,
                ssthresh: r.ssthresh,
                w_max: 0,
                cwnd_prior: 0,
            },
        }
    }

    /// Spurious congestion event: back to the state saved before it (RFC 4015 §3.2), but never
    /// below what slow start has regrown meanwhile.
    pub fn undo(&mut self, saved: Snapshot) {
        match self {
            Cc::Cubic(c) => c.restore(saved),
            Cc::Reno(r) => {
                r.cwnd = r.cwnd.max(saved.cwnd);
                r.ssthresh = saved.ssthresh;
                r.credit = 0;
            }
        }
    }
}

pub fn initial_window(mss: u32) -> u32 {
    (10 * mss).min((2 * mss).max(14600))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(bytes: u32, limited: bool) -> CcAck {
        CcAck {
            now: Instant::now(),
            bytes,
            mss: 1000,
            cwnd_limited: limited,
            in_recovery: false,
            rtt: None,
            srtt: Duration::from_millis(50),
            snd_una: 0,
            snd_nxt: 0,
        }
    }

    #[test]
    fn reno_slow_start_loss_avoidance() {
        let mut c = Cc::reno(1000);
        assert_eq!(c.cwnd(), 10000);
        c.on_ack(&ack(1000, true));
        assert_eq!(c.cwnd(), 11000);
        c.on_loss(1000);
        assert_eq!((c.cwnd(), c.ssthresh()), (5500, 5500));
        c.on_ack(&ack(5500, true));
        assert_eq!(c.cwnd(), 6500);
        c.on_ack(&ack(1000, false));
        assert_eq!(c.cwnd(), 6500, "app-limited ACKs cannot grow cwnd");
        c.on_rto(1000, true);
        assert_eq!((c.cwnd(), c.ssthresh()), (1000, 3250));
    }

    #[test]
    fn undo_restores_the_saved_controller_but_keeps_regrown_window() {
        let mut c = Cc::new(1000);
        let (cwnd, ssthresh) = (c.cwnd(), c.ssthresh());
        let saved = c.snapshot();
        c.on_loss(1000);
        assert!(c.cwnd() < cwnd);
        c.undo(saved);
        assert_eq!((c.cwnd(), c.ssthresh()), (cwnd, ssthresh));
        c.on_rto(1000, true);
        assert_eq!(c.cwnd(), 1000);
        c.undo(saved);
        assert_eq!(c.cwnd(), cwnd);
        // Window regrown beyond the saved one while the loss was believed stays.
        let mut c = Cc::new(1000);
        c.on_ack(&ack(1000, true));
        let grown = c.cwnd();
        c.undo(saved);
        assert_eq!(c.cwnd(), grown);
    }

    #[test]
    fn pacing_gain_follows_slow_start() {
        let mut c = Cc::new(1000);
        assert_eq!(c.pacing_gain(), (2, 1));
        c.on_loss(1000);
        assert_eq!(c.pacing_gain(), (6, 5));
    }
}
