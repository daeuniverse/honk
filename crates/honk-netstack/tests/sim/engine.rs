//! Discrete-event driver for two hosts joined by a pair of links, in virtual time.

use super::link::{Link, LinkConfig};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// Exactly the sans-I/O surface of `honk_netstack::Stack`, plus the application hook.
pub trait Host {
    fn receive(&mut self, now: Instant, packet: &[u8]);
    fn poll_transmit(&mut self, now: Instant, out: &mut [u8]) -> Option<usize>;
    fn poll_timeout(&self) -> Option<Instant>;
    fn handle_timeout(&mut self, now: Instant);
    /// Runs the application after events: read, write, connect, close. Must not transmit.
    fn poll_app(&mut self, now: Instant);
}

/// Packets a host may emit per wakeup. `Packets(0)` suppresses pulls, not ingress, application
/// work or future timers; raising the budget resumes the same host without resetting it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PullBudget {
    Unlimited,
    Packets(usize),
}

impl PullBudget {
    fn paused(self) -> bool {
        self == PullBudget::Packets(0)
    }
    fn limit(self) -> usize {
        match self {
            PullBudget::Unlimited => usize::MAX,
            PullBudget::Packets(n) => n,
        }
    }
}

/// Only differences between instants matter to the stacks, so one process-wide origin suffices.
pub fn epoch() -> Instant {
    static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);
    *EPOCH
}

#[derive(Clone, Debug)]
pub struct SimConfig {
    pub seed: u64,
    /// Host A to host B.
    pub a_to_b: LinkConfig,
    pub b_to_a: LinkConfig,
    /// Size of the `out` buffer handed to `poll_transmit` (the inner IP MTU).
    pub mtu: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Stopped,
    Deadline,
}

pub struct Sim<A: Host, B: Host> {
    pub a: A,
    pub b: B,
    pub a_to_b: Link,
    pub b_to_a: Link,
    pub budget_a: PullBudget,
    pub budget_b: PullBudget,
    now: Instant,
    buf: Vec<u8>,
}

/// More settle passes at one instant than any sane stack needs: a host whose `poll_timeout`
/// stays due after `handle_timeout`, or two hosts answering each other over a zero-delay link.
const SETTLE_LIMIT: u32 = 1_000_000;

impl<A: Host, B: Host> Sim<A, B> {
    pub fn new(cfg: &SimConfig, a: A, b: B) -> Self {
        // Distinct streams per direction so changing one link's model leaves the other's draws alone.
        let seed = |salt: u64| super::rng::mix(cfg.seed ^ salt);
        Sim {
            a,
            b,
            a_to_b: Link::new(cfg.a_to_b.clone(), seed(1)),
            b_to_a: Link::new(cfg.b_to_a.clone(), seed(2)),
            budget_a: PullBudget::Unlimited,
            budget_b: PullBudget::Unlimited,
            now: epoch(),
            buf: vec![0; cfg.mtu],
        }
    }

    pub fn now(&self) -> Instant {
        self.now
    }

    pub fn elapsed(&self) -> Duration {
        self.now - epoch()
    }

    /// Runs until `stop` holds (checked once the current instant is settled) or `deadline` passes.
    pub fn run(&mut self, deadline: Instant, mut stop: impl FnMut(&Self) -> bool) -> Outcome {
        loop {
            self.settle();
            if stop(self) {
                return Outcome::Stopped;
            }
            match self.next_event() {
                Some(t) if t <= deadline => self.now = t.max(self.now),
                _ => {
                    self.now = self.now.max(deadline);
                    return Outcome::Deadline;
                }
            }
        }
    }

    fn next_event(&self) -> Option<Instant> {
        // smoltcp also uses an overdue poll timeout to mean blocked egress. A zero pull budget
        // cannot resolve that work: do not spin on it, but still visit future timer deadlines.
        let timeout =
            |h: &dyn Host, b: PullBudget| h.poll_timeout().filter(|&t| !b.paused() || t > self.now);
        [
            self.a_to_b.next_arrival(),
            self.b_to_a.next_arrival(),
            timeout(&self.a, self.budget_a),
            timeout(&self.b, self.budget_b),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Processes everything due at `now` until nothing changes. All packets of a pass reach their
    /// host with the same `now`, which is the batch ingress time the design requires.
    fn settle(&mut self) {
        let now = self.now;
        for pass in 0.. {
            assert!(
                pass < SETTLE_LIMIT,
                "livelock at +{:?}: a host keeps reporting due work (poll_timeout() <= now after handle_timeout)",
                self.elapsed()
            );
            let mut progress = false;
            while let Some(p) = self.a_to_b.pop_due(now) {
                self.b.receive(now, &p);
                progress = true;
            }
            while let Some(p) = self.b_to_a.pop_due(now) {
                self.a.receive(now, &p);
                progress = true;
            }
            progress |= service(
                &mut self.a,
                self.budget_a,
                now,
                &mut self.buf,
                &mut self.a_to_b,
            );
            progress |= service(
                &mut self.b,
                self.budget_b,
                now,
                &mut self.buf,
                &mut self.b_to_a,
            );
            if !progress {
                return;
            }
        }
    }
}

/// One owner wakeup: due timer, application, then up to the budget of pulled packets.
fn service(
    host: &mut dyn Host,
    budget: PullBudget,
    now: Instant,
    buf: &mut [u8],
    tx: &mut Link,
) -> bool {
    let mut progress = false;
    if host.poll_timeout().is_some_and(|t| t <= now) {
        host.handle_timeout(now);
        progress = !budget.paused();
    }
    host.poll_app(now);
    for _ in 0..budget.limit() {
        let Some(n) = host.poll_transmit(now, buf) else {
            break;
        };
        assert!(
            n <= buf.len(),
            "poll_transmit reported {n} bytes for a {} byte buffer",
            buf.len()
        );
        tx.send(now, &buf[..n]);
        progress = true;
    }
    progress
}
