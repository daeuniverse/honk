//! One direction of the simulated path. The explicit order is iid/Gilbert-Elliott loss,
//! duplication, rate limiting with a packet FIFO/drop-tail byte cap, then propagation delay,
//! jitter and reorder hold. Both copies consume bandwidth; propagation is outside the queue cap.

use super::rng::Rng;
use super::wire::{WireStats, WireTracker};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, VecDeque};
use std::time::{Duration, Instant};

/// Two-state burst-loss model; the state advances once per packet.
#[derive(Clone, Copy, Debug)]
pub struct GilbertElliott {
    pub p_good_to_bad: f64,
    pub p_bad_to_good: f64,
    pub loss_good: f64,
    pub loss_bad: f64,
}

#[derive(Clone, Debug)]
pub struct LinkConfig {
    /// Propagation delay (one way).
    pub delay: Duration,
    /// Extra delay drawn uniformly from `[0, jitter]` per packet. Non-zero jitter reorders.
    pub jitter: Duration,
    /// iid loss probability.
    pub loss: f64,
    pub burst: Option<GilbertElliott>,
    /// Probability that a packet is held back by `reorder_hold` (so later packets overtake it).
    pub reorder: f64,
    pub reorder_hold: Duration,
    pub duplicate: f64,
    /// Bottleneck rate over IP bytes (no link-layer overhead). `None` = unlimited.
    pub rate_bps: Option<u64>,
    /// Drop-tail queue size in bytes, counting the packet in service. Only used with `rate_bps`.
    pub queue_bytes: usize,
}

impl LinkConfig {
    pub fn new(delay: Duration) -> Self {
        LinkConfig {
            delay,
            jitter: Duration::ZERO,
            loss: 0.0,
            burst: None,
            reorder: 0.0,
            reorder_hold: Duration::ZERO,
            duplicate: 0.0,
            rate_bps: None,
            queue_bytes: usize::MAX,
        }
    }

    pub fn rate(mut self, bps: u64, queue_bytes: usize) -> Self {
        self.rate_bps = Some(bps);
        self.queue_bytes = queue_bytes;
        self
    }

    pub fn loss(mut self, p: f64) -> Self {
        self.loss = p;
        self
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LinkStats {
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub delivered_packets: u64,
    pub dropped_loss: u64,
    pub dropped_queue: u64,
    pub duplicated: u64,
    pub reordered: u64,
    /// High-water mark of the bottleneck queue, including the packet in service.
    pub max_queue_bytes: usize,
    pub wire: WireStats,
}

struct InFlight {
    at: Instant,
    seq: u64,
    data: Vec<u8>,
}

impl PartialEq for InFlight {
    fn eq(&self, o: &Self) -> bool {
        (self.at, self.seq) == (o.at, o.seq)
    }
}
impl Eq for InFlight {}
impl PartialOrd for InFlight {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for InFlight {
    // Reversed: `BinaryHeap` is a max-heap and the earliest arrival must pop first.
    fn cmp(&self, o: &Self) -> Ordering {
        (o.at, o.seq).cmp(&(self.at, self.seq))
    }
}

pub struct Link {
    cfg: LinkConfig,
    rng: Rng,
    ge_bad: bool,
    departures: VecDeque<(Instant, usize)>,
    queued_bytes: usize,
    heap: BinaryHeap<InFlight>,
    seq: u64,
    wire: WireTracker,
    pub stats: LinkStats,
}

impl Link {
    pub fn new(cfg: LinkConfig, seed: u64) -> Self {
        assert!(cfg.rate_bps.is_none_or(|bps| bps > 0));
        Link {
            cfg,
            rng: Rng::new(seed),
            ge_bad: false,
            departures: VecDeque::new(),
            queued_bytes: 0,
            heap: BinaryHeap::new(),
            seq: 0,
            wire: WireTracker::default(),
            stats: LinkStats::default(),
        }
    }

    pub fn config(&self) -> &LinkConfig {
        &self.cfg
    }

    pub fn stats(&self) -> LinkStats {
        LinkStats {
            wire: self.wire.stats,
            ..self.stats
        }
    }

    /// The sender emitted `pkt` at `now`.
    pub fn send(&mut self, now: Instant, pkt: &[u8]) {
        self.stats.sent_packets += 1;
        self.stats.sent_bytes += pkt.len() as u64;
        self.wire.observe(pkt);

        if self.lost() {
            self.stats.dropped_loss += 1;
            return;
        }
        let duplicate = self.rng.chance(self.cfg.duplicate);
        self.send_copy(now, pkt);
        if duplicate {
            self.stats.duplicated += 1;
            self.send_copy(now, pkt);
        }
    }

    fn send_copy(&mut self, now: Instant, pkt: &[u8]) {
        let departure = match self.cfg.rate_bps {
            None => now,
            Some(bps) => match self.serialize(now, pkt.len(), bps) {
                Some(t) => t,
                None => {
                    self.stats.dropped_queue += 1;
                    return;
                }
            },
        };

        let mut arrival = departure + self.cfg.delay + self.jitter();
        if self.rng.chance(self.cfg.reorder) {
            arrival += self.cfg.reorder_hold;
            self.stats.reordered += 1;
        }
        self.push(arrival, pkt);
    }

    pub fn next_arrival(&self) -> Option<Instant> {
        self.heap.peek().map(|p| p.at)
    }

    /// Pops the earliest packet that has arrived by `now`.
    pub fn pop_due(&mut self, now: Instant) -> Option<Vec<u8>> {
        if self.heap.peek()?.at > now {
            return None;
        }
        self.stats.delivered_packets += 1;
        self.heap.pop().map(|p| p.data)
    }

    fn lost(&mut self) -> bool {
        let mut lost = self.rng.chance(self.cfg.loss);
        if let Some(ge) = self.cfg.burst {
            let flip = if self.ge_bad {
                ge.p_bad_to_good
            } else {
                ge.p_good_to_bad
            };
            if self.rng.chance(flip) {
                self.ge_bad = !self.ge_bad;
            }
            let p = if self.ge_bad {
                ge.loss_bad
            } else {
                ge.loss_good
            };
            // Both draws always happen so the stream does not depend on earlier outcomes.
            lost |= self.rng.chance(p);
        }
        lost
    }

    fn serialize(&mut self, now: Instant, len: usize, bps: u64) -> Option<Instant> {
        while self.departures.front().is_some_and(|&(t, _)| t <= now) {
            self.queued_bytes -= self.departures.pop_front().unwrap().1;
        }
        if len > self.cfg.queue_bytes.saturating_sub(self.queued_bytes) {
            return None;
        }
        self.queued_bytes += len;
        self.stats.max_queue_bytes = self.stats.max_queue_bytes.max(self.queued_bytes);
        let start = self.departures.back().map_or(now, |&(t, _)| t.max(now));
        let service =
            Duration::from_nanos((len as u128 * 8_000_000_000).div_ceil(u128::from(bps)) as u64);
        let done = start + service;
        self.departures.push_back((done, len));
        Some(done)
    }

    fn jitter(&mut self) -> Duration {
        Duration::from_nanos(self.rng.up_to(self.cfg.jitter.as_nanos() as u64))
    }

    fn push(&mut self, at: Instant, pkt: &[u8]) {
        self.seq += 1;
        self.heap.push(InFlight {
            at,
            seq: self.seq,
            data: pkt.to_vec(),
        });
    }
}
