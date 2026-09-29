//! Advisory pressure on one node-to-proxy carrier, never business-flow outcomes.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

pub(crate) mod tcp;

#[cfg(feature = "rprx")]
pub use tcp::RawObserver;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PressureReason {
    Rtt,
    Loss,
    Both,
}

#[derive(Clone, Copy, Debug)]
pub struct TransportPressure {
    pub observed_at: Instant,
    pub reason: PressureReason,
}

#[derive(Debug, Default)]
pub struct TransportQuality {
    enabled: AtomicBool,
    pressure: Mutex<[Option<TransportPressure>; 2]>,
}

tokio::task_local! {
    static CURRENT_QUALITY: Arc<TransportQuality>;
}

impl TransportQuality {
    /// Enable collection only when a Score authority binds this runtime.
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> [Option<TransportPressure>; 2] {
        *self.pressure.lock()
    }

    /// Bind physical construction, not a logical stream's later I/O polls.
    /// Spawned factories must enter this scope using their captured runtime.
    pub async fn scope<F: Future>(self: Arc<Self>, future: F) -> F::Output {
        CURRENT_QUALITY.scope(self, future).await
    }

    pub(crate) fn current() -> Option<Arc<Self>> {
        CURRENT_QUALITY.try_with(Arc::clone).ok()
    }

    pub(crate) fn report(&self, ipv6: bool, reason: PressureReason, now: Instant) {
        if !self.is_enabled() {
            return;
        }
        let mut slots = self.pressure.lock();
        let slot = &mut slots[usize::from(ipv6)];
        if slot.is_some_and(|previous| {
            now.saturating_duration_since(previous.observed_at) < Duration::from_secs(30)
        }) {
            return;
        }
        *slot = Some(TransportPressure {
            observed_at: now,
            reason,
        });
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CarrierSample {
    pub at: Instant,
    pub rtt: Option<Duration>,
    pub acknowledged: Option<u64>,
    pub transmitted: Option<u64>,
    pub lost: Option<u64>,
    pub lost_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub rx_bytes: Option<u64>,
    pub tx_datagrams: Option<u64>,
    pub rx_datagrams: Option<u64>,
}

#[derive(Debug, Default)]
struct Episode {
    suspect: u8,
    normal: u8,
    latched: bool,
}

impl Episode {
    fn observe(&mut self, pressure: Option<bool>) -> bool {
        match pressure {
            None => {
                self.suspect = 0;
                self.normal = 0;
            }
            Some(false) => {
                self.suspect = 0;
                self.normal = (self.normal + 1).min(2);
                if self.normal == 2 {
                    self.latched = false;
                }
            }
            Some(true) => {
                self.normal = 0;
                self.suspect = (self.suspect + 1).min(3);
                if self.suspect == 3 && !self.latched {
                    self.latched = true;
                    return true;
                }
            }
        }
        false
    }
}

#[derive(Debug)]
pub(crate) struct CarrierSampler {
    quality: Arc<TransportQuality>,
    ipv6: bool,
    previous: Option<CarrierSample>,
    baseline: Duration,
    trained: u8,
    rtt: Episode,
    loss: Episode,
}

impl CarrierSampler {
    pub(crate) fn new(quality: Arc<TransportQuality>, ipv6: bool) -> Self {
        Self {
            quality,
            ipv6,
            previous: None,
            baseline: Duration::ZERO,
            trained: 0,
            rtt: Episode::default(),
            loss: Episode::default(),
        }
    }

    pub(crate) fn reset(&mut self) {
        self.previous = None;
        self.baseline = Duration::ZERO;
        self.trained = 0;
        self.rtt = Episode::default();
        self.loss = Episode::default();
    }

    pub(crate) fn observe(&mut self, sample: CarrierSample) {
        if !self.quality.is_enabled() {
            self.reset();
            return;
        }
        let Some(previous) = self.previous else {
            self.previous = Some(sample);
            return;
        };
        let elapsed = sample.at.saturating_duration_since(previous.at);
        if elapsed < Duration::from_secs(1) {
            return;
        }
        let counters = [
            (sample.acknowledged, previous.acknowledged),
            (sample.transmitted, previous.transmitted),
            (sample.lost, previous.lost),
            (sample.lost_bytes, previous.lost_bytes),
            (sample.tx_bytes, previous.tx_bytes),
            (sample.rx_bytes, previous.rx_bytes),
            (sample.tx_datagrams, previous.tx_datagrams),
            (sample.rx_datagrams, previous.rx_datagrams),
        ];
        if elapsed > Duration::from_secs(10)
            || counters
                .iter()
                .any(|(new, old)| new.zip(*old).is_some_and(|(new, old)| new < old))
        {
            self.reset();
            self.previous = Some(sample);
            return;
        }
        self.previous = Some(sample);
        let delta = |new: Option<u64>, old: Option<u64>| {
            new.zip(old).and_then(|(new, old)| new.checked_sub(old))
        };
        let tx = delta(sample.tx_bytes, previous.tx_bytes);
        let rx = delta(sample.rx_bytes, previous.rx_bytes);
        let tx_datagrams = delta(sample.tx_datagrams, previous.tx_datagrams);
        let rx_datagrams = delta(sample.rx_datagrams, previous.rx_datagrams);
        let enough = |tx: Option<u64>, rx: Option<u64>, minimum| {
            tx.is_some_and(|n| n >= minimum)
                || rx.is_some_and(|n| n >= minimum)
                || tx
                    .zip(rx)
                    .is_some_and(|(tx, rx)| tx.saturating_add(rx) >= minimum)
        };
        let active = enough(tx, rx, 4096) || enough(tx_datagrams, rx_datagrams, 32);
        let acknowledged = delta(sample.acknowledged, previous.acknowledged)
            .is_some_and(|acknowledged| acknowledged > 0);
        if !active || !acknowledged {
            self.rtt.observe(None);
            self.loss.observe(None);
            return;
        }

        let rtt_pressure = sample.rtt.filter(|rtt| !rtt.is_zero()).and_then(|rtt| {
            if self.trained < 4 {
                self.baseline = self
                    .baseline
                    .saturating_mul(u32::from(self.trained))
                    .saturating_add(rtt)
                    / u32::from(self.trained + 1);
                self.trained += 1;
                return None;
            }
            let pressure = rtt >= self.baseline.saturating_add(self.baseline / 2)
                && rtt >= self.baseline.saturating_add(Duration::from_millis(20));
            if !pressure && !self.rtt.latched {
                self.baseline = self.baseline.saturating_mul(3).saturating_add(rtt) / 4;
            }
            Some(pressure)
        });
        let sent_payload =
            tx.is_some_and(|tx| tx >= 4096) || tx_datagrams.is_some_and(|tx| tx >= 32);
        let loss_pressure = delta(sample.transmitted, previous.transmitted)
            .zip(delta(sample.lost, previous.lost))
            .zip(delta(sample.lost_bytes, previous.lost_bytes))
            .filter(|((sent, _), _)| sent_payload && *sent >= 32)
            .map(|((sent, lost), bytes)| {
                lost >= 3 && bytes > 0 && u128::from(lost) * 100 >= u128::from(sent) * 5
            });
        let rtt = self.rtt.observe(rtt_pressure);
        let loss = self.loss.observe(loss_pressure);
        let reason = match (rtt, loss) {
            (true, true) => PressureReason::Both,
            (true, false) => PressureReason::Rtt,
            (false, true) => PressureReason::Loss,
            (false, false) => return,
        };
        self.quality.report(self.ipv6, reason, sample.at);
    }
}

#[cfg(test)]
mod tests;
