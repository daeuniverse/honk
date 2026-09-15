//! Per-node-per-domain latency and dial-failure tracking.

use super::latencies::{LatencySample, SyncLatencies10};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

pub(crate) const TIMEOUT_LATENCY: Duration = Duration::from_secs(10);

/// Strike cap: repeated failures stop mattering beyond this.
pub(crate) const FAILURE_STRIKES_MAX: u8 = 3;
/// Minimum consecutive real successes to clear any demotion — mirrors the
/// RECOVERY_SUCCESSES_NEEDED liveness hysteresis at ranking level.
pub(crate) const STRIKE_CLEAR_SUCCESSES: u8 = 2;

/// Real-traffic EMA weight: α = 1/8 (self-referential — the probe-target
/// vs real-target RTT distribution mismatch never enters the baseline).
pub(crate) const TRAFFIC_EMA_SHIFT: u32 = 3;
/// Dials before the EMA judges anything.
pub(crate) const TRAFFIC_EMA_WARMUP: u8 = 3;
/// Consecutive slow dials that demote the node.
pub(crate) const SLOW_DIAL_STREAK_MAX: u8 = 3;
/// Absolute slack on top of the relative 2×EMA slow threshold.
pub(crate) const SLOW_DIAL_MARGIN: Duration = Duration::from_millis(500);
/// Absolute slow-threshold floor: a fast node's RTT roughly doubling under
/// incumbency load (e.g. 60→120ms) is normal, not degradation — without the
/// floor `min(2×ema, ema+margin)` collapses to 2×ema and flaps URLTest.
pub(crate) const SLOW_DIAL_FLOOR: Duration = Duration::from_millis(250);

/// Consecutive dial failures that produce one strike — a lone transient
/// failure (the retry race rescues the flow) must not demote the node.
pub(crate) const DIAL_FAILURE_STRIKE_AT: u8 = 2;

/// Verdict of one real dial against the node's own traffic EMA.
pub(crate) enum TrafficVerdict {
    /// EMA still warming up — no judgement made.
    Warmup,
    Fast,
    Slow,
}
#[derive(Default)]
struct FailureState {
    strikes: u8,
    clear_progress: u8,
    dial_fail_streak: u8,
}

impl FailureState {
    fn record_strike(&mut self) {
        self.strikes = self.strikes.saturating_add(1).min(FAILURE_STRIKES_MAX);
        self.clear_progress = 0;
    }

    fn record_probe_success(&mut self) {
        if self.strikes == 0 {
            return;
        }
        self.clear_progress = self.clear_progress.saturating_add(1);
        if self.clear_progress >= self.strikes.max(STRIKE_CLEAR_SUCCESSES) {
            self.strikes = 0;
            self.clear_progress = 0;
        }
    }
}

pub(crate) struct DialerCollection {
    pub latencies: SyncLatencies10,
    pub moving_average: Mutex<Duration>,
    failure_state: Mutex<FailureState>,
    traffic_ema_nanos: AtomicU64,
    traffic_samples: AtomicU8,
    slow_dial_streak: AtomicU8,
}

impl DialerCollection {
    pub(crate) fn new() -> Self {
        Self {
            latencies: SyncLatencies10::new(10),
            moving_average: Mutex::new(Duration::ZERO),
            failure_state: Mutex::new(FailureState::default()),
            traffic_ema_nanos: AtomicU64::new(0),
            traffic_samples: AtomicU8::new(0),
            slow_dial_streak: AtomicU8::new(0),
        }
    }

    fn update_moving_average(&self, latency: Duration) {
        let mut ma = self.moving_average.lock();
        if *ma == Duration::ZERO {
            *ma = latency;
        } else {
            *ma = (*ma + latency) / 2;
        }
    }

    pub(crate) fn mark_available(&self, latency: Duration) {
        let mut failure = self.failure_state.lock();
        self.latencies.append(LatencySample::real(latency));
        self.update_moving_average(latency);
        // Demotion clears only after max(strikes, STRIKE_CLEAR_SUCCESSES)
        // consecutive real successes — a fast-but-flaky node cannot reclaim
        // rank with one lucky probe.
        failure.record_probe_success();
    }

    fn mark_unavailable_locked(&self, failure: &mut FailureState) {
        failure.record_strike();
        // The synthetic sample is display-excluded and never feeds the moving
        // average; the failure strike owns ranking demotion.
        self.latencies
            .append(LatencySample::synthetic(TIMEOUT_LATENCY));
    }

    pub(crate) fn mark_unavailable(&self) {
        let mut failure = self.failure_state.lock();
        self.mark_unavailable_locked(&mut failure);
    }

    /// Record probe unavailability without creating a ranking strike. Probe
    /// liveness counters own exclusion; dial failures alone own demotion.
    pub(crate) fn mark_probe_unavailable(&self) {
        let mut failure = self.failure_state.lock();
        failure.clear_progress = 0;
    }

    /// Record one real dial failure. The streak threshold, strike, and
    /// unavailable publication share one order with real-success resets.
    pub(crate) fn record_dial_failure(&self) {
        let mut failure = self.failure_state.lock();
        failure.dial_fail_streak = failure.dial_fail_streak.saturating_add(1);
        if failure.dial_fail_streak >= DIAL_FAILURE_STRIKE_AT {
            self.mark_unavailable_locked(&mut failure);
        }
    }

    /// A real dial success breaks the failure streak (probe successes do
    /// not — a probe-alive but dial-dead node must still accumulate).
    pub(crate) fn reset_dial_fail_streak(&self) {
        self.failure_state.lock().dial_fail_streak = 0;
    }

    /// Failure-demoted nodes rank below every non-demoted candidate until
    /// enough consecutive real successes clear the strikes.
    pub(crate) fn is_failure_demoted(&self) -> bool {
        self.failure_state.lock().strikes > 0
    }

    /// Judge one real dial against the node's own traffic EMA, then fold it
    /// in. Sudden degradation (elapsed > min(2×ema, ema+SLOW_DIAL_MARGIN),
    /// floored at SLOW_DIAL_FLOOR) reports Slow; gradual drift stays owned
    /// by the probe cycle.
    pub(crate) fn record_traffic_latency(&self, elapsed: Duration) -> TrafficVerdict {
        let elapsed_nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let ema = self.traffic_ema_nanos.load(Ordering::Relaxed);
        let samples = self.traffic_samples.load(Ordering::Relaxed);
        let verdict = if samples < TRAFFIC_EMA_WARMUP {
            TrafficVerdict::Warmup
        } else if ema > 0
            && elapsed_nanos
                > ema
                    .saturating_mul(2)
                    .min(ema.saturating_add(
                        u64::try_from(SLOW_DIAL_MARGIN.as_nanos()).unwrap_or(u64::MAX),
                    ))
                    .max(u64::try_from(SLOW_DIAL_FLOOR.as_nanos()).unwrap_or(u64::MAX))
        {
            TrafficVerdict::Slow
        } else {
            TrafficVerdict::Fast
        };
        let new_ema = if ema == 0 {
            elapsed_nanos
        } else {
            ema.saturating_mul(7).saturating_add(elapsed_nanos) >> TRAFFIC_EMA_SHIFT
        };
        self.traffic_ema_nanos.store(new_ema, Ordering::Relaxed);
        if samples < TRAFFIC_EMA_WARMUP {
            self.traffic_samples.store(samples + 1, Ordering::Relaxed);
        }
        verdict
    }

    /// One more consecutive slow dial; returns the new streak length.
    pub(crate) fn bump_slow_streak(&self) -> u8 {
        let streak = self.slow_dial_streak.load(Ordering::Relaxed);
        let streak = (streak + 1).min(SLOW_DIAL_STREAK_MAX);
        self.slow_dial_streak.store(streak, Ordering::Relaxed);
        streak
    }

    pub(crate) fn reset_slow_streak(&self) {
        self.slow_dial_streak.store(0, Ordering::Relaxed);
    }

    /// Seed a restored (persisted) sample: feeds latency history and the
    /// moving average WITHOUT touching the alive flag — liveness is
    /// decided by probes; this only pre-seeds ranking data at startup.
    pub(crate) fn restore_sample(&self, latency: Duration, at: std::time::SystemTime) {
        self.latencies.append(LatencySample {
            latency,
            at,
            synthetic: false,
        });
        self.update_moving_average(latency);
    }

    pub(crate) fn moving_average_duration(&self) -> Duration {
        *self.moving_average.lock()
    }
}
