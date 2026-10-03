use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use quinn::{Connection, VarInt};

use super::metrics::{record_quic_path_stall, record_quic_session_rx_drop};
use super::{QUIC_SAMPLE_INTERVAL, QuicPathHealth, SendCompletion};

pub(super) const PATH_TIMEOUT_STREAK: u8 = 3;
pub(super) const PATH_MIN_UNACKED_SENDS: u64 = 3;
const PATH_WATCH_INTERVAL: Duration = Duration::from_secs(1);
static PATH_CLOCK: LazyLock<Instant> = LazyLock::new(Instant::now);

pub(super) fn path_now_millis() -> u64 {
    PATH_CLOCK
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX - 1)) as u64
        + 1
}

const PATH_EPOCH_MASK: u64 = (1_u64 << 62) - 1;
pub(super) const PATH_WAITING: u64 = 1_u64 << 62;
const PATH_MUTATING: u64 = 1_u64 << 63;
const PATH_TIMEOUT_BITS: u32 = 2;
const PATH_TIMEOUT_MASK: u64 = (1_u64 << PATH_TIMEOUT_BITS) - 1;

fn path_epoch(state: u64) -> u64 {
    state & PATH_EPOCH_MASK
}

pub(super) fn path_state(epoch: u64, waiting: bool) -> u64 {
    (epoch & PATH_EPOCH_MASK) | if waiting { PATH_WAITING } else { 0 }
}

pub(super) fn timeout_state(epoch: u64, streak: u8) -> u64 {
    (epoch << PATH_TIMEOUT_BITS) | u64::from(streak.min(PATH_TIMEOUT_STREAK))
}

fn timeout_state_epoch(state: u64) -> u64 {
    state >> PATH_TIMEOUT_BITS
}

pub(super) fn timeout_state_streak(state: u64) -> u8 {
    (state & PATH_TIMEOUT_MASK) as u8
}

impl QuicPathHealth {
    pub(crate) fn new(conn: &Connection) -> Arc<Self> {
        let stats = conn.stats();
        let now = path_now_millis();
        let rtt = stats.path.rtt;
        Arc::new(Self {
            ack_state: AtomicU64::new(0),
            last_acked_packets: AtomicU64::new(stats.path.acked_ack_eliciting_packets),
            sampled_acked_packets: AtomicU64::new(stats.path.acked_ack_eliciting_packets),
            sampled_sent_ack_eliciting_packets: AtomicU64::new(
                stats.path.sent_ack_eliciting_packets,
            ),
            waiting_sent_baseline: AtomicU64::new(stats.path.sent_ack_eliciting_packets),
            waiting_acked_baseline: AtomicU64::new(stats.path.acked_ack_eliciting_packets),
            unacked_since_ms: AtomicU64::new(0),
            last_sample_ms: AtomicU64::new(now),
            timeout_state: AtomicU64::new(timeout_state(0, 0)),
            waiting_since_ms: AtomicU64::new(0),
            send_timeout_ms: AtomicU64::new(duration_millis(bounded_quic_send_timeout(rtt))),
            path_stall_timeout_ms: AtomicU64::new(duration_millis(
                quic_path_stall_timeout_from_rtt(rtt),
            )),
            path_stalled: AtomicBool::new(false),
            telemetry_enabled: AtomicBool::new(false),
        })
    }

    pub(crate) fn send_timeout(&self) -> Duration {
        Duration::from_millis(self.send_timeout_ms.load(Ordering::Acquire).max(1))
    }

    pub(crate) fn enable_telemetry(&self) {
        self.telemetry_enabled.store(true, Ordering::Release);
    }

    pub(crate) fn telemetry_enabled(&self) -> bool {
        self.telemetry_enabled.load(Ordering::Acquire)
    }

    pub(crate) fn record_session_rx_drop(&self) {
        if self.telemetry_enabled() {
            record_quic_session_rx_drop();
        }
    }

    fn refresh_timing_from_rtt(&self, rtt: Duration) {
        self.send_timeout_ms.store(
            duration_millis(bounded_quic_send_timeout(rtt)),
            Ordering::Release,
        );
        self.path_stall_timeout_ms.store(
            duration_millis(quic_path_stall_timeout_from_rtt(rtt)),
            Ordering::Release,
        );
    }
    pub(super) fn unacked_sends_since_wait(&self) -> u64 {
        let sent = self
            .sampled_sent_ack_eliciting_packets
            .load(Ordering::Acquire)
            .saturating_sub(self.waiting_sent_baseline.load(Ordering::Acquire));
        let acked = self
            .last_acked_packets
            .load(Ordering::Acquire)
            .saturating_sub(self.waiting_acked_baseline.load(Ordering::Acquire));
        sent.saturating_sub(acked)
    }

    fn refresh_unacked_since(&self, now: u64) {
        let state = self.ack_state.load(Ordering::Acquire);
        if state & (PATH_WAITING | PATH_MUTATING) != PATH_WAITING {
            self.unacked_since_ms.store(0, Ordering::Release);
            return;
        }
        if self.unacked_sends_since_wait() != 0 {
            let _ =
                self.unacked_since_ms
                    .compare_exchange(0, now, Ordering::AcqRel, Ordering::Acquire);
        } else {
            self.unacked_since_ms.store(0, Ordering::Release);
        }
    }

    pub(super) fn note_ack_progress(&self, current: u64) -> bool {
        if self.path_stalled.load(Ordering::Acquire)
            || current <= self.last_acked_packets.load(Ordering::Acquire)
        {
            return false;
        }
        loop {
            if self.path_stalled.load(Ordering::Acquire) {
                return false;
            }
            let state = self.ack_state.load(Ordering::Acquire);
            if state & PATH_MUTATING != 0 {
                std::hint::spin_loop();
                continue;
            }
            if current <= self.last_acked_packets.load(Ordering::Acquire) {
                return false;
            }
            if self
                .ack_state
                .compare_exchange(
                    state,
                    state | PATH_MUTATING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }
            if current <= self.last_acked_packets.load(Ordering::Acquire) {
                self.ack_state.store(state, Ordering::Release);
                return false;
            }
            let epoch = path_epoch(state).wrapping_add(1) & PATH_EPOCH_MASK;
            self.last_acked_packets.store(current, Ordering::Release);
            self.waiting_sent_baseline.store(
                self.sampled_sent_ack_eliciting_packets
                    .load(Ordering::Acquire),
                Ordering::Release,
            );
            self.waiting_acked_baseline
                .store(current, Ordering::Release);
            self.timeout_state
                .store(timeout_state(epoch, 0), Ordering::Release);
            self.waiting_since_ms.store(0, Ordering::Release);
            self.unacked_since_ms.store(0, Ordering::Release);
            self.ack_state
                .store(path_state(epoch, false), Ordering::Release);
            return true;
        }
    }

    fn apply_sample(&self, stats: quinn::ConnectionStats, now: u64) -> u64 {
        // A newer sampler may have claimed the next interval while this
        // snapshot was waiting for Quinn's state lock; never publish its
        // older RTT after that sampler.
        if self.last_sample_ms.load(Ordering::Acquire) <= now {
            self.refresh_timing_from_rtt(stats.path.rtt);
        }
        self.last_sample_ms.fetch_max(now, Ordering::Release);
        self.sampled_acked_packets
            .fetch_max(stats.path.acked_ack_eliciting_packets, Ordering::Release);
        self.sampled_sent_ack_eliciting_packets
            .fetch_max(stats.path.sent_ack_eliciting_packets, Ordering::Release);
        let current = self.sampled_acked_packets.load(Ordering::Acquire);
        self.note_ack_progress(current);
        self.refresh_unacked_since(now);
        current
    }
    /// Refresh Quinn statistics at most once per second on packet send paths.
    fn refresh_sample(&self, conn: &Connection) -> u64 {
        let now = path_now_millis();
        let last = self.last_sample_ms.load(Ordering::Acquire);
        if now.saturating_sub(last) >= QUIC_SAMPLE_INTERVAL.as_millis() as u64
            && self
                .last_sample_ms
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            return self.apply_sample(conn.stats(), now);
        }
        self.sampled_acked_packets.load(Ordering::Acquire)
    }

    pub(crate) fn record_send_started(&self, conn: &Connection) -> crate::proxy::QuicSendToken {
        self.refresh_sample(conn);
        loop {
            if self.path_stalled.load(Ordering::Acquire) {
                return crate::proxy::QuicSendToken::INACTIVE;
            }
            let state = self.ack_state.load(Ordering::Acquire);
            if state & PATH_MUTATING != 0 {
                if self.path_stalled.load(Ordering::Acquire) {
                    return crate::proxy::QuicSendToken::INACTIVE;
                }
                std::hint::spin_loop();
                continue;
            }
            let ack_baseline = self.last_acked_packets.load(Ordering::Acquire);
            let sent_baseline = self
                .sampled_sent_ack_eliciting_packets
                .load(Ordering::Acquire);
            if state == self.ack_state.load(Ordering::Acquire) {
                return crate::proxy::QuicSendToken::new(
                    path_epoch(state),
                    ack_baseline,
                    sent_baseline,
                    path_now_millis(),
                );
            }
        }
    }
    pub(super) fn complete_send(
        &self,
        token: crate::proxy::QuicSendToken,
        completion: SendCompletion,
        observed_acks: u64,
    ) -> bool {
        if !token.is_active() {
            return false;
        }
        self.note_ack_progress(observed_acks);
        if matches!(completion, SendCompletion::Failure) {
            return false;
        }
        loop {
            if self.path_stalled.load(Ordering::Acquire) {
                return false;
            }
            let state = self.ack_state.load(Ordering::Acquire);
            if state & PATH_MUTATING != 0 {
                if self.path_stalled.load(Ordering::Acquire) {
                    return false;
                }
                std::hint::spin_loop();
                continue;
            }
            if path_epoch(state) != token.ack_epoch
                || self.last_acked_packets.load(Ordering::Acquire) > token.ack_baseline
            {
                return false;
            }
            if self
                .ack_state
                .compare_exchange(
                    state,
                    state | PATH_MUTATING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }
            if self.last_acked_packets.load(Ordering::Acquire) > token.ack_baseline {
                self.ack_state.store(state, Ordering::Release);
                return false;
            }
            let epoch = path_epoch(state);
            let timeout = self.timeout_state.load(Ordering::Acquire);
            let previous_streak = if timeout_state_epoch(timeout) == epoch {
                timeout_state_streak(timeout)
            } else {
                0
            };
            let streak = if matches!(completion, SendCompletion::Timeout) {
                previous_streak.saturating_add(1).min(PATH_TIMEOUT_STREAK)
            } else {
                0
            };
            self.timeout_state
                .store(timeout_state(epoch, streak), Ordering::Release);
            if state & PATH_WAITING == 0 {
                self.waiting_sent_baseline
                    .store(token.sent_baseline, Ordering::Release);
                self.waiting_acked_baseline
                    .store(token.ack_baseline, Ordering::Release);
                self.waiting_since_ms
                    .store(token.started_at, Ordering::Release);
                self.unacked_since_ms.store(0, Ordering::Release);
            } else {
                // Concurrent sends can complete out of order. Keep the
                // earliest accepted packet in the watchdog's accounting.
                self.waiting_sent_baseline
                    .fetch_min(token.sent_baseline, Ordering::AcqRel);
                self.waiting_since_ms
                    .fetch_min(token.started_at, Ordering::AcqRel);
            }
            self.ack_state
                .store(path_state(epoch, true), Ordering::Release);
            self.refresh_unacked_since(path_now_millis());
            return true;
        }
    }

    pub(crate) fn record_send_success(
        &self,
        token: crate::proxy::QuicSendToken,
        conn: &Connection,
    ) {
        let observed = self.refresh_sample(conn);
        self.complete_send(token, SendCompletion::Success, observed);
    }

    pub(crate) fn record_send_timeout(
        &self,
        token: crate::proxy::QuicSendToken,
        conn: &Connection,
    ) -> bool {
        let observed = self.refresh_sample(conn);
        self.complete_send(token, SendCompletion::Timeout, observed) && self.telemetry_enabled()
    }

    pub(crate) fn record_send_failure(&self, token: crate::proxy::QuicSendToken) {
        self.complete_send(
            token,
            SendCompletion::Failure,
            self.sampled_acked_packets.load(Ordering::Acquire),
        );
    }

    fn check_stalled(&self, conn: &Connection) -> bool {
        if conn.close_reason().is_some() {
            return false;
        }
        let state = self.ack_state.load(Ordering::Acquire);
        if state & PATH_WAITING == 0 || state & PATH_MUTATING != 0 {
            return false;
        }
        self.refresh_sample(conn);
        let state = self.ack_state.load(Ordering::Acquire);
        if state & PATH_WAITING == 0 || state & PATH_MUTATING != 0 {
            return false;
        }
        let epoch = path_epoch(state);
        let unacked_sends = self.unacked_sends_since_wait();
        let timeout = self.timeout_state.load(Ordering::Acquire);
        let streak = if timeout_state_epoch(timeout) == epoch {
            timeout_state_streak(timeout)
        } else {
            0
        };
        let now = path_now_millis();
        let timeout_elapsed = Duration::from_millis(
            now.saturating_sub(self.waiting_since_ms.load(Ordering::Acquire)),
        );
        let no_ack_elapsed =
            elapsed_since_millis(now, self.unacked_since_ms.load(Ordering::Acquire));
        if !should_retire_path(
            timeout_elapsed,
            no_ack_elapsed,
            streak,
            unacked_sends,
            self.send_timeout(),
            self.path_stall_timeout(),
        ) {
            return false;
        }
        if self
            .ack_state
            .compare_exchange(
                state,
                state | PATH_MUTATING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        if conn.close_reason().is_some() {
            self.ack_state.store(state, Ordering::Release);
            return false;
        }
        // An ACK may arrive between the last sample and the claim. Recheck
        // while the mutation bit blocks send completions and ACK samplers.
        let latest = conn.stats();
        if latest.path.acked_ack_eliciting_packets > self.last_acked_packets.load(Ordering::Acquire)
        {
            self.sampled_acked_packets
                .fetch_max(latest.path.acked_ack_eliciting_packets, Ordering::Release);
            self.sampled_sent_ack_eliciting_packets
                .fetch_max(latest.path.sent_ack_eliciting_packets, Ordering::Release);
            self.last_acked_packets
                .store(latest.path.acked_ack_eliciting_packets, Ordering::Release);
            self.waiting_sent_baseline.store(
                self.sampled_sent_ack_eliciting_packets
                    .load(Ordering::Acquire),
                Ordering::Release,
            );
            self.waiting_acked_baseline
                .store(latest.path.acked_ack_eliciting_packets, Ordering::Release);
            self.unacked_since_ms.store(0, Ordering::Release);
            let next_epoch = path_epoch(state).wrapping_add(1) & PATH_EPOCH_MASK;
            self.timeout_state
                .store(timeout_state(next_epoch, 0), Ordering::Release);
            self.waiting_since_ms.store(0, Ordering::Release);
            self.ack_state
                .store(path_state(next_epoch, false), Ordering::Release);
            return false;
        }
        self.path_stalled.store(true, Ordering::Release);
        conn.close(VarInt::from_u32(0), b"QUIC path stalled");
        true
    }

    fn path_stall_timeout(&self) -> Duration {
        Duration::from_millis(self.path_stall_timeout_ms.load(Ordering::Acquire).max(1))
    }

    pub(crate) fn is_stalled(&self) -> bool {
        self.path_stalled.load(Ordering::Acquire)
    }
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX - 1)).max(1) as u64
}

pub(super) fn elapsed_since_millis(now: u64, since: u64) -> Duration {
    if since == 0 {
        Duration::ZERO
    } else {
        Duration::from_millis(now.saturating_sub(since))
    }
}
pub(super) fn bounded_quic_send_timeout(rtt: Duration) -> Duration {
    rtt.checked_mul(4)
        .unwrap_or(Duration::MAX)
        .clamp(Duration::from_secs(1), Duration::from_secs(5))
}

pub(super) fn should_retire_path(
    timeout_elapsed: Duration,
    no_ack_elapsed: Duration,
    timeout_streak: u8,
    unacked_sends: u64,
    send_timeout: Duration,
    no_ack_timeout: Duration,
) -> bool {
    (no_ack_elapsed >= no_ack_timeout && unacked_sends >= PATH_MIN_UNACKED_SENDS)
        || (timeout_streak >= PATH_TIMEOUT_STREAK && timeout_elapsed >= send_timeout)
}

fn quic_path_stall_timeout_from_rtt(rtt: Duration) -> Duration {
    rtt.checked_mul(8)
        .unwrap_or(Duration::MAX)
        .max(Duration::from_secs(10))
}

/// Close a shared QUIC path only after repeated send deadlines or a full
/// no-ACK grace period. Any new packet acknowledgement clears both clocks.
pub(crate) fn spawn_quic_path_watchdog(conn: Connection, health: Arc<QuicPathHealth>) {
    let _ = crate::runtime::spawn_owned(async move {
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + PATH_WATCH_INTERVAL,
            PATH_WATCH_INTERVAL,
        );
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = conn.closed() => break,
                _ = ticker.tick() => {
                    if health.check_stalled(&conn) {
                        if health.telemetry_enabled() {
                            record_quic_path_stall();
                        }
                        break;
                    }
                }
            }
        }
    });
}
