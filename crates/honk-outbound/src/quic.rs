//! Shared QUIC client plumbing for QUIC-based proxy protocols.
//!
//! Used by the TUIC v5, Juicity, and Hysteria2 outbounds.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, anyhow};
use bytes::Bytes;
use parking_lot::Mutex as SyncMutex;
use quinn::congestion;
use quinn::{
    ClientConfig, Connection, Endpoint, EndpointConfig, RecvStream, SendStream, TransportConfig,
    VarInt,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Map a congestion-control name (`cubic` / `new_reno` / `bbr`, as used by
/// sing-box and dae node configs) to a quinn controller factory.
///
/// Unknown names fall back to cubic with a warning (all three algorithms are
/// provided by quinn-proto itself).
pub fn congestion_factory(
    name: Option<&str>,
) -> Arc<dyn congestion::ControllerFactory + Send + Sync> {
    match name.unwrap_or("cubic") {
        "cubic" => Arc::new(congestion::CubicConfig::default()),
        "new_reno" => Arc::new(congestion::NewRenoConfig::default()),
        "bbr" => Arc::new(congestion::BbrConfig::default()),
        other => {
            warn!("unknown QUIC congestion control '{other}', falling back to cubic");
            Arc::new(congestion::CubicConfig::default())
        }
    }
}

/// Fixed-rate "brutal" sender (hysteria2 parity): paces at a constant rate
/// and ignores loss entirely. quinn's token-bucket pacer refills at
/// window/RTT, so reporting a window of `rate × RTT` yields the target
/// pacing rate — the same shape as apernet's brutal sender, whose congestion
/// window is `SendBPS × RTT`.
#[derive(Debug)]
pub struct BrutalConfig {
    /// Target send rate in bytes per second.
    bytes_per_second: u64,
}

impl BrutalConfig {
    /// Build a factory for a target rate in bits per second (hysteria2
    /// bandwidth configs are in bps; 1 Mbps = 1e6 bps).
    pub fn from_bps(bps: u64) -> Self {
        Self {
            bytes_per_second: bps / 8,
        }
    }
}

impl congestion::ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn congestion::Controller> {
        Box::new(Brutal {
            rate: self.bytes_per_second,
            // RFC 9002 initial RTT; refined by the first ACK.
            rtt: Duration::from_millis(333),
            mtu: current_mtu,
        })
    }
}
struct Brutal {
    /// Target send rate, bytes per second.
    rate: u64,
    /// Latest smoothed RTT estimate.
    rtt: Duration,
    mtu: u16,
}

impl Brutal {
    fn bdp(&self) -> u64 {
        (u128::from(self.rate).saturating_mul(self.rtt.as_micros()) / 1_000_000)
            .min(u128::from(u64::MAX)) as u64
    }
}

impl congestion::Controller for Brutal {
    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        self.rtt = rtt.get();
    }

    /// Brutal never slows down for loss or ECN — that is its entire point.
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
    }

    fn window(&self) -> u64 {
        self.bdp().max(self.initial_window())
    }

    fn metrics(&self) -> congestion::ControllerMetrics {
        // ControllerMetrics is #[non_exhaustive]: no struct literals outside
        // the crate, mutate a default value instead.
        let mut metrics = congestion::ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.pacing_rate = Some(self.rate.saturating_mul(8));
        metrics
    }

    fn clone_box(&self) -> Box<dyn congestion::Controller> {
        Box::new(Brutal {
            rate: self.rate,
            rtt: self.rtt,
            mtu: self.mtu,
        })
    }

    fn initial_window(&self) -> u64 {
        10 * u64::from(self.mtu)
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

const QUIC_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const PATH_TIMEOUT_STREAK: u8 = 3;
const PATH_MIN_UNACKED_SENDS: u64 = 3;
const PATH_WATCH_INTERVAL: Duration = Duration::from_secs(1);
static PATH_CLOCK: LazyLock<Instant> = LazyLock::new(Instant::now);

fn path_now_millis() -> u64 {
    PATH_CLOCK
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX - 1)) as u64
        + 1
}

const PATH_EPOCH_MASK: u64 = (1_u64 << 62) - 1;
const PATH_WAITING: u64 = 1_u64 << 62;
const PATH_MUTATING: u64 = 1_u64 << 63;
const PATH_TIMEOUT_BITS: u32 = 2;
const PATH_TIMEOUT_MASK: u64 = (1_u64 << PATH_TIMEOUT_BITS) - 1;

fn path_epoch(state: u64) -> u64 {
    state & PATH_EPOCH_MASK
}

fn path_state(epoch: u64, waiting: bool) -> u64 {
    (epoch & PATH_EPOCH_MASK) | if waiting { PATH_WAITING } else { 0 }
}

fn timeout_state(epoch: u64, streak: u8) -> u64 {
    (epoch << PATH_TIMEOUT_BITS) | u64::from(streak.min(PATH_TIMEOUT_STREAK))
}

fn timeout_state_epoch(state: u64) -> u64 {
    state >> PATH_TIMEOUT_BITS
}

fn timeout_state_streak(state: u64) -> u8 {
    (state & PATH_TIMEOUT_MASK) as u8
}

/// Connection-wide QUIC delivery progress. Packet sends only read atomics;
/// Quinn statistics are sampled at most once per second, plus on a send
/// deadline and the watchdog's one-second tick.
#[derive(Debug)]
pub(crate) struct QuicPathHealth {
    ack_state: AtomicU64,
    last_acked_packets: AtomicU64,
    sampled_acked_packets: AtomicU64,
    sampled_sent_ack_eliciting_packets: AtomicU64,
    waiting_sent_baseline: AtomicU64,
    waiting_acked_baseline: AtomicU64,
    unacked_since_ms: AtomicU64,
    last_sample_ms: AtomicU64,
    timeout_state: AtomicU64,
    waiting_since_ms: AtomicU64,
    send_timeout_ms: AtomicU64,
    path_stall_timeout_ms: AtomicU64,
    path_stalled: AtomicBool,
    telemetry_enabled: AtomicBool,
}

enum SendCompletion {
    Success,
    Timeout,
    Failure,
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
    fn unacked_sends_since_wait(&self) -> u64 {
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

    fn note_ack_progress(&self, current: u64) -> bool {
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
    fn complete_send(
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

fn elapsed_since_millis(now: u64, since: u64) -> Duration {
    if since == 0 {
        Duration::ZERO
    } else {
        Duration::from_millis(now.saturating_sub(since))
    }
}
fn bounded_quic_send_timeout(rtt: Duration) -> Duration {
    rtt.checked_mul(4)
        .unwrap_or(Duration::MAX)
        .clamp(Duration::from_secs(1), Duration::from_secs(5))
}

fn should_retire_path(
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
    tokio::spawn(async move {
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

const FLOW_CONTROL_MIN_RTT: Duration = Duration::from_millis(80);
const FLOW_CONTROL_COOLDOWN: Duration = Duration::from_secs(5 * 60);
const FLOW_CONTROL_MIN_WINDOW: u64 = 8 << 20;
const FLOW_CONTROL_MAX_WINDOW: u64 = 32 << 20;
const FLOW_CONTROL_PROMOTION_SAMPLES: u8 = 3;

#[derive(Debug, Default)]
struct AdaptiveFlowProfile {
    connection_receive_floor: u64,
    stream_receive_floor: u64,
    send_floor: u64,
    last_connection_receive_adjust_ms: Option<u64>,
    last_stream_receive_adjust_ms: Option<u64>,
    last_send_adjust_ms: Option<u64>,
}

#[derive(Debug, Default)]
pub(crate) struct AdaptiveFlowProfiles(SyncMutex<[AdaptiveFlowProfile; 2]>);

impl AdaptiveFlowProfiles {
    fn lock(&self) -> parking_lot::MutexGuard<'_, [AdaptiveFlowProfile; 2]> {
        self.0.lock()
    }
}

#[derive(Debug)]
struct AdaptiveFlowSampler {
    last_sample_ms: u64,
    last_received_bytes: u64,
    last_sent_bytes: u64,
    last_stream_data_blocked: u64,
    receive_rate_ewma: u64,
    send_rate_ewma: u64,
    connection_receive_high_samples: u8,
    send_high_samples: u8,
}

impl AdaptiveFlowSampler {
    fn new(stats: &quinn::ConnectionStats, now: u64) -> Self {
        Self {
            last_sample_ms: now,
            last_received_bytes: stats.flow_control.received_bytes,
            last_sent_bytes: stats.flow_control.sent_bytes,
            last_stream_data_blocked: stats.frame_rx.stream_data_blocked,
            receive_rate_ewma: 0,
            send_rate_ewma: 0,
            connection_receive_high_samples: 0,
            send_high_samples: 0,
        }
    }

    fn observe(
        &mut self,
        profile: &mut AdaptiveFlowProfile,
        stats: &quinn::ConnectionStats,
        now: u64,
    ) {
        let elapsed_ms = now.saturating_sub(self.last_sample_ms);
        if elapsed_ms == 0 {
            return;
        }
        let received = stats
            .flow_control
            .received_bytes
            .saturating_sub(self.last_received_bytes);
        let sent = stats
            .flow_control
            .sent_bytes
            .saturating_sub(self.last_sent_bytes);
        let stream_data_blocked = stats
            .frame_rx
            .stream_data_blocked
            .saturating_sub(self.last_stream_data_blocked);
        self.last_sample_ms = now;
        self.last_received_bytes = stats.flow_control.received_bytes;
        self.last_sent_bytes = stats.flow_control.sent_bytes;
        self.last_stream_data_blocked = stats.frame_rx.stream_data_blocked;
        self.receive_rate_ewma = flow_rate_ewma(
            self.receive_rate_ewma,
            bytes_per_second(received, elapsed_ms),
        );
        self.send_rate_ewma =
            flow_rate_ewma(self.send_rate_ewma, bytes_per_second(sent, elapsed_ms));

        let receive_bdp = flow_bdp_bytes(self.receive_rate_ewma, stats.path.rtt);
        let send_bdp = flow_bdp_bytes(self.send_rate_ewma, stats.path.rtt);
        let receive_credit_pressured = flow_credit_pressured(
            stats.flow_control.receive_window_available,
            stats.flow_control.receive_window,
        );
        let receive_near = stats.path.rtt >= FLOW_CONTROL_MIN_RTT
            && flow_nears_window(
                receive_bdp,
                stats.flow_control.receive_window,
                receive_credit_pressured,
            );
        update_flow_window(
            &mut self.connection_receive_high_samples,
            &mut profile.connection_receive_floor,
            &mut profile.last_connection_receive_adjust_ms,
            received != 0 && receive_near,
            received == 0 && receive_near && receive_credit_pressured,
            receive_bdp,
            now,
        );
        update_stream_receive_window(
            &mut profile.stream_receive_floor,
            &mut profile.last_stream_receive_adjust_ms,
            stats.path.rtt >= FLOW_CONTROL_MIN_RTT && stream_data_blocked != 0,
            stats.flow_control.stream_receive_window,
            now,
        );
        let send_credit_pressured = flow_credit_pressured(
            stats.flow_control.send_window_available,
            stats.flow_control.send_window,
        );
        let send_near = stats.path.rtt >= FLOW_CONTROL_MIN_RTT
            && flow_nears_window(
                send_bdp,
                stats.flow_control.send_window,
                send_credit_pressured,
            );
        update_flow_window(
            &mut self.send_high_samples,
            &mut profile.send_floor,
            &mut profile.last_send_adjust_ms,
            sent != 0 && send_near,
            sent == 0 && send_near && send_credit_pressured,
            send_bdp,
            now,
        );
    }
}

fn bytes_per_second(bytes: u64, elapsed_ms: u64) -> u64 {
    (u128::from(bytes) * 1_000 / u128::from(elapsed_ms.max(1))).min(u128::from(u64::MAX)) as u64
}

fn flow_rate_ewma(previous: u64, sample: u64) -> u64 {
    if previous == 0 {
        sample
    } else {
        ((u128::from(previous) * 9 + u128::from(sample)) / 10).min(u128::from(u64::MAX)) as u64
    }
}

fn flow_bdp_bytes(rate: u64, rtt: Duration) -> u64 {
    (u128::from(rate) * rtt.as_nanos() / 1_000_000_000).min(u128::from(u64::MAX)) as u64
}

fn flow_credit_pressured(available: u64, window: u64) -> bool {
    window != 0 && u128::from(available) * 4 <= u128::from(window)
}

fn flow_nears_window(bdp: u64, window: u64, credit_pressured: bool) -> bool {
    window != 0
        && (u128::from(bdp) * 4 >= u128::from(window) * 3
            || (credit_pressured && u128::from(bdp) * 2 >= u128::from(window)))
}

fn adaptive_window(bdp: u64) -> u64 {
    bdp.saturating_mul(2)
        .clamp(FLOW_CONTROL_MIN_WINDOW, FLOW_CONTROL_MAX_WINDOW)
        .next_multiple_of(1 << 20)
        .min(FLOW_CONTROL_MAX_WINDOW)
}

fn update_flow_window(
    high_samples: &mut u8,
    floor: &mut u64,
    last_adjust_ms: &mut Option<u64>,
    high: bool,
    preserve: bool,
    bdp: u64,
    now: u64,
) {
    if high {
        *high_samples = high_samples
            .saturating_add(1)
            .min(FLOW_CONTROL_PROMOTION_SAMPLES);
    } else if !preserve {
        *high_samples = 0;
    }
    if *high_samples < FLOW_CONTROL_PROMOTION_SAMPLES
        || last_adjust_ms
            .is_some_and(|last| now.saturating_sub(last) < FLOW_CONTROL_COOLDOWN.as_millis() as u64)
    {
        return;
    }
    let target = adaptive_window(bdp);
    if target > *floor {
        *floor = target;
        *last_adjust_ms = Some(now);
    }
    *high_samples = 0;
}

fn update_stream_receive_window(
    floor: &mut u64,
    last_adjust_ms: &mut Option<u64>,
    blocked: bool,
    current_window: u64,
    now: u64,
) {
    if !blocked
        || last_adjust_ms
            .is_some_and(|last| now.saturating_sub(last) < FLOW_CONTROL_COOLDOWN.as_millis() as u64)
    {
        return;
    }
    let target = current_window
        .saturating_mul(2)
        .clamp(FLOW_CONTROL_MIN_WINDOW, FLOW_CONTROL_MAX_WINDOW);
    if target > *floor {
        *floor = target;
        *last_adjust_ms = Some(now);
    }
}

fn apply_flow_control_profile(
    conn: &Connection,
    stats: &quinn::ConnectionStats,
    profile: &AdaptiveFlowProfile,
) {
    if profile.stream_receive_floor > stats.flow_control.stream_receive_window {
        conn.set_stream_receive_window(
            VarInt::try_from(profile.stream_receive_floor)
                .expect("stream receive floor originated from a QUIC window"),
        );
    }
    if profile.connection_receive_floor > stats.flow_control.receive_window {
        conn.set_receive_window(
            VarInt::try_from(profile.connection_receive_floor)
                .expect("connection receive floor originated from a QUIC window"),
        );
    }
    if profile.send_floor > stats.flow_control.send_window {
        conn.set_send_window(profile.send_floor);
    }
}

fn seed_flow_control_profile(profile: &mut AdaptiveFlowProfile, stats: &quinn::ConnectionStats) {
    profile.connection_receive_floor = profile
        .connection_receive_floor
        .max(stats.flow_control.receive_window);
    profile.stream_receive_floor = profile
        .stream_receive_floor
        .max(stats.flow_control.stream_receive_window);
    profile.send_floor = profile.send_floor.max(stats.flow_control.send_window);
}

/// Process-wide QUIC path telemetry. Connection labels are intentionally not
/// retained; the snapshot is suitable for the aggregate `/stats` surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuicStatsSnapshot {
    pub active_connections: u64,
    pub srtt_us: u64,
    pub cwnd_bytes: u64,
    pub flow_received_bytes: u64,
    pub flow_sent_bytes: u64,
    pub receive_window_bytes: u64,
    pub receive_window_available_bytes: u64,
    pub stream_receive_window_bytes: u64,
    pub send_window_bytes: u64,
    pub send_window_available_bytes: u64,
    pub loss_rate_ppm: u64,
    pub sent_packets: u64,
    pub ack_frames: u64,
    pub lost_packets: u64,
    pub sent_plpmtud_probes: u64,
    pub lost_plpmtud_probes: u64,
    pub current_mtu: u64,
    pub black_holes: u64,
    pub congestion_events: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_datagrams: u64,
    pub rx_datagrams: u64,
    pub tx_ios: u64,
    pub rx_ios: u64,
    pub transport_tx_would_block: u64,
    pub transport_rx_drops: u64,
    pub transport_tx_drops: u64,
    pub session_rx_drops: u64,
    pub send_timeouts: u64,
    pub path_stalls: u64,
}

#[derive(Debug, Default)]
struct QuicMetricTotals {
    sent_packets: AtomicU64,
    ack_frames: AtomicU64,
    lost_packets: AtomicU64,
    sent_plpmtud_probes: AtomicU64,
    lost_plpmtud_probes: AtomicU64,
    black_holes: AtomicU64,
    congestion_events: AtomicU64,
    flow_received_bytes: AtomicU64,
    flow_sent_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    tx_datagrams: AtomicU64,
    rx_datagrams: AtomicU64,
    tx_ios: AtomicU64,
    rx_ios: AtomicU64,
    transport_tx_would_block: AtomicU64,
    transport_rx_drops: AtomicU64,
    transport_tx_drops: AtomicU64,
    session_rx_drops: AtomicU64,
    send_timeouts: AtomicU64,
    path_stalls: AtomicU64,
}

impl QuicMetricTotals {
    fn add_stats(&self, stats: &quinn::ConnectionStats) {
        self.sent_packets
            .fetch_add(stats.path.sent_packets, Ordering::Relaxed);
        self.ack_frames
            .fetch_add(stats.frame_rx.acks, Ordering::Relaxed);
        self.lost_packets
            .fetch_add(stats.path.lost_packets, Ordering::Relaxed);
        self.sent_plpmtud_probes
            .fetch_add(stats.path.sent_plpmtud_probes, Ordering::Relaxed);
        self.lost_plpmtud_probes
            .fetch_add(stats.path.lost_plpmtud_probes, Ordering::Relaxed);
        self.black_holes
            .fetch_add(stats.path.black_holes_detected, Ordering::Relaxed);
        self.congestion_events
            .fetch_add(stats.path.congestion_events, Ordering::Relaxed);
        self.flow_received_bytes
            .fetch_add(stats.flow_control.received_bytes, Ordering::Relaxed);
        self.flow_sent_bytes
            .fetch_add(stats.flow_control.sent_bytes, Ordering::Relaxed);
        self.tx_bytes
            .fetch_add(stats.udp_tx.bytes, Ordering::Relaxed);
        self.rx_bytes
            .fetch_add(stats.udp_rx.bytes, Ordering::Relaxed);
        self.tx_datagrams
            .fetch_add(stats.udp_tx.datagrams, Ordering::Relaxed);
        self.rx_datagrams
            .fetch_add(stats.udp_rx.datagrams, Ordering::Relaxed);
        self.tx_ios.fetch_add(stats.udp_tx.ios, Ordering::Relaxed);
        self.rx_ios.fetch_add(stats.udp_rx.ios, Ordering::Relaxed);
    }

    fn add_received_bytes(&self, bytes: u64) {
        self.flow_received_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct QuicMetricEntry {
    stats: quinn::ConnectionStats,
}

#[derive(Debug, Default)]
struct QuicMetrics {
    entries: SyncMutex<HashMap<u64, QuicMetricEntry>>,
    next_id: AtomicU64,
    totals: QuicMetricTotals,
}

static QUIC_METRICS: LazyLock<QuicMetrics> = LazyLock::new(QuicMetrics::default);

fn quic_metrics() -> &'static QuicMetrics {
    &QUIC_METRICS
}

fn register_quic_connection(stats: quinn::ConnectionStats) -> u64 {
    let metrics = quic_metrics();
    let id = metrics
        .next_id
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    metrics.entries.lock().insert(id, QuicMetricEntry { stats });
    id
}

fn update_quic_connection(id: u64, stats: quinn::ConnectionStats) {
    let metrics = quic_metrics();
    if let Some(entry) = metrics.entries.lock().get_mut(&id) {
        entry.stats = stats;
    }
}

fn finish_quic_connection(id: u64, stats: quinn::ConnectionStats) -> bool {
    let metrics = quic_metrics();
    let mut entries = metrics.entries.lock();
    if entries.remove(&id).is_none() {
        return false;
    }
    metrics.totals.add_stats(&stats);
    true
}

#[derive(Debug, Default)]
struct QuicMetricTracker {
    id: Option<u64>,
    closed_received_bytes: Option<u64>,
    finished: bool,
}

impl QuicMetricTracker {
    fn sample(&mut self, stats: quinn::ConnectionStats) {
        if self.finished || self.closed_received_bytes.is_some() {
            return;
        }
        match self.id {
            Some(id) => update_quic_connection(id, stats),
            None => self.id = Some(register_quic_connection(stats)),
        }
    }

    fn close(&mut self, stats: quinn::ConnectionStats) {
        let Some(id) = self.id else {
            return;
        };
        if finish_quic_connection(id, stats) {
            self.closed_received_bytes = Some(stats.flow_control.received_bytes);
        }
    }

    fn finish(&mut self, stats: quinn::ConnectionStats) {
        self.finished = true;
        if let Some(closed) = self.closed_received_bytes.take() {
            quic_metrics()
                .totals
                .add_received_bytes(stats.flow_control.received_bytes.saturating_sub(closed));
        } else if let Some(id) = self.id {
            finish_quic_connection(id, stats);
        }
        self.id = None;
    }
}

fn add_active_stats(snapshot: &mut QuicStatsSnapshot, stats: &quinn::ConnectionStats) {
    snapshot.sent_packets = snapshot
        .sent_packets
        .saturating_add(stats.path.sent_packets);
    snapshot.ack_frames = snapshot.ack_frames.saturating_add(stats.frame_rx.acks);
    snapshot.lost_packets = snapshot
        .lost_packets
        .saturating_add(stats.path.lost_packets);
    snapshot.sent_plpmtud_probes = snapshot
        .sent_plpmtud_probes
        .saturating_add(stats.path.sent_plpmtud_probes);
    snapshot.lost_plpmtud_probes = snapshot
        .lost_plpmtud_probes
        .saturating_add(stats.path.lost_plpmtud_probes);
    snapshot.black_holes = snapshot
        .black_holes
        .saturating_add(stats.path.black_holes_detected);
    snapshot.congestion_events = snapshot
        .congestion_events
        .saturating_add(stats.path.congestion_events);
    snapshot.flow_received_bytes = snapshot
        .flow_received_bytes
        .saturating_add(stats.flow_control.received_bytes);
    snapshot.flow_sent_bytes = snapshot
        .flow_sent_bytes
        .saturating_add(stats.flow_control.sent_bytes);
    snapshot.tx_bytes = snapshot.tx_bytes.saturating_add(stats.udp_tx.bytes);
    snapshot.rx_bytes = snapshot.rx_bytes.saturating_add(stats.udp_rx.bytes);
    snapshot.tx_datagrams = snapshot.tx_datagrams.saturating_add(stats.udp_tx.datagrams);
    snapshot.rx_datagrams = snapshot.rx_datagrams.saturating_add(stats.udp_rx.datagrams);
    snapshot.tx_ios = snapshot.tx_ios.saturating_add(stats.udp_tx.ios);
    snapshot.rx_ios = snapshot.rx_ios.saturating_add(stats.udp_rx.ios);
}

/// Return aggregate QUIC counters and averages for active paths.
pub fn quic_stats_snapshot() -> QuicStatsSnapshot {
    let metrics = quic_metrics();
    let entries = metrics.entries.lock();
    let active = entries.len() as u64;
    let mut snapshot = QuicStatsSnapshot {
        sent_packets: metrics.totals.sent_packets.load(Ordering::Relaxed),
        ack_frames: metrics.totals.ack_frames.load(Ordering::Relaxed),
        lost_packets: metrics.totals.lost_packets.load(Ordering::Relaxed),
        sent_plpmtud_probes: metrics.totals.sent_plpmtud_probes.load(Ordering::Relaxed),
        lost_plpmtud_probes: metrics.totals.lost_plpmtud_probes.load(Ordering::Relaxed),
        black_holes: metrics.totals.black_holes.load(Ordering::Relaxed),
        congestion_events: metrics.totals.congestion_events.load(Ordering::Relaxed),
        flow_received_bytes: metrics.totals.flow_received_bytes.load(Ordering::Relaxed),
        flow_sent_bytes: metrics.totals.flow_sent_bytes.load(Ordering::Relaxed),
        tx_bytes: metrics.totals.tx_bytes.load(Ordering::Relaxed),
        rx_bytes: metrics.totals.rx_bytes.load(Ordering::Relaxed),
        tx_datagrams: metrics.totals.tx_datagrams.load(Ordering::Relaxed),
        rx_datagrams: metrics.totals.rx_datagrams.load(Ordering::Relaxed),
        tx_ios: metrics.totals.tx_ios.load(Ordering::Relaxed),
        rx_ios: metrics.totals.rx_ios.load(Ordering::Relaxed),
        transport_tx_would_block: metrics
            .totals
            .transport_tx_would_block
            .load(Ordering::Relaxed),
        transport_rx_drops: metrics.totals.transport_rx_drops.load(Ordering::Relaxed),
        transport_tx_drops: metrics.totals.transport_tx_drops.load(Ordering::Relaxed),
        session_rx_drops: metrics.totals.session_rx_drops.load(Ordering::Relaxed),
        send_timeouts: metrics.totals.send_timeouts.load(Ordering::Relaxed),
        path_stalls: metrics.totals.path_stalls.load(Ordering::Relaxed),
        active_connections: active,
        ..Default::default()
    };
    let mut rtt_us = 0u128;
    let mut cwnd_bytes = 0u128;
    let mut mtu = 0u128;
    let mut receive_window = 0u128;
    let mut receive_window_available = 0u128;
    let mut stream_receive_window = 0u128;
    let mut send_window = 0u128;
    let mut send_window_available = 0u128;
    for entry in entries.values() {
        add_active_stats(&mut snapshot, &entry.stats);
        rtt_us += entry.stats.path.rtt.as_micros();
        cwnd_bytes += entry.stats.path.cwnd as u128;
        mtu += entry.stats.path.current_mtu as u128;
        receive_window += u128::from(entry.stats.flow_control.receive_window);
        receive_window_available += u128::from(entry.stats.flow_control.receive_window_available);
        stream_receive_window += u128::from(entry.stats.flow_control.stream_receive_window);
        send_window += u128::from(entry.stats.flow_control.send_window);
        send_window_available += u128::from(entry.stats.flow_control.send_window_available);
    }
    let data_sent = snapshot
        .sent_packets
        .saturating_sub(snapshot.sent_plpmtud_probes);
    snapshot.loss_rate_ppm = if data_sent == 0 {
        0
    } else {
        (u128::from(snapshot.lost_packets) * 1_000_000 / u128::from(data_sent)).min(1_000_000)
            as u64
    };
    if active != 0 {
        let active = u128::from(active);
        snapshot.srtt_us = (rtt_us / active).min(u128::from(u64::MAX)) as u64;
        snapshot.cwnd_bytes = (cwnd_bytes / active).min(u128::from(u64::MAX)) as u64;
        snapshot.receive_window_bytes = (receive_window / active).min(u128::from(u64::MAX)) as u64;
        snapshot.receive_window_available_bytes =
            (receive_window_available / active).min(u128::from(u64::MAX)) as u64;
        snapshot.stream_receive_window_bytes =
            (stream_receive_window / active).min(u128::from(u64::MAX)) as u64;
        snapshot.send_window_bytes = (send_window / active).min(u128::from(u64::MAX)) as u64;
        snapshot.send_window_available_bytes =
            (send_window_available / active).min(u128::from(u64::MAX)) as u64;
        snapshot.current_mtu = (mtu / active).min(u128::from(u64::MAX)) as u64;
    }
    snapshot
}

/// Count a QUIC packet-send timeout observed by the core driver.
pub fn record_quic_send_timeout() {
    quic_metrics()
        .totals
        .send_timeouts
        .fetch_add(1, Ordering::Relaxed);
}

/// Count a QUIC path retired by the core driver watchdog.
pub fn record_quic_path_stall() {
    quic_metrics()
        .totals
        .path_stalls
        .fetch_add(1, Ordering::Relaxed);
}

fn record_transport_tx_would_block() {
    quic_metrics()
        .totals
        .transport_tx_would_block
        .fetch_add(1, Ordering::Relaxed);
}

fn record_transport_rx_drop() {
    quic_metrics()
        .totals
        .transport_rx_drops
        .fetch_add(1, Ordering::Relaxed);
}
fn record_transport_tx_drop() {
    quic_metrics()
        .totals
        .transport_tx_drops
        .fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_quic_session_rx_drop() {
    quic_metrics()
        .totals
        .session_rx_drops
        .fetch_add(1, Ordering::Relaxed);
}

/// Caller-tunable options for [`client_config`]. Everything defaults to the
/// quinn/cubic behavior; protocol handlers override only what they need.
#[derive(Clone, Default)]
pub struct QuicClientOptions {
    /// Congestion controller; `None` = cubic. Use [`congestion_factory`] for
    /// named algorithms or [`BrutalConfig`] for hysteria2's fixed-rate sender.
    pub congestion: Option<Arc<dyn congestion::ControllerFactory + Send + Sync>>,
    /// QUIC keep-alive interval.
    pub keep_alive: Option<Duration>,
    /// Initial per-stream receive window, bytes.
    pub stream_receive_window: Option<u64>,
    /// Initial connection-level receive window, bytes.
    pub conn_receive_window: Option<u64>,
    /// Disable QUIC path MTU discovery.
    pub disable_mtu_discovery: bool,
    /// UDP payload size (NOT link MTU): applied as the send-side
    /// `initial_mtu` and the PMTUD upper bound; the endpoint's
    /// `max_udp_payload_size` (receive advertisement) is set separately by
    /// the protocol handler from the same node field.
    pub max_udp_payload_size: Option<u16>,
}

impl QuicClientOptions {
    /// Options with a named congestion controller (`cubic`/`new_reno`/`bbr`).
    pub fn with_congestion(name: Option<&str>) -> Self {
        Self {
            congestion: Some(congestion_factory(name)),
            ..Default::default()
        }
    }
}

/// Assemble a quinn [`ClientConfig`] for a proxy protocol.
///
/// - `alpn`: ALPN protocol list required by the protocol (TUIC: `tuic`,
///   Juicity/Hysteria2: `h3`).
/// - `options`: transport tuning, see [`QuicClientOptions`].
///
/// TLS is the BoringSSL backend in [`crate::quic_boring`] (Chrome fingerprint
/// when `tls_implementation = "utls"`, ECH when the node carries one —
/// static config, or DNS HTTPS-RR discovery when only `ech_enabled` is set,
/// pinSHA256 when `tls_pin_sha256` is set).
pub async fn client_config(
    node: &honk_config::node::Node,
    alpn: &[&[u8]],
    options: QuicClientOptions,
) -> anyhow::Result<ClientConfig> {
    let alpn_wire = alpn
        .iter()
        .flat_map(|p| std::iter::once(p.len() as u8).chain(p.iter().copied()))
        .collect::<Vec<u8>>();
    let tls = node.tls().ok_or_else(|| {
        anyhow!(
            "node '{}' protocol '{}' has no QUIC TLS configuration",
            node.name,
            node.protocol().as_str()
        )
    })?;
    let ech = match crate::tls::load_ech_config_list(node)? {
        Some(list) => Some(Arc::new(list)),
        None if tls.ech_enabled => {
            let name = tls.sni.clone().unwrap_or_else(|| node.host().to_string());
            crate::tls::discover_ech_config(&name).await.map(Arc::new)
        }
        None => None,
    };
    let pin_sha256 = tls
        .pin_sha256
        .as_deref()
        .map(|pin| {
            crate::tls::parse_pin_sha256(pin).ok_or_else(|| {
                anyhow!(
                    "node '{}': invalid tls_pin_sha256 (expected 64 hex chars)",
                    node.name
                )
            })
        })
        .transpose()?;
    let crypto =
        crate::quic_boring::BoringQuicClientConfig::new(crate::quic_boring::BoringQuicOptions {
            alpn_wire,
            skip_cert_verify: tls.skip_cert_verify,
            chrome: crate::tls::chrome_mode(),
            ech_config_list: ech,
            pin_sha256,
            ticket_key: Some(format!(
                "{}|{}|{}|{}",
                node.host(),
                node.port,
                tls.sni.clone().unwrap_or_else(|| node.host().to_string()),
                alpn.iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect::<Vec<_>>()
                    .join(","),
            )),
        })?;
    let mut cfg = ClientConfig::new(Arc::new(crypto));
    let mut transport = TransportConfig::default();
    transport
        .congestion_controller_factory(
            options
                .congestion
                .unwrap_or_else(|| congestion_factory(None)),
        )
        .max_concurrent_uni_streams(VarInt::from_u32(4096));
    if let Some(w) = options.stream_receive_window {
        transport.stream_receive_window(VarInt::from_u64(w)?);
    }
    if let Some(w) = options.conn_receive_window {
        transport.receive_window(VarInt::from_u64(w)?);
    }
    if let Some(mtu) = options.max_udp_payload_size {
        let mtu = clamp_quic_payload_size(mtu);
        transport.initial_mtu(mtu);
        if !options.disable_mtu_discovery {
            let mut mtud = quinn::MtuDiscoveryConfig::default();
            mtud.upper_bound(mtu);
            transport.mtu_discovery_config(Some(mtud));
        }
    }
    if options.disable_mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    if let Some(ka) = options.keep_alive {
        transport.keep_alive_interval(Some(ka));
    }
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) async fn recv_read_exact(recv: &mut RecvStream, buf: &mut [u8]) -> io::Result<()> {
    recv.read_exact(buf)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))
}

pub(crate) async fn survives_auth_close_window(conn: &Connection) -> bool {
    let wait = (2 * conn.rtt()).max(Duration::from_millis(2));
    tokio::select! {
        _ = conn.closed() => false,
        _ = tokio::time::sleep(wait) => conn.close_reason().is_none(),
    }
}

#[cfg(test)]
mod path_health_tests {
    use super::*;
    use crate::proxy::QuicSendToken;

    fn health(last_ack: u64, epoch: u64, streak: u8, since: u64) -> QuicPathHealth {
        QuicPathHealth {
            ack_state: AtomicU64::new(path_state(epoch, since != 0)),
            last_acked_packets: AtomicU64::new(last_ack),
            sampled_acked_packets: AtomicU64::new(last_ack),
            sampled_sent_ack_eliciting_packets: AtomicU64::new(last_ack),
            waiting_sent_baseline: AtomicU64::new(last_ack),
            waiting_acked_baseline: AtomicU64::new(last_ack),
            unacked_since_ms: AtomicU64::new(0),
            last_sample_ms: AtomicU64::new(path_now_millis()),
            timeout_state: AtomicU64::new(timeout_state(epoch, streak)),
            waiting_since_ms: AtomicU64::new(since),
            send_timeout_ms: AtomicU64::new(1_000),
            path_stall_timeout_ms: AtomicU64::new(10_000),
            path_stalled: AtomicBool::new(false),
            telemetry_enabled: AtomicBool::new(false),
        }
    }

    fn flow_stats(received: u64, sent: u64, window: u64) -> quinn::ConnectionStats {
        let mut stats = quinn::ConnectionStats::default();
        stats.path.rtt = Duration::from_millis(125);
        stats.flow_control.received_bytes = received;
        stats.flow_control.sent_bytes = sent;
        stats.flow_control.receive_window = window;
        stats.flow_control.receive_window_available = window;
        stats.flow_control.stream_receive_window = window;
        stats.flow_control.send_window = window;
        stats.flow_control.send_window_available = window;
        stats
    }

    #[test]
    fn sustained_high_bdp_promotes_with_cooldown_and_cap() {
        const MIB: u64 = 1 << 20;
        let mut stats = flow_stats(0, 0, 8 * MIB);
        let mut sampler = AdaptiveFlowSampler::new(&stats, 1_000);
        let mut profile = AdaptiveFlowProfile::default();

        for step in 1..=3 {
            stats.flow_control.received_bytes += 48 * MIB;
            stats.flow_control.sent_bytes += 48 * MIB;
            sampler.observe(&mut profile, &stats, 1_000 + step * 1_000);
            if step < 3 {
                assert_eq!(
                    (
                        profile.connection_receive_floor,
                        profile.stream_receive_floor,
                        profile.send_floor,
                    ),
                    (0, 0, 0),
                );
            }
        }
        assert_eq!(
            (
                profile.connection_receive_floor,
                profile.stream_receive_floor,
                profile.send_floor,
            ),
            (12 * MIB, 0, 12 * MIB),
        );

        stats.flow_control.receive_window = 12 * MIB;
        stats.flow_control.stream_receive_window = 12 * MIB;
        stats.flow_control.send_window = 12 * MIB;
        let mut cooldown_sampler = AdaptiveFlowSampler::new(&stats, 4_000);
        for step in 1..=3 {
            stats.flow_control.received_bytes += 256 * MIB;
            stats.flow_control.sent_bytes += 256 * MIB;
            cooldown_sampler.observe(&mut profile, &stats, 4_000 + step * 1_000);
        }
        assert_eq!(
            (
                profile.connection_receive_floor,
                profile.stream_receive_floor,
                profile.send_floor,
            ),
            (12 * MIB, 0, 12 * MIB),
        );

        let mut resumed_sampler = AdaptiveFlowSampler::new(&stats, 304_000);
        for step in 1..=3 {
            stats.flow_control.received_bytes += 256 * MIB;
            stats.flow_control.sent_bytes += 256 * MIB;
            resumed_sampler.observe(&mut profile, &stats, 304_000 + step * 1_000);
        }
        assert_eq!(
            (
                profile.connection_receive_floor,
                profile.stream_receive_floor,
                profile.send_floor,
            ),
            (FLOW_CONTROL_MAX_WINDOW, 0, FLOW_CONTROL_MAX_WINDOW),
        );

        let mut idle_sampler = AdaptiveFlowSampler::new(&stats, 307_000);
        for step in 1..=60 {
            idle_sampler.observe(&mut profile, &stats, 307_000 + step * 1_000);
        }
        assert_eq!(
            (
                profile.connection_receive_floor,
                profile.stream_receive_floor,
                profile.send_floor,
            ),
            (FLOW_CONTROL_MAX_WINDOW, 0, FLOW_CONTROL_MAX_WINDOW),
        );
        assert!(!flow_nears_window(4 * MIB, 8 * MIB, false));
        assert!(flow_nears_window(4 * MIB, 8 * MIB, true));
        assert_eq!(adaptive_window(u64::MAX), FLOW_CONTROL_MAX_WINDOW);
    }

    #[test]
    fn aggregate_bdp_does_not_train_stream_window() {
        const MIB: u64 = 1 << 20;
        let mut stats = flow_stats(0, 0, 8 * MIB);
        let mut sampler = AdaptiveFlowSampler::new(&stats, 1_000);
        let mut profile = AdaptiveFlowProfile::default();
        for step in 1..=3 {
            stats.flow_control.received_bytes += 48 * MIB;
            sampler.observe(&mut profile, &stats, 1_000 + step * 1_000);
        }
        assert_eq!(profile.connection_receive_floor, 12 * MIB);
        assert_eq!(profile.stream_receive_floor, 0);

        stats.frame_rx.stream_data_blocked += 1;
        sampler.observe(&mut profile, &stats, 5_000);
        assert_eq!(profile.stream_receive_floor, 16 * MIB);
    }

    #[test]
    fn credit_stalls_preserve_but_do_not_advance_promotion() {
        const MIB: u64 = 1 << 20;
        fn sampled_floor(pressured: bool) -> u64 {
            let mut stats = flow_stats(0, 0, 8 * MIB);
            stats.flow_control.send_window_available = if pressured { 0 } else { 8 * MIB };
            let mut sampler = AdaptiveFlowSampler::new(&stats, 1_000);
            let mut profile = AdaptiveFlowProfile::default();
            for step in 1..=7 {
                if matches!(step, 1 | 4 | 7) {
                    stats.flow_control.sent_bytes += 48 * MIB;
                }
                sampler.observe(&mut profile, &stats, 1_000 + step * 1_000);
            }
            profile.send_floor
        }

        assert!(sampled_floor(true) > 8 * MIB);
        assert_eq!(sampled_floor(false), 0);
    }

    #[test]
    fn configured_window_does_not_start_cooldown() {
        const MIB: u64 = 1 << 20;
        let mut seeded = AdaptiveFlowProfile::default();
        seed_flow_control_profile(&mut seeded, &flow_stats(0, 0, 16 * MIB));
        let mut samples = 0;
        for now in 1..=3 {
            update_flow_window(
                &mut samples,
                &mut seeded.connection_receive_floor,
                &mut seeded.last_connection_receive_adjust_ms,
                true,
                false,
                4 * MIB,
                now,
            );
        }
        assert_eq!(seeded.connection_receive_floor, 16 * MIB);
        assert_eq!(seeded.last_connection_receive_adjust_ms, None);
        for now in 4..=6 {
            update_flow_window(
                &mut samples,
                &mut seeded.connection_receive_floor,
                &mut seeded.last_connection_receive_adjust_ms,
                true,
                false,
                12 * MIB,
                now,
            );
        }
        assert_eq!(seeded.connection_receive_floor, 24 * MIB);
        assert_eq!(seeded.last_connection_receive_adjust_ms, Some(6));
    }

    #[test]
    fn metric_tracker_counts_post_close_reads_once() {
        const DELIVERED: u64 = 1 << 50;
        let totals = &quic_metrics().totals.flow_received_bytes;
        let before = totals.load(Ordering::Relaxed);
        let mut tracker = QuicMetricTracker::default();
        let stats = quinn::ConnectionStats::default();
        tracker.sample(stats);
        tracker.close(stats);
        let mut drained = stats;
        drained.flow_control.received_bytes = DELIVERED;
        tracker.finish(drained);

        assert!(totals.load(Ordering::Relaxed).wrapping_sub(before) >= DELIVERED);
        tracker.sample(stats);
        assert!(tracker.id.is_none());
    }

    #[test]
    fn send_deadline_is_bounded_by_rtt() {
        assert_eq!(
            bounded_quic_send_timeout(Duration::ZERO),
            Duration::from_secs(1)
        );
        assert_eq!(
            bounded_quic_send_timeout(Duration::from_millis(250)),
            Duration::from_secs(1)
        );
        assert_eq!(
            bounded_quic_send_timeout(Duration::from_secs(2)),
            Duration::from_secs(5)
        );
        assert_eq!(elapsed_since_millis(20_000, 0), Duration::ZERO);
        assert_eq!(
            elapsed_since_millis(20_000, 19_990),
            Duration::from_millis(10)
        );
    }

    #[test]
    fn repeated_timeouts_or_long_silence_retire() {
        assert!(!should_retire_path(
            Duration::from_secs(3),
            Duration::from_secs(10),
            PATH_TIMEOUT_STREAK,
            0,
            Duration::from_secs(4),
            Duration::from_secs(10),
        ));
        assert!(should_retire_path(
            Duration::from_secs(4),
            Duration::ZERO,
            PATH_TIMEOUT_STREAK,
            0,
            Duration::from_secs(4),
            Duration::from_secs(10),
        ));
        assert!(!should_retire_path(
            Duration::from_secs(10),
            Duration::from_secs(10),
            0,
            1,
            Duration::from_secs(4),
            Duration::from_secs(10),
        ));
        assert!(should_retire_path(
            Duration::ZERO,
            Duration::from_secs(10),
            0,
            PATH_MIN_UNACKED_SENDS,
            Duration::from_secs(4),
            Duration::from_secs(10),
        ));
    }
    #[test]
    fn ack_progress_clears_wait_and_stale_completion_cannot_rearm() {
        let h = health(3, 0, 2, 42);
        assert!(h.note_ack_progress(4));
        assert!(!h.complete_send(QuicSendToken::new(0, 3, 3, 10), SendCompletion::Timeout, 4,));
        assert_eq!(h.ack_state.load(Ordering::Acquire) & PATH_WAITING, 0);
        assert_eq!(
            timeout_state_streak(h.timeout_state.load(Ordering::Acquire)),
            0
        );
    }

    #[test]
    fn historical_losses_do_not_count_as_current_unacked_sends() {
        let h = health(95, 0, 0, 0);
        h.sampled_sent_ack_eliciting_packets
            .store(100, Ordering::Release);
        assert!(h.complete_send(
            QuicSendToken::new(0, 95, 100, 10),
            SendCompletion::Timeout,
            95,
        ));
        h.sampled_sent_ack_eliciting_packets
            .store(101, Ordering::Release);
        assert_eq!(h.unacked_sends_since_wait(), 1);
        assert!(!should_retire_path(
            Duration::from_secs(10),
            Duration::from_secs(10),
            0,
            h.unacked_sends_since_wait(),
            Duration::from_secs(4),
            Duration::from_secs(10),
        ));
    }

    #[test]
    fn timeout_streak_is_scoped_to_ack_epoch() {
        let h = health(0, 0, 0, 0);
        assert!(h.complete_send(QuicSendToken::new(0, 0, 0, 10), SendCompletion::Timeout, 0,));
        assert!(h.complete_send(QuicSendToken::new(0, 0, 0, 20), SendCompletion::Timeout, 0,));
        assert_eq!(
            timeout_state_streak(h.timeout_state.load(Ordering::Acquire)),
            2
        );
        assert_ne!(h.ack_state.load(Ordering::Acquire) & PATH_WAITING, 0);
    }

    #[test]
    fn concurrent_send_completion_keeps_earliest_baseline() {
        let h = health(0, 0, 0, 0);
        assert!(h.complete_send(
            QuicSendToken::new(0, 0, 20, 200),
            SendCompletion::Success,
            0,
        ));
        assert!(h.complete_send(
            QuicSendToken::new(0, 0, 10, 100),
            SendCompletion::Success,
            0,
        ));
        h.sampled_sent_ack_eliciting_packets
            .store(20, Ordering::Release);
        assert_eq!(h.waiting_sent_baseline.load(Ordering::Acquire), 10);
        assert_eq!(h.waiting_since_ms.load(Ordering::Acquire), 100);
        assert_eq!(h.unacked_sends_since_wait(), 10);
    }

    #[test]
    fn successful_send_preserves_first_stall_deadline() {
        let h = health(0, 0, 2, 42);
        assert!(h.complete_send(QuicSendToken::new(0, 0, 0, 100), SendCompletion::Success, 0,));
        assert_eq!(h.waiting_since_ms.load(Ordering::Acquire), 42);
        assert_eq!(
            timeout_state_streak(h.timeout_state.load(Ordering::Acquire)),
            0
        );
    }

    #[test]
    fn ack_progress_invalidates_all_old_send_tokens() {
        let h = health(0, 0, 0, 0);
        let token = QuicSendToken::new(0, 0, 0, 100);
        assert!(h.note_ack_progress(1));
        assert!(!h.complete_send(token, SendCompletion::Success, 1));
        assert_eq!(h.ack_state.load(Ordering::Acquire) & PATH_WAITING, 0);
    }
}
/// UDP fragment reassembly shared by the TUIC and Hysteria2 session bridges
/// (sing `udpDefragger` parity).
pub(crate) mod defrag {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    const DEFRAG_MAX_PENDING: usize = 64;
    const DEFRAG_MAX_FRAGMENTS: usize = 64;
    const DEFRAG_MAX_AGE: Duration = Duration::from_secs(10);

    struct DefragBuffer {
        frags: Vec<Option<Vec<u8>>>,
        count: usize,
        bytes: usize,
        updated: Instant,
    }

    pub(crate) struct Defragmenter {
        map: HashMap<u64, DefragBuffer>,
        latest_packet: Option<u64>,
        max_payload: usize,
    }

    impl Defragmenter {
        pub(crate) fn new(max_payload: usize) -> Self {
            Self {
                map: HashMap::new(),
                latest_packet: None,
                max_payload,
            }
        }

        fn packet_key(&mut self, packet_id: u16) -> u64 {
            let packet_id = u64::from(packet_id);
            let Some(latest) = self.latest_packet else {
                // Leave one complete cycle below the initial key for delayed fragments.
                let key = (1 << 16) | packet_id;
                self.latest_packet = Some(key);
                return key;
            };
            let base = latest & !u64::from(u16::MAX);
            let candidate = base | packet_id;
            let delta = candidate as i128 - latest as i128;
            let key = if delta > i128::from(1u64 << 15) {
                candidate.saturating_sub(1 << 16)
            } else if delta < -i128::from(1u64 << 15) {
                candidate.saturating_add(1 << 16)
            } else {
                candidate
            };
            if key > latest {
                self.latest_packet = Some(key);
            }
            key
        }

        pub(crate) fn feed(
            &mut self,
            packet_id: u16,
            frag_id: u8,
            frag_total: u8,
            data: Vec<u8>,
        ) -> Option<Vec<u8>> {
            if frag_total == 0
                || usize::from(frag_id) >= usize::from(frag_total)
                || usize::from(frag_total) > DEFRAG_MAX_FRAGMENTS
                || data.len() > self.max_payload
            {
                return None;
            }
            let packet_key = self.packet_key(packet_id);
            if frag_total == 1 {
                return Some(data);
            }
            let frag_total = usize::from(frag_total);
            if self.map.len() >= DEFRAG_MAX_PENDING && !self.map.contains_key(&packet_key) {
                self.map
                    .retain(|_, buffer| buffer.updated.elapsed() < DEFRAG_MAX_AGE);
                if self.map.len() >= DEFRAG_MAX_PENDING {
                    return None;
                }
            }
            let entry = self.map.entry(packet_key).or_insert_with(|| DefragBuffer {
                frags: (0..frag_total).map(|_| None).collect(),
                count: 0,
                bytes: 0,
                updated: Instant::now(),
            });
            if entry.frags.len() != frag_total {
                entry.frags = (0..frag_total).map(|_| None).collect();
                entry.count = 0;
                entry.bytes = 0;
            }
            let frag_id = usize::from(frag_id);
            if entry.frags[frag_id].is_some() {
                return None;
            }
            let Some(bytes) = entry.bytes.checked_add(data.len()) else {
                self.map.remove(&packet_key);
                return None;
            };
            if bytes > self.max_payload {
                self.map.remove(&packet_key);
                return None;
            }
            entry.frags[frag_id] = Some(data);
            entry.count += 1;
            entry.bytes = bytes;
            entry.updated = Instant::now();
            if entry.count != entry.frags.len() {
                return None;
            }
            let entry = self.map.remove(&packet_key).expect("entry just inserted");
            let mut data = Vec::with_capacity(entry.bytes);
            for frag in entry.frags.into_iter().flatten() {
                data.extend_from_slice(&frag);
            }
            Some(data)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn reassembly_is_bounded_and_packet_id_wrap_is_distinct() {
            let mut defrag = Defragmenter::new(4);
            assert!(defrag.feed(7, 0, 65, vec![]).is_none());
            assert!(defrag.feed(8, 0, 2, vec![1, 2, 3]).is_none());
            assert!(defrag.feed(8, 1, 2, vec![4, 5]).is_none());

            assert!(defrag.feed(0, 0, 2, vec![0]).is_none());
            assert_eq!(defrag.feed(32_767, 0, 1, vec![0]), Some(vec![0]));
            assert_eq!(defrag.feed(65_534, 0, 1, vec![0]), Some(vec![0]));
            assert_eq!(defrag.feed(1, 0, 1, vec![0]), Some(vec![0]));
            assert!(defrag.feed(0, 0, 2, vec![2]).is_none());
            assert_eq!(defrag.feed(0, 1, 2, vec![3]), Some(vec![2, 3]));
        }

        #[test]
        fn inferred_previous_cycle_ids_never_alias() {
            let mut defrag = Defragmenter::new(8);
            assert!(defrag.feed(1, 0, 2, vec![1]).is_none());
            assert!(defrag.feed(40_001, 0, 2, vec![2]).is_none());
            assert!(defrag.feed(50_001, 1, 2, vec![3]).is_none());
            assert_eq!(defrag.feed(40_001, 1, 2, vec![4]), Some(vec![2, 4]));
            assert_eq!(defrag.feed(50_001, 0, 2, vec![5]), Some(vec![5, 3]));
        }

        #[test]
        fn delayed_previous_cycle_fragments_do_not_collide() {
            let mut defrag = Defragmenter::new(8);
            assert!(defrag.feed(65_530, 0, 2, vec![1]).is_none());
            assert!(defrag.feed(100, 0, 2, vec![2]).is_none());
            assert!(defrag.feed(0, 0, 2, vec![3]).is_none());
            assert!(defrag.feed(65_500, 0, 2, vec![4]).is_none());
            assert_eq!(defrag.feed(0, 1, 2, vec![5]), Some(vec![3, 5]));
            assert_eq!(defrag.feed(65_500, 1, 2, vec![6]), Some(vec![4, 6]));
        }

        #[test]
        fn malformed_fragments_do_not_advance_packet_epoch() {
            let mut defrag = Defragmenter::new(8);
            assert_eq!(defrag.packet_key(10), (1 << 16) | 10);
            assert!(defrag.feed(65_000, 0, 65, vec![1]).is_none());
            assert_eq!(defrag.latest_packet, Some((1 << 16) | 10));
            assert!(defrag.feed(11, 0, 2, vec![2]).is_none());
            assert_eq!(defrag.feed(11, 1, 2, vec![3]), Some(vec![2, 3]));
        }
    }
}

/// Bind a non-blocking UDP socket with `SO_MARK` set so the local eBPF
/// datapath treats QUIC packets to the proxy server as control-plane traffic
/// and does not re-route them (same bypass as `util::udp_marked_bind`; QUIC
/// needs ownership of the raw socket, so it cannot reuse that helper).
///
/// Public so protocol handlers that wrap the socket themselves (Hysteria2's
/// salamander obfuscation) can reuse the same marking logic.
pub fn marked_udp_socket(ipv6: bool) -> io::Result<std::net::UdpSocket> {
    let bind_addr: SocketAddr = if ipv6 {
        "[::]:0".parse().expect("hardcoded IPv6 bind address")
    } else {
        "0.0.0.0:0".parse().expect("hardcoded IPv4 bind address")
    };
    crate::util::marked_udp_socket(bind_addr)
}

/// Create a client-only quinn [`Endpoint`] on a marked UDP socket for the
/// given address family.
///
/// The endpoint advertises `max_udp_payload_size = 1252` instead of quinn's
/// 1472: on PPPoE/tunneled last miles, larger downlink UDP datagrams are
/// silently black-holed (measured on a CN PPPoE line: ≤1260B echoes pass,
/// 1280B all lost), which kills every QUIC handshake whose ServerHello
/// flight exceeds the threshold. 1252 matches quic-go's default; going
/// lower (e.g. the RFC minimum 1200) shrinks the server's flight allowance
/// below its anti-amplification budget (3× the client Initial) and can
/// deadlock handshakes against large certificate chains.
pub fn client_endpoint(ipv6: bool) -> io::Result<Endpoint> {
    client_endpoint_with_mtu(ipv6, 1252)
}

fn clamp_quic_payload_size(mtu: u16) -> u16 {
    mtu.clamp(1200, 65527)
}

fn default_gso_enabled(max_udp_payload_size: u16) -> bool {
    max_udp_payload_size > 1252
}
const MAX_QUIC_GSO_SEGMENTS: usize = 16;

fn gso_transmit_segments(enabled: bool, kernel_max: usize) -> usize {
    if enabled {
        kernel_max.min(MAX_QUIC_GSO_SEGMENTS)
    } else {
        1
    }
}

/// [`client_endpoint`] with an explicit advertised `max_udp_payload_size`.
///
/// An explicit MTU above the conservative 1252 default opts into UDP GSO:
/// the operator has already declared that the path carries larger datagrams.
/// `HONK_QUIC_GSO=0|1` overrides that policy process-wide.
pub fn client_endpoint_with_mtu(ipv6: bool, max_udp_payload_size: u16) -> io::Result<Endpoint> {
    let max_udp_payload_size = clamp_quic_payload_size(max_udp_payload_size);
    let socket = marked_udp_socket(ipv6)?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("no async runtime available for QUIC"))?;
    let io = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
    let inner = quinn::udp::UdpSocketState::new((&*io).into())?;
    static GSO_OVERRIDE: std::sync::LazyLock<Option<bool>> = std::sync::LazyLock::new(|| {
        std::env::var("HONK_QUIC_GSO")
            .ok()
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
    });
    let gso = (*GSO_OVERRIDE).unwrap_or_else(|| default_gso_enabled(max_udp_payload_size));
    let socket = Arc::new(NoGsoUdpSocket { io, inner, gso });
    Endpoint::new_with_abstract_socket(
        endpoint_config_with_mtu(max_udp_payload_size)?,
        None,
        socket,
        runtime,
    )
}

/// EndpointConfig advertising `max_udp_payload_size` (see `client_endpoint`
/// for why 1252 is the safe default on PMTU-black-holed last miles).
pub(crate) fn endpoint_config_with_mtu(mtu: u16) -> io::Result<EndpointConfig> {
    let mut config = EndpointConfig::default();
    config
        .max_udp_payload_size(clamp_quic_payload_size(mtu))
        .map_err(io::Error::other)?;
    Ok(config)
}

/// GSO policy. The safe 1252-byte default sends one datagram per syscall,
/// dodging PPPoE uplinks that drop later segments of a GSO super-packet.
/// Explicit larger MTUs enable batches capped at 16 segments because those
/// paths have already opted out of the black-hole-safe default.
/// `HONK_QUIC_GSO=0|1` forces either mode.
///
/// This is quinn's own `runtime/tokio.rs` socket with only
/// [`max_transmit_segments`](quinn::AsyncUdpSocket::max_transmit_segments)
/// made policy-driven; ECN, GRO receives, and pktinfo stay unchanged.
#[derive(Debug)]
struct NoGsoUdpSocket {
    io: Arc<tokio::net::UdpSocket>,
    inner: quinn::udp::UdpSocketState,
    gso: bool,
}

impl quinn::AsyncUdpSocket for NoGsoUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(NoGsoUdpPoller {
            socket: Arc::clone(&self.io),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        self.io.try_io(tokio::io::Interest::WRITABLE, || {
            self.inner.send((&self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            std::task::ready!(self.io.poll_recv_ready(cx))?;
            match self.io.try_io(tokio::io::Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                Ok(res) => return Poll::Ready(Ok(res)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        gso_transmit_segments(self.gso, self.inner.max_gso_segments())
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}

#[derive(Debug)]
struct NoGsoUdpPoller {
    socket: Arc<tokio::net::UdpSocket>,
}

impl quinn::UdpPoller for NoGsoUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

/// Keeps one QUIC connection in the aggregate metrics registry until it is
/// closed or the owning pooled client drops it.
pub struct QuicConnectionMonitor {
    conn: Connection,
    tracker: Arc<SyncMutex<QuicMetricTracker>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for QuicConnectionMonitor {
    fn drop(&mut self) {
        self.task.abort();
        self.tracker.lock().finish(self.conn.stats());
    }
}

/// Register a pooled QUIC connection for one-second aggregate sampling.
pub fn monitor_quic_connection(conn: &Connection) -> QuicConnectionMonitor {
    let tracker = Arc::new(SyncMutex::new(QuicMetricTracker::default()));
    tracker.lock().sample(conn.stats());
    let task_conn = conn.clone();
    let task_tracker = Arc::clone(&tracker);
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + QUIC_SAMPLE_INTERVAL,
            QUIC_SAMPLE_INTERVAL,
        );
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = task_conn.closed() => break,
                _ = ticker.tick() => task_tracker.lock().sample(task_conn.stats()),
            }
        }
        task_tracker.lock().close(task_conn.stats());
    });
    QuicConnectionMonitor {
        conn: conn.clone(),
        tracker,
        task,
    }
}

struct QuicClientConnectionMonitor {
    conn: Connection,
    metrics_enabled: Arc<AtomicBool>,
    tracker: Arc<SyncMutex<QuicMetricTracker>>,
    task: tokio::task::JoinHandle<()>,
}

impl QuicClientConnectionMonitor {
    fn enable_metrics(&self) {
        self.metrics_enabled.store(true, Ordering::Release);
        self.tracker.lock().sample(self.conn.stats());
    }
}

impl Drop for QuicClientConnectionMonitor {
    fn drop(&mut self) {
        self.task.abort();
        self.tracker.lock().finish(self.conn.stats());
    }
}

fn spawn_quic_client_connection_monitor<C: Send + Sync + 'static>(
    conn: Connection,
    profiles: Arc<AdaptiveFlowProfiles>,
    ipv6: bool,
    owner: Weak<C>,
    metrics_enabled: bool,
) -> QuicClientConnectionMonitor {
    let family = usize::from(ipv6);
    let initial_stats = conn.stats();
    {
        let mut profiles = profiles.lock();
        let profile = &mut profiles[family];
        seed_flow_control_profile(profile, &initial_stats);
        apply_flow_control_profile(&conn, &initial_stats, profile);
    }
    let mut sampler = AdaptiveFlowSampler::new(&initial_stats, path_now_millis());
    let tracker = Arc::new(SyncMutex::new(QuicMetricTracker::default()));
    if metrics_enabled {
        tracker.lock().sample(initial_stats);
    }
    let enabled = Arc::new(AtomicBool::new(metrics_enabled));
    let task_conn = conn.clone();
    let task_tracker = Arc::clone(&tracker);
    let task_enabled = Arc::clone(&enabled);
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + QUIC_SAMPLE_INTERVAL,
            QUIC_SAMPLE_INTERVAL,
        );
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = task_conn.closed() => break,
                _ = ticker.tick() => {
                    if owner.upgrade().is_none() {
                        break;
                    }
                    let stats = task_conn.stats();
                    {
                        let mut profiles = profiles.lock();
                        let profile = &mut profiles[family];
                        sampler.observe(profile, &stats, path_now_millis());
                        apply_flow_control_profile(&task_conn, &stats, profile);
                    }
                    if task_enabled.load(Ordering::Acquire) {
                        task_tracker.lock().sample(stats);
                    }
                }
            }
        }
        let stats = task_conn.stats();
        let mut tracker = task_tracker.lock();
        if task_enabled.load(Ordering::Acquire) {
            tracker.sample(stats);
        }
        tracker.close(stats);
    });
    QuicClientConnectionMonitor {
        conn,
        metrics_enabled: enabled,
        tracker,
        task,
    }
}

struct TrackedConnection<C> {
    id: u64,
    connection: Connection,
    _endpoint: Endpoint,
    state: Weak<C>,
    monitor: Arc<QuicClientConnectionMonitor>,
}

struct State<C> {
    /// Lazily created endpoint, tagged with its address family. Recreated when
    /// the family of the resolved server address changes.
    endpoint: Option<(bool, Endpoint)>,
    conn: Option<(Connection, Arc<C>)>,
    connections: Vec<TrackedConnection<C>>,
    next_connection_id: u64,
    metrics_enabled: bool,

    /// Set by [`QuicClient::force_close`]: future dials fail instead of
    /// re-dialing into a closed client.
    closed: bool,
}

impl<C> State<C> {
    fn prune_connections(&mut self) {
        self.connections.retain(|tracked| {
            if tracked.state.upgrade().is_some() {
                return true;
            }
            if tracked.connection.close_reason().is_none() {
                tracked
                    .connection
                    .close(VarInt::from_u32(0), b"state dropped");
            }
            false
        });
    }
}

fn spawn_tracked_connection_cleanup<C: Send + Sync + 'static>(
    state: Weak<Mutex<State<C>>>,
    id: u64,
    connection: Connection,
    owner: Weak<C>,
    monitor: Arc<QuicClientConnectionMonitor>,
) {
    tokio::spawn(async move {
        let _monitor = monitor;
        let mut removed = false;
        loop {
            if owner.upgrade().is_none() {
                if connection.close_reason().is_none() {
                    connection.close(VarInt::from_u32(0), b"state dropped");
                }
                break;
            }
            tokio::select! {
                _ = connection.closed(), if !removed => {
                    if let Some(state) = state.upgrade() {
                        let mut state = state.lock().await;
                        state.connections.retain(|tracked| tracked.id != id);
                    }
                    removed = true;
                }
                _ = tokio::time::sleep(QUIC_SAMPLE_INTERVAL) => {}
            }
        }
        if !removed && let Some(state) = state.upgrade() {
            let mut state = state.lock().await;
            state.connections.retain(|tracked| tracked.id != id);
        }
    });
}

struct ConnectionCloseGuard(Option<Connection>);

impl ConnectionCloseGuard {
    fn new(conn: Connection) -> Self {
        Self(Some(conn))
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ConnectionCloseGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.0.take() {
            conn.close(VarInt::from_u32(0), b"connection setup cancelled");
        }
    }
}

/// Per-server QUIC connection holder.
///
/// Keeps at most one active QUIC connection to the server and re-dials on
/// demand (first use, connection loss, or explicit [`QuicClient::invalidate`]).
/// **Rotation overlaps by construction**: a flow owns its `(Connection,
/// Arc<C>)` pair, so when the holder detects the connection's close reason
/// and dials a fresh one, in-flight streams/datagram flows finish on the
/// old connection while new flows land on the new one — one Active plus
/// one draining, without a hard cut. The generic `C` is the
/// protocol-specific per-connection state (demux maps, background task
/// handles, ...), built by the `setup` closure inside the single-flight
/// critical section so concurrent dialers share exactly one handshake.
pub struct QuicClient<C> {
    server_host: String,
    server_port: u16,
    server_name: String,
    config: ClientConfig,
    /// Optional custom endpoint constructor, called with the address family
    /// (`true` = IPv6) of the resolved server address. Hysteria2 uses this to
    /// run QUIC over a salamander-obfuscated socket; when unset the plain
    /// marked socket from [`client_endpoint`] is used.
    endpoint_factory: Option<Arc<dyn Fn(bool) -> io::Result<Endpoint> + Send + Sync>>,
    /// Advertised `max_udp_payload_size` cap for the default endpoint (see
    /// [`client_endpoint`] for the safe 1252 default).
    mtu: u16,
    flow_control_profiles: Arc<AdaptiveFlowProfiles>,
    state: Arc<Mutex<State<C>>>,
}
impl<C: Send + Sync + 'static> QuicClient<C> {
    pub fn new(
        server_host: impl Into<String>,
        server_port: u16,
        server_name: impl Into<String>,
        config: ClientConfig,
    ) -> Self {
        Self {
            server_host: server_host.into(),
            server_port,
            server_name: server_name.into(),
            config,
            endpoint_factory: None,
            mtu: 1252,
            flow_control_profiles: Arc::new(AdaptiveFlowProfiles::default()),
            state: Arc::new(Mutex::new(State {
                endpoint: None,
                conn: None,
                connections: Vec::new(),
                next_connection_id: 1,
                metrics_enabled: false,
                closed: false,
            })),
        }
    }

    pub(crate) fn with_flow_control_profiles(
        mut self,
        profiles: Option<Arc<AdaptiveFlowProfiles>>,
    ) -> Self {
        if let Some(profiles) = profiles {
            self.flow_control_profiles = profiles;
        }
        self
    }

    /// Advertise a larger `max_udp_payload_size` on paths known to carry it
    /// (anything but PMTU-black-holed last miles — see [`client_endpoint`]).
    /// Larger datagrams directly lower the per-packet processing cost that
    /// caps single-connection QUIC throughput (~180k pps at 1252B).
    pub fn with_max_udp_payload_size(mut self, mtu: u16) -> Self {
        self.mtu = clamp_quic_payload_size(mtu);
        self
    }

    /// Use a custom endpoint constructor instead of [`client_endpoint`] (see
    /// the field docs). The factory is called once per address family and the
    /// resulting endpoint is cached like the default one.
    pub fn with_endpoint_factory(
        mut self,
        factory: impl Fn(bool) -> io::Result<Endpoint> + Send + Sync + 'static,
    ) -> Self {
        self.endpoint_factory = Some(Arc::new(factory));
        self
    }
    pub(crate) async fn enable_metrics(&self)
    where
        C: QuicConnState,
    {
        let mut state = self.state.lock().await;
        state.metrics_enabled = true;
        for tracked in &state.connections {
            tracked.monitor.enable_metrics();
            if let Some(ctx) = tracked.state.upgrade() {
                ctx.enable_telemetry();
            }
        }
    }

    /// Return the shared connection (plus its protocol state), dialing and
    /// running `setup` first when there is no live connection.
    ///
    /// Resolved server addresses are raced until one completes the QUIC
    /// handshake; protocol setup runs exactly once for that winner.
    pub async fn connection_with<F, Fut>(
        &self,
        connect_timeout: Duration,
        setup: F,
    ) -> anyhow::Result<(Connection, Arc<C>)>
    where
        F: FnOnce(Connection) -> Fut,
        Fut: Future<Output = anyhow::Result<C>>,
    {
        self.connection_with_inner(connect_timeout, setup, |_, _| {})
            .await
    }

    pub(crate) async fn connection_with_metrics<F, Fut>(
        &self,
        connect_timeout: Duration,
        setup: F,
    ) -> anyhow::Result<(Connection, Arc<C>)>
    where
        C: QuicConnState,
        F: FnOnce(Connection) -> Fut,
        Fut: Future<Output = anyhow::Result<C>>,
    {
        self.connection_with_inner(connect_timeout, setup, |ctx, _| {
            ctx.enable_telemetry();
        })
        .await
    }

    async fn connection_with_inner<F, Fut, H>(
        &self,
        connect_timeout: Duration,
        setup: F,
        mut on_publish: H,
    ) -> anyhow::Result<(Connection, Arc<C>)>
    where
        F: FnOnce(Connection) -> Fut,
        Fut: Future<Output = anyhow::Result<C>>,
        H: FnMut(&C, &Connection),
    {
        let mut state = self.state.lock().await;
        if state.closed {
            anyhow::bail!("QUIC client is closed");
        }
        state.prune_connections();
        if let Some((conn, ctx)) = &state.conn
            && conn.close_reason().is_none()
        {
            if state.metrics_enabled {
                on_publish(ctx.as_ref(), conn);
            }
            return Ok((conn.clone(), Arc::clone(ctx)));
        }
        state.conn = None;

        let host = format!("{}:{}", self.server_host, self.server_port);
        let addrs: Vec<SocketAddr> = crate::bootstrap::resolve(&self.server_host)
            .await
            .with_context(|| format!("resolve {host}"))?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.server_port))
            .collect();
        if addrs.is_empty() {
            anyhow::bail!("resolve {host}: no addresses");
        }

        let cached_endpoint = state
            .endpoint
            .as_ref()
            .map(|(ipv6, endpoint)| (*ipv6, endpoint.clone()));
        let raced = crate::address_race::race_resolved_addrs(&addrs, |server_addr| {
            let ipv6 = server_addr.is_ipv6();
            let dial_config = self.config.clone();
            let endpoint = cached_endpoint
                .as_ref()
                .filter(|(cached_ipv6, _)| *cached_ipv6 == ipv6)
                .map(|(_, endpoint)| endpoint.clone());
            async move {
                let endpoint = match endpoint {
                    Some(endpoint) => endpoint,
                    None => match &self.endpoint_factory {
                        Some(factory) => factory(ipv6),
                        None => client_endpoint_with_mtu(ipv6, self.mtu),
                    }
                    .with_context(|| format!("create QUIC endpoint (ipv6={ipv6})"))?,
                };
                let mut last_error = None;
                // Keep retries inside one address job: the shared scheduler
                // races addresses for this node, never protocol attempts or nodes.
                for attempt in 1..=3u8 {
                    let connecting = match endpoint.connect_with(
                        dial_config.clone(),
                        server_addr,
                        &self.server_name,
                    ) {
                        Ok(connecting) => connecting,
                        Err(error) => return Err(error.into()),
                    };
                    match tokio::time::timeout(connect_timeout, connecting).await {
                        Err(_) => {
                            last_error = Some(anyhow!(
                                "QUIC connect to {server_addr} timed out (attempt {attempt})"
                            ));
                        }
                        Ok(Err(error)) => {
                            last_error = Some(anyhow!(
                                "QUIC connect to {server_addr}: {error} (attempt {attempt})"
                            ));
                        }
                        Ok(Ok(connection)) => return Ok((connection, endpoint, ipv6)),
                    }
                }
                Err(last_error.unwrap_or_else(|| anyhow!("QUIC connect to {server_addr} failed")))
            }
        })
        .await;
        let (conn, endpoint, ipv6) = match raced {
            Some(result) => result?,
            None => anyhow::bail!("resolve {host}: no addresses"),
        };
        state.endpoint = Some((ipv6, endpoint.clone()));
        let mut close_guard = ConnectionCloseGuard::new(conn.clone());
        let ctx = match setup(conn.clone()).await {
            Ok(ctx) => ctx,
            Err(error) => {
                close_guard.disarm();
                conn.close(VarInt::from_u32(0), b"setup failed");
                return Err(error);
            }
        };
        let ctx = Arc::new(ctx);
        // The single-flight mutex makes this unreachable today; keep the
        // freshly dialed connection out of a closed client if that changes.
        if state.closed {
            anyhow::bail!("QUIC client closed during dial");
        }
        if state.metrics_enabled {
            on_publish(ctx.as_ref(), &conn);
        }
        close_guard.disarm();
        let id = state.next_connection_id;
        state.next_connection_id = state.next_connection_id.wrapping_add(1).max(1);
        let owner = Arc::downgrade(&ctx);
        let monitor = Arc::new(spawn_quic_client_connection_monitor(
            conn.clone(),
            Arc::clone(&self.flow_control_profiles),
            ipv6,
            owner.clone(),
            state.metrics_enabled,
        ));
        state.connections.push(TrackedConnection {
            id,
            connection: conn.clone(),
            _endpoint: endpoint.clone(),
            state: owner.clone(),
            monitor: Arc::clone(&monitor),
        });
        spawn_tracked_connection_cleanup(
            Arc::downgrade(&self.state),
            id,
            conn.clone(),
            owner,
            monitor,
        );
        state.conn = Some((conn.clone(), Arc::clone(&ctx)));
        Ok((conn, ctx))
    }

    /// Drop the cached connection if it is `conn`, forcing the next
    /// [`connection_with`](Self::connection_with) call to re-dial. Used when a
    /// stream operation fails on a half-dead connection.
    pub async fn invalidate(&self, conn: &Connection) {
        let mut state = self.state.lock().await;
        if let Some((cached, _)) = &state.conn
            && cached.stable_id() == conn.stable_id()
        {
            state.conn = None;
        }
        state.prune_connections();
    }

    /// Release the reusable holder without closing flows that already own
    /// connection/state clones. A later dial may rebuild this client.
    pub async fn release_cached(&self) {
        let mut state = self.state.lock().await;
        state.conn = None;
        state.endpoint = None;
        state.prune_connections();
    }

    /// Close the cached connection and endpoint, terminating every flow that
    /// still owns a connection clone, and reject future dials. Awaits an
    /// in-flight dial's single-flight section so its late connection is also
    /// closed; a try-lock skip would leak that connection and endpoint driver.
    pub async fn force_close(&self) {
        let mut state = self.state.lock().await;
        state.closed = true;
        state.conn = None;
        for tracked in state.connections.drain(..) {
            tracked
                .connection
                .close(VarInt::from_u32(0), b"generation shutdown");
        }
        if let Some((_, endpoint)) = state.endpoint.take() {
            endpoint.close(VarInt::from_u32(0), b"generation shutdown");
        }
    }
}

/// A QUIC bidirectional stream as a single `AsyncRead + AsyncWrite` object.
///
/// Dropping the send half finishes the stream (sends FIN), which is what the
/// relay's half-close semantics rely on. The [`StreamDropGuard`] lets the
/// owning protocol track open-stream counts (for idle connection reaping)
/// without wrapping the stream again.
pub struct QuicBiStream {
    send: SendStream,
    recv: RecvStream,
    guard: StreamDropGuard,
}

/// Fires the registered callback when dropped. Lives inside
/// [`QuicBiStream`]; users that split the stream into its raw quinn halves
/// ([`QuicBiStream::into_parts`]) keep the guard for the same lifetime
/// accounting.
pub(crate) struct StreamDropGuard(Option<Box<dyn Fn() + Send + Sync>>);

impl Drop for StreamDropGuard {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

impl std::fmt::Debug for QuicBiStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicBiStream")
            .field("send", &self.send)
            .field("recv", &self.recv)
            .finish_non_exhaustive()
    }
}

impl QuicBiStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            guard: StreamDropGuard(None),
        }
    }

    /// Register a callback fired when this stream object is dropped.
    pub fn with_on_drop(mut self, f: impl Fn() + Send + Sync + 'static) -> Self {
        self.guard.0 = Some(Box::new(f));
        self
    }

    /// Poll one cancellation-safe scatter write. `chunks` retains exactly the
    /// unsent suffix when progress is made.
    pub(crate) fn poll_write_chunks(
        &mut self,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
    ) -> Poll<io::Result<usize>> {
        use std::future::Future;

        let result = std::pin::pin!(self.send.write_chunks(chunks)).poll(cx);
        result.map(|result| {
            result
                .map(|written| written.bytes)
                .map_err(io::Error::other)
        })
    }

    /// Split into the raw quinn halves plus the drop guard (open-stream
    /// accounting) — for users that drive the halves separately, e.g. UDP
    /// session bridges.
    pub(crate) fn into_parts(self) -> (SendStream, RecvStream, StreamDropGuard) {
        (self.send, self.recv, self.guard)
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Fully-qualified calls: quinn's inherent `poll_read`/`poll_write`
        // methods (different error types) would shadow the trait methods.
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

// ---------------------------------------------------------------------------
// Shared skeletons for the TUIC / Juicity / Hysteria2 protocol handlers
// ---------------------------------------------------------------------------

/// Per-connection state shared by the QUIC proxy handlers: the activity
/// bookkeeping used by the dial retry skeleton and the idle reaper.
pub(crate) trait QuicConnState: Send + Sync + 'static {
    /// Record activity on the connection (resets the idle reaper).
    fn touch(&self);
    /// Counter of open streams/bridges on this connection.
    fn open_counter(&self) -> &Arc<AtomicUsize>;
    /// Include watchdog retirements from this connection in aggregate telemetry.
    fn enable_telemetry(&self);
}

/// TUIC-style exporter authentication (sing `clientHandshake`,
/// `client.go:197-214`): one uni stream carrying
/// `[version, 0x00, uuid(16), token(32)]` where
/// `token = TLS ExportKeyingMaterial(label = uuid, context = password, 32)`.
/// Juicity reuses the same frame with version 0x00 and keeps the stream
/// open (`finish = false`); TUIC finishes it right after the write.
///
/// There is no positive auth acknowledgement: a server that rejects the
/// credentials closes the connection, so the call waits a brief `grace`
/// period for that to surface as a dial error here instead of a stream
/// failure on the first proxied connection. Returns the auth stream.
pub(crate) async fn exporter_auth(
    conn: &Connection,
    uuid: &[u8; 16],
    password: &str,
    version: u8,
    finish: bool,
    grace: Duration,
) -> anyhow::Result<SendStream> {
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|e| anyhow!("QUIC exporter auth: TLS keying material export failed: {e:?}"))?;
    let mut auth = Vec::with_capacity(2 + 16 + 32);
    auth.push(version);
    auth.push(0x00); // CMD_AUTHENTICATE
    auth.extend_from_slice(uuid);
    auth.extend_from_slice(&token);
    let mut stream = conn
        .open_uni()
        .await
        .context("QUIC exporter auth: open authenticate stream")?;
    stream
        .write_all(&auth)
        .await
        .context("QUIC exporter auth: send authenticate")?;
    if finish {
        stream
            .finish()
            .context("QUIC exporter auth: finish authenticate stream")?;
    }
    tokio::select! {
        e = conn.closed() => Err(anyhow!("QUIC exporter auth: connection closed during authentication: {e}")),
        _ = tokio::time::sleep(grace) => Ok(stream),
    }
}

/// Per-tick callback for [`spawn_conn_reaper`] (TUIC's heartbeat datagram);
/// returning false ends the reaper loop.
type ReaperTick = Box<dyn Fn(&Connection) -> bool + Send + 'static>;

/// Spawn the idle-connection reaper shared by the QUIC protocol handlers:
/// every `interval`, close the connection when the owning protocol state was
/// dropped ("state dropped") or when it has had no open streams/bridges for
/// `idle_timeout` ("idle"). `on_tick` runs after the liveness checks (TUIC's
/// heartbeat datagram); returning false ends the loop.
pub(crate) fn spawn_conn_reaper(
    conn: Connection,
    open: Weak<AtomicUsize>,
    last_activity: Weak<AtomicU64>,
    interval: Duration,
    idle_timeout: Duration,
    on_tick: Option<ReaperTick>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if conn.close_reason().is_some() {
                break;
            }
            let (Some(open), Some(last)) = (open.upgrade(), last_activity.upgrade()) else {
                // Protocol state dropped: nothing can use this connection.
                conn.close(VarInt::from_u32(0), b"state dropped");
                break;
            };
            let idle = now_secs().saturating_sub(last.load(Ordering::Relaxed));
            if open.load(Ordering::Relaxed) == 0 && idle > idle_timeout.as_secs() {
                conn.close(VarInt::from_u32(0), b"idle");
                break;
            }
            if let Some(on_tick) = &on_tick
                && !on_tick(&conn)
            {
                break;
            }
        }
    });
}

/// Shared TCP-over-QUIC dial skeleton (TUIC/Juicity/Hysteria2). The returned
/// stream decrements the connection's open counter on drop.
pub(crate) async fn dial_quic_stream<S, Connect, Fut, Make, MakeFut>(
    client: &QuicClient<S>,
    connect: Connect,
    connect_timeout: Duration,
    make: Make,
    retryable: impl Fn(&anyhow::Error) -> bool,
    proto: &'static str,
) -> anyhow::Result<QuicBiStream>
where
    S: QuicConnState,
    Connect: Fn(Duration) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<(Connection, Arc<S>)>>,
    Make: Fn(Connection) -> MakeFut,
    MakeFut: std::future::Future<Output = anyhow::Result<(SendStream, RecvStream)>>,
{
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..2 {
        let (conn, state) = connect(connect_timeout).await?;
        state.touch();
        match make(conn.clone()).await {
            Ok((send, recv)) => {
                let open = Arc::clone(state.open_counter());
                open.fetch_add(1, Ordering::Relaxed);
                let stream_state = Arc::clone(&state);
                let stream = QuicBiStream::new(send, recv).with_on_drop(move || {
                    open.fetch_sub(1, Ordering::Relaxed);
                    let _state_kept_alive_under_this_stream = &stream_state;
                });
                return Ok(stream);
            }
            Err(e) if retryable(&e) => {
                debug!("{proto}: stream open failed (attempt {attempt}): {e}");
                client.invalidate(&conn).await;
                last_err = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.expect("loop runs at least once"))
}

#[cfg(test)]
pub(crate) mod testutil {
    //! In-process QUIC test servers: self-signed certs plus endpoint builders
    //! shared by the TUIC and Juicity handler tests.

    use std::sync::Arc;

    use anyhow::anyhow;
    use quinn::{ServerConfig, TransportConfig};

    /// Build a quinn server config with a freshly generated self-signed
    /// certificate (valid for `localhost`) and the given ALPN list.
    ///
    /// When `datagrams` is false the server does not advertise QUIC datagram
    /// support, which exercises the UDP-over-stream fallback of clients.
    pub fn server_config(alpn: &[&[u8]], datagrams: bool) -> anyhow::Result<ServerConfig> {
        server_config_with_cert(alpn, datagrams).map(|(config, _)| config)
    }

    /// [`server_config`] that also returns the leaf certificate DER (for
    /// pinSHA256 tests).
    pub fn server_config_with_cert(
        alpn: &[&[u8]],
        datagrams: bool,
    ) -> anyhow::Result<(ServerConfig, Vec<u8>)> {
        server_config_impl(alpn, datagrams, false)
    }

    /// [`server_config`] restricted to TLS 1.3 ChaCha20-Poly1305, forcing the
    /// peer onto the ChaCha20 header-protection path.
    pub fn server_config_chacha20(alpn: &[&[u8]], datagrams: bool) -> anyhow::Result<ServerConfig> {
        server_config_impl(alpn, datagrams, true).map(|(config, _)| config)
    }

    fn server_config_impl(
        alpn: &[&[u8]],
        datagrams: bool,
        chacha20_only: bool,
    ) -> anyhow::Result<(ServerConfig, Vec<u8>)> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;

        let mut provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();
        if chacha20_only {
            // ChaCha20 first so the handshake negotiates it; AES-128 stays
            // because quinn derives QUIC initial keys from it.
            provider.cipher_suites = vec![
                tokio_rustls::rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                tokio_rustls::rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ];
        }
        let mut tls_config =
            tokio_rustls::rustls::ServerConfig::builder_with_provider(provider.into())
                .with_safe_default_protocol_versions()
                .map_err(|e| anyhow!("TLS protocol versions: {e}"))?
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
                        signing_key.serialize_der().into(),
                    ),
                )
                .map_err(|e| anyhow!("TLS server config: {e}"))?;
        if chacha20_only {
            // rustls defaults to client order; honk's BoringSSL client offers
            // AES first, so the suite restriction alone is not enough.
            tls_config.ignore_client_order = true;
        }
        tls_config.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();

        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| anyhow!("rustls server config is not QUIC-compatible: {e}"))?;
        let mut config = ServerConfig::with_crypto(Arc::new(quic_crypto));
        if !datagrams {
            let mut transport = TransportConfig::default();
            transport.datagram_receive_buffer_size(None);
            config.transport_config(Arc::new(transport));
        }
        Ok((config, cert.der().to_vec()))
    }

    /// Start a QUIC server endpoint on a loopback ephemeral port.
    pub fn server_endpoint(
        alpn: &[&[u8]],
        datagrams: bool,
    ) -> anyhow::Result<(quinn::Endpoint, std::net::SocketAddr)> {
        let endpoint = quinn::Endpoint::server(
            server_config(alpn, datagrams)?,
            "127.0.0.1:0".parse().expect("hardcoded bind address"),
        )?;
        let addr = endpoint.local_addr()?;
        Ok((endpoint, addr))
    }

    /// [`server_endpoint`] restricted to ChaCha20-Poly1305.
    pub fn server_endpoint_chacha20(
        alpn: &[&[u8]],
        datagrams: bool,
    ) -> anyhow::Result<(quinn::Endpoint, std::net::SocketAddr)> {
        let endpoint = quinn::Endpoint::server(
            server_config_chacha20(alpn, datagrams)?,
            "127.0.0.1:0".parse().expect("hardcoded bind address"),
        )?;
        let addr = endpoint.local_addr()?;
        Ok((endpoint, addr))
    }
}

#[cfg(test)]
mod brutal_tests {
    use super::*;
    use congestion::ControllerFactory;

    fn controller(rate_bps: u64) -> Box<dyn congestion::Controller> {
        Arc::new(BrutalConfig::from_bps(rate_bps)).build(Instant::now(), 1200)
    }

    #[test]
    fn window_is_rate_times_rtt() {
        let cc = controller(100_000_000);
        // Initial RTT guess 333ms: BDP = 12.5e6 × 0.333 ≈ 4.16 MB.
        let w = cc.window();
        assert!((4_000_000..4_400_000).contains(&w), "window {w}");
    }

    #[test]
    fn bdp_divides_before_u64_clamp() {
        let brutal = Brutal {
            rate: 1_000_000_000_000_000,
            rtt: Duration::from_secs(1),
            mtu: 1200,
        };
        assert_eq!(brutal.bdp(), 1_000_000_000_000_000);
    }

    #[test]
    fn loss_never_shrinks_window() {
        let mut cc = controller(50_000_000);
        let before = cc.window();
        cc.on_congestion_event(Instant::now(), Instant::now(), true, 12000);
        cc.on_congestion_event(Instant::now(), Instant::now(), false, 0);
        assert_eq!(cc.window(), before);
    }
}

#[cfg(test)]
mod client_tests {
    use super::*;

    fn quic_node() -> honk_config::node::Node {
        honk_config::node::Node {
            outbound: honk_config::node::OutboundConfig::Hysteria2(Default::default()),
            ..Default::default()
        }
    }

    fn skip_verify_node() -> honk_config::node::Node {
        let mut node = quic_node();
        node.tls_mut().unwrap().skip_cert_verify = true;
        node
    }
    #[test]
    fn explicit_large_mtu_enables_gso_by_default() {
        assert!(!default_gso_enabled(1252));
        assert!(default_gso_enabled(1253));
        assert!(default_gso_enabled(1452));
    }

    #[test]
    fn gso_batches_are_bounded() {
        assert_eq!(gso_transmit_segments(false, 64), 1);
        assert_eq!(gso_transmit_segments(true, 8), 8);
        assert_eq!(gso_transmit_segments(true, 64), MAX_QUIC_GSO_SEGMENTS);
    }

    #[tokio::test]
    async fn client_config_rejects_invalid_pin() {
        let mut node = quic_node();
        node.name = "bad-pin".to_string();
        node.tls_mut().unwrap().pin_sha256 = Some("not-a-pin".to_string());
        let error = match client_config(&node, &[b"h3"], QuicClientOptions::default()).await {
            Ok(_) => panic!("invalid pin must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("invalid tls_pin_sha256"));
    }

    #[tokio::test]
    async fn real_quic_loser_connection_closes_when_fallback_wins() {
        let (first_server, first_addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        let (second_server, second_addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        let first_closed = tokio::spawn(async move {
            let connection = first_server.accept().await.unwrap().await.unwrap();
            connection.closed().await
        });
        let second_accepted =
            tokio::spawn(async move { second_server.accept().await.unwrap().await.unwrap() });
        let mut node = skip_verify_node();
        node.name = "quic-address-race".to_string();
        let config = client_config(&node, &[b"h3"], QuicClientOptions::default())
            .await
            .unwrap();
        let endpoint = client_endpoint(false).unwrap();
        let first_connection = endpoint
            .connect_with(config.clone(), first_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let mut first_connection = Some(first_connection);
        let addrs = [first_addr, second_addr];

        let winner = crate::address_race::race_resolved_addrs_with_stagger(
            &addrs,
            Duration::from_millis(20),
            |addr| {
                let held = (addr == first_addr).then(|| {
                    first_connection
                        .take()
                        .expect("first address launched once")
                });
                let endpoint = endpoint.clone();
                let config = config.clone();
                async move {
                    if let Some(connection) = held {
                        let _connection = connection;
                        return std::future::pending::<anyhow::Result<Connection>>().await;
                    }
                    Ok(endpoint.connect_with(config, addr, "localhost")?.await?)
                }
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(winner.remote_address(), second_addr);

        let second_connection = tokio::time::timeout(Duration::from_secs(1), second_accepted)
            .await
            .expect("winning QUIC handshake did not reach the server")
            .unwrap();
        let _closed = tokio::time::timeout(Duration::from_secs(1), first_closed)
            .await
            .expect("losing QUIC connection stayed open")
            .unwrap();
        winner.close(VarInt::from_u32(0), b"test complete");
        drop(second_connection);
        endpoint.close(VarInt::from_u32(0), b"test complete");
    }

    async fn test_client(port: u16) -> QuicClient<()> {
        let mut node = skip_verify_node();
        node.name = "quic-test".to_string();
        node.host = "127.0.0.1".to_string();
        node.address = format!("127.0.0.1:{port}");
        node.port = port;
        let config = client_config(&node, &[b"h3"], QuicClientOptions::default())
            .await
            .unwrap();
        QuicClient::new("127.0.0.1", port, "localhost", config)
    }

    fn spawn_accept_loop(endpoint: Endpoint) {
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let _ = incoming.await;
                });
            }
        });
    }

    #[tokio::test]
    async fn adaptive_profile_updates_live_connection_windows() {
        const MIB: u64 = 1 << 20;
        let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        let accepted = tokio::spawn({
            let endpoint = endpoint.clone();
            async move { endpoint.accept().await.unwrap().await.unwrap() }
        });
        let mut node = skip_verify_node();
        node.host = "127.0.0.1".to_string();
        node.address = format!("127.0.0.1:{}", addr.port());
        node.port = addr.port();
        let config = client_config(
            &node,
            &[b"h3"],
            QuicClientOptions {
                stream_receive_window: Some(8 * MIB),
                conn_receive_window: Some(8 * MIB),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let profiles = Arc::new(AdaptiveFlowProfiles::default());
        let client = QuicClient::new("127.0.0.1", addr.port(), "localhost", config)
            .with_flow_control_profiles(Some(Arc::clone(&profiles)));
        let (conn, state) = client
            .connection_with(Duration::from_secs(1), |_| async {
                Ok::<(), anyhow::Error>(())
            })
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&profiles, &client.flow_control_profiles));
        assert_eq!(Arc::strong_count(&profiles), 3);
        let server = accepted.await.unwrap();
        let profile = AdaptiveFlowProfile {
            connection_receive_floor: 16 * MIB,
            stream_receive_floor: 16 * MIB,
            send_floor: 20 * MIB,
            ..Default::default()
        };

        apply_flow_control_profile(&conn, &conn.stats(), &profile);
        let stats = conn.stats().flow_control;
        assert_eq!(stats.stream_receive_window, 16 * MIB);
        assert_eq!(stats.receive_window, 16 * MIB);
        assert_eq!(stats.send_window, 20 * MIB);
        drop(client);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(Arc::strong_count(&profiles), 2);
        drop(state);
        tokio::time::timeout(Duration::from_secs(2), async {
            while Arc::strong_count(&profiles) != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("adaptive monitor outlived its flow state");

        conn.close(VarInt::from_u32(0), b"test complete");
        endpoint.close(VarInt::from_u32(0), b"test complete");
        drop(server);
    }

    #[tokio::test]
    async fn closed_connection_tracking_is_pruned_while_flow_state_lives() {
        let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        let accepted = tokio::spawn({
            let endpoint = endpoint.clone();
            async move { endpoint.accept().await.unwrap().await.unwrap() }
        });
        let client = test_client(addr.port()).await;
        let (conn, flow_state) = client
            .connection_with(Duration::from_secs(1), |_| async {
                Ok::<(), anyhow::Error>(())
            })
            .await
            .unwrap();
        let server = accepted.await.unwrap();
        assert_eq!(client.state.lock().await.connections.len(), 1);

        conn.close(VarInt::from_u32(0), b"test complete");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if client.state.lock().await.connections.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("closed connection remained in client tracking");

        drop(flow_state);
        client.force_close().await;
        endpoint.close(VarInt::from_u32(0), b"test complete");
        drop(server);
    }

    #[tokio::test]
    async fn dead_warm_quic_reconnect_waits_for_limit_one() {
        let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        let client = Arc::new(test_client(addr.port()).await);
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
                .unwrap()
                .0,
        );
        let first_accept = tokio::spawn({
            let endpoint = endpoint.clone();
            async move { endpoint.accept().await.unwrap().await.unwrap() }
        });
        let (first, _) = generation
            .scope_dials(client.connection_with(Duration::from_secs(1), |_| async {
                Ok::<(), anyhow::Error>(())
            }))
            .await
            .unwrap();
        let first_server = first_accept.await.unwrap();
        first.close(VarInt::from_u32(0), b"replace");
        client.invalidate(&first).await;

        let held = generation.acquire_dial_permit().await;
        let reconnect = tokio::spawn({
            let client = Arc::clone(&client);
            let generation = Arc::clone(&generation);
            async move {
                generation
                    .scope_dials(client.connection_with(Duration::from_secs(1), |_| async {
                        Ok::<(), anyhow::Error>(())
                    }))
                    .await
            }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), endpoint.accept())
                .await
                .is_err(),
            "dead cached QUIC reconnect bypassed the physical dial limit"
        );

        drop(held);
        let incoming = tokio::time::timeout(Duration::from_secs(1), endpoint.accept())
            .await
            .expect("admitted QUIC reconnect sent no Initial")
            .expect("server endpoint closed");
        let second_accept = tokio::spawn(async move { incoming.await.unwrap() });
        let (second, _) = tokio::time::timeout(Duration::from_secs(1), reconnect)
            .await
            .expect("admitted QUIC reconnect did not finish")
            .unwrap()
            .unwrap();
        let second_server = second_accept.await.unwrap();

        second.close(VarInt::from_u32(0), b"test complete");
        client.force_close().await;
        endpoint.close(VarInt::from_u32(0), b"test complete");
        drop((first_server, second_server));
    }

    #[tokio::test]
    async fn force_close_covers_connection_cached_by_in_flight_dial() {
        let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        spawn_accept_loop(endpoint);
        let client = Arc::new(test_client(addr.port()).await);

        // Park the dial inside its setup closure: it holds the single-flight
        // state lock with the handshake already completed.
        let (setup_entered, entered) = tokio::sync::oneshot::channel::<()>();
        let (release_setup, release) = tokio::sync::oneshot::channel::<()>();
        let dial = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                client
                    .connection_with(Duration::from_secs(5), move |_conn| async move {
                        let _ = setup_entered.send(());
                        let _ = release.await;
                        Ok::<(), anyhow::Error>(())
                    })
                    .await
            }
        });
        entered.await.unwrap();

        let closer = tokio::spawn({
            let client = Arc::clone(&client);
            async move { client.force_close().await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !closer.is_finished(),
            "force_close must wait out the in-flight dial"
        );

        let _ = release_setup.send(());
        let (conn, _) = dial.await.unwrap().unwrap();
        closer.await.unwrap();
        assert!(
            conn.close_reason().is_some(),
            "a connection cached just before the close must still be closed"
        );
        assert!(
            client
                .connection_with(Duration::from_secs(1), |_conn| async {
                    Ok::<(), anyhow::Error>(())
                })
                .await
                .is_err(),
            "a closed client rejects new dials"
        );
    }

    #[tokio::test]
    async fn release_cached_keeps_client_reusable_for_a_fresh_connection() {
        let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        spawn_accept_loop(endpoint);
        let client = test_client(addr.port()).await;
        let (first, _) = client
            .connection_with(Duration::from_secs(5), |_conn| async {
                Ok::<(), anyhow::Error>(())
            })
            .await
            .unwrap();

        client.release_cached().await;
        let state = client.state.lock().await;
        assert!(state.conn.is_none());
        assert!(!state.closed);
        drop(state);

        let (second, _) = client
            .connection_with(Duration::from_secs(5), |_conn| async {
                Ok::<(), anyhow::Error>(())
            })
            .await
            .unwrap();
        assert_ne!(first.stable_id(), second.stable_id());
        client.force_close().await;
        assert!(first.close_reason().is_some());
        assert!(second.close_reason().is_some());
    }

    /// A cold-node health probe dials QUIC through an ephemeral runtime;
    /// closing it must deterministically close the cached connection and
    /// endpoint driver (drop-alone is not relied upon).
    struct ProbeClient(QuicClient<()>);
    #[async_trait::async_trait]
    impl crate::runtime::QuicRuntimeClient for ProbeClient {
        fn into_erased(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
            self
        }
        async fn force_close(&self) {
            self.0.force_close().await;
        }
        async fn release_warm(&self) {
            self.0.release_cached().await;
        }
    }

    fn tuic_ephemeral() -> Arc<crate::runtime::NodeRuntime> {
        crate::runtime::NodeRuntime::ephemeral(&honk_config::node::Node {
            outbound: honk_config::node::OutboundConfig::Tuic(Default::default()),
            ..Default::default()
        })
    }

    async fn probe_client(
        runtime: &crate::runtime::NodeRuntime,
        port: u16,
    ) -> (Arc<ProbeClient>, quinn::Connection) {
        let crate::runtime::ProtocolRuntime::Quic(quic) = &runtime.runtime else {
            panic!("tuic runtime expected");
        };
        let client: Arc<ProbeClient> = quic
            .client(|| async { Ok(Arc::new(ProbeClient(test_client(port).await))) })
            .await
            .unwrap();
        let (conn, _) = client
            .0
            .connection_with(Duration::from_secs(5), |_conn| async {
                Ok::<(), anyhow::Error>(())
            })
            .await
            .unwrap();
        (client, conn)
    }

    #[tokio::test]
    async fn ephemeral_runtime_close_shuts_quic_client() {
        let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        spawn_accept_loop(endpoint);
        let runtime = tuic_ephemeral();
        let (_client, conn) = probe_client(&runtime, addr.port()).await;
        assert!(conn.close_reason().is_none());
        assert!(runtime.is_warm_or_stateless());

        runtime.close().await;
        assert!(
            conn.close_reason().is_some(),
            "closing the ephemeral runtime must close the probe connection"
        );
        assert!(
            !runtime.is_warm_or_stateless(),
            "a closed runtime no longer reports warm clients"
        );
    }

    /// A probe future dropped mid-flight (outer timeout / task abort) never
    /// runs the explicit close; the guard's Drop must still close the cached
    /// connection and endpoint driver.
    #[tokio::test]
    async fn ephemeral_guard_releases_quic_client_when_probe_is_aborted() {
        use crate::runtime::NodeRuntime;

        let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        spawn_accept_loop(endpoint);
        let (conn_tx, conn_rx) = tokio::sync::oneshot::channel();
        let probe = tokio::spawn(async move {
            let guard = NodeRuntime::ephemeral_guarded(&honk_config::node::Node {
                outbound: honk_config::node::OutboundConfig::Tuic(Default::default()),
                ..Default::default()
            });
            let runtime = guard.runtime();
            let (_client, conn) = probe_client(&runtime, addr.port()).await;
            let _ = conn_tx.send(conn);
            std::future::pending::<()>().await;
        });
        let conn = conn_rx.await.unwrap();
        probe.abort();
        let _ = probe.await;

        tokio::time::timeout(Duration::from_secs(5), async {
            while conn.close_reason().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the guard Drop must drive the QUIC close after abort");
    }
}

// ---------------------------------------------------------------------------
// QUIC over a proxied UDP tunnel
// ---------------------------------------------------------------------------

use crate::proxy::{PacketErrorClass, PacketTransport, QuicSendAttempt, packet_error_class};

/// quinn [`AsyncUdpSocket`] over a framed [`PacketTransport`]: outbound
/// datagrams ride a bounded channel drained by a forwarder task (the
/// transport's async send cannot run in a poll context), while inbound
/// datagrams are accepted only from the configured QUIC peer.
const TRANSPORT_QUEUE_CAP: usize = 64;
/// A queued QUIC datagram must not wait behind a full adapter queue longer
/// than the longest per-packet send deadline.
const TRANSPORT_PACKET_MAX_AGE: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct QueuedTransportPacket {
    data: Vec<u8>,
    enqueued_at: Instant,
}

#[derive(Debug)]
struct TransportIoError {
    kind: io::ErrorKind,
    message: String,
}

impl TransportIoError {
    fn new(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    fn fatal(error: io::Error) -> Self {
        let mut error = Self::new(error);
        // Quinn deliberately ignores UDP ECONNRESET on its receive path, but
        // every worker error exposed here has already terminated the adapter.
        if error.kind == io::ErrorKind::ConnectionReset {
            error.kind = io::ErrorKind::ConnectionAborted;
        }
        error
    }

    fn to_io_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

type SharedRecvWaker = Arc<SyncMutex<Option<Waker>>>;

fn wake_recv(waker: &SharedRecvWaker) {
    let waker = waker.lock().take();
    if let Some(waker) = waker {
        waker.wake();
    }
}
type SharedTransportError = Arc<SyncMutex<Option<TransportIoError>>>;

#[derive(Debug)]
struct TransportQuinnSocket {
    remote: SocketAddr,
    outbound: tokio::sync::mpsc::Sender<QueuedTransportPacket>,
    inbound: SyncMutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    send_error: SharedTransportError,
    recv_error: SharedTransportError,
    recv_waker: SharedRecvWaker,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    metrics_enabled: bool,
}

impl TransportQuinnSocket {
    fn new(transport: Arc<dyn PacketTransport>, remote: SocketAddr) -> Arc<Self> {
        Self::new_with_metrics(transport, remote, false)
    }

    fn new_with_metrics(
        transport: Arc<dyn PacketTransport>,
        remote: SocketAddr,
        metrics_enabled: bool,
    ) -> Arc<Self> {
        let (outbound_tx, mut outbound_rx) =
            tokio::sync::mpsc::channel::<QueuedTransportPacket>(TRANSPORT_QUEUE_CAP);
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(TRANSPORT_QUEUE_CAP);
        let send_error = Arc::new(SyncMutex::new(None));
        let recv_error = Arc::new(SyncMutex::new(None));
        let recv_waker = Arc::new(SyncMutex::new(None));
        let sender = tokio::spawn({
            let transport = Arc::clone(&transport);
            let send_error = Arc::clone(&send_error);
            let recv_waker = Arc::clone(&recv_waker);
            async move {
                let mut first_datagram = true;
                while let Some(queued) = outbound_rx.recv().await {
                    if queued.enqueued_at.elapsed() >= TRANSPORT_PACKET_MAX_AGE {
                        if metrics_enabled {
                            record_transport_tx_drop();
                        }
                        continue;
                    }
                    let first = first_datagram;
                    let data = queued.data;
                    let timeout = transport.send_timeout().max(Duration::from_millis(1));
                    let attempt = QuicSendAttempt::new(transport.as_ref());
                    let result = tokio::time::timeout(timeout, async {
                        if first {
                            transport.send_packet_confirmed(&data).await
                        } else {
                            transport.send_packet(&data).await
                        }
                    })
                    .await;
                    let timed_out = match &result {
                        Err(_) => true,
                        Ok(Err(error)) => error.kind() == io::ErrorKind::TimedOut,
                        Ok(Ok(())) => false,
                    };
                    let result = match result {
                        Ok(result) => result,
                        Err(_) => Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "QUIC PacketTransport send deadline exceeded",
                        )),
                    };
                    match result {
                        Ok(()) => {
                            first_datagram = false;
                            attempt.success();
                        }
                        Err(error) => {
                            if timed_out {
                                attempt.timeout();
                            } else {
                                attempt.failure();
                            }
                            let congestion = packet_error_class(&error)
                                == PacketErrorClass::Congestion
                                || (error.kind() == io::ErrorKind::TimedOut
                                    && transport.send_timeout_is_congestion());
                            if congestion {
                                if metrics_enabled {
                                    record_transport_tx_drop();
                                }
                                continue;
                            }
                            *send_error.lock() = Some(TransportIoError::fatal(error));
                            wake_recv(&recv_waker);
                            outbound_rx.close();
                            return;
                        }
                    }
                }
            }
        });
        let allows_full_cone_replies = transport.allows_full_cone_replies();
        let receiver = tokio::spawn({
            let recv_error = Arc::clone(&recv_error);
            let recv_waker = Arc::clone(&recv_waker);
            async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let (n, source) = match transport.recv_packet(&mut buf).await {
                        Ok(packet) => packet,
                        Err(error) => {
                            *recv_error.lock() = Some(TransportIoError::fatal(error));
                            wake_recv(&recv_waker);
                            return;
                        }
                    };
                    if n == 0 {
                        continue;
                    }
                    if source != remote && !allows_full_cone_replies {
                        continue;
                    }
                    if n > buf.len() {
                        *recv_error.lock() = Some(TransportIoError::fatal(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "PacketTransport returned a datagram larger than its receive buffer",
                        )));
                        wake_recv(&recv_waker);
                        return;
                    }
                    // A full queue drops the datagram (UDP semantics); the
                    // transport read must never backpressure or allocate for a drop.
                    match inbound_tx.try_reserve() {
                        Ok(permit) => permit.send(buf[..n].to_vec()),
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            if metrics_enabled {
                                record_transport_rx_drop();
                            }
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            *recv_error.lock() = Some(TransportIoError::fatal(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "QUIC adapter receive queue closed",
                            )));
                            wake_recv(&recv_waker);
                            return;
                        }
                    }
                }
            }
        });
        Arc::new(Self {
            remote,
            outbound: outbound_tx,
            inbound: SyncMutex::new(inbound_rx),
            send_error,
            recv_error,
            recv_waker,
            tasks: Mutex::new(vec![sender, receiver]),
            metrics_enabled,
        })
    }

    fn send_error(&self) -> Option<io::Error> {
        self.send_error
            .lock()
            .as_ref()
            .map(TransportIoError::to_io_error)
    }

    fn recv_error(&self) -> Option<io::Error> {
        self.recv_error
            .lock()
            .as_ref()
            .map(TransportIoError::to_io_error)
    }

    fn terminal_error(&self) -> Option<io::Error> {
        self.recv_error().or_else(|| self.send_error())
    }

    async fn close_tasks(&self) {
        let mut tasks = self.tasks.lock().await;
        for task in tasks.iter() {
            task.abort();
        }
        for task in tasks.iter_mut() {
            let _ = task.await;
        }
        tasks.clear();
    }
}

impl Drop for TransportQuinnSocket {
    fn drop(&mut self) {
        for task in self.tasks.get_mut().drain(..) {
            task.abort();
        }
    }
}

type TransportSendPermit = Result<
    tokio::sync::mpsc::OwnedPermit<QueuedTransportPacket>,
    tokio::sync::mpsc::error::SendError<()>,
>;

struct TransportUdpPoller {
    socket: Arc<TransportQuinnSocket>,
    writable: SyncMutex<Option<Pin<Box<dyn Future<Output = TransportSendPermit> + Send>>>>,
}

impl std::fmt::Debug for TransportUdpPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportUdpPoller").finish_non_exhaustive()
    }
}

impl quinn::UdpPoller for TransportUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.socket.send_error() {
            *this.writable.lock() = None;
            return Poll::Ready(Err(error));
        }

        let mut writable = this.writable.lock();
        if writable.is_none() {
            *writable = Some(Box::pin(this.socket.outbound.clone().reserve_owned()));
        }
        match writable.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(permit)) => {
                drop(permit);
                *writable = None;
                Poll::Ready(this.socket.send_error().map_or(Ok(()), Err))
            }
            Poll::Ready(Err(_)) => {
                *writable = None;
                Poll::Ready(Err(this
                    .socket
                    .send_error()
                    .unwrap_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))))
            }
        }
    }
}
impl quinn::AsyncUdpSocket for TransportQuinnSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(TransportUdpPoller {
            socket: self,
            writable: SyncMutex::new(None),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        if transmit.destination != self.remote {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PacketTransport QUIC destination does not match its peer",
            ));
        }
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PacketTransport QUIC does not support segmented transmits",
            ));
        }
        if let Some(error) = self.send_error() {
            return Err(error);
        }

        match self.outbound.try_reserve() {
            Ok(permit) => {
                permit.send(QueuedTransportPacket {
                    data: transmit.contents.to_vec(),
                    enqueued_at: Instant::now(),
                });
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                if self.metrics_enabled {
                    record_transport_tx_would_block();
                }
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(self
                .send_error()
                .unwrap_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))),
        }
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = self.terminal_error() {
            return Poll::Ready(Err(error));
        }
        *self.recv_waker.lock() = Some(cx.waker().clone());
        if let Some(error) = self.terminal_error() {
            return Poll::Ready(Err(error));
        }

        let mut inbound = self.inbound.lock();
        let mut count = 0;
        for (buf, meta_slot) in bufs.iter_mut().zip(meta.iter_mut()) {
            match inbound.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    // The endpoint advertises a 1252-byte receive buffer. Never hand Quinn a
                    // truncated packet: a partial QUIC packet is indistinguishable from wire
                    // corruption. Fail the adapter so the caller can redial with a safe path.
                    if data.len() > buf.len() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "PacketTransport returned a datagram larger than the QUIC receive buffer",
                        )));
                    }
                    let len = data.len();
                    buf[..len].copy_from_slice(&data);
                    *meta_slot = quinn::udp::RecvMeta {
                        addr: self.remote,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    count += 1;
                }
                Poll::Ready(None) => {
                    return if count == 0 {
                        Poll::Ready(Err(self
                            .terminal_error()
                            .unwrap_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))))
                    } else {
                        Poll::Ready(Ok(count))
                    };
                }
                Poll::Pending => {
                    if count != 0 {
                        return Poll::Ready(Ok(count));
                    }
                    drop(inbound);
                    return if let Some(error) = self.terminal_error() {
                        Poll::Ready(Err(error))
                    } else {
                        Poll::Pending
                    };
                }
            }
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // There is no kernel socket; quinn uses this only to validate the
        // endpoint's address family.
        let ip: std::net::IpAddr = match self.remote {
            SocketAddr::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.into(),
            SocketAddr::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.into(),
        };
        Ok(SocketAddr::new(ip, 0))
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

/// Owns a client-only quinn endpoint and the bounded [`PacketTransport`]
/// adapter workers that drive it.
#[derive(Debug)]
pub struct PacketTransportEndpoint {
    endpoint: Endpoint,
    socket: Arc<TransportQuinnSocket>,
}

impl PacketTransportEndpoint {
    /// Borrow the Quinn endpoint. Keep this owner alive as long as any
    /// connection opened from it can still perform I/O.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Close the Quinn endpoint and wait up to `timeout` for it to drain.
    /// A zero timeout leaves the adapter workers alive until Quinn releases
    /// the socket; other closes abort and join them.
    pub async fn close(&self, timeout: Duration) {
        self.endpoint.close(VarInt::from_u32(0), b"shutdown");
        if timeout.is_zero() {
            return;
        }
        let _ = tokio::time::timeout(timeout, self.endpoint.wait_idle()).await;
        self.socket.close_tasks().await;
    }
}

/// Create a [`PacketTransportEndpoint`] pinned to `remote` with the safe
/// 1252-byte UDP payload cap. Metrics are disabled because this constructor is
/// also used by temporary health probes.
pub fn packet_transport_endpoint(
    transport: Arc<dyn PacketTransport>,
    remote: SocketAddr,
) -> io::Result<PacketTransportEndpoint> {
    packet_transport_endpoint_with_metrics(transport, remote, false)
}

/// Create a packet-backed endpoint whose adapter pressure counters belong to a
/// persistent pooled DNS connection.
pub fn packet_transport_endpoint_with_metrics(
    transport: Arc<dyn PacketTransport>,
    remote: SocketAddr,
    metrics_enabled: bool,
) -> io::Result<PacketTransportEndpoint> {
    if transport.relay_addr() != remote {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PacketTransport relay address does not match the QUIC peer",
        ));
    }
    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("no async runtime available for QUIC"))?;
    let socket = if metrics_enabled {
        TransportQuinnSocket::new_with_metrics(transport, remote, true)
    } else {
        TransportQuinnSocket::new(transport, remote)
    };
    let endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config_with_mtu(1252)?,
        None,
        socket.clone(),
        runtime,
    )?;
    Ok(PacketTransportEndpoint { endpoint, socket })
}

/// Establish a QUIC connection through a proxied UDP tunnel and time the
/// handshake.  This is the real QUIC liveness probe: unlike a bare
/// Version-Negotiation trigger (which many frontends ignore), it proves
/// TLS-in-QUIC reachability through the node's UDP path.  `config` comes from
/// [`client_config`] — pass a node with `skip_cert_verify` for pure liveness
/// probing.
pub async fn quic_handshake_probe(
    transport: Arc<dyn PacketTransport>,
    target: SocketAddr,
    server_name: &str,
    config: &ClientConfig,
    timeout: Duration,
) -> anyhow::Result<Duration> {
    let endpoint = packet_transport_endpoint(transport, target)?;

    let start = Instant::now();
    let connecting = endpoint
        .endpoint()
        .connect_with(config.clone(), target, server_name)
        .context("create QUIC connecting")?;
    let conn = tokio::time::timeout(timeout, connecting)
        .await
        .context("QUIC handshake timeout")??;
    let elapsed = start.elapsed();
    conn.close(quinn::VarInt::from_u32(0), b"probe");
    drop(conn);
    endpoint.close(Duration::ZERO).await;
    Ok(elapsed)
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    #[derive(Debug)]
    struct SendFailedPacketTransport;

    #[async_trait::async_trait]
    impl PacketTransport for SendFailedPacketTransport {
        fn relay_addr(&self) -> SocketAddr {
            "127.0.0.1:443".parse().unwrap()
        }

        async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::ConnectionReset))
        }

        async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    #[derive(Debug)]
    struct ReceiveFailedPacketTransport;

    #[async_trait::async_trait]
    impl PacketTransport for ReceiveFailedPacketTransport {
        fn relay_addr(&self) -> SocketAddr {
            "127.0.0.1:443".parse().unwrap()
        }

        async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }

        async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::from(io::ErrorKind::ConnectionReset))
        }
    }

    #[derive(Debug)]
    struct AdmissionPacketTransport {
        confirmed: AtomicUsize,
        ordinary: AtomicUsize,
        ordinary_sent: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl PacketTransport for AdmissionPacketTransport {
        fn relay_addr(&self) -> SocketAddr {
            "127.0.0.1:443".parse().unwrap()
        }

        async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
            self.ordinary.fetch_add(1, Ordering::SeqCst);
            self.ordinary_sent.notify_one();
            Ok(())
        }

        async fn send_packet_confirmed(&self, _data: &[u8]) -> io::Result<()> {
            self.confirmed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    #[derive(Debug)]
    struct CongestedPacketTransport {
        sends: AtomicUsize,
        sent_after_congestion: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl PacketTransport for CongestedPacketTransport {
        fn relay_addr(&self) -> SocketAddr {
            "127.0.0.1:443".parse().unwrap()
        }

        fn send_timeout_is_congestion(&self) -> bool {
            true
        }

        async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
            if self.sends.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(io::Error::from(io::ErrorKind::TimedOut))
            } else {
                self.sent_after_congestion.notify_one();
                Ok(())
            }
        }

        async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    #[derive(Debug)]
    struct SequencePacketTransport {
        remote: SocketAddr,
        packets: Mutex<std::collections::VecDeque<(Vec<u8>, SocketAddr)>>,
        full_cone: bool,
    }

    #[async_trait::async_trait]
    impl PacketTransport for SequencePacketTransport {
        fn relay_addr(&self) -> SocketAddr {
            self.remote
        }

        fn allows_full_cone_replies(&self) -> bool {
            self.full_cone
        }

        async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }

        async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let Some((packet, source)) = self.packets.lock().await.pop_front() else {
                return std::future::pending().await;
            };
            let len = packet.len().min(buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok((len, source))
        }
    }

    #[derive(Debug)]
    struct UdpPacketTransport {
        socket: tokio::net::UdpSocket,
        remote: SocketAddr,
    }

    #[async_trait::async_trait]
    impl PacketTransport for UdpPacketTransport {
        fn relay_addr(&self) -> SocketAddr {
            self.remote
        }

        async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
            self.socket.send(data).await?;
            Ok(())
        }

        async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Ok((self.socket.recv(buf).await?, self.remote))
        }
    }

    #[tokio::test]
    async fn packet_transport_failures_surface() {
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let transmit = quinn::udp::Transmit {
            destination: remote,
            ecn: None,
            contents: b"initial",
            segment_size: None,
            src_ip: None,
        };
        let send_socket = TransportQuinnSocket::new(Arc::new(SendFailedPacketTransport), remote);
        quinn::AsyncUdpSocket::try_send(&*send_socket, &transmit).unwrap();

        let mut data = [0; 64];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let send_error = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| {
                let mut bufs = [std::io::IoSliceMut::new(&mut data)];
                quinn::AsyncUdpSocket::poll_recv(&*send_socket, cx, &mut bufs, &mut meta)
            }),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(send_error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(
            quinn::AsyncUdpSocket::try_send(&*send_socket, &transmit)
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionAborted
        );

        let recv_socket = TransportQuinnSocket::new(Arc::new(ReceiveFailedPacketTransport), remote);
        let recv_error = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| {
                let mut bufs = [std::io::IoSliceMut::new(&mut data)];
                quinn::AsyncUdpSocket::poll_recv(&*recv_socket, cx, &mut bufs, &mut meta)
            }),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(recv_error.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn zero_timeout_close_does_not_surface_adapter_error() {
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let endpoint = packet_transport_endpoint(
            Arc::new(AdmissionPacketTransport {
                confirmed: AtomicUsize::new(0),
                ordinary: AtomicUsize::new(0),
                ordinary_sent: tokio::sync::Notify::new(),
            }),
            remote,
        )
        .unwrap();

        endpoint.close(Duration::ZERO).await;
        tokio::task::yield_now().await;

        let mut data = [0; 1];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let receive = tokio::time::timeout(
            Duration::from_millis(10),
            std::future::poll_fn(|cx| {
                let mut bufs = [std::io::IoSliceMut::new(&mut data)];
                quinn::AsyncUdpSocket::poll_recv(&*endpoint.socket, cx, &mut bufs, &mut meta)
            }),
        )
        .await;
        assert!(
            receive.is_err(),
            "graceful close surfaced an adapter I/O error"
        );
    }

    #[tokio::test]
    async fn packet_transport_congestion_drops_only_one_datagram() {
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let transport = Arc::new(CongestedPacketTransport {
            sends: AtomicUsize::new(0),
            sent_after_congestion: tokio::sync::Notify::new(),
        });
        let socket = TransportQuinnSocket::new(transport.clone(), remote);
        for contents in [b"dropped".as_slice(), b"forwarded".as_slice()] {
            quinn::AsyncUdpSocket::try_send(
                &*socket,
                &quinn::udp::Transmit {
                    destination: remote,
                    ecn: None,
                    contents,
                    segment_size: None,
                    src_ip: None,
                },
            )
            .unwrap();
        }

        tokio::time::timeout(
            Duration::from_secs(1),
            transport.sent_after_congestion.notified(),
        )
        .await
        .unwrap();
        assert_eq!(transport.sends.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn packet_transport_confirms_only_the_first_datagram() {
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let transport = Arc::new(AdmissionPacketTransport {
            confirmed: AtomicUsize::new(0),
            ordinary: AtomicUsize::new(0),
            ordinary_sent: tokio::sync::Notify::new(),
        });
        let socket = TransportQuinnSocket::new(transport.clone(), remote);
        for contents in [b"first".as_slice(), b"second".as_slice()] {
            quinn::AsyncUdpSocket::try_send(
                &*socket,
                &quinn::udp::Transmit {
                    destination: remote,
                    ecn: None,
                    contents,
                    segment_size: None,
                    src_ip: None,
                },
            )
            .unwrap();
        }

        tokio::time::timeout(Duration::from_secs(1), transport.ordinary_sent.notified())
            .await
            .unwrap();
        assert_eq!(transport.confirmed.load(Ordering::SeqCst), 1);
        assert_eq!(transport.ordinary.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn packet_transport_socket_is_peer_pinned_and_family_matched() {
        let remote: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let wrong: SocketAddr = "[2001:db8::3]:443".parse().unwrap();
        let socket = TransportQuinnSocket::new(
            Arc::new(SequencePacketTransport {
                remote,
                full_cone: false,
                packets: Mutex::new(std::collections::VecDeque::from([
                    (b"wrong".to_vec(), wrong),
                    (vec![0x5a; 65], remote),
                ])),
            }),
            remote,
        );
        assert!(
            quinn::AsyncUdpSocket::local_addr(&*socket)
                .unwrap()
                .is_ipv6()
        );

        let error = quinn::AsyncUdpSocket::try_send(
            &*socket,
            &quinn::udp::Transmit {
                destination: wrong,
                ecn: None,
                contents: b"wrong peer",
                segment_size: None,
                src_ip: None,
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let mut data = [0u8; 64];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| {
                let mut bufs = [std::io::IoSliceMut::new(&mut data)];
                quinn::AsyncUdpSocket::poll_recv(&*socket, cx, &mut bufs, &mut meta)
            }),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn packet_transport_socket_accepts_full_cone_reply_metadata() {
        let remote: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let reply_source: SocketAddr = "[2001:db8::3]:443".parse().unwrap();
        let socket = TransportQuinnSocket::new(
            Arc::new(SequencePacketTransport {
                remote,
                packets: Mutex::new(std::collections::VecDeque::from([(
                    b"accepted".to_vec(),
                    reply_source,
                )])),
                full_cone: true,
            }),
            remote,
        );
        let mut data = [0; 64];
        let mut meta = [quinn::udp::RecvMeta::default()];

        let received = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| {
                let mut bufs = [std::io::IoSliceMut::new(&mut data)];
                quinn::AsyncUdpSocket::poll_recv(&*socket, cx, &mut bufs, &mut meta)
            }),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(received, 1);
        assert_eq!(&data[..meta[0].len], b"accepted");
        assert_eq!(meta[0].addr, remote);
    }

    #[tokio::test]
    async fn handshake_crosses_packet_transport_adapter() {
        let (server, remote) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        let server_task = tokio::spawn(async move {
            server.accept().await.unwrap().await.unwrap();
        });
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(remote).await.unwrap();
        let mut node = honk_config::node::Node {
            outbound: honk_config::node::OutboundConfig::Hysteria2(Default::default()),
            ..Default::default()
        };
        let tls = node.tls_mut().unwrap();
        tls.sni = Some("localhost".into());
        tls.skip_cert_verify = true;
        let config = client_config(&node, &[b"h3"], QuicClientOptions::default())
            .await
            .unwrap();

        quic_handshake_probe(
            Arc::new(UdpPacketTransport { socket, remote }),
            remote,
            "localhost",
            &config,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }
}
