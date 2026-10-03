use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Weak};
use std::time::Instant;

use parking_lot::Mutex as SyncMutex;
use quinn::Connection;

use crate::transport_quality::{CarrierSample, CarrierSampler, TransportQuality};

use super::flow_control::{
    AdaptiveFlowSampler, apply_flow_control_profile, seed_flow_control_profile,
};
use super::path_health::path_now_millis;
use super::{
    AdaptiveFlowProfiles, QUIC_SAMPLE_INTERVAL, QuicMetricEntry, QuicMetricTotals,
    QuicMetricTracker, QuicMetrics,
};

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

static QUIC_METRICS: LazyLock<QuicMetrics> = LazyLock::new(QuicMetrics::default);

pub(super) fn quic_metrics() -> &'static QuicMetrics {
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

impl QuicMetricTracker {
    pub(super) fn sample(&mut self, stats: quinn::ConnectionStats) {
        if self.finished || self.closed_received_bytes.is_some() {
            return;
        }
        match self.id {
            Some(id) => update_quic_connection(id, stats),
            None => self.id = Some(register_quic_connection(stats)),
        }
    }

    pub(super) fn close(&mut self, stats: quinn::ConnectionStats) {
        let Some(id) = self.id else {
            return;
        };
        if finish_quic_connection(id, stats) {
            self.closed_received_bytes = Some(stats.flow_control.received_bytes);
        }
    }

    pub(super) fn finish(&mut self, stats: quinn::ConnectionStats) {
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

pub(super) fn record_transport_tx_would_block() {
    quic_metrics()
        .totals
        .transport_tx_would_block
        .fetch_add(1, Ordering::Relaxed);
}

pub(super) fn record_transport_rx_drop() {
    quic_metrics()
        .totals
        .transport_rx_drops
        .fetch_add(1, Ordering::Relaxed);
}
pub(super) fn record_transport_tx_drop() {
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

/// Keeps one QUIC connection in the aggregate metrics registry until it is
/// closed or the owning pooled client drops it.
pub struct QuicConnectionMonitor {
    conn: Connection,
    tracker: Arc<SyncMutex<QuicMetricTracker>>,
    task: Option<tokio::task::AbortHandle>,
}

impl Drop for QuicConnectionMonitor {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        self.tracker.lock().finish(self.conn.stats());
    }
}

/// Register a pooled QUIC connection for one-second aggregate sampling.
pub fn monitor_quic_connection(conn: &Connection) -> QuicConnectionMonitor {
    let tracker = Arc::new(SyncMutex::new(QuicMetricTracker::default()));
    tracker.lock().sample(conn.stats());
    let task_conn = conn.clone();
    let task_tracker = Arc::clone(&tracker);
    let task = crate::runtime::spawn_owned(async move {
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

struct QuicCarrierPressure {
    quality: Arc<TransportQuality>,
    remote: SocketAddr,
    sampler: CarrierSampler,
}

impl QuicCarrierPressure {
    fn new(quality: Arc<TransportQuality>, mut remote: SocketAddr) -> Self {
        remote.set_ip(remote.ip().to_canonical());
        Self {
            sampler: CarrierSampler::new(Arc::clone(&quality), remote.is_ipv6()),
            quality,
            remote,
        }
    }

    fn observe(&mut self, stats: &quinn::ConnectionStats, mut remote: SocketAddr, at: Instant) {
        remote.set_ip(remote.ip().to_canonical());
        if remote != self.remote {
            self.remote = remote;
            self.sampler = CarrierSampler::new(Arc::clone(&self.quality), remote.is_ipv6());
        }
        // Confirmation and runtime admission each start a fresh carrier baseline.
        if !self.quality.is_enabled() || stats.frame_rx.handshake_done == 0 {
            self.sampler.reset();
            return;
        }
        let Some(transmitted) = stats
            .path
            .sent_packets
            .checked_sub(stats.path.sent_plpmtud_probes)
        else {
            self.sampler.reset();
            return;
        };
        self.sampler.observe(CarrierSample {
            at,
            rtt: Some(stats.path.rtt),
            acknowledged: Some(stats.path.acked_ack_eliciting_packets),
            transmitted: Some(transmitted),
            // Quinn already excludes PLPMTUD losses; do not subtract them twice.
            lost: Some(stats.path.lost_packets),
            lost_bytes: Some(stats.path.lost_bytes),
            // These are ACKed stream bytes, not all offered UDP payload bytes.
            tx_bytes: Some(stats.flow_control.sent_bytes),
            rx_bytes: Some(stats.flow_control.received_bytes),
            tx_datagrams: Some(stats.frame_tx.datagram),
            rx_datagrams: Some(stats.frame_rx.datagram),
        });
    }
}

pub(super) struct QuicClientConnectionMonitor {
    conn: Connection,
    metrics_enabled: Arc<AtomicBool>,
    tracker: Arc<SyncMutex<QuicMetricTracker>>,
    task: Option<tokio::task::AbortHandle>,
    pressure: Arc<SyncMutex<Option<QuicCarrierPressure>>>,
}

impl QuicClientConnectionMonitor {
    pub(super) fn enable_metrics(&self, quality: Arc<TransportQuality>) {
        self.metrics_enabled.store(true, Ordering::Release);
        let at = Instant::now();
        let stats = {
            let mut tracker = self.tracker.lock();
            let stats = self.conn.stats();
            tracker.sample(stats);
            stats
        };
        let mut pressure = self.pressure.lock();
        if pressure
            .as_ref()
            .is_none_or(|current| !Arc::ptr_eq(&current.quality, &quality))
        {
            let remote = self.conn.remote_address();
            let mut sampler = QuicCarrierPressure::new(quality, remote);
            sampler.observe(&stats, remote, at);
            *pressure = Some(sampler);
        }
    }
}

impl Drop for QuicClientConnectionMonitor {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        self.tracker.lock().finish(self.conn.stats());
    }
}

pub(super) fn spawn_quic_client_connection_monitor<C: Send + Sync + 'static>(
    conn: Connection,
    profiles: Arc<AdaptiveFlowProfiles>,
    ipv6: bool,
    owner: Weak<C>,
    quality: Option<Arc<TransportQuality>>,
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
    let metrics_enabled = quality.is_some();
    let pressure = Arc::new(SyncMutex::new(quality.map(|quality| {
        let remote = conn.remote_address();
        let mut sampler = QuicCarrierPressure::new(quality, remote);
        sampler.observe(&initial_stats, remote, Instant::now());
        sampler
    })));
    let tracker = Arc::new(SyncMutex::new(QuicMetricTracker::default()));
    if metrics_enabled {
        tracker.lock().sample(initial_stats);
    }
    let enabled = Arc::new(AtomicBool::new(metrics_enabled));
    let task_conn = conn.clone();
    let task_tracker = Arc::clone(&tracker);
    let task_enabled = Arc::clone(&enabled);
    let task_pressure = Arc::clone(&pressure);
    let task = crate::runtime::spawn_owned(async move {
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
                    let at = Instant::now();
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
                    if task_conn.close_reason().is_none()
                        && let Some(pressure) = task_pressure.lock().as_mut()
                    {
                        pressure.observe(&stats, task_conn.remote_address(), at);
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
        pressure,
        task,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::transport_quality::PressureReason;

    fn loss_stats(tick: u64) -> quinn::ConnectionStats {
        let mut stats = quinn::ConnectionStats::default();
        stats.frame_rx.handshake_done = 1;
        stats.path.rtt = Duration::from_millis(20);
        stats.path.acked_ack_eliciting_packets = 32 * tick;
        stats.path.sent_packets = 64 * tick;
        stats.path.sent_plpmtud_probes = 32 * tick;
        stats.path.lost_plpmtud_probes = 32 * tick;
        stats.path.lost_packets = 3 * tick;
        stats.path.lost_bytes = 3600 * tick;
        stats.frame_tx.datagram = 32 * tick;
        stats
    }

    #[test]
    fn native_datagram_pressure_excludes_probe_sends_not_probe_losses() {
        let quality = Arc::new(TransportQuality::default());
        quality.enable();
        let remote = "127.0.0.1:443".parse().unwrap();
        let mut pressure = QuicCarrierPressure::new(Arc::clone(&quality), remote);
        let now = Instant::now();
        for tick in 0..=2 {
            pressure.observe(&loss_stats(tick), remote, now + Duration::from_secs(tick));
        }
        assert!(quality.snapshot()[0].is_none());
        pressure.observe(&loss_stats(3), remote, now + Duration::from_secs(3));
        let event = quality.snapshot()[0].unwrap();
        assert_eq!(event.reason, PressureReason::Loss);
        assert_eq!(event.observed_at, now + Duration::from_secs(3));
        assert!(quality.snapshot()[1].is_none());
    }

    #[test]
    fn heartbeat_ack_and_probe_only_traffic_cannot_publish_pressure() {
        let quality = Arc::new(TransportQuality::default());
        quality.enable();
        let remote = "127.0.0.1:443".parse().unwrap();
        let mut pressure = QuicCarrierPressure::new(Arc::clone(&quality), remote);
        let now = Instant::now();
        for tick in 0..=12 {
            let mut stats = loss_stats(tick);
            // Even one tiny heartbeat each second is below the TUIC idle fence.
            stats.frame_tx.datagram = tick;
            stats.flow_control.sent_bytes = 64 * tick;
            stats.udp_tx.bytes = 65536 * tick;
            stats.frame_tx.ping = tick;
            stats.frame_rx.acks = 64 * tick;
            stats.path.rtt = Duration::from_millis(if tick < 5 { 20 } else { 80 });
            pressure.observe(&stats, remote, now + Duration::from_secs(tick));
        }
        assert!(quality.snapshot().iter().all(Option::is_none));
        for tick in 13..=24 {
            let mut stats = loss_stats(tick);
            stats.frame_tx.datagram = 12;
            stats.flow_control.sent_bytes = 64 * 12;
            stats.path.sent_packets = stats.path.sent_plpmtud_probes;
            stats.path.lost_packets = 0;
            stats.path.lost_bytes = 0;
            pressure.observe(&stats, remote, now + Duration::from_secs(tick));
        }
        assert!(quality.snapshot().iter().all(Option::is_none));
    }

    #[test]
    fn receive_only_datagrams_do_not_turn_ack_losses_into_send_pressure() {
        let quality = Arc::new(TransportQuality::default());
        quality.enable();
        let remote = "127.0.0.1:443".parse().unwrap();
        let mut pressure = QuicCarrierPressure::new(Arc::clone(&quality), remote);
        let now = Instant::now();
        for tick in 0..=8 {
            let mut stats = loss_stats(tick);
            stats.frame_tx.datagram = 0;
            stats.frame_rx.datagram = 32 * tick;
            pressure.observe(&stats, remote, now + Duration::from_secs(tick));
        }
        assert!(quality.snapshot().iter().all(Option::is_none));
    }

    #[test]
    fn activation_and_handshake_confirmation_discard_old_history() {
        let quality = Arc::new(TransportQuality::default());
        let remote = "127.0.0.1:443".parse().unwrap();
        let mut pressure = QuicCarrierPressure::new(Arc::clone(&quality), remote);
        let now = Instant::now();
        for tick in 0..=4 {
            pressure.observe(&loss_stats(tick), remote, now + Duration::from_secs(tick));
        }
        assert!(quality.snapshot()[0].is_none());
        quality.enable();
        for tick in 5..=9 {
            let mut stats = loss_stats(tick);
            stats.frame_rx.handshake_done = 0;
            pressure.observe(&stats, remote, now + Duration::from_secs(tick));
        }
        assert!(quality.snapshot()[0].is_none());
        for tick in 10..=12 {
            pressure.observe(&loss_stats(tick), remote, now + Duration::from_secs(tick));
        }
        assert!(quality.snapshot()[0].is_none());
        pressure.observe(&loss_stats(13), remote, now + Duration::from_secs(13));
        assert_eq!(
            quality.snapshot()[0].unwrap().observed_at,
            now + Duration::from_secs(13)
        );
    }

    #[test]
    fn runtime_activation_reseeds_a_confirmed_carrier() {
        let quality = Arc::new(TransportQuality::default());
        let remote = "127.0.0.1:443".parse().unwrap();
        let mut pressure = QuicCarrierPressure::new(Arc::clone(&quality), remote);
        let now = Instant::now();
        for tick in 0..=2 {
            pressure.observe(&loss_stats(tick), remote, now + Duration::from_secs(tick));
        }
        quality.enable();
        for tick in 3..=5 {
            pressure.observe(&loss_stats(tick), remote, now + Duration::from_secs(tick));
        }
        assert!(quality.snapshot()[0].is_none());
        pressure.observe(&loss_stats(6), remote, now + Duration::from_secs(6));
        assert_eq!(
            quality.snapshot()[0].unwrap().observed_at,
            now + Duration::from_secs(6)
        );
    }

    #[test]
    fn invalid_probe_send_counters_restart_the_observation_window() {
        let quality = Arc::new(TransportQuality::default());
        quality.enable();
        let remote = "127.0.0.1:443".parse().unwrap();
        let mut pressure = QuicCarrierPressure::new(Arc::clone(&quality), remote);
        let now = Instant::now();
        for tick in 0..=2 {
            pressure.observe(&loss_stats(tick), remote, now + Duration::from_secs(tick));
        }
        let mut invalid = loss_stats(3);
        invalid.path.sent_packets = invalid.path.sent_plpmtud_probes - 1;
        pressure.observe(&invalid, remote, now + Duration::from_secs(3));
        for tick in 4..=6 {
            pressure.observe(&loss_stats(tick), remote, now + Duration::from_secs(tick));
        }
        assert!(quality.snapshot()[0].is_none());
        pressure.observe(&loss_stats(7), remote, now + Duration::from_secs(7));
        assert_eq!(
            quality.snapshot()[0].unwrap().observed_at,
            now + Duration::from_secs(7)
        );
    }

    #[test]
    fn mapped_ipv4_retains_current_pressure_streak() {
        let quality = Arc::new(TransportQuality::default());
        quality.enable();
        let remote = "127.0.0.1:443".parse().unwrap();
        let mapped = "[::ffff:127.0.0.1]:443".parse().unwrap();
        let mut pressure = QuicCarrierPressure::new(Arc::clone(&quality), remote);
        let now = Instant::now();
        for tick in 0..=2 {
            pressure.observe(&loss_stats(tick), remote, now + Duration::from_secs(tick));
        }
        pressure.observe(&loss_stats(3), mapped, now + Duration::from_secs(3));
        assert_eq!(
            quality.snapshot()[0].unwrap().observed_at,
            now + Duration::from_secs(3)
        );
        assert!(quality.snapshot()[1].is_none());
    }

    #[test]
    fn peer_tuple_changes_reseed_and_switch_family() {
        let quality = Arc::new(TransportQuality::default());
        quality.enable();
        let remote = "127.0.0.1:443".parse().unwrap();
        let next_port = "127.0.0.1:444".parse().unwrap();
        let ipv6 = "[::1]:444".parse().unwrap();
        let mut pressure = QuicCarrierPressure::new(Arc::clone(&quality), remote);
        let now = Instant::now();
        for tick in 0..=2 {
            pressure.observe(&loss_stats(tick), remote, now + Duration::from_secs(tick));
        }
        for tick in 3..=5 {
            pressure.observe(
                &loss_stats(tick),
                next_port,
                now + Duration::from_secs(tick),
            );
        }
        assert!(quality.snapshot()[0].is_none());
        pressure.observe(&loss_stats(6), next_port, now + Duration::from_secs(6));
        let first = quality.snapshot()[0].unwrap().observed_at;
        assert_eq!(first, now + Duration::from_secs(6));
        for tick in 7..=9 {
            pressure.observe(&loss_stats(tick), ipv6, now + Duration::from_secs(tick));
            assert!(quality.snapshot()[1].is_none());
        }
        pressure.observe(&loss_stats(10), ipv6, now + Duration::from_secs(10));
        assert_eq!(
            quality.snapshot()[1].unwrap().observed_at,
            now + Duration::from_secs(10)
        );
        assert_eq!(quality.snapshot()[0].unwrap().observed_at, first);
    }

    #[tokio::test]
    async fn repeated_monitor_activation_preserves_current_pressure_streak() {
        use crate::quic::{self, testutil};

        let (server_endpoint, remote) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        let accepted = tokio::spawn({
            let endpoint = server_endpoint.clone();
            async move { endpoint.accept().await.unwrap().await.unwrap() }
        });
        let mut node = honk_config::node::Node {
            outbound: honk_config::node::OutboundConfig::Hysteria2(Default::default()),
            ..Default::default()
        };
        node.tls_mut().unwrap().skip_cert_verify = true;
        let config = quic::client_config(&node, &[b"h3"], quic::QuicClientOptions::default())
            .await
            .unwrap();
        let endpoint = quic::client_endpoint(false).unwrap();
        let conn = endpoint
            .connect_with(config, remote, "localhost")
            .unwrap()
            .await
            .unwrap();
        let server = accepted.await.unwrap();
        let owner = Arc::new(());
        let monitor = spawn_quic_client_connection_monitor(
            conn,
            Arc::new(AdaptiveFlowProfiles::default()),
            false,
            Arc::downgrade(&owner),
            None,
        );
        let quality = Arc::new(TransportQuality::default());
        quality.enable();
        monitor.enable_metrics(Arc::clone(&quality));
        let now = Instant::now() + Duration::from_secs(20);
        for tick in 0..=3 {
            monitor.enable_metrics(Arc::clone(&quality));
            monitor.pressure.lock().as_mut().unwrap().observe(
                &loss_stats(tick),
                remote,
                now + Duration::from_secs(tick),
            );
        }
        assert_eq!(
            quality.snapshot()[0].unwrap().observed_at,
            now + Duration::from_secs(3)
        );
        drop(monitor);
        server.close(quinn::VarInt::from_u32(0), b"test complete");
        endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
        server_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    }
}
