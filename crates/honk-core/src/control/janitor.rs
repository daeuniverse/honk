//! BPF map janitor — background task that cleans up stale eBPF map entries.
//!
//! Mirrors Go's `startConnStateJanitor` from `daed/wing/dae-core/control/control_plane.go`.
//! The janitor runs on a configurable tick interval and performs periodic cleanup
//! of conn-state, redirect tracking, cookie PID metadata, and routing handoff
//! entries.
//!
//! All swept maps are plain hashes: the kernel never evicts on its own
//! (silent LRU eviction could re-route or break live flows mid-flight), so
//! occupancy management lives here. Accepted TCP owners pin conn-state and
//! redirect metadata for their full relay lifetime; unpinned TCP ACTIVE and
//! UDP entries keep the 120-second userspace backstop, while TCP CLOSING uses
//! the datapath's strict 10-second rule. `CONN_STATE_OCCUPANCY` drives
//! conn-state pressure; auxiliary scans use their current completion and
//! coverage to accelerate cleanup when stale work or map occupancy warrants it:
//!
//! - `< 70%` full: steady sweep interval (60 s)
//! - `70–85%`: elevated interval (15 s)
//! - `>= 85%`: conn-state pressure mode — sweep every tick
//! - a bounded auxiliary scan or `>= 85%` current auxiliary coverage selects
//!   the aggressive auxiliary cadence

use super::connection::{TcpFlowKey, TcpFlowPins};
use crate::ebpf::EbpfBackend;
use honk_ebpf_common::TuplesKey;
use honk_ebpf_common::conn::{
    BpfStatsKey, ConnState, MAX_CONN_STATE_NUM, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS, TcpState,
    UDP_CONN_STATE_TIMEOUT_NS, tcp_conn_state_expired,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Janitor tick interval: 2 seconds.
const JANITOR_TICK_INTERVAL_SECS: u64 = 2;
/// Normal-mode redirect-track scan interval: 60 seconds.
const REDIRECT_STEADY_INTERVAL_SECS: u64 = 60;
/// Aggressive-mode redirect-track scan interval: 8 seconds.
const REDIRECT_PRESSURE_INTERVAL_SECS: u64 = 8;
/// Normal-mode routing-handoff scan interval: 60 seconds.
const ROUTING_HANDOFF_STEADY_SECS: u64 = 60;
/// Aggressive-mode routing-handoff scan interval: 8 seconds.
const ROUTING_HANDOFF_PRESSURE_SECS: u64 = 8;
/// Map health check interval: 5 seconds.
const HEALTH_CHECK_INTERVAL_SECS: u64 = 5;

/// Conn-state sweep interval below the elevated watermark: 60 seconds.
const CONN_STATE_STEADY_INTERVAL_SECS: u64 = 60;
/// Conn-state sweep interval between the elevated and pressure watermarks.
const CONN_STATE_ELEVATED_INTERVAL_SECS: u64 = 15;
/// Occupancy fraction of CONN_STATE_MAP that shortens the sweep interval.
const CONN_STATE_ELEVATED_WATERMARK: f64 = 0.70;
/// Occupancy fraction that latches pressure mode (sweep every tick).
const CONN_STATE_PRESSURE_WATERMARK: f64 = 0.85;

const JANITOR_MIN_SCAN_CHUNK: usize = 128;
const JANITOR_BASE_SCAN_CHUNK: usize = 256;
const JANITOR_MAX_SCAN_CHUNK: usize = 1024;
const JANITOR_DELETE_CHUNK: usize = 128;
const JANITOR_BASE_CANDIDATES: usize = 1024;
const JANITOR_MAX_CANDIDATES: usize = 4096;
const JANITOR_BASE_SCAN_BUDGET: Duration = Duration::from_millis(100);
const JANITOR_ELEVATED_SCAN_BUDGET: Duration = Duration::from_millis(150);
const JANITOR_PRESSURE_SCAN_BUDGET: Duration = Duration::from_millis(200);
const AUX_MAP_CAPACITY: usize = 65_536;
const AUX_MAP_PRESSURE_WATERMARK: f64 = 0.80;

/// Redirect track entry timeout: 120 seconds.
const REDIRECT_TRACK_TIMEOUT_NS: u64 = 120_000_000_000;
/// Cookie PID entry timeout: 600 seconds.
const COOKIE_PID_TIMEOUT_NS: u64 = 600_000_000_000;
/// Routing handoff entry timeout: 30 seconds.
const ROUTING_HANDOFF_TIMEOUT_NS: u64 = 30_000_000_000;

/// Number of consecutive ticks without conn-state overflow after which
/// pressure mode is switched off.
const PRESSURE_EXIT_ROUNDS: u32 = 3;

/// TCP protocol number in `TuplesKey::l4proto`.
const IPPROTO_TCP: u8 = 6;

/// Live CONN_STATE_MAP occupancy estimate, derived from the datapath's
/// insert/delete counters plus the janitor's own delete accounting, and
/// recalibrated against the exact entry count on every sweep.
#[derive(Debug, Default)]
struct OccupancyGauge {
    /// Cumulative entries deleted by janitor sweeps.
    janitor_deletes: u64,
    /// `exact_count - raw_estimate` recorded at the last sweep, absorbing
    /// races (e.g. a datapath delete of an entry the janitor also removed).
    drift: i64,
}

impl OccupancyGauge {
    /// Raw counter-derived occupancy before drift correction.
    fn raw_estimate(&self, inserts: u64, ebpf_deletes: u64, userspace_deletes: u64) -> i64 {
        inserts as i64
            - ebpf_deletes as i64
            - self.janitor_deletes as i64
            - userspace_deletes as i64
    }

    fn estimate(&self, inserts: u64, ebpf_deletes: u64, userspace_deletes: u64) -> u64 {
        (self.raw_estimate(inserts, ebpf_deletes, userspace_deletes) + self.drift).max(0) as u64
    }

    /// Recalibrate with the exact entry count observed during a sweep.
    fn calibrate(&mut self, exact: u64, inserts: u64, ebpf_deletes: u64, userspace_deletes: u64) {
        self.drift = exact as i64 - self.raw_estimate(inserts, ebpf_deletes, userspace_deletes);
    }

    fn note_janitor_deletes(&mut self, n: u64) {
        self.janitor_deletes += n;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ScanTuning {
    chunk: usize,
    candidates: usize,
    budget: Duration,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AuxScanResult {
    /// Number of entries removed after the bounded scan.
    deleted: u64,
    /// Entries visited; exact map cardinality only when `complete` is true.
    scanned: usize,
    /// False when the candidate or wall-clock bound stopped traversal.
    complete: bool,
}

fn aux_scan_is_pressured(scanned: usize, complete: bool) -> bool {
    !complete || scanned as f64 / AUX_MAP_CAPACITY as f64 >= CONN_STATE_PRESSURE_WATERMARK
}

fn scan_tuning(utilization: f64, previous_elapsed: Duration) -> ScanTuning {
    let (mut chunk, candidates, budget) = if utilization >= CONN_STATE_PRESSURE_WATERMARK {
        (
            JANITOR_BASE_SCAN_CHUNK * 2,
            JANITOR_MAX_CANDIDATES,
            JANITOR_PRESSURE_SCAN_BUDGET,
        )
    } else if utilization >= CONN_STATE_ELEVATED_WATERMARK {
        (
            JANITOR_BASE_SCAN_CHUNK,
            JANITOR_BASE_CANDIDATES * 2,
            JANITOR_ELEVATED_SCAN_BUDGET,
        )
    } else {
        (
            JANITOR_BASE_SCAN_CHUNK,
            JANITOR_BASE_CANDIDATES,
            JANITOR_BASE_SCAN_BUDGET,
        )
    };
    if previous_elapsed > budget {
        chunk = (chunk / 2).max(JANITOR_MIN_SCAN_CHUNK);
    } else if utilization >= CONN_STATE_ELEVATED_WATERMARK && previous_elapsed < budget / 2 {
        chunk = (chunk * 2).min(JANITOR_MAX_SCAN_CHUNK);
    }
    ScanTuning {
        chunk,
        candidates,
        budget,
    }
}

/// Tracks the pressure state of the BPF maps for adaptive cleanup intervals.
#[derive(Debug, Clone, Default)]
struct PressureState {
    /// Whether pressure mode is active (shorter scan intervals).
    active: bool,
    /// Consecutive ticks without new conn-state overflow while active.
    quiet_rounds: u32,
    /// Last observed UDP overflow counter value.
    last_udp_overflow: u64,
    /// Last observed TCP overflow counter value.
    last_tcp_overflow: u64,
}

/// The BPF map janitor.
///
/// Runs background cleanup of stale eBPF map entries to prevent map overflow
/// and memory pressure. The janitor adapts its behaviour based on map pressure.
pub struct BpfJanitor {
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    tcp_flow_pins: Arc<TcpFlowPins>,
    stop_tx: tokio::sync::watch::Sender<bool>,
}

impl BpfJanitor {
    /// Create a new janitor bound to the given eBPF backend.
    pub(super) fn new(
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        tcp_flow_pins: Arc<TcpFlowPins>,
    ) -> Self {
        let (stop_tx, _) = tokio::sync::watch::channel(false);
        Self {
            ebpf,
            tcp_flow_pins,
            stop_tx,
        }
    }

    /// Return a receiver that fires when `stop()` is called.
    pub fn stop_handle(&self) -> tokio::sync::watch::Receiver<bool> {
        self.stop_tx.subscribe()
    }

    /// Signal the janitor to stop.
    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }

    /// Spawn the janitor on a tokio task.
    ///
    /// Returns a `JoinHandle` that completes when the janitor exits.
    /// The janitor runs until `stop()` is called or the stop receiver is dropped.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        self.spawn_inner(None)
    }

    /// Spawn with a guard that reports task death to the control plane.
    pub(super) fn spawn_supervised(
        self,
        exit_guard: super::runtime::CriticalTaskExit,
    ) -> tokio::task::JoinHandle<()> {
        self.spawn_inner(Some(exit_guard))
    }

    fn spawn_inner(
        self,
        exit_guard: Option<super::runtime::CriticalTaskExit>,
    ) -> tokio::task::JoinHandle<()> {
        let mut stop_rx = self.stop_tx.subscribe();

        tokio::spawn(async move {
            let _exit_guard = exit_guard;
            let tick_duration = Duration::from_secs(JANITOR_TICK_INTERVAL_SECS);
            let mut interval = tokio::time::interval(tick_duration);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            // Skip the first immediate tick.
            interval.tick().await;

            let mut pressure = PressureState::default();
            let mut gauge = OccupancyGauge::default();
            let mut aux_scan_high_water = [0usize; 3];
            let mut aux_scan_results = [AuxScanResult {
                complete: true,
                ..AuxScanResult::default()
            }; 3];

            let mut last_aux_failures = [0u64; 3];
            let mut aux_pressure_warned = [false; 3];
            let mut last_scan_elapsed = [Duration::ZERO; 4];

            let mut last_redirect_cleanup = tokio::time::Instant::now();
            let mut last_cookie_pid_cleanup = tokio::time::Instant::now();
            let mut last_routing_handoff = tokio::time::Instant::now();
            let mut last_health_check = tokio::time::Instant::now();
            let mut last_conn_state_cleanup = tokio::time::Instant::now();

            info!(
                "BPF janitor: started (tick={}s; conn-state sweep is watermark-driven)",
                JANITOR_TICK_INTERVAL_SECS
            );

            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = stop_rx.changed() => {
                        info!("BPF janitor: received stop signal, exiting");
                        return;
                    }
                }

                if *stop_rx.borrow() {
                    info!("BPF janitor: stopping");
                    return;
                }

                let now = tokio::time::Instant::now();

                let (overflow_delta, utilization, occ_counters) = {
                    let ebpf = self.ebpf.read().await;
                    let udp = ebpf.get_bpf_stats(0).unwrap_or(None).unwrap_or(0);
                    let tcp = ebpf.get_bpf_stats(1).unwrap_or(None).unwrap_or(0);
                    let delta =
                        udp > pressure.last_udp_overflow || tcp > pressure.last_tcp_overflow;
                    pressure.last_udp_overflow = udp;
                    pressure.last_tcp_overflow = tcp;
                    let counters = ebpf.conn_state_occupancy().unwrap_or((0, 0));
                    let userspace_deletes = crate::ebpf::USERSPACE_CONN_STATE_DELETES
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let occupancy = gauge.estimate(counters.0, counters.1, userspace_deletes);
                    (
                        delta,
                        occupancy as f64 / f64::from(MAX_CONN_STATE_NUM),
                        (counters, userspace_deletes),
                    )
                };
                update_pressure_state(&mut pressure, overflow_delta, utilization);

                let aux_pressure = aux_scan_results
                    .iter()
                    .any(|result| aux_scan_is_pressured(result.scanned, result.complete));
                let redirect_interval = if pressure.active || aux_pressure {
                    Duration::from_secs(REDIRECT_PRESSURE_INTERVAL_SECS)
                } else {
                    Duration::from_secs(REDIRECT_STEADY_INTERVAL_SECS)
                };
                let routing_interval = if pressure.active || aux_pressure {
                    Duration::from_secs(ROUTING_HANDOFF_PRESSURE_SECS)
                } else {
                    Duration::from_secs(ROUTING_HANDOFF_STEADY_SECS)
                };

                let conn_state_interval = if pressure.active {
                    Duration::from_secs(JANITOR_TICK_INTERVAL_SECS)
                } else if utilization >= CONN_STATE_ELEVATED_WATERMARK {
                    Duration::from_secs(CONN_STATE_ELEVATED_INTERVAL_SECS)
                } else {
                    Duration::from_secs(CONN_STATE_STEADY_INTERVAL_SECS)
                };

                if last_conn_state_cleanup + conn_state_interval <= now {
                    let tuning = scan_tuning(utilization, last_scan_elapsed[0]);
                    let started = Instant::now();
                    let (deleted, total) = self
                        .cleanup_conn_state(&mut gauge, occ_counters, tuning)
                        .await;
                    last_scan_elapsed[0] = started.elapsed();
                    last_conn_state_cleanup = now;
                    if utilization >= CONN_STATE_ELEVATED_WATERMARK || deleted > 0 {
                        info!(
                            "BPF janitor: conn-state sweep removed {}/{} entries (occupancy ~{:.1}%)",
                            deleted,
                            total,
                            utilization * 100.0
                        );
                    }
                }
                let auxiliary_pressure_floor = if pressure.active || aux_pressure {
                    CONN_STATE_PRESSURE_WATERMARK
                } else {
                    0.0
                };

                if last_redirect_cleanup + redirect_interval <= now {
                    let utilization = (aux_scan_results[0].scanned as f64
                        / AUX_MAP_CAPACITY as f64)
                        .max(auxiliary_pressure_floor);
                    let tuning = scan_tuning(utilization, last_scan_elapsed[1]);
                    let started = Instant::now();
                    let result = self.cleanup_redirect_track(tuning).await;
                    last_scan_elapsed[1] = started.elapsed();
                    aux_scan_high_water[0] = aux_scan_high_water[0].max(result.scanned);
                    aux_scan_results[0] = result;
                    last_redirect_cleanup = now;
                }
                if last_cookie_pid_cleanup + redirect_interval <= now {
                    let utilization = (aux_scan_results[1].scanned as f64
                        / AUX_MAP_CAPACITY as f64)
                        .max(auxiliary_pressure_floor);
                    let tuning = scan_tuning(utilization, last_scan_elapsed[2]);
                    let started = Instant::now();
                    let result = self.cleanup_cookie_pid(tuning).await;
                    last_scan_elapsed[2] = started.elapsed();
                    aux_scan_high_water[1] = aux_scan_high_water[1].max(result.scanned);
                    aux_scan_results[1] = result;
                    last_cookie_pid_cleanup = now;
                }

                if last_routing_handoff + routing_interval <= now {
                    let utilization = (aux_scan_results[2].scanned as f64
                        / AUX_MAP_CAPACITY as f64)
                        .max(auxiliary_pressure_floor);
                    let tuning = scan_tuning(utilization, last_scan_elapsed[3]);
                    let started = Instant::now();
                    let result = self.cleanup_routing_handoff(tuning).await;
                    last_scan_elapsed[3] = started.elapsed();
                    aux_scan_high_water[2] = aux_scan_high_water[2].max(result.scanned);
                    aux_scan_results[2] = result;
                    last_routing_handoff = now;
                }

                if last_health_check + Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS) <= now {
                    self.check_map_health(
                        utilization,
                        aux_scan_high_water,
                        &mut last_aux_failures,
                        &mut aux_pressure_warned,
                    )
                    .await;
                    last_health_check = now;
                }
            }
        })
    }
    async fn run_blocking_read<T, F>(&self, label: &'static str, work: F) -> Option<T>
    where
        T: Send + 'static,
        F: FnOnce(&dyn EbpfBackend) -> T + Send + 'static,
    {
        let ebpf = Arc::clone(&self.ebpf);
        match tokio::task::spawn_blocking(move || {
            let ebpf = ebpf.blocking_read();
            work(ebpf.as_ref())
        })
        .await
        {
            Ok(result) => Some(result),
            Err(error) => {
                error!(%error, map = label, "BPF janitor blocking read task failed");
                None
            }
        }
    }

    async fn run_blocking_chunked_delete<T, F>(
        &self,
        label: &'static str,
        entries: Vec<T>,
        mut work: F,
    ) -> Option<anyhow::Result<u64>>
    where
        T: Send + 'static,
        F: FnMut(&mut dyn EbpfBackend, &[T]) -> anyhow::Result<u64> + Send + 'static,
    {
        let ebpf = Arc::clone(&self.ebpf);
        match tokio::task::spawn_blocking(move || {
            let mut deleted = 0u64;
            // Releasing between chunks lets queued per-flow readers run before
            // the next bounded delete batch reacquires the writer lock.
            for chunk in entries.chunks(JANITOR_DELETE_CHUNK) {
                let mut ebpf = ebpf.blocking_write();
                deleted += work(ebpf.as_mut(), chunk)?;
            }
            anyhow::Ok(deleted)
        })
        .await
        {
            Ok(result) => Some(result),
            Err(error) => {
                error!(%error, map = label, "BPF janitor blocking delete task failed");
                None
            }
        }
    }

    /// Clean up unowned conn-state entries with state-based timeouts (TCP
    /// closing: 10 s, TCP active: 120 s, UDP: 120 s). Accepted TCP owners are
    /// never eviction candidates. Returns `(deleted, total_scanned)` and
    /// recalibrates the occupancy gauge against the exact entry count.
    async fn cleanup_conn_state(
        &self,
        gauge: &mut OccupancyGauge,
        occ_counters: ((u64, u64), u64),
        tuning: ScanTuning,
    ) -> (u64, usize) {
        let now_ns = match monotonic_now_ns() {
            Ok(ns) => ns,
            Err(error) => {
                error!(%error, "BPF janitor: failed to get monotonic time");
                return (0, 0);
            }
        };
        self.cleanup_conn_state_at(now_ns, gauge, occ_counters, tuning)
            .await
    }

    async fn cleanup_conn_state_at(
        &self,
        now_ns: u64,
        gauge: &mut OccupancyGauge,
        occ_counters: ((u64, u64), u64),
        tuning: ScanTuning,
    ) -> (u64, usize) {
        let pins = Arc::clone(&self.tcp_flow_pins);
        let scanned = self
            .run_blocking_read("conn-state", move |ebpf| {
                let pinned = pins.snapshot();
                let deadline = Instant::now() + tuning.budget;
                let mut expired = Vec::<(TuplesKey, ConnState)>::with_capacity(tuning.candidates);
                let mut total = 0usize;
                let mut completed = true;
                ebpf.conn_state_for_each_chunk(tuning.chunk, &mut |chunk| {
                    total += chunk.len();
                    for (key, state) in chunk {
                        let age = now_ns.saturating_sub(state.last_seen_ns);
                        let stale = if key.l4proto == IPPROTO_TCP {
                            if pinned.contains(&TcpFlowKey::from_tuples(key)) {
                                continue;
                            }
                            tcp_conn_state_expired(state, age)
                                || (state.state != TcpState::TcpStateClosing as u8
                                    && age > TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS)
                        } else {
                            age > UDP_CONN_STATE_TIMEOUT_NS
                        };
                        if stale {
                            expired.push((*key, *state));
                        }
                    }
                    let keep_scanning =
                        expired.len() < tuning.candidates && Instant::now() < deadline;
                    completed &= keep_scanning;
                    keep_scanning
                })?;
                expired.truncate(tuning.candidates);
                anyhow::Ok((expired, total, completed))
            })
            .await;
        let Some(scanned) = scanned else {
            return (0, 0);
        };
        let (expired, total, completed) = match scanned {
            Ok(result) => result,
            Err(error) => {
                debug!(%error, "BPF janitor: conn-state scan failed");
                return (0, 0);
            }
        };
        let deleted = if expired.is_empty() {
            0
        } else {
            match self
                .run_blocking_chunked_delete("conn-state", expired, move |ebpf, entries| {
                    ebpf.conn_state_remove_if_unchanged(entries, now_ns)
                })
                .await
            {
                Some(Ok(deleted)) => deleted,
                Some(Err(error)) => {
                    debug!(%error, "BPF janitor: conn-state delete failed");
                    0
                }
                None => 0,
            }
        };
        if completed {
            let ((inserts, ebpf_deletes), userspace_deletes) = occ_counters;
            gauge.calibrate(total as u64, inserts, ebpf_deletes, userspace_deletes);
        }
        gauge.note_janitor_deletes(deleted);
        (deleted, total)
    }

    #[cfg(test)]
    pub(super) async fn cleanup_conn_state_for_test(&self, now_ns: u64) -> (u64, usize) {
        let mut gauge = OccupancyGauge::default();
        self.cleanup_conn_state_at(
            now_ns,
            &mut gauge,
            ((0, 0), 0),
            ScanTuning {
                chunk: JANITOR_MAX_SCAN_CHUNK,
                candidates: JANITOR_MAX_CANDIDATES,
                budget: Duration::from_secs(1),
            },
        )
        .await
    }

    /// Clean up stale redirect track entries.
    async fn cleanup_redirect_track(&self, tuning: ScanTuning) -> AuxScanResult {
        let now_ns = match monotonic_now_ns() {
            Ok(ns) => ns,
            Err(error) => {
                error!(%error, "BPF janitor: failed to get monotonic time");
                return AuxScanResult::default();
            }
        };
        self.cleanup_redirect_track_at(now_ns, tuning).await
    }

    async fn cleanup_redirect_track_at(&self, now_ns: u64, tuning: ScanTuning) -> AuxScanResult {
        let pins = Arc::clone(&self.tcp_flow_pins);
        let scanned = self
            .run_blocking_read("redirect-track", move |ebpf| {
                let pinned = pins.snapshot();
                let deadline = Instant::now() + tuning.budget;
                let mut expired = Vec::with_capacity(tuning.candidates);
                let mut total = 0usize;
                let mut complete = true;
                ebpf.redirect_track_for_each_chunk(tuning.chunk, &mut |chunk| {
                    total += chunk.len();
                    for (key, entry) in chunk {
                        if key.l4proto == IPPROTO_TCP
                            && pinned.contains(&TcpFlowKey::from_redirect(key))
                        {
                            continue;
                        }
                        if now_ns.saturating_sub(entry.last_seen_ns) > REDIRECT_TRACK_TIMEOUT_NS {
                            expired.push((*key, *entry));
                        }
                    }
                    complete = expired.len() < tuning.candidates && Instant::now() < deadline;
                    complete
                })?;
                expired.truncate(tuning.candidates);
                anyhow::Ok((expired, total, complete))
            })
            .await;
        let (expired, total, complete) = match scanned {
            Some(Ok(scanned)) => scanned,
            Some(Err(error)) => {
                debug!(%error, "BPF janitor: redirect-track scan failed");
                return AuxScanResult::default();
            }
            None => return AuxScanResult::default(),
        };
        let deleted = if expired.is_empty() {
            0
        } else {
            match self
                .run_blocking_chunked_delete("redirect-track", expired, move |ebpf, entries| {
                    ebpf.redirect_track_remove_if_unchanged(entries, now_ns)
                })
                .await
            {
                Some(Ok(deleted)) => deleted,
                Some(Err(error)) => {
                    debug!(%error, "BPF janitor: redirect-track delete failed");
                    0
                }
                None => 0,
            }
        };
        if deleted > 0 {
            debug!(deleted, "BPF janitor: removed redirect track entries");
        }
        AuxScanResult {
            deleted,
            scanned: total,
            complete,
        }
    }

    #[cfg(test)]
    pub(super) async fn cleanup_redirect_track_for_test(&self, now_ns: u64) -> (u64, usize) {
        let result = self
            .cleanup_redirect_track_at(
                now_ns,
                ScanTuning {
                    chunk: JANITOR_MAX_SCAN_CHUNK,
                    candidates: JANITOR_MAX_CANDIDATES,
                    budget: Duration::from_secs(1),
                },
            )
            .await;
        (result.deleted, result.scanned)
    }

    /// Clean up stale cookie PID metadata entries.
    ///
    /// Entries whose `last_seen_ns` is older than `COOKIE_PID_TIMEOUT_NS`
    /// are evicted, matching Go's `cleanupCookiePidMap` behaviour.
    async fn cleanup_cookie_pid(&self, tuning: ScanTuning) -> AuxScanResult {
        let now_ns = match monotonic_now_ns() {
            Ok(ns) => ns,
            Err(error) => {
                error!(%error, "BPF janitor: failed to get monotonic time");
                return AuxScanResult::default();
            }
        };
        let scanned = self
            .run_blocking_read("cookie-pid", move |ebpf| {
                let deadline = Instant::now() + tuning.budget;
                let mut expired = Vec::with_capacity(tuning.candidates);
                let mut total = 0usize;
                let mut complete = true;
                ebpf.cookie_pid_for_each_chunk(tuning.chunk, &mut |chunk| {
                    total += chunk.len();
                    for (cookie, entry) in chunk {
                        if now_ns.saturating_sub(entry.last_seen_ns) > COOKIE_PID_TIMEOUT_NS {
                            expired.push((*cookie, *entry));
                        }
                    }
                    complete = expired.len() < tuning.candidates && Instant::now() < deadline;
                    complete
                })?;
                expired.truncate(tuning.candidates);
                anyhow::Ok((expired, total, complete))
            })
            .await;
        let (expired, total, complete) = match scanned {
            Some(Ok(scanned)) => scanned,
            Some(Err(error)) => {
                debug!(%error, "BPF janitor: cookie-PID scan failed");
                return AuxScanResult::default();
            }
            None => return AuxScanResult::default(),
        };
        let deleted = if expired.is_empty() {
            0
        } else {
            match self
                .run_blocking_chunked_delete("cookie-pid", expired, move |ebpf, entries| {
                    ebpf.cookie_pid_remove_if_unchanged(entries, now_ns)
                })
                .await
            {
                Some(Ok(deleted)) => deleted,
                Some(Err(error)) => {
                    debug!(%error, "BPF janitor: cookie-PID delete failed");
                    0
                }
                None => 0,
            }
        };
        if deleted > 0 {
            debug!(deleted, "BPF janitor: removed cookie PID entries");
        }
        AuxScanResult {
            deleted,
            scanned: total,
            complete,
        }
    }

    /// Clean up expired routing handoff entries.
    async fn cleanup_routing_handoff(&self, tuning: ScanTuning) -> AuxScanResult {
        let now_ns = match monotonic_now_ns() {
            Ok(ns) => ns,
            Err(error) => {
                error!(%error, "BPF janitor: failed to get monotonic time");
                return AuxScanResult::default();
            }
        };
        let scanned = self
            .run_blocking_read("routing-handoff", move |ebpf| {
                let deadline = Instant::now() + tuning.budget;
                let mut expired = Vec::with_capacity(tuning.candidates);
                let mut total = 0usize;
                let mut complete = true;
                ebpf.routing_handoff_for_each_chunk(tuning.chunk, &mut |chunk| {
                    total += chunk.len();
                    for (key, entry) in chunk {
                        if now_ns.saturating_sub(entry.last_seen_ns) > ROUTING_HANDOFF_TIMEOUT_NS {
                            expired.push((*key, *entry));
                        }
                    }
                    complete = expired.len() < tuning.candidates && Instant::now() < deadline;
                    complete
                })?;
                expired.truncate(tuning.candidates);
                anyhow::Ok((expired, total, complete))
            })
            .await;
        let (expired, total, complete) = match scanned {
            Some(Ok(scanned)) => scanned,
            Some(Err(error)) => {
                debug!(%error, "BPF janitor: routing-handoff scan failed");
                return AuxScanResult::default();
            }
            None => return AuxScanResult::default(),
        };
        let deleted = if expired.is_empty() {
            0
        } else {
            match self
                .run_blocking_chunked_delete("routing-handoff", expired, move |ebpf, entries| {
                    ebpf.routing_handoff_remove_if_unchanged(entries, now_ns)
                })
                .await
            {
                Some(Ok(deleted)) => deleted,
                Some(Err(error)) => {
                    debug!(%error, "BPF janitor: routing-handoff delete failed");
                    0
                }
                None => 0,
            }
        };
        if deleted > 0 {
            debug!(deleted, "BPF janitor: removed routing handoff entries");
        }
        AuxScanResult {
            deleted,
            scanned: total,
            complete,
        }
    }

    /// Check BPF map health — overflow counter warnings plus conn-state
    /// occupancy watermark warnings.
    async fn check_map_health(
        &self,
        utilization: f64,
        aux_scan_high_water: [usize; 3],
        last_aux_failures: &mut [u64; 3],
        aux_pressure_warned: &mut [bool; 3],
    ) {
        let ebpf = self.ebpf.read().await;
        let stat = |key: BpfStatsKey| ebpf.get_bpf_stats(key as u32).unwrap_or(None).unwrap_or(0);
        let udp_overflow = stat(BpfStatsKey::UdpConnOverflow);
        let tcp_overflow = stat(BpfStatsKey::TcpConnOverflow);
        let redirect_failures = stat(BpfStatsKey::RedirectTrackInsertFailure);
        let handoff_failures = stat(BpfStatsKey::RoutingHandoffInsertFailure);
        let cookie_failures = stat(BpfStatsKey::CookiePidInsertFailure);
        drop(ebpf);

        if udp_overflow > 0 || tcp_overflow > 0 {
            warn!(
                "BPF janitor: map overflow detected — UDP={}, TCP={}. \
                 Some packets may be falling back to slower paths. \
                 Consider increasing map capacity.",
                udp_overflow, tcp_overflow
            );
        }
        let aux_failures = [redirect_failures, handoff_failures, cookie_failures];
        if aux_failures
            .iter()
            .zip(last_aux_failures.iter())
            .any(|(current, previous)| current > previous)
        {
            warn!(
                redirect_failures,
                handoff_failures,
                cookie_failures,
                "BPF janitor: auxiliary map insert failures increased"
            );
        }
        *last_aux_failures = aux_failures;

        for (index, (map, entries)) in [
            ("redirect-track", aux_scan_high_water[0]),
            ("cookie-pid", aux_scan_high_water[1]),
            ("routing-handoff", aux_scan_high_water[2]),
        ]
        .into_iter()
        .enumerate()
        {
            let utilization = entries as f64 / AUX_MAP_CAPACITY as f64;
            if utilization >= AUX_MAP_PRESSURE_WATERMARK && !aux_pressure_warned[index] {
                warn!(
                    map,
                    entries,
                    capacity = AUX_MAP_CAPACITY,
                    utilization_pct = utilization * 100.0,
                    "BPF janitor: auxiliary map scan high-water indicates pressure"
                );
                aux_pressure_warned[index] = true;
            }
        }

        if udp_overflow > 100 {
            error!(
                "BPF janitor: CRITICAL — UDP conn state map under heavy pressure (overflow={}). \
                 Consider increasing udp_conn_state_map capacity or reducing UDP connection timeout.",
                udp_overflow
            );
        }
        if tcp_overflow > 100 {
            error!(
                "BPF janitor: CRITICAL — TCP conn state map under heavy pressure (overflow={}). \
                 Consider increasing tcp_conn_state_map capacity or reducing TCP connection timeout.",
                tcp_overflow
            );
        }

        if utilization >= CONN_STATE_PRESSURE_WATERMARK {
            warn!(
                "BPF janitor: conn-state map occupancy ~{:.1}% — sweeping every tick; \
                 consider increasing MAX_CONN_STATE_NUM if this persists",
                utilization * 100.0
            );
        }
    }
}

/// Get the current monotonic time in nanoseconds (CLOCK_MONOTONIC).
///
/// Uses `nix::time::clock_gettime` for cross-platform monotonic time access.
/// This matches `bpf_ktime_get_ns()` which also uses CLOCK_MONOTONIC on Linux.
pub(super) fn monotonic_now_ns() -> anyhow::Result<u64> {
    let ts = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)?;
    Ok(ts.tv_sec() as u64 * 1_000_000_000 + ts.tv_nsec() as u64)
}

/// Update the pressure state from the conn-state overflow counters and the
/// live occupancy watermark.
///
/// Pressure mode latches on when either the kernel's UDP/TCP overflow
/// counters grow (insert failures — the fail-closed last resort) or the
/// estimated occupancy crosses `CONN_STATE_PRESSURE_WATERMARK`.  It switches
/// off after `PRESSURE_EXIT_ROUNDS` consecutive ticks with neither signal.
fn update_pressure_state(state: &mut PressureState, overflow_delta: bool, utilization: f64) {
    let high_water = utilization >= CONN_STATE_PRESSURE_WATERMARK;
    if overflow_delta || high_water {
        if !state.active {
            if overflow_delta {
                info!("BPF janitor: entering pressure mode (conn state overflow)");
            } else {
                info!(
                    "BPF janitor: entering pressure mode (conn-state occupancy ~{:.1}%)",
                    utilization * 100.0
                );
            }
        }
        state.active = true;
        state.quiet_rounds = 0;
        return;
    }
    if !state.active {
        return;
    }
    state.quiet_rounds += 1;
    if state.quiet_rounds >= PRESSURE_EXIT_ROUNDS {
        state.active = false;
        state.quiet_rounds = 0;
        info!(
            "BPF janitor: exiting pressure mode (quiet for {} rounds)",
            PRESSURE_EXIT_ROUNDS
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::mock::MockEbpfBackend;
    use honk_ebpf_common::{RedirectEntry, RedirectTuple};

    #[test]
    fn aux_pressure_uses_current_scan_result() {
        let at_watermark = (AUX_MAP_CAPACITY as f64 * CONN_STATE_PRESSURE_WATERMARK) as usize;
        assert!(!aux_scan_is_pressured(at_watermark, true));
        assert!(aux_scan_is_pressured(at_watermark + 1, true));
        assert!(aux_scan_is_pressured(0, false));
    }

    #[test]
    fn scan_tuning_grows_with_pressure() {
        let steady = scan_tuning(0.5, Duration::ZERO);
        let elevated = scan_tuning(CONN_STATE_ELEVATED_WATERMARK, Duration::ZERO);
        let pressure = scan_tuning(CONN_STATE_PRESSURE_WATERMARK, Duration::ZERO);

        assert!(steady.chunk < elevated.chunk);
        assert!(elevated.chunk <= pressure.chunk);
        assert!(steady.candidates < elevated.candidates);
        assert!(elevated.candidates < pressure.candidates);
        assert!(steady.budget < elevated.budget);
        assert!(elevated.budget < pressure.budget);
    }

    #[test]
    fn scan_tuning_reduces_chunk_after_budget_overrun() {
        let fast = scan_tuning(CONN_STATE_PRESSURE_WATERMARK, Duration::ZERO);
        let slow = scan_tuning(
            CONN_STATE_PRESSURE_WATERMARK,
            JANITOR_PRESSURE_SCAN_BUDGET + Duration::from_millis(1),
        );

        assert!(slow.chunk < fast.chunk);
        assert_eq!(slow.candidates, fast.candidates);
        assert_eq!(slow.budget, fast.budget);
    }

    #[tokio::test]
    async fn blocking_scan_keeps_hot_path_readers_available() {
        let backend: Arc<RwLock<Box<dyn EbpfBackend>>> =
            Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
        let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::new(TcpFlowPins::default()));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let scan = tokio::spawn(async move {
            janitor
                .run_blocking_read("test", move |_| {
                    entered_tx.send(()).expect("test receiver stays alive");
                    release_rx.recv().expect("test scan gets released");
                })
                .await
        });

        entered_rx.await.expect("blocking scan started");
        let read_available = tokio::time::timeout(Duration::from_millis(100), backend.read())
            .await
            .is_ok();
        release_tx.send(()).expect("release blocking scan");
        scan.await.expect("scan task joins");

        assert!(
            read_available,
            "bounded janitor scans must not block per-flow eBPF reads"
        );
    }

    #[test]
    fn test_pressure_state_enter_on_overflow_delta() {
        let mut state = PressureState::default();
        assert!(!state.active);

        update_pressure_state(&mut state, true, 0.0);
        assert!(state.active);
        assert_eq!(state.quiet_rounds, 0);
    }

    #[test]
    fn test_pressure_state_enter_on_high_watermark() {
        let mut state = PressureState::default();
        assert!(!state.active);

        update_pressure_state(&mut state, false, CONN_STATE_PRESSURE_WATERMARK + 0.01);
        assert!(state.active);
        assert_eq!(state.quiet_rounds, 0);
    }

    #[test]
    fn test_pressure_state_stays_inactive_below_watermark() {
        let mut state = PressureState::default();
        for _ in 0..10 {
            update_pressure_state(&mut state, false, CONN_STATE_PRESSURE_WATERMARK - 0.01);
            assert!(!state.active);
        }
    }

    #[test]
    fn test_pressure_state_exit_after_quiet_rounds() {
        let mut state = PressureState {
            active: true,
            quiet_rounds: 0,
            last_udp_overflow: 0,
            last_tcp_overflow: 0,
        };

        // No overflow and below the watermark for PRESSURE_EXIT_ROUNDS
        // consecutive ticks → exit.
        for _ in 0..PRESSURE_EXIT_ROUNDS {
            assert!(state.active);
            update_pressure_state(&mut state, false, 0.0);
        }
        assert!(!state.active);
    }

    #[test]
    fn test_pressure_state_overflow_resets_quiet_counter() {
        let mut state = PressureState {
            active: true,
            quiet_rounds: 2,
            last_udp_overflow: 0,
            last_tcp_overflow: 0,
        };

        // A new overflow restarts the quiet-period countdown.
        update_pressure_state(&mut state, true, 0.0);
        assert!(state.active);
        assert_eq!(state.quiet_rounds, 0);

        // And it still takes the full run of quiet ticks to exit.
        for _ in 0..PRESSURE_EXIT_ROUNDS - 1 {
            update_pressure_state(&mut state, false, 0.0);
            assert!(state.active);
        }
        update_pressure_state(&mut state, false, 0.0);
        assert!(!state.active);
    }

    #[test]
    fn test_pressure_state_inactive_stays_inactive_without_overflow() {
        let mut state = PressureState::default();
        for _ in 0..10 {
            update_pressure_state(&mut state, false, 0.0);
            assert!(!state.active);
        }
    }

    #[test]
    fn test_occupancy_gauge_estimate_and_calibrate() {
        let mut gauge = OccupancyGauge::default();
        // 100 inserts, 30 datapath deletes, 20 janitor deletes, 10 userspace
        // deletes → 40 live.
        gauge.note_janitor_deletes(20);
        assert_eq!(gauge.estimate(100, 30, 10), 40);

        // A sweep observes 35 entries (5 lost to races) → drift corrects.
        gauge.calibrate(35, 100, 30, 10);
        assert_eq!(gauge.estimate(100, 30, 10), 35);
        // Post-calibration deltas apply on top of the exact count.
        assert_eq!(gauge.estimate(110, 35, 12), 38);
    }

    #[test]
    fn test_occupancy_gauge_never_negative() {
        let gauge = OccupancyGauge::default();
        assert_eq!(gauge.estimate(0, 10, 5), 0);
    }

    #[test]
    fn test_monotonic_now_ns_returns_value() {
        let ns = monotonic_now_ns().expect("monotonic time should be available");
        assert!(ns > 0, "monotonic time should be positive, got {}", ns);
    }
    fn test_tuple(src_port: u16, l4proto: u8) -> TuplesKey {
        let mut key: TuplesKey = unsafe { std::mem::zeroed() };
        key.src_ip[15] = 1;
        key.dst_ip[15] = 2;
        key.src_port = src_port;
        key.dst_port = 443;
        key.l4proto = l4proto;
        key
    }

    fn test_state(state: TcpState, last_seen_ns: u64) -> ConnState {
        ConnState {
            state: state as u8,
            last_seen_ns,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn aux_pressure_detects_bounded_scan_and_recovers() -> anyhow::Result<()> {
        let backend: Arc<RwLock<Box<dyn EbpfBackend>>> =
            Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
        let stale = RedirectEntry::default();
        {
            let mut backend = backend.write().await;
            for port in 0..=(JANITOR_BASE_CANDIDATES as u16) {
                backend.redirect_track_store(
                    &RedirectTuple::from_tuples(&test_tuple(port, 17)),
                    &stale,
                )?;
            }
        }

        let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::new(TcpFlowPins::default()));
        let first = janitor
            .cleanup_redirect_track_at(
                REDIRECT_TRACK_TIMEOUT_NS + 1,
                scan_tuning(0.0, Duration::ZERO),
            )
            .await;
        assert_eq!(first.deleted, JANITOR_BASE_CANDIDATES as u64);
        assert_eq!(first.scanned, JANITOR_BASE_CANDIDATES);
        assert!(!first.complete);
        assert!(aux_scan_is_pressured(first.scanned, first.complete));

        let second = janitor
            .cleanup_redirect_track_at(
                REDIRECT_TRACK_TIMEOUT_NS + 1,
                scan_tuning(CONN_STATE_PRESSURE_WATERMARK, Duration::ZERO),
            )
            .await;
        assert_eq!(second.deleted, 1);
        assert_eq!(second.scanned, 1);
        assert!(second.complete);
        assert!(!aux_scan_is_pressured(second.scanned, second.complete));

        Ok(())
    }

    #[tokio::test]
    async fn tcp_pin_conn_state_matrix() -> anyhow::Result<()> {
        let pinned_active = test_tuple(10_001, IPPROTO_TCP);
        let pinned_closing = test_tuple(10_002, IPPROTO_TCP);
        let unpinned_active = test_tuple(10_003, IPPROTO_TCP);
        let unpinned_closing = test_tuple(10_004, IPPROTO_TCP);
        let udp = test_tuple(10_005, 17);
        let now_ns = TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS + 1;

        let backend: Arc<RwLock<Box<dyn EbpfBackend>>> =
            Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
        {
            let mut backend = backend.write().await;
            backend
                .tcp_conn_state_store(&pinned_active, &test_state(TcpState::TcpStateActive, 0))?;
            backend
                .tcp_conn_state_store(&pinned_closing, &test_state(TcpState::TcpStateClosing, 0))?;
            backend
                .tcp_conn_state_store(&unpinned_active, &test_state(TcpState::TcpStateActive, 0))?;
            backend.tcp_conn_state_store(
                &unpinned_closing,
                &test_state(TcpState::TcpStateClosing, 0),
            )?;
            backend.udp_conn_state_store(&udp, &test_state(TcpState::TcpStateActive, 0))?;
        }

        let pins = Arc::new(TcpFlowPins::default());
        pins.retain_for_test(TcpFlowKey::from_tuples(&pinned_active));
        pins.retain_for_test(TcpFlowKey::from_tuples(&pinned_closing));
        let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::clone(&pins));

        assert_eq!(janitor.cleanup_conn_state_for_test(now_ns).await, (3, 5));
        {
            let backend = backend.read().await;
            assert!(backend.tcp_conn_state_lookup(&pinned_active)?.is_some());
            assert!(backend.tcp_conn_state_lookup(&pinned_closing)?.is_some());
            assert!(backend.tcp_conn_state_lookup(&unpinned_active)?.is_none());
            assert!(backend.tcp_conn_state_lookup(&unpinned_closing)?.is_none());
            assert!(backend.udp_conn_state_lookup(&udp)?.is_none());
        }

        assert_eq!(
            pins.release_for_test(TcpFlowKey::from_tuples(&pinned_active)),
            Some(true)
        );
        assert_eq!(
            pins.release_for_test(TcpFlowKey::from_tuples(&pinned_closing)),
            Some(true)
        );
        assert_eq!(janitor.cleanup_conn_state_for_test(now_ns).await, (2, 2));
        let backend = backend.read().await;
        assert!(backend.tcp_conn_state_lookup(&pinned_active)?.is_none());
        assert!(backend.tcp_conn_state_lookup(&pinned_closing)?.is_none());

        anyhow::Ok(())
    }

    #[tokio::test]
    async fn tcp_pin_redirect_matrix() -> anyhow::Result<()> {
        let pinned_key = test_tuple(20_001, IPPROTO_TCP);
        let unpinned_key = test_tuple(20_002, IPPROTO_TCP);
        let udp_key = test_tuple(20_003, 17);
        let pinned = RedirectTuple::from_tuples(&pinned_key);
        let unpinned = RedirectTuple::from_tuples(&unpinned_key);
        let udp = RedirectTuple::from_tuples(&udp_key);
        let stale = RedirectEntry {
            last_seen_ns: 0,
            ..Default::default()
        };
        let now_ns = REDIRECT_TRACK_TIMEOUT_NS + 1;

        let backend: Arc<RwLock<Box<dyn EbpfBackend>>> =
            Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
        {
            let mut backend = backend.write().await;
            backend.redirect_track_store(&pinned, &stale)?;
            backend.redirect_track_store(&unpinned, &stale)?;
            backend.redirect_track_store(&udp, &stale)?;
        }

        let pins = Arc::new(TcpFlowPins::default());
        pins.retain_for_test(TcpFlowKey::from_tuples(&pinned_key));
        let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::clone(&pins));

        assert_eq!(
            janitor.cleanup_redirect_track_for_test(now_ns).await,
            (2, 3)
        );
        {
            let backend = backend.read().await;
            assert!(backend.redirect_track_lookup(&pinned)?.is_some());
            assert!(backend.redirect_track_lookup(&unpinned)?.is_none());
            assert!(backend.redirect_track_lookup(&udp)?.is_none());
        }

        assert_eq!(
            pins.release_for_test(TcpFlowKey::from_tuples(&pinned_key)),
            Some(true)
        );
        assert_eq!(
            janitor.cleanup_redirect_track_for_test(now_ns).await,
            (1, 1)
        );
        assert!(
            backend
                .read()
                .await
                .redirect_track_lookup(&pinned)?
                .is_none()
        );

        Ok(())
    }
}
