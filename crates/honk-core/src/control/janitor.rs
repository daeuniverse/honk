//! BPF map janitor — background task that cleans up stale eBPF map entries.
//!
//! Mirrors Go's `startConnStateJanitor` from `daed/wing/dae-core/control/control_plane.go`.
//! The janitor runs on a configurable tick interval and performs periodic cleanup
//! of conn-state, redirect tracking, and routing handoff. Socket identity
//! storage is reclaimed by the kernel with the socket,
//! never by this janitor.
//!
//! All swept maps are plain hashes: the kernel never evicts on its own
//! (silent LRU eviction could re-route or break live flows mid-flight), so
//! occupancy management lives here. Accepted TCP owners pin conn-state and
//! redirect metadata for their full relay lifetime. Unpinned TCP ACTIVE and
//! UDP conn-state keep the 120-second backstop; TCP CLOSING uses 10 seconds.
//! Unpinned TCP and stateless UDP/53 redirects need only 30 seconds because
//! the next forward packet can rebuild them without losing conn authority.
//! Conn, redirect and handoff occupancy
//! jointly select the cadence and candidate bound: 60 s below 70%, 15 s below
//! 85%, and every two-second tick / 4096 candidates under pressure. A bounded
//! auxiliary scan keeps that aggressive cadence until its backlog is drained.

use super::connection::TcpFlowPins;
use super::udp_endpoint::UdpEndpointPool;
#[cfg(test)]
use crate::ebpf::EbpfBackend;
use crate::ebpf::RETIRE_BATCH_CAPACITY;
use health::{AuxMap, HealthLatches};
use honk_ebpf_common::conn::{BpfStatsKey, MAX_CONN_STATE_NUM};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, watch};
use tracing::{debug, error, info, warn};

/// Janitor tick interval: 2 seconds.
const JANITOR_TICK_INTERVAL_SECS: u64 = 2;
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

/// Visit granularity for backends without `BPF_MAP_LOOKUP_BATCH`; the batch
/// path streams fixed-size kernel batches instead.
const JANITOR_SCAN_CHUNK: usize = 256;
const JANITOR_DELETE_CHUNK: usize = RETIRE_BATCH_CAPACITY;
const JANITOR_BASE_CANDIDATES: usize = 1024;
const JANITOR_MAX_CANDIDATES: usize = 4096;
const JANITOR_BASE_SCAN_BUDGET: Duration = Duration::from_millis(100);
const JANITOR_ELEVATED_SCAN_BUDGET: Duration = Duration::from_millis(150);
const JANITOR_PRESSURE_SCAN_BUDGET: Duration = Duration::from_millis(200);
const AUX_MAP_CAPACITY: usize = 65_536;
const AUX_MAP_PRESSURE_WATERMARK: f64 = 0.80;

/// Number of consecutive ticks without conn-state overflow after which
/// pressure mode is switched off.
const PRESSURE_EXIT_ROUNDS: u32 = 3;

/// Live CONN_STATE_MAP occupancy estimate, derived from the datapath's
/// insert/delete counters plus the userspace delete counter (which every
/// backend retirement feeds), recalibrated against the exact entry count on
/// every sweep.
#[derive(Debug, Default)]
struct OccupancyGauge {
    /// `exact_count - raw_estimate` recorded at the last sweep, absorbing
    /// races (e.g. a datapath delete of an entry the janitor also removed).
    drift: i64,
}

impl OccupancyGauge {
    /// Raw counter-derived occupancy before drift correction.
    fn raw_estimate(inserts: u64, ebpf_deletes: u64, userspace_deletes: u64) -> i64 {
        inserts as i64 - ebpf_deletes as i64 - userspace_deletes as i64
    }

    fn estimate(&self, inserts: u64, ebpf_deletes: u64, userspace_deletes: u64) -> u64 {
        (Self::raw_estimate(inserts, ebpf_deletes, userspace_deletes) + self.drift).max(0) as u64
    }

    /// Recalibrate with the exact entry count observed during a sweep.
    fn calibrate(&mut self, exact: u64, inserts: u64, ebpf_deletes: u64, userspace_deletes: u64) {
        self.drift = exact as i64 - Self::raw_estimate(inserts, ebpf_deletes, userspace_deletes);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ScanTuning {
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

fn scan_tuning(utilization: f64) -> ScanTuning {
    let (candidates, budget) = if utilization >= CONN_STATE_PRESSURE_WATERMARK {
        (JANITOR_MAX_CANDIDATES, JANITOR_PRESSURE_SCAN_BUDGET)
    } else if utilization >= CONN_STATE_ELEVATED_WATERMARK {
        (JANITOR_BASE_CANDIDATES * 2, JANITOR_ELEVATED_SCAN_BUDGET)
    } else {
        (JANITOR_BASE_CANDIDATES, JANITOR_BASE_SCAN_BUDGET)
    };
    ScanTuning { candidates, budget }
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
    ebpf: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>>,
    tcp_flow_pins: Arc<TcpFlowPins>,
    udp_pool: Option<Arc<UdpEndpointPool>>,
    scan_cursors: [Arc<parking_lot::Mutex<crate::ebpf::FlowScanCursor>>; 3],
    #[cfg(test)]
    blocking_read_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    before_delete_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl BpfJanitor {
    /// Create a new janitor bound to the given eBPF backend.
    pub(super) fn new(
        ebpf: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>>,
        tcp_flow_pins: Arc<TcpFlowPins>,
    ) -> Self {
        Self {
            ebpf,
            tcp_flow_pins,
            udp_pool: None,
            scan_cursors: std::array::from_fn(|_| Arc::default()),
            #[cfg(test)]
            blocking_read_hook: None,
            #[cfg(test)]
            before_delete_hook: None,
        }
    }

    /// Retire the endpoints of UDP flows whose conn this janitor deletes.
    pub(super) fn with_udp_pool(mut self, pool: Arc<UdpEndpointPool>) -> Self {
        self.udp_pool = Some(pool);
        self
    }

    /// Spawn with a guard that reports unexpected task death to the control plane.
    pub(super) fn spawn_supervised(
        self,
        exit_guard: super::runtime::CriticalTaskExit,
        mut stop: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut exit_guard = exit_guard;
            let tick_duration = Duration::from_secs(JANITOR_TICK_INTERVAL_SECS);
            let mut interval = tokio::time::interval(tick_duration);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            // Skip the first immediate tick.
            interval.tick().await;

            let mut state = tick::TickState::new(tokio::time::Instant::now());

            info!(
                "BPF janitor: started (tick={}s; conn-state sweep is watermark-driven)",
                JANITOR_TICK_INTERVAL_SECS
            );

            loop {
                // Never race a stop against an in-flight blocking scan or deletion.
                if *stop.borrow_and_update() {
                    exit_guard.expected_stop();
                    return;
                }
                tokio::select! {
                    biased;
                    changed = stop.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        continue;
                    }
                    _ = interval.tick() => {}
                }

                let now = tokio::time::Instant::now();
                let now_ns = match monotonic_now_ns() {
                    Ok(now_ns) => Some(now_ns),
                    Err(error) => {
                        warn!(%error, "BPF janitor: failed to get monotonic time");
                        None
                    }
                };

                if let Err(error) = self.tick(&mut state, now, now_ns).await {
                    error!(error = %format_args!("{error:#}"), "BPF janitor: tick failed");
                    return;
                }
            }
        })
    }

    #[cfg(test)]
    pub(super) async fn cleanup_conn_state_for_test(&self, now_ns: u64) -> (u64, usize) {
        let mut gauge = OccupancyGauge::default();
        self.cleanup_conn_state_at(
            now_ns,
            &mut gauge,
            Some(((0, 0), 0)),
            ScanTuning {
                candidates: JANITOR_MAX_CANDIDATES,
                budget: Duration::from_secs(1),
            },
        )
        .await
        .expect("conn-state retirement succeeds")
    }

    #[cfg(test)]
    pub(super) async fn cleanup_redirect_track_for_test(&self, now_ns: u64) -> (u64, usize) {
        let result = self
            .cleanup_redirect_track_at(
                now_ns,
                ScanTuning {
                    candidates: JANITOR_MAX_CANDIDATES,
                    budget: Duration::from_secs(1),
                },
            )
            .await
            .expect("redirect retirement succeeds");
        (result.deleted, result.scanned)
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

/// Update pressure from conn-state overflow and separate conn/redirect/handoff
/// utilization samples, so an auxiliary episode is not attributed to conn-state.
///
/// Pressure mode latches on when either the kernel's UDP/TCP overflow
/// counters grow (insert failures — the fail-closed last resort) or the
/// estimated occupancy crosses `CONN_STATE_PRESSURE_WATERMARK`.  It switches
/// off after `PRESSURE_EXIT_ROUNDS` consecutive ticks with neither signal.
fn update_pressure_state(state: &mut PressureState, overflow_delta: bool, utilizations: [f64; 3]) {
    let [conn_utilization, redirect_utilization, handoff_utilization] = utilizations;
    let high_water = utilizations
        .into_iter()
        .any(|utilization| utilization >= CONN_STATE_PRESSURE_WATERMARK);
    if overflow_delta || high_water {
        if !state.active {
            warn!(
                conn_overflow = overflow_delta,
                conn_utilization_pct = conn_utilization * 100.0,
                redirect_utilization_pct = redirect_utilization * 100.0,
                handoff_utilization_pct = handoff_utilization * 100.0,
                "BPF janitor: entering pressure mode"
            );
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
            quiet_rounds = PRESSURE_EXIT_ROUNDS,
            conn_utilization_pct = conn_utilization * 100.0,
            redirect_utilization_pct = redirect_utilization * 100.0,
            handoff_utilization_pct = handoff_utilization * 100.0,
            "BPF janitor: exiting pressure mode"
        );
    }
}

mod health;
mod sweep;
mod tick;

#[cfg(test)]
mod tests;
