use super::*;
use anyhow::Context;
use tokio::time::Instant;

const ADMISSION_PRESSURE_EXIT_WATERMARK: f64 = 0.60;

pub(super) fn admission_pressured(active: bool, utilization: f64) -> bool {
    utilization
        >= if active {
            ADMISSION_PRESSURE_EXIT_WATERMARK
        } else {
            CONN_STATE_ELEVATED_WATERMARK
        }
}

pub(super) fn telemetry_sample<T>(signal: &'static str, result: anyhow::Result<T>) -> Option<T> {
    match result {
        Ok(sample) => Some(sample),
        Err(error) => {
            crate::logging::warn_throttled!(
                signal,
                error = %format_args!("{error:#}"),
                "BPF janitor: telemetry read failed; retaining the previous sample"
            );
            None
        }
    }
}

pub(super) struct TickState {
    pub(super) pressure: PressureState,
    pub(super) gauge: OccupancyGauge,
    aux_scan_results: [AuxScanResult; AuxMap::COUNT],
    health: HealthLatches,
    last_cleanup: Instant,
    last_health_check: Instant,
    admission_pressure: bool,
    conn_occupancy: u64,
    aux_occupancy: (u64, u64),
}

impl TickState {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            pressure: PressureState::default(),
            gauge: OccupancyGauge::default(),
            aux_scan_results: [AuxScanResult {
                complete: true,
                ..AuxScanResult::default()
            }; AuxMap::COUNT],
            health: HealthLatches::default(),
            last_cleanup: now,
            last_health_check: now,
            admission_pressure: false,
            conn_occupancy: 0,
            aux_occupancy: (0, 0),
        }
    }
}

impl BpfJanitor {
    pub(super) async fn tick(
        &self,
        state: &mut TickState,
        now: Instant,
        now_ns: Option<u64>,
    ) -> anyhow::Result<()> {
        let (overflow_delta, overflow_read_ok, utilizations, occ_counters) = {
            let backend = self.ebpf.read().await;
            let ebpf = backend.tc()?;
            let udp = telemetry_sample(
                BpfStatsKey::UdpConnOverflow.label(),
                ebpf.get_bpf_stats(BpfStatsKey::UdpConnOverflow as u32)
                    .map(|value| value.unwrap_or(0)),
            );
            let tcp = telemetry_sample(
                BpfStatsKey::TcpConnOverflow.label(),
                ebpf.get_bpf_stats(BpfStatsKey::TcpConnOverflow as u32)
                    .map(|value| value.unwrap_or(0)),
            );
            let overflow_read_ok = udp.is_some() && tcp.is_some();
            let udp = udp.unwrap_or(state.pressure.last_udp_overflow);
            let tcp = tcp.unwrap_or(state.pressure.last_tcp_overflow);
            let delta =
                udp > state.pressure.last_udp_overflow || tcp > state.pressure.last_tcp_overflow;
            state.pressure.last_udp_overflow = udp;
            state.pressure.last_tcp_overflow = tcp;
            let occ_counters =
                telemetry_sample("conn-state occupancy", ebpf.conn_state_occupancy()).map(
                    |counters| {
                        let userspace_deletes = crate::ebpf::USERSPACE_CONN_STATE_DELETES
                            .load(std::sync::atomic::Ordering::Relaxed);
                        state.conn_occupancy =
                            state
                                .gauge
                                .estimate(counters.0, counters.1, userspace_deletes);
                        (counters, userspace_deletes)
                    },
                );
            if let Some(occupancy) = telemetry_sample("auxiliary occupancy", ebpf.aux_occupancy()) {
                state.aux_occupancy = occupancy;
            }
            (
                delta,
                overflow_read_ok,
                [
                    state.conn_occupancy as f64 / f64::from(MAX_CONN_STATE_NUM),
                    state.aux_occupancy.0 as f64 / AUX_MAP_CAPACITY as f64,
                    state.aux_occupancy.1 as f64 / AUX_MAP_CAPACITY as f64,
                ],
                occ_counters,
            )
        };
        let [conn_utilization, redirect_utilization, handoff_utilization] = utilizations;
        let admission_pressure = admission_pressured(state.admission_pressure, conn_utilization);
        if admission_pressure != state.admission_pressure {
            self.ebpf
                .write()
                .await
                .tc_mut()?
                .set_admission_pressure(admission_pressure)
                .context("publishing reverse UDP admission pressure")?;
            state.admission_pressure = admission_pressure;
        }
        let utilization = conn_utilization
            .max(redirect_utilization)
            .max(handoff_utilization);
        // A missed overflow sample cannot establish another quiet round.
        if overflow_read_ok || overflow_delta || utilization >= CONN_STATE_PRESSURE_WATERMARK {
            update_pressure_state(&mut state.pressure, overflow_delta, utilizations);
        }
        let backlog = state
            .aux_scan_results
            .iter()
            .any(|result| aux_scan_is_pressured(result.scanned, result.complete));
        let utilization = if state.pressure.active || backlog {
            utilization.max(CONN_STATE_PRESSURE_WATERMARK)
        } else {
            utilization
        };
        let interval = Duration::from_secs(if utilization >= CONN_STATE_PRESSURE_WATERMARK {
            JANITOR_TICK_INTERVAL_SECS
        } else if utilization >= CONN_STATE_ELEVATED_WATERMARK {
            CONN_STATE_ELEVATED_INTERVAL_SECS
        } else {
            CONN_STATE_STEADY_INTERVAL_SECS
        });
        if state.last_cleanup + interval <= now
            && let Some(now_ns) = now_ns
        {
            let tuning = scan_tuning(utilization);
            let (deleted, total) = self
                .cleanup_conn_state_at(now_ns, &mut state.gauge, occ_counters, tuning)
                .await
                .context("conn-state retirement")?;
            if utilization >= CONN_STATE_ELEVATED_WATERMARK || deleted > 0 {
                debug!(
                    deleted,
                    total,
                    conn_utilization_pct = conn_utilization * 100.0,
                    redirect_utilization_pct = redirect_utilization * 100.0,
                    handoff_utilization_pct = handoff_utilization * 100.0,
                    "BPF janitor: conn-state sweep"
                );
            }
            for map in AuxMap::ALL {
                state.aux_scan_results[map as usize] = match map {
                    AuxMap::RedirectTrack => self.cleanup_redirect_track_at(now_ns, tuning).await,
                    AuxMap::RoutingHandoff => self.cleanup_routing_handoff_at(now_ns, tuning).await,
                }
                .with_context(|| format!("{} retirement", map.label()))?;
            }
            state.last_cleanup = now;
        }
        if state.last_health_check + Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS) <= now {
            self.check_map_health(utilizations, state.aux_scan_results, &mut state.health)
                .await?;
            state.last_health_check = now;
        }
        Ok(())
    }
}
