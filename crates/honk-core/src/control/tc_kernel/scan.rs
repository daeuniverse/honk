//! Kernel map snapshots used by the adaptive janitor.

use super::TcKernelController;
use crate::ebpf::{
    ConnStateChunkVisitor, EbpfBackend, FlowScanCursor, RedirectTrackChunkVisitor,
    RoutingHandoffChunkVisitor,
};
use honk_ebpf_common::conn::BpfStatsKey;

pub(in crate::control) fn telemetry_sample<T>(
    signal: &'static str,
    result: anyhow::Result<T>,
) -> Option<T> {
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

pub(in crate::control) struct PressureSample {
    pub(in crate::control) udp_overflow: Option<u64>,
    pub(in crate::control) tcp_overflow: Option<u64>,
    pub(in crate::control) conn: Option<((u64, u64), u64)>,
    pub(in crate::control) auxiliary: Option<(u64, u64)>,
}

pub(in crate::control) struct MapScan<'a>(&'a dyn EbpfBackend);

impl MapScan<'_> {
    pub(in crate::control) fn conn_state(
        &self,
        size: usize,
        cursor: &mut FlowScanCursor,
        visit: &mut ConnStateChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        self.0.conn_state_for_each_chunk(size, cursor, visit)
    }

    pub(in crate::control) fn redirect_track(
        &self,
        size: usize,
        cursor: &mut FlowScanCursor,
        visit: &mut RedirectTrackChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        self.0.redirect_track_for_each_chunk(size, cursor, visit)
    }

    pub(in crate::control) fn routing_handoff(
        &self,
        size: usize,
        cursor: &mut FlowScanCursor,
        visit: &mut RoutingHandoffChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        self.0.routing_handoff_for_each_chunk(size, cursor, visit)
    }
}

impl TcKernelController {
    pub(in crate::control) fn blocking_scan<T>(
        &self,
        scan: impl FnOnce(&MapScan<'_>) -> T,
    ) -> anyhow::Result<T> {
        let backend = Self::map_read(self.backend.blocking_read())?;
        Ok(scan(&MapScan(&*backend)))
    }

    pub(in crate::control) async fn sample_failures(
        &self,
        mut counters: [u64; BpfStatsKey::COUNT as usize],
    ) -> anyhow::Result<[u64; BpfStatsKey::COUNT as usize]> {
        let backend = self.read().await?;
        for key in BpfStatsKey::ALL {
            if let Some(value) = telemetry_sample(
                key.label(),
                backend
                    .get_bpf_stats(key as u32)
                    .map(|value| value.unwrap_or(0)),
            ) {
                counters[key as usize] = value;
            }
        }
        Ok(counters)
    }

    pub(in crate::control) async fn sample_pressure(&self) -> anyhow::Result<PressureSample> {
        let backend = self.read().await?;
        let overflow = |key: BpfStatsKey| {
            telemetry_sample(
                key.label(),
                backend
                    .get_bpf_stats(key as u32)
                    .map(|value| value.unwrap_or(0)),
            )
        };
        Ok(PressureSample {
            udp_overflow: overflow(BpfStatsKey::UdpConnOverflow),
            tcp_overflow: overflow(BpfStatsKey::TcpConnOverflow),
            conn: telemetry_sample("conn-state occupancy", backend.conn_state_occupancy()).map(
                |counters| {
                    let deletes = crate::ebpf::USERSPACE_CONN_STATE_DELETES
                        .load(std::sync::atomic::Ordering::Relaxed);
                    (counters, deletes)
                },
            ),
            auxiliary: telemetry_sample("auxiliary occupancy", backend.aux_occupancy()),
        })
    }

    pub(in crate::control) async fn set_admission_pressure(
        &self,
        pressured: bool,
    ) -> anyhow::Result<()> {
        self.with_write(|tc| tc.set_admission_pressure(pressured))
            .await
    }
}
