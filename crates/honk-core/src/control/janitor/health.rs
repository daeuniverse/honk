use super::{
    AUX_MAP_CAPACITY, AUX_MAP_PRESSURE_WATERMARK, AuxScanResult, BpfJanitor,
    CONN_STATE_PRESSURE_WATERMARK,
};
use honk_ebpf_common::conn::BpfStatsKey;
use tracing::warn;

#[derive(Clone, Copy)]
#[repr(usize)]
pub(super) enum AuxMap {
    RedirectTrack,
    RoutingHandoff,
}

impl AuxMap {
    pub(super) const ALL: [Self; 2] = [Self::RedirectTrack, Self::RoutingHandoff];
    pub(super) const COUNT: usize = Self::ALL.len();

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::RedirectTrack => "redirect-track",
            Self::RoutingHandoff => "routing-handoff",
        }
    }
}

#[derive(Default)]
pub(super) struct HealthLatches {
    pub(super) last_failures: [u64; BpfStatsKey::COUNT as usize],
    pub(super) aux_pressure_warned: [bool; AuxMap::COUNT],
    pub(super) overflow_warned: bool,
    pub(super) udp_pressure_warned: bool,
    pub(super) tcp_pressure_warned: bool,
    pub(super) occupancy_warned: bool,
}

impl BpfJanitor {
    pub(super) async fn check_map_health(
        &self,
        [conn_utilization, redirect_utilization, handoff_utilization]: [f64; 3],
        aux_scans: [AuxScanResult; AuxMap::COUNT],
        latches: &mut HealthLatches,
    ) -> anyhow::Result<()> {
        let backend = self.ebpf.read().await;
        let ebpf = backend.tc()?;
        let mut stats = latches.last_failures;
        for key in BpfStatsKey::ALL {
            if let Some(value) = super::tick::telemetry_sample(
                key.label(),
                ebpf.get_bpf_stats(key as u32)
                    .map(|value| value.unwrap_or(0)),
            ) {
                stats[key as usize] = value;
            }
        }
        drop(backend);
        let udp_overflow = stats[BpfStatsKey::UdpConnOverflow as usize];
        let tcp_overflow = stats[BpfStatsKey::TcpConnOverflow as usize];

        let udp_increased =
            udp_overflow > latches.last_failures[BpfStatsKey::UdpConnOverflow as usize];
        let tcp_increased =
            tcp_overflow > latches.last_failures[BpfStatsKey::TcpConnOverflow as usize];
        let overflow_increased = udp_increased || tcp_increased;
        // Auxiliary or occupancy-only pressure cannot promote old overflow history.
        if !overflow_increased {
            latches.overflow_warned = false;
        }
        if !udp_increased {
            latches.udp_pressure_warned = false;
        }
        if !tcp_increased {
            latches.tcp_pressure_warned = false;
        }
        if conn_utilization < CONN_STATE_PRESSURE_WATERMARK {
            latches.occupancy_warned = false;
        }
        let first_in_episode =
            |increased: bool, warned: &mut bool| increased && !std::mem::replace(warned, true);

        if udp_overflow > 0 || tcp_overflow > 0 {
            crate::logging::warn_on_entry!(
                first_in_episode(overflow_increased, &mut latches.overflow_warned),
                udp_overflow,
                tcp_overflow,
                conn_utilization_pct = conn_utilization * 100.0,
                redirect_utilization_pct = redirect_utilization * 100.0,
                handoff_utilization_pct = handoff_utilization * 100.0,
                "BPF janitor: conn-state overflow detected; consider increasing map capacity"
            );
        }
        for key in BpfStatsKey::ALL {
            let message = match key {
                BpfStatsKey::UdpConnOverflow
                | BpfStatsKey::TcpConnOverflow
                | BpfStatsKey::UdpReverseLearningSuspended => continue,
                BpfStatsKey::RedirectTrackInsertFailure
                | BpfStatsKey::RoutingHandoffInsertFailure => {
                    "BPF janitor: auxiliary map insert failures increased"
                }
                BpfStatsKey::SocketIdentityCaptureFailure => {
                    "BPF janitor: socket identity capture failures increased; affected sockets lost process-name matching"
                }
                BpfStatsKey::TcpChildProofStorageFailure
                | BpfStatsKey::TcpPublisherClaimFailure => {
                    "BPF janitor: TCP ownership publication failures increased; affected connections were refused"
                }
                BpfStatsKey::NewFlowRateLimited => {
                    "BPF janitor: a LAN source exceeded its per-CPU new-flow limit; excess flow attempts were dropped"
                }
            };
            let failures = stats[key as usize];
            if failures > latches.last_failures[key as usize] {
                warn!(counter = key.label(), failures, "{message}");
            }
        }
        latches.last_failures = stats;

        for map in AuxMap::ALL {
            let index = map as usize;
            let scan = aux_scans[index];
            let entries = scan.scanned;
            let utilization = entries as f64 / AUX_MAP_CAPACITY as f64;
            if utilization >= AUX_MAP_PRESSURE_WATERMARK {
                if !latches.aux_pressure_warned[index] {
                    warn!(
                        map = map.label(),
                        entries,
                        capacity = AUX_MAP_CAPACITY,
                        utilization_pct = utilization * 100.0,
                        "BPF janitor: auxiliary map scan high-water indicates pressure"
                    );
                    latches.aux_pressure_warned[index] = true;
                }
            } else if scan.complete {
                // A bounded scan is only a lower bound; a complete one proves
                // the map left pressure.
                latches.aux_pressure_warned[index] = false;
            }
        }

        if udp_overflow > 100 {
            crate::logging::warn_on_entry!(
                first_in_episode(udp_increased, &mut latches.udp_pressure_warned),
                overflow = udp_overflow,
                conn_utilization_pct = conn_utilization * 100.0,
                redirect_utilization_pct = redirect_utilization * 100.0,
                handoff_utilization_pct = handoff_utilization * 100.0,
                "BPF janitor: UDP conn-state overflow is high; consider increasing map capacity or reducing the UDP connection timeout"
            );
        }
        if tcp_overflow > 100 {
            crate::logging::warn_on_entry!(
                first_in_episode(tcp_increased, &mut latches.tcp_pressure_warned),
                overflow = tcp_overflow,
                conn_utilization_pct = conn_utilization * 100.0,
                redirect_utilization_pct = redirect_utilization * 100.0,
                handoff_utilization_pct = handoff_utilization * 100.0,
                "BPF janitor: TCP conn-state overflow is high; consider increasing map capacity or reducing the TCP connection timeout"
            );
        }

        if conn_utilization >= CONN_STATE_PRESSURE_WATERMARK {
            crate::logging::warn_on_entry!(
                first_in_episode(true, &mut latches.occupancy_warned),
                conn_utilization_pct = conn_utilization * 100.0,
                redirect_utilization_pct = redirect_utilization * 100.0,
                handoff_utilization_pct = handoff_utilization * 100.0,
                "BPF janitor: conn-state map occupancy is high; sweeping every tick; consider increasing MAX_CONN_STATE_NUM if this persists"
            );
        }
        Ok(())
    }
}
