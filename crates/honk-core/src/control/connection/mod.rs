pub(in crate::control) fn score_runtime_outcome(
    generation: &honk_outbound::runtime::OutboundRuntimeRegistry,
    error: &anyhow::Error,
) -> crate::group::ScoreOutcome {
    if generation.is_shutdown() {
        crate::group::ScoreOutcome::Shutdown
    } else {
        crate::group::ScoreOutcome::from_error(error)
    }
}
fn overall_dial_timeout(connect_timeout: std::time::Duration) -> std::time::Duration {
    connect_timeout
        .saturating_mul(4)
        .max(std::time::Duration::from_secs(10))
}

pub(in crate::control) fn report_dial_failure_if_current(
    generation: &honk_outbound::runtime::OutboundRuntimeRegistry,
    alive_set: &honk_outbound::alive::AliveDialerSet,
    node_id: uuid::Uuid,
    domain: honk_outbound::alive::ProbeDomain,
    ipver: honk_outbound::alive::IpVersion,
) {
    if generation.is_shutdown() {
        return;
    }
    alive_set.report_unavailable_traffic(node_id, domain, ipver);
    alive_set.record_dial_failure(node_id, domain, ipver);
    alive_set.notify_check_tcp(node_id);
}

mod handoff;
pub(crate) use handoff::build_tuples_key;
pub(super) use handoff::{TcpFlowKey, TcpFlowPins};

mod context;

#[cfg_attr(not(feature = "native-api"), path = "observation/inert.rs")]
pub(in crate::control) mod observation;

pub(super) use context::{ConnectionGuard, ControlPlaneHandle};

mod tcp;

mod udp;

mod routing;

#[cfg(test)]
pub(in crate::control) use routing::{RealityOutcome, domain_reality_outcome};
