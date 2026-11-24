use super::*;
use honk_outbound::alive::RouteHealthRevision;
use honk_outbound::group::{DialKey, OwnedTarget};
use std::collections::HashSet;

pub(super) fn tcp_relay_score_outcome(error: &anyhow::Error) -> crate::group::ScoreOutcome {
    if error.is::<relay::ClientIoError>() {
        crate::group::ScoreOutcome::Cancelled
    } else {
        crate::group::ScoreOutcome::from_error(error)
    }
}

type UnpackedTcpScorePlan = (
    Vec<OwnedTarget>,
    SelectionPlanMode,
    HashMap<DialKey, crate::group::ScoreAttempt>,
    HashMap<DialKey, Vec<String>>,
    HashMap<DialKey, Vec<String>>,
    IpVersion,
    RouteHealthRevision,
);

pub(super) fn tcp_score_context(
    target: SocketAddr,
    domain: Option<&str>,
    health_family: IpVersion,
) -> crate::group::ScoreSelectionContext {
    let target_family = if target.is_ipv6() {
        IpVersion::V6
    } else {
        IpVersion::V4
    };
    crate::group::ScoreSelectionContext {
        network: SelectionNetwork::Tcp,
        probe_domain: ProbeDomain::Tcp,
        target_family: Some(target_family),
        health_family,
        target: Some(match domain {
            Some(domain) => crate::group::ScoreTarget::domain(domain, target.port()),
            None => target.into(),
        }),
    }
}

pub(super) fn unpack_tcp_score_plan(
    plan: crate::control::reload::ResolvedScorePlan,
) -> UnpackedTcpScorePlan {
    let mut seen = HashSet::new();
    let mut targets = Vec::with_capacity(plan.targets.len());
    let mut feedback = HashMap::new();
    let mut selection_chains = HashMap::new();
    let mut final_owners = HashMap::new();
    for (((target, value), selection_chain), used_final_owners) in plan
        .targets
        .into_iter()
        .zip(plan.feedback)
        .zip(plan.selection_chains)
        .zip(plan.final_owners)
    {
        let key = target.key();
        if !seen.insert(key) {
            continue;
        }
        if let Some(value) = value {
            feedback.insert(key, value);
        }
        selection_chains.insert(key, selection_chain);
        if !used_final_owners.is_empty() {
            final_owners.insert(key, used_final_owners);
        }
        targets.push(target);
    }
    (
        targets,
        plan.mode,
        feedback,
        selection_chains,
        final_owners,
        plan.health_family,
        plan.route_revision,
    )
}

pub(super) fn timeout_started_score_reporters(
    reporters: &parking_lot::Mutex<Vec<(crate::group::ScoreReporter, bool)>>,
) {
    for (reporter, routed) in reporters.lock().iter() {
        reporter.setup_failed(if *routed {
            crate::group::ScoreOutcome::RouteFailure
        } else {
            crate::group::ScoreOutcome::Timeout
        });
    }
}

pub(super) const COLD_URLTEST_STAGGER: Duration = Duration::from_millis(200);

/// Wait until this candidate's absolute cold-URLTest release offset. The
/// first candidate starts immediately; sleeping candidates have not acquired
/// a dial permit and are dropped with their accepted connection owner.
pub(super) async fn wait_for_cold_urltest_release(index: usize) {
    if index != 0 {
        tokio::time::sleep(COLD_URLTEST_STAGGER.saturating_mul(index as u32)).await;
    }
}
