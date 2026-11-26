use std::{error::Error, sync::Arc};

use honk_outbound::{
    alive::{
        IpVersion, ProbeDomain, RouteHealthRevision, UdpBareReply, UdpHealthNotifications,
        UdpHopRole, UdpRouteAdmission,
    },
    group::{ExitCollapse, GroupManager, OwnedTarget, ScoreOutcome, ScoreReporter},
    proxy::DialFailureScope,
    runtime::OutboundRuntimeRegistry,
};

pub(in crate::control) struct UdpTrafficEvidence {
    manager: Arc<GroupManager>,
    generation: Arc<OutboundRuntimeRegistry>,
    kind: EvidenceKind,
}

enum EvidenceKind {
    Route {
        admission: UdpRouteAdmission,
        leaf_hops: usize,
        collapse: ExitCollapse,
    },
    Bare(UdpBareReply),
}

impl UdpTrafficEvidence {
    pub(in crate::control) fn capture_route(
        manager: &Arc<GroupManager>,
        generation: &Arc<OutboundRuntimeRegistry>,
        target: &OwnedTarget,
        selection_chain: &[String],
        final_owners: &[String],
        revision: RouteHealthRevision,
        family: IpVersion,
    ) -> Option<Self> {
        let admission = manager.capture_udp_route(
            target,
            selection_chain,
            final_owners,
            revision,
            ProbeDomain::DataUdp,
            family,
        )?;
        let leaf_hops = match target.route() {
            Some(route) => route.leaf_hops(),
            None => target.node.resolved_chain_hops().map_or(
                usize::from(target.collapse == ExitCollapse::Member),
                <[_]>::len,
            ),
        };
        Some(Self {
            manager: Arc::clone(manager),
            generation: Arc::clone(generation),
            kind: EvidenceKind::Route {
                admission,
                leaf_hops,
                collapse: target.collapse,
            },
        })
    }

    pub(in crate::control) fn capture_bare(
        manager: &Arc<GroupManager>,
        generation: &Arc<OutboundRuntimeRegistry>,
        node: uuid::Uuid,
        family: IpVersion,
    ) -> Option<Self> {
        let proof = manager.capture_udp_bare_reply(node, family)?;
        Some(Self {
            manager: Arc::clone(manager),
            generation: Arc::clone(generation),
            kind: EvidenceKind::Bare(proof),
        })
    }

    pub(in crate::control) fn is_route(&self) -> bool {
        matches!(self.kind, EvidenceKind::Route { .. })
    }

    pub(in crate::control) fn current(&self) -> bool {
        match &self.kind {
            EvidenceKind::Route { admission, .. } => {
                !self.generation.is_shutdown() && self.manager.udp_route_current(admission)
            }
            EvidenceKind::Bare(_) => true,
        }
    }

    pub(in crate::control) fn publish_score(
        evidence: Option<&Self>,
        reporter: &ScoreReporter,
        publish: impl FnOnce(&ScoreReporter),
    ) {
        if let Some(Self {
            manager,
            generation,
            kind: EvidenceKind::Route { admission, .. },
        }) = evidence
        {
            manager.with_udp_score_authority(admission, |current| {
                if current && !generation.is_shutdown() {
                    publish(reporter);
                } else {
                    reporter.finish_stale();
                }
            });
        } else {
            publish(reporter);
        }
    }

    pub(super) fn depends_on(
        &self,
        node: uuid::Uuid,
        domain: ProbeDomain,
        family: IpVersion,
        role: UdpHopRole,
    ) -> bool {
        if self.generation.is_shutdown() {
            return false;
        }
        let depends = match &self.kind {
            EvidenceKind::Route { admission, .. } => {
                admission.depends_on(node, domain, family, role)
            }
            EvidenceKind::Bare(proof) => proof.depends_on(node, domain, family, role),
        };
        depends && self.manager.udp_hop_down(node, domain, family, role)
    }

    pub(in crate::control) fn report_failure(&self, error: &(dyn Error + 'static)) {
        if let EvidenceKind::Route { admission, .. } = &self.kind
            && !self.generation.is_shutdown()
        {
            self.manager.report_udp_route_failure(admission, error);
        }
    }

    pub(super) fn report_reply(&self) {
        if let Some(notifications) = self.settle_reply() {
            notifications.notify();
        }
    }

    pub(super) fn settle_reply(&self) -> Option<UdpHealthNotifications<'_>> {
        if self.generation.is_shutdown() {
            return None;
        }
        match &self.kind {
            EvidenceKind::Route { admission, .. } => self.manager.settle_udp_route_reply(admission),
            EvidenceKind::Bare(proof) => self.manager.settle_udp_bare_reply(proof),
        }
    }

    pub(in crate::control) fn score_failure(
        &self,
        outcome: ScoreOutcome,
        scope: DialFailureScope,
    ) -> ScoreOutcome {
        let EvidenceKind::Route {
            leaf_hops,
            collapse,
            ..
        } = self.kind
        else {
            return outcome;
        };
        if matches!(
            outcome,
            ScoreOutcome::Success
                | ScoreOutcome::Shutdown
                | ScoreOutcome::Cancelled
                | ScoreOutcome::Rejected
        ) {
            return outcome;
        }
        match scope {
            DialFailureScope::Hop(hop) | DialFailureScope::Prefix(hop) if hop < leaf_hops => {
                outcome
            }
            DialFailureScope::Target => ScoreOutcome::TargetFailure,
            DialFailureScope::LocalRejection => ScoreOutcome::Rejected,
            DialFailureScope::Unattributed
                if collapse == ExitCollapse::Member && outcome.is_node_failure() =>
            {
                outcome
            }
            _ => ScoreOutcome::RouteFailure,
        }
    }
}
