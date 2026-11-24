use super::*;
use honk_outbound::alive::RouteHealthRevision;
use honk_outbound::group::{ExitCollapse, ScoreSelectionPlan};
mod connectivity;
mod dns;
mod fingerprint;
mod policy;
mod subscription;
mod transaction;
mod warm;
pub(in crate::control) use warm::WarmTask;

pub(in crate::control) use fingerprint::{
    declaring_sources_replaced, dns_routing_state_reusable, effective_config_unchanged,
    routing_state_reusable, subscription_nodes_unchanged,
};
pub(crate) use policy::{LogFiles, StartupDowngrades, restart_required_fields};
#[cfg(test)]
pub(in crate::control) use policy::{RestartField, restart_required_changes};
#[cfg(feature = "native-api")]
pub(crate) use transaction::rebase_subscription_nodes;

#[cfg(test)]
pub(in crate::control) use warm::{
    SelectorWarmResources, run_udp_warm_dispatches, selector_warm_candidates, udp_warm_candidates,
    warm_selector_candidate,
};

#[cfg(test)]
pub(in crate::control) use subscription::config_with_subscription_nodes;

#[cfg(test)]
pub(in crate::control) use connectivity::sync_health_check_nodes;
pub(in crate::control) use connectivity::{
    OutboundHealthDependency, OutboundHealthIndex, build_outbound_id_map,
    extend_route_health_dependencies, group_check_url_registrations, group_connectivity_snapshot,
    group_datapath_alive, health_registrations, initial_route_connectivity,
    install_interrupt_callback, install_selector_warm_callback, open_group_connectivity,
    publish_group_connectivity, urltest_group_registrations,
};

#[derive(Clone, Copy, Debug, Default)]
pub(in crate::control) enum OutboundConstraint {
    #[default]
    Any,
    #[cfg(all(feature = "native-api", any(feature = "clash-api", test)))]
    Node(uuid::Uuid),
    #[cfg(feature = "native-api")]
    Unavailable,
}

/// What a resolved plan dials per entry. A TCP plan holds targets; a UDP
/// plan holds nodes, since routes through group exits carry TCP only and
/// selection offers none for UDP.
pub(super) trait PlanTarget: Sized {
    fn node(node: Node, collapse: ExitCollapse) -> Self;
    fn own(group_manager: &GroupManager, target: honk_outbound::group::Target<'_>) -> Option<Self>;
}

impl PlanTarget for honk_outbound::group::OwnedTarget {
    fn node(node: Node, collapse: ExitCollapse) -> Self {
        Self {
            node,
            route: None,
            collapse,
        }
    }

    fn own(group_manager: &GroupManager, target: honk_outbound::group::Target<'_>) -> Option<Self> {
        Some(group_manager.own_target(target))
    }
}

impl PlanTarget for Node {
    fn node(node: Node, _: ExitCollapse) -> Self {
        node
    }

    fn own(_: &GroupManager, target: honk_outbound::group::Target<'_>) -> Option<Self> {
        debug_assert!(target.route.is_none(), "a UDP plan holds no route");
        target.route.is_none().then(|| target.node.clone())
    }
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedScorePlan<T = honk_outbound::group::OwnedTarget> {
    pub(super) mode: honk_outbound::group::SelectionPlanMode,
    pub(super) targets: Vec<T>,
    pub(super) health_family: IpVersion,
    pub(super) route_revision: RouteHealthRevision,
    pub(super) feedback: Vec<Option<honk_outbound::group::ScoreAttempt>>,
    pub(super) selection_chains: Vec<Vec<String>>,
    pub(super) final_owners: Vec<Vec<String>>,
    #[cfg(feature = "native-api")]
    pub(super) observation: Option<Arc<honk_outbound::group::observation::SelectionObservation>>,
}

fn own_score_plan<T: PlanTarget>(
    group_manager: &GroupManager,
    (plan, route_revision): (ScoreSelectionPlan<'_>, RouteHealthRevision),
) -> ResolvedScorePlan<T> {
    let mut targets = Vec::with_capacity(plan.entries.len());
    let mut feedback = Vec::with_capacity(plan.entries.len());
    let mut selection_chains = Vec::with_capacity(plan.entries.len());
    let mut final_owners = Vec::with_capacity(plan.entries.len());
    for entry in plan.entries {
        // A plain node takes the clone-and-push path with no `Option<T>` in
        // between, which would copy the node once more.
        let target = match entry.route {
            None => T::node(entry.node.clone(), entry.collapse),
            route => {
                let target = honk_outbound::group::Target {
                    node: entry.node,
                    route,
                };
                let Some(target) = T::own(group_manager, target) else {
                    continue;
                };
                target
            }
        };
        targets.push(target);
        feedback.push(entry.feedback);
        selection_chains.push(entry.selection_chain);
        final_owners.push(entry.final_owners);
    }
    ResolvedScorePlan {
        mode: plan.mode,
        targets,
        health_family: plan.health_family,
        route_revision,
        feedback,
        selection_chains,
        final_owners,
        #[cfg(feature = "native-api")]
        observation: plan.observation,
    }
}

pub(super) fn resolve_urltest_retry_plan_for_target(
    group_manager: &GroupManager,
    outbound_name: &str,
    context: &honk_outbound::group::ScoreSelectionContext,
    original: Option<&honk_outbound::group::ScoreContinuation>,
) -> ResolvedScorePlan {
    own_score_plan(
        group_manager,
        group_manager.urltest_retry_dial_plan(outbound_name, context, original),
    )
}

pub(super) fn resolve_score_retry_plan_for_target(
    group_manager: &GroupManager,
    outbound_name: &str,
    context: &honk_outbound::group::ScoreSelectionContext,
    failed_node: uuid::Uuid,
    final_owners: &[String],
    original: &honk_outbound::group::ScoreContinuation,
) -> ResolvedScorePlan {
    own_score_plan(
        group_manager,
        group_manager.score_retry_dial_plan(
            outbound_name,
            context,
            failed_node,
            final_owners,
            original,
        ),
    )
}

pub(super) fn resolve_outbound_plan_for_target<T: PlanTarget>(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    context: &honk_outbound::group::ScoreSelectionContext,
    constraint: OutboundConstraint,
) -> ResolvedScorePlan<T> {
    #[cfg(feature = "native-api")]
    if match constraint {
        OutboundConstraint::Unavailable => true,
        #[cfg(any(feature = "clash-api", test))]
        OutboundConstraint::Node(id) => !config.nodes.iter().any(|node| node.id == id),
        OutboundConstraint::Any => false,
    } {
        return ResolvedScorePlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            targets: Vec::new(),
            health_family: context.health_family,
            route_revision: RouteHealthRevision::default(),
            feedback: Vec::new(),
            selection_chains: Vec::new(),
            final_owners: Vec::new(),
            #[cfg(feature = "native-api")]
            observation: None,
        };
    }
    if matches!(constraint, OutboundConstraint::Any)
        && let Some(node) = config.builtin_node(outbound_name)
    {
        return ResolvedScorePlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            targets: vec![T::node(node, ExitCollapse::None)],
            health_family: context.health_family,
            route_revision: RouteHealthRevision::default(),
            feedback: vec![None],
            selection_chains: vec![vec![outbound_name.to_owned()]],
            final_owners: vec![Vec::new()],
            #[cfg(feature = "native-api")]
            observation: None,
        };
    }
    if let Some(node) = config.nodes.iter().find(|node| match constraint {
        OutboundConstraint::Any => node.name == outbound_name,
        #[cfg(all(feature = "native-api", any(feature = "clash-api", test)))]
        OutboundConstraint::Node(id) => node.id == id,
        #[cfg(feature = "native-api")]
        OutboundConstraint::Unavailable => false,
    }) {
        let health_family = if group_manager.is_node_selectable_for_domain(
            node.id,
            context.probe_domain,
            context.health_family,
        ) {
            Some(context.health_family)
        } else if context.health_family == IpVersion::V6
            && group_manager.is_node_selectable_for_domain(
                node.id,
                context.probe_domain,
                IpVersion::V4,
            )
        {
            Some(IpVersion::V4)
        } else {
            None
        };
        return ResolvedScorePlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            targets: health_family
                .map(|_| T::node(node.clone(), ExitCollapse::None))
                .into_iter()
                .collect(),
            health_family: health_family.unwrap_or(context.health_family),
            route_revision: RouteHealthRevision::default(),
            feedback: health_family.map(|_| None).into_iter().collect(),
            selection_chains: health_family
                .map(|_| vec![node.name.clone()])
                .into_iter()
                .collect(),
            final_owners: health_family.map(|_| Vec::new()).into_iter().collect(),
            #[cfg(feature = "native-api")]
            observation: None,
        };
    }
    if !config
        .groups
        .iter()
        .any(|group| group.name == outbound_name)
    {
        return ResolvedScorePlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            targets: vec![T::node(Config::builtin_direct_node(), ExitCollapse::None)],
            health_family: context.health_family,
            route_revision: RouteHealthRevision::default(),
            feedback: vec![None],
            selection_chains: vec![vec![Config::BUILTIN_DIRECT_NODE.to_owned()]],
            final_owners: vec![Vec::new()],
            #[cfg(feature = "native-api")]
            observation: None,
        };
    }
    own_score_plan(
        group_manager,
        group_manager.dial_plan_for_target(outbound_name, context, None),
    )
}

/// Concrete UDP candidates plus target-aware Score feedback, attribution,
/// and the health family selected by final outbound resolution.
#[derive(Debug, Clone)]
pub(super) struct ResolvedUdpPlan {
    pub(super) mode: honk_outbound::group::SelectionPlanMode,
    pub(super) nodes: Vec<Node>,
    pub(super) ipver: IpVersion,
    pub(super) feedback: Vec<Option<honk_outbound::group::ScoreAttempt>>,
    pub(super) selection_chains: Vec<Vec<String>>,
    #[cfg(feature = "native-api")]
    pub(super) observation: Option<Arc<honk_outbound::group::observation::SelectionObservation>>,
}

pub(super) fn resolve_udp_outbound_plan_for_target(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    context: &honk_outbound::group::ScoreSelectionContext,
    constraint: OutboundConstraint,
) -> ResolvedUdpPlan {
    let plan = resolve_outbound_plan_for_target::<Node>(
        config,
        group_manager,
        outbound_name,
        context,
        constraint,
    );
    ResolvedUdpPlan {
        mode: plan.mode,
        nodes: plan.targets,
        ipver: plan.health_family,
        feedback: plan.feedback,
        selection_chains: plan.selection_chains,
        #[cfg(feature = "native-api")]
        observation: plan.observation,
    }
}
