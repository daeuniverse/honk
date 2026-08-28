use super::*;
mod connectivity;
mod fingerprint;
mod policy;
mod subscription;
mod transaction;
mod warm;

pub(in crate::control) use fingerprint::{
    dns_routing_state_reusable, effective_config_unchanged, routing_state_reusable,
    subscription_nodes_unchanged,
};
pub(in crate::control) use policy::restart_required_changes;

#[cfg(test)]
pub(in crate::control) use warm::{
    SelectorWarmResources, run_udp_warm_dispatches, selector_warm_candidates, udp_warm_candidates,
    warm_selector_candidate,
};

#[cfg(test)]
pub(in crate::control) use subscription::config_with_subscription_nodes;

pub(in crate::control) use connectivity::{
    build_outbound_id_map, group_check_url_registrations, group_connectivity_snapshot,
    group_datapath_alive, install_interrupt_callback, install_selector_warm_callback,
    open_group_connectivity, publish_group_connectivity, sync_health_check_nodes,
    urltest_group_registrations,
};

#[cfg(feature = "clash-api")]
pub(crate) fn resolve_outbound_nodes(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    domain: ProbeDomain,
    ipver: IpVersion,
) -> Vec<Node> {
    if let Some(node) = config.builtin_node(outbound_name) {
        return vec![node];
    }
    if let Some(node) = config.nodes.iter().find(|n| n.name == outbound_name) {
        return vec![node.clone()];
    }
    for group in &config.groups {
        if group.name == outbound_name {
            let mut nodes =
                group_manager.select_nodes_in_order_for_domain(&group.name, domain, ipver);
            // Fallback: IPv6 targets may still be forwarded through nodes that
            // are only reachable over IPv4 (common for proxy servers with only
            // an A record). Try IPv4 alive candidates before giving up.
            if nodes.is_empty() && ipver == IpVersion::V6 {
                nodes = group_manager.select_nodes_in_order_for_domain(
                    &group.name,
                    domain,
                    IpVersion::V4,
                );
                if !nodes.is_empty() {
                    warn!(
                        "resolve_outbound_nodes: group '{}' has no IPv6 alive node; falling back to IPv4 alive candidates",
                        group.name
                    );
                }
            }
            if nodes.is_empty() {
                warn!(
                    "resolve_outbound_nodes: group '{}' has no available node (ipver={:?})",
                    group.name, ipver
                );
                // When all nodes in a group are dead and `final` is configured,
                // recursively resolve the fallback outbound.
                if let Some(final_name) = group_manager.get_final_outbound(&group.name) {
                    info!(
                        "Group '{}' has no alive nodes, falling back to final outbound '{}'",
                        group.name, final_name
                    );
                    return resolve_outbound_nodes(
                        config,
                        group_manager,
                        &final_name,
                        domain,
                        ipver,
                    );
                }
            }
            return nodes.into_iter().cloned().collect();
        }
    }
    warn!(
        "Outbound '{}' not found, falling back to direct",
        outbound_name
    );
    vec![Config::builtin_direct_node()]
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedScorePlan {
    pub(super) mode: honk_outbound::group::SelectionPlanMode,
    pub(super) nodes: Vec<Node>,
    pub(super) health_family: IpVersion,
    pub(super) feedback: Vec<Option<honk_outbound::group::ScoreFeedback>>,
    pub(super) selection_chains: Vec<Vec<String>>,
}

fn own_score_plan(plan: honk_outbound::group::ScoreSelectionPlan<'_>) -> ResolvedScorePlan {
    let mut nodes = Vec::with_capacity(plan.entries.len());
    let mut feedback = Vec::with_capacity(plan.entries.len());
    let mut selection_chains = Vec::with_capacity(plan.entries.len());
    for entry in plan.entries {
        nodes.push(entry.node.clone());
        feedback.push(entry.feedback);
        selection_chains.push(entry.selection_chain);
    }
    ResolvedScorePlan {
        mode: plan.mode,
        nodes,
        health_family: plan.health_family,
        feedback,
        selection_chains,
    }
}

pub(super) fn resolve_urltest_retry_plan_for_target(
    group_manager: &GroupManager,
    outbound_name: &str,
    context: &honk_outbound::group::ScoreSelectionContext,
) -> ResolvedScorePlan {
    own_score_plan(group_manager.urltest_retry_plan_for_target(outbound_name, context))
}

pub(super) fn resolve_outbound_plan_for_target(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    context: &honk_outbound::group::ScoreSelectionContext,
) -> ResolvedScorePlan {
    resolve_outbound_plan_for_target_inner(
        config,
        group_manager,
        outbound_name,
        context,
        0,
        &mut Vec::new(),
    )
}

fn resolve_outbound_plan_for_target_inner(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    context: &honk_outbound::group::ScoreSelectionContext,
    depth: usize,
    visited: &mut Vec<String>,
) -> ResolvedScorePlan {
    if let Some(node) = config.builtin_node(outbound_name) {
        return ResolvedScorePlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes: vec![node],
            health_family: context.health_family,
            feedback: vec![None],
            selection_chains: vec![vec![outbound_name.to_owned()]],
        };
    }
    if let Some(node) = config.nodes.iter().find(|node| node.name == outbound_name) {
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
            nodes: health_family.map(|_| node.clone()).into_iter().collect(),
            health_family: health_family.unwrap_or(context.health_family),
            feedback: health_family.map(|_| None).into_iter().collect(),
            selection_chains: health_family
                .map(|_| vec![node.name.clone()])
                .into_iter()
                .collect(),
        };
    }
    let Some(group) = config
        .groups
        .iter()
        .find(|group| group.name == outbound_name)
    else {
        return ResolvedScorePlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes: vec![Config::builtin_direct_node()],
            health_family: context.health_family,
            feedback: vec![None],
            selection_chains: vec![vec![Config::BUILTIN_DIRECT_NODE.to_owned()]],
        };
    };
    if depth >= honk_outbound::group::MAX_GROUP_DEPTH
        || visited.iter().any(|name| name == outbound_name)
    {
        return ResolvedScorePlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes: Vec::new(),
            health_family: context.health_family,
            feedback: Vec::new(),
            selection_chains: Vec::new(),
        };
    }
    let plan = group_manager.selection_plan_for_target_with_health_fallback(outbound_name, context);
    if !plan.entries.is_empty() {
        return own_score_plan(plan);
    }
    let Some(final_name) = group.final_outbound.as_deref() else {
        return ResolvedScorePlan {
            mode: plan.mode,
            nodes: Vec::new(),
            health_family: plan.health_family,
            feedback: Vec::new(),
            selection_chains: Vec::new(),
        };
    };
    visited.push(outbound_name.to_owned());
    let mut terminal = resolve_outbound_plan_for_target_inner(
        config,
        group_manager,
        final_name,
        context,
        depth + 1,
        visited,
    );
    visited.pop();
    for chain in &mut terminal.selection_chains {
        chain.insert(0, outbound_name.to_owned());
    }
    for (index, node) in terminal.nodes.iter().enumerate() {
        let outer = group_manager.feedback_for_group_node(outbound_name, node.id, context.clone());
        terminal.feedback[index] = match (outer, terminal.feedback[index].take()) {
            (Some(outer), Some(inner)) => {
                Some(inner.prepend_attribution(outer.attributions()[0].group.clone(), node.id))
            }
            (Some(outer), None) => Some(outer),
            (None, inner) => inner,
        };
    }
    terminal
}

/// Concrete UDP candidates plus target-aware Score feedback, attribution,
/// and the health family selected by final outbound resolution.
#[derive(Debug, Clone)]
pub(super) struct ResolvedUdpPlan {
    pub(super) mode: honk_outbound::group::SelectionPlanMode,
    pub(super) nodes: Vec<Node>,
    pub(super) ipver: IpVersion,
    pub(super) feedback: Vec<Option<honk_outbound::group::ScoreFeedback>>,
    pub(super) selection_chains: Vec<Vec<String>>,
}

pub(super) fn resolve_udp_outbound_plan_for_target(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    context: &honk_outbound::group::ScoreSelectionContext,
) -> ResolvedUdpPlan {
    let plan = resolve_outbound_plan_for_target(config, group_manager, outbound_name, context);
    ResolvedUdpPlan {
        mode: plan.mode,
        nodes: plan.nodes,
        ipver: plan.health_family,
        feedback: plan.feedback,
        selection_chains: plan.selection_chains,
    }
}
