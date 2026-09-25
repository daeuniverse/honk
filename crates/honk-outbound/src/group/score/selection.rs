use crate::group::GroupMember;

use super::*;

pub(in crate::group) struct ExcludedScoreLeaf<'a> {
    node_id: Uuid,
    final_owners: &'a [String],
}

#[derive(Clone, Copy)]
pub(in crate::group) struct ScoreSelectionRules<'a> {
    pub(in crate::group) cold_urltest: bool,
    pub(in crate::group) allow_trials: bool,
    pub(in crate::group) excluded: Option<&'a ExcludedScoreLeaf<'a>>,
}

impl Default for ScoreSelectionRules<'_> {
    fn default() -> Self {
        Self {
            cold_urltest: false,
            allow_trials: true,
            excluded: None,
        }
    }
}

impl super::GroupManager {
    /// Shared scorer handle for fallible reload construction.
    pub fn score_state(&self) -> Arc<ScorePolicyState> {
        Arc::clone(&self.score_state)
    }

    /// Publish committed group/leaf membership and prune only removed pairs.
    /// Extant non-Score groups remain valid for reporters started before a
    /// policy change; new selection creates feedback only for Score groups.
    pub fn publish_score_membership(&self) {
        let groups = self.groups.keys().cloned().collect::<Vec<_>>();
        let membership = self.groups.values().flat_map(|group| {
            self.reachable_leaf_nodes_in_group(&group.name)
                .into_iter()
                .map(move |node| (group.name.clone(), node.id))
        });
        self.score_state
            .publish_generation(Arc::clone(&self.score_authority), groups, membership);
    }

    /// Aggregate scorer feedback for concrete work scheduled by leaf ID.
    /// Every Score group that recursively contains the leaf is attributed
    /// once, regardless of how many nested paths reach it.
    pub fn feedback_for_node(
        &self,
        node_id: Uuid,
        context: ScoreSelectionContext,
    ) -> Option<ScoreFeedback> {
        let attributions: Vec<_> = self
            .groups
            .values()
            .filter(|group| group.policy == honk_config::group::GroupPolicy::Score)
            .filter(|group| self.group_reaches_node(&group.name, node_id))
            .map(|group| ScoreAttribution {
                group: group.name.clone(),
                node_id,
            })
            .collect();
        (!attributions.is_empty() && self.score_state.is_current_authority(&self.score_authority))
            .then(|| {
                ScoreFeedback::new(
                    Arc::clone(&self.score_state),
                    Arc::clone(&self.score_authority),
                    context,
                    attributions,
                )
            })
    }

    /// Attribute configured HTTP quality only to groups checking the same URL.
    pub fn feedback_for_http_probe(
        &self,
        node_id: Uuid,
        context: ScoreSelectionContext,
        probe_url: &str,
        default_probe_url: &str,
    ) -> Option<ScoreFeedback> {
        let attributions: Vec<_> = self
            .groups
            .values()
            .filter(|group| group.policy == honk_config::group::GroupPolicy::Score)
            .filter(|group| group.check_url.as_deref().unwrap_or(default_probe_url) == probe_url)
            .filter(|group| self.group_reaches_node(&group.name, node_id))
            .map(|group| ScoreAttribution {
                group: group.name.clone(),
                node_id,
            })
            .collect();
        (!attributions.is_empty() && self.score_state.is_current_authority(&self.score_authority))
            .then(|| {
                ScoreFeedback::new(
                    Arc::clone(&self.score_state),
                    Arc::clone(&self.score_authority),
                    context,
                    attributions,
                )
                .with_source(ScoreSource::HealthProbe)
            })
    }

    /// Feedback for work explicitly attributed to one Score group.
    /// Selected leaves should use their plan-carried feedback.
    pub fn feedback_for_group_node(
        &self,
        group_name: &str,
        node_id: Uuid,
        context: ScoreSelectionContext,
    ) -> Option<ScoreFeedback> {
        self.groups
            .get(group_name)
            .filter(|group| group.policy == honk_config::group::GroupPolicy::Score)
            .filter(|_| self.score_state.is_current_authority(&self.score_authority))
            .map(|group| {
                ScoreFeedback::new(
                    Arc::clone(&self.score_state),
                    Arc::clone(&self.score_authority),
                    context,
                    vec![ScoreAttribution {
                        group: group.name.clone(),
                        node_id,
                    }],
                )
            })
    }

    /// Target-aware selection with IPv6-target/IPv4-proxy health fallback.
    /// The target family remains unchanged in feedback keys; only the
    /// candidate health filter retries with IPv4.
    pub fn selection_plan_for_target_with_health_fallback(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
        original: Option<&ScoreContinuation>,
    ) -> super::ScoreSelectionPlan<'_> {
        let plan = self.selection_plan_for_target_with_effects(
            group_name,
            context,
            super::SelectionEffects::ApplyWithHealthFallback,
            None,
            original,
        );
        if !plan.entries.is_empty() || context.health_family != IpVersion::V6 {
            return plan;
        }
        let mut fallback = context.clone();
        fallback.health_family = IpVersion::V4;
        self.selection_plan_for_target_with_effects(
            group_name,
            &fallback,
            super::SelectionEffects::Apply,
            None,
            original,
        )
    }
    /// Return the latency-ordered URLTest alternatives for one target without
    /// changing selection state. Each entry keeps the same Honk attribution
    /// and selection chain as an ordinary target-aware plan.
    pub fn urltest_retry_plan_for_target(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
        original: Option<&ScoreContinuation>,
    ) -> super::ScoreSelectionPlan<'_> {
        let Some(group) = self.groups.get(group_name) else {
            return super::ScoreSelectionPlan {
                mode: super::SelectionPlanMode::Authoritative,
                health_family: context.health_family,
                entries: Vec::new(),
            };
        };
        if group.policy != honk_config::group::GroupPolicy::URLTest {
            return super::ScoreSelectionPlan {
                mode: super::SelectionPlanMode::Authoritative,
                health_family: context.health_family,
                entries: Vec::new(),
            };
        }
        let mut visited = Vec::new();
        let candidates = self.flatten_candidates_for_target(
            group,
            context,
            &mut visited,
            0,
            super::SelectionEffects::Peek,
            ScoreSelectionRules {
                allow_trials: false,
                ..Default::default()
            },
        );
        let candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group.check_url.as_deref(),
        );
        let mut seen = std::collections::HashSet::new();
        let candidates = self
            .order_by_latency(
                candidates,
                context.network,
                context.health_family,
                group.check_url.as_deref(),
            )
            .into_iter()
            .filter(|candidate| seen.insert(candidate.node.id))
            .take(3)
            .map(|mut candidate| {
                candidate.selection_chain.insert(0, group.name.as_str());
                candidate
            })
            .collect();
        self.score_selection_plan(
            candidates,
            super::SelectionPlanMode::Authoritative,
            context,
            original,
        )
    }

    /// Resolve one different Score-owned TCP leaf without opening a new final edge.
    /// `final_owners` must come from the failed entry resolved by this manager.
    pub fn score_retry_plan_for_target(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
        failed_node: Uuid,
        final_owners: &[String],
        original: &ScoreContinuation,
    ) -> super::ScoreSelectionPlan<'_> {
        let excluded = ExcludedScoreLeaf {
            node_id: failed_node,
            final_owners,
        };
        let mut plan = self.selection_plan_for_target_with_effects(
            group_name,
            context,
            super::SelectionEffects::Apply,
            Some(&excluded),
            Some(original),
        );
        plan.entries.retain(|entry| entry.feedback.is_some());
        plan
    }

    fn score_selection_plan<'a>(
        &'a self,
        candidates: Vec<super::Candidate<'a>>,
        mode: super::SelectionPlanMode,
        context: &ScoreSelectionContext,
        original: Option<&ScoreContinuation>,
    ) -> super::ScoreSelectionPlan<'a> {
        let mut opportunity = original.map(|original| Arc::clone(&original.opportunity));
        super::ScoreSelectionPlan {
            mode,
            health_family: context.health_family,
            entries: candidates
                .into_iter()
                .map(|candidate| {
                    let attributions: Vec<_> = candidate
                        .attribution
                        .into_iter()
                        .map(|group| ScoreAttribution {
                            group: group.to_string(),
                            node_id: candidate.node.id,
                        })
                        .collect();
                    let selection_chain = candidate
                        .selection_chain
                        .into_iter()
                        .map(str::to_owned)
                        .collect();
                    let feedback =
                        (!attributions.is_empty()).then(|| {
                            ScoreAttempt::planned(
                                ScoreFeedback::new(
                                    Arc::clone(&self.score_state),
                                    Arc::clone(&self.score_authority),
                                    context.clone(),
                                    attributions,
                                ),
                                Arc::clone(opportunity.get_or_insert_with(|| {
                                    Arc::new(budget::Opportunity::default())
                                })),
                                candidate.score_work,
                                if original.is_some() {
                                    ScoreTrialSource::Recovery
                                } else {
                                    ScoreTrialSource::None
                                },
                            )
                        });
                    super::ScoreSelectionEntry {
                        node: candidate.node,
                        feedback,
                        selection_chain,
                        final_owners: candidate
                            .final_owners
                            .into_iter()
                            .map(str::to_owned)
                            .collect(),
                    }
                })
                .collect(),
        }
    }

    /// Target-aware, candidate-safe plan with attribution captured during
    /// recursive selection rather than recovered from the selected NodeId.
    pub fn selection_plan_for_target(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
    ) -> super::ScoreSelectionPlan<'_> {
        self.selection_plan_for_target_with_effects(
            group_name,
            context,
            super::SelectionEffects::Apply,
            None,
            None,
        )
    }

    fn selection_plan_for_target_with_effects(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
        effects: super::SelectionEffects,
        excluded: Option<&ExcludedScoreLeaf<'_>>,
        original: Option<&ScoreContinuation>,
    ) -> super::ScoreSelectionPlan<'_> {
        let Some(group) = self.groups.get(group_name) else {
            return self.score_selection_plan(
                Vec::new(),
                super::SelectionPlanMode::Authoritative,
                context,
                original,
            );
        };
        if effects.applies() {
            self.mark_used(group_name);
        }
        let (mode, candidates) = self.selection_candidates_for_target(
            group,
            context,
            &mut Vec::new(),
            0,
            effects,
            ScoreSelectionRules {
                cold_urltest: excluded.is_none(),
                allow_trials: excluded.is_none() && original.is_none(),
                excluded,
            },
        );
        self.score_selection_plan(candidates, mode, context, original)
    }

    pub(in crate::group) fn selection_candidates_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
        rules: ScoreSelectionRules<'_>,
    ) -> (super::SelectionPlanMode, Vec<super::Candidate<'a>>) {
        if depth >= super::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return (super::SelectionPlanMode::Authoritative, Vec::new());
        }
        let (mut mode, mut candidates) =
            self.normal_candidates_for_target(group, context, visited, depth, effects, rules);
        if candidates.is_empty()
            && let Some(member) = self.final_member(group)
            && rules.excluded.is_none_or(|excluded| {
                matches!(member, GroupMember::Group(_))
                    && excluded.final_owners.contains(&group.name)
            })
        {
            // A business IPv6 target may use an IPv4 proxy. Defer this final
            // until the outer health-family retry has tried that ordinary path.
            if effects.health_fallback() && context.health_family == IpVersion::V6 {
                let mut ipv4 = context.clone();
                ipv4.health_family = IpVersion::V4;
                if !self
                    .normal_candidates_for_target(
                        group,
                        &ipv4,
                        visited,
                        depth,
                        effects.peek(),
                        rules,
                    )
                    .1
                    .is_empty()
                {
                    return (mode, candidates);
                }
            }
            match member {
                GroupMember::Node(node) => {
                    if matches!(
                        node.protocol(),
                        honk_config::types::NodeProtocol::Direct
                            | honk_config::types::NodeProtocol::Block
                    ) || self.is_node_selectable_for_domain(
                        node.id,
                        context.probe_domain,
                        context.health_family,
                    ) {
                        mode = super::SelectionPlanMode::Authoritative;
                        candidates.push(super::Candidate {
                            via: None,
                            node,
                            attribution: Vec::new(),
                            selection_chain: vec![node.name.as_str()],
                            final_owners: Vec::new(),
                            score_work: Vec::new(),
                        });
                    }
                }
                GroupMember::Group(final_group) => {
                    if effects.applies() {
                        self.mark_used(&final_group.name);
                    }
                    visited.push(group.name.as_str());
                    (mode, candidates) = self.selection_candidates_for_target(
                        final_group,
                        context,
                        visited,
                        depth + 1,
                        effects,
                        rules,
                    );
                    visited.pop();
                    for candidate in &mut candidates {
                        candidate.via = Some(final_group);
                        candidate.final_owners.insert(0, group.name.as_str());
                    }
                }
            }
        }
        for candidate in &mut candidates {
            if group.policy == honk_config::group::GroupPolicy::Score {
                candidate.attribution.insert(0, group.name.as_str());
            }
            candidate.selection_chain.insert(0, group.name.as_str());
        }
        (mode, candidates)
    }

    fn normal_candidates_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
        rules: ScoreSelectionRules<'_>,
    ) -> (super::SelectionPlanMode, Vec<super::Candidate<'a>>) {
        let selected_member = self.selector_member(group);
        let mut candidates =
            self.flatten_candidates_for_target(group, context, visited, depth, effects, rules);
        let before_filter = (effects.applies()
            && group.policy == honk_config::group::GroupPolicy::Score
            && self.score_state.is_current_authority(&self.score_authority))
        .then(|| super::unique_candidate_ids(&candidates))
        .flatten();
        candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group.check_url.as_deref(),
        );
        if let Some(before_filter) = before_filter {
            self.score_state.record_dead_filtered(
                &self.score_authority,
                SelectionReasonKey::new(&group.name, context.network),
                super::removed_unique_candidate_count(before_filter, &candidates),
            );
        }
        if candidates.is_empty() {
            let candidate = rules
                .excluded
                .is_none()
                .then(|| {
                    self.last_resort_candidate_for_target(
                        group, context, visited, depth, effects, rules,
                    )
                })
                .flatten();
            let mode = if candidate.is_none()
                && rules.cold_urltest
                && group.policy == honk_config::group::GroupPolicy::URLTest
            {
                super::SelectionPlanMode::ColdUrlTest
            } else {
                super::SelectionPlanMode::Authoritative
            };
            return (mode, candidate.into_iter().collect());
        }
        if rules.cold_urltest
            && group.policy == honk_config::group::GroupPolicy::URLTest
            && !candidates.iter().any(|candidate| {
                self.node_latency(
                    candidate.node,
                    context.network,
                    context.health_family,
                    group.check_url.as_deref(),
                    candidate.tag(),
                ) != Duration::MAX
            })
        {
            return (
                super::SelectionPlanMode::ColdUrlTest,
                self.order_by_latency(
                    candidates,
                    context.network,
                    context.health_family,
                    group.check_url.as_deref(),
                ),
            );
        }
        let candidate = match group.policy {
            honk_config::group::GroupPolicy::Selector => selected_member
                .and_then(|member| Self::pick_selector(&candidates, member))
                .and_then(|picked| {
                    self.commit_selector_pick_for_target(
                        group, picked, context, visited, depth, effects, rules,
                    )
                }),
            honk_config::group::GroupPolicy::URLTest => Some(self.pick_urltest(
                &candidates,
                group,
                context.network,
                context.health_family,
                effects,
            )),
            honk_config::group::GroupPolicy::LoadBalance => {
                Some(self.pick_load_balance(&candidates, group, context.network, effects))
            }
            honk_config::group::GroupPolicy::Fallback => {
                Some(self.pick_fallback(&candidates, group, context.network, effects))
            }
            honk_config::group::GroupPolicy::Score => {
                Some(self.pick_score(&candidates, group, context, effects, rules.allow_trials))
            }
        };
        (
            super::SelectionPlanMode::Authoritative,
            candidate.into_iter().collect(),
        )
    }

    fn last_resort_candidate_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
        rules: ScoreSelectionRules<'_>,
    ) -> Option<super::Candidate<'a>> {
        if depth >= super::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return None;
        }
        let selected_member = if group.policy == honk_config::group::GroupPolicy::Selector {
            Some(self.selector_member(group)?)
        } else {
            None
        };
        let node = self.last_resort_tcp_leaf(group, context.probe_domain, effects)?;
        if group.nodes.contains(&node.id)
            && selected_member.is_none_or(
                |member| matches!(member, GroupMember::Node(selected) if selected.id == node.id),
            )
        {
            return Some(super::Candidate {
                via: None,
                node,
                attribution: Vec::new(),
                selection_chain: vec![node.name.as_str()],
                final_owners: Vec::new(),
                score_work: Vec::new(),
            });
        }

        visited.push(group.name.as_str());
        let candidate = group.groups.iter().find_map(|tag| {
            if selected_member.is_some_and(
                |member| !matches!(member, GroupMember::Group(selected) if selected.name == *tag),
            ) {
                return None;
            }
            let subgroup = self.groups.get(tag)?;
            self.pick_candidate_for_target(subgroup, context, visited, depth + 1, effects, rules)
                .filter(|candidate| candidate.node.id == node.id)
                .map(|mut candidate| {
                    candidate.via = Some(subgroup);
                    candidate
                })
        });
        visited.pop();
        candidate
    }

    pub(in crate::group) fn pick_candidate_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
        rules: ScoreSelectionRules<'_>,
    ) -> Option<super::Candidate<'a>> {
        self.selection_candidates_for_target(
            group,
            context,
            visited,
            depth,
            effects,
            ScoreSelectionRules {
                cold_urltest: false,
                ..rules
            },
        )
        .1
        .into_iter()
        .next()
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::group) fn commit_selector_pick_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        picked: super::Candidate<'a>,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
        rules: ScoreSelectionRules<'_>,
    ) -> Option<super::Candidate<'a>> {
        let Some(sub) = picked.via.filter(|_| effects.applies()) else {
            return Some(picked);
        };
        self.mark_used(&sub.name);
        visited.push(group.name.as_str());
        let committed =
            self.pick_candidate_for_target(sub, context, visited, depth + 1, effects, rules);
        visited.pop();
        committed.map(|mut committed| {
            committed.via = picked.via;
            committed
        })
    }

    pub(in crate::group) fn flatten_candidates_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
        rules: ScoreSelectionRules<'_>,
    ) -> Vec<super::Candidate<'a>> {
        if depth >= super::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return Vec::new();
        }
        visited.push(group.name.as_str());
        // Only the serving Selector member may advance nested policy state.
        let sub_effects =
            if group.policy == honk_config::group::GroupPolicy::Selector && effects.applies() {
                effects.peek()
            } else {
                effects
            };
        let mut candidates: Vec<_> = group
            .nodes
            .iter()
            .filter_map(|id| self.nodes.get(id))
            .filter(|node| {
                rules
                    .excluded
                    .is_none_or(|excluded| node.id != excluded.node_id)
            })
            .map(|node| super::Candidate {
                via: None,
                node,
                attribution: Vec::new(),
                selection_chain: vec![node.name.as_str()],
                final_owners: Vec::new(),
                score_work: Vec::new(),
            })
            .collect();
        for tag in &group.groups {
            let Some(subgroup) = self.groups.get(tag.as_str()) else {
                continue;
            };
            if sub_effects.applies() {
                self.mark_used(tag);
            }
            if let Some(mut candidate) = self.pick_candidate_for_target(
                subgroup,
                context,
                visited,
                depth + 1,
                sub_effects,
                rules,
            ) {
                candidate.via = Some(subgroup);
                candidates.push(candidate);
            }
        }
        visited.pop();
        candidates
    }

    /// Inspect the ordinary aggregate choice without reserving validation work.
    pub fn score_verification_for_network(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> Option<(String, ScoreVerificationSnapshot)> {
        let group = self.groups.get(group_name)?;
        if group.policy != honk_config::group::GroupPolicy::Score {
            return None;
        }
        let context = Self::aggregate_score_context(network);
        let candidates = self.flatten_candidates_for_target(
            group,
            &context,
            &mut Vec::new(),
            0,
            super::SelectionEffects::Peek,
            ScoreSelectionRules::default(),
        );
        let candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group.check_url.as_deref(),
        );
        let mut unique = Vec::with_capacity(candidates.len());
        for candidate in &candidates {
            if !unique
                .iter()
                .any(|existing: &&super::Candidate<'_>| existing.node.id == candidate.node.id)
            {
                unique.push(candidate);
            }
        }
        let nodes: Vec<_> = unique.iter().map(|candidate| candidate.node).collect();
        let names: Vec<_> = unique.iter().map(|candidate| candidate.tag()).collect();
        let (index, snapshot) = self
            .score_state
            .verification_selection(group_name, &context, &nodes, &names)?;
        Some((names[index].to_owned(), snapshot))
    }

    /// Group/network counters advance only during authorized selections.
    pub fn score_verification_counters(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> ScoreVerificationCounters {
        if self
            .groups
            .get(group_name)
            .is_none_or(|group| group.policy != honk_config::group::GroupPolicy::Score)
        {
            return ScoreVerificationCounters::default();
        }
        self.score_state.verification_counters(group_name, network)
    }

    /// Fixed aggregate accounting; reading cannot reserve, expire, or earn currency.
    pub fn score_budget_counters(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> ScoreBudgetCounters {
        self.score_state.budget_counters(group_name, network)
    }

    fn aggregate_score_context(network: SelectionNetwork) -> ScoreSelectionContext {
        ScoreSelectionContext::aggregate(
            network,
            match network {
                SelectionNetwork::Tcp => ProbeDomain::Tcp,
                SelectionNetwork::Udp => ProbeDomain::DataUdp,
            },
            IpVersion::V4,
        )
    }

    /// Aggregate winner used by display/control surfaces.
    pub fn get_score_selection_for_network(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> Option<String> {
        let group = self.groups.get(group_name)?;
        let context = Self::aggregate_score_context(network);
        let mut visited = Vec::new();
        self.pick_candidate_for_target(
            group,
            &context,
            &mut visited,
            0,
            super::SelectionEffects::Peek,
            ScoreSelectionRules::default(),
        )
        .map(|candidate| candidate.tag().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::group::{Group, GroupPolicy};
    use honk_config::node::Node;

    #[test]
    fn publication_between_ranking_and_plan_construction_refuses_node_work() {
        let nodes = ["a", "b"].map(|name| Node {
            id: Uuid::new_v5(&honk_config::node::NODE_ID_NAMESPACE, name.as_bytes()),
            name: name.into(),
            ..Default::default()
        });
        let group = Group {
            id: Uuid::new_v4(),
            name: "score".into(),
            policy: GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        };
        let manager = GroupManager::new(std::slice::from_ref(&group), &nodes);
        // Trials only serve challengers with fewer completions than the ordinary selection.
        manager.score_state().inner.lock().aggregate.put(
            AggregateKey {
                group: "score".into(),
                network: SelectionNetwork::Tcp,
                family: None,
                node_id: nodes[0].id,
            },
            Stats {
                setup_success: 1.0,
                updated_at: Some(Instant::now()),
                ..Default::default()
            },
        );
        let context = ScoreSelectionContext {
            network: SelectionNetwork::Tcp,
            probe_domain: ProbeDomain::Tcp,
            target_family: Some(IpVersion::V4),
            health_family: IpVersion::V4,
            target: Some(ScoreTarget::domain("reload.example", 443)),
        };
        let (mode, candidates) = manager.selection_candidates_for_target(
            &group,
            &context,
            &mut Vec::new(),
            0,
            SelectionEffects::Apply,
            ScoreSelectionRules {
                cold_urltest: true,
                ..Default::default()
            },
        );
        assert_eq!(
            manager
                .score_budget_counters("score", SelectionNetwork::Tcp)
                .reserved,
            1
        );
        let replacement = GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&group),
            &nodes,
            None,
            manager.score_state(),
        );
        replacement.publish_score_membership();
        let published = replacement.score_budget_counters("score", SelectionNetwork::Tcp);
        let plan = manager.score_selection_plan(candidates, mode, &context, None);
        assert!(
            !plan.entries[0]
                .feedback
                .as_ref()
                .is_none_or(|attempt| attempt.begin().is_ok())
        );
        assert_eq!(
            replacement.score_budget_counters("score", SelectionNetwork::Tcp),
            published
        );
        assert_eq!(replacement.score_state().root_business_starts(), 0);
        assert_eq!(
            (published.reserved, published.spent, published.refunded),
            (0, 0, 1)
        );
    }
}
