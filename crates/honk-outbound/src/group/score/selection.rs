use super::*;

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
            let mut node_ids: HashSet<_> = self
                .leaf_nodes_in_group(&group.name)
                .into_iter()
                .map(|node| node.id)
                .collect();
            let mut visited = HashSet::new();
            self.collect_final_outbound_node_ids(group, &mut visited, &mut node_ids);
            node_ids
                .into_iter()
                .map(move |node_id| (group.name.clone(), node_id))
        });
        self.score_state
            .publish_generation(Arc::clone(&self.score_authority), groups, membership);
    }

    fn collect_final_outbound_node_ids(
        &self,
        group: &honk_config::group::Group,
        visited: &mut HashSet<String>,
        node_ids: &mut HashSet<Uuid>,
    ) {
        if !visited.insert(group.name.clone()) {
            return;
        }
        let Some(final_name) = group.final_outbound.as_deref() else {
            return;
        };
        match final_name {
            honk_config::Config::BUILTIN_DIRECT_NODE => {
                node_ids.insert(honk_config::config::DIRECT_NODE_ID);
            }
            honk_config::Config::BUILTIN_BLOCK_NODE => {
                node_ids.insert(honk_config::config::BLOCK_NODE_ID);
            }
            _ => {
                if let Some(node) = self.node_by_name(final_name) {
                    node_ids.insert(node.id);
                } else if let Some(final_group) = self.groups.get(final_name) {
                    node_ids.extend(
                        self.leaf_nodes_in_group(final_name)
                            .into_iter()
                            .map(|node| node.id),
                    );
                    self.collect_final_outbound_node_ids(final_group, visited, node_ids);
                }
            }
        }
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
            .filter(|group| {
                self.leaf_nodes_in_group(&group.name)
                    .iter()
                    .any(|node| node.id == node_id)
            })
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

    /// Feedback for a terminal `final` leaf attributed to one outer Honk
    /// group. Ordinary selected leaves should use their plan-carried feedback.
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
    ) -> super::ScoreSelectionPlan<'_> {
        let plan = self.selection_plan_for_target(group_name, context);
        if !plan.entries.is_empty() || context.health_family != IpVersion::V6 {
            return plan;
        }
        let mut fallback = context.clone();
        fallback.health_family = IpVersion::V4;
        self.selection_plan_for_target(group_name, &fallback)
    }
    /// Return the latency-ordered URLTest alternatives for one target without
    /// changing selection state. Each entry keeps the same Honk attribution
    /// and selection chain as an ordinary target-aware plan.
    pub fn urltest_retry_plan_for_target(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
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
            .collect();
        self.score_selection_plan(candidates, super::SelectionPlanMode::Authoritative, context)
    }

    fn score_selection_plan<'a>(
        &'a self,
        candidates: Vec<super::Candidate<'a>>,
        mode: super::SelectionPlanMode,
        context: &ScoreSelectionContext,
    ) -> super::ScoreSelectionPlan<'a> {
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
                    let feedback = (!attributions.is_empty())
                        .then(|| {
                            ScoreFeedback::new(
                                Arc::clone(&self.score_state),
                                Arc::clone(&self.score_authority),
                                context.clone(),
                                attributions,
                            )
                        })
                        .filter(|_| self.score_state.is_current_authority(&self.score_authority));
                    super::ScoreSelectionEntry {
                        node: candidate.node,
                        feedback,
                        selection_chain,
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
        let Some(group) = self.groups.get(group_name) else {
            return super::ScoreSelectionPlan {
                mode: super::SelectionPlanMode::Authoritative,
                health_family: context.health_family,
                entries: Vec::new(),
            };
        };
        self.mark_used(group_name);
        let mut visited = Vec::new();
        let mut candidates = self.flatten_candidates_for_target(
            group,
            context,
            &mut visited,
            0,
            super::SelectionEffects::Apply,
        );
        let before_filter = (group.policy == honk_config::group::GroupPolicy::Score
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
        let (mode, candidates) = if candidates.is_empty() {
            let candidate = self.last_resort_candidate_for_target(
                group,
                context,
                &mut visited,
                0,
                super::SelectionEffects::Apply,
            );
            (
                super::SelectionPlanMode::Authoritative,
                candidate.into_iter().collect(),
            )
        } else if group.policy == honk_config::group::GroupPolicy::URLTest
            && !candidates.iter().any(|candidate| {
                self.node_latency(
                    candidate.node,
                    context.network,
                    context.health_family,
                    group.check_url.as_deref(),
                    candidate.tag,
                ) != Duration::MAX
            })
        {
            (
                super::SelectionPlanMode::ColdUrlTest,
                self.order_by_latency(
                    candidates,
                    context.network,
                    context.health_family,
                    group.check_url.as_deref(),
                ),
            )
        } else {
            let candidate = match group.policy {
                honk_config::group::GroupPolicy::Selector => {
                    let picked = self.pick_selector(
                        &candidates,
                        group,
                        context.network,
                        super::SelectionEffects::Apply,
                    );
                    self.commit_selector_pick_for_target(
                        group,
                        picked,
                        context,
                        &mut visited,
                        0,
                        super::SelectionEffects::Apply,
                    )
                }
                honk_config::group::GroupPolicy::URLTest => self.pick_urltest(
                    &candidates,
                    group,
                    context.network,
                    context.health_family,
                    super::SelectionEffects::Apply,
                ),
                honk_config::group::GroupPolicy::LoadBalance => self.pick_load_balance(
                    &candidates,
                    group,
                    context.network,
                    super::SelectionEffects::Apply,
                ),
                honk_config::group::GroupPolicy::Fallback => self.pick_fallback(
                    &candidates,
                    group,
                    context.network,
                    super::SelectionEffects::Apply,
                ),
                honk_config::group::GroupPolicy::Score => {
                    self.pick_score(&candidates, group, context, super::SelectionEffects::Apply)
                }
            };
            (super::SelectionPlanMode::Authoritative, vec![candidate])
        };
        let candidates = candidates
            .into_iter()
            .map(|mut candidate| {
                if group.policy == honk_config::group::GroupPolicy::Score {
                    candidate.attribution.insert(0, group.name.as_str());
                }
                candidate.selection_chain.insert(0, group.name.as_str());
                candidate
            })
            .collect();
        self.score_selection_plan(candidates, mode, context)
    }

    fn last_resort_candidate_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
    ) -> Option<super::Candidate<'a>> {
        if depth >= super::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return None;
        }
        let node = self.last_resort_tcp_leaf(group, context.probe_domain, effects)?;
        if group.nodes.contains(&node.id) {
            return Some(super::Candidate {
                tag: node.name.as_str(),
                node,
                attribution: Vec::new(),
                selection_chain: vec![node.name.as_str()],
            });
        }

        visited.push(group.name.as_str());
        let candidate = group.groups.iter().find_map(|tag| {
            let subgroup = self.groups.get(tag)?;
            self.pick_candidate_for_target(subgroup, context, visited, depth + 1, effects)
                .filter(|candidate| candidate.node.id == node.id)
                .map(|mut candidate| {
                    candidate.tag = tag.as_str();
                    candidate
                })
        });
        visited.pop();
        candidate
    }

    fn pick_candidate_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
    ) -> Option<super::Candidate<'a>> {
        let mut candidates =
            self.flatten_candidates_for_target(group, context, visited, depth, effects);
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
        let mut candidate = if candidates.is_empty() {
            self.last_resort_candidate_for_target(group, context, visited, depth, effects)
        } else {
            Some(match group.policy {
                honk_config::group::GroupPolicy::Selector => {
                    let picked = self.pick_selector(&candidates, group, context.network, effects);
                    self.commit_selector_pick_for_target(
                        group, picked, context, visited, depth, effects,
                    )
                }
                honk_config::group::GroupPolicy::URLTest => self.pick_urltest(
                    &candidates,
                    group,
                    context.network,
                    context.health_family,
                    effects,
                ),
                honk_config::group::GroupPolicy::LoadBalance => {
                    self.pick_load_balance(&candidates, group, context.network, effects)
                }
                honk_config::group::GroupPolicy::Fallback => {
                    self.pick_fallback(&candidates, group, context.network, effects)
                }
                honk_config::group::GroupPolicy::Score => {
                    self.pick_score(&candidates, group, context, effects)
                }
            })
        }?;
        if group.policy == honk_config::group::GroupPolicy::Score {
            candidate.attribution.insert(0, group.name.as_str());
        }
        candidate.selection_chain.insert(0, group.name.as_str());
        Some(candidate)
    }

    /// Target-aware counterpart of `commit_selector_pick`.
    fn commit_selector_pick_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        picked: super::Candidate<'a>,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
    ) -> super::Candidate<'a> {
        if !effects.applies() {
            return picked;
        }
        let Some(sub) = self.groups.get(picked.tag) else {
            return picked;
        };
        self.mark_used(picked.tag);
        visited.push(group.name.as_str());
        let committed = self.pick_candidate_for_target(sub, context, visited, depth + 1, effects);
        visited.pop();
        match committed {
            Some(mut committed) => {
                committed.tag = picked.tag;
                committed
            }
            None => picked,
        }
    }

    fn flatten_candidates_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
    ) -> Vec<super::Candidate<'a>> {
        if depth >= super::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return Vec::new();
        }
        visited.push(group.name.as_str());
        // Same rule as `flatten_candidates` (see `commit_selector_pick`).
        let sub_effects =
            if group.policy == honk_config::group::GroupPolicy::Selector && effects.applies() {
                super::SelectionEffects::Peek
            } else {
                effects
            };
        let mut candidates: Vec<_> = group
            .nodes
            .iter()
            .filter_map(|id| self.nodes.get(id))
            .map(|node| super::Candidate {
                tag: node.name.as_str(),
                node,
                attribution: Vec::new(),
                selection_chain: vec![node.name.as_str()],
            })
            .collect();
        for tag in &group.groups {
            let Some(subgroup) = self.groups.get(tag.as_str()) else {
                continue;
            };
            if sub_effects.applies() {
                self.mark_used(tag);
            }
            if let Some(mut candidate) =
                self.pick_candidate_for_target(subgroup, context, visited, depth + 1, sub_effects)
            {
                candidate.tag = tag.as_str();
                candidates.push(candidate);
            }
        }
        visited.pop();
        candidates
    }

    /// Aggregate winner used by display/control surfaces.
    pub fn get_score_selection_for_network(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> Option<String> {
        let group = self.groups.get(group_name)?;
        let context = ScoreSelectionContext::aggregate(
            network,
            match network {
                SelectionNetwork::Tcp => ProbeDomain::Tcp,
                SelectionNetwork::Udp => ProbeDomain::DataUdp,
            },
            IpVersion::V4,
        );
        let mut visited = Vec::new();
        let mut candidates = self.flatten_candidates_for_target(
            group,
            &context,
            &mut visited,
            0,
            super::SelectionEffects::Peek,
        );
        candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group.check_url.as_deref(),
        );
        (!candidates.is_empty()).then(|| {
            self.pick_score(&candidates, group, &context, super::SelectionEffects::Peek)
                .tag
                .to_string()
        })
    }
}
