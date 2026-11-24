use crate::alive::RouteHealthRevision;
use crate::group::observation;
use crate::group::{DialKey, GroupMember, ScoreView, SelectorState, Target};

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
    pub(in crate::group) selector: Option<&'a SelectorState>,
    /// The root group's `routes`: false when no group the root reaches has
    /// an exit, so nested levels skip their exit checks. True when unknown.
    pub(in crate::group) routes: bool,
    /// The packet dialer accepts configured nodes and single-hop collapses.
    pub(in crate::group) node_targets_only: bool,
    /// Preserve the ordinary walk's first family during packet DNS fallback.
    pub(in crate::group) packet_initial_family: Option<IpVersion>,
    /// Follow the sole leaf only on the root's authorized last-resort walk.
    pub(in crate::group) sole_leaf: bool,
}

impl Default for ScoreSelectionRules<'_> {
    fn default() -> Self {
        Self {
            cold_urltest: false,
            allow_trials: true,
            excluded: None,
            selector: None,
            routes: true,
            node_targets_only: false,
            packet_initial_family: None,
            sole_leaf: false,
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
        let membership = self
            .groups
            .values()
            .map(|entry| &entry.group)
            .flat_map(|group| {
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
            .map(|entry| &entry.group)
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
            .map(|entry| &entry.group)
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
            .map(|entry| &entry.group)
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

    /// Connectivity admission for exit routes and UDP-capable configured chains.
    /// Preview avoids Score membership changes, counters and trial reservations.
    pub fn routed_group_available(
        &self,
        group_name: &str,
        domain: ProbeDomain,
        family: IpVersion,
    ) -> Option<bool> {
        let entry = self.groups.get(group_name)?;
        let network = SelectionNetwork::from_probe_domain(domain);
        let udp = network == SelectionNetwork::Udp;
        if !(entry.routes || udp && self.group_has_udp_chain(group_name)) {
            return None;
        }
        let selector = if udp {
            self.route_plan_snapshot(group_name, network).0
        } else {
            None
        };
        let available = |health_family| {
            let context = ScoreSelectionContext::aggregate(network, domain, health_family);
            let (_, candidates) = self.selection_candidates_for_target(
                &entry.group,
                &context,
                &mut Vec::new(),
                0,
                super::SelectionEffects::Preview,
                ScoreSelectionRules {
                    allow_trials: false,
                    selector: selector.as_deref(),
                    routes: entry.routes,
                    ..Default::default()
                },
            );
            !candidates.is_empty()
        };
        Some(available(family) || (family == IpVersion::V6 && available(IpVersion::V4)))
    }

    fn capture_dial_plan<'a>(
        &'a self,
        group_name: &str,
        context: &ScoreSelectionContext,
        select: impl FnOnce(Option<&SelectorState>) -> ScoreSelectionPlan<'a>,
    ) -> (ScoreSelectionPlan<'a>, RouteHealthRevision) {
        let (selector, revision) = self.route_plan_snapshot(group_name, context.network);
        let plan = observation::capture(|| select(selector.as_deref()));
        (plan, revision)
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
        self.dial_plan_for_target(group_name, context, original).0
    }

    /// Each candidate and its health-family fallback use the Selector state named by the revision.
    pub fn dial_plan_for_target(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
        original: Option<&ScoreContinuation>,
    ) -> (ScoreSelectionPlan<'_>, RouteHealthRevision) {
        self.dial_plan_with_routes(group_name, context, original, false)
    }

    /// Select a target for a packet dialer that can open only a node's own transport.
    pub fn node_packet_dial_plan(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
        original: Option<&ScoreContinuation>,
    ) -> (ScoreSelectionPlan<'_>, RouteHealthRevision) {
        self.dial_plan_with_routes(group_name, context, original, true)
    }

    fn dial_plan_with_routes(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
        original: Option<&ScoreContinuation>,
        node_targets_only: bool,
    ) -> (ScoreSelectionPlan<'_>, RouteHealthRevision) {
        let node_targets_only = node_targets_only && context.network == SelectionNetwork::Udp;
        self.capture_dial_plan(group_name, context, |selector| {
            let rules = ScoreSelectionRules {
                selector,
                node_targets_only,
                packet_initial_family: node_targets_only.then_some(context.health_family),
                ..Default::default()
            };
            let plan = self.selection_plan_for_target_with_effects(
                group_name,
                context,
                super::SelectionEffects::ApplyWithHealthFallback,
                original,
                rules,
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
                original,
                rules,
            )
        })
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
        self.urltest_retry_dial_plan(group_name, context, original)
            .0
    }

    /// URLTest alternatives and the revision used for this retry round.
    pub fn urltest_retry_dial_plan(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
        original: Option<&ScoreContinuation>,
    ) -> (ScoreSelectionPlan<'_>, RouteHealthRevision) {
        self.capture_dial_plan(group_name, context, |selector| {
            let Some(entry) = self.groups.get(group_name) else {
                observation::gap();
                return super::ScoreSelectionPlan {
                    mode: super::SelectionPlanMode::Authoritative,
                    health_family: context.health_family,
                    entries: Vec::new(),
                    observation: None,
                };
            };
            let group = &entry.group;
            let pinned = group.policy == honk_config::group::GroupPolicy::URLTest
                && self
                    .plan_selector_member(group, context.network, selector)
                    .is_some();
            if group.policy != honk_config::group::GroupPolicy::URLTest || pinned {
                return observation::decision(
                    group,
                    context.health_family,
                    super::SelectionEffects::Peek,
                    || {
                        observation::reason(if pinned { "pinned" } else { "not_urltest" });
                        self.score_selection_plan(
                            Vec::new(),
                            super::SelectionPlanMode::Authoritative,
                            context,
                            original,
                            entry.routes,
                        )
                    },
                );
            }
            observation::decision(
                group,
                context.health_family,
                super::SelectionEffects::Peek,
                || {
                    let mut visited = Vec::new();
                    let (candidates, _) = self.flatten_candidates_for_target(
                        group,
                        context,
                        &mut visited,
                        0,
                        super::SelectionEffects::Peek,
                        ScoreSelectionRules {
                            allow_trials: false,
                            routes: entry.routes,
                            selector,
                            ..Default::default()
                        },
                    );
                    let candidates = self.filter_alive_candidates(
                        candidates,
                        context.probe_domain,
                        context.health_family,
                        group,
                        &[],
                        ScoreSelectionRules {
                            routes: entry.routes,
                            ..Default::default()
                        },
                    );
                    observation::metric("sorting_latency", None);
                    observation::reason("retry_candidates_pending");
                    let candidates = self.order_by_latency(
                        candidates,
                        context.network,
                        context.health_family,
                        group.check_url.as_deref(),
                    );
                    let root_has_exit = group.exit.is_some();
                    let mut keys = [DialKey::Node(Uuid::nil()); 3];
                    let limit = keys.len();
                    let mut accepted = 0;
                    let targets = candidates
                        .into_iter()
                        .filter_map(|mut candidate| {
                            if root_has_exit {
                                candidate.selection_chain.insert(0, group.name.as_str());
                                candidate.exit_on_path = true;
                            }
                            let (node, route) = if entry.routes {
                                self.compose_candidate_route(&candidate, context.network)?
                            } else {
                                (candidate.node, None)
                            };
                            let key = DialKey::of(node, route.as_ref());
                            if keys[..accepted].contains(&key) {
                                return None;
                            }
                            keys[accepted] = key;
                            accepted += 1;
                            if !root_has_exit {
                                candidate.selection_chain.insert(0, group.name.as_str());
                            }
                            let target = Target {
                                node,
                                route: route.map(Box::new),
                            };
                            Some((candidate, target))
                        })
                        .take(limit);
                    self.score_selection_plan_from_targets(
                        targets,
                        super::SelectionPlanMode::Authoritative,
                        context,
                        original,
                    )
                },
            )
        })
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
        self.score_retry_dial_plan(group_name, context, failed_node, final_owners, original)
            .0
    }

    /// Score replacement and the revision used for its new selection.
    pub fn score_retry_dial_plan(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
        failed_node: Uuid,
        final_owners: &[String],
        original: &ScoreContinuation,
    ) -> (ScoreSelectionPlan<'_>, RouteHealthRevision) {
        self.capture_dial_plan(group_name, context, |selector| {
            let excluded = ExcludedScoreLeaf {
                node_id: failed_node,
                final_owners,
            };
            let mut plan = self.selection_plan_for_target_with_effects(
                group_name,
                context,
                super::SelectionEffects::Apply,
                Some(original),
                ScoreSelectionRules {
                    excluded: Some(&excluded),
                    selector,
                    ..Default::default()
                },
            );
            plan.entries.retain(|entry| entry.feedback.is_some());
            plan
        })
    }

    pub(super) fn score_selection_plan<'a>(
        &'a self,
        candidates: Vec<super::Candidate<'a>>,
        mode: super::SelectionPlanMode,
        context: &ScoreSelectionContext,
        original: Option<&ScoreContinuation>,
        routes: bool,
    ) -> super::ScoreSelectionPlan<'a> {
        if routes {
            let targets = candidates.into_iter().filter_map(|candidate| {
                let target = self.routed_chain(&candidate, context.network)?;
                Some((candidate, target))
            });
            self.score_selection_plan_from_targets(targets, mode, context, original)
        } else {
            debug_assert!(
                candidates
                    .iter()
                    .all(|candidate| self.dials_its_leaf(candidate, context.network)),
                "a candidate under a root without routes does not dial its leaf"
            );
            let targets = candidates.into_iter().map(|candidate| {
                let target = Target::node(candidate.node);
                (candidate, target)
            });
            self.score_selection_plan_from_targets(targets, mode, context, original)
        }
    }

    fn score_selection_plan_from_targets<'a>(
        &'a self,
        targets: impl Iterator<Item = (super::Candidate<'a>, Target<'a>)>,
        mode: super::SelectionPlanMode,
        context: &ScoreSelectionContext,
        original: Option<&ScoreContinuation>,
    ) -> super::ScoreSelectionPlan<'a> {
        let mut opportunity = original.map(|original| Arc::clone(&original.opportunity));
        // Filtered plans have no exact size, but their candidate count bounds the allocation.
        let mut entries = Vec::with_capacity(targets.size_hint().1.unwrap_or_default());
        entries.extend(targets.map(|(candidate, target)| {
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
            let feedback = (!attributions.is_empty()).then(|| {
                ScoreAttempt::planned(
                    ScoreFeedback::new(
                        Arc::clone(&self.score_state),
                        Arc::clone(&self.score_authority),
                        context.clone(),
                        attributions,
                    )
                    .with_pool_bound(candidate.pool_bound),
                    Arc::clone(
                        opportunity.get_or_insert_with(|| Arc::new(budget::Opportunity::default())),
                    ),
                    candidate.score_work,
                    if original.is_some() {
                        ScoreTrialSource::Recovery
                    } else {
                        ScoreTrialSource::None
                    },
                )
            });
            super::ScoreSelectionEntry {
                node: target.node,
                collapse: target.collapse(candidate.node, candidate.exit_on_path),
                route: target.route,
                feedback,
                selection_chain,
                final_owners: candidate
                    .final_owners
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            }
        }));
        super::ScoreSelectionPlan {
            mode,
            health_family: context.health_family,
            observation: None,
            entries,
        }
    }

    /// Target-aware, candidate-safe plan with attribution captured during
    /// recursive selection rather than recovered from the selected NodeId.
    pub fn selection_plan_for_target(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
    ) -> super::ScoreSelectionPlan<'_> {
        self.capture_dial_plan(group_name, context, |selector| {
            self.selection_plan_for_target_with_effects(
                group_name,
                context,
                super::SelectionEffects::Apply,
                None,
                ScoreSelectionRules {
                    selector,
                    ..Default::default()
                },
            )
        })
        .0
    }

    fn selection_plan_for_target_with_effects(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
        effects: super::SelectionEffects,
        original: Option<&ScoreContinuation>,
        rules: ScoreSelectionRules<'_>,
    ) -> super::ScoreSelectionPlan<'_> {
        let Some(entry) = self.groups.get(group_name) else {
            observation::gap();
            return self.score_selection_plan(
                Vec::new(),
                super::SelectionPlanMode::Authoritative,
                context,
                original,
                false,
            );
        };
        let (mode, candidates) = self.selection_candidates_for_entry(
            &entry.group,
            Some(&entry.idle_activity),
            context,
            &mut Vec::new(),
            0,
            effects,
            ScoreSelectionRules {
                cold_urltest: rules.excluded.is_none(),
                allow_trials: rules.excluded.is_none() && original.is_none(),
                routes: entry.routes,
                node_targets_only: rules.node_targets_only && entry.routes,
                packet_initial_family: rules.packet_initial_family.filter(|_| entry.routes),
                ..rules
            },
        );
        self.score_selection_plan(candidates, mode, context, original, entry.routes)
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
        self.selection_candidates_for_entry(group, None, context, visited, depth, effects, rules)
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::group) fn selection_candidates_for_entry<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        idle_activity: Option<&'a std::sync::OnceLock<Arc<crate::alive::IdleActivitySlot>>>,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
        rules: ScoreSelectionRules<'_>,
    ) -> (super::SelectionPlanMode, Vec<super::Candidate<'a>>) {
        observation::decision(group, context.health_family, effects, || {
            if depth >= super::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
                observation::reason("resolution_limit");
                return (super::SelectionPlanMode::Authoritative, Vec::new());
            }
            // Offering none when no route through the exit can carry UDP,
            // before any policy runs, lets a parent pick a UDP-capable sibling.
            if context.network == SelectionNetwork::Udp
                && group.exit.is_some()
                && !self.exit_offers_udp(group, visited)
            {
                observation::reason("exit_without_udp");
                return (super::SelectionPlanMode::Authoritative, Vec::new());
            }
            let (mut mode, mut candidates, mut ordinary) = self.normal_candidates_for_target(
                group,
                idle_activity,
                context,
                visited,
                depth,
                effects,
                rules,
            );
            if candidates.is_empty()
                && let Some(member) = self.final_member(group)
                && rules.excluded.is_none_or(|excluded| {
                    matches!(member, GroupMember::Group(_))
                        && excluded.final_owners.contains(&group.name)
                })
            {
                ordinary = false;
                // A business IPv6 target may use an IPv4 proxy. Defer this final
                // until the outer health-family retry has tried that ordinary path.
                if (effects.health_fallback()
                    || (!rules.node_targets_only && rules.packet_initial_family.is_some()))
                    && context.health_family == IpVersion::V6
                {
                    let mut ipv4 = context.clone();
                    ipv4.health_family = IpVersion::V4;
                    let preflight = if effects.prepares_score() {
                        super::SelectionEffects::Preview
                    } else {
                        effects.peek()
                    };
                    if !observation::decision(group, ipv4.health_family, preflight, || {
                        self.normal_candidates_for_target(
                            group,
                            idle_activity,
                            &ipv4,
                            visited,
                            depth,
                            preflight,
                            rules,
                        )
                    })
                    .1
                    .is_empty()
                    {
                        observation::reason("health_family_fallback");
                        return (mode, candidates);
                    }
                }
                match member {
                    GroupMember::Node(node) => {
                        let routed = self.has_exits() && rules.routes;
                        let eligible = if routed && context.probe_domain != ProbeDomain::Tcp {
                            self.leaf_route_available(
                                node,
                                group,
                                visited,
                                context.probe_domain,
                                Some(context.health_family),
                                rules.node_targets_only,
                            )
                        } else {
                            matches!(
                                node.protocol(),
                                honk_config::types::NodeProtocol::Direct
                                    | honk_config::types::NodeProtocol::Block
                            ) || self.is_node_selectable_for_domain(
                                node.id,
                                context.probe_domain,
                                context.health_family,
                            )
                        };
                        observation::member(
                            member,
                            Some(node),
                            Some(eligible),
                            "final_eligibility",
                        );
                        if eligible {
                            mode = super::SelectionPlanMode::Authoritative;
                            candidates.push(super::Candidate {
                                via: None,
                                node,
                                attribution: Vec::new(),
                                pool_bound: 0,
                                selection_chain: vec![node.name.as_str()],
                                exit_on_path: false,
                                final_owners: if context.network == SelectionNetwork::Udp
                                    && (node.chain_hops().is_some() || rules.routes)
                                {
                                    vec![group.name.as_str()]
                                } else {
                                    Vec::new()
                                },
                                score_work: Vec::new(),
                            });
                        }
                    }
                    GroupMember::Group(final_group) => {
                        visited.push(group.name.as_str());
                        (mode, candidates) = self.selection_candidates_for_target(
                            final_group,
                            context,
                            visited,
                            depth + 1,
                            effects,
                            ScoreSelectionRules {
                                sole_leaf: false,
                                ..rules
                            },
                        );
                        visited.pop();
                        for candidate in &mut candidates {
                            candidate.via = Some(final_group);
                            candidate.final_owners.insert(0, group.name.as_str());
                        }
                        if candidates.is_empty() {
                            observation::member(member, None, Some(false), "final_empty");
                        } else {
                            for candidate in &candidates {
                                observation::candidate(candidate, true, "final_candidate");
                            }
                        }
                    }
                }
                if context.probe_domain == ProbeDomain::Tcp && self.has_exits() && rules.routes {
                    candidates.retain(|candidate| {
                        candidate.via.is_some()
                            || self.leaf_route_available(
                                candidate.node,
                                group,
                                visited,
                                context.probe_domain,
                                Some(context.health_family),
                                rules.node_targets_only,
                            )
                    });
                }
                if mode == super::SelectionPlanMode::ColdUrlTest && !candidates.is_empty() {
                    observation::selected(None, "final_candidates_pending");
                } else {
                    observation::selected(
                        candidates.first(),
                        if candidates.is_empty() {
                            "final_unavailable"
                        } else {
                            "final_selected"
                        },
                    );
                }
            }
            for candidate in &mut candidates {
                if group.policy == honk_config::group::GroupPolicy::Score {
                    candidate.pool_bound = (candidate.pool_bound << 1) | u8::from(ordinary);
                    candidate.attribution.insert(0, group.name.as_str());
                }
                candidate.selection_chain.insert(0, group.name.as_str());
                candidate.exit_on_path |= group.exit.is_some();
            }
            (mode, candidates)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn normal_candidates_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        idle_activity: Option<&'a std::sync::OnceLock<Arc<crate::alive::IdleActivitySlot>>>,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
        rules: ScoreSelectionRules<'_>,
    ) -> (super::SelectionPlanMode, Vec<super::Candidate<'a>>, bool) {
        let selected_member = self.plan_selector_member(group, context.network, rules.selector);
        if let Some(member) = selected_member {
            observation::previous(member);
        }
        // A pinned automatic group chooses exactly like a Selector.
        let policy = if selected_member.is_some() {
            honk_config::group::GroupPolicy::Selector
        } else {
            group.policy
        };
        if effects.applies() && policy != honk_config::group::GroupPolicy::Selector {
            self.mark_used(&group.name, idle_activity);
        }
        let ordinary_score = policy == honk_config::group::GroupPolicy::Score;
        let (mut candidates, withdrawn) = if policy == honk_config::group::GroupPolicy::Selector
            && let Some(GroupMember::Group(subgroup)) = selected_member
        {
            // Apply must reach the chosen child even when its committed readonly view is empty.
            visited.push(group.name.as_str());
            let candidate = self.pick_candidate_for_target(
                subgroup,
                context,
                visited,
                depth + 1,
                effects,
                rules,
            );
            visited.pop();
            if candidate.is_none() {
                observation::member(
                    GroupMember::Group(subgroup),
                    None,
                    Some(false),
                    "empty_member",
                );
            }
            (
                candidate
                    .into_iter()
                    .map(|mut candidate| {
                        candidate.via = Some(subgroup);
                        candidate
                    })
                    .collect(),
                Vec::new(),
            )
        } else {
            self.flatten_candidates_for_target(group, context, visited, depth, effects, rules)
        };
        let before_filter = (!rules.node_targets_only
            && effects.prepares_score()
            && group.policy == honk_config::group::GroupPolicy::Score
            && self.score_state.is_current_authority(&self.score_authority))
        .then(|| super::unique_candidate_ids(&candidates))
        .flatten();
        candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group,
            visited,
            rules,
        );
        let health_filtered =
            before_filter.and_then(|before| super::removed_unique_candidates(before, &candidates));
        if effects.applies()
            && let Some(filtered) = &health_filtered
        {
            self.score_state.record_dead_filtered(
                &self.score_authority,
                SelectionReasonKey::new(&group.name, context.network),
                filtered.len(),
            );
        }
        if candidates.is_empty() {
            let candidate = (rules.excluded.is_none()
                && (!rules.routes || !self.has_exits() || depth == 0 || rules.sole_leaf))
                .then(|| {
                    self.last_resort_candidate_for_target(
                        group, context, visited, depth, effects, rules,
                    )
                })
                .flatten();
            let candidate = candidate.filter(|candidate| {
                !rules.routes
                    || !self.has_exits()
                    || candidate.via.is_some()
                    || self.leaf_route_available(
                        candidate.node,
                        group,
                        visited,
                        context.probe_domain,
                        None,
                        rules.node_targets_only,
                    )
            });
            let candidate = candidate.and_then(|candidate| {
                if ordinary_score {
                    self.pick_score(
                        ScoreView {
                            origins: &[candidate],
                            preview: effects == super::SelectionEffects::Preview,
                            ..Default::default()
                        },
                        group,
                        context,
                        effects,
                        false,
                    )
                } else {
                    Some(candidate)
                }
            });
            let mode = if candidate.is_none()
                && rules.cold_urltest
                && policy == honk_config::group::GroupPolicy::URLTest
            {
                super::SelectionPlanMode::ColdUrlTest
            } else {
                super::SelectionPlanMode::Authoritative
            };
            observation::selected(
                candidate.as_ref(),
                if candidate.is_some() {
                    "sole_tcp_leaf_last_resort"
                } else {
                    "no_eligible_candidate"
                },
            );
            return (mode, candidate.into_iter().collect(), ordinary_score);
        }
        if rules.cold_urltest
            && policy == honk_config::group::GroupPolicy::URLTest
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
            observation::metric("sorting_latency", None);
            observation::reason("cold_candidates_pending");
            return (
                super::SelectionPlanMode::ColdUrlTest,
                self.order_by_latency(
                    candidates,
                    context.network,
                    context.health_family,
                    group.check_url.as_deref(),
                ),
                false,
            );
        }
        let pin_effects = if rules.node_targets_only {
            effects.peek()
        } else {
            effects
        };
        let candidate = match policy {
            honk_config::group::GroupPolicy::Selector => {
                observation::reason("selector_choice");
                selected_member.and_then(|member| Self::pick_selector(&candidates, member))
            }
            honk_config::group::GroupPolicy::URLTest => Some(self.pick_urltest(
                &candidates,
                group,
                context.network,
                context.health_family,
                pin_effects,
            )),
            honk_config::group::GroupPolicy::LoadBalance => {
                let index = self.pick_load_balance(&candidates, group, context.network, effects);
                Some(candidates.swap_remove(index))
            }
            honk_config::group::GroupPolicy::Fallback => {
                let index = self.pick_fallback(&candidates, group, context.network, pin_effects);
                Some(candidates.swap_remove(index))
            }
            honk_config::group::GroupPolicy::Score if rules.node_targets_only => {
                let cold = !self
                    .score_state
                    .score_pool_initialized(&group.name, context.network);
                let bootstrap = cold
                    .then(|| self.packet_score_bootstrap(group, context, visited, depth, rules));
                self.pick_packet_score(&candidates, group, context, bootstrap, effects.applies())
            }
            honk_config::group::GroupPolicy::Score => self.pick_score(
                ScoreView {
                    origins: &candidates,
                    health_filtered: health_filtered.as_ref(),
                    withdrawn: &withdrawn,
                    preview: effects == super::SelectionEffects::Preview,
                },
                group,
                context,
                effects,
                rules.allow_trials,
            ),
        };
        observation::chosen(candidate.as_ref());
        if candidate.is_none() {
            observation::reason("selected_member_unavailable");
        }
        (
            super::SelectionPlanMode::Authoritative,
            candidate.into_iter().collect(),
            ordinary_score,
        )
    }

    fn packet_score_bootstrap<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        rules: ScoreSelectionRules<'_>,
    ) -> (ScoreSelectionContext, Vec<super::Candidate<'a>>) {
        let mut ordinary = context.clone();
        ordinary.probe_domain = ProbeDomain::DataUdp;
        ordinary.health_family = rules.packet_initial_family.unwrap_or(context.health_family);
        let rules = ScoreSelectionRules {
            allow_trials: false,
            node_targets_only: false,
            ..rules
        };
        let mut collect = |context: &ScoreSelectionContext| {
            observation::decision(
                group,
                context.health_family,
                super::SelectionEffects::Preview,
                || {
                    let (candidates, _) = self.flatten_candidates_for_target(
                        group,
                        context,
                        visited,
                        depth,
                        super::SelectionEffects::Preview,
                        rules,
                    );
                    self.filter_alive_candidates(
                        candidates,
                        context.probe_domain,
                        context.health_family,
                        group,
                        visited,
                        rules,
                    )
                },
            )
        };
        let mut candidates = collect(&ordinary);
        if candidates.is_empty() && ordinary.health_family == IpVersion::V6 {
            ordinary.health_family = IpVersion::V4;
            candidates = collect(&ordinary);
        }
        (ordinary, candidates)
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
        let selected_member =
            match self.plan_selector_member(group, context.network, rules.selector) {
                None if group.policy == honk_config::group::GroupPolicy::Selector => return None,
                selected_member => selected_member,
            };
        let node =
            self.last_resort_tcp_leaf(group, context.probe_domain, effects, rules.selector)?;
        if group.nodes.contains(&node.id)
            && selected_member.is_none_or(
                |member| matches!(member, GroupMember::Node(selected) if selected.id == node.id),
            )
        {
            return Some(super::Candidate {
                via: None,
                node,
                attribution: Vec::new(),
                pool_bound: 0,
                selection_chain: vec![node.name.as_str()],
                exit_on_path: false,
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
            let sub_entry = self.groups.get(tag)?;
            let subgroup = &sub_entry.group;
            self.pick_candidate_for_entry(
                subgroup,
                Some(&sub_entry.idle_activity),
                context,
                visited,
                depth + 1,
                effects,
                ScoreSelectionRules {
                    sole_leaf: true,
                    ..rules
                },
            )
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
        self.pick_candidate_for_entry(group, None, context, visited, depth, effects, rules)
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::group) fn pick_candidate_for_entry<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        idle_activity: Option<&'a std::sync::OnceLock<Arc<crate::alive::IdleActivitySlot>>>,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
        rules: ScoreSelectionRules<'_>,
    ) -> Option<super::Candidate<'a>> {
        self.selection_candidates_for_entry(
            group,
            idle_activity,
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

    pub(in crate::group) fn flatten_candidates_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
        rules: ScoreSelectionRules<'_>,
    ) -> (Vec<super::Candidate<'a>>, Vec<&'a str>) {
        if depth >= super::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return (Vec::new(), Vec::new());
        }
        visited.push(group.name.as_str());
        // Only the serving Selector or pinned member may advance nested policy
        // state.
        let sub_effects = if effects.applies()
            && (group.policy == honk_config::group::GroupPolicy::Selector
                || self
                    .plan_selector_member(group, context.network, rules.selector)
                    .is_some())
        {
            effects.peek()
        } else {
            effects
        };
        let mut candidates: Vec<_> = group
            .nodes
            .iter()
            .filter_map(|id| {
                let node = self.nodes.get(id);
                if node.is_none() {
                    observation::gap();
                }
                node
            })
            .filter(|node| {
                let eligible = rules
                    .excluded
                    .is_none_or(|excluded| node.id != excluded.node_id);
                if !eligible {
                    observation::member(
                        GroupMember::Node(node),
                        Some(node),
                        Some(false),
                        "retry_excluded",
                    );
                }
                eligible
            })
            .map(|node| super::Candidate {
                via: None,
                node,
                attribution: Vec::new(),
                pool_bound: 0,
                selection_chain: vec![node.name.as_str()],
                exit_on_path: false,
                final_owners: Vec::new(),
                score_work: Vec::new(),
            })
            .collect();
        let mut withdrawn = Vec::new();
        for tag in &group.groups {
            let Some(sub_entry) = self.groups.get(tag.as_str()) else {
                observation::gap();
                continue;
            };
            let subgroup = &sub_entry.group;
            if let Some(mut candidate) = self.pick_candidate_for_entry(
                subgroup,
                Some(&sub_entry.idle_activity),
                context,
                visited,
                depth + 1,
                sub_effects,
                rules,
            ) {
                candidate.via = Some(subgroup);
                candidates.push(candidate);
            } else {
                observation::member(
                    GroupMember::Group(subgroup),
                    None,
                    Some(false),
                    "empty_member",
                );
                if !rules.node_targets_only
                    && effects.prepares_score()
                    && group.policy == honk_config::group::GroupPolicy::Score
                    && rules.excluded.is_none()
                {
                    // A full child resolution is authoritative; a retry-only absence is not.
                    withdrawn.push(subgroup.name.as_str());
                }
            }
        }
        visited.pop();
        (candidates, withdrawn)
    }

    /// Inspect the ordinary aggregate choice without reserving validation work.
    pub fn score_verification_for_network(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> Option<(String, ScoreVerificationSnapshot)> {
        let entry = self.groups.get(group_name)?;
        let group = &entry.group;
        if group.policy != honk_config::group::GroupPolicy::Score {
            return None;
        }
        let context = Self::aggregate_score_context(network);
        let (candidates, _) = self.flatten_candidates_for_target(
            group,
            &context,
            &mut Vec::new(),
            0,
            super::SelectionEffects::Peek,
            ScoreSelectionRules {
                routes: entry.routes,
                ..Default::default()
            },
        );
        let candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group,
            &[],
            ScoreSelectionRules {
                routes: entry.routes,
                ..Default::default()
            },
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
        let (index, snapshot) = self.score_state.verification_selection(
            group_name,
            &context,
            &nodes,
            &names,
            &candidates,
        )?;
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
            .is_none_or(|entry| entry.group.policy != honk_config::group::GroupPolicy::Score)
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
        let entry = self.groups.get(group_name)?;
        let context = Self::aggregate_score_context(network);
        let mut visited = Vec::new();
        self.pick_candidate_for_target(
            &entry.group,
            &context,
            &mut visited,
            0,
            super::SelectionEffects::Peek,
            ScoreSelectionRules {
                routes: entry.routes,
                ..Default::default()
            },
        )
        .map(|candidate| candidate.tag().to_owned())
    }
}
