//! Source-time policy facts; no target keys, scorer cells, or later state reads.

#[cfg(feature = "flow-observation")]
use std::sync::Arc;
use uuid::Uuid;

use super::{Candidate, Group, GroupMember, IpVersion, ScoreSelectionPlan, SelectionEffects};

#[derive(Clone, Debug)]
pub struct SelectionObservation {
    pub decisions: Vec<GroupDecision>,
    pub truncated: bool,
}

#[derive(Clone, Debug)]
pub struct GroupDecision {
    pub group_name: String,
    pub policy: &'static str,
    pub reason: &'static str,
    pub health_family: IpVersion,
    pub applied: bool,
    pub selected_member: Option<ObservedMember>,
    pub previous_member: Option<ObservedMember>,
    pub previous_leaf_node_id: Option<Uuid>,
    pub metric: Option<&'static str>,
    pub tolerance_ms: Option<f64>,
    pub candidates: Vec<ObservedCandidate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedMember {
    Node { id: Uuid, name: Option<String> },
    Group { name: String },
}

#[derive(Clone, Debug)]
pub struct ObservedCandidate {
    pub member: ObservedMember,
    pub leaf_node_id: Option<Uuid>,
    pub leaf_node_name: Option<String>,
    pub eligible: Option<bool>,
    pub sorting_latency_ms: Option<f64>,
    pub score: Option<f64>,
    pub selected: bool,
    pub reason: &'static str,
}

pub(super) fn capture<'a>(
    build: impl FnOnce() -> ScoreSelectionPlan<'a>,
) -> ScoreSelectionPlan<'a> {
    #[cfg(feature = "flow-observation")]
    if crate::runtime::flow_observation::current().is_some()
        && captured::CAPTURE.try_with(|_| ()).is_err()
    {
        let state = std::cell::RefCell::new(captured::Capture::default());
        let plan = captured::CAPTURE.sync_scope(state, || {
            let mut plan = build();
            captured::CAPTURE.with(|state| {
                let state = std::mem::take(&mut *state.borrow_mut());
                plan.observation = Some(Arc::new(SelectionObservation {
                    decisions: state.decisions,
                    truncated: state.truncated,
                }));
            });
            plan
        });
        return plan;
    }
    build()
}

pub(super) fn decision<T>(
    group: &Group,
    health_family: IpVersion,
    effects: SelectionEffects,
    build: impl FnOnce() -> T,
) -> T {
    #[cfg(feature = "flow-observation")]
    if let Ok(index) = captured::CAPTURE.try_with(|state| {
        let mut state = state.borrow_mut();
        if state.decisions.len() == 64 || !captured::safe_name(&group.name) {
            state.truncated = true;
            return None;
        }
        let index = state.decisions.len();
        let policy = match group.policy {
            super::GroupPolicy::Selector => "selector",
            super::GroupPolicy::URLTest => "urltest",
            super::GroupPolicy::LoadBalance => "load_balance",
            super::GroupPolicy::Fallback => "fallback",
            super::GroupPolicy::Score => "score",
        };
        state.decisions.push(GroupDecision {
            group_name: group.name.clone(),
            policy,
            reason: "no_eligible_candidate",
            health_family,
            applied: effects.applies(),
            selected_member: None,
            previous_member: None,
            previous_leaf_node_id: None,
            metric: None,
            tolerance_ms: None,
            candidates: Vec::new(),
        });
        Some(index)
    }) {
        return captured::DECISION.sync_scope(index, build);
    }
    let _ = (group, health_family, effects);
    build()
}

pub(super) fn active() -> bool {
    #[cfg(feature = "flow-observation")]
    return captured::DECISION
        .try_with(|index| index.is_some())
        .unwrap_or(false);
    #[cfg(not(feature = "flow-observation"))]
    false
}

pub(super) fn gap() {
    #[cfg(feature = "flow-observation")]
    let _ = captured::CAPTURE.try_with(|state| state.borrow_mut().truncated = true);
}

pub(super) fn candidate(candidate: &Candidate<'_>, eligible: bool, reason: &'static str) {
    member(
        candidate.member(),
        Some(candidate.node),
        Some(eligible),
        reason,
    );
}

pub(super) fn member(
    member: GroupMember<'_>,
    leaf: Option<&honk_config::node::Node>,
    eligible: Option<bool>,
    reason: &'static str,
) {
    #[cfg(feature = "flow-observation")]
    captured::update(|state, index| {
        if state.rows == 256 {
            state.truncated = true;
            return;
        }
        let Some(member) = state.member(member) else {
            return;
        };
        state.decisions[index].candidates.push(ObservedCandidate {
            member,
            leaf_node_id: leaf.map(|node| node.id),
            leaf_node_name: leaf.and_then(|node| captured::name(&node.name)),
            eligible,
            sorting_latency_ms: None,
            score: None,
            selected: false,
            reason,
        });
        state.rows += 1;
    });
    let _ = (member, leaf, eligible, reason);
}

pub(super) fn selected(candidate: Option<&Candidate<'_>>, reason: &'static str) {
    self::reason(reason);
    chosen(candidate);
}

pub(super) fn chosen(candidate: Option<&Candidate<'_>>) {
    #[cfg(feature = "flow-observation")]
    captured::update(|state, index| {
        let member = candidate.and_then(|candidate| state.member(candidate.member()));
        let decision = &mut state.decisions[index];
        decision.selected_member = member;
        for row in &mut decision.candidates {
            row.selected = candidate.is_some_and(|candidate| {
                captured::matches(&row.member, candidate.member())
                    && row.leaf_node_id == Some(candidate.node.id)
            });
        }
    });
    let _ = candidate;
}

pub(super) fn reason(reason: &'static str) {
    #[cfg(feature = "flow-observation")]
    captured::update(|state, index| state.decisions[index].reason = reason);
    let _ = reason;
}

pub(super) fn previous(member: GroupMember<'_>) {
    #[cfg(feature = "flow-observation")]
    captured::update(|state, index| {
        let member = state.member(member);
        state.decisions[index].previous_member = member;
    });
    let _ = member;
}

pub(super) fn previous_tag(manager: &super::GroupManager, group: &Group, tag: &str) {
    if active() {
        let mut members = manager.members(group).filter(|member| member.tag() == tag);
        if let Some(member) = members.next()
            && members.next().is_none()
        {
            previous(member);
        } else {
            gap();
        }
    }
}

pub(super) fn previous_node(id: Uuid) {
    #[cfg(feature = "flow-observation")]
    captured::update(|state, index| {
        let decision = &mut state.decisions[index];
        // Score retains a leaf, not the historical subgroup path that selected it.
        decision.previous_member = None;
        decision.previous_leaf_node_id = Some(id);
    });
    let _ = id;
}

pub(super) fn metric(metric: &'static str, tolerance_ms: Option<f64>) {
    #[cfg(feature = "flow-observation")]
    captured::update(|state, index| {
        state.decisions[index].metric = Some(metric);
        state.decisions[index].tolerance_ms = tolerance_ms.filter(|value| value.is_finite());
    });
    let _ = (metric, tolerance_ms);
}

pub(super) fn latency(id: Uuid, tag: &str, latency: std::time::Duration) {
    #[cfg(feature = "flow-observation")]
    captured::update(|state, index| {
        let latency =
            (latency != std::time::Duration::MAX).then_some(latency.as_secs_f64() * 1000.0);
        for row in &mut state.decisions[index].candidates {
            let same_member = match &row.member {
                ObservedMember::Node { .. } => true,
                ObservedMember::Group { name } => name == tag,
            };
            if row.leaf_node_id == Some(id) && same_member {
                row.sorting_latency_ms = latency.filter(|value| value.is_finite());
            }
        }
    });
    let _ = (id, tag, latency);
}

pub(super) fn latency_tier(candidate: &Candidate<'_>, demoted: bool) {
    #[cfg(feature = "flow-observation")]
    captured::update(|state, index| {
        for row in &mut state.decisions[index].candidates {
            if row.leaf_node_id == Some(candidate.node.id)
                && captured::matches(&row.member, candidate.member())
            {
                row.reason = if demoted {
                    "failure_demoted"
                } else {
                    "latency_ranked"
                };
            }
        }
    });
    let _ = (candidate, demoted);
}

pub(super) fn score(id: Uuid, score: f64) {
    #[cfg(feature = "flow-observation")]
    captured::update(|state, index| {
        for row in &mut state.decisions[index].candidates {
            if row.leaf_node_id == Some(id) && row.eligible == Some(true) {
                row.score = score.is_finite().then_some(score);
            }
        }
    });
    let _ = (id, score);
}

pub(super) fn score_eligible(id: Uuid, eligible: bool) {
    #[cfg(feature = "flow-observation")]
    captured::update(|state, index| {
        for row in &mut state.decisions[index].candidates {
            if row.leaf_node_id == Some(id) && row.eligible == Some(true) {
                row.reason = if eligible {
                    "score_ordinary_eligible"
                } else {
                    "score_ordinary_ineligible"
                };
            }
        }
    });
    let _ = (id, eligible);
}

pub(super) fn ordered(candidates: &[Candidate<'_>]) {
    #[cfg(feature = "flow-observation")]
    captured::update(|state, index| {
        state.decisions[index].candidates.sort_by_cached_key(|row| {
            candidates
                .iter()
                .position(|candidate| {
                    row.leaf_node_id == Some(candidate.node.id)
                        && captured::matches(&row.member, candidate.member())
                })
                .unwrap_or(usize::MAX)
        });
    });
    let _ = candidates;
}

#[cfg(feature = "flow-observation")]
mod captured {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    pub(super) struct Capture {
        pub(super) decisions: Vec<GroupDecision>,
        pub(super) truncated: bool,
        pub(super) rows: usize,
    }

    tokio::task_local! {
        pub(super) static CAPTURE: RefCell<Capture>;
        pub(super) static DECISION: Option<usize>;
    }

    pub(super) fn safe_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 512
            && !name
                .chars()
                .any(|c| c.is_control() || matches!(c, '/' | '\\' | '@'))
    }

    pub(super) fn name(value: &str) -> Option<String> {
        safe_name(value).then(|| value.to_owned())
    }

    impl Capture {
        pub(super) fn member(&mut self, member: GroupMember<'_>) -> Option<ObservedMember> {
            match member {
                GroupMember::Node(node) => Some(ObservedMember::Node {
                    id: node.id,
                    name: name(&node.name),
                }),
                GroupMember::Group(group) => {
                    let Some(name) = name(&group.name) else {
                        self.truncated = true;
                        return None;
                    };
                    Some(ObservedMember::Group { name })
                }
            }
        }
    }

    pub(super) fn matches(observed: &ObservedMember, member: GroupMember<'_>) -> bool {
        match (observed, member) {
            (ObservedMember::Node { id, .. }, GroupMember::Node(node)) => *id == node.id,
            (ObservedMember::Group { name }, GroupMember::Group(group)) => *name == group.name,
            _ => false,
        }
    }

    pub(super) fn update(update: impl FnOnce(&mut Capture, usize)) {
        if let Ok(Some(index)) = DECISION.try_with(|index| *index) {
            let _ = CAPTURE.try_with(|state| update(&mut state.borrow_mut(), index));
        }
    }
}
