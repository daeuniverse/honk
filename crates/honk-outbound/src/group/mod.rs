//! Node group manager — Selector (manual), URLTest (auto lowest-latency with
//! separate TCP/UDP selections), LoadBalance (per-group round-robin) and
//! Fallback (sticky first-alive). Filters dead nodes via `AliveDialerSet`, except
//! that a sole TCP leaf with no `final` remains a last resort.
//! Modeled after sing-box outbound groups.
//!
//! UDP candidate filtering is per-node: a node with both UDP probe domains
//! (DataUDP + DnsUDP) explicitly dead is excluded from UDP selection even
//! when its TCP is alive; nodes never probed for UDP inherit TCP liveness
//! (see `filter_alive_candidates`).
//!
//! Groups nest (sing-box style): `Group.groups` lists sub-group tags whose
//! own current selection contributes one member candidate each (the leaf
//! node the sub-group's policy picks). Every policy's pick therefore
//! resolves recursively to a single leaf node — the dial path stays
//! authoritative. Member-facing APIs report tags (node names + sub-group
//! tags); leaf-facing APIs (`leaf_node_names_in_group`,
//! `delay_test_members`) expand sub-groups to the real nodes underneath.
//!
//! `GroupManager` is the facade: it owns the group/node tables and the
//! selection pipeline entry points below. The internals are split by
//! responsibility — `resolver` (group-graph expansion and member/leaf
//! introspection), `filter` (liveness filtering), `policy` (per-policy
//! picks and latency ranking), `state` (selection caches and callbacks).

use honk_config::group::{Group, GroupPolicy};
use honk_config::node::Node;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use crate::alive::{AliveDialerSet, IpVersion, ProbeDomain};

use state::UrlTestSelections;

pub use score::{
    ScoreAttribution, ScoreCacheSnapshot, ScoreFeedback, ScoreOutcome, ScorePolicyState,
    ScoreReasonCounters, ScoreReasonGroupSnapshot, ScoreReporter, ScoreSelectionContext,
    ScoreTarget,
};
pub use state::{InterruptCallback, PersistCallback, SelectorChangeCallback};

/// Maximum nesting depth for group → sub-group resolution. Construction-
/// time cycle breaking keeps the group graph acyclic; this bound (plus the
/// per-resolution visited set) is defense in depth against pathological
/// configs.
pub const MAX_GROUP_DEPTH: usize = 8;

/// Network dimension for per-network group selections.
///
/// sing-box keeps `selectedOutboundTCP` and `selectedOutboundUDP` apart;
/// honk does the same for URLTest groups so a node with fast TCP but
/// broken UDP does not drag UDP flows down (and vice versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelectionNetwork {
    Tcp,
    Udp,
}

impl SelectionNetwork {
    /// Map a health-check probe domain onto the selection network: TCP
    /// stays TCP; both UDP probe domains share the single UDP selection.
    pub fn from_probe_domain(domain: ProbeDomain) -> Self {
        match domain {
            ProbeDomain::Tcp => SelectionNetwork::Tcp,
            ProbeDomain::DnsUdp | ProbeDomain::DataUdp => SelectionNetwork::Udp,
        }
    }

    const fn slot(self) -> usize {
        match self {
            Self::Tcp => 0,
            Self::Udp => 1,
        }
    }
}

/// Provenance of a group selection plan.
///
/// The mode is explicit because one surviving candidate does not make a cold
/// URLTest selection authoritative: callers must preserve the selection
/// policy rather than infer it from `nodes.len()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionPlanMode {
    /// Selector, LoadBalance, Fallback, and warm URLTest have already chosen
    /// their one authoritative leaf.
    Authoritative,
    /// A top-level URLTest group has no usable measurement and may prepare
    /// its ordered eligible leaves with UDP staggering.
    ColdUrlTest,
}

/// Concrete leaf nodes plus the selection provenance that produced them.
#[derive(Debug, Clone)]
pub struct SelectionPlan<'a> {
    pub mode: SelectionPlanMode,
    pub nodes: Vec<&'a Node>,
}
#[derive(Clone)]
pub struct ScoreSelectionEntry<'a> {
    pub node: &'a Node,
    pub feedback: Option<ScoreFeedback>,
    pub selection_chain: Vec<String>,
}

#[derive(Clone)]
pub struct ScoreSelectionPlan<'a> {
    pub mode: SelectionPlanMode,
    pub health_family: IpVersion,
    pub entries: Vec<ScoreSelectionEntry<'a>>,
}

/// Whether resolving a selection may update group state or must only observe
/// it. Peek is deliberately threaded through nested policies so warm-up
/// discovery shares production semantics without advancing selection state.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SelectionEffects {
    Apply,
    Peek,
}

impl SelectionEffects {
    fn applies(self) -> bool {
        self == Self::Apply
    }
}

/// Shared, hot-swappable handle to the current [`GroupManager`].
///
/// The outer cell is stable and cloned into the control plane, per-
/// connection handles, and the clash API; a config reload swaps the inner
/// `Arc` so every holder sees the rebuilt manager at once. Reads are
/// effectively uncontended (reloads are rare), so a `parking_lot` RwLock
/// keeps the hot path cheap.
pub type SharedGroupManager = Arc<parking_lot::RwLock<Arc<GroupManager>>>;

/// A dialable candidate of a group: a leaf node plus the member tag that
/// selected it. Direct members use their node name; nested candidates use
/// the sub-group tag while retaining the leaf chosen by that sub-group.
#[derive(Debug, Clone)]
struct Candidate<'a> {
    /// Display tag: node name for direct members, sub-group tag for nested.
    tag: &'a str,
    /// Leaf node that would actually be dialed.
    node: &'a Node,
    attribution: Vec<&'a str>,
    selection_chain: Vec<&'a str>,
}

enum UniqueCandidateIds {
    Single(uuid::Uuid),
    Multiple(HashSet<uuid::Uuid>),
}

fn unique_candidate_ids(candidates: &[Candidate<'_>]) -> Option<UniqueCandidateIds> {
    let mut ids = candidates.iter().map(|candidate| candidate.node.id);
    let first = ids.next()?;
    let mut multiple = None;
    for id in ids.filter(|id| *id != first) {
        multiple
            .get_or_insert_with(|| HashSet::from([first]))
            .insert(id);
    }
    Some(match multiple {
        Some(ids) => UniqueCandidateIds::Multiple(ids),
        None => UniqueCandidateIds::Single(first),
    })
}

fn removed_unique_candidate_count(mut before: UniqueCandidateIds, after: &[Candidate<'_>]) -> u64 {
    match &mut before {
        UniqueCandidateIds::Single(id) => {
            u64::from(!after.iter().any(|candidate| candidate.node.id == *id))
        }
        UniqueCandidateIds::Multiple(ids) => {
            for candidate in after {
                ids.remove(&candidate.node.id);
            }
            u64::try_from(ids.len()).unwrap_or(u64::MAX)
        }
    }
}

pub struct GroupManager {
    groups: HashMap<String, Group>,
    /// Node lookup by UUID.
    nodes: HashMap<uuid::Uuid, Node>,
    /// Alive / health tracking (may be None in tests).
    alive_set: Option<Arc<AliveDialerSet>>,
    /// Per-group URLTest selection cache, split by network (TCP/UDP).
    urltest_cache: RwLock<HashMap<String, UrlTestSelections>>,
    /// Per-group TCP/UDP round-robin counters for LoadBalance.
    lb_counters: HashMap<String, [AtomicUsize; 2]>,
    /// Per-group TCP/UDP Fallback pins.
    fallback_cache: RwLock<HashMap<String, [Option<String>; 2]>>,
    /// Per-group last-used timestamp for idle timeout.
    last_used: RwLock<HashMap<String, Instant>>,
    /// Per-group selector choice (set via API, persisted by caller).
    /// group_name → selected node name.
    selector_choice: RwLock<HashMap<String, String>>,
    /// Rate limiter for the "selector choice health-filtered" warning,
    /// keyed per (group, network) so a degraded choice logs at most once
    /// per cooldown instead of once per dial.
    selector_fallback_log: RwLock<HashMap<(String, SelectionNetwork), Instant>>,
    /// Invoked on selector choice changes (cache.db persistence hook).
    persist_callback: RwLock<Option<PersistCallback>>,
    /// Wakes the generation-owned selector warm coordinator.
    selector_change_callback: RwLock<Option<SelectorChangeCallback>>,
    /// Invoked on selection changes for groups with interrupt_connections.
    interrupt_callback: RwLock<Option<InterruptCallback>>,
    score_state: Arc<ScorePolicyState>,
    score_authority: Arc<score::ScoreAuthority>,
}

impl GroupManager {
    pub fn score_reason_snapshot(&self) -> Vec<ScoreReasonGroupSnapshot> {
        let mut group_names: Vec<_> = self
            .groups
            .values()
            .filter(|group| group.policy == GroupPolicy::Score)
            .map(|group| group.name.clone())
            .collect();
        group_names.sort_unstable();
        self.score_state.reason_snapshot(group_names)
    }

    pub fn score_cache_snapshot(&self) -> ScoreCacheSnapshot {
        self.score_state.cache_snapshot()
    }

    pub fn new(groups: &[Group], nodes: &[Node]) -> Self {
        Self::with_alive_set(groups, nodes, None)
    }

    pub fn with_alive_set(
        groups: &[Group],
        nodes: &[Node],
        alive_set: Option<Arc<AliveDialerSet>>,
    ) -> Self {
        let score_state = Arc::new(ScorePolicyState::default());
        let manager = Self::with_alive_set_and_score_state(groups, nodes, alive_set, score_state);
        manager.publish_score_membership();
        manager
    }

    pub fn with_alive_set_and_score_state(
        groups: &[Group],
        nodes: &[Node],
        alive_set: Option<Arc<AliveDialerSet>>,
        score_state: Arc<ScorePolicyState>,
    ) -> Self {
        Self::build(groups, nodes, alive_set, score_state)
    }

    fn build(
        groups: &[Group],
        nodes: &[Node],
        alive_set: Option<Arc<AliveDialerSet>>,
        score_state: Arc<ScorePolicyState>,
    ) -> Self {
        Self::build_inner(groups, nodes, alive_set, score_state)
    }

    fn build_inner(
        groups: &[Group],
        nodes: &[Node],
        alive_set: Option<Arc<AliveDialerSet>>,
        score_state: Arc<ScorePolicyState>,
    ) -> Self {
        let mut group_map: HashMap<String, Group> =
            groups.iter().map(|g| (g.name.clone(), g.clone())).collect();
        resolver::break_group_cycles(&mut group_map);
        for g in groups {
            if g.check_url.is_some() && g.policy == GroupPolicy::Selector {
                tracing::warn!(
                    "group '{}': check_url is ignored on Selector groups (sing-box parity: it is a urltest option)",
                    g.name
                );
            }
        }
        Self {
            groups: group_map,
            nodes: nodes.iter().map(|n| (n.id, n.clone())).collect(),
            alive_set,
            urltest_cache: RwLock::new(HashMap::new()),
            lb_counters: groups
                .iter()
                .map(|group| {
                    (
                        group.name.clone(),
                        std::array::from_fn(|_| AtomicUsize::new(0)),
                    )
                })
                .collect(),
            fallback_cache: RwLock::new(HashMap::new()),
            last_used: RwLock::new(HashMap::new()),
            selector_choice: RwLock::new(HashMap::new()),
            selector_fallback_log: RwLock::new(HashMap::new()),
            persist_callback: RwLock::new(None),
            selector_change_callback: RwLock::new(None),
            interrupt_callback: RwLock::new(None),
            score_state,
            score_authority: Arc::new(score::ScoreAuthority),
        }
    }

    /// Select a single node from a group (TCP, IPv4).
    pub fn select_node(&self, name: &str) -> Option<&Node> {
        self.select_node_for_domain(name, ProbeDomain::Tcp, IpVersion::V4)
    }

    /// Select one eligible node, or a sole TCP leaf as the last resort.
    pub fn select_node_for_domain(
        &self,
        group_name: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Option<&Node> {
        let group = self.groups.get(group_name)?;
        self.mark_used(group_name);
        // The overwhelmingly common selector has only direct members. Avoid
        // constructing its transient candidate/visited vectors; nested
        // groups still take the guarded recursive path below.
        if group.policy == GroupPolicy::Selector && group.groups.is_empty() {
            return self
                .pick_direct_selector(group, domain, ipver, SelectionEffects::Apply)
                .or_else(|| self.last_resort_tcp_leaf(group, domain, SelectionEffects::Apply));
        }
        let mut visited = Vec::with_capacity(MAX_GROUP_DEPTH);
        self.pick_in_group(
            group,
            domain,
            ipver,
            &mut visited,
            0,
            SelectionEffects::Apply,
        )
    }

    /// Select a single alive node, excluding one by name (for failover retry).
    pub fn select_node_excluded(
        &self,
        name: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
        excluded_node_name: &str,
    ) -> Option<&Node> {
        let group = self.groups.get(name)?;
        let mut visited = Vec::new();
        let candidates = self.flatten_candidates(
            group,
            domain,
            ipver,
            &mut visited,
            0,
            SelectionEffects::Apply,
        );
        let candidates: Vec<Candidate> = self
            .filter_alive_candidates(candidates, domain, ipver, group.check_url.as_deref())
            .into_iter()
            .filter(|c| c.node.name != excluded_node_name)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        Some(
            self.pick_best_by_latency(
                &candidates,
                group,
                SelectionNetwork::from_probe_domain(domain),
                ipver,
            )
            .node,
        )
    }

    /// Select candidate node(s) for dialing, retaining the legacy Vec API.
    ///
    /// New callers that must distinguish a cold URLTest plan from a
    /// single-candidate authoritative pick should use
    /// [`Self::selection_plan_for_domain`] instead; vector length is not
    /// provenance (liveness filtering can leave one cold candidate).
    pub fn select_nodes_in_order_for_domain(
        &self,
        group_name: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Vec<&Node> {
        self.selection_plan_for_domain(group_name, domain, ipver)
            .nodes
    }

    /// Resolve the top-level group's concrete leaves and retain whether its
    /// policy made an authoritative choice or remains a cold URLTest plan.
    ///
    /// Nested groups contribute only their own current leaf through
    /// [`Self::flatten_candidates`]; a nested cold URLTest therefore never
    /// contaminates the caller's provenance. Only this requested top-level
    /// URLTest can return [`SelectionPlanMode::ColdUrlTest`].
    pub fn selection_plan_for_domain(
        &self,
        group_name: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> SelectionPlan<'_> {
        self.selection_plan_for_domain_with_effects(
            group_name,
            domain,
            ipver,
            SelectionEffects::Apply,
        )
    }

    /// Resolve a selection plan without changing group activity, caches,
    /// round-robin cursors, persistence, or connection interruption state.
    /// This is used by UDP warm-up discovery, which must observe the exact
    /// next production plan without itself becoming traffic.
    pub fn peek_selection_plan_for_domain(
        &self,
        group_name: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> SelectionPlan<'_> {
        self.selection_plan_for_domain_with_effects(
            group_name,
            domain,
            ipver,
            SelectionEffects::Peek,
        )
    }

    /// Retry candidates after an authoritative single-candidate dial
    /// failure: unique URLTest leaves in latency order (≤3). Within the race
    /// order is irrelevant — a just-failed incumbent that still measures
    /// fastest re-races alongside its alternates and loses by failing
    /// again; a strike-demoted one is re-raced too, since the race itself
    /// is the verdict. Non-URLTest groups yield no candidates (pins are
    /// not retried).
    pub fn urltest_retry_candidates(
        &self,
        group_name: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Vec<&Node> {
        let Some(group) = self.groups.get(group_name) else {
            return Vec::new();
        };
        if group.policy != GroupPolicy::URLTest {
            return Vec::new();
        }
        let mut visited = Vec::new();
        let candidates = self.flatten_candidates(
            group,
            domain,
            ipver,
            &mut visited,
            0,
            SelectionEffects::Peek,
        );
        let candidates =
            self.filter_alive_candidates(candidates, domain, ipver, group.check_url.as_deref());
        let network = SelectionNetwork::from_probe_domain(domain);
        let mut retry = Vec::with_capacity(3);
        for candidate in
            self.order_by_latency(candidates, network, ipver, group.check_url.as_deref())
        {
            if retry
                .iter()
                .any(|node: &&Node| node.id == candidate.node.id)
            {
                continue;
            }
            retry.push(candidate.node);
            if retry.len() == 3 {
                break;
            }
        }
        retry
    }

    fn selection_plan_for_domain_with_effects(
        &self,
        group_name: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
        effects: SelectionEffects,
    ) -> SelectionPlan<'_> {
        let Some(group) = self.groups.get(group_name) else {
            return SelectionPlan {
                mode: SelectionPlanMode::Authoritative,
                nodes: vec![],
            };
        };
        if effects.applies() {
            self.mark_used(group_name);
        }
        if group.policy == GroupPolicy::Selector && group.groups.is_empty() {
            return SelectionPlan {
                mode: SelectionPlanMode::Authoritative,
                nodes: self
                    .pick_direct_selector(group, domain, ipver, effects)
                    .or_else(|| self.last_resort_tcp_leaf(group, domain, effects))
                    .into_iter()
                    .collect(),
            };
        }
        let mut visited = Vec::new();
        let candidates = self.flatten_candidates(group, domain, ipver, &mut visited, 0, effects);
        let before_filter = (effects.applies()
            && group.policy == GroupPolicy::Score
            && self.score_state.is_current_authority(&self.score_authority))
        .then(|| unique_candidate_ids(&candidates))
        .flatten();
        let candidates =
            self.filter_alive_candidates(candidates, domain, ipver, group.check_url.as_deref());
        let network = SelectionNetwork::from_probe_domain(domain);
        if let Some(before_filter) = before_filter {
            self.score_state.record_dead_filtered(
                &self.score_authority,
                score::SelectionReasonKey::new(&group.name, network),
                removed_unique_candidate_count(before_filter, &candidates),
            );
        }
        // Measurements on UDP-dead nodes cannot make the surviving plan warm:
        // determine URLTest provenance only from eligible candidates. A cold
        // group stays cold with one (or zero) survivor.
        let urltest_has_data = group.policy == GroupPolicy::URLTest
            && candidates.iter().any(|c| {
                self.node_latency(c.node, network, ipver, group.check_url.as_deref(), c.tag)
                    != Duration::MAX
            });
        if candidates.is_empty() {
            if let Some(node) = self.last_resort_tcp_leaf(group, domain, effects) {
                return SelectionPlan {
                    mode: SelectionPlanMode::Authoritative,
                    nodes: vec![node],
                };
            }
            return SelectionPlan {
                mode: if group.policy == GroupPolicy::URLTest && !urltest_has_data {
                    SelectionPlanMode::ColdUrlTest
                } else {
                    SelectionPlanMode::Authoritative
                },
                nodes: vec![],
            };
        }
        match group.policy {
            GroupPolicy::Selector => {
                let picked = self.pick_selector(&candidates, group, network, effects);
                let committed = self.commit_selector_pick(
                    group,
                    picked,
                    domain,
                    ipver,
                    &mut visited,
                    0,
                    effects,
                );
                SelectionPlan {
                    mode: SelectionPlanMode::Authoritative,
                    nodes: vec![committed.node],
                }
            }
            GroupPolicy::URLTest => {
                if urltest_has_data {
                    SelectionPlan {
                        mode: SelectionPlanMode::Authoritative,
                        nodes: vec![
                            self.pick_urltest(&candidates, group, network, ipver, effects)
                                .node,
                        ],
                    }
                } else {
                    SelectionPlan {
                        mode: SelectionPlanMode::ColdUrlTest,
                        nodes: self
                            .order_by_latency(
                                candidates,
                                network,
                                ipver,
                                group.check_url.as_deref(),
                            )
                            .into_iter()
                            .map(|c| c.node)
                            .collect(),
                    }
                }
            }
            GroupPolicy::LoadBalance => SelectionPlan {
                mode: SelectionPlanMode::Authoritative,
                nodes: vec![
                    self.pick_load_balance(&candidates, group, network, effects)
                        .node,
                ],
            },
            GroupPolicy::Fallback => SelectionPlan {
                mode: SelectionPlanMode::Authoritative,
                nodes: vec![
                    self.pick_fallback(&candidates, group, network, effects)
                        .node,
                ],
            },
            GroupPolicy::Score => SelectionPlan {
                mode: SelectionPlanMode::Authoritative,
                nodes: vec![
                    self.pick_score(
                        &candidates,
                        group,
                        &ScoreSelectionContext::aggregate(network, domain, ipver),
                        effects,
                    )
                    .node,
                ],
            },
        }
    }

    /// Get the group's policy.
    pub fn get_group_policy(&self, name: &str) -> Option<GroupPolicy> {
        self.groups.get(name).map(|g| g.policy)
    }

    /// Get the `final_outbound` fallback name, if configured.
    pub fn get_final_outbound(&self, group_name: &str) -> Option<String> {
        self.groups
            .get(group_name)
            .and_then(|g| g.final_outbound.clone())
    }

    /// Look up a node by display name (dashboard/API boundary — the hot
    /// paths key on NodeId). Sub-group tags and unknown names yield `None`.
    pub fn node_by_name(&self, name: &str) -> Option<&Node> {
        self.nodes.values().find(|n| n.name == name)
    }

    /// Wrap this manager into a [`SharedGroupManager`] cell (see the type's
    /// docs for the hot-swap semantics).
    pub fn into_shared(self) -> SharedGroupManager {
        Arc::new(parking_lot::RwLock::new(Arc::new(self)))
    }

    /// Alive UDP leaves of a group ordered by latency (best first), capped at
    /// `limit`. Used by the periodic UDP warm coordinator to pre-dial the
    /// top-N leaves per group after each probe cycle. Peek semantics: no
    /// activity marks, no cache writes.
    pub fn ranked_udp_leaves(
        &self,
        group_name: &str,
        ipver: IpVersion,
        limit: usize,
    ) -> Vec<&Node> {
        if limit == 0 {
            return Vec::new();
        }
        let Some(group) = self.groups.get(group_name) else {
            return Vec::new();
        };
        let mut visited = Vec::new();
        let candidates = self.flatten_candidates(
            group,
            ProbeDomain::DataUdp,
            ipver,
            &mut visited,
            0,
            SelectionEffects::Peek,
        );
        let candidates = self.filter_alive_candidates(
            candidates,
            ProbeDomain::DataUdp,
            ipver,
            group.check_url.as_deref(),
        );
        let ordered = self.order_by_latency(
            candidates,
            SelectionNetwork::Udp,
            ipver,
            group.check_url.as_deref(),
        );
        ordered.into_iter().take(limit).map(|c| c.node).collect()
    }

    /// The node's UDP ranking latency (DataUDP, then DNS-UDP;
    /// `Duration::MAX` when unmeasured). The warm coordinator re-ranks its
    /// merged per-group candidate lists by this to enforce its process-wide
    /// cap on the globally fastest leaves.
    pub fn udp_latency(&self, node: &Node, ipver: IpVersion) -> Duration {
        self.node_latency(node, SelectionNetwork::Udp, ipver, None, &node.name)
    }
}

mod filter;
mod policy;
mod resolver;
mod score;
mod state;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod udp_selection_repro_tests;
