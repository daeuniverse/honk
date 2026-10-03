//! Group-graph resolution: construction-time cycle breaking, recursive
//! candidate flattening through nested sub-groups, and the member/leaf
//! introspection APIs (display tags vs. real nodes) built on top of them.

use super::*;

#[cfg(feature = "flow-observation")]
pub struct GroupSelection<'a> {
    pub member: GroupMember<'a>,
    pub leaf: Option<&'a Node>,
}

#[cfg(feature = "flow-observation")]
impl GroupManager {
    /// Apply the same last-definition and cycle rules as the runtime graph.
    pub fn effective_groups(groups: &[Group]) -> HashMap<String, Group> {
        let mut groups = groups
            .iter()
            .map(|group| (group.name.clone(), group.clone()))
            .collect();
        break_group_cycles(&mut groups);
        groups
    }

    pub fn group(&self, name: &str) -> Option<&Group> {
        self.groups.get(name)
    }

    pub fn group_members(&self, name: &str) -> impl Iterator<Item = GroupMember<'_>> {
        self.groups
            .get(name)
            .into_iter()
            .flat_map(|group| self.members(group))
    }

    /// Enumerate unique ordinary leaves, stopping before exceeding the request limit.
    pub fn probe_leaves(&self, name: &str, limit: usize) -> Vec<&Node> {
        let mut leaves: Vec<&Node> = Vec::new();
        if limit == 0 {
            return leaves;
        }
        self.visit_group_leaves(name, 0, &mut [""; MAX_GROUP_DEPTH], false, &mut |node| {
            if !leaves.iter().any(|leaf| leaf.id == node.id) {
                leaves.push(node);
            }
            leaves.len() == limit
        });
        leaves
    }

    /// Bound the graph work before invoking allocation-producing policy planners.
    pub fn probe_plan_within_limit(&self, name: &str, mut limit: usize) -> bool {
        self.probe_graph_budget(name, &mut limit, &mut [""; MAX_GROUP_DEPTH], 0)
    }

    fn probe_graph_budget<'a>(
        &'a self,
        name: &str,
        remaining: &mut usize,
        visited: &mut [&'a str; MAX_GROUP_DEPTH],
        depth: usize,
    ) -> bool {
        if depth >= MAX_GROUP_DEPTH || visited[..depth].contains(&name) {
            return true;
        }
        let Some(group) = self.groups.get(name) else {
            return true;
        };
        let cost = 1usize
            .saturating_add(group.nodes.len())
            .saturating_add(group.groups.len());
        let Some(next) = remaining.checked_sub(cost) else {
            return false;
        };
        *remaining = next;
        visited[depth] = group.name.as_str();
        for child in &group.groups {
            if !self.probe_graph_budget(child, remaining, visited, depth + 1) {
                return false;
            }
        }
        match self.final_member(group) {
            Some(GroupMember::Group(child)) => {
                self.probe_graph_budget(&child.name, remaining, visited, depth + 1)
            }
            Some(GroupMember::Node(_)) => match remaining.checked_sub(1) {
                Some(next) => {
                    *remaining = next;
                    true
                }
                None => false,
            },
            None => true,
        }
    }

    /// Resolve one direct member without changing selection state or falling back
    /// to an arbitrary leaf when a cold URLTest plan has several candidates.
    pub fn probe_leaf<'a>(
        &'a self,
        member: GroupMember<'a>,
        domain: ProbeDomain,
        ip: IpVersion,
    ) -> Option<&'a Node> {
        let node = match member {
            GroupMember::Node(node) => node,
            GroupMember::Group(group) => {
                if !self.probe_plan_within_limit(&group.name, 256) {
                    return None;
                }
                let plan = self.peek_selection_plan_for_domain(&group.name, domain, ip);
                match plan.nodes.as_slice() {
                    [node] => *node,
                    _ => return None,
                }
            }
        };
        (node.protocol() != honk_config::types::NodeProtocol::Block
            && (domain == ProbeDomain::Tcp
                || (crate::descriptor::descriptor(node.protocol()).supports_udp)(node)))
        .then_some(node)
    }

    /// Observe stable choices, without marking activity or advancing policy state.
    pub fn peek_selection(
        &self,
        name: &str,
        network: SelectionNetwork,
    ) -> Option<GroupSelection<'_>> {
        self.peek_selection_inner(self.groups.get(name)?, network, 0)
    }

    fn peek_selection_inner<'a>(
        &'a self,
        group: &'a Group,
        network: SelectionNetwork,
        depth: usize,
    ) -> Option<GroupSelection<'a>> {
        if depth >= MAX_GROUP_DEPTH {
            return None;
        }
        let member = match (group.policy, self.selector_member(group, network)) {
            (_, Some(member)) => member,
            (GroupPolicy::Selector | GroupPolicy::LoadBalance, None) => return None,
            (GroupPolicy::Score, None) => {
                let context = ScoreSelectionContext::aggregate(
                    network,
                    match network {
                        SelectionNetwork::Tcp => ProbeDomain::Tcp,
                        SelectionNetwork::Udp => ProbeDomain::DataUdp,
                    },
                    IpVersion::V4,
                );
                let candidate = self.pick_candidate_for_target(
                    group,
                    &context,
                    &mut Vec::new(),
                    depth,
                    SelectionEffects::Peek,
                    score::selection::ScoreSelectionRules::default(),
                )?;
                return Some(GroupSelection {
                    member: candidate.member(),
                    leaf: Some(candidate.node),
                });
            }
            (GroupPolicy::URLTest | GroupPolicy::Fallback, None) => {
                let tag = if group.policy == GroupPolicy::URLTest {
                    self.get_urltest_selection_for_network(&group.name, network)?
                } else {
                    self.get_fallback_selection_for_network(&group.name, network)?
                };
                let mut matches = self.members(group).filter(|member| member.tag() == tag);
                let member = matches.next()?;
                // These legacy caches retain tags, not NodeIds. Ambiguity is unknown.
                if matches.next().is_some() {
                    return None;
                }
                member
            }
        };
        let leaf = match member {
            GroupMember::Node(node) => Some(node),
            GroupMember::Group(child) => self
                .peek_selection_inner(child, network, depth + 1)
                .and_then(|selection| selection.leaf),
        };
        Some(GroupSelection { member, leaf })
    }
}

impl GroupManager {
    /// Resolve a group to the single leaf node its policy selects.
    /// `visited`/`depth` thread the cycle/depth guards through nesting.
    pub(super) fn pick_in_group<'a>(
        &'a self,
        group: &'a Group,
        domain: ProbeDomain,
        ipver: IpVersion,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: SelectionEffects,
    ) -> Option<&'a Node> {
        self.pick_candidate_for_target(
            group,
            &ScoreSelectionContext::aggregate(
                SelectionNetwork::from_probe_domain(domain),
                domain,
                ipver,
            ),
            visited,
            depth,
            effects,
            score::selection::ScoreSelectionRules::default(),
        )
        .map(|candidate| candidate.node)
    }

    /// Flatten a group's members into dial candidates: every direct member
    /// node plus, for each nested sub-group, the single leaf the
    /// sub-group's own policy currently selects (recursively, depth-capped
    /// and cycle-guarded). Alive filtering happens afterwards in
    /// [`GroupManager::filter_alive_candidates`].
    pub(super) fn flatten_candidates<'a>(
        &'a self,
        group: &'a Group,
        domain: ProbeDomain,
        ipver: IpVersion,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: SelectionEffects,
    ) -> Vec<Candidate<'a>> {
        self.flatten_candidates_for_target(
            group,
            &ScoreSelectionContext::aggregate(
                SelectionNetwork::from_probe_domain(domain),
                domain,
                ipver,
            ),
            visited,
            depth,
            effects,
            score::selection::ScoreSelectionRules::default(),
        )
        .0
    }

    pub(super) fn members<'a>(&'a self, group: &'a Group) -> impl Iterator<Item = GroupMember<'a>> {
        group
            .nodes
            .iter()
            .filter_map(move |id| self.nodes.get(id))
            .map(GroupMember::Node)
            .chain(
                group
                    .groups
                    .iter()
                    .filter_map(move |tag| self.groups.get(tag))
                    .map(GroupMember::Group),
            )
    }

    pub(super) fn final_member<'a>(&'a self, group: &Group) -> Option<GroupMember<'a>> {
        use honk_config::Config;
        use std::sync::LazyLock;

        static DIRECT: LazyLock<Node> = LazyLock::new(Config::builtin_direct_node);
        static BLOCK: LazyLock<Node> = LazyLock::new(Config::builtin_block_node);
        let name = group.final_outbound.as_deref()?;
        match name {
            Config::BUILTIN_DIRECT_NODE => Some(GroupMember::Node(&DIRECT)),
            Config::BUILTIN_BLOCK_NODE => Some(GroupMember::Node(&BLOCK)),
            _ => self
                .node_by_name(name)
                .map(GroupMember::Node)
                .or_else(|| self.groups.get(name).map(GroupMember::Group)),
        }
    }

    /// Borrowed member tags of a group (direct node names, then sub-group
    /// tags; deduplicated). Missing sub-group tags are skipped.
    pub(super) fn member_tags<'a>(&'a self, group: &'a Group) -> Vec<&'a str> {
        let mut out: Vec<&'a str> = Vec::new();
        for member in self.members(group) {
            let tag = member.tag();
            if !out.contains(&tag) {
                out.push(tag);
            }
        }
        out
    }

    /// Member tags of a group: direct member node names followed by nested
    /// sub-group tags (deduplicated, declaration order within each kind).
    ///
    /// This is the member list a dashboard shows (the clash `all` field):
    /// sing-box nested groups drill down layer by layer, so sub-groups
    /// appear under their own tag, not expanded to leaves. Use
    /// [`GroupManager::reachable_leaf_nodes_in_group`] for health and connectivity.
    pub fn node_names_in_group(&self, group_name: &str) -> Vec<String> {
        let Some(group) = self.groups.get(group_name) else {
            return vec![];
        };
        self.member_tags(group)
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    /// Ordinary member leaf names, excluding explicit final edges.
    pub fn leaf_node_names_in_group(&self, group_name: &str) -> Vec<String> {
        self.leaf_nodes_in_group(group_name)
            .into_iter()
            .map(|n| n.name.clone())
            .collect()
    }

    /// Ordinary member leaves, deduplicated by NodeId and cycle-guarded.
    pub fn leaf_nodes_in_group(&self, group_name: &str) -> Vec<&Node> {
        self.group_leaf_nodes(group_name, false)
    }

    /// All leaves reachable through membership and explicit final edges.
    /// Final leaves remain separate from the ordinary member/display list.
    pub fn reachable_leaf_nodes_in_group(&self, group_name: &str) -> Vec<&Node> {
        self.group_leaf_nodes(group_name, true)
    }

    /// Whether membership or explicit final edges can reach this health carrier.
    pub fn group_reaches_node(&self, group_name: &str, node_id: uuid::Uuid) -> bool {
        self.visit_group_leaves(
            group_name,
            0,
            &mut [""; MAX_GROUP_DEPTH],
            true,
            &mut |node| node.id == node_id,
        )
    }

    fn group_leaf_nodes(&self, group_name: &str, include_final: bool) -> Vec<&Node> {
        let mut out: Vec<&Node> = Vec::new();
        self.visit_group_leaves(
            group_name,
            0,
            &mut [""; MAX_GROUP_DEPTH],
            include_final,
            &mut |node| {
                if !out.iter().any(|existing| existing.id == node.id) {
                    out.push(node);
                }
                false
            },
        );
        out
    }

    /// Keep a sole TCP leaf dialable when probe health cannot choose an alternative.
    /// A real dial can then prove recovery without leaking traffic to another outbound.
    /// Explicit `final` fallbacks and UDP health remain authoritative.
    pub(super) fn last_resort_tcp_leaf<'a>(
        &'a self,
        group: &'a Group,
        domain: ProbeDomain,
        effects: SelectionEffects,
    ) -> Option<&'a Node> {
        if domain != ProbeDomain::Tcp || group.final_outbound.is_some() {
            return None;
        }
        let leaves = self.leaf_nodes_in_group(&group.name);
        match leaves.as_slice() {
            [node]
                if self
                    .first_leaf(group, &mut Vec::new(), 0, true)
                    .is_some_and(|selected| selected.id == node.id) =>
            {
                self.warn_selector_last_resort(group, &node.name, effects);
                Some(*node)
            }
            _ => None,
        }
    }

    fn visit_group_leaves<'a>(
        &'a self,
        group_name: &str,
        depth: usize,
        visited: &mut [&'a str; MAX_GROUP_DEPTH],
        include_final: bool,
        visit: &mut impl FnMut(&'a Node) -> bool,
    ) -> bool {
        if depth >= MAX_GROUP_DEPTH || visited[..depth].contains(&group_name) {
            return false;
        }
        let Some(group) = self.groups.get(group_name) else {
            return false;
        };
        visited[depth] = group.name.as_str();
        group
            .nodes
            .iter()
            .filter_map(|id| self.nodes.get(id))
            .any(&mut *visit)
            || group
                .groups
                .iter()
                .any(|tag| self.visit_group_leaves(tag, depth + 1, visited, include_final, visit))
            || (include_final
                && match self.final_member(group) {
                    Some(GroupMember::Node(node)) => visit(node),
                    Some(GroupMember::Group(group)) => {
                        self.visit_group_leaves(&group.name, depth + 1, visited, true, visit)
                    }
                    None => false,
                })
    }

    /// First leaf node reachable from a group in declaration order,
    /// ignoring health. Serving fallbacks must also respect Selector choices;
    /// explicit delay tests may inspect every member to discover recovery.
    fn first_leaf<'a>(
        &'a self,
        group: &'a Group,
        visited: &mut Vec<&'a str>,
        depth: usize,
        respect_selectors: bool,
    ) -> Option<&'a Node> {
        if depth >= MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return None;
        }
        let selected = match respect_selectors
            .then(|| self.selector_member(group, SelectionNetwork::Tcp))
            .flatten()
        {
            None if respect_selectors && group.policy == GroupPolicy::Selector => return None,
            selected => selected,
        };
        visited.push(group.name.as_str());
        let result = match selected {
            Some(GroupMember::Node(node)) => Some(node),
            Some(GroupMember::Group(sub)) => {
                self.first_leaf(sub, visited, depth + 1, respect_selectors)
            }
            None => {
                let mut result = group.nodes.iter().find_map(|id| self.nodes.get(id));
                if result.is_none() {
                    for tag in &group.groups {
                        if let Some(sub) = self.groups.get(tag) {
                            result = self.first_leaf(sub, visited, depth + 1, respect_selectors);
                            if result.is_some() {
                                break;
                            }
                        }
                    }
                }
                result
            }
        };
        visited.pop();
        result
    }

    /// The current TCP selection chain from a group down to its leaf.
    pub fn selection_chain(&self, group_name: &str) -> Vec<String> {
        self.selection_chain_for_network(group_name, SelectionNetwork::Tcp)
    }

    /// The current selection chain for one network: `[group, ..sub-groups, leaf]`.
    ///
    /// The chain stops at the first group without a formed selection (a
    /// URLTest group before any measurement, or LoadBalance, which has no
    /// stable pick). Callers that dial must snapshot this together with the
    /// selection plan; reading it again after an await can combine a newer
    /// group choice with an older physical connection.
    pub fn selection_chain_for_network(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> Vec<String> {
        self.selection_path_for_network(group_name, network).0
    }

    fn selection_path_for_network(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> (Vec<String>, Option<&Node>) {
        let mut chain = vec![group_name.to_string()];
        let Some(mut group) = self.groups.get(group_name) else {
            return (chain, None);
        };
        for _ in 0..MAX_GROUP_DEPTH {
            let member = match (group.policy, self.selector_member(group, network)) {
                (_, Some(member)) => Some(member),
                (GroupPolicy::Selector | GroupPolicy::LoadBalance, None) => None,
                (GroupPolicy::URLTest, None) => self
                    .get_urltest_selection_for_network(&group.name, network)
                    .and_then(|tag| self.members(group).find(|member| member.tag() == tag)),
                (GroupPolicy::Fallback, None) => self
                    .get_fallback_selection_for_network(&group.name, network)
                    .and_then(|tag| self.members(group).find(|member| member.tag() == tag)),
                (GroupPolicy::Score, None) => self
                    .get_score_selection_for_network(&group.name, network)
                    .and_then(|tag| {
                        self.members(group)
                            .find(|member| member.tag() == tag)
                            .or_else(|| {
                                self.final_member(group)
                                    .filter(|member| member.tag() == tag)
                            })
                    }),
            };
            let Some(member) = member else { break };
            match member {
                GroupMember::Node(node) => {
                    chain.push(node.name.clone());
                    return (chain, Some(node));
                }
                GroupMember::Group(next) => {
                    if chain.contains(&next.name) {
                        break;
                    }
                    chain.push(next.name.clone());
                    group = next;
                }
            }
        }
        (chain, None)
    }

    /// Resolve a Selector's configured choice to the leaf that must remain
    /// warm. Unlike traffic selection, an explicitly chosen direct node is
    /// retained even while unhealthy so recovery can make it hot again.
    /// Nested policies use their stable current selection; a cold/invalid
    /// chain falls back to the production network pick without mutating it.
    pub fn selector_warm_node(&self, group_name: &str, network: SelectionNetwork) -> Option<&Node> {
        let group = self.groups.get(group_name)?;
        if group.policy != GroupPolicy::Selector {
            return None;
        }
        if let Some(node) = self.selection_path_for_network(group_name, network).1 {
            return Some(node);
        }
        let domain = match network {
            SelectionNetwork::Tcp => ProbeDomain::Tcp,
            SelectionNetwork::Udp => ProbeDomain::DataUdp,
        };
        self.peek_selection_plan_for_domain(group_name, domain, IpVersion::V4)
            .nodes
            .first()
            .copied()
    }

    /// Flattened members for an explicit delay test: one `(tag, leaf)`
    /// pair per member — direct members under their node name, sub-groups
    /// under their tag with the leaf their policy currently selects (or,
    /// when the sub-group has no alive leaf, its first leaf in declaration
    /// order, so an explicit test can discover recovery). Members sharing
    /// a leaf appear once (first tag wins) to avoid duplicate measurement.
    pub fn delay_test_members(&self, group_name: &str) -> Vec<(String, Node)> {
        self.delay_test_targets(group_name)
            .into_iter()
            .map(|(member, leaf)| (member.tag().to_owned(), leaf.clone()))
            .collect()
    }

    /// [`Self::delay_test_members`] keeping each direct member's identity.
    pub fn delay_test_targets(&self, group_name: &str) -> Vec<(GroupMember<'_>, &Node)> {
        let Some(group) = self.groups.get(group_name) else {
            return vec![];
        };
        let mut out: Vec<(GroupMember<'_>, &Node)> = Vec::new();
        let mut seen: Vec<uuid::Uuid> = Vec::new();
        for id in &group.nodes {
            if let Some(n) = self.nodes.get(id)
                && !seen.contains(&n.id)
            {
                seen.push(n.id);
                out.push((GroupMember::Node(n), n));
            }
        }
        for tag in &group.groups {
            let Some(sub) = self.groups.get(tag.as_str()) else {
                continue;
            };
            let mut visited = Vec::new();
            // Delay tests and provider listings only display the sub-group's
            // current pick: peek, or a dashboard poll would record phantom
            // Score selections and flap history for unused groups.
            let leaf = self
                .pick_in_group(
                    sub,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                    &mut visited,
                    0,
                    SelectionEffects::Peek,
                )
                .or_else(|| {
                    let mut visited = Vec::new();
                    self.first_leaf(sub, &mut visited, 0, false)
                });
            if let Some(leaf) = leaf
                && !seen.contains(&leaf.id)
            {
                seen.push(leaf.id);
                out.push((GroupMember::Group(sub), leaf));
            }
        }
        out
    }

    /// Migrate exact choices, dropping removed members rather than retargeting a
    /// same-named node. The control owner fences writes against this publication.
    pub fn migrate_selector_choices_from(&self, old: &GroupManager) {
        let mut state = old.selector_choice.read().clone();
        state.overrides.clear();
        state.choices.retain(|name, choices| {
            let Ok(group) = self.selector_group(name) else {
                return false;
            };
            for member in choices.iter_mut() {
                if member
                    .as_ref()
                    .is_some_and(|member| self.member_by_identity(group, member).is_none())
                {
                    *member = None;
                }
            }
            choices.iter().any(Option::is_some)
        });
        *self.selector_choice.write() = state;
    }
}

/// Break cycles in the sub-group graph before the manager starts
/// resolving selections.
///
/// DFS over `Group.groups` edges; every back edge (an edge pointing at a
/// group currently on the DFS stack) closes a cycle and is removed from
/// the parent's `groups` list with a warning. Unknown tags are left in
/// place — resolution skips them. The recursion paths additionally carry
/// their own depth/visited guards, so a broken graph can warn but never
/// hang or panic.
pub(super) fn break_group_cycles(groups: &mut HashMap<String, Group>) {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Visiting,
        Done,
    }

    fn visit(
        name: &str,
        groups: &HashMap<String, Group>,
        states: &mut HashMap<String, State>,
        cuts: &mut Vec<(String, String)>,
    ) {
        states.insert(name.to_string(), State::Visiting);
        if let Some(group) = groups.get(name) {
            for child in &group.groups {
                if !groups.contains_key(child.as_str()) {
                    continue;
                }
                match states.get(child.as_str()) {
                    None => visit(child, groups, states, cuts),
                    Some(State::Visiting) => cuts.push((name.to_string(), child.clone())),
                    Some(State::Done) => {}
                }
            }
        }
        states.insert(name.to_string(), State::Done);
    }

    let mut states: HashMap<String, State> = HashMap::new();
    let mut cuts: Vec<(String, String)> = Vec::new();
    // Sorted start order keeps edge-cutting deterministic across runs.
    let mut names: Vec<String> = groups.keys().cloned().collect();
    names.sort();
    for name in names {
        if !states.contains_key(&name) {
            visit(&name, groups, &mut states, &mut cuts);
        }
    }
    for (parent, child) in cuts {
        if let Some(group) = groups.get_mut(&parent) {
            let before = group.groups.len();
            group.groups.retain(|t| t != &child);
            if group.groups.len() != before {
                tracing::warn!(
                    "nested group cycle detected: cut edge '{}' -> '{}' to break the loop",
                    parent,
                    child
                );
            }
        }
    }
}

#[cfg(all(test, feature = "flow-observation"))]
mod native_probe_tests {
    use super::*;
    use honk_config::node::OutboundConfig;
    use uuid::Uuid;

    fn nodes() -> [Node; 2] {
        [1, 2].map(|id| Node {
            id: Uuid::from_u128(id),
            name: format!("node-{id}"),
            ..Default::default()
        })
    }

    #[test]
    fn native_probe_bounds_nested_planner_inputs_before_candidate_expansion() {
        let nodes = nodes();
        let child = Group {
            name: "large".into(),
            policy: GroupPolicy::URLTest,
            nodes: vec![nodes[0].id; 256],
            ..Default::default()
        };
        let parent = Group {
            name: "parent".into(),
            final_outbound: Some(child.name.clone()),
            ..Default::default()
        };
        let manager = GroupManager::new(&[parent, child], &nodes);
        assert!(!manager.probe_plan_within_limit("parent", 256));
        assert!(manager.probe_plan_within_limit("parent", 258));
        let member = GroupMember::Group(manager.group("large").unwrap());
        assert!(
            manager
                .probe_leaf(member, ProbeDomain::Tcp, IpVersion::V4)
                .is_none()
        );
    }

    #[test]
    fn native_probe_leaves_bound_unique_members_and_exclude_final() {
        let nodes = nodes();
        let child = Group {
            name: "child".into(),
            nodes: vec![nodes[0].id, nodes[1].id],
            ..Default::default()
        };
        let parent = Group {
            name: "parent".into(),
            nodes: vec![nodes[0].id, nodes[0].id],
            groups: vec![child.name.clone()],
            final_outbound: Some("direct".into()),
            ..Default::default()
        };
        let manager = GroupManager::new(&[parent, child], &nodes);
        let ids = |limit| {
            manager
                .probe_leaves("parent", limit)
                .into_iter()
                .map(|node| node.id)
                .collect::<Vec<_>>()
        };
        assert!(ids(0).is_empty());
        assert_eq!(ids(1), [nodes[0].id]);
        assert_eq!(ids(2), [nodes[0].id, nodes[1].id]);
        assert_eq!(ids(65), [nodes[0].id, nodes[1].id]);
        assert!(manager.probe_leaves("missing", 65).is_empty());
    }

    #[test]
    fn native_probe_members_preserve_duplicate_names_and_dead_node_identity() {
        let mut nodes = nodes();
        nodes[1].name = nodes[0].name.clone();
        let child = Group {
            name: "child".into(),
            nodes: vec![nodes[0].id],
            ..Default::default()
        };
        let parent = Group {
            name: "parent".into(),
            nodes: nodes.iter().map(|node| node.id).collect(),
            groups: vec![child.name.clone()],
            ..Default::default()
        };
        let alive = Arc::new(AliveDialerSet::new());
        let manager = GroupManager::with_alive_set(&[parent, child], &nodes, Some(alive.clone()));
        let leaves: Vec<_> = manager
            .group_members("parent")
            .map(|member| {
                manager
                    .probe_leaf(member, ProbeDomain::Tcp, IpVersion::V4)
                    .unwrap()
                    .id
            })
            .collect();
        assert_eq!(leaves, [nodes[0].id, nodes[1].id, nodes[0].id]);
        for domain in [ProbeDomain::Tcp, ProbeDomain::DnsUdp, ProbeDomain::DataUdp] {
            alive.report_unavailable_forced(nodes[0].id, domain, IpVersion::V4);
            assert_eq!(
                manager
                    .probe_leaf(GroupMember::Node(&nodes[0]), domain, IpVersion::V4)
                    .map(|node| node.id),
                Some(nodes[0].id)
            );
        }
        let child = GroupMember::Group(manager.group("child").unwrap());
        assert!(
            manager
                .probe_leaf(child, ProbeDomain::DataUdp, IpVersion::V4)
                .is_none()
        );
        let tcp_only = Node {
            outbound: OutboundConfig::Vmess(Default::default()),
            ..nodes[0].clone()
        };
        let member = GroupMember::Node(&tcp_only);
        assert!(
            manager
                .probe_leaf(member, ProbeDomain::Tcp, IpVersion::V4)
                .is_some()
        );
        assert!(
            manager
                .probe_leaf(member, ProbeDomain::DnsUdp, IpVersion::V4)
                .is_none()
        );
        let direct = honk_config::Config::builtin_direct_node();
        let block = honk_config::Config::builtin_block_node();
        for domain in [ProbeDomain::Tcp, ProbeDomain::DnsUdp, ProbeDomain::DataUdp] {
            assert_eq!(
                manager
                    .probe_leaf(GroupMember::Node(&direct), domain, IpVersion::V4)
                    .map(|node| node.id),
                Some(direct.id)
            );
            assert!(
                manager
                    .probe_leaf(GroupMember::Node(&block), domain, IpVersion::V4)
                    .is_none()
            );
        }
    }

    #[test]
    fn native_probe_subgroup_peek_rejects_ambiguous_cold_plans() {
        let nodes = nodes();
        let group = Group {
            name: "urltest".into(),
            policy: GroupPolicy::URLTest,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        };
        let alive = Arc::new(AliveDialerSet::new());
        alive.register_urltest_group(&group.name, &group.nodes, Some(Duration::from_secs(60)));
        let manager = GroupManager::with_alive_set(&[group], &nodes, Some(alive.clone()));
        let member = GroupMember::Group(manager.group("urltest").unwrap());
        assert!(
            manager
                .probe_leaf(member, ProbeDomain::DataUdp, IpVersion::V6)
                .is_none()
        );
        alive.record_probe_latency(
            nodes[1].id,
            ProbeDomain::DataUdp,
            IpVersion::V6,
            Duration::from_millis(10),
        );
        assert_eq!(
            manager
                .probe_leaf(member, ProbeDomain::DataUdp, IpVersion::V6)
                .map(|node| node.id),
            Some(nodes[1].id)
        );
        assert!(
            manager
                .probe_leaf(member, ProbeDomain::DataUdp, IpVersion::V4)
                .is_none()
        );
        assert!(alive.is_urltest_group_idle("urltest"));
        assert_eq!(
            manager.get_urltest_selection_for_network("urltest", SelectionNetwork::Udp),
            None
        );
        for domain in [ProbeDomain::DnsUdp, ProbeDomain::DataUdp] {
            alive.report_unavailable_forced(nodes[1].id, domain, IpVersion::V4);
        }
        assert_eq!(
            manager
                .probe_leaf(member, ProbeDomain::DataUdp, IpVersion::V4)
                .map(|node| node.id),
            Some(nodes[0].id)
        );
        for domain in [ProbeDomain::DnsUdp, ProbeDomain::DataUdp] {
            alive.report_unavailable_forced(nodes[0].id, domain, IpVersion::V4);
        }
        assert!(
            manager
                .probe_leaf(member, ProbeDomain::DataUdp, IpVersion::V4)
                .is_none()
        );
    }

    #[test]
    fn native_probe_peek_does_not_advance_nested_load_balance() {
        let nodes = nodes();
        let child = Group {
            name: "child".into(),
            policy: GroupPolicy::LoadBalance,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        };
        let parent = Group {
            name: "parent".into(),
            groups: vec![child.name.clone()],
            ..Default::default()
        };
        let manager = GroupManager::new(&[parent, child], &nodes);
        let member = GroupMember::Group(manager.group("parent").unwrap());
        for _ in 0..2 {
            assert_eq!(
                manager
                    .probe_leaf(member, ProbeDomain::DataUdp, IpVersion::V4)
                    .map(|node| node.id),
                Some(nodes[0].id)
            );
        }
        for node in nodes {
            assert_eq!(
                manager
                    .select_node_for_domain("parent", ProbeDomain::DataUdp, IpVersion::V4)
                    .map(|selected| selected.id),
                Some(node.id)
            );
        }
    }
}
