//! Group-graph resolution: construction-time cycle breaking, recursive
//! candidate flattening through nested sub-groups, and the member/leaf
//! introspection APIs (display tags vs. real nodes) built on top of them.

use super::*;

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
        let selected = if respect_selectors && group.policy == GroupPolicy::Selector {
            Some(self.selector_member(group)?)
        } else {
            None
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
            let member = match group.policy {
                GroupPolicy::Selector => self.selector_member(group),
                GroupPolicy::URLTest => self
                    .get_urltest_selection_for_network(&group.name, network)
                    .and_then(|tag| self.members(group).find(|member| member.tag() == tag)),
                GroupPolicy::Fallback => self
                    .get_fallback_selection_for_network(&group.name, network)
                    .and_then(|tag| self.members(group).find(|member| member.tag() == tag)),
                GroupPolicy::LoadBalance => None,
                GroupPolicy::Score => self
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
    /// chain falls back to the next production TCP leaf without mutating it.
    pub fn selector_warm_node(&self, group_name: &str) -> Option<&Node> {
        let group = self.groups.get(group_name)?;
        if group.policy != GroupPolicy::Selector {
            return None;
        }
        if let Some(node) = self
            .selection_path_for_network(group_name, SelectionNetwork::Tcp)
            .1
        {
            return Some(node);
        }
        self.peek_selection_plan_for_domain(group_name, ProbeDomain::Tcp, IpVersion::V4)
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
        let Some(group) = self.groups.get(group_name) else {
            return vec![];
        };
        let mut out: Vec<(String, Node)> = Vec::new();
        let mut seen: Vec<uuid::Uuid> = Vec::new();
        for id in &group.nodes {
            if let Some(n) = self.nodes.get(id)
                && !seen.contains(&n.id)
            {
                seen.push(n.id);
                out.push((n.name.clone(), n.clone()));
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
                out.push((tag.clone(), leaf.clone()));
            }
        }
        out
    }

    /// Copy runtime selector choices from a previous instance (used on
    /// config reload). Choices whose group no longer exists, or whose
    /// selected member tag (node name or sub-group tag) is no longer a
    /// member of that group, are dropped. Persist/interrupt callbacks are
    /// not fired — they are wired after migration by the caller.
    pub fn migrate_selector_choices_from(&self, old: &GroupManager) {
        let old_choices = old.selector_choice.read().clone();
        if old_choices.is_empty() {
            return;
        }
        let mut migrated = 0usize;
        let mut choices = self.selector_choice.write();
        for (group_name, member_tag) in old_choices {
            let still_valid = self
                .groups
                .get(&group_name)
                .map(|g| self.member_tags(g).contains(&member_tag.as_str()))
                .unwrap_or(false);
            if still_valid {
                choices.insert(group_name, member_tag);
                migrated += 1;
            }
        }
        if migrated > 0 {
            tracing::info!(
                "migrated {} selector choice(s) across config reload",
                migrated
            );
        }
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
