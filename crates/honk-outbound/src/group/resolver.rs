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
        self.pick_candidate_in_group(group, domain, ipver, visited, depth, effects)
            .map(|candidate| candidate.node)
    }

    /// After a Selector pick, commit the serving sub-group's own selection:
    /// sub-groups are peeked during flattening, so only the real service
    /// path records selection state (ranks, incumbent marks, URLTest
    /// caches), whatever member the pick landed on — stored choice, default,
    /// or alive fallback.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn commit_selector_pick<'a>(
        &'a self,
        group: &'a Group,
        picked: Candidate<'a>,
        domain: ProbeDomain,
        ipver: IpVersion,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: SelectionEffects,
    ) -> Candidate<'a> {
        if !effects.applies() {
            return picked;
        }
        let Some(sub) = self.groups.get(picked.tag) else {
            return picked;
        };
        self.mark_used(picked.tag);
        visited.push(group.name.as_str());
        let committed =
            self.pick_candidate_in_group(sub, domain, ipver, visited, depth + 1, effects);
        visited.pop();
        match committed {
            Some(mut committed) => {
                committed.tag = picked.tag;
                committed
            }
            None => picked,
        }
    }

    pub(super) fn pick_candidate_in_group<'a>(
        &'a self,
        group: &'a Group,
        domain: ProbeDomain,
        ipver: IpVersion,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: SelectionEffects,
    ) -> Option<Candidate<'a>> {
        let candidates = self.flatten_candidates(group, domain, ipver, visited, depth, effects);
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
        if candidates.is_empty() {
            return self
                .last_resort_tcp_leaf(group, domain)
                .map(|node| Candidate {
                    tag: node.name.as_str(),
                    node,
                    attribution: Vec::new(),
                    selection_chain: vec![node.name.as_str()],
                });
        }
        let candidate = match group.policy {
            GroupPolicy::Selector => {
                let picked = self.pick_selector(&candidates, group);
                self.commit_selector_pick(group, picked, domain, ipver, visited, depth, effects)
            }
            GroupPolicy::URLTest => self.pick_urltest(&candidates, group, network, ipver, effects),
            GroupPolicy::LoadBalance => {
                self.pick_load_balance(&candidates, group, network, effects)
            }
            GroupPolicy::Fallback => self.pick_fallback(&candidates, group, network, effects),
            GroupPolicy::Score => self.pick_score(
                &candidates,
                group,
                &ScoreSelectionContext::aggregate(network, domain, ipver),
                effects,
            ),
        };
        let mut candidate = candidate;
        if group.policy == GroupPolicy::Score {
            candidate.attribution.push(group.name.as_str());
        }
        Some(candidate)
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
        if depth >= MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return Vec::new();
        }
        visited.push(group.name.as_str());
        // A Selector peeks all sub-groups here; `commit_selector_pick`
        // re-resolves the serving one with applied effects after the pick.
        let sub_effects = if group.policy == GroupPolicy::Selector && effects.applies() {
            SelectionEffects::Peek
        } else {
            effects
        };
        let mut out: Vec<Candidate<'a>> = group
            .nodes
            .iter()
            .filter_map(|id| self.nodes.get(id))
            .map(|node| Candidate {
                tag: node.name.as_str(),
                node,
                attribution: Vec::new(),
                selection_chain: vec![node.name.as_str()],
            })
            .collect();
        for sub_tag in &group.groups {
            let Some(sub) = self.groups.get(sub_tag.as_str()) else {
                continue;
            };
            // Sub-group participation counts as activity only for real
            // traffic. Peek follows the same nested policy without waking
            // health checks or updating idle timestamps.
            if sub_effects.applies() {
                self.mark_used(sub_tag);
            }
            if let Some(mut candidate) =
                self.pick_candidate_in_group(sub, domain, ipver, visited, depth + 1, sub_effects)
            {
                candidate.tag = sub_tag.as_str();
                out.push(candidate);
            }
        }
        visited.pop();
        out
    }

    /// Borrowed member tags of a group (direct node names, then sub-group
    /// tags; deduplicated). Missing sub-group tags are skipped.
    pub(super) fn member_tags<'a>(&'a self, group: &'a Group) -> Vec<&'a str> {
        let mut out: Vec<&'a str> = Vec::new();
        for id in &group.nodes {
            if let Some(n) = self.nodes.get(id)
                && !out.contains(&n.name.as_str())
            {
                out.push(n.name.as_str());
            }
        }
        for tag in &group.groups {
            if self.groups.contains_key(tag.as_str()) && !out.contains(&tag.as_str()) {
                out.push(tag.as_str());
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
    /// [`GroupManager::leaf_node_names_in_group`] where the real nodes
    /// underneath matter (health checks, eBPF connectivity aggregation).
    pub fn node_names_in_group(&self, group_name: &str) -> Vec<String> {
        let Some(group) = self.groups.get(group_name) else {
            return vec![];
        };
        self.member_tags(group)
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    /// All leaf node names reachable from a group, expanding nested
    /// sub-groups recursively (deduplicated, cycle-guarded). Unlike
    /// [`GroupManager::node_names_in_group`] — which lists display tags —
    /// this resolves to the real nodes whose health state drives probing
    /// and eBPF connectivity pushes.
    pub fn leaf_node_names_in_group(&self, group_name: &str) -> Vec<String> {
        self.leaf_nodes_in_group(group_name)
            .into_iter()
            .map(|n| n.name.clone())
            .collect()
    }

    /// All leaf nodes reachable from a group (deduplicated by NodeId,
    /// cycle-guarded) — the health-state carriers behind
    /// [`GroupManager::leaf_node_names_in_group`].
    pub fn leaf_nodes_in_group(&self, group_name: &str) -> Vec<&Node> {
        let mut out: Vec<&Node> = Vec::new();
        let mut visited: Vec<&str> = Vec::new();
        self.collect_leaf_nodes(group_name, 0, &mut visited, &mut out);
        out
    }

    /// Keep a sole TCP leaf dialable when probe health cannot choose an alternative.
    /// A real dial can then prove recovery without leaking traffic to another outbound.
    /// Explicit `final` fallbacks and UDP health remain authoritative.
    pub(super) fn last_resort_tcp_leaf<'a>(
        &'a self,
        group: &'a Group,
        domain: ProbeDomain,
    ) -> Option<&'a Node> {
        if domain != ProbeDomain::Tcp || group.final_outbound.is_some() {
            return None;
        }
        let leaves = self.leaf_nodes_in_group(&group.name);
        match leaves.as_slice() {
            [node] => Some(*node),
            _ => None,
        }
    }

    fn collect_leaf_nodes<'a>(
        &'a self,
        group_name: &str,
        depth: usize,
        visited: &mut Vec<&'a str>,
        out: &mut Vec<&'a Node>,
    ) {
        if depth >= MAX_GROUP_DEPTH {
            return;
        }
        let Some(group) = self.groups.get(group_name) else {
            return;
        };
        if visited.contains(&group.name.as_str()) {
            return;
        }
        visited.push(group.name.as_str());
        for id in &group.nodes {
            if let Some(n) = self.nodes.get(id)
                && !out.iter().any(|o| o.id == n.id)
            {
                out.push(n);
            }
        }
        for tag in &group.groups {
            self.collect_leaf_nodes(tag, depth + 1, visited, out);
        }
        visited.pop();
    }

    /// First leaf node reachable from a group in declaration order,
    /// ignoring alive state. Cycle/depth-guarded like the selection paths.
    fn first_leaf<'a>(
        &'a self,
        group: &'a Group,
        visited: &mut Vec<&'a str>,
        depth: usize,
    ) -> Option<&'a Node> {
        if depth >= MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return None;
        }
        visited.push(group.name.as_str());
        let mut result = group.nodes.iter().find_map(|id| self.nodes.get(id));
        if result.is_none() {
            for tag in &group.groups {
                if let Some(sub) = self.groups.get(tag.as_str()) {
                    result = self.first_leaf(sub, visited, depth + 1);
                    if result.is_some() {
                        break;
                    }
                }
            }
        }
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
        let mut chain = vec![group_name.to_string()];
        let mut current = group_name.to_string();
        for _ in 0..MAX_GROUP_DEPTH {
            let Some(group) = self.groups.get(&current) else {
                break;
            };
            let next: Option<String> = match group.policy {
                GroupPolicy::Selector => self
                    .selector_choice
                    .read()
                    .get(&group.name)
                    .cloned()
                    .or_else(|| group.default.clone())
                    .or_else(|| self.member_tags(group).first().map(|s| s.to_string())),
                GroupPolicy::URLTest => {
                    self.get_urltest_selection_for_network(&group.name, network)
                }
                GroupPolicy::Fallback => {
                    self.get_fallback_selection_for_network(&group.name, network)
                }
                GroupPolicy::LoadBalance => None,
                GroupPolicy::Score => self.get_score_selection_for_network(&group.name, network),
            };
            let Some(tag) = next else { break };
            if tag == current || chain.contains(&tag) {
                break;
            }
            chain.push(tag.clone());
            current = tag;
        }
        chain
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
            .selection_chain(group_name)
            .last()
            .and_then(|name| self.node_by_name(name))
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
                    self.first_leaf(sub, &mut visited, 0)
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
