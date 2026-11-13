//! The structure of nested groups: member, subgroup, `final` and `exit`
//! edges resolved once by name, one traversal over them, and the one rule
//! that composes a leaf with the exits of the groups it is selected through.
//!
//! Only structure lives here. Policies, health and caches stay with their
//! owners; the validator and group consumers answer their own questions by
//! visiting this graph.

use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::ops::ControlFlow;

use uuid::Uuid;

use crate::Config;
use crate::group::{Group, MAX_GROUP_DEPTH};
use crate::node::{MAX_CHAIN_HOPS, Node};
use crate::route::Route;

/// A group's `final` edge. Builtins resolve first, then nodes, then groups,
/// as group selection resolves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalEdge {
    Direct,
    Block,
    /// Every node of that name, in configuration order. Selection dials the
    /// first.
    Nodes(Box<[Uuid]>),
    Group(usize),
}

/// A group's `exit` edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitEdge {
    Node(Uuid),
    /// The name does not resolve to exactly one node that can be dialed over
    /// a tunnel. Such a group offers no candidates.
    Unresolved,
}

#[derive(Debug)]
struct Edges<'a> {
    name: &'a str,
    members: &'a [Uuid],
    subgroups: Box<[usize]>,
    final_edge: Option<FinalEdge>,
    exit: Option<ExitEdge>,
}

/// Group edges of one configuration. Cycles stay in the graph; every
/// traversal bounds itself.
#[derive(Debug)]
pub struct GroupGraph<'a> {
    groups: Vec<Edges<'a>>,
    index: HashMap<&'a str, usize>,
    nodes: HashMap<Uuid, &'a Node>,
    chains: HashMap<Uuid, Box<[Uuid]>>,
}

impl<'a> GroupGraph<'a> {
    /// A later group of the same name replaces an earlier one, as in group
    /// lookups by name.
    pub fn new(groups: &'a [Group], nodes: &'a [Node]) -> Self {
        let mut by_name: Vec<(&str, Uuid)> = nodes
            .iter()
            .map(|node| (node.name.as_str(), node.id))
            .collect();
        by_name.sort_by_key(|(name, _)| *name);
        let namesakes = |name: &str| {
            let start = by_name.partition_point(|(other, _)| *other < name);
            let end = start + by_name[start..].partition_point(|(other, _)| *other == name);
            &by_name[start..end]
        };
        let index: HashMap<&str, usize> = groups
            .iter()
            .enumerate()
            .map(|(index, group)| (group.name.as_str(), index))
            .collect();
        let by_id: HashMap<Uuid, &Node> = nodes.iter().map(|node| (node.id, node)).collect();
        let unique = |name: &str| match namesakes(name) {
            [(_, id)] => Some(*id),
            _ => None,
        };
        let chains = nodes
            .iter()
            .filter_map(|node| {
                let hops = node.chain_hops()?;
                let ids = hops
                    .iter()
                    .map(|hop| unique(hop))
                    .collect::<Option<Box<[Uuid]>>>()?;
                Some((node.id, ids))
            })
            .collect();
        let groups = groups
            .iter()
            .map(|group| Edges {
                name: group.name.as_str(),
                members: &group.nodes,
                subgroups: group
                    .groups
                    .iter()
                    .filter_map(|tag| index.get(tag.as_str()).copied())
                    .collect(),
                final_edge: group.final_outbound.as_deref().and_then(|name| match name {
                    Config::BUILTIN_DIRECT_NODE => Some(FinalEdge::Direct),
                    Config::BUILTIN_BLOCK_NODE => Some(FinalEdge::Block),
                    _ => match namesakes(name) {
                        [] => index.get(name).map(|index| FinalEdge::Group(*index)),
                        nodes => Some(FinalEdge::Nodes(nodes.iter().map(|(_, id)| *id).collect())),
                    },
                }),
                exit: group.exit.as_deref().map(|name| {
                    unique(name)
                        .and_then(|id| by_id.get(&id))
                        .filter(|node| node.chain_hops().is_none() && node.supports_tunneled_dial())
                        .map_or(ExitEdge::Unresolved, |node| ExitEdge::Node(node.id))
                }),
            })
            .collect();
        Self {
            groups,
            index,
            nodes: by_id,
            chains,
        }
    }

    pub fn len(&self) -> usize {
        self.groups.len()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// The group of that name.
    pub fn group(&self, name: &str) -> Option<usize> {
        self.index.get(name).copied()
    }

    pub fn name(&self, group: usize) -> &'a str {
        self.groups[group].name
    }

    pub fn exit(&self, group: usize) -> Option<ExitEdge> {
        self.groups[group].exit
    }

    pub fn final_edge(&self, group: usize) -> Option<&FinalEdge> {
        self.groups[group].final_edge.as_ref()
    }

    /// Whether any group has an exit.
    pub fn has_exits(&self) -> bool {
        self.groups.iter().any(|group| group.exit.is_some())
    }

    pub fn node(&self, id: Uuid) -> Option<&'a Node> {
        self.nodes.get(&id).copied()
    }

    /// A configured chain's hop IDs, entry first; `None` for any other node
    /// and for a chain whose hops do not each name exactly one node.
    pub fn chain_hops(&self, id: Uuid) -> Option<&[Uuid]> {
        self.chains.get(&id).map(|hops| &hops[..])
    }

    /// Every resolved configured chain, by chain node ID.
    pub fn chains(&self) -> impl Iterator<Item = (Uuid, &[Uuid])> {
        self.chains.iter().map(|(id, hops)| (*id, &hops[..]))
    }

    /// Visit every leaf reachable from `root` through members, subgroups and
    /// `final`, in that order, within `limits`. The visitor sees the exits of
    /// the groups on the current path, outermost first.
    pub fn visit(
        &self,
        root: usize,
        limits: Limits,
        visitor: &mut impl Visitor,
    ) -> ControlFlow<()> {
        let mut walk = Walk {
            graph: self,
            limits,
            path: Vec::with_capacity(limits.max_depth),
            exits: Vec::with_capacity(limits.max_depth),
            visitor,
        };
        walk.group(root, 0)?;
        ControlFlow::Continue(())
    }
}

/// How far a traversal goes. A group already on the current path is not
/// entered again, and a `final` naming several nodes reaches the first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Groups on one path; the root is at depth 0.
    pub(crate) max_depth: usize,
}

impl Limits {
    /// What group selection reaches.
    pub const SELECTION: Self = Self {
        max_depth: MAX_GROUP_DEPTH,
    };
}

/// A leaf reached by a traversal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leaf {
    /// A member ID, or a node a `final` names.
    Node(Uuid),
    /// `final: direct`.
    Direct,
    /// `final: block`.
    Block,
}

/// Whether a traversal enters a group's members.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Descend,
    /// The visitor already knows this subtree; it counts as complete.
    Skip,
}

pub trait Visitor {
    /// Before a group's members, with the exits of the groups around it,
    /// outermost first.
    fn enter(
        &mut self,
        _group: usize,
        _depth: usize,
        _outer_exits: &[Uuid],
    ) -> ControlFlow<(), Step> {
        ControlFlow::Continue(Step::Descend)
    }

    /// `exits` holds the exits of every group on the path, this leaf's own
    /// included, outermost first.
    fn leaf(&mut self, leaf: Leaf, exits: &[Uuid]) -> ControlFlow<()>;

    /// After a group's members. `complete` is false when the depth limit or
    /// the path guard cut the subtree short; only a complete subtree's
    /// answer is independent of the path that reached it.
    fn leave(&mut self, _group: usize, _depth: usize, _outer_exits: &[Uuid], _complete: bool) {}
}

struct Walk<'g, 'a, 'v, V> {
    graph: &'g GroupGraph<'a>,
    limits: Limits,
    path: Vec<usize>,
    exits: Vec<Uuid>,
    visitor: &'v mut V,
}

impl<V: Visitor> Walk<'_, '_, '_, V> {
    fn group(&mut self, group: usize, depth: usize) -> ControlFlow<(), bool> {
        if depth >= self.limits.max_depth || self.path.contains(&group) {
            return ControlFlow::Continue(false);
        }
        if self.visitor.enter(group, depth, &self.exits)? == Step::Skip {
            return ControlFlow::Continue(true);
        }
        let edges = &self.graph.groups[group];
        let exit = match edges.exit {
            Some(ExitEdge::Node(exit)) => Some(exit),
            _ => None,
        };
        self.path.push(group);
        self.exits.extend(exit);
        let mut complete = true;
        for member in edges.members {
            self.visitor.leaf(Leaf::Node(*member), &self.exits)?;
        }
        for subgroup in &edges.subgroups {
            complete &= self.group(*subgroup, depth + 1)?;
        }
        match &edges.final_edge {
            None => {}
            Some(FinalEdge::Direct) => self.visitor.leaf(Leaf::Direct, &self.exits)?,
            Some(FinalEdge::Block) => self.visitor.leaf(Leaf::Block, &self.exits)?,
            Some(FinalEdge::Nodes(nodes)) => {
                self.visitor.leaf(Leaf::Node(nodes[0]), &self.exits)?;
            }
            Some(FinalEdge::Group(final_group)) => {
                complete &= self.group(*final_group, depth + 1)?;
            }
        }
        if exit.is_some() {
            self.exits.pop();
        }
        self.path.pop();
        self.visitor.leave(group, depth, &self.exits, complete);
        ControlFlow::Continue(complete)
    }
}

/// What a leaf dials through the exits of the groups it was selected
/// through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Composed {
    /// No exit on the path: the leaf dials as it is.
    Direct,
    /// One node is left: dial that node itself.
    Collapsed(Uuid),
    Routed(Route),
    /// More than `MAX_CHAIN_HOPS` hops.
    TooLong,
}

/// Compose `leaf`'s own hops (none for `direct`, the node itself for a plain
/// node, its hops for a configured chain) with the exits of the groups on
/// its path, innermost first. A hop the next exit repeats is entered once;
/// the leaf's own hops stay as configured.
pub fn compose(
    leaf: Uuid,
    leaf_hops: &[Uuid],
    exits_inner_first: impl IntoIterator<Item = Uuid>,
) -> Composed {
    let mut hops = [Uuid::nil(); MAX_CHAIN_HOPS];
    let mut len = leaf_hops.len();
    if len > MAX_CHAIN_HOPS {
        return Composed::TooLong;
    }
    hops[..len].copy_from_slice(leaf_hops);
    let mut last = leaf_hops.last().copied();
    let mut any_exit = false;
    for exit in exits_inner_first {
        any_exit = true;
        if last == Some(exit) {
            continue;
        }
        last = Some(exit);
        if len == MAX_CHAIN_HOPS {
            return Composed::TooLong;
        }
        hops[len] = exit;
        len += 1;
    }
    match len {
        _ if !any_exit => Composed::Direct,
        1 => Composed::Collapsed(hops[0]),
        _ => Composed::Routed(Route::new(leaf, &hops[..len], leaf_hops.len())),
    }
}

/// Break nested-group cycles in place: a DFS over subgroup edges in sorted
/// name order removes, with a warning, every edge back to a group still on
/// the DFS stack. Unknown tags stay; resolution skips them. Only a group
/// manager's own copy is cut: `final` edges stay, and every traversal keeps
/// its own guards.
pub fn cut_cycles<G: BorrowMut<Group>>(groups: &mut HashMap<String, G>) {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Visiting,
        Done,
    }

    fn visit<G: BorrowMut<Group>>(
        name: &str,
        groups: &HashMap<String, G>,
        states: &mut HashMap<String, State>,
        cuts: &mut Vec<(String, String)>,
    ) {
        states.insert(name.to_string(), State::Visiting);
        if let Some(group) = groups.get(name) {
            for child in &group.borrow().groups {
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
            let group = group.borrow_mut();
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

#[cfg(test)]
mod tests;
