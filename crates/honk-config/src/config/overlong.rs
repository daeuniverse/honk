//! The validator's walk for routes through group exits that are too long.

use std::collections::HashMap;
use std::ops::ControlFlow;

use uuid::Uuid;

use crate::group::MAX_GROUP_DEPTH;
use crate::group_graph::{Composed, GroupGraph, Leaf, Step, Visitor, compose};
use crate::types::NodeProtocol;

/// Walks all declared groups, including shadowed namesakes, and counts exit
/// stacks even in groups with no leaf.
///
/// A route's length is the length of its part below a group, which depends
/// only on the nearest exit outside that group, plus the length of the exits
/// outside it. So a subtree found within the limit under some outer exits
/// stays within it under the same nearest exit and no more outer hops.
pub(super) struct Overlong<'g, 'a> {
    graph: &'g GroupGraph<'a>,
    within: HashMap<(usize, Option<Uuid>), Within>,
    frames: Vec<Frame>,
}

#[derive(Clone, Copy)]
struct Within {
    outer_hops: usize,
    /// Levels below the group the subtree reached; reused only where they
    /// still fit under the depth limit.
    height: usize,
}

struct Frame {
    outer_hops: usize,
    deepest: usize,
}

impl<'g, 'a> Overlong<'g, 'a> {
    pub(super) fn new(graph: &'g GroupGraph<'a>) -> Self {
        Self {
            graph,
            within: HashMap::new(),
            frames: Vec::new(),
        }
    }

    pub(super) fn overlong(&mut self, root: usize) -> bool {
        self.frames.clear();
        let graph = self.graph;
        graph.visit(root, self).is_break()
    }
}

/// Hops the exits add on their own, a repeated adjacent exit entered once.
fn exit_hops(exits: &[Uuid]) -> usize {
    exits.len() - exits.windows(2).filter(|pair| pair[0] == pair[1]).count()
}

fn too_long(leaf: Uuid, hops: &[Uuid], exits: &[Uuid]) -> ControlFlow<()> {
    match compose(leaf, hops, exits.iter().rev().copied()) {
        Composed::TooLong => ControlFlow::Break(()),
        _ => ControlFlow::Continue(()),
    }
}

impl Visitor for Overlong<'_, '_> {
    fn enter(&mut self, group: usize, depth: usize, outer_exits: &[Uuid]) -> ControlFlow<(), Step> {
        let outer_hops = exit_hops(outer_exits);
        if let Some(within) = self.within.get(&(group, outer_exits.last().copied()))
            && outer_hops <= within.outer_hops
            && depth + within.height < MAX_GROUP_DEPTH
        {
            if let Some(parent) = self.frames.last_mut() {
                parent.deepest = parent.deepest.max(depth + within.height);
            }
            return ControlFlow::Continue(Step::Skip);
        }
        // A group's exit stack counts even when the group has no leaf.
        let own = match self.graph.exit(group) {
            Some(crate::group_graph::ExitEdge::Node(exit)) => Some(exit),
            _ => None,
        };
        if compose(
            Uuid::nil(),
            &[],
            own.into_iter().chain(outer_exits.iter().rev().copied()),
        ) == Composed::TooLong
        {
            return ControlFlow::Break(());
        }
        self.frames.push(Frame {
            outer_hops,
            deepest: depth,
        });
        ControlFlow::Continue(Step::Descend)
    }

    fn leaf(&mut self, leaf: Leaf, exits: &[Uuid]) -> ControlFlow<()> {
        let Leaf::Node(id) = leaf else {
            return too_long(Uuid::nil(), &[], exits);
        };
        let Some(node) = self.graph.node(id) else {
            return ControlFlow::Continue(());
        };
        match node.protocol() {
            NodeProtocol::Direct | NodeProtocol::Block => too_long(id, &[], exits),
            NodeProtocol::Chain => match node.resolved_chain_hops() {
                Some(hops) => too_long(id, hops, exits),
                None => ControlFlow::Continue(()),
            },
            _ => too_long(id, &[id], exits),
        }
    }

    fn leave(&mut self, group: usize, depth: usize, outer_exits: &[Uuid], complete: bool) {
        let Some(frame) = self.frames.pop() else {
            return;
        };
        if let Some(parent) = self.frames.last_mut() {
            parent.deepest = parent.deepest.max(frame.deepest);
        }
        if !complete {
            return;
        }
        let known = self
            .within
            .entry((group, outer_exits.last().copied()))
            .or_insert(Within {
                outer_hops: frame.outer_hops,
                height: frame.deepest - depth,
            });
        if frame.outer_hops > known.outer_hops {
            *known = Within {
                outer_hops: frame.outer_hops,
                height: frame.deepest - depth,
            };
        }
    }
}

#[cfg(test)]
mod tests;
