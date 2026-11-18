//! A leaf selected through groups with an `exit`, and the nodes it dials.
//!
//! A route's identity is opaque outside this module: callers compare, hash
//! and copy routes but never build a key from their parts, so the identity
//! can change without touching them.

use crate::node::MAX_CHAIN_HOPS;
use uuid::Uuid;

/// The nodes a group member dials when the groups it was selected through
/// have exits: the leaf's own hops, then one hop per exit from the innermost
/// group out. Two routes are equal when they have the same leaf and dial the
/// same hops; node IDs derive from node content, so a route keeps its
/// identity across reloads.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Route {
    /// The group member: a plain node, a configured chain or builtin `direct`.
    leaf: Uuid,
    /// The dialed nodes, entry first; unused slots are nil.
    hops: [Uuid; MAX_CHAIN_HOPS],
    len: u8,
    /// How many leading hops belong to the leaf.
    leaf_hops: u8,
}

impl Route {
    /// `hops` holds 2..=`MAX_CHAIN_HOPS` nodes, the leaf's own `leaf_hops`
    /// first.
    pub(crate) fn new(leaf: Uuid, hops: &[Uuid], leaf_hops: usize) -> Self {
        debug_assert!((2..=MAX_CHAIN_HOPS).contains(&hops.len()));
        debug_assert!(leaf_hops <= hops.len());
        let mut slots = [Uuid::nil(); MAX_CHAIN_HOPS];
        slots[..hops.len()].copy_from_slice(hops);
        Self {
            leaf,
            hops: slots,
            len: hops.len() as u8,
            leaf_hops: leaf_hops as u8,
        }
    }

    /// The group member this route was selected as.
    pub fn leaf(&self) -> Uuid {
        self.leaf
    }

    /// The nodes this route dials, entry first.
    pub fn hops(&self) -> &[Uuid] {
        &self.hops[..usize::from(self.len)]
    }

    /// How many leading hops belong to the leaf: 1 for a plain node, its hop
    /// count for a configured chain, 0 for `direct`.
    pub fn leaf_hops(&self) -> usize {
        usize::from(self.leaf_hops)
    }

    /// The last hop: the exit of the outermost group with one.
    pub fn exit(&self) -> Uuid {
        self.hops[usize::from(self.len) - 1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_route_holds_its_hops_without_allocating() {
        assert_eq!(std::mem::size_of::<Route>(), 16 * (MAX_CHAIN_HOPS + 1) + 2);
        let [leaf, exit] = [Uuid::from_u128(1), Uuid::from_u128(2)];
        let route = Route::new(leaf, &[leaf, exit], 1);
        assert_eq!(route.hops(), [leaf, exit]);
        assert_eq!(
            (route.leaf(), route.leaf_hops(), route.exit()),
            (leaf, 1, exit)
        );
    }

    #[test]
    fn routes_over_the_same_hops_from_different_leaves_stay_apart() {
        let [chain, a, b, exit] = [1, 2, 3, 4].map(Uuid::from_u128);
        let through_chain = Route::new(chain, &[a, b, exit], 2);
        let through_plain = Route::new(a, &[a, b, exit], 1);
        assert_ne!(through_chain, through_plain);
        let set: std::collections::HashSet<_> = [through_chain, through_plain].into();
        assert_eq!(set.len(), 2);
    }
}
