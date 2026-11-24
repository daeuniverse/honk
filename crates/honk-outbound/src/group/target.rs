//! What a group selection dials: a configured node, or a route from a leaf
//! through the exits of the groups it was selected through. Health
//! attribution for a dial reads only the target, never the registry.

use honk_config::config::{Config, DIRECT_NODE_ID};
use honk_config::node::Node;
use honk_config::route::Route;
use uuid::Uuid;

use crate::proxy::{DialFailureScope, dial_failure_scope};

/// A selection result. `node` is always a configured node: the leaf, or
/// for a route that collapsed to one hop that hop itself. A route's leaf is
/// `node`.
#[derive(Clone, Debug)]
pub struct Target<'a> {
    pub node: &'a Node,
    pub route: Option<Box<Route>>,
}

impl<'a> Target<'a> {
    pub fn node(node: &'a Node) -> Self {
        Self { node, route: None }
    }

    pub(super) fn collapse(&self, member: &Node, exit_on_path: bool) -> ExitCollapse {
        if !exit_on_path
            || self.route.is_some()
            || self.node.id == honk_config::config::BLOCK_NODE_ID
        {
            ExitCollapse::None
        } else if member.id == self.node.id {
            ExitCollapse::Member
        } else {
            ExitCollapse::Direct
        }
    }
}

/// A single physical exit still has a distinct route-health role even when it is the selected leaf.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum ExitCollapse {
    #[default]
    None,
    Member,
    Direct,
}

/// A target captured with the selection that produced it, so dials and
/// observation never consult a later configuration.
#[derive(Clone, Debug)]
pub struct OwnedTarget {
    pub node: Node,
    pub route: Option<Box<RoutedTarget>>,
    pub collapse: ExitCollapse,
}

/// A route with its hop names from the manager that selected it.
#[derive(Clone, Debug)]
pub struct RoutedTarget {
    pub route: Route,
    pub hop_names: Box<[String]>,
}

impl OwnedTarget {
    pub fn node(node: Node) -> Self {
        Self {
            node,
            route: None,
            collapse: ExitCollapse::None,
        }
    }

    /// The leaf selected by the group before exit composition.
    pub fn selected_member(&self) -> (Uuid, &str) {
        if self.collapse == ExitCollapse::Direct {
            (DIRECT_NODE_ID, Config::BUILTIN_DIRECT_NODE)
        } else {
            (self.node.id, &self.node.name)
        }
    }

    pub fn route(&self) -> Option<&Route> {
        self.route.as_deref().map(|routed| &routed.route)
    }

    pub fn uses_route_evidence(&self) -> bool {
        self.route.is_some() || self.collapse != ExitCollapse::None
    }

    pub fn key(&self) -> DialKey {
        DialKey::of(&self.node, self.route())
    }

    /// The names of a route's hops, captured with its selection.
    pub fn hop_names(&self) -> Option<&[String]> {
        self.route.as_deref().map(|routed| &*routed.hop_names)
    }

    pub fn dial_ref(&self) -> crate::proxy::DialRef<'_> {
        match self.route() {
            Some(route) => crate::proxy::DialRef::Route(route),
            None => crate::proxy::DialRef::Node(self.node.id),
        }
    }

    /// Map physical faults onto the leaf selected by Score, without changing retry eligibility.
    pub fn score_failure(
        &self,
        outcome: super::ScoreOutcome,
        cause: &(dyn std::error::Error + 'static),
    ) -> super::ScoreOutcome {
        use super::ScoreOutcome;
        use crate::proxy::DialFailureScope;

        if !self.uses_route_evidence() && self.node.chain_hops().is_none() {
            return outcome;
        }
        if matches!(
            outcome,
            ScoreOutcome::Cancelled | ScoreOutcome::Shutdown | ScoreOutcome::Rejected
        ) {
            return outcome;
        }
        match crate::proxy::dial_failure_scope(cause) {
            DialFailureScope::Target => ScoreOutcome::TargetFailure,
            DialFailureScope::Hop(i) | DialFailureScope::Prefix(i)
                if self.route().is_some_and(|route| i < route.leaf_hops()) =>
            {
                outcome
            }
            DialFailureScope::LocalRejection => ScoreOutcome::Rejected,
            DialFailureScope::Hop(0) if self.collapse == ExitCollapse::Member => outcome,
            DialFailureScope::Unattributed
                if self.collapse == ExitCollapse::Member && outcome.is_node_failure() =>
            {
                outcome
            }
            _ if !self.uses_route_evidence() => outcome,
            _ => ScoreOutcome::RouteFailure,
        }
    }

    /// Return a UUID only when the failure identifies its owner; a stage alone is not proof.
    pub fn failure_owner(&self, error: &anyhow::Error) -> Option<Uuid> {
        if !self.uses_route_evidence() && self.node.chain_hops().is_none() {
            return Some(self.node.id);
        }
        match (dial_failure_scope(error.as_ref()), self.route()) {
            (DialFailureScope::Prefix(hop), Some(route)) if hop < route.leaf_hops() => {
                Some(route.leaf())
            }
            (DialFailureScope::Prefix(hop), None)
                if self.node.chain_hops().is_some_and(|hops| hop < hops.len()) =>
            {
                Some(self.node.id)
            }
            (
                DialFailureScope::Target
                | DialFailureScope::Prefix(_)
                | DialFailureScope::LocalRejection,
                _,
            ) => None,
            (_, None) => Some(self.node.id),
            (DialFailureScope::Hop(hop), Some(route)) if hop < route.leaf_hops() => {
                Some(route.leaf())
            }
            (DialFailureScope::Hop(hop), Some(route)) => route.hops().get(hop).copied(),
            (DialFailureScope::Unattributed, Some(_)) => None,
        }
    }
}

/// Identity of a dial within one plan: a node dialed as itself and the same
/// node as a route's leaf are different entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DialKey {
    Node(Uuid),
    Route(Route),
}

impl DialKey {
    pub fn success_owner(&self) -> Uuid {
        match self {
            Self::Node(id) => *id,
            Self::Route(route) => route.exit(),
        }
    }

    /// In addition to the exit, a response proves the logical chain leaf and distinct inner exits.
    pub fn proven(&self) -> impl Iterator<Item = Uuid> + '_ {
        let exit = self.success_owner();
        let (leaf, inner) = match self {
            Self::Route(route) => {
                let last = route.hops().len() - 1;
                let leaf = (route.leaf_hops() != 0 && route.leaf() != exit).then_some(route.leaf());
                (leaf, &route.hops()[route.leaf_hops().min(last)..last])
            }
            Self::Node(_) => (None, &[][..]),
        };
        leaf.into_iter()
            .chain(inner.iter().enumerate().filter_map(move |(index, &id)| {
                (id != exit && Some(id) != leaf && !inner[..index].contains(&id)).then_some(id)
            }))
    }

    pub(super) fn of(node: &Node, route: Option<&Route>) -> Self {
        match route {
            Some(route) => Self::Route(*route),
            None => Self::Node(node.id),
        }
    }
}
