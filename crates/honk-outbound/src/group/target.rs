//! What a group selection dials: a configured node, or a route from a leaf
//! through the exits of the groups it was selected through. Health
//! attribution for a dial reads only the target, never the registry.

use honk_config::node::Node;
use honk_config::route::Route;
use uuid::Uuid;

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

    pub fn key(&self) -> DialKey {
        DialKey::of(self.node, self.route.as_deref())
    }
}

/// A target captured with the selection that produced it, so dials and
/// observation never consult a later configuration.
#[derive(Clone, Debug)]
pub struct OwnedTarget {
    pub node: Node,
    pub route: Option<Box<RoutedTarget>>,
}

/// A route with its hop names from the manager that selected it.
#[derive(Clone, Debug)]
pub struct RoutedTarget {
    pub route: Route,
    pub hop_names: Box<[String]>,
}

impl OwnedTarget {
    pub fn node(node: Node) -> Self {
        Self { node, route: None }
    }

    pub fn route(&self) -> Option<&Route> {
        self.route.as_deref().map(|routed| &routed.route)
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

    /// The node a successful dial's latency belongs to: a route's exit.
    pub fn success_owner(&self) -> Uuid {
        self.route().map_or(self.node.id, Route::exit)
    }

    /// The other nodes a successful dial proves reachable: a route's leaf,
    /// which stands for a configured chain leaf's own hops, and every exit
    /// before the last. Empty for any other target.
    pub fn proven(&self) -> impl Iterator<Item = Uuid> + '_ {
        let (leaf, inner) = match self.route() {
            Some(route) => {
                let last = route.hops().len() - 1;
                // A chain leaf whose last hop is the exit adds no hop of its own.
                (
                    Some(route.leaf()),
                    &route.hops()[route.leaf_hops().min(last)..last],
                )
            }
            None => (None, &[][..]),
        };
        let exit = self.route().map(Route::exit);
        leaf.into_iter().chain(
            inner
                .iter()
                .enumerate()
                .filter(move |(index, id)| {
                    Some(**id) != exit && Some(**id) != leaf && !inner[..*index].contains(id)
                })
                .map(|(_, id)| *id),
        )
    }

    /// The node a failed dial counts against: the hop that failed, or the
    /// leaf when that hop belongs to a configured chain leaf. A route
    /// failure no hop owns, such as the chain deadline, counts against
    /// nothing.
    pub fn failure_owner(&self, error: &anyhow::Error) -> Option<Uuid> {
        let Some(route) = self.route() else {
            return Some(self.node.id);
        };
        let failure = crate::proxy::failed_hop(error)?;
        Some(match failure.hop < route.leaf_hops() {
            true => route.leaf(),
            false => failure.node,
        })
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
    fn of(node: &Node, route: Option<&Route>) -> Self {
        match route {
            Some(route) => Self::Route(*route),
            None => Self::Node(node.id),
        }
    }
}
