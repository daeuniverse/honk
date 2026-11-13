//! Runtimes for routes through group exits. A route is a selection result,
//! not a configured node, so it has no `NodeRuntime`; it dials over the
//! runtimes its generation already holds for its hops.

use std::collections::HashMap;
use std::sync::Arc;

use honk_config::node::MAX_CHAIN_HOPS;
use honk_config::route::Route;

use super::NodeRuntime;

/// Maximum route runtimes cached per generation. A route past it dials over an
/// uncached runtime.
pub const MAX_ROUTE_RUNTIMES: usize = 4096;

/// A route and its generation's hop runtimes. It owns no protocol state,
/// tasks or transport evidence: each hop's stay with that hop's runtime.
#[derive(Debug)]
pub struct RouteRuntime {
    route: Route,
    /// Entry first; slots past the route's length repeat its exit, so the
    /// hops borrow as one slice without a separate allocation.
    hops: [Arc<NodeRuntime>; MAX_CHAIN_HOPS],
    /// Whether the exit tunnels UDP over the stream to it.
    pub udp_capable: bool,
}

impl RouteRuntime {
    /// `None` when any hop is missing from `nodes`.
    fn build(route: &Route, nodes: &HashMap<uuid::Uuid, Arc<NodeRuntime>>) -> Option<Self> {
        let ids = route.hops();
        let exit = nodes.get(&route.exit())?;
        let mut hops: [Arc<NodeRuntime>; MAX_CHAIN_HOPS] =
            std::array::from_fn(|_| Arc::clone(exit));
        for (slot, id) in hops.iter_mut().zip(ids) {
            *slot = Arc::clone(nodes.get(id)?);
        }
        let exit = &hops[ids.len().saturating_sub(1)].node;
        Some(Self {
            route: *route,
            udp_capable: crate::descriptor::carries_udp(match ids.len() {
                1 => crate::descriptor::UdpPath::Own(exit),
                _ => crate::descriptor::UdpPath::Tunneled { exit },
            }),
            hops,
        })
    }

    pub fn route(&self) -> &Route {
        &self.route
    }

    /// The hop runtimes, entry first.
    pub fn hops(&self) -> &[Arc<NodeRuntime>] {
        &self.hops[..self.route.hops().len()]
    }
}

/// A generation's route runtimes, each built once on first use. The lock is a
/// leaf: no other lock is taken and nothing is awaited while it is held.
#[derive(Debug, Default)]
pub(super) struct RouteRuntimes {
    routes: parking_lot::RwLock<HashMap<Route, Arc<RouteRuntime>>>,
    full_warned: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    pub(super) builds: std::sync::atomic::AtomicUsize,
}

impl RouteRuntimes {
    pub(super) fn get_or_build(
        &self,
        route: &Route,
        nodes: &HashMap<uuid::Uuid, Arc<NodeRuntime>>,
    ) -> Option<Arc<RouteRuntime>> {
        if let Some(runtime) = self.routes.read().get(route) {
            return Some(Arc::clone(runtime));
        }
        let mut routes = self.routes.write();
        if let Some(runtime) = routes.get(route) {
            return Some(Arc::clone(runtime));
        }
        let runtime = Arc::new(RouteRuntime::build(route, nodes)?);
        #[cfg(test)]
        self.builds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if routes.len() < MAX_ROUTE_RUNTIMES {
            routes.insert(*route, Arc::clone(&runtime));
        } else if !self
            .full_warned
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            tracing::warn!(
                limit = MAX_ROUTE_RUNTIMES,
                "route runtime cache is full; further routes dial without caching"
            );
        }
        Some(runtime)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.routes.read().len()
    }
}
