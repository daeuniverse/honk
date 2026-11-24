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

const _: () = assert!(MAX_CHAIN_HOPS == 4);

/// The ordered hop runtimes owned by this generation. Protocol state, tasks
/// and transport evidence stay with each hop.
#[derive(Debug)]
pub struct RouteRuntime {
    hops: RouteHops,
}

#[derive(Debug)]
enum RouteHops {
    Two([Arc<NodeRuntime>; 2]),
    Three([Arc<NodeRuntime>; 3]),
    Four([Arc<NodeRuntime>; 4]),
}

impl RouteRuntime {
    /// `None` when any hop is missing from `nodes`.
    fn build(route: &Route, nodes: &HashMap<uuid::Uuid, Arc<NodeRuntime>>) -> Option<Self> {
        let get = |id: &uuid::Uuid| nodes.get(id).cloned();
        let hops = match route.hops() {
            [a, b] => RouteHops::Two([get(a)?, get(b)?]),
            [a, b, c] => RouteHops::Three([get(a)?, get(b)?, get(c)?]),
            [a, b, c, d] => RouteHops::Four([get(a)?, get(b)?, get(c)?, get(d)?]),
            _ => unreachable!("routes contain two to four hops"),
        };
        Some(Self { hops })
    }

    /// Intrinsic UDP capability of the entire captured hop sequence.
    pub fn udp_capable(&self) -> bool {
        crate::descriptor::tunneled_hops_carry_udp(self.hops(), |hop| Some(hop.node.as_ref()))
    }

    /// The hop runtimes, entry first.
    pub fn hops(&self) -> &[Arc<NodeRuntime>] {
        match &self.hops {
            RouteHops::Two(hops) => hops,
            RouteHops::Three(hops) => hops,
            RouteHops::Four(hops) => hops,
        }
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
