use super::*;
use honk_config::group_graph::{Composed, compose};
use honk_config::route::Route;

fn nodes() -> [Node; 2] {
    [
        node("front", NodeProtocol::Socks5),
        node("land", NodeProtocol::Trojan),
    ]
}

fn route(leaf: uuid::Uuid, hops: &[&Node]) -> Route {
    let ids: Vec<_> = hops.iter().map(|hop| hop.id).collect();
    let (last, own) = ids.split_last().unwrap();
    match compose(leaf, own, [*last]) {
        Composed::Routed(route) => route,
        other => panic!("expected a route, got {other:?}"),
    }
}

fn assert_holds_hops_of(
    generation: &OutboundRuntimeRegistry,
    runtime: &RouteRuntime,
    hops: &[&Node],
) {
    assert_eq!(runtime.hops().len(), hops.len());
    for (held, hop) in runtime.hops().iter().zip(hops) {
        assert!(Arc::ptr_eq(held, &generation.get(&hop.id).unwrap()));
    }
}

#[test]
fn concurrent_first_dials_build_one_route_runtime() {
    let nodes = nodes();
    let generation = Arc::new(OutboundRuntimeRegistry::build(&nodes).unwrap());
    let hops = nodes
        .each_ref()
        .map(|node| generation.get(&node.id).unwrap());
    let before = hops.each_ref().map(Arc::strong_count);
    let route = route(nodes[0].id, &[&nodes[0], &nodes[1]]);
    let barrier = Arc::new(std::sync::Barrier::new(32));
    let runtimes: Vec<_> = (0..32)
        .map(|_| {
            let (generation, barrier) = (Arc::clone(&generation), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                generation.route_runtime(&route).unwrap()
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert!(
        runtimes
            .iter()
            .all(|runtime| Arc::ptr_eq(runtime, &runtimes[0]))
    );
    assert_eq!(generation.routes.builds.load(Ordering::Relaxed), 1);
    assert_eq!(
        hops.each_ref().map(Arc::strong_count),
        before.map(|count| count + 1)
    );
    assert_holds_hops_of(&generation, &runtimes[0], &[&nodes[0], &nodes[1]]);
}

#[test]
fn a_reload_rebuilds_route_runtimes_over_the_new_hops() {
    let [front, land] = nodes();
    let nodes = [front, node("middle", NodeProtocol::Socks5), land];
    let hops = nodes.each_ref();
    let old = OutboundRuntimeRegistry::build(&nodes).unwrap();
    let route = route(nodes[0].id, &hops);
    let before = old.route_runtime(&route).unwrap();
    let (new, reused) = OutboundRuntimeRegistry::build_reusing(&nodes, 8, Some(&old)).unwrap();
    assert_eq!(reused.len(), hops.len());
    assert_eq!(new.routes.len(), 0);
    let after = new.route_runtime(&route).unwrap();
    assert!(!Arc::ptr_eq(&before, &after));
    assert_holds_hops_of(&new, &after, &hops);
    // A DNS fork dials over its own hop runtimes, never the source's.
    let fork = old.fork_for_dns().unwrap();
    assert_eq!(fork.routes.len(), 0);
    let forked = fork.route_runtime(&route).unwrap();
    assert_holds_hops_of(&fork, &forked, &hops);
    assert!(!Arc::ptr_eq(&forked.hops()[0], &before.hops()[0]));
}

#[test]
fn a_route_with_a_replaced_physical_hop_is_not_in_the_new_generation() {
    let [front, land] = nodes();
    let old = OutboundRuntimeRegistry::build(&[front.clone(), land.clone()]).unwrap();
    let captured = route(front.id, &[&front, &land]);
    let first = old.route_runtime(&captured).unwrap();

    let mut replacement = land.clone();
    replacement.port += 1;
    replacement.address = format!("{}:{}", replacement.host, replacement.port);
    replacement.id = replacement.derive_id();
    let (new, _) = OutboundRuntimeRegistry::build_reusing(
        &[front.clone(), replacement.clone()],
        8,
        Some(&old),
    )
    .unwrap();
    assert!(new.route_runtime(&captured).is_none());
    assert_holds_hops_of(&old, &first, &[&front, &land]);

    let updated = route(front.id, &[&front, &replacement]);
    assert_ne!(updated, captured);
    let rebuilt = new.route_runtime(&updated).unwrap();
    assert_holds_hops_of(&new, &rebuilt, &[&front, &replacement]);
}

#[test]
fn a_rejected_reload_keeps_old_route_runtimes() {
    let nodes = nodes();
    let old = OutboundRuntimeRegistry::build(&nodes).unwrap();
    let route = route(nodes[0].id, &[&nodes[0], &nodes[1]]);
    let before = old.route_runtime(&route).unwrap();
    let rejected = [nodes[0].clone(), nodes[1].clone(), nodes[0].clone()];
    assert_admission(
        OutboundRuntimeRegistry::build_reusing(&rejected, 8, Some(&old)).unwrap_err(),
        "duplicate-node-id",
        2,
    );
    assert!(Arc::ptr_eq(&before, &old.route_runtime(&route).unwrap()));
    assert_holds_hops_of(&old, &before, &[&nodes[0], &nodes[1]]);
}

#[test]
fn a_retired_generation_builds_no_route_runtime() {
    let nodes = nodes();
    let generation = OutboundRuntimeRegistry::build(&nodes).unwrap();
    let route = route(nodes[0].id, &[&nodes[0], &nodes[1]]);
    generation.begin_retirement();
    assert!(generation.route_runtime(&route).is_none());
    assert_eq!(generation.routes.builds.load(Ordering::Relaxed), 0);
}

#[test]
fn a_route_with_a_missing_hop_builds_no_runtime() {
    let nodes = nodes();
    let generation = OutboundRuntimeRegistry::build(&nodes[..1]).unwrap();
    assert!(
        generation
            .route_runtime(&route(nodes[0].id, &[&nodes[0], &nodes[1]]))
            .is_none()
    );
    assert!(
        generation
            .route_runtime(&route(nodes[1].id, &[&nodes[1], &nodes[0]]))
            .is_none()
    );
    assert!(
        generation
            .route_runtime(&route(nodes[0].id, &[&nodes[0], &nodes[1], &nodes[0]]))
            .is_none()
    );
    assert_eq!(generation.routes.len(), 0);
}

#[test]
fn a_full_route_cache_still_builds_uncached() {
    let [front, land] = nodes();
    let nodes = [
        front,
        node("middle", NodeProtocol::Socks5),
        node("near", NodeProtocol::Socks5),
        land,
    ];
    let hops = nodes.each_ref();
    let generation = OutboundRuntimeRegistry::build(&nodes).unwrap();
    for leaf in 0..MAX_ROUTE_RUNTIMES {
        let leaf = uuid::Uuid::from_u128(leaf as u128 + 1);
        generation.route_runtime(&route(leaf, &hops)).unwrap();
    }
    assert_eq!(generation.routes.len(), MAX_ROUTE_RUNTIMES);
    let overflow = route(uuid::Uuid::from_u128(u128::MAX), &hops);
    let first = generation.route_runtime(&overflow).unwrap();
    let second = generation.route_runtime(&overflow).unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(generation.routes.len(), MAX_ROUTE_RUNTIMES);
    assert_holds_hops_of(&generation, &first, &hops);
}
