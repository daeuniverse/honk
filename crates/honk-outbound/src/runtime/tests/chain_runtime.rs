use super::*;

fn nodes() -> [Node; 3] {
    let front = node("front", NodeProtocol::Socks5);
    let land = node("land", NodeProtocol::Trojan);
    [
        Node::chain_from_nodes("via", &[&front, &land]).unwrap(),
        front,
        land,
    ]
}

fn assert_holds_hops_of(generation: &OutboundRuntimeRegistry, chain: &Node, hops: &[&Node]) {
    let runtime = generation.get(&chain.id).unwrap();
    runtime.validate_for_probe().unwrap();
    assert_eq!(runtime.chain_hops().len(), hops.len());
    for (held, hop) in runtime.chain_hops().iter().zip(hops) {
        assert!(Arc::ptr_eq(held, &generation.get(&hop.id).unwrap()));
    }
}

#[test]
fn chain_runtime_holds_the_hops_built_in_the_same_pass() {
    // The chain precedes its hops in the input; the second pass still finds them.
    let nodes = nodes();
    let generation = OutboundRuntimeRegistry::build(&nodes).unwrap();
    assert_holds_hops_of(&generation, &nodes[0], &[&nodes[1], &nodes[2]]);
    let runtime = generation.get(&nodes[0].id).unwrap();
    assert!(!runtime.udp_capable);
    assert!(matches!(&runtime.runtime, ProtocolRuntime::Chain(_)));
    assert!(
        generation
            .get(&nodes[1].id)
            .unwrap()
            .chain_hops()
            .is_empty()
    );
}

#[test]
fn chain_is_rebuilt_even_when_its_hops_are_reused() {
    let nodes = nodes();
    let first = OutboundRuntimeRegistry::build(&nodes).unwrap();
    let (second, reused) =
        OutboundRuntimeRegistry::build_reusing(&nodes, 64, Some(&first)).unwrap();
    assert_eq!(reused, HashSet::from([nodes[1].id, nodes[2].id]));
    assert!(!Arc::ptr_eq(
        &first.get(&nodes[0].id).unwrap(),
        &second.get(&nodes[0].id).unwrap()
    ));
    assert_holds_hops_of(&second, &nodes[0], &[&nodes[1], &nodes[2]]);
}

#[test]
fn chain_follows_a_replaced_hop_into_the_new_generation() {
    let mut nodes = nodes();
    let original_chain = nodes[0].clone();
    let original_exit = nodes[2].clone();
    let first = OutboundRuntimeRegistry::build(&nodes).unwrap();
    nodes[2] = node("land", NodeProtocol::SS);
    assert!(matches!(
        OutboundRuntimeRegistry::build_reusing(&nodes, 64, Some(&first)),
        Err(RuntimeRegistryError::Admission(_))
    ));
    nodes[0] = Node::chain_from_nodes("via", &[&nodes[1], &nodes[2]]).unwrap();
    assert_ne!(nodes[0].id, original_chain.id);
    let (second, _) = OutboundRuntimeRegistry::build_reusing(&nodes, 64, Some(&first)).unwrap();
    assert!(second.get(&original_chain.id).is_none());
    assert_holds_hops_of(&first, &original_chain, &[&nodes[1], &original_exit]);
    assert_holds_hops_of(&second, &nodes[0], &[&nodes[1], &nodes[2]]);
}

#[test]
fn dns_fork_chains_hold_the_fork_hops() {
    let nodes = nodes();
    let main = OutboundRuntimeRegistry::build(&nodes).unwrap();
    let dns = main.fork_for_dns().unwrap();
    assert_holds_hops_of(&dns, &nodes[0], &[&nodes[1], &nodes[2]]);
    assert!(!Arc::ptr_eq(
        &dns.get(&nodes[1].id).unwrap(),
        &main.get(&nodes[1].id).unwrap()
    ));
}

#[test]
fn unresolved_hops_fail_admission() {
    let mut nodes = nodes();
    assert!(NodeRuntime::try_ephemeral(&nodes[0]).is_err());
    nodes[0] = Node::chain("via", vec!["front".into(), "land".into()]);
    assert!(matches!(
        OutboundRuntimeRegistry::build(&nodes),
        Err(RuntimeRegistryError::Admission(_))
    ));
}

#[cfg(feature = "owned-tasks")]
#[tokio::test]
async fn private_chain_close_joins_hop_work_and_leaves_reused_registry_children_live() {
    use futures_util::FutureExt as _;

    let nodes = nodes();
    let (first, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&nodes, 1, 1, 1, true, None)
            .unwrap();
    let mut stale = Node::chain_from_nodes("via", &[&nodes[2], &nodes[1]]).unwrap();
    stale.id = nodes[0].id;
    assert!(matches!(
        first.try_ephemeral_guarded(&stale),
        Err(RuntimeRegistryError::ChainBinding)
    ));
    let mut guard = first.try_ephemeral_guarded(&nodes[0]).unwrap();
    let private = guard.runtime();
    let admitted = first.get(&nodes[0].id).unwrap();
    assert!(!Arc::ptr_eq(&private, &admitted));
    assert_eq!(private.chain_hops().len(), admitted.chain_hops().len());
    for (hop, live) in private.chain_hops().iter().zip(admitted.chain_hops()) {
        assert_eq!(hop.node.id, live.node.id);
        assert!(!Arc::ptr_eq(hop, live));
    }

    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let worker = private.chain_hops()[1]
        .task_owner
        .as_ref()
        .unwrap()
        .spawn_blocking(move || {
            started.send(()).unwrap();
            let _ = released.recv();
        })
        .unwrap();
    let live = admitted.chain_hops()[0]
        .task_scope()
        .spawn(std::future::pending())
        .unwrap();
    ready.await.unwrap();
    assert!(guard.close().now_or_never().is_none());
    release.send(()).unwrap();
    guard.close().await.unwrap();
    assert!(worker.is_finished());

    let (next, reused) = OutboundRuntimeRegistry::build_reusing(&nodes, 1, Some(&first)).unwrap();
    first.mark_moved_out(reused);
    first.retire_reusable_state().await;
    first.shutdown().await;
    assert!(!live.is_finished());
    next.shutdown().await;
    assert!(live.is_finished());
}
