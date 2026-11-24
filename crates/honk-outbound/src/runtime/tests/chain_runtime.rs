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
    // A Trojan exit carries UDP over the stream to it.
    assert!(runtime.udp_capable);
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
fn composed_udp_requires_the_entry_to_support_tunneled_dial() {
    use crate::alive::{IpVersion, ProbeDomain};
    use crate::group::{GroupManager, ScoreSelectionContext, SelectionNetwork};
    use crate::proxy::{DialFailureScope, DialRef, ProxyRegistry, dial_failure_scope};
    use honk_config::group::Group;

    let cases = [
        ("socks5://127.0.0.1:1080#socks", true),
        ("anytls://secret@127.0.0.1:443#anytls", false),
        ("hysteria2://auth@127.0.0.1:443#hy2", false),
        ("trojan://secret@entry.example:443?ech=1#ech", false),
        (
            "trojan://secret@127.0.0.1:443?security=tls&sni=entry.example&type=xhttp&path=%2Fx#xhttp",
            false,
        ),
        #[cfg(feature = "rprx")]
        (
            "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?security=tls&flow=xtls-rprx-vision#vision",
            false,
        ),
        #[cfg(feature = "rprx")]
        (
            "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?mux=xray#mux",
            false,
        ),
        #[cfg(feature = "rprx")]
        (
            "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?encryption=mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#encryption",
            false,
        ),
    ];
    let tcp =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let udp = ScoreSelectionContext::aggregate(
        SelectionNetwork::Udp,
        ProbeDomain::DataUdp,
        IpVersion::V4,
    );
    let proxy = ProxyRegistry::default_resolver().unwrap();
    for (link, capable) in cases {
        let front = Node::from_share_link(link).unwrap();
        let land = Node::from_share_link("trojan://secret@127.0.0.1:444#land").unwrap();
        let via = Node::chain_from_nodes("via", &[&front, &land]).unwrap();
        let group = |name: &str, node: &Node, exit: Option<&Node>| Group {
            name: name.into(),
            nodes: vec![node.id],
            exit: exit.map(|node| node.name.clone()),
            ..Default::default()
        };
        let groups = [
            group("bare", &front, None),
            group("configured", &via, None),
            group("route", &front, Some(&land)),
            group("collapsed", &land, Some(&land)),
        ];
        let (front_id, via_id, land_id) = (front.id, via.id, land.id);
        let nodes = [front, via, land];
        let generation = OutboundRuntimeRegistry::build(&nodes).unwrap();
        let manager = GroupManager::new(&groups, &nodes);
        let eligible = |name, context| manager.selection_plan_for_target(name, context).entries;

        assert_eq!(eligible("bare", &udp)[0].node.id, front_id);
        let collapsed = eligible("collapsed", &udp);
        assert_eq!(collapsed[0].node.id, land_id);
        assert!(collapsed[0].route.is_none());
        assert_eq!(eligible("configured", &tcp)[0].node.id, via_id);
        let routed_tcp = eligible("route", &tcp);
        let route = routed_tcp[0].route.as_deref().unwrap();
        assert_eq!(route.hops(), [front_id, land_id]);
        assert_eq!(generation.udp_capable(&nodes[1]), capable, "{link}");
        assert_eq!(
            generation.route_runtime(route).unwrap().udp_capable(),
            capable,
            "{link}"
        );
        assert_eq!(!eligible("configured", &udp).is_empty(), capable, "{link}");
        assert_eq!(!eligible("route", &udp).is_empty(), capable, "{link}");
        assert_eq!(
            manager.routed_group_available("route", ProbeDomain::DataUdp, IpVersion::V4),
            Some(capable),
            "{link}"
        );

        let (_, framing) = proxy.udp_probe_target(&generation, &nodes[0]).unwrap();
        assert_eq!(framing.id, front_id);
        let bound = proxy
            .udp_framing_node(&generation, DialRef::Node(land_id))
            .unwrap();
        assert_eq!(bound.id, land_id);
        for dial in [DialRef::Node(via_id), DialRef::Route(route)] {
            match proxy.udp_framing_node(&generation, dial) {
                Ok(framing) => {
                    assert!(capable, "{link}");
                    assert_eq!(framing.id, land_id);
                }
                Err(error) => {
                    assert!(!capable, "{link}: {error:#}");
                    assert_eq!(
                        dial_failure_scope(error.as_ref()),
                        DialFailureScope::LocalRejection
                    );
                }
            }
        }
    }
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
