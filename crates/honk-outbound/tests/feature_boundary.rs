#![cfg(not(feature = "rprx"))]

use honk_config::group_graph::{Composed, compose};
use honk_config::node::{Node, OutboundConfig, VmessConfig};
use honk_outbound::ProxyRegistry;
use honk_outbound::group::{ExitCollapse, OwnedTarget};
use honk_outbound::proxy::{
    DialFailureScope, DialRef, MissingProtocolHandler, dial_failure_scope, is_packet_rejection,
};
use honk_outbound::runtime::{NodeRuntime, OutboundRuntimeRegistry, ProtocolRuntime};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

// Integration tests link the normal library: cfg(test) must not enable its backend.
#[tokio::test]
async fn parsed_vless_has_no_backend_without_rprx() {
    for link in [
        "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:9?security=none&mux=h2mux&udp=1",
        "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:9?security=none&type=xhttp",
    ] {
        assert_no_vless_backend(Node::from_share_link(link).unwrap()).await;
    }
}

async fn assert_no_vless_backend(node: Node) {
    let generation = Arc::new(OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap());
    let fork = generation.fork_for_dns().unwrap();
    let mut ephemeral = NodeRuntime::try_ephemeral_guarded(&node).unwrap();
    let (successor, reused) = OutboundRuntimeRegistry::build_reusing(
        std::slice::from_ref(&node),
        1,
        Some(generation.as_ref()),
    )
    .unwrap();
    generation.mark_moved_out(reused);
    for runtime in [
        generation.get(&node.id).unwrap(),
        fork.get(&node.id).unwrap(),
        ephemeral.runtime(),
        successor.get(&node.id).unwrap(),
    ] {
        assert!(matches!(runtime.runtime, ProtocolRuntime::None));
        assert_eq!(runtime.warm_counts().sessions, 0);
        assert!(runtime.is_warm_or_stateless_for(honk_outbound::proxy::WarmRequirement::Session));
        assert!(runtime.is_warm_or_stateless_for(honk_outbound::proxy::WarmRequirement::Udp));
    }
    let registry = ProxyRegistry::default_resolver().unwrap();
    let timeout = Duration::from_millis(100);
    let target = "127.0.0.1:9".parse().unwrap();
    assert!(registry.dial(&node, target, None, timeout).await.is_err());
    assert!(
        registry
            .dial_udp_transport(&node, target, None, timeout)
            .await
            .is_err()
    );
    assert!(
        registry
            .warm_session(Arc::clone(&generation), node.id, timeout)
            .await
            .is_err()
    );
    assert!(
        registry
            .warm_udp(Arc::clone(&generation), node.id, timeout)
            .await
            .is_err()
    );
    ephemeral.close().await.unwrap();
    fork.shutdown().await;
    generation.shutdown().await;
    successor.shutdown().await;
}

#[tokio::test]
async fn missing_tcp_backend_is_retryable_without_connecting_the_prefix() {
    const UUID: &str = "00000000-0000-4000-8000-000000000001";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let front = Node::from_share_link(&format!("socks5://{addr}#front")).unwrap();
    let mut vmess = Node {
        name: "vmess".into(),
        host: "127.0.0.1".into(),
        address: "127.0.0.1:9".into(),
        port: 9,
        outbound: OutboundConfig::Vmess(VmessConfig {
            uuid: Some(UUID.into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    vmess.id = vmess.derive_id();
    let registry = ProxyRegistry::default_resolver().unwrap();
    for missing in [
        vmess,
        Node::from_share_link(&format!("vless://{UUID}@127.0.0.1:9?security=none#vless")).unwrap(),
    ] {
        let check = |error: &anyhow::Error| {
            assert!(matches!(
                error.downcast_ref::<MissingProtocolHandler>(),
                Some(handler) if handler.0 == missing.protocol()
            ));
            assert_eq!(
                dial_failure_scope(error.as_ref()),
                DialFailureScope::LocalRejection
            );
            assert!(!is_packet_rejection(error));
            let mut owner = OwnedTarget::node(missing.clone());
            assert_eq!(owner.failure_owner(error), Some(missing.id));
            for collapse in [ExitCollapse::Direct, ExitCollapse::Member] {
                owner.collapse = collapse;
                assert_eq!(owner.failure_owner(error), None);
            }
        };
        for hops in [[&front, &missing], [&missing, &front]] {
            let chain = Node::chain_from_nodes("configured", &hops).unwrap();
            let generation = Arc::new(
                OutboundRuntimeRegistry::build(&[chain.clone(), front.clone(), missing.clone()])
                    .unwrap(),
            );
            let Composed::Routed(route) = compose(hops[0].id, &[hops[0].id], [hops[1].id]) else {
                panic!("expected a two-hop route");
            };
            for dial in [
                DialRef::Node(missing.id),
                DialRef::Node(chain.id),
                DialRef::Route(&route),
            ] {
                let error = registry
                    .dial_ref(
                        Arc::clone(&generation),
                        dial,
                        "127.0.0.1:9".parse().unwrap(),
                        None,
                        Duration::from_millis(100),
                    )
                    .await
                    .expect_err("the missing handler cannot open TCP");
                check(&error);
                assert_eq!(OwnedTarget::node(chain.clone()).failure_owner(&error), None);
            }
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "an unavailable backend must not even open the usable prefix socket"
    );
}

#[tokio::test]
async fn composed_udp_missing_a_backend_refuses_before_connecting_the_prefix() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let front = Node::from_share_link(&format!("socks5://{addr}#front")).unwrap();
    let missing = Node::from_share_link(
        "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:9?security=none#vless",
    )
    .unwrap();
    let trojan = Node::from_share_link("trojan://secret@127.0.0.1:443#land").unwrap();
    let proxy = ProxyRegistry::default_resolver().unwrap();
    for hops in [&[&front, &missing][..], &[&front, &missing, &trojan][..]] {
        let chain = Node::chain_from_nodes("configured-udp", hops).unwrap();
        let generation = Arc::new(
            OutboundRuntimeRegistry::build(&[
                chain.clone(),
                front.clone(),
                missing.clone(),
                trojan.clone(),
            ])
            .unwrap(),
        );
        let Composed::Routed(route) =
            compose(front.id, &[front.id], hops[1..].iter().map(|hop| hop.id))
        else {
            panic!("expected a composed UDP route");
        };
        let timeout = Duration::from_millis(100);
        for error in [
            proxy
                .dial_udp_transport_runtime(Arc::clone(&generation), chain.id, addr, None, timeout)
                .await
                .unwrap_err(),
            proxy
                .dial_udp_route(generation, &route, addr, None, timeout)
                .await
                .unwrap_err(),
        ] {
            assert!(matches!(
                error.downcast_ref::<MissingProtocolHandler>(),
                Some(handler) if handler.0 == missing.protocol()
            ));
            assert_eq!(
                dial_failure_scope(error.as_ref()),
                DialFailureScope::LocalRejection
            );
            assert!(!is_packet_rejection(&error));
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[test]
fn udp_selection_skips_uncompiled_bound_hops_before_policy() {
    use honk_config::group::{Group, GroupPolicy};
    use honk_outbound::alive::{IpVersion, ProbeDomain};
    use honk_outbound::group::GroupManager;

    const UUID: &str = "00000000-0000-4000-8000-000000000001";
    let front = Node::from_share_link("socks5://127.0.0.1:1080#front").unwrap();
    let land = Node::from_share_link("trojan://secret@127.0.0.1:443#land").unwrap();
    let vless = Node::from_share_link(&format!("vless://{UUID}@127.0.0.1:9#vless")).unwrap();
    let mut vmess = Node {
        name: "vmess".into(),
        host: "127.0.0.1".into(),
        address: "127.0.0.1:9".into(),
        port: 9,
        outbound: OutboundConfig::Vmess(VmessConfig {
            uuid: Some(UUID.into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    vmess.id = vmess.derive_id();
    for hops in [
        &[&vmess, &land][..],
        &[&front, &vmess, &land],
        &[&front, &vless],
    ] {
        let chain = Node::chain_from_nodes("via", hops).unwrap();
        let exit_group = |name: &str, node: &Node, exit: &Node| Group {
            name: name.into(),
            nodes: vec![node.id],
            exit: Some(exit.name.clone()),
            ..Default::default()
        };
        let parent = Group {
            name: "parent".into(),
            policy: GroupPolicy::Fallback,
            nodes: vec![chain.id],
            groups: vec!["route".into(), "safe".into()],
            ..Default::default()
        };
        let mut route = exit_group("route", hops[0], hops.last().unwrap());
        let mut groups = Vec::new();
        if hops.len() == 3 {
            route.nodes.clear();
            route.groups.push("inner".into());
            groups.push(exit_group("inner", hops[0], hops[1]));
        }
        groups.extend([
            route,
            Group {
                name: "safe".into(),
                nodes: vec![front.id],
                ..Default::default()
            },
            parent,
        ]);
        let manager = GroupManager::new(
            &groups,
            &[
                front.clone(),
                vmess.clone(),
                vless.clone(),
                land.clone(),
                chain.clone(),
            ],
        );
        assert!(!manager.node_carries_udp(&chain));
        assert_eq!(
            manager.routed_group_available("route", ProbeDomain::DataUdp, IpVersion::V4),
            Some(false)
        );
        let plan = manager.selection_plan_for_domain("parent", ProbeDomain::DataUdp, IpVersion::V4);
        assert_eq!(
            plan.nodes.iter().map(|node| node.id).collect::<Vec<_>>(),
            [front.id]
        );
    }
}
