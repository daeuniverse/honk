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
