#![cfg(not(feature = "rprx"))]

use honk_config::node::Node;
use honk_outbound::ProxyRegistry;
use honk_outbound::runtime::{NodeRuntime, OutboundRuntimeRegistry, ProtocolRuntime};
use std::sync::Arc;
use std::time::Duration;

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
