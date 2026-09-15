use super::*;

#[test]
fn vless_registry_builds_only_selected_path_pools() {
    use honk_config::node::{Udp443Policy, VlessMultiplex, VlessUdpMux};
    use std::num::NonZeroU16;

    let limit = NonZeroU16::new(8).unwrap();
    for (multiplex, expected) in [
        (VlessMultiplex::Off, (false, false, false)),
        (VlessMultiplex::H2 { padding: false }, (true, false, false)),
        (
            VlessMultiplex::Xray {
                tcp: Some(limit),
                udp: VlessUdpMux::SharedTcp,
                udp443: Udp443Policy::Reject,
            },
            (false, true, false),
        ),
        (
            VlessMultiplex::Xray {
                tcp: Some(limit),
                udp: VlessUdpMux::Separate(limit),
                udp443: Udp443Policy::Reject,
            },
            (false, true, true),
        ),
    ] {
        let node = vless_node("vless", multiplex);
        let registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let ProtocolRuntime::Vless(runtime) = &registry.get(&node.id).unwrap().runtime else {
            panic!("VLESS node must own a VLESS runtime");
        };
        assert_eq!(runtime.h2_pool().is_ok(), expected.0);
        assert_eq!(runtime.shared_cool_pool().is_ok(), expected.1);
        assert_eq!(runtime.separate_cool_pool().is_ok(), expected.2);
    }
}
async fn reserve_existing_cool_child(
    pool: &Arc<crate::proxy::vless_cool::VlessCoolPool>,
    expected: &Arc<crate::proxy::vless_cool::VlessCoolSession>,
) -> crate::session::SessionPermit<crate::proxy::vless_cool::VlessCoolSession> {
    let crate::session::SpeculativeCheckout::Shared { session, permit } =
        pool.checkout_speculative().await.unwrap()
    else {
        panic!("spare child capacity must not require a replacement carrier");
    };
    assert!(Arc::ptr_eq(&session, expected));
    permit
}

#[tokio::test]
async fn separate_cool_warm_transitions_preserve_opposite_child_admission() {
    use crate::session::ManagedSession as _;
    use honk_config::node::{Udp443Policy, VlessMultiplex, VlessUdpMux};
    use std::num::NonZeroU16;

    enum Finish {
        Release,
        Rollback,
        Cancel,
    }

    let limit = NonZeroU16::new(8).unwrap();
    for reason in [WarmRetention::Selector, WarmRetention::Udp] {
        let node = vless_node(
            "vless-independent-warm",
            VlessMultiplex::Xray {
                tcp: Some(limit),
                udp: VlessUdpMux::Separate(limit),
                udp443: Udp443Policy::Reject,
            },
        );
        let registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let runtime = registry.get(&node.id).unwrap();
        let ProtocolRuntime::Vless(vless) = &runtime.runtime else {
            panic!("VLESS runtime expected");
        };
        let shared = vless.shared_cool_pool().unwrap();
        let separate = vless.separate_cool_pool().unwrap();
        let (owned_pool, opposite_pool) = match reason {
            WarmRetention::Selector => (shared, separate),
            WarmRetention::Udp => (separate, shared),
        };
        let (opposite_io, _opposite_peer) = tokio::io::duplex(1024);
        let opposite = crate::proxy::vless_cool::connect(Box::new(opposite_io), 8);
        opposite_pool.insert(&opposite);
        let opposite_child = opposite.try_reserve().unwrap();

        for finish in [Finish::Release, Finish::Rollback, Finish::Cancel] {
            let (owned_io, _owned_peer) = tokio::io::duplex(1024);
            let owned = crate::proxy::vless_cool::connect(Box::new(owned_io), 8);
            owned_pool.insert(&owned);
            let owned_child = owned.try_reserve().unwrap();

            let attempt = runtime.retain_warm(reason).await;
            drop(reserve_existing_cool_child(&opposite_pool, &opposite).await);
            drop(reserve_existing_cool_child(&owned_pool, &owned).await);
            match finish {
                Finish::Release => {
                    attempt.commit();
                    runtime.release_warm(reason).await;
                }
                Finish::Rollback => attempt.rollback().await,
                Finish::Cancel => drop(attempt),
            }

            assert!(owned.try_reserve().is_none(), "unpin must stop admission");
            assert!(!owned.is_closed(), "unpin must not cut an existing child");
            drop(reserve_existing_cool_child(&opposite_pool, &opposite).await);
            drop(owned_child);
            assert!(owned.is_closed(), "last child completes the unpinned drain");
        }

        drop(opposite_child);
        registry.shutdown().await;
    }
}
#[test]
fn vless_probe_readiness_uses_the_requested_path() {
    use honk_config::node::{Udp443Policy, VlessMultiplex, VlessUdpMux};
    use std::num::NonZeroU16;

    let limit = NonZeroU16::new(8).unwrap();
    let udp_only = vless_node(
        "vless-udp-only-pool",
        VlessMultiplex::Xray {
            tcp: None,
            udp: VlessUdpMux::Separate(limit),
            udp443: Udp443Policy::Reject,
        },
    );
    let tcp_only = vless_node(
        "vless-tcp-only-pool",
        VlessMultiplex::Xray {
            tcp: Some(limit),
            udp: VlessUdpMux::Protocol,
            udp443: Udp443Policy::Reject,
        },
    );
    let registry = OutboundRuntimeRegistry::build(&[udp_only.clone(), tcp_only.clone()]).unwrap();
    let udp_runtime = registry.get(&udp_only.id).unwrap();
    assert!(udp_runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Session));
    assert!(!udp_runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Udp));
    let tcp_runtime = registry.get(&tcp_only.id).unwrap();
    assert!(!tcp_runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Session));
    assert!(tcp_runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Udp));
}
#[test]
fn vless_source_id_normalizes_client_and_partitions_scope() {
    use honk_config::node::{VlessMultiplex, VlessUdpPath};

    let node = vless_node("vless-source", VlessMultiplex::Off);
    let registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    let runtime = registry.get(&node.id).unwrap();
    let ipv4 = "192.0.2.1:53000".parse().unwrap();
    let mapped = "[::ffff:192.0.2.1]:53000".parse().unwrap();
    let reply = "198.51.100.2:53".parse().unwrap();
    let id = runtime
        .vless_source_id(ipv4, VlessUdpPath::Xudp, None)
        .unwrap();
    assert_ne!(id, [0; 8]);

    assert_eq!(
        id,
        runtime
            .vless_source_id(mapped, VlessUdpPath::Xudp, None)
            .unwrap()
    );
    assert_ne!(
        id,
        runtime
            .vless_source_id(ipv4, VlessUdpPath::CoolShared, None)
            .unwrap()
    );
    assert_ne!(
        id,
        runtime
            .vless_source_id(ipv4, VlessUdpPath::Xudp, Some(reply))
            .unwrap()
    );
}

fn cold_probe_vless_node(name: &str) -> Node {
    let limit = std::num::NonZeroU16::new(8).unwrap();
    vless_node(
        name,
        honk_config::node::VlessMultiplex::Xray {
            tcp: Some(limit),
            udp: honk_config::node::VlessUdpMux::Separate(limit),
            udp443: honk_config::node::Udp443Policy::Reject,
        },
    )
}

#[test]
fn cold_http_and_udp_probes_share_exhausted_generation_and_dns_carrier_gate() {
    let node = cold_probe_vless_node("carrier-cold-probes");
    let (generation, _) = OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
        std::slice::from_ref(&node),
        1,
        1,
        1,
        None,
    )
    .unwrap();
    let dns = generation.fork_for_dns().unwrap();
    let held = dns.get(&node.id).unwrap().acquire_vless_carrier().unwrap();
    let (http, http_guard) = crate::urltest::try_probe_runtime(
        &generation,
        &node,
        crate::proxy::WarmRequirement::Session,
    )
    .unwrap();
    let (udp, udp_guard) =
        crate::urltest::try_probe_runtime(&dns, &node, crate::proxy::WarmRequirement::Udp).unwrap();
    assert!(http_guard.is_some());
    assert!(udp_guard.is_some());
    for runtime in [&http, &udp] {
        let error = runtime.acquire_vless_carrier().unwrap_err();
        assert!(matches!(
            error.downcast_ref::<crate::proxy::PacketRejection>(),
            Some(crate::proxy::PacketRejection::Capacity)
        ));
    }

    drop(held);
    let held = http.acquire_vless_carrier().unwrap();
    let error = udp.acquire_vless_carrier().unwrap_err();
    assert!(matches!(
        error.downcast_ref::<crate::proxy::PacketRejection>(),
        Some(crate::proxy::PacketRejection::Capacity)
    ));
    drop(held);
}

#[test]
fn reload_and_dns_share_the_startup_vless_carrier_ceiling() {
    let first_node = vless_node("carrier-first", honk_config::node::VlessMultiplex::Off);
    let (first, _) = OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
        std::slice::from_ref(&first_node),
        1,
        4,
        1,
        None,
    )
    .unwrap();
    let first_runtime = first.get(&first_node.id).unwrap();
    let held = first_runtime.acquire_vless_carrier().unwrap();
    let dns = first.fork_for_dns().unwrap();
    let dns_runtime = dns.get(&first_node.id).unwrap();
    let successor_node = vless_node("carrier-successor", honk_config::node::VlessMultiplex::Off);
    let (successor, _) = OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
        std::slice::from_ref(&successor_node),
        1,
        99,
        99,
        Some(&first),
    )
    .unwrap();
    let successor_runtime = successor.get(&successor_node.id).unwrap();

    for runtime in [&dns_runtime, &successor_runtime] {
        let error = runtime.acquire_vless_carrier().unwrap_err();
        assert!(matches!(
            error.downcast_ref::<crate::proxy::PacketRejection>(),
            Some(crate::proxy::PacketRejection::Capacity)
        ));
    }
    drop(held);
    drop(successor_runtime.acquire_vless_carrier().unwrap());
}

#[test]
fn zero_vless_carrier_ceiling_remains_zero_for_cold_probes() {
    let node = cold_probe_vless_node("carrier-zero");
    let (registry, _) = OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
        std::slice::from_ref(&node),
        1,
        1,
        0,
        None,
    )
    .unwrap();
    for requirement in [
        crate::proxy::WarmRequirement::Session,
        crate::proxy::WarmRequirement::Udp,
    ] {
        let (runtime, guard) =
            crate::urltest::try_probe_runtime(&registry, &node, requirement).unwrap();
        assert!(guard.is_some());
        let error = runtime.acquire_vless_carrier().unwrap_err();
        assert!(matches!(
            error.downcast_ref::<crate::proxy::PacketRejection>(),
            Some(crate::proxy::PacketRejection::Capacity)
        ));
    }
}
#[test]
fn vless_runtime_reuse_is_path_exact() {
    use honk_config::node::{Udp443Policy, VlessMultiplex, VlessUdpMux};
    use std::num::NonZeroU16;

    let node = vless_node(
        "vless-cool",
        VlessMultiplex::Xray {
            tcp: Some(NonZeroU16::new(8).unwrap()),
            udp: VlessUdpMux::SharedTcp,
            udp443: Udp443Policy::Reject,
        },
    );
    let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    let (unchanged, reused) =
        OutboundRuntimeRegistry::build_reusing(std::slice::from_ref(&node), 64, Some(&first))
            .unwrap();
    assert_eq!(reused, HashSet::from([node.id]));
    assert!(Arc::ptr_eq(
        &first.get(&node.id).unwrap(),
        &unchanged.get(&node.id).unwrap()
    ));

    let mut changed = node.clone();
    changed.vless_mut().unwrap().multiplex = VlessMultiplex::H2 { padding: false };
    changed.id = changed.derive_id();
    let (changed_registry, reused) =
        OutboundRuntimeRegistry::build_reusing(std::slice::from_ref(&changed), 64, Some(&first))
            .unwrap();
    assert!(reused.is_empty());
    assert!(!Arc::ptr_eq(
        &first.get(&node.id).unwrap(),
        &changed_registry.get(&changed.id).unwrap()
    ));
    let ProtocolRuntime::Vless(vless) = &changed_registry.get(&changed.id).unwrap().runtime else {
        panic!("VLESS runtime expected");
    };
    assert!(vless.h2_pool().is_ok());
}

#[test]
fn parsed_equivalent_vless_udp_fallbacks_reuse_runtime() {
    let uuid = "00000000-0000-0000-0000-000000000001";
    let common = "mux=xray&concurrency=-1&xudpConcurrency=8&xudpProxyUDP443=skip";
    for (left, right) in [
        (
            format!(
                "vless://{uuid}@example.com:443?security=tls&flow=xtls-rprx-vision&packetEncoding=auto&{common}#same-name"
            ),
            format!(
                "vless://{uuid}@example.com:443?security=tls&flow=xtls-rprx-vision&packetEncoding=uot-v2&{common}#same-name"
            ),
        ),
        (
            format!("vless://{uuid}@example.com:443?packetEncoding=auto&{common}#same-name"),
            format!("vless://{uuid}@example.com:443?packetEncoding=none&{common}#same-name"),
        ),
    ] {
        let left = Node::from_share_link(&left).unwrap();
        let right = Node::from_share_link(&right).unwrap();
        assert_eq!(left.id, right.id);
        let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&left)).unwrap();
        let first_runtime = first.get(&left.id).unwrap();
        let (replacement, reused) =
            OutboundRuntimeRegistry::build_reusing(std::slice::from_ref(&right), 64, Some(&first))
                .unwrap();
        assert_eq!(reused, HashSet::from([left.id]));
        assert!(Arc::ptr_eq(
            &first_runtime,
            &replacement.get(&right.id).unwrap()
        ));
    }
}
