use super::dial::source_path as source_path_in;
use super::*;
use crate::control::udp_endpoint::SourcePath;
use honk_config::node::OutboundConfig;
use honk_config::types::NodeProtocol;

fn node(protocol: NodeProtocol) -> Node {
    Node {
        outbound: OutboundConfig::from_protocol(protocol),
        ..Default::default()
    }
}

fn source_path(registry: &ProxyRegistry, node: &Node, port: u16) -> Option<SourcePath> {
    let empty = honk_outbound::runtime::OutboundRuntimeRegistry::build(&[]).unwrap();
    source_path_in(registry, &empty, node, port)
}

fn production() -> ProxyRegistry {
    ProxyRegistry::default_resolver().unwrap()
}

/// SOCKS5 registered with or without a shared-source slot.
fn socks5_registry(shared: bool) -> ProxyRegistry {
    let handler = Arc::new(honk_outbound::proxy::socks5::Socks5Handler::new());
    let mut entry =
        honk_outbound::proxy::ProtocolEntry::new(NodeProtocol::Socks5, Arc::clone(&handler))
            .with_packet(Arc::clone(&handler));
    if shared {
        entry = entry.with_shared(handler);
    }
    let mut registry = ProxyRegistry::new();
    registry.register(entry);
    registry
}

#[test]
fn source_path_selects_shared_exactly_for_the_registered_slots() {
    let registry = production();
    for (protocol, shared) in [
        (NodeProtocol::SS, true),
        (NodeProtocol::Trojan, true),
        (NodeProtocol::VMess, false),
        (NodeProtocol::Socks5, true),
        (NodeProtocol::Juicity, true),
        (NodeProtocol::AnyTLS, true),
        (NodeProtocol::Direct, false),
        (NodeProtocol::Block, false),
    ] {
        assert_eq!(
            source_path(&registry, &node(protocol), 443),
            shared.then_some(SourcePath::Shared),
            "{protocol:?}"
        );
    }
}

#[test]
fn the_registered_slot_alone_selects_the_shared_path() {
    let socks5 = node(NodeProtocol::Socks5);
    assert_eq!(
        source_path(&socks5_registry(false), &socks5, 443),
        None,
        "a registry without the slot keeps the ordinary path"
    );
    assert_eq!(
        source_path(&socks5_registry(true), &socks5, 443),
        Some(SourcePath::Shared)
    );
    assert_eq!(
        source_path(&ProxyRegistry::new(), &socks5, 443),
        None,
        "an unregistered protocol has no slot"
    );
}

#[cfg(feature = "rprx")]
#[test]
fn vless_shares_explicit_uot_and_h2_but_keeps_xudp_and_native_apart() {
    use honk_config::node::{
        Udp443Policy, VlessConfig, VlessMultiplex, VlessUdpEncoding, VlessUdpPath,
    };
    fn vless(
        udp_encoding: VlessUdpEncoding,
        multiplex: VlessMultiplex,
        network: Option<&str>,
    ) -> Node {
        Node {
            outbound: OutboundConfig::Vless(VlessConfig {
                udp_encoding,
                multiplex,
                network: network.map(Into::into),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
    let registry = production();
    let off = VlessMultiplex::Off;
    for port in [53, 443, 5301] {
        for node in [
            vless(VlessUdpEncoding::UotV2, off, None),
            vless(
                VlessUdpEncoding::Auto,
                VlessMultiplex::H2 { padding: false },
                None,
            ),
        ] {
            assert_eq!(
                source_path(&registry, &node, port),
                Some(SourcePath::Shared),
                "{port}"
            );
        }
    }
    assert_eq!(
        source_path(
            &ProxyRegistry::new(),
            &vless(VlessUdpEncoding::UotV2, off, None),
            5301
        ),
        None,
        "without a registered slot UoT stays on the ordinary path"
    );
    assert_eq!(
        source_path(&registry, &vless(VlessUdpEncoding::Auto, off, None), 53),
        None
    );
    assert_eq!(
        source_path(&registry, &vless(VlessUdpEncoding::Native, off, None), 5301),
        None
    );
    assert_eq!(
        source_path(&registry, &vless(VlessUdpEncoding::Xudp, off, None), 5301),
        Some(SourcePath::Vless(VlessUdpPath::Xudp))
    );
    // Reject and the capability gate keep their terminal meaning.
    let rejecting = vless(
        VlessUdpEncoding::UotV2,
        VlessMultiplex::xray(-1, -1, Udp443Policy::Reject),
        None,
    );
    assert_eq!(source_path(&registry, &rejecting, 443), None);
    assert_eq!(
        source_path(&registry, &rejecting, 5301),
        Some(SourcePath::Shared)
    );
    assert_eq!(
        source_path(
            &registry,
            &vless(VlessUdpEncoding::UotV2, off, Some("tcp")),
            5301
        ),
        None
    );
}

#[test]
fn quic_sources_keep_their_concrete_paths() {
    assert_eq!(
        source_path(&production(), &node(NodeProtocol::Hysteria2), 443),
        Some(SourcePath::Hysteria2)
    );
    assert_eq!(
        source_path(&production(), &node(NodeProtocol::Tuic), 443),
        Some(SourcePath::Tuic)
    );
}

fn chain_node(name: &str, hops: &[&Node]) -> Node {
    Node::chain_from_nodes(name, hops).unwrap()
}

fn exit_node(name: &str, port: u16, outbound: OutboundConfig) -> Node {
    let mut node = Node {
        name: name.into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        outbound,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

fn trojan_exit(port: u16) -> Node {
    exit_node(
        "trojan",
        port,
        OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            password: Some("secret".into()),
            tls: honk_config::node::TlsOptions {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        }),
    )
}

/// Only a configured chain whose exit registers a tunneled shared source,
/// Trojan here, shares a source; a VLESS exit sends native UDP per flow.
#[test]
fn a_chain_shares_a_source_only_when_configured_with_a_shared_exit() {
    let front = exit_node("front", 1080, OutboundConfig::Socks5(Default::default()));
    let trojan = trojan_exit(443);
    let vless = exit_node(
        "vless",
        443,
        OutboundConfig::Vless(honk_config::node::VlessConfig {
            uuid: Some("00000000-0000-4000-8000-000000000001".into()),
            ..Default::default()
        }),
    );
    let via_trojan = chain_node("via-trojan", &[&front, &trojan]);
    let via_vless = chain_node("via-vless", &[&front, &vless]);
    let generation = honk_outbound::runtime::OutboundRuntimeRegistry::build(&[
        via_trojan.clone(),
        via_vless.clone(),
        front.clone(),
        trojan.clone(),
        vless,
    ])
    .unwrap();
    let registry = production();
    for (node, path) in [(&via_trojan, Some(SourcePath::Shared)), (&via_vless, None)] {
        assert_eq!(
            source_path_in(&registry, &generation, node, 443),
            path,
            "{}",
            node.name
        );
    }
}

/// Two destinations of one client ride one Trojan associate through the chain.
#[tokio::test]
async fn one_client_shares_one_chain_association_across_destinations() {
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = server.accept().await {
            held.push(stream);
        }
    });
    let relay = crate::test_support::socks5_relay().await;
    let front = exit_node(
        "front",
        relay.addr.port(),
        OutboundConfig::Socks5(Default::default()),
    );
    let trojan = trojan_exit(port);
    let via = chain_node("via", &[&front, &trojan]);
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[via.clone(), front, trojan])
            .unwrap(),
    );
    let registry = production();
    let pool = Arc::new(crate::control::udp_endpoint::UdpEndpointPool::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let stats = Arc::new(crate::stats::StatsManager::new());
    let client: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    let path = source_path_in(&registry, &generation, &via, 53).unwrap();
    let mut attachments = Vec::new();
    for target in ["192.0.2.1:53", "192.0.2.2:53"] {
        let preparation = pool
            .prepare_source(
                &registry,
                Arc::clone(&generation),
                generation.get(&via.id).unwrap(),
                client,
                path,
                None,
                target.parse().unwrap(),
                None,
                Duration::from_secs(3),
                Arc::clone(&alive),
                Arc::clone(&stats),
                IpVersion::V4,
                false,
            )
            .await
            .unwrap();
        attachments.push(preparation.commit(&pool).await.unwrap());
    }
    assert_eq!(relay.requests.lock().len(), 1);
}

fn exit_group(name: &str, member: &Node, exit: &Node) -> honk_config::group::Group {
    honk_config::group::Group {
        name: name.into(),
        nodes: vec![member.id],
        exit: Some(exit.name.clone()),
        ..Default::default()
    }
}

async fn prepare_plan(
    handle: &ControlPlaneHandle,
    plan: crate::control::reload::ResolvedScorePlan,
    manager: &Arc<GroupManager>,
    generation: &Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    destination: &str,
) -> anyhow::Result<
    Option<(
        honk_outbound::group::OwnedTarget,
        super::dial::PreparedEndpoint,
    )>,
> {
    handle
        .prepare_udp_candidates(
            plan,
            None,
            "127.0.0.1:40000".parse().unwrap(),
            destination.parse().unwrap(),
            None,
            Duration::from_millis(500),
            tokio::time::Instant::now() + Duration::from_secs(5),
            generation,
            manager,
            #[cfg(feature = "native-api")]
            &super::super::observation::ConnectionObservation::default(),
        )
        .await
}

#[tokio::test]
async fn ordinary_udp_handoff_and_staged_mapping_use_the_committed_group_owner()
-> anyhow::Result<()> {
    use crate::control::connection::handoff::HandoffResult;
    use crate::control::tests::support::{canonical_socks5, control_plane};

    let front = canonical_socks5("entry", "127.0.0.1", 11081, None);
    let land = Node::from_share_link("trojan://password@127.0.0.1:11082#terminal")?;
    let chain = Node::chain_from_nodes("configured", &[&front, &land])?;
    let replacement = canonical_socks5("override", "127.0.0.1", 11083, None);
    let (chain_id, replacement_id) = (chain.id, replacement.id);
    let mut config = Config {
        groups: vec![
            Group {
                name: "north".into(),
                nodes: vec![chain.id],
                ..Default::default()
            },
            Group {
                name: "south".into(),
                nodes: vec![front.id],
                ..Default::default()
            },
        ],
        nodes: vec![front, land, chain, replacement],
        ..Default::default()
    };
    config.ensure_builtin_nodes();
    config.global.nfqueue_enable = false;
    let mut cp = control_plane(config.clone());
    let mode = Arc::new(parking_lot::RwLock::new(crate::mode::ModeState::new(
        "Rule", "",
    )));
    cp.set_mode_state(mode.clone());
    let handle = cp.spawn_handle();
    let base = OutboundIndex::UserBase as u8;
    let context = crate::group::ScoreSelectionContext::aggregate(
        SelectionNetwork::Udp,
        ProbeDomain::DataUdp,
        IpVersion::V4,
    );
    let check = async |generation| -> anyhow::Result<()> {
        let manager = handle.group_manager.read().clone();
        let name = {
            let owned = handle.config.read().await;
            let backend = handle.ebpf.read().await;
            assert_eq!(backend.routing_policy_generation(), generation);
            assert_eq!(
                handle.staged_udp_outbound(&owned, &manager, "north", OutboundConstraint::Group)?,
                base
            );
            assert_eq!(
                handle.staged_udp_outbound(&owned, &manager, "south", OutboundConstraint::Group)?,
                base + 1
            );
            handle.resolve_udp_handoff_group(backend.as_ref(), base, generation)?
        };
        assert_eq!(name, "north");
        let info = build_connection_info(
            None,
            "192.0.2.1:5443".parse()?,
            "192.0.2.2:53000".parse()?,
            "udp",
            None,
        );
        for (setting, must, expected_id, slot) in [
            ("Rule", false, chain_id, base),
            (
                "Global",
                false,
                replacement_id,
                OutboundIndex::ControlPlaneRouting as u8,
            ),
            ("Global", true, chain_id, base),
        ] {
            *mode.write() = crate::mode::ModeState::new(setting, "override");
            let handoff = HandoffResult::from(RoutingHandoffEntry {
                routing_generation: generation,
                result: RoutingResult {
                    outbound: base,
                    must: u8::from(must),
                    ..Default::default()
                },
                ..Default::default()
            });
            let mut route = handle
                .prepare_routing(
                    DialMode::Ip,
                    &info,
                    false,
                    Some(&handoff),
                    Some(name.as_str()),
                    #[cfg(feature = "native-api")]
                    false,
                )
                .await;
            let decision = handle
                .apply_mode_override(&mut route, OutboundConstraint::Group)
                .await;
            let active = handle.config.read().await;
            let plan = resolve_outbound_plan_for_target(
                &active,
                &manager,
                &decision.name,
                &context,
                decision.constraint,
            );
            assert!(matches!(plan.targets.as_slice(), [target] if target.node.id == expected_id));
            assert_eq!(
                handle.staged_udp_outbound(
                    &active,
                    &manager,
                    &decision.name,
                    decision.constraint
                )?,
                slot
            );
        }
        Ok(())
    };
    let generation = cp.ebpf.read().await.routing_policy_generation();
    check(generation).await?;
    config.groups.swap(0, 1);
    config.groups.push(Group {
        name: "third".into(),
        ..Default::default()
    });
    *cp.config.write().await = Arc::new(config.clone());
    cp.reload_group_manager().await?;
    check(generation).await?;
    assert_udp_handoff_generations(&handle, base + 2, "third", &[], &[generation]).await;
    {
        let manager = cp.group_manager.read();
        assert!(
            handle
                .staged_udp_outbound(&config, &manager, "third", OutboundConstraint::Group)
                .is_err()
        );
    }
    cp.ebpf
        .write()
        .await
        .inject_routing_fault(crate::ebpf::RoutingPushPhase::Root, 1)?;
    assert_eq!(
        cp.apply_runtime_config(config.clone(), Default::default(), &DrainTracker::new())
            .await,
        ReloadOutcome::Rejected
    );
    check(generation + 1).await?;
    config.groups.retain(|group| group.name != "north");
    *cp.config.write().await = Arc::new(config.clone());
    cp.reload_group_manager().await?;
    assert_udp_handoff_generations(&handle, base, "north", &[], &[generation + 1]).await;
    let manager = cp.group_manager.read();
    assert!(
        handle
            .staged_udp_outbound(&config, &manager, "north", OutboundConstraint::Group)
            .is_err()
    );
    let plan = resolve_outbound_plan_for_target(
        &config,
        &manager,
        "north",
        &context,
        OutboundConstraint::Group,
    );
    assert!(plan.targets.is_empty());
    Ok(())
}

const NEIGHBOR_SLOT: u8 = OutboundIndex::UserBase as u8;
const OWNER_SLOT: u8 = NEIGHBOR_SLOT + 1;

fn udp_slot_config() -> (Config, uuid::Uuid) {
    let front = crate::control::tests::support::canonical_socks5("entry", "127.0.0.1", 11081, None);
    let exit = Node::from_share_link("trojan://password@127.0.0.1:11082#terminal").unwrap();
    let chain = chain_node("configured", &[&front, &exit]);
    let chain_id = chain.id;
    let mut config = Config {
        groups: ["neighbor", "owner"]
            .into_iter()
            .map(|name| Group {
                name: name.into(),
                nodes: vec![front.id],
                ..Default::default()
            })
            .collect(),
        nodes: vec![front, exit, chain],
        ..Default::default()
    };
    config.ensure_builtin_nodes();
    config.global.nfqueue_enable = false;
    (config, chain_id)
}

async fn udp_routing_root(handle: &ControlPlaneHandle) -> (u32, u64) {
    let backend = handle.ebpf.read().await;
    (
        backend.active_routing_slot().unwrap(),
        backend.routing_policy_generation(),
    )
}

async fn apply_udp_slot_config(cp: &ControlPlane, config: &Config) {
    let outcome = cp
        .apply_runtime_config(config.clone(), Default::default(), &DrainTracker::new())
        .await;
    assert!(
        matches!(outcome, ReloadOutcome::Committed { .. }),
        "{outcome:?}"
    );
}

async fn reload_udp_slot_manager(cp: &ControlPlane, config: &Config) -> anyhow::Result<()> {
    *cp.config.write().await = Arc::new(config.clone());
    cp.reload_group_manager().await
}

async fn assert_udp_handoff_generations(
    handle: &ControlPlaneHandle,
    slot: u8,
    group: &str,
    accepted: &[u64],
    rejected: &[u64],
) {
    let backend = handle.ebpf.read().await;
    for &generation in accepted {
        let result = handle.resolve_udp_handoff_group(backend.as_ref(), slot, generation);
        assert_eq!(
            result.as_deref().ok(),
            Some(group),
            "slot {slot}, generation {generation}: {result:?}"
        );
    }
    for &generation in rejected {
        let result = handle.resolve_udp_handoff_group(backend.as_ref(), slot, generation);
        assert!(
            result.is_err(),
            "slot {slot}, generation {generation}: {result:?}"
        );
    }
}

#[tokio::test]
async fn udp_handoff_partial_promotion_uses_the_reassigned_owners_start() -> anyhow::Result<()> {
    use crate::control::tests::support::control_plane;

    let (mut config, chain) = udp_slot_config();
    let cp = control_plane(config.clone());
    let handle = cp.spawn_handle();
    let (_, initial) = udp_routing_root(&handle).await;

    config.groups[1].name = "replacement".into();
    apply_udp_slot_config(&cp, &config).await;
    let (root, owner_start) = udp_routing_root(&handle).await;
    assert!(owner_start > initial);

    config.groups[0].policy = GroupPolicy::Fallback;
    apply_udp_slot_config(&cp, &config).await;
    let fenced = owner_start + 1;
    assert_eq!(udp_routing_root(&handle).await, (root, fenced));
    assert_udp_handoff_generations(
        &handle,
        OWNER_SLOT,
        "replacement",
        &[0, fenced],
        &[fenced + 1],
    )
    .await;

    config.groups[1].nodes[0] = chain;
    reload_udp_slot_manager(&cp, &config).await?;
    assert_eq!(udp_routing_root(&handle).await, (root, fenced));
    assert_udp_handoff_generations(
        &handle,
        OWNER_SLOT,
        "replacement",
        &[owner_start, fenced],
        &[0, initial],
    )
    .await;
    assert_udp_handoff_generations(&handle, NEIGHBOR_SLOT, "neighbor", &[0, initial], &[]).await;
    Ok(())
}

#[tokio::test]
async fn udp_handoff_full_capability_flips_publish_fresh_roots() -> anyhow::Result<()> {
    use crate::control::tests::support::control_plane;

    let (mut flat, chain) = udp_slot_config();
    let cp = control_plane(flat.clone());
    let handle = cp.spawn_handle();
    let (root, initial) = udp_routing_root(&handle).await;
    let mut chained = flat.clone();
    chained.groups[1].nodes[0] = chain;
    *cp.config.write().await = Arc::new(chained.clone());
    apply_udp_slot_config(&cp, &chained).await;
    let (chain_root, chain_floor) = udp_routing_root(&handle).await;
    assert_eq!((chain_root, chain_floor), (root ^ 1, initial + 2));
    assert_udp_handoff_generations(
        &handle,
        OWNER_SLOT,
        "owner",
        &[chain_floor],
        &[0, initial, chain_floor - 1],
    )
    .await;

    cp.ebpf
        .write()
        .await
        .inject_routing_fault(crate::ebpf::RoutingPushPhase::Root, 1)?;
    assert_eq!(
        cp.apply_runtime_config(flat.clone(), Default::default(), &DrainTracker::new())
            .await,
        ReloadOutcome::Rejected
    );
    let rejected_fence = chain_floor + 1;
    assert_eq!(
        udp_routing_root(&handle).await,
        (chain_root, rejected_fence)
    );
    assert_udp_handoff_generations(
        &handle,
        OWNER_SLOT,
        "owner",
        &[chain_floor, rejected_fence],
        &[0, initial],
    )
    .await;

    chained.groups[0].policy = GroupPolicy::Fallback;
    flat.groups[0].policy = GroupPolicy::Fallback;
    apply_udp_slot_config(&cp, &chained).await;
    let unrelated_fence = rejected_fence + 1;
    assert_eq!(
        udp_routing_root(&handle).await,
        (chain_root, unrelated_fence)
    );
    assert_udp_handoff_generations(
        &handle,
        OWNER_SLOT,
        "owner",
        &[chain_floor, rejected_fence, unrelated_fence],
        &[0, initial],
    )
    .await;

    reload_udp_slot_manager(&cp, &flat).await?;
    assert_udp_handoff_generations(&handle, OWNER_SLOT, "owner", &[chain_floor], &[0, initial])
        .await;
    apply_udp_slot_config(&cp, &chained).await;
    let (restored_root, restored_floor) = udp_routing_root(&handle).await;
    assert_eq!(
        (restored_root, restored_floor),
        (chain_root ^ 1, unrelated_fence + 2)
    );
    assert_udp_handoff_generations(
        &handle,
        OWNER_SLOT,
        "owner",
        &[restored_floor],
        &[chain_floor, unrelated_fence],
    )
    .await;

    apply_udp_slot_config(&cp, &flat).await;
    let (flat_root, flat_floor) = udp_routing_root(&handle).await;
    assert_eq!(
        (flat_root, flat_floor),
        (restored_root ^ 1, restored_floor + 2)
    );
    assert_udp_handoff_generations(
        &handle,
        OWNER_SLOT,
        "owner",
        &[flat_floor],
        &[0, restored_floor, flat_floor - 1],
    )
    .await;

    flat.groups[1].name = "replacement".into();
    apply_udp_slot_config(&cp, &flat).await;
    let (_, replacement_floor) = udp_routing_root(&handle).await;
    assert_udp_handoff_generations(
        &handle,
        OWNER_SLOT,
        "replacement",
        &[replacement_floor],
        &[0, flat_floor],
    )
    .await;
    Ok(())
}

#[tokio::test]
async fn udp_handoff_affected_slot_reuse_requires_full_publication() -> anyhow::Result<()> {
    use crate::control::tests::support::control_plane;

    let (mut config, chain) = udp_slot_config();
    let flat = std::mem::replace(&mut config.groups[1].nodes[0], chain);
    let cp = control_plane(config.clone());
    let handle = cp.spawn_handle();
    let (root, initial) = udp_routing_root(&handle).await;
    assert_udp_handoff_generations(&handle, OWNER_SLOT, "owner", &[0, initial], &[initial + 1])
        .await;

    config.groups[0].policy = GroupPolicy::Fallback;
    apply_udp_slot_config(&cp, &config).await;
    let fenced = initial + 1;
    assert_eq!(udp_routing_root(&handle).await, (root, fenced));
    assert_udp_handoff_generations(&handle, OWNER_SLOT, "owner", &[0, initial, fenced], &[]).await;

    config.groups[1].nodes[0] = flat;
    reload_udp_slot_manager(&cp, &config).await?;
    assert_eq!(udp_routing_root(&handle).await, (root, fenced));
    assert_udp_handoff_generations(&handle, OWNER_SLOT, "owner", &[initial, fenced], &[0]).await;

    let mut absent = config.clone();
    absent.groups.pop().unwrap();
    let mut rebound = config.clone();
    rebound.groups[1].name = "replacement".into();
    for candidate in [&absent, &rebound, &config] {
        reload_udp_slot_manager(&cp, candidate).await?;
        assert_udp_handoff_generations(&handle, OWNER_SLOT, "owner", &[], &[fenced]).await;
    }

    cp.ebpf
        .write()
        .await
        .inject_routing_fault(crate::ebpf::RoutingPushPhase::Root, 1)?;
    assert_eq!(
        cp.apply_runtime_config(config.clone(), Default::default(), &DrainTracker::new())
            .await,
        ReloadOutcome::Rejected
    );
    let rejected_fence = fenced + 1;
    assert_eq!(udp_routing_root(&handle).await, (root, rejected_fence));
    assert_udp_handoff_generations(&handle, OWNER_SLOT, "owner", &[], &[rejected_fence]).await;

    apply_udp_slot_config(&cp, &config).await;
    let (restored_root, restored_floor) = udp_routing_root(&handle).await;
    assert_eq!(
        (restored_root, restored_floor),
        (root ^ 1, rejected_fence + 2)
    );
    assert_udp_handoff_generations(
        &handle,
        OWNER_SLOT,
        "owner",
        &[restored_floor],
        &[0, initial, rejected_fence],
    )
    .await;

    apply_udp_slot_config(&cp, &absent).await;
    let (_, removed) = udp_routing_root(&handle).await;
    assert_udp_handoff_generations(&handle, OWNER_SLOT, "owner", &[], &[removed]).await;
    apply_udp_slot_config(&cp, &config).await;
    let (_, reused) = udp_routing_root(&handle).await;
    assert_udp_handoff_generations(
        &handle,
        OWNER_SLOT,
        "owner",
        &[reused],
        &[0, restored_floor, removed],
    )
    .await;
    assert_udp_handoff_generations(
        &handle,
        NEIGHBOR_SLOT,
        "neighbor",
        &[0, initial, reused],
        &[],
    )
    .await;
    Ok(())
}

#[tokio::test]
async fn udp_handoff_partial_flat_aba_cannot_inherit_chain_owner_age() -> anyhow::Result<()> {
    use crate::control::tests::support::control_plane;

    let (mut config, chain) = udp_slot_config();
    let cp = control_plane(config.clone());
    let handle = cp.spawn_handle();
    let (root, initial) = udp_routing_root(&handle).await;

    let owner = config.groups.pop().unwrap();
    reload_udp_slot_manager(&cp, &config).await?;
    config.groups.push(owner);
    reload_udp_slot_manager(&cp, &config).await?;
    assert_udp_handoff_generations(&handle, OWNER_SLOT, "owner", &[0, initial], &[]).await;

    config.groups[1].nodes[0] = chain;
    reload_udp_slot_manager(&cp, &config).await?;
    assert_eq!(udp_routing_root(&handle).await, (root, initial));
    assert_udp_handoff_generations(&handle, OWNER_SLOT, "owner", &[], &[0, initial]).await;
    assert_udp_handoff_generations(&handle, NEIGHBOR_SLOT, "neighbor", &[0, initial], &[]).await;

    apply_udp_slot_config(&cp, &config).await;
    let (published, floor) = udp_routing_root(&handle).await;
    assert_eq!((published, floor), (root ^ 1, initial + 2));
    assert_udp_handoff_generations(&handle, OWNER_SLOT, "owner", &[floor], &[0, initial]).await;
    Ok(())
}

#[tokio::test]
async fn udp_handoff_missing_auxiliary_cannot_skip_the_cached_group_cutoff() -> anyhow::Result<()> {
    use crate::control::tests::support::test_dns_forwarder;
    use crate::ebpf::UdpFlowOwner;

    let (mut config, chain) = udp_slot_config();
    let source = "192.0.2.2".parse()?;
    let destination = "192.0.2.1".parse()?;
    let key = |port| build_tuples_key(destination, 5443, source, port, 17);
    let mut backend = crate::ebpf::mock::MockEbpfBackend::new();
    for (port, slot, published) in [
        (53000, OWNER_SLOT, true),
        (53001, OWNER_SLOT, false),
        (53002, NEIGHBOR_SLOT, true),
    ] {
        backend.udp_conn_state_store(
            &key(port),
            &ConnState {
                incarnation: u64::from(port),
                meta: RoutingMeta {
                    raw: u64::from(slot)
                        | if published {
                            ROUTING_META_FLAG_PUBLISHED
                        } else {
                            0
                        },
                },
                ..Default::default()
            },
        )?;
    }
    let cp = ControlPlane::new(
        config.clone(),
        Box::new(backend),
        Router::from_config(&config.routing)?,
        Arc::new(ProxyRegistry::default_resolver()?),
        DnsResolver::new(&config.dns)?,
        test_dns_forwarder(),
    )?;
    let handle = cp.spawn_handle();
    #[cfg(feature = "native-api")]
    let observation = ConnectionObservation::default();
    let lookup = async |port, incarnation| {
        handle
            .lookup_udp_handoff(
                &key(port),
                UdpFlowOwner::new(0, incarnation).unwrap(),
                #[cfg(feature = "native-api")]
                &observation,
            )
            .await
    };
    let (handoff, group) = lookup(53000, Some(53000)).await?;
    assert!(handoff.is_none());
    assert_eq!(group.as_ref().map(|group| group.name()), Some("owner"));

    config.groups[1].nodes[0] = chain;
    apply_udp_slot_config(&cp, &config).await;
    let refused = lookup(53000, Some(53000))
        .await
        .err()
        .expect("expired group proof");
    assert!(honk_outbound::proxy::is_packet_rejection(&refused));
    assert!(matches!(lookup(53001, Some(53001)).await?, (None, None)));
    let (handoff, group) = lookup(53002, Some(53002)).await?;
    assert!(handoff.is_none());
    assert_eq!(group.as_ref().map(|group| group.name()), Some("neighbor"));
    assert!(matches!(lookup(53003, None).await?, (None, None)));
    Ok(())
}

#[tokio::test]
async fn udp_handoff_revalidates_the_original_group_after_a_mode_replacement() -> anyhow::Result<()>
{
    use crate::control::connection::handoff::UdpGroupProof;
    use crate::control::tests::support::control_plane;

    let (mut config, chain) = udp_slot_config();
    let mut cp = control_plane(config.clone());
    let mode = Arc::new(parking_lot::RwLock::new(crate::mode::ModeState::new(
        "Global", "neighbor",
    )));
    cp.set_mode_state(Arc::clone(&mode));
    let handle = cp.spawn_handle();
    let capture = async |generation| {
        let backend = handle.ebpf.read().await;
        handle.capture_udp_group(backend.as_ref(), OWNER_SLOT, generation)
    };
    let revalidate = |proof| handle.revalidate_udp_group(&handle.group_manager.read(), proof);
    let choose = async |proof: &UdpGroupProof| {
        let mut route = RoutingDecision {
            outbound: proof.name().to_owned(),
            must: false,
            mark: None,
            matched_rule: None,
            reroute_by_sniffed_domain: false,
            #[cfg(feature = "native-api")]
            native_route: None,
        };
        handle
            .apply_mode_override(&mut route, OutboundConstraint::Group)
            .await
    };

    let original = capture(0).await?;
    let selected = choose(&original).await;
    assert_eq!(original.name(), "owner");
    assert_eq!(selected.name, "neighbor");
    assert!(matches!(selected.constraint, OutboundConstraint::Any));
    revalidate(&original)?;

    config.groups[1].name = "successor".into();
    apply_udp_slot_config(&cp, &config).await;
    assert!(revalidate(&original).is_err());
    let waiting = capture(0).await?;
    assert_eq!(waiting.name(), "successor");
    let selected = choose(&waiting).await;
    assert_eq!(selected.name, "neighbor");
    revalidate(&waiting)?;

    // A manager-only promotion can raise the cutoff without a kernel root switch.
    let root = udp_routing_root(&handle).await;
    config.groups[1].nodes[0] = chain;
    reload_udp_slot_manager(&cp, &config).await?;
    assert_eq!(udp_routing_root(&handle).await, root);
    assert!(revalidate(&waiting).is_err());
    let current = capture(root.1).await?;
    assert_eq!(current.name(), "successor");
    revalidate(&current)?;

    *mode.write() = crate::mode::ModeState::new("Direct", "");
    assert_eq!(choose(&current).await.name, "direct");
    revalidate(&current)?;
    assert_eq!(choose(&waiting).await.name, "direct");
    assert!(revalidate(&waiting).is_err());
    Ok(())
}

/// Uses the control plane's published manager and runtime for both plan and dial.
struct RouteFixture {
    control: ControlPlane,
    generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    nodes: Vec<Node>,
}

impl RouteFixture {
    fn new(nodes: Vec<Node>, groups: Vec<honk_config::group::Group>) -> Self {
        let control = crate::control::tests::support::control_plane(honk_config::Config {
            nodes: nodes.clone(),
            groups,
            ..Default::default()
        });
        let generation = control.runtime_registry.read().clone();
        Self {
            control,
            generation,
            nodes,
        }
    }

    async fn plan(
        handle: &ControlPlaneHandle,
        root: &str,
    ) -> (Arc<GroupManager>, crate::control::reload::ResolvedScorePlan) {
        let config = handle.config.read().await;
        let manager = handle.group_manager.read().clone();
        let plan = crate::control::reload::resolve_outbound_plan_for_target(
            &config,
            &manager,
            root,
            &crate::group::ScoreSelectionContext::aggregate(
                SelectionNetwork::Udp,
                ProbeDomain::DataUdp,
                IpVersion::V4,
            ),
            crate::control::reload::OutboundConstraint::Any,
        );
        (manager, plan)
    }

    async fn prepare(
        &self,
        handle: &ControlPlaneHandle,
        root: &str,
        destination: &str,
    ) -> anyhow::Result<
        Option<(
            honk_outbound::group::OwnedTarget,
            super::dial::PreparedEndpoint,
        )>,
    > {
        let (manager, plan) = Self::plan(handle, root).await;
        assert!(!plan.targets.is_empty());
        prepare_plan(handle, plan, &manager, &self.generation, destination).await
    }

    fn demoted(&self, handle: &ControlPlaneHandle) -> Vec<String> {
        self.nodes
            .iter()
            .filter(|node| {
                handle
                    .alive_set
                    .is_failure_demoted(node.id, ProbeDomain::DataUdp, IpVersion::V4)
            })
            .map(|node| node.name.clone())
            .collect()
    }
}

async fn holding_server() -> u16 {
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = server.accept().await {
            held.push(stream);
        }
    });
    port
}

fn socks5_hop(name: &str, port: u16) -> Node {
    exit_node(name, port, OutboundConfig::Socks5(Default::default()))
}

#[tokio::test]
async fn fifty_front_connection_refusals_disable_only_its_udp_carrier_role() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let front = socks5_hop("front", port);
    let land = trojan_exit(443);
    let group = exit_group("g", &front, &land);
    let hops = [front.id, land.id];
    let fixture = RouteFixture::new(vec![front, land], vec![group]);
    let handle = fixture.control.spawn_handle();
    // This fixture models an exit-only physical hop without a periodic probe registration.
    handle.alive_set.remove_node(hops[0]);
    let manager = handle.group_manager.read().clone();
    for _ in 0..50 {
        assert!(manager.udp_route_path_available(
            hops[0],
            &hops,
            ProbeDomain::DataUdp,
            IpVersion::V4
        ));
        let prepared = fixture.prepare(&handle, "g", "192.0.2.1:53").await;
        assert!(!matches!(prepared, Ok(Some(_))));
    }
    assert!(!manager.udp_route_path_available(hops[0], &hops, ProbeDomain::DataUdp, IpVersion::V4));
    assert!(manager.is_node_selectable_for_domain(hops[0], ProbeDomain::DataUdp, IpVersion::V4));
    assert!(manager.is_node_selectable_for_domain(hops[1], ProbeDomain::DataUdp, IpVersion::V4));
    assert!(manager.udp_route_path_available(hops[0], &hops, ProbeDomain::DataUdp, IpVersion::V6));
    assert!(fixture.demoted(&handle).is_empty());
}

#[tokio::test]
async fn unlocalized_tunneled_udp_setup_eof_is_health_neutral() {
    let refusing = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = refusing.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = refusing.accept().await {
            drop(stream);
        }
    });
    let relay = crate::test_support::socks5_relay().await;
    let front = socks5_hop("front", relay.addr.port());
    // EOF through the front does not identify which physical hop closed.
    let land = exit_node(
        "land",
        port,
        OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            password: Some("secret".into()),
            tls: honk_config::node::TlsOptions {
                enabled: true,
                sni: Some("land.example".into()),
                ..Default::default()
            },
            ..Default::default()
        }),
    );
    let group = exit_group("g", &front, &land);
    let fixture = RouteFixture::new(vec![front, land], vec![group]);
    let handle = fixture.control.spawn_handle();
    for _ in 0..2 {
        let prepared = fixture.prepare(&handle, "g", "192.0.2.1:53").await;
        assert!(!matches!(prepared, Ok(Some(_))));
    }
    assert!(fixture.demoted(&handle).is_empty());
}

/// A bound transport supplies no UDP reply proof until a datagram arrives.
#[tokio::test]
async fn route_udp_preparation_does_not_credit_any_hop() {
    let outer = crate::test_support::socks5_relay().await;
    let inner = crate::test_support::socks5_relay().await;
    let front = socks5_hop("front", outer.addr.port());
    let mid = socks5_hop("mid", inner.addr.port());
    let land = trojan_exit(holding_server().await);
    let inner = exit_group("inner", &front, &mid);
    let outer = honk_config::group::Group {
        name: "g".into(),
        groups: vec!["inner".into()],
        exit: Some(land.name.clone()),
        ..Default::default()
    };
    let fixture = RouteFixture::new(vec![front, mid, land], vec![inner, outer]);
    let handle = fixture.control.spawn_handle();
    let fail_all = || {
        for node in &fixture.nodes {
            crate::control::report_dial_failure_if_current(
                &fixture.generation,
                &handle.alive_set,
                node.id,
                ProbeDomain::DataUdp,
                IpVersion::V4,
            );
        }
    };
    fail_all();
    let prepared = fixture.prepare(&handle, "g", "192.0.2.1:53").await;
    assert!(matches!(prepared, Ok(Some(_))), "{:?}", prepared.err());
    fail_all();
    assert_eq!(fixture.demoted(&handle), ["front", "mid", "trojan"]);
}

/// A route's UDP is a flow of its own even when its leaf could share a
/// source: the source pool keys by the generation's nodes, not by routes.
#[tokio::test]
async fn group_exit_routes_never_get_a_shared_source() {
    let relay = crate::test_support::socks5_relay().await;
    let front = socks5_hop("front", relay.addr.port());
    let land = trojan_exit(holding_server().await);
    let group = exit_group("g", &front, &land);
    let fixture = RouteFixture::new(vec![front.clone(), land], vec![group]);
    assert!(source_path(&production(), &front, 53).is_some());
    let handle = fixture.control.spawn_handle();
    let (_, prepared) = fixture
        .prepare(&handle, "g", "192.0.2.1:53")
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        prepared.transport,
        super::dial::PreparedEndpointTransport::Flow(_)
    ));
}

#[tokio::test]
async fn cold_udp_tries_distinct_routes_and_keeps_the_winner_path() {
    let refusing = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_port = refusing.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = refusing.accept().await {
            drop(stream);
        }
    });
    let relay = crate::test_support::socks5_relay().await;
    let front = socks5_hop("front", relay.addr.port());
    let mut bad = trojan_exit(bad_port);
    bad.name = "refusing".into();
    let tls = &mut bad.trojan_mut().unwrap().tls;
    tls.enabled = true;
    tls.sni = Some("land.example".into());
    bad.id = bad.derive_id();
    let good = trojan_exit(holding_server().await);
    let groups = vec![
        exit_group("first", &front, &bad),
        exit_group("duplicate", &front, &bad),
        exit_group("winner", &front, &good),
    ];
    let requested = [
        bad.address.parse::<SocketAddr>().unwrap(),
        good.address.parse::<SocketAddr>().unwrap(),
    ];
    let fixture = RouteFixture::new(vec![front, bad, good], groups);
    let handle = fixture.control.spawn_handle();
    let (manager, mut plan) = RouteFixture::plan(&handle, "first").await;
    plan.mode = crate::group::SelectionPlanMode::ColdUrlTest;
    for root in ["duplicate", "winner"] {
        let (_, mut other) = RouteFixture::plan(&handle, root).await;
        plan.targets.append(&mut other.targets);
        plan.feedback.append(&mut other.feedback);
        plan.selection_chains.append(&mut other.selection_chains);
        plan.final_owners.append(&mut other.final_owners);
    }
    assert_eq!(plan.targets[0].key(), plan.targets[1].key());
    let expected = plan.targets[2].key();
    let selection_chains = plan.selection_chains.clone();
    let (target, prepared) =
        prepare_plan(&handle, plan, &manager, &fixture.generation, "192.0.2.1:53")
            .await
            .unwrap()
            .unwrap();
    assert_eq!(target.key(), expected);
    assert_eq!(prepared.chain, selection_chains[2]);
    let requests = relay.requests.lock();
    assert_eq!(requests.len(), requested.len());
    assert!(requested.iter().all(|peer| requests.contains(peer)));
}

#[tokio::test]
async fn selected_block_after_ready_prevents_the_first_trojan_datagram() {
    use crate::control::udp_endpoint::EndpointReservation;
    use tokio::io::AsyncReadExt;

    let peer = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = crate::test_support::socks5_relay().await;
    let front = socks5_hop("front", relay.addr.port());
    let land = trojan_exit(peer.local_addr().unwrap().port());
    let block = honk_config::Config::builtin_block_node();
    let group = honk_config::group::Group {
        nodes: vec![front.id, block.id],
        policy: honk_config::group::GroupPolicy::Selector,
        ..exit_group("g", &front, &land)
    };
    let fixture = RouteFixture::new(vec![front, land, block], vec![group]);
    let handle = fixture.control.spawn_handle();
    let dst = "192.0.2.1:5000".parse().unwrap();
    let client = "127.0.0.1:40000".parse().unwrap();
    let (_, prepared) = fixture
        .prepare(&handle, "g", "192.0.2.1:5000")
        .await
        .unwrap()
        .unwrap();
    let PreparedEndpointTransport::Flow(transport) = prepared.transport else {
        panic!("expected routed flow");
    };
    let transport = transport.commit().await.unwrap();
    let mut endpoint = UdpEndpoint::new_scored(
        transport,
        dst,
        false,
        fixture.nodes[1].id,
        IpVersion::V4,
        prepared.reporter,
    );
    endpoint.set_traffic_evidence(prepared.evidence.clone());
    let endpoint = Arc::new(endpoint);
    let permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let EndpointReservation::Initializing(mut lease) =
        handle
            .udp_pool
            .reserve_or_enqueue(client, dst, b"no replay", permit, &handle.stats)
    else {
        panic!("fresh lease");
    };
    assert!(lease.bind_selected(fixture.nodes[1].id, prepared.evidence));
    let mut driver = handle.udp_pool.spawn_driver(
        client,
        dst,
        lease.generation(),
        lease.decision_token(),
        Arc::clone(&endpoint),
        lease.take_queue_receiver().unwrap(),
        Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
        Arc::clone(&handle.alive_set),
        Arc::clone(&handle.stats),
        handle
            .stats
            .outbound_tracker("g", crate::stats::OutboundKind::Group),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease.commit_ready(Arc::clone(&endpoint)));
    handle
        .group_manager
        .read()
        .set_selector_choice("g", "block", crate::group::SelectorNetworks::Udp)
        .unwrap();
    driver.start(lease.take_first().unwrap()).unwrap();
    drop(lease);
    let error = driver.wait_first_ack().await.unwrap_err();
    assert_eq!(
        crate::group::ScoreOutcome::from_io_error(&error),
        crate::group::ScoreOutcome::Cancelled
    );
    let (mut observed, _) = peer.accept().await.unwrap();
    let mut header = [0; 68];
    observed.read_exact(&mut header).await.unwrap();
    assert_eq!(header[58], 3);
    drop(endpoint);
    assert!(handle.udp_pool.shutdown().await.joined);
    let mut frame = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), observed.read_to_end(&mut frame))
        .await
        .unwrap()
        .unwrap();
    assert!(frame.is_empty());
    assert_eq!(relay.requests.lock().len(), 1);
}

/// The framing node owns the UDP/443 decision even when the TCP prefix has a different policy.
#[cfg(feature = "rprx")]
#[tokio::test]
async fn a_route_checks_the_port_policy_of_its_exit() {
    use honk_config::node::{Udp443Policy, VlessConfig, VlessMultiplex};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let leaf = exit_node(
        "leaf",
        listener.local_addr().unwrap().port(),
        OutboundConfig::Vless(VlessConfig {
            uuid: Some("00000000-0000-4000-8000-000000000001".into()),
            multiplex: VlessMultiplex::xray(-1, 1, Udp443Policy::Reject),
            ..Default::default()
        }),
    );
    assert!(leaf.supports_tunneled_dial());
    assert!(!honk_outbound::descriptor::udp_target_allowed(&leaf, 443));
    let land = trojan_exit(holding_server().await);
    let group = exit_group("g", &leaf, &land);
    let collapsed = exit_group("collapsed", &leaf, &leaf);
    let fixture = RouteFixture::new(vec![land, leaf], vec![group, collapsed]);
    let handle = fixture.control.spawn_handle();
    let refused = fixture
        .prepare(&handle, "collapsed", "192.0.2.1:443")
        .await
        .err()
        .expect("collapsed native UDP/443 policy");
    assert_eq!(
        honk_outbound::proxy::packet_rejection(&refused),
        Some(honk_outbound::proxy::PacketRejection::Policy)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    let prepared = fixture.prepare(&handle, "g", "192.0.2.1:443").await;
    assert!(matches!(prepared, Ok(Some(_))), "{:?}", prepared.err());
    assert!(
        tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .is_ok()
    );
}
