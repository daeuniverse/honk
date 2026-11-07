use super::*;

pub(super) fn unsynchronized_core(
    authority: RoutingAuthority,
    ingresses: &[Ingress],
    budget: &Arc<MemoryBudget>,
    table: Option<Firewall>,
) -> RoutedCore {
    RoutedCore {
        authority,
        core: CoreForward::new(ingresses, Arc::clone(budget), 2).unwrap(),
        fib: Fib::new(budget, ingresses[0].namespace).unwrap(),
        routes: Vec::new(),
        address_generation: 1,
        firewall: table.unwrap_or_else(|| Firewall::new_history(Arc::clone(budget), 2, 0).unwrap()),
        ingress_roles: Vec::new(),
        reassembly_outputs: reassembly::Outputs::new(budget).unwrap(),
        pending_reassembly_error: None,
        reassembly_poll_pending: false,
        counters: RefusalCounters::default(),
        _role_charge: budget.reserve(0).unwrap(),
        _charge: budget.reserve(0).unwrap(),
        budget: Arc::clone(budget),
    }
}

#[test]
fn fib_prohibit_authorizes_admin_error_without_forwarding_authority() {
    assert!(permits_admin_error(&Resolution::Error(
        TransitError::AdminProhibited
    )));
    for input in [
        Resolution::Drop,
        Resolution::LocalInput,
        Resolution::Error(TransitError::HostUnreachable),
    ] {
        assert!(!permits_admin_error(&input));
    }
}

#[tokio::test]
async fn expired_reverse_tcp_is_silent_and_new_endpoint_is_admitted_without_retire() {
    use honk_netstack::wire::{self, tcp};
    use std::{os::fd::AsFd, time::Duration};

    let mut config = honk_config::Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.groups.push(honk_config::group::Group {
        name: "proxy".into(),
        nodes: config
            .nodes
            .iter()
            .filter(|node| node.name == "direct")
            .map(|node| node.id)
            .collect(),
        ..Default::default()
    });
    config.routing.default_outbound = "proxy".into();
    let router = crate::routing::Router::from_config(&config.routing).unwrap();
    let plane = crate::control::tests::support::control_plane(config);
    *plane.router.write().await = router;
    let authority = plane
        .core_forward_policy(Execution::MixedEndpoints)
        .await
        .unwrap();
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    let ingress = Ingress {
        scope: honk_datapath::ScopeId::allocate().unwrap(),
        namespace: socket_namespace(socket.as_fd()).unwrap(),
        ifindex: 2,
        attachment: 1,
        mark: MarkProvenance::BeforeSkb,
    };
    let reply = Ingress {
        ifindex: 3,
        ..ingress
    };
    let budget = MemoryBudget::new(16 << 20);
    let mut core = unsynchronized_core(authority, &[ingress, reply], &budget, None);
    for ipv6 in [false, true] {
        let source = if ipv6 { "2001:db8::1" } else { "192.0.2.1" }
            .parse()
            .unwrap();
        let destination = if ipv6 { "2001:db8::2" } else { "198.51.100.1" }
            .parse()
            .unwrap();
        let old = Instant::now() - Duration::from_secs(7441);
        let mut bytes = [0; 80];
        let mut header = tcp::Header {
            src_port: 40000,
            dst_port: 443,
            seq: 10,
            ack: 0,
            flags: tcp::SYN,
            window: 4096,
            urgent: 0,
            options: Default::default(),
        };
        let len = tcp::emit_packet(&mut bytes, source, destination, &header, [&[], &[]]).unwrap();
        let packet = core
            .core
            .receive(ingress, old, &bytes[..len])
            .unwrap()
            .unwrap();
        let original = packet.query();
        let route = Route {
            generation: 1,
            ifindex: reply.ifindex,
            l2: honk_datapath::forward::LinkPath::untagged(reply.ifindex),
            mtu: 1500,
            next_hop: destination,
            preferred_source: None,
            source_mac: [2; 6],
            destination_mac: [4; 6],
        };
        let Prepared::Forward(output) = core.core.prepare(packet, route, 1, old).unwrap() else {
            panic!("initial Core owner missing");
        };
        let held = output.lease();
        drop(output);
        assert!(
            core.core.retains(original, Instant::now()),
            "actual output retains the old executor past idle expiry"
        );
        drop(held);
        assert!(core.core.retains(original, old));
        assert!(!core.core.retains(original, Instant::now()));
        assert!(
            core.has_maintenance(),
            "the expired directory entry has not been swept"
        );
        header.src_port = 443;
        header.dst_port = 40000;
        for flags in [tcp::ACK, tcp::FIN | tcp::ACK, tcp::RST, tcp::SYN | tcp::ACK] {
            header.flags = flags;
            let len =
                tcp::emit_packet(&mut bytes, destination, source, &header, [&[], &[]]).unwrap();
            assert!(matches!(
                core.forward_cached(
                    reply,
                    wire::PacketView::from_slice(&bytes[..len]),
                    None,
                    Instant::now(),
                    |_, _| -> io::Result<Option<()>> { panic!("stale reverse traffic reached TX") }
                )
                .unwrap(),
                CachedDecision::Drop
            ));
            for segmented in [false, true] {
                let now = Instant::now();
                let packet = if segmented {
                    core.receive_segments(reply, now, &[&bytes[..17], &bytes[17..len]])
                } else {
                    core.receive(reply, now, &bytes[..len])
                }
                .unwrap()
                .unwrap();
                assert!(matches!(
                    core.decide(packet, None, now).await.unwrap(),
                    Decision::Drop
                ));
            }
        }
        header.flags = tcp::SYN | 0xc0;
        let len = tcp::emit_packet(&mut bytes, destination, source, &header, [&[], &[]]).unwrap();
        let now = Instant::now();
        assert!(matches!(
            core.forward_cached(
                reply,
                wire::PacketView::from_slice(&bytes[..len]),
                None,
                now,
                |_, _| -> io::Result<Option<()>> { panic!("new Endpoint SYN reached Core TX") }
            )
            .unwrap(),
            CachedDecision::Cold
        ));
        let packet = core.receive(reply, now, &bytes[..len]).unwrap().unwrap();
        let Decision::Endpoint(_, admission) = core.decide(packet, None, now).await.unwrap() else {
            panic!("a fresh SYN must be able to reuse the expired tuple");
        };
        assert_eq!(admission.into_snapshot().decision.outbound, "proxy");
    }
}

#[tokio::test]
async fn endpoint_handoff_retains_matched_rule_and_native_generation() {
    use std::os::fd::AsFd;
    let mut config = honk_config::parser::parse_dae_config(
        "global { dial_mode: ip }\nrouting { dport(80) -> block\n dport(443) -> proxy\n fallback: direct }",
    ).unwrap();
    config.ensure_builtin_nodes();
    config.groups.push(honk_config::group::Group {
        name: "proxy".into(),
        nodes: config
            .nodes
            .iter()
            .filter(|node| node.name == "direct")
            .map(|node| node.id)
            .collect(),
        ..Default::default()
    });
    let router = crate::routing::Router::from_config(&config.routing).unwrap();
    #[allow(unused_mut)]
    let mut plane = crate::control::tests::support::control_plane(config);
    *plane.router.write().await = router;
    #[cfg(feature = "native-api")]
    let native = {
        let native = crate::native_api::observation::NativeObservation::attach(&mut plane).await;
        native.attach_for_test();
        native
    };
    let authority = plane
        .core_forward_policy(Execution::MixedEndpoints)
        .await
        .unwrap();
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    let ingress = Ingress {
        scope: honk_datapath::ScopeId::allocate().unwrap(),
        namespace: socket_namespace(socket.as_fd()).unwrap(),
        ifindex: 2,
        attachment: 1,
        mark: MarkProvenance::BeforeSkb,
    };
    let budget = MemoryBudget::new(16 << 20);
    let mut core = unsynchronized_core(authority, &[ingress], &budget, None);
    let mut bytes = [0; 64];
    let source = "192.0.2.2:40000".parse().unwrap();
    let destination = "198.51.100.2:443".parse().unwrap();
    let len =
        honk_netstack::wire::udp::emit_packet(&mut bytes, source, destination, b"rule").unwrap();
    let now = Instant::now();
    let packet = core.receive(ingress, now, &bytes[..len]).unwrap().unwrap();
    let Decision::Endpoint(_, admission) = core.decide(packet, None, now).await.unwrap() else {
        panic!("matching group route must enter Endpoint");
    };
    #[allow(unused_mut)]
    let mut snapshot = admission.into_snapshot();
    assert_eq!(snapshot.decision.outbound, "proxy");
    assert_eq!(
        snapshot.decision.matched_rule,
        Some(("dport".into(), "443".into()))
    );
    assert!(snapshot.final_before_sniff());
    #[cfg(feature = "native-api")]
    let captured = snapshot.native.as_ref().unwrap().0;
    *plane.router.write().await = crate::routing::Router::new(&[], "block").unwrap();
    plane.diagnostics.write().generation += 1;
    assert_eq!(
        snapshot.decision.matched_rule,
        Some(("dport".into(), "443".into()))
    );
    #[cfg(feature = "native-api")]
    {
        use crate::control::connection::observation::ConnectionObservation;
        let mut observation = ConnectionObservation::begin(
            Some(&native.core),
            crate::observe::vocab::Network::Udp,
            source,
            destination,
        );
        let flow = Arc::clone(observation.flow().unwrap());
        observation.routed(&mut snapshot.decision);
        let detail = native.core.flows.test_detail(flow.id());
        let route = detail["trace"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|step| step["stage"] == "route")
            .expect("captured route reached flow recorder");
        assert_eq!(
            route["generation_id"],
            format!("{}:{captured}", native.core.instance_id)
        );
        assert_eq!(route["data"]["plane"], "userspace");
        assert_eq!(route["data"]["outbound"], "proxy");
        assert_eq!(route["data"]["input"]["dst_port"], 443);
        assert!(
            route["data"]["rule_id"]
                .as_str()
                .unwrap()
                .ends_with(":rule:1")
        );
    }
}

#[tokio::test]
async fn received_native_quote_pins_overflow_before_old_id_retirement() {
    use honk_netstack::wire;
    use std::{os::fd::AsFd, time::Duration};
    let mut config = honk_config::Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    let plane = crate::control::tests::support::control_plane(config);
    let authority = plane
        .core_forward_policy(Execution::MixedEndpoints)
        .await
        .unwrap();
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    let ingress = Ingress {
        scope: honk_datapath::ScopeId::allocate().unwrap(),
        namespace: socket_namespace(socket.as_fd()).unwrap(),
        ifindex: 2,
        attachment: 1,
        mark: MarkProvenance::BeforeSkb,
    };
    let reply = Ingress {
        ifindex: 3,
        ..ingress
    };
    let budget = MemoryBudget::new(16 << 20);
    let table = Firewall::new_history(budget.clone(), 2, 1).unwrap();
    let mut core = unsynchronized_core(authority, &[ingress, reply], &budget, Some(table));
    let now = Instant::now();
    let mut original = [0; 64];
    let len = wire::udp::emit_packet(
        &mut original,
        "192.0.2.2:40000".parse().unwrap(),
        "198.51.100.2:18080".parse().unwrap(),
        b"native",
    )
    .unwrap();
    original[4..8].fill(0);
    original[10..12].fill(0);
    let checksum = wire::checksum::checksum(&original[..20]);
    original[10..12].copy_from_slice(&checksum.to_be_bytes());
    let facts = Facts::parse(&original[..len]).unwrap();
    let pressure = budget.reserve(budget.limit() - budget.used()).unwrap();
    let native = core
        .firewall
        .observe_plain(ingress, reply, facts.tuple, 0, now)
        .unwrap();
    assert!(
        !native.is_exact(),
        "real budget refusal must take the fixed overflow owner"
    );
    drop(native);
    drop(pressure);
    core.firewall.expire(now);
    let mut error = [0; 56];
    wire::emit_ip_header(
        &mut error,
        "198.51.100.254".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        wire::PROTO_ICMP,
        36,
    )
    .unwrap();
    error[20] = 3;
    error[21] = 1;
    error[28..].copy_from_slice(&original[..28]);
    let checksum = wire::checksum::checksum(&error[20..]);
    error[22..24].copy_from_slice(&checksum.to_be_bytes());
    let received_at = now + Duration::from_secs(149);
    let packet = core.receive(reply, received_at, &error).unwrap().unwrap();
    let admitted_at = now + Duration::from_millis(150_500);
    assert!(admitted_at < packet.deadline());
    core.firewall.expire(admitted_at);
    let binding = core
        .firewall
        .admit(Admission {
            ingress,
            reply_ingress: reply,
            facts: &facts,
            dnat: None,
            snat: SourceNat::Snat {
                address: "203.0.113.1".parse().unwrap(),
                ports: None,
            },
            egress: None,
            received_at: admitted_at,
            now: admitted_at,
        })
        .unwrap();
    binding.rewrite(&mut original[..len], false).unwrap();
    wire::PacketView::from_slice(&original[..len])
        .validate_transport()
        .unwrap();
    assert_ne!(
        u16::from_be_bytes([original[4], original[5]]),
        0,
        "a completed quote must exclude the old raw ID through its queued/CQ ownership"
    );
    drop(packet);
}

#[tokio::test]
async fn blocked_bound_nat_packets_neither_allocate_ids_nor_renew_bindings() {
    use honk_netstack::wire;
    use std::{os::fd::AsFd, time::Duration};

    let mut config = honk_config::Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.routing.default_outbound = "block".into();
    let plane = crate::control::tests::support::control_plane(config);
    *plane.router.write().await = crate::routing::Router::new(&[], "block").unwrap();
    let authority = plane
        .core_forward_policy(Execution::MixedEndpoints)
        .await
        .unwrap();
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    let ingress = Ingress {
        scope: honk_datapath::ScopeId::allocate().unwrap(),
        namespace: socket_namespace(socket.as_fd()).unwrap(),
        ifindex: 2,
        attachment: 1,
        mark: MarkProvenance::BeforeSkb,
    };
    let reply_ingress = Ingress {
        ifindex: 3,
        ..ingress
    };
    let budget = MemoryBudget::new(128 << 20);
    let now = Instant::now();
    let mut bytes = [0; 64];
    let length = wire::udp::emit_packet(
        &mut bytes,
        "192.0.2.2:41000".parse().unwrap(),
        "198.51.100.2:18080".parse().unwrap(),
        b"blocked",
    )
    .unwrap();
    bytes[6..8].fill(0);
    bytes[10..12].fill(0);
    let checksum = wire::checksum::checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    let mut table = Firewall::new(Arc::clone(&budget), 2, 1).unwrap();
    let witness = table
        .admit(Admission {
            ingress,
            reply_ingress,
            facts: &Facts::parse(&bytes[..length]).unwrap(),
            dnat: None,
            snat: SourceNat::Snat {
                address: "203.0.113.1".parse().unwrap(),
                ports: None,
            },
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    let mut core = unsynchronized_core(authority, &[ingress, reply_ingress], &budget, Some(table));
    let baseline = budget.used();
    for segmented in [false, true] {
        let received_at = now + Duration::from_secs(10);
        let packet = if segmented {
            core.receive_segments(ingress, received_at, &[&bytes[..7], &bytes[7..length]])
        } else {
            core.receive(ingress, received_at, &bytes[..length])
        }
        .unwrap()
        .unwrap();
        assert!(matches!(
            core.decide(packet, None, received_at).await.unwrap(),
            Decision::Drop
        ));
        assert_eq!(
            budget.used(),
            baseline,
            "blocked RX must not quarantine another NAT ID"
        );
    }
    core.firewall.expire(now + Duration::from_secs(120));
    assert!(
        !witness.is_active(),
        "blocked RX must not refresh idle retention"
    );
}

#[tokio::test]
async fn completing_related_reassembly_pins_identity_before_pending_keys_disappear() {
    use honk_netstack::wire;
    use std::{os::fd::AsFd, time::Duration};

    let mut config = honk_config::Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    let plane = crate::control::tests::support::control_plane(config);
    let authority = plane
        .core_forward_policy(Execution::MixedEndpoints)
        .await
        .unwrap();
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    let ingress = Ingress {
        scope: honk_datapath::ScopeId::allocate().unwrap(),
        namespace: socket_namespace(socket.as_fd()).unwrap(),
        ifindex: 2,
        attachment: 1,
        mark: MarkProvenance::BeforeSkb,
    };
    let reply_ingress = Ingress {
        ifindex: 3,
        ..ingress
    };
    let budget = MemoryBudget::new(128 << 20);
    let now = Instant::now();
    let mut request = [0; 64];
    let len = wire::udp::emit_packet(
        &mut request,
        "192.0.2.2:41000".parse().unwrap(),
        "198.51.100.2:18080".parse().unwrap(),
        b"quote",
    )
    .unwrap();
    let atomic = request[..len].to_vec();
    request[6..8].fill(0);
    request[10..12].fill(0);
    let checksum = wire::checksum::checksum(&request[..20]);
    request[10..12].copy_from_slice(&checksum.to_be_bytes());
    let mut table = Firewall::new(Arc::clone(&budget), 2, 1).unwrap();
    let binding = table
        .admit(Admission {
            ingress,
            reply_ingress,
            facts: &Facts::parse(&request[..len]).unwrap(),
            dnat: None,
            snat: SourceNat::Snat {
                address: "203.0.113.1".parse().unwrap(),
                ports: None,
            },
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    binding.rewrite(&mut request[..len], false).unwrap();
    drop(binding);
    table.expire(now);
    drop(
        table
            .lookup(
                ingress,
                &Facts::parse(&atomic).unwrap(),
                now + Duration::from_secs(110),
            )
            .unwrap()
            .unwrap(),
    );
    let mut error = [0; 56];
    wire::emit_ip_header(
        &mut error,
        "198.51.100.254".parse().unwrap(),
        "203.0.113.1".parse().unwrap(),
        wire::PROTO_ICMP,
        36,
    )
    .unwrap();
    error[20] = 3;
    error[21] = 1;
    error[28..].copy_from_slice(&request[..28]);
    let checksum = wire::checksum::checksum(&error[20..]);
    error[22..24].copy_from_slice(&checksum.to_be_bytes());
    let mut core = unsynchronized_core(authority, &[ingress, reply_ingress], &budget, Some(table));
    for (offset, end, more) in [(0usize, 16usize, true), (16, 36, false)] {
        let mut fragment = error[..20].to_vec();
        fragment.extend_from_slice(&error[20 + offset..20 + end]);
        let len = fragment.len() as u16;
        fragment[2..4].copy_from_slice(&len.to_be_bytes());
        let flags = (offset / 8) as u16 | if more { 0x2000 } else { 0 };
        fragment[6..8].copy_from_slice(&flags.to_be_bytes());
        fragment[10..12].fill(0);
        let checksum = wire::checksum::checksum(&fragment[..20]);
        fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
        let at = now + Duration::from_secs(if more { 119 } else { 121 });
        let packet = core.receive(reply_ingress, at, &fragment).unwrap();
        if more {
            assert!(packet.is_none());
        } else {
            let packet = packet.expect("completion still owns the original NAT identity");
            assert!(packet.is_reassembled());
            assert!(packet.binding().is_some());
            assert!(!packet.binding().unwrap().is_authorized());
            assert!(core.fragments_quiescent());
        }
    }
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespace"]
async fn firewall_capacity_refusal_keeps_packet_owner_alive() {
    use crate::routing::{GeoRequirements, GeoSourceSet, Router, SharedMatchers};
    let config = honk_config::parser::parse_dae_config(
        "global { dial_mode: ip }\ndatapath {\n backend: xdp\n direct: core\n interface { dut0: lan\n dut1: wan }\n firewall {\n original { default: allow }\n forward { default: allow }\n }\n}",
    ).unwrap();
    let sources = GeoSourceSet::load(&GeoRequirements::for_forwarding(&config));
    let mut router = Router::from_config(&config.routing).unwrap();
    router
        .bind_firewall(&config, None, &sources, &mut SharedMatchers::default())
        .unwrap();
    let plane = crate::control::tests::support::control_plane(config);
    *plane.router.write().await = router;
    let authority = plane
        .core_forward_policy(Execution::MixedEndpoints)
        .await
        .unwrap();
    let ingresses = smoke_ingresses();
    let ingress = ingresses[0];
    let budget = MemoryBudget::new(128 << 20);
    let mut core = RoutedCore::new(
        authority,
        &ingresses,
        Requirements {
            execution: Execution::MixedEndpoints,
            nat: false,
            native_continuation: false,
            kernel_firewall: false,
            qdisc: false,
            skb_classification: false,
        },
        budget.clone(),
    )
    .unwrap();
    core.set_ingress_roles(&[
        (ingress, InterfaceRole::Lan),
        (ingresses[1], InterfaceRole::Wan),
    ])
    .unwrap();
    let baseline = budget.used();
    let mut bytes = [0u8; 64];
    let length = honk_netstack::wire::udp::emit_packet(
        &mut bytes,
        "192.0.2.2:41000".parse().unwrap(),
        "198.51.100.2:18080".parse().unwrap(),
        b"capacity",
    )
    .unwrap();
    let packet = core
        .receive(ingress, Instant::now(), &bytes[..length])
        .unwrap()
        .unwrap();
    let pressure = budget.reserve(budget.limit() - budget.used()).unwrap();
    assert!(matches!(
        core.decide(packet, None, Instant::now()).await.unwrap(),
        Decision::Drop
    ));
    assert!(core.authority.admitting());
    assert!(core.firewall.is_empty());
    assert_eq!(core.counters().nat_capacity, 1);
    drop(pressure);
    assert_eq!(budget.used(), baseline);
    let packet = core
        .receive(ingress, Instant::now(), &bytes[..length])
        .unwrap()
        .unwrap();
    assert!(matches!(
        core.decide(packet, None, Instant::now()).await.unwrap(),
        Decision::Forward(Prepared::Forward(_), _)
    ));
    assert!(!core.firewall.is_empty());
    assert_eq!(core.counters().nat_capacity, 1);
}

#[test]
fn routed_only_rejects_implicit_requirements_and_marked_or_proxy_policy() {
    let explicit = r#"{"execution":"routed-only","nat":false,"native_continuation":false,"kernel_firewall":false,"qdisc":false,"skb_classification":false}"#;
    let mut requirements: Requirements = serde_json::from_str(explicit).unwrap();
    requirements.validate().unwrap();
    requirements.nat = true;
    requirements.validate().unwrap();
    requirements.kernel_firewall = true;
    assert!(requirements.validate().is_err());
    assert!(serde_json::from_str::<Requirements>("{}").is_err());
    let mut routing = RoutingConfig::default();
    validate_policy(&routing).unwrap();
    routing.default_mark = 1;
    assert!(validate_policy(&routing).is_err());
    routing.default_mark = 0;
    routing.default_outbound = "proxy".into();
    assert!(validate_policy(&routing).is_err());
}

#[test]
fn final_execution_uses_shared_mode_and_preserves_must_and_block() {
    let mut config = honk_config::Config::default();
    config.ensure_builtin_nodes();
    let query = RouteQuery {
        ingress: Ingress {
            scope: honk_datapath::ScopeId::HOST,
            namespace: 1,
            ifindex: 2,
            attachment: 1,
            mark: MarkProvenance::BeforeSkb,
        },
        source: "192.0.2.1".parse().unwrap(),
        destination: "198.51.100.1".parse().unwrap(),
        protocol: 6,
        ports: Some((40000, 443)),
        traffic_class: 0,
    };
    for (state, routed, must, expected) in [
        (
            crate::mode::ModeState::new("Rule", "block"),
            "direct",
            false,
            Disposition::Core,
        ),
        (
            crate::mode::ModeState::new("Global", "block"),
            "direct",
            false,
            Disposition::Drop,
        ),
        (
            crate::mode::ModeState::new("Global", "direct"),
            "proxy",
            false,
            Disposition::Core,
        ),
        (
            crate::mode::ModeState::new("Direct", ""),
            "proxy",
            false,
            Disposition::Core,
        ),
        (
            crate::mode::ModeState::new("Direct", ""),
            "proxy",
            true,
            Disposition::Endpoint,
        ),
        (
            crate::mode::ModeState::new("Direct", ""),
            "block",
            false,
            Disposition::Drop,
        ),
        (
            crate::mode::ModeState::new("Global", "block"),
            "direct",
            true,
            Disposition::Core,
        ),
    ] {
        let selected = mode_decision(
            Some(&state),
            &config,
            #[cfg(feature = "native-api")]
            None,
            routed.into(),
            must,
        );
        assert_eq!(
            disposition(
                &selected.name,
                must,
                false,
                query,
                Execution::MixedEndpoints,
                false
            ),
            expected
        );
    }
    assert_eq!(
        disposition("proxy", false, false, query, Execution::RoutedOnly, false),
        Disposition::Drop
    );
    let dns = RouteQuery {
        protocol: 17,
        ports: Some((40000, 53)),
        ..query
    };
    assert_eq!(
        disposition(
            "direct",
            false,
            false,
            dns,
            Execution::MixedEndpoints,
            false
        ),
        Disposition::Endpoint
    );
    assert_eq!(
        disposition("direct", true, false, dns, Execution::MixedEndpoints, false),
        Disposition::Core
    );
    assert_eq!(
        disposition(
            "proxy",
            false,
            false,
            query,
            Execution::MixedEndpoints,
            true
        ),
        Disposition::Core
    );
    assert_eq!(
        disposition(
            "block",
            false,
            false,
            query,
            Execution::MixedEndpoints,
            true
        ),
        Disposition::Drop
    );
    assert_eq!(
        disposition("block", true, false, query, Execution::MixedEndpoints, true),
        Disposition::Drop
    );
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespace"]
async fn plain_output_history_survives_first_nat_enable_and_cq_owners() {
    use honk_netstack::wire;
    let ingresses = smoke_ingresses();
    for cached_owns_identity in [false, true] {
        let mut config = honk_config::parser::parse_dae_config(
        "global { dial_mode: ip\n nfqueue_enable: false }\ndatapath { backend: xdp\n direct: core\n interface { dut0: lan\n dut1: wan } }",
    ).unwrap();
        config.ensure_builtin_nodes();
        let plane = crate::control::tests::support::control_plane(config);
        let authority = plane
            .core_forward_policy(Execution::MixedEndpoints)
            .await
            .unwrap();
        let budget = MemoryBudget::new(32 << 20);
        let mut core = RoutedCore::new(
            authority,
            &ingresses,
            Requirements {
                execution: Execution::MixedEndpoints,
                nat: false,
                native_continuation: false,
                kernel_firewall: false,
                qdisc: false,
                skb_classification: false,
            },
            budget.clone(),
        )
        .unwrap();
        core.set_ingress_roles(&[
            (ingresses[0], InterfaceRole::Lan),
            (ingresses[1], InterfaceRole::Wan),
        ])
        .unwrap();
        let mut bytes = [0; 80];
        let mut emit = |source: &str, destination: &str| {
            let len = wire::udp::emit_packet(
                &mut bytes,
                source.parse().unwrap(),
                destination.parse().unwrap(),
                b"identity",
            )
            .unwrap();
            bytes[4..8].fill(0);
            bytes[10..12].fill(0);
            let checksum = wire::checksum::checksum(&bytes[..20]);
            bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
            bytes[..len].to_vec()
        };
        let plain = emit("192.0.2.2:40000", "198.51.100.2:18080");
        let mut atomic = plain.clone();
        atomic[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        atomic[10..12].fill(0);
        let checksum = wire::checksum::checksum(&atomic[..20]);
        atomic[10..12].copy_from_slice(&checksum.to_be_bytes());
        let initial = if cached_owns_identity {
            &atomic
        } else {
            &plain
        };
        let now = Instant::now();
        let packet = core.receive(ingresses[0], now, initial).unwrap().unwrap();
        let Decision::Forward(Prepared::Forward(mut output), _) =
            core.decide(packet, None, now).await.unwrap()
        else {
            panic!("plain traffic must forward without conntrack authority");
        };
        let mut wire_bytes = [0; 1500];
        let (len, owned_cq) = output.write_next(&mut wire_bytes).unwrap();
        wire::PacketView::from_slice(&wire_bytes[..len])
            .validate_transport()
            .unwrap();
        let plain_id = u16::from_be_bytes([wire_bytes[4], wire_bytes[5]]);
        drop(output);
        assert!(
            core.firewall.is_empty(),
            "native history must not create a binding grant"
        );
        let borrowed_input = if cached_owns_identity {
            &plain
        } else {
            &atomic
        };
        let CachedDecision::Forwarded((cached_id, borrowed_cq)) = core
            .forward_cached(
                ingresses[0],
                wire::PacketView::from_slice(borrowed_input),
                None,
                Instant::now(),
                |_, output| {
                    let mut wire_bytes = [0; 1500];
                    let len = output
                        .write_next_segments(&mut [&mut wire_bytes], &[])
                        .unwrap();
                    wire::PacketView::from_slice(&wire_bytes[..len])
                        .validate_transport()
                        .unwrap();
                    Ok(Some((
                        u16::from_be_bytes([wire_bytes[4], wire_bytes[5]]),
                        output.lease(),
                    )))
                },
            )
            .unwrap()
        else {
            panic!("plain native history cannot disable the borrowed fast path");
        };
        assert_eq!(cached_id, plain_id);
        let mut replacement = honk_config::parser::parse_dae_config(
        "global { dial_mode: ip\n nfqueue_enable: false }\ndatapath { backend: xdp\n direct: core\n interface { dut0: lan\n dut1: wan }\n firewall { original { default: allow }\n forward { default: allow } }\n nat { prerouting { dip(198.51.100.99, 203.0.113.1) -> dnat(198.51.100.2) } } }",
    ).unwrap();
        replacement.ensure_builtin_nodes();
        assert!(
            plane
                .reload_runtime_config(replacement, Default::default())
                .await
        );
        let translated = emit("192.0.2.2:41000", "198.51.100.99:18080");
        let now = Instant::now();
        let packet = core
            .receive(ingresses[0], now, &translated)
            .unwrap()
            .unwrap();
        let Decision::Forward(Prepared::Forward(mut output), _) =
            core.decide(packet, None, now).await.unwrap()
        else {
            panic!("NAT must remain available alongside previously plain traffic");
        };
        let (len, translated_cq) = output.write_next(&mut wire_bytes).unwrap();
        let ip = wire::PacketView::from_slice(&wire_bytes[..len])
            .validate_transport()
            .unwrap();
        assert_eq!(ip.dst, "198.51.100.2".parse::<std::net::IpAddr>().unwrap());
        assert_ne!(u16::from_be_bytes([wire_bytes[4], wire_bytes[5]]), plain_id);
        drop(output);
        let mut rejected = plane.config.read().await.as_ref().clone();
        rejected
            .datapath
            .as_mut()
            .unwrap()
            .firewall
            .as_mut()
            .unwrap()
            .forward
            .default = FirewallVerdict::Reject;
        assert!(
            plane
                .reload_runtime_config(rejected, Default::default())
                .await
        );
        let public = emit("192.0.2.2:42000", "203.0.113.1:18080");
        let now = Instant::now();
        let packet = core.receive(ingresses[0], now, &public).unwrap().unwrap();
        let Decision::Forward(Prepared::Error { packet, error }, _) =
            core.decide(packet, None, now).await.unwrap()
        else {
            panic!("forward reject must be evaluated after the DNAT input lookup");
        };
        assert_eq!(error, TransitError::AdminProhibited);
        let route = core.error_route(&packet).unwrap().unwrap();
        let len = core
            .error(Instant::now(), &packet, error, route, &mut wire_bytes)
            .unwrap()
            .unwrap();
        let ip = wire::parse_ip(&wire_bytes[..len]).unwrap();
        assert_eq!(
            &wire_bytes[ip.payload.start..ip.payload.start + 2],
            &[3, 13]
        );
        let quoted = wire::parse_ip(&wire_bytes[ip.payload.start + 8..len]).unwrap();
        assert_eq!(
            quoted.dst,
            "203.0.113.1".parse::<std::net::IpAddr>().unwrap()
        );
        drop(packet);
        drop(core);
        assert!(budget.used() > 0);
        drop(owned_cq);
        assert!(budget.used() > 0);
        drop(borrowed_cq);
        drop(translated_cq);
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespace"]
async fn unbound_native_quote_cannot_authorize_a_reused_nat_identity() {
    use honk_netstack::wire;
    use std::{net::SocketAddr, time::Duration};

    let ingresses = smoke_ingresses();
    for wait_before_policy in [false, true] {
        let mut config = honk_config::parser::parse_dae_config(
            "global { dial_mode: ip\n nfqueue_enable: false }\ndatapath { backend: xdp\n direct: core\n interface { dut0: lan\n dut1: wan } }",
        ).unwrap();
        config.ensure_builtin_nodes();
        let plane = crate::control::tests::support::control_plane(config);
        let authority = plane
            .core_forward_policy(Execution::MixedEndpoints)
            .await
            .unwrap();
        let budget = MemoryBudget::new(32 << 20);
        let table = Firewall::new_history(budget.clone(), 4, 1).unwrap();
        let mut core = unsynchronized_core(authority, &ingresses, &budget, Some(table));
        core.core = CoreForward::new(&ingresses, budget.clone(), 4).unwrap();
        core.set_ingress_roles(&[
            (ingresses[0], InterfaceRole::Lan),
            (ingresses[1], InterfaceRole::Wan),
        ])
        .unwrap();
        core.fib.synchronize().unwrap();
        let source = if wait_before_policy {
            "192.0.2.99"
        } else {
            "192.0.2.2"
        }
        .parse()
        .unwrap();
        let public = "198.51.100.99".parse().unwrap();
        let private = "198.51.100.2".parse().unwrap();
        let udp = |port, destination, payload: &[u8]| {
            let mut bytes = vec![0; 128];
            let len = wire::udp::emit_packet(
                &mut bytes,
                SocketAddr::new(source, port),
                SocketAddr::new(destination, 18080),
                payload,
            )
            .unwrap();
            bytes.truncate(len);
            bytes[4..8].fill(0);
            bytes[10..12].fill(0);
            let checksum = wire::checksum::checksum(&bytes[..20]);
            bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
            bytes
        };
        let past = Instant::now() - Duration::from_secs(241);
        let mut old = udp(40000, public, b"old-incarnation");
        let facts = Facts::parse(&old).unwrap();
        let old_grant = core
            .firewall
            .admit(Admission {
                ingress: ingresses[0],
                reply_ingress: ingresses[1],
                facts: &facts,
                dnat: Some(firewall::DestinationNat {
                    address: "198.51.100.2".parse().unwrap(),
                    port: None,
                }),
                snat: SourceNat::None,
                egress: None,
                received_at: past,
                now: past,
            })
            .unwrap();
        old_grant.rewrite(&mut old, false).unwrap();
        let reused_id = u16::from_be_bytes([old[4], old[5]]);
        core.firewall.revoke(0);
        let mut native = udp(41000, private, b"native-output");
        native[4..6].copy_from_slice(&reused_id.to_be_bytes());
        native[10..12].fill(0);
        let checksum = wire::checksum::checksum(&native[..20]);
        native[10..12].copy_from_slice(&checksum.to_be_bytes());
        let mut packet = core
            .core
            .receive(ingresses[0], past, &native)
            .unwrap()
            .unwrap();
        let (tuple, id) = packet.native_identity().unwrap();
        packet.bind_native(
            core.firewall
                .observe_plain(ingresses[0], ingresses[1], tuple, id, past)
                .unwrap(),
        );
        let Resolution::Forward(route) = core.fib.lookup(packet.query()).unwrap() else {
            panic!("native fixture requires its real forward neighbor");
        };
        let Prepared::Forward(mut output) = core.core.prepare(packet, route, 0, past).unwrap()
        else {
            panic!("native fixture must emit a real remapped datagram");
        };
        let mut emitted = [0; 1500];
        let (len, native_cq) = output.write_next(&mut emitted).unwrap();
        let native_wire = emitted[..len].to_vec();
        let remapped_id = u16::from_be_bytes([native_wire[4], native_wire[5]]);
        assert_ne!(remapped_id, reused_id);
        drop(output);
        drop(old_grant);
        core.firewall.expire(past);
        core.firewall.expire(Instant::now());

        let mut quoted = native_wire[..20].to_vec();
        quoted.extend_from_slice(&native_wire[28..36]);
        quoted[2..4].copy_from_slice(&28u16.to_be_bytes());
        quoted[6..8].copy_from_slice(&1u16.to_be_bytes());
        quoted[10..12].fill(0);
        let checksum = wire::checksum::checksum(&quoted[..20]);
        quoted[10..12].copy_from_slice(&checksum.to_be_bytes());
        let mut error = vec![0; 56];
        wire::emit_ip_header(
            &mut error,
            "198.51.100.254".parse().unwrap(),
            source,
            wire::PROTO_ICMP,
            36,
        )
        .unwrap();
        error[20] = 3;
        error[21] = 1;
        error[28..].copy_from_slice(&quoted);
        let checksum = wire::checksum::checksum(&error[20..]);
        error[22..24].copy_from_slice(&checksum.to_be_bytes());
        let now = Instant::now();
        let packet = core.receive(ingresses[1], now, &error).unwrap().unwrap();
        assert!(packet.binding().is_none());
        assert!(packet.native_quote().is_some());
        let waiting = if wait_before_policy {
            let Decision::Wait(packet) = core.decide(packet, None, now).await.unwrap() else {
                panic!("the missing return neighbor must retain the original wire quote");
            };
            assert_eq!(
                u16::from_be_bytes([packet.as_ref()[32], packet.as_ref()[33]]),
                remapped_id
            );
            Facts::from_packet(&packet).unwrap();
            Some(packet)
        } else {
            let Decision::Forward(Prepared::Forward(mut output), _) =
                core.decide(packet, None, now).await.unwrap()
            else {
                panic!("policy-free forwarding must repair the native quote at output");
            };
            let (len, cq) = output.write_next(&mut emitted).unwrap();
            Facts::parse(&emitted[..len]).unwrap();
            assert_eq!(u16::from_be_bytes([emitted[32], emitted[33]]), reused_id);
            drop(cq);
            drop(output);
            None
        };

        let mut candidate = honk_config::parser::parse_dae_config(
            "global { dial_mode: ip\n nfqueue_enable: false }\ndatapath { backend: xdp\n direct: core\n interface { dut0: lan\n dut1: wan }\n firewall { original { l4proto(udp) -> allow\n default: drop }\n forward { l4proto(udp) -> allow\n default: drop } }\n nat { prerouting { dip(198.51.100.99) -> dnat(198.51.100.2) } } }",
        ).unwrap();
        candidate.ensure_builtin_nodes();
        assert!(
            plane
                .reload_runtime_config(candidate, Default::default())
                .await
        );
        let new = udp(42000, public, b"new-incarnation");
        let now = Instant::now();
        let packet = core.receive(ingresses[0], now, &new).unwrap().unwrap();
        let Decision::Forward(Prepared::Forward(mut output), _) =
            core.decide(packet, None, now).await.unwrap()
        else {
            panic!("the new UDP incarnation must receive its own grant");
        };
        let (len, new_cq) = output.write_next(&mut emitted).unwrap();
        let new_facts = Facts::parse(&emitted[..len]).unwrap();
        assert_eq!(new_facts.tuple.source_port, 42000);
        assert_eq!(u16::from_be_bytes([emitted[4], emitted[5]]), reused_id);
        drop(output);
        let packet = match waiting {
            Some(packet) => packet,
            None => core
                .receive(ingresses[1], Instant::now(), &error)
                .unwrap()
                .unwrap(),
        };
        assert!(
            Instant::now() < packet.deadline(),
            "exercise authorization, not deadline disposal"
        );
        assert!(packet.binding().is_none());
        assert!(
            matches!(
                core.decide(packet, None, Instant::now()).await.unwrap(),
                Decision::Drop
            ),
            "a native quote must not borrow the new incarnation's related-NAT authority"
        );
        drop(new_cq);
        drop(native_cq);
    }
}

fn smoke_ingresses() -> [Ingress; 2] {
    use std::os::{fd::AsFd, unix::fs::MetadataExt};
    assert!(
        std::fs::read_to_string("/proc/cmdline")
            .unwrap()
            .contains("virtme.")
    );
    assert_ne!(
        std::fs::metadata("/proc/self/ns/net").unwrap().ino(),
        std::fs::metadata("/proc/1/ns/net").unwrap().ino()
    );
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    let scope = honk_datapath::ScopeId::allocate().unwrap();
    let namespace = socket_namespace(socket.as_fd()).unwrap();
    ["dut0", "dut1"].map(|name| Ingress {
        scope,
        namespace,
        ifindex: std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
            .unwrap()
            .trim()
            .parse()
            .unwrap(),
        attachment: 1,
        mark: MarkProvenance::BeforeSkb,
    })
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespace"]
async fn unresolved_forward_neighbor_does_not_delay_transit_errors() {
    use honk_netstack::wire;
    let ingresses = smoke_ingresses();
    let mut config = honk_config::Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    let plane = crate::control::tests::support::control_plane(config);
    let authority = plane
        .core_forward_policy(Execution::MixedEndpoints)
        .await
        .unwrap();
    let budget = MemoryBudget::new(16 << 20);
    let mut core = unsynchronized_core(authority, &ingresses, &budget, None);
    for ipv6 in [false, true] {
        let source = if ipv6 {
            "[fd00:1::2]:40000"
        } else {
            "192.0.2.2:40000"
        }
        .parse()
        .unwrap();
        let destination = if ipv6 {
            "[fd00:2::99]:18080"
        } else {
            "198.51.100.99:18080"
        }
        .parse()
        .unwrap();
        for (hop_limit, payload, expected) in [
            (0, 16, TransitError::HopLimitExceeded),
            (1, 16, TransitError::HopLimitExceeded),
            (64, 1600, TransitError::PacketTooBig { mtu: 1500 }),
        ] {
            let mut bytes = vec![0; payload + 48];
            let len = wire::udp::emit_packet(&mut bytes, source, destination, &vec![0x5a; payload])
                .unwrap();
            bytes.truncate(len);
            bytes[if ipv6 { 7 } else { 8 }] = hop_limit;
            if !ipv6 {
                bytes[10..12].fill(0);
                let sum = wire::checksum::checksum(&bytes[..20]);
                bytes[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            core.fib.synchronize().unwrap();
            let now = Instant::now();
            let packet = core.receive(ingresses[0], now, &bytes).unwrap().unwrap();
            assert!(matches!(
                core.fib.lookup(packet.query()).unwrap(),
                Resolution::NeighborPending(_)
            ));
            let Decision::Forward(Prepared::Error { packet, error }, generation) =
                core.decide(packet, None, now).await.unwrap()
            else {
                panic!("forward neighbor absence cannot delay a known transit error");
            };
            assert_eq!(error, expected);
            let route = core
                .error_route(&packet)
                .unwrap()
                .expect("return neighbor is configured");
            let mut output = [0; 1280];
            let len = core
                .error(Instant::now(), &packet, error, route, &mut output)
                .unwrap()
                .unwrap();
            let ip = wire::PacketView::from_slice(&output[..len])
                .validate_transport()
                .unwrap();
            assert_eq!(ip.dst, source.ip());
            let expected_type = match (ipv6, expected) {
                (true, TransitError::HopLimitExceeded) => [3, 0],
                (false, TransitError::HopLimitExceeded) => [11, 0],
                (true, _) => [2, 0],
                (false, _) => [3, 4],
            };
            assert_eq!(
                &output[ip.payload.start..ip.payload.start + 2],
                &expected_type
            );
            assert_eq!(
                core.submit(route, generation, || Ok(Some(len)))
                    .await
                    .unwrap(),
                Some(len)
            );
            let invalid_source = Route {
                preferred_source: Some(if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap()),
                ..route
            };
            assert!(
                core.error(Instant::now(), &packet, error, invalid_source, &mut output)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(core.state(), FibState::Ready);
            assert!(core.authority.admitting());
        }
        let mut bytes = [0; 80];
        let destination = if ipv6 {
            "[fd00:2::98]:18080"
        } else {
            "198.51.100.98:18080"
        }
        .parse()
        .unwrap();
        let len = wire::udp::emit_packet(&mut bytes, source, destination, b"prohibit").unwrap();
        core.fib.synchronize().unwrap();
        let now = Instant::now();
        let packet = core
            .receive(ingresses[0], now, &bytes[..len])
            .unwrap()
            .unwrap();
        let Decision::Forward(Prepared::Error { packet, error }, _) =
            core.decide(packet, None, now).await.unwrap()
        else {
            panic!("real prohibit route must retain administrative error authority");
        };
        assert_eq!(error, TransitError::AdminProhibited);
        let route = core.error_route(&packet).unwrap().unwrap();
        let mut output = [0; 1280];
        let len = core
            .error(Instant::now(), &packet, error, route, &mut output)
            .unwrap()
            .unwrap();
        let ip = wire::parse_ip(&output[..len]).unwrap();
        assert_eq!(
            &output[ip.payload.start..ip.payload.start + 2],
            if ipv6 { &[1, 1] } else { &[3, 13] }
        );
        let missing_source = if ipv6 {
            "[fd00:1::99]:40000"
        } else {
            "192.0.2.99:40000"
        }
        .parse()
        .unwrap();
        let len = wire::udp::emit_packet(
            &mut bytes,
            missing_source,
            destination,
            b"no-return-neighbor",
        )
        .unwrap();
        core.fib.synchronize().unwrap();
        let now = Instant::now();
        let packet = core
            .receive(ingresses[0], now, &bytes[..len])
            .unwrap()
            .unwrap();
        let Decision::Forward(Prepared::Error { packet, .. }, _) =
            core.decide(packet, None, now).await.unwrap()
        else {
            panic!("prohibit still applies with unresolved return neighbor");
        };
        assert!(core.error_route(&packet).unwrap().is_none());
        assert!(core.authority.admitting());
    }
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespace"]
async fn generated_reassembly_error_keeps_scoped_nat_and_funding_through_completion() {
    use honk_netstack::wire;
    use std::time::Duration;
    let ingresses = smoke_ingresses();
    for completion_after_owner in [false, true] {
        let mut config = honk_config::Config::default();
        config.ensure_builtin_nodes();
        config.global.dial_mode = "ip".into();
        let plane = crate::control::tests::support::control_plane(config);
        let authority = plane
            .core_forward_policy(Execution::MixedEndpoints)
            .await
            .unwrap();
        let budget = MemoryBudget::new(32 << 20);
        let start = Instant::now() - Duration::from_secs(31);
        let mut bytes = [0; 80];
        let len = wire::udp::emit_packet(
            &mut bytes,
            "192.0.2.2:40000".parse().unwrap(),
            "198.51.100.99:18080".parse().unwrap(),
            &[0x5a; 32],
        )
        .unwrap();
        bytes[6..8].fill(0);
        bytes[10..12].fill(0);
        let checksum = wire::checksum::checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        let facts = Facts::parse(&bytes[..len]).unwrap();
        let mut table = Firewall::new(budget.clone(), 2, 1).unwrap();
        let witness = table
            .admit(Admission {
                ingress: ingresses[0],
                reply_ingress: ingresses[1],
                facts: &facts,
                dnat: None,
                snat: SourceNat::Snat {
                    address: "203.0.113.1".parse().unwrap(),
                    ports: None,
                },
                egress: None,
                received_at: start,
                now: start,
            })
            .unwrap();
        drop(witness);
        let mut core = unsynchronized_core(authority, &ingresses, &budget, Some(table));
        core.fib.synchronize().unwrap();
        let baseline = budget.used();
        let mut fragment = bytes[..36].to_vec();
        fragment[2..4].copy_from_slice(&36u16.to_be_bytes());
        fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        fragment[10..12].fill(0);
        let checksum = wire::checksum::checksum(&fragment[..20]);
        fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert!(
            core.receive(ingresses[0], start, &fragment)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            core.poll_reassembly_timeout(start),
            Some(start + Duration::from_secs(30))
        );
        let mut output = [0; 1280];
        let generated = core
            .poll_reassembly_error(Instant::now(), &mut output)
            .await
            .unwrap()
            .expect("timeout emits despite unresolved forward neighbor");
        assert_eq!(&output[20..22], &[11, 1]);
        assert_eq!(core.reassembly_outputs.pending(), 1);
        assert!(!core.fragments_quiescent());
        let due = Instant::now();
        assert_eq!(core.poll_reassembly_timeout(due), Some(due));
        assert!(
            core.poll_reassembly_error(due, &mut [0; 1280])
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(core.poll_reassembly_timeout(due), None);
        assert!(budget.used() > baseline);
        assert_eq!(
            core.submit(generated.route, generated.generation, || Ok(Some(())))
                .await
                .unwrap(),
            Some(())
        );
        core.firewall
            .expire(Instant::now() + Duration::from_secs(121));
        let retirement = Instant::now() + Duration::from_secs(242);
        core.firewall.expire(retirement);
        assert!(
            !core.firewall.is_empty(),
            "exported timeout must retain matching NAT ownership"
        );
        let outputs = Arc::clone(&core.reassembly_outputs);
        if completion_after_owner {
            drop(core);
            assert!(
                budget.used() > 0,
                "exported quote remains funded after owner teardown"
            );
            drop(generated);
            assert_eq!(outputs.pending(), 0);
            drop(outputs);
            assert_eq!(budget.used(), 0);
        } else {
            drop(generated);
            assert_eq!(outputs.pending(), 0);
            assert!(core.fragments_quiescent());
            core.firewall.expire(retirement);
            core.firewall
                .expire(retirement + Duration::from_secs(120) - Duration::from_nanos(1));
            assert!(
                !core.firewall.is_empty(),
                "CQ return must start a fresh full MDL"
            );
            core.firewall.expire(retirement + Duration::from_secs(120));
            assert!(core.firewall.is_empty());
            drop(core);
            drop(outputs);
            assert_eq!(budget.used(), 0);
        }
    }
}

#[tokio::test]
async fn submit_refuses_mode_generation_and_aba_without_router_reload() {
    let mut config = honk_config::Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    let mut plane = crate::control::tests::support::control_plane(config);
    let mode = Arc::new(parking_lot::RwLock::new(crate::mode::ModeState::new(
        "Rule", "direct",
    )));
    plane.set_mode_state(mode.clone());
    plane.start_datapath_flags_coordinator().unwrap();
    let flags = plane.datapath_flags_handle().unwrap();
    flags.initialize(false, false).await.unwrap();
    let authority = plane
        .core_forward_policy(Execution::MixedEndpoints)
        .await
        .unwrap();
    let admitted = authority.generation(Some(&mode.read()));
    use std::os::fd::AsFd;
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    let ingress = Ingress {
        scope: honk_datapath::ScopeId::allocate().unwrap(),
        namespace: socket_namespace(socket.as_fd()).unwrap(),
        ifindex: 2,
        attachment: 1,
        mark: MarkProvenance::BeforeSkb,
    };
    let budget = MemoryBudget::new(16 << 20);
    let mut core = unsynchronized_core(authority.clone(), &[ingress], &budget, None);
    core.fib.synchronize().unwrap();
    let mut route = Route {
        generation: core.fib.generation(),
        ifindex: 2,
        l2: honk_datapath::forward::LinkPath::untagged(2),
        mtu: 1500,
        next_hop: "192.0.2.2".parse().unwrap(),
        preferred_source: None,
        source_mac: [2; 6],
        destination_mac: [4; 6],
    };
    assert_eq!(
        core.submit(route, admitted, || Ok(Some(7))).await.unwrap(),
        Some(7)
    );
    flags.set_mode("Global").await.unwrap();
    let global = authority.generation(Some(&mode.read()));
    assert_eq!(admitted.routing, global.routing);
    assert!(
        core.submit(route, admitted, || -> io::Result<Option<()>> {
            panic!("stale mode submitted a descriptor");
        })
        .await
        .unwrap()
        .is_none()
    );
    flags.set_mode("Rule").await.unwrap();
    assert!(
        core.submit(route, admitted, || -> io::Result<Option<()>> {
            panic!("mode ABA revived a descriptor");
        })
        .await
        .unwrap()
        .is_none()
    );
    core.fib.synchronize().unwrap();
    route.generation = core.fib.generation();
    let current = authority.generation(Some(&mode.read()));
    assert_eq!(
        core.submit(route, current, || Ok(Some(9))).await.unwrap(),
        Some(9)
    );
}
