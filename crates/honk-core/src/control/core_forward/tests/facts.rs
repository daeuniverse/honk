use super::*;
use crate::dns::projection::{ProjectionObservation, RoutingProjectionSnapshot};
use honk_netstack::wire::{self, tcp};
use honk_outbound::alive::IpVersion;
use std::{net::IpAddr, os::fd::AsFd, time::Duration};

async fn fact_core(
    outbound: &str,
) -> (
    ControlPlane,
    RoutedCore,
    [Ingress; 2],
    [ScopeId; 2],
    Arc<RoutingProjectionSnapshot>,
) {
    let mut config = honk_config::parser::parse_dae_config(&format!(
        "global {{ dial_mode: ip\n nfqueue_enable: false }}\nrouting {{ domain(suffix: test) -> {outbound}\n fallback: direct }}",
    )).unwrap();
    config.ensure_builtin_nodes();
    if outbound == "proxy" {
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
    }
    let plane = crate::control::tests::support::control_plane(config);
    let snapshot = {
        let mut router = plane.router.write().await;
        let config = plane.config.read().await;
        *router = crate::routing::Router::from_config(&config.routing).unwrap();
        let generation = plane.diagnostics.read().generation.checked_add(1).unwrap();
        let snapshot = Arc::new(RoutingProjectionSnapshot::new(
            generation,
            Arc::new(router.clone()),
        ));
        plane.diagnostics.write().generation = generation;
        plane
            .dns_controller
            .prepare_projection_publication()
            .commit(Arc::clone(&snapshot), None);
        snapshot
    };
    let projection = plane.dns_controller.routing_projection();
    projection.shutdown(Duration::from_secs(1)).await;
    let budget = MemoryBudget::new(16 << 20);
    let scopes = [ScopeId::allocate().unwrap(), ScopeId::allocate().unwrap()];
    projection
        .register_packet_scopes(scopes.into_iter().rev(), &budget)
        .unwrap();
    let authority = plane
        .core_forward_policy(Execution::MixedEndpoints)
        .await
        .unwrap();
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    let first = Ingress {
        scope: ScopeId::allocate().unwrap(),
        namespace: socket_namespace(socket.as_fd()).unwrap(),
        ifindex: 2,
        attachment: 1,
        mark: MarkProvenance::BeforeSkb,
    };
    let ingresses = [
        first,
        Ingress {
            ifindex: 3,
            ..first
        },
    ];
    let mut core = unsynchronized_core(authority, &ingresses, &budget, None);
    core.set_ingress_bindings(&[
        IngressBinding {
            ingress: ingresses[0],
            role: InterfaceRole::Lan,
            facts: scopes[0],
        },
        IngressBinding {
            ingress: ingresses[1],
            role: InterfaceRole::Wan,
            facts: scopes[1],
        },
    ])
    .unwrap();
    (plane, core, ingresses, scopes, snapshot)
}

fn positive_fact<'a>(name: &'a str, ips: &'a [IpAddr]) -> ProjectionObservation<'a> {
    ProjectionObservation::Positive {
        domain: name,
        family: IpVersion::V4,
        ips,
        expires_at: tokio::time::Instant::now() + Duration::from_secs(30),
    }
}

fn clear_fact(name: &str) -> ProjectionObservation<'_> {
    ProjectionObservation::Clear {
        domain: name,
        family: IpVersion::V4,
    }
}

fn udp() -> Vec<u8> {
    let mut bytes = vec![0; 80];
    let len = wire::udp::emit_packet(
        &mut bytes,
        "192.0.2.1:40000".parse().unwrap(),
        "198.51.100.2:18080".parse().unwrap(),
        b"scoped-fact",
    )
    .unwrap();
    bytes.truncate(len);
    bytes
}

fn syn() -> Vec<u8> {
    let mut bytes = vec![0; 80];
    let len = tcp::emit_packet(
        &mut bytes,
        "192.0.2.1".parse().unwrap(),
        "198.51.100.2".parse().unwrap(),
        &tcp::Header {
            src_port: 40000,
            dst_port: 443,
            seq: 10,
            ack: 0,
            flags: tcp::SYN,
            window: 4096,
            urgent: 0,
            options: Default::default(),
        },
        [&[], &[]],
    )
    .unwrap();
    bytes.truncate(len);
    bytes
}

async fn prepare_forward(
    core: &mut RoutedCore,
    ingress: Ingress,
) -> (Prepared, PolicyGeneration, Route) {
    let bytes = udp();
    let packet = core
        .receive(ingress, Instant::now(), &bytes)
        .unwrap()
        .unwrap();
    core.fib.synchronize().unwrap();
    let route = Route {
        generation: core.fib.generation(),
        ifindex: 3,
        l2: honk_datapath::forward::LinkPath::untagged(3),
        mtu: 1500,
        next_hop: packet.query().destination,
        preferred_source: None,
        source_mac: [2; 6],
        destination_mac: [4; 6],
    };
    core.routes.push(Cached {
        query: packet.query(),
        route,
    });
    let authority = core.authority();
    let Decision::Forward(prepared, generation) = core
        .decide(&authority.read_policy().await, packet, None, Instant::now())
        .unwrap()
    else {
        panic!("bound direct fact must produce an owned Core decision");
    };
    assert!(generation.facts.is_some());
    assert!(matches!(prepared, Prepared::Forward(_)));
    (prepared, generation, route)
}

#[tokio::test]
async fn packet_scope_registration_charge_follows_its_owners() {
    if crate::test_support::run_exact_in_child(
        "HONK_PACKET_FACT_OWNER_CHILD",
        "control::core_forward::tests::facts::packet_scope_registration_charge_follows_its_owners",
    ) {
        return;
    }
    let mut config = honk_config::Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    let plane = crate::control::tests::support::control_plane(config);
    let projection = plane.dns_controller.routing_projection();
    let controller_owner = Arc::downgrade(&plane.dns_controller);
    let projection_owner = Arc::downgrade(&projection);
    projection.shutdown(Duration::from_secs(1)).await;
    let budget = MemoryBudget::new(4096);
    let baseline = budget.used();
    let scope = ScopeId::allocate().unwrap();
    projection
        .register_packet_scopes([scope].into_iter(), &budget)
        .unwrap();
    assert!(budget.used() > baseline);
    let authority = plane
        .core_forward_policy(Execution::MixedEndpoints)
        .await
        .unwrap();
    drop(projection);
    drop(plane);
    assert!(controller_owner.upgrade().is_none());
    assert!(projection_owner.upgrade().is_some());
    assert!(authority.0.projection.owns_packet_scope(scope));
    assert!(
        budget.used() > baseline,
        "the actual Core registration still owns the projection"
    );
    drop(authority);
    assert!(projection_owner.upgrade().is_none());
    assert_eq!(budget.used(), baseline);
}

#[tokio::test]
async fn core_reads_only_its_bound_scope_facts() {
    let (_plane, mut core, ingresses, scopes, snapshot) = fact_core("block").await;
    let authority = core.authority();
    let projection = Arc::clone(&authority.0.projection);
    let bytes = udp();
    let ip = "198.51.100.2".parse().unwrap();
    projection.submit(
        ScopeId::HOST,
        Arc::clone(&snapshot),
        positive_fact("blocked.test", &[ip]),
    );
    assert!(matches!(
        core.forward_cached(
            ingresses[0],
            wire::PacketView::from_slice(&bytes),
            None,
            Instant::now(),
            |_, _| -> io::Result<Option<()>> { panic!("uncached packet reached TX") },
        )
        .unwrap(),
        CachedDecision::Cold
    ));
    projection.submit(
        scopes[0],
        Arc::clone(&snapshot),
        positive_fact("blocked.test", &[ip]),
    );
    assert!(matches!(
        core.forward_cached(
            ingresses[0],
            wire::PacketView::from_slice(&bytes),
            None,
            Instant::now(),
            |_, _| -> io::Result<Option<()>> { panic!("bound Block reached TX") },
        )
        .unwrap(),
        CachedDecision::Drop
    ));
    assert!(matches!(
        core.forward_cached(
            ingresses[1],
            wire::PacketView::from_slice(&bytes),
            None,
            Instant::now(),
            |_, _| -> io::Result<Option<()>> { panic!("another realm reached TX") },
        )
        .unwrap(),
        CachedDecision::Cold
    ));
    let packet = core
        .receive(ingresses[0], Instant::now(), &bytes)
        .unwrap()
        .unwrap();
    assert!(matches!(
        core.decide(&authority.read_policy().await, packet, None, Instant::now())
            .unwrap(),
        Decision::Drop
    ));
    let mut unbound = unsynchronized_core(authority.clone(), &ingresses, &core.budget, None);
    let packet = unbound
        .receive(ingresses[0], Instant::now(), &bytes)
        .unwrap()
        .unwrap();
    assert!(matches!(
        unbound
            .decide(&authority.read_policy().await, packet, None, Instant::now())
            .unwrap(),
        Decision::Drop
    ));
    unbound
        .set_ingress_bindings(&[
            IngressBinding {
                ingress: ingresses[0],
                role: InterfaceRole::Lan,
                facts: ScopeId::allocate().unwrap(),
            },
            IngressBinding {
                ingress: ingresses[1],
                role: InterfaceRole::Wan,
                facts: scopes[1],
            },
        ])
        .unwrap();
    let packet = unbound
        .receive(ingresses[0], Instant::now(), &bytes)
        .unwrap()
        .unwrap();
    assert!(matches!(
        unbound
            .decide(&authority.read_policy().await, packet, None, Instant::now())
            .unwrap(),
        Decision::Drop
    ));
}

#[tokio::test]
async fn core_submit_checks_fact_stamp_inside_the_writer() {
    let (_plane, mut core, ingresses, scopes, snapshot) = fact_core("direct").await;
    let authority = core.authority();
    let projection = Arc::clone(&authority.0.projection);
    let ip = "198.51.100.2".parse().unwrap();
    projection.submit(
        scopes[0],
        Arc::clone(&snapshot),
        positive_fact("a.test", &[ip]),
    );
    let (prepared, generation, route) = prepare_forward(&mut core, ingresses[0]).await;
    assert_eq!(
        core.submit(&authority.read_policy().await, route, generation, || {
            assert!(projection.try_packet_facts().is_none());
            assert!(authority.0.router.try_write().is_err());
            assert!(authority.0.config.try_write().is_err());
            Ok(Some(7))
        })
        .unwrap(),
        Some(7)
    );
    projection.submit(scopes[0], Arc::clone(&snapshot), clear_fact("a.test"));
    projection.submit(
        scopes[0],
        Arc::clone(&snapshot),
        positive_fact("a.test", &[ip]),
    );
    assert!(
        core.submit(
            &authority.read_policy().await,
            route,
            generation,
            || -> io::Result<Option<()>> {
                panic!("clear/repopulate ABA reached the synchronous writer");
            }
        )
        .unwrap()
        .is_none()
    );
    drop(prepared);
    let (prepared, generation, route) = prepare_forward(&mut core, ingresses[0]).await;
    projection.submit(
        scopes[1],
        Arc::clone(&snapshot),
        positive_fact("other.test", &[ip]),
    );
    assert_eq!(
        core.submit(&authority.read_policy().await, route, generation, || {
            assert!(projection.try_packet_facts().is_none());
            Ok(Some(9))
        })
        .unwrap(),
        Some(9)
    );
    drop(prepared);
}

#[tokio::test]
async fn cached_core_writer_keeps_fact_mutation_serialization() {
    let (_plane, mut core, ingresses, scopes, snapshot) = fact_core("direct").await;
    let projection = Arc::clone(&core.authority.0.projection);
    let ip = "198.51.100.2".parse().unwrap();
    projection.submit(
        scopes[0],
        Arc::clone(&snapshot),
        positive_fact("a.test", &[ip]),
    );
    let (prepared, _, _) = prepare_forward(&mut core, ingresses[0]).await;
    drop(prepared);
    let bytes = udp();
    assert!(matches!(
        core.forward_cached(
            ingresses[0],
            wire::PacketView::from_slice(&bytes),
            None,
            Instant::now(),
            |_, _| {
                assert!(projection.try_packet_facts().is_none());
                Ok(Some(7))
            },
        )
        .unwrap(),
        CachedDecision::Forwarded(7)
    ));
    let facts = projection.packet_facts();
    assert!(matches!(
        core.forward_cached(
            ingresses[0],
            wire::PacketView::from_slice(&bytes),
            None,
            Instant::now(),
            |_, _| -> io::Result<Option<()>> { panic!("contended facts reached cached TX") },
        )
        .unwrap(),
        CachedDecision::Cold
    ));
    drop(facts);
}

#[tokio::test]
async fn core_endpoint_admission_uses_scoped_bitmap() {
    let (_plane, mut core, ingresses, scopes, snapshot) = fact_core("proxy").await;
    let authority = core.authority();
    let ip = "198.51.100.2".parse().unwrap();
    authority
        .0
        .projection
        .submit(scopes[0], snapshot, positive_fact("proxied.test", &[ip]));
    let bytes = syn();
    let packet = core
        .receive(ingresses[0], Instant::now(), &bytes)
        .unwrap()
        .unwrap();
    let Decision::Endpoint(_, admission) = core
        .decide(&authority.read_policy().await, packet, None, Instant::now())
        .unwrap()
    else {
        panic!("scoped domain rule did not select Endpoint");
    };
    assert_eq!(admission.into_snapshot().decision.outbound, "proxy");
}

#[tokio::test]
async fn core_endpoint_admission_commits_only_current_facts() {
    for mutate_bound_scope in [true, false] {
        let (_plane, mut core, ingresses, scopes, snapshot) = fact_core("proxy").await;
        let authority = core.authority();
        let projection = Arc::clone(&authority.0.projection);
        let ip = "198.51.100.2".parse().unwrap();
        projection.submit(
            scopes[0],
            Arc::clone(&snapshot),
            positive_fact("proxied.test", &[ip]),
        );
        let scope = scopes[usize::from(!mutate_bound_scope)];
        core.after_fact_read = Some(Box::new(move || {
            projection.submit(scope, Arc::clone(&snapshot), clear_fact("proxied.test"));
            projection.submit(scope, snapshot, positive_fact("proxied.test", &[ip]));
        }));
        let bytes = syn();
        let packet = core
            .receive(ingresses[0], Instant::now(), &bytes)
            .unwrap()
            .unwrap();
        let deadline = packet.deadline();
        let original_storage = packet.as_ref().as_ptr();
        let decision = core
            .decide(&authority.read_policy().await, packet, None, Instant::now())
            .unwrap();
        let decision = if mutate_bound_scope {
            let Decision::Wait(packet) = decision else {
                panic!("uncommitted stale fact became an Endpoint admission");
            };
            assert_eq!(packet.deadline(), deadline);
            assert_eq!(packet.as_ref().as_ptr(), original_storage);
            assert_eq!(packet.as_ref(), bytes);
            core.decide(&authority.read_policy().await, packet, None, Instant::now())
                .unwrap()
        } else {
            decision
        };
        let Decision::Endpoint(packet, admission) = decision else {
            panic!("fresh bound facts did not commit Endpoint");
        };
        assert_eq!(packet.deadline(), deadline);
        assert_eq!(admission.into_snapshot().decision.outbound, "proxy");
    }
}

#[test]
fn routed_only_rejects_unbacked_domain_predicates() {
    for condition in [
        "domain(test)",
        "!domain(test)",
        "domain(suffix: test)",
        "!domain(suffix: test)",
        "domain(keyword: test)",
        "domain(regex: test)",
        "domain(geosite: test)",
    ] {
        let config = honk_config::parser::parse_dae_config(&format!(
            "global {{ dial_mode: ip }}\nrouting {{ {condition} -> direct\n fallback: direct }}",
        ))
        .unwrap();
        let error = validate_config(&config).unwrap_err();
        assert!(
            error.to_string().contains("no packet DNS fact scope"),
            "{condition}: {error:#}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn cached_core_rechecks_original_expiry_at_the_writer_boundary() {
    let (_plane, mut core, ingresses, scopes, snapshot) = fact_core("direct").await;
    let projection = Arc::clone(&core.authority.0.projection);
    let ip = "198.51.100.2".parse().unwrap();
    let (prepared, _, _) = prepare_forward(&mut core, ingresses[0]).await;
    drop(prepared);
    projection.submit(
        scopes[0],
        snapshot,
        ProjectionObservation::Positive {
            domain: "a.test",
            family: IpVersion::V4,
            ips: &[ip],
            expires_at: tokio::time::Instant::now() + Duration::from_secs(2),
        },
    );
    core.after_fact_read = Some(Box::new(|| {
        let before = tokio::time::Instant::now();
        let mut advance = std::pin::pin!(tokio::time::advance(Duration::from_secs(3)));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let _ = advance.as_mut().poll(&mut cx);
        assert!(tokio::time::Instant::now() >= before + Duration::from_secs(3));
    }));
    let bytes = udp();
    assert!(matches!(
        core.forward_cached(
            ingresses[0],
            wire::PacketView::from_slice(&bytes),
            None,
            Instant::now(),
            |_, _| -> io::Result<Option<()>> { panic!("expired cached fact reached TX") },
        )
        .unwrap(),
        CachedDecision::Drop
    ));
}

#[tokio::test]
async fn core_ingress_bindings_are_exact_nonhost_and_set_once() {
    let (_plane, core, ingresses, scopes, _snapshot) = fact_core("direct").await;
    let mut unbound = unsynchronized_core(core.authority(), &ingresses, &core.budget, None);
    let first = IngressBinding {
        ingress: ingresses[0],
        role: InterfaceRole::Lan,
        facts: scopes[0],
    };
    let second = IngressBinding {
        ingress: ingresses[1],
        role: InterfaceRole::Wan,
        facts: scopes[1],
    };
    for bindings in [
        vec![first],
        vec![first, first],
        vec![
            IngressBinding {
                facts: ScopeId::HOST,
                ..first
            },
            second,
        ],
        vec![
            IngressBinding {
                ingress: Ingress {
                    attachment: 2,
                    ..ingresses[0]
                },
                ..first
            },
            second,
        ],
    ] {
        assert!(unbound.set_ingress_bindings(&bindings).is_err());
        assert!(unbound.ingress_bindings.is_empty());
    }
    unbound.set_ingress_bindings(&[first, second]).unwrap();
    assert!(unbound.set_ingress_bindings(&[first, second]).is_err());
    assert_eq!(unbound.ingress_bindings, [first, second]);
}
