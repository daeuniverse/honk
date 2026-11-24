use super::*;

#[tokio::test]
async fn packet_dns_admission_requires_a_registered_nonhost_scope() {
    let controller = snapshot_controller(snapshot_forwarder(Arc::new(SnapshotUpstream {
        ip: [192, 0, 2, 1],
        calls: AtomicUsize::new(0),
        entered: None,
        release: None,
    })));
    let foreign = honk_datapath::ScopeId::allocate().unwrap();
    assert!(controller.try_admit_packet_query(true, foreign).is_err());
    assert!(
        controller
            .try_admit_packet_query(false, honk_datapath::ScopeId::HOST)
            .is_err()
    );
    let (scope, _owner) = packet_scope(&controller);
    assert!(controller.try_admit_packet_query(false, foreign).is_err());
    let admitted = controller
        .try_admit_packet_query(true, scope.scope())
        .unwrap();
    assert!(controller.try_admit_query(true).is_err());
    drop(admitted);
    assert!(controller.try_admit_query(true).is_ok());
    assert!(
        controller
            .register_packet_scopes(std::slice::from_ref(&scope))
            .is_err()
    );
}

#[tokio::test]
async fn packet_dns_answers_do_not_enter_the_kernel_projection() {
    struct Answers;
    #[async_trait::async_trait]
    impl DnsUpstreamPool for Answers {
        async fn query(&self, _: &str, query: &[u8]) -> anyhow::Result<Vec<u8>> {
            let (name, _) =
                crate::dns::forwarder::parse_dns_question(query).expect("valid client query");
            Ok(a_response(
                query,
                if name == "example.com" {
                    [192, 0, 2, 2]
                } else {
                    [192, 0, 2, 1]
                },
            ))
        }
    }
    let forwarder = Arc::new(
        DnsForwarder::new(
            Arc::new(Answers),
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                16,
            ))),
            Arc::new(
                crate::dns::routing::DnsRouter::new_from_dns_config(
                    &honk_config::dns::DnsConfig::default(),
                )
                .unwrap(),
            ),
        )
        .with_cache_enabled(false),
    );
    let (controller, backend) = projection_controller(forwarder);
    let (scope, _scope_owner) = packet_scope(&controller);
    let packet_query = query_with_txid("packet.example.com", 1);
    let admission = controller
        .try_admit_packet_query(true, scope.scope())
        .unwrap();
    let publication = controller.prepare_projection_publication();
    let answer = tokio::time::timeout(
        Duration::from_secs(1),
        controller.answer_query(
            &admission,
            &packet_query,
            crate::dns::query::DnsRequestMeta::new(None, None),
            crate::dns::query::validate_exact_dns_query(&packet_query)
                .unwrap()
                .ingress(),
        ),
    )
    .await
    .expect("packet-owned DNS must not wait for a kernel publication");
    assert!(answer.wire().ends_with(&[192, 0, 2, 1]));
    drop(admission);
    drop(publication);
    let host_query = query_with_txid("example.com", 2);
    let admission = controller.try_admit_query(true).unwrap();
    let answer = controller
        .answer_query(
            &admission,
            &host_query,
            crate::dns::query::DnsRequestMeta::new(None, None),
            crate::dns::query::validate_exact_dns_query(&host_query)
                .unwrap()
                .ingress(),
        )
        .await;
    assert!(answer.wire().ends_with(&[192, 0, 2, 2]));
    drop(admission);
    let host = crate::ebpf::maps::lpm_key_bytes(&crate::ebpf::maps::ip_addr_to_lpm_key(
        "192.0.2.2".parse().unwrap(),
    ));
    let packet = crate::ebpf::maps::lpm_key_bytes(&crate::ebpf::maps::ip_addr_to_lpm_key(
        "192.0.2.1".parse().unwrap(),
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if backend
                .read()
                .await
                .projection_map_snapshot()
                .iter()
                .any(|(key, _)| *key == host)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("host-owned control query must reach the real projection worker");
    assert!(
        !backend
            .read()
            .await
            .projection_map_snapshot()
            .iter()
            .any(|(key, _)| *key == packet)
    );
    controller.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn packet_dns_registration_requires_one_shared_budget_without_partial_ownership() {
    let controller = || {
        snapshot_controller(snapshot_forwarder(Arc::new(SnapshotUpstream {
            ip: [192, 0, 2, 1],
            calls: AtomicUsize::new(0),
            entered: None,
            release: None,
        })))
    };
    let first = controller();
    let second = controller();
    let target = controller();
    assert!(target.register_packet_scopes(&[]).is_err());
    let (a, _a_owner) = packet_scope(&first);
    let (b, _b_owner) = packet_scope(&second);
    let budget = a.budget();
    let before = budget.used();
    let error = target
        .register_packet_scopes(&[a.clone(), b.clone()])
        .unwrap_err();
    assert!(error.to_string().contains("share one memory budget"));
    assert!(!target.owns_packet_scope(a.scope()));
    assert!(!target.owns_packet_scope(b.scope()));
    assert_eq!(budget.used(), before);
    target
        .register_packet_scopes(std::slice::from_ref(&a))
        .unwrap();
    assert!(target.owns_packet_scope(a.scope()));
    assert!(budget.used() > before);
    for controller in [&first, &second, &target] {
        controller.shutdown(Duration::from_secs(1)).await;
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn auxiliary_rebind_fences_a_cached_query_waiting_for_publication() {
    use crate::dns::runtime::{
        DnsRuntime, DnsRuntimeParts, RoutingProjectionSnapshot, RuntimeGeneration,
    };

    let ip = [192, 0, 2, 17];
    let query = query_with_txid("example.com", 1);
    let (controller, upstream) = test_controller(a_response(&query, ip), Duration::ZERO);
    let router = Arc::new(
        Router::from_config(
            &honk_config::parser::parse_dae_config(
                "routing { domain(suffix: example.com) -> block\n fallback: direct }",
            )
            .unwrap()
            .routing,
        )
        .unwrap(),
    );
    let provider = controller.runtime_provider();
    let publish_runtime = |generation| {
        let snapshot = Arc::new(RoutingProjectionSnapshot::new(
            generation,
            Arc::clone(&router),
        ));
        provider.publish(DnsRuntime::new(DnsRuntimeParts {
            generation: RuntimeGeneration::new(generation),
            forwarder: controller.forwarder(),
            routing_projection: Arc::clone(&snapshot),
            outbound_runtime: None,
            transport: Arc::new(NoopRuntimeTransport),
        }));
        snapshot
    };
    let projection = &controller.routing_projection;
    let aux = ScopeId::allocate().unwrap();
    let lan = ScopeId::allocate().unwrap();
    let root = honk_netstack::MemoryBudget::new(4096);
    projection.register_aux_scopes(&[aux], &root).unwrap();
    projection
        .register_packet_scopes([lan, aux].into_iter(), &root)
        .unwrap();
    assert!(controller.try_admit_packet_query(false, aux).is_err());
    projection.set_aux_binding(aux, true).unwrap();
    let initial = publish_runtime(1);
    projection
        .prepare_snapshot_publication()
        .commit(initial, None);
    for scope in [lan, aux] {
        let admission = controller.try_admit_packet_query(false, scope).unwrap();
        let answer = controller
            .answer_query(
                &admission,
                &query,
                DnsRequestMeta::EMPTY,
                IngressProfile::Tcp,
            )
            .await;
        assert!(answer.wire().ends_with(&ip));
    }
    let fact = |scope, generation| {
        projection
            .packet_facts()
            .lookup(scope, ip.into(), &router, generation)
            .unwrap()
    };
    let (Some(_), physical_stamp) = fact(lan, 1) else {
        panic!("missing physical fact")
    };
    let (Some(_), old_stamp) = fact(aux, 1) else {
        panic!("missing auxiliary fact")
    };

    let next = publish_runtime(2);
    let held = controller.try_admit_packet_query(false, aux).unwrap();
    let outcome = controller
        .dns_service()
        .resolve_client_outcome_with_runtime(
            &held.runtime,
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Tcp,
            None,
        )
        .await
        .unwrap();
    assert_eq!(outcome.provenance(), crate::dns::outcome::Provenance::Cache);
    let delayed = controller.project_answer(&held.runtime, held.projection_scope, outcome);
    tokio::pin!(delayed);
    assert!(futures::poll!(delayed.as_mut()).is_pending());
    let address = "192.0.2.53:53".parse().unwrap();
    let peer = "192.0.2.1:41000".parse().unwrap();
    let (mut packet_client, mut packet_stream) = tokio::io::duplex(512);
    crate::dns::transport::write_length_prefixed(&mut packet_client, &query)
        .await
        .unwrap();
    let packet_tcp = controller.handle_packet_tcp_dns(&mut packet_stream, peer, address, aux);
    tokio::pin!(packet_tcp);
    assert!(futures::poll!(packet_tcp.as_mut()).is_pending());
    projection.set_aux_binding(aux, false).unwrap();
    assert!(!projection.packet_facts().is_current(old_stamp));
    assert!(projection.packet_facts().is_current(physical_stamp));
    let (_offline_client, mut offline_stream) = tokio::io::duplex(512);
    let error = controller
        .handle_packet_tcp_dns(&mut offline_stream, peer, address, aux)
        .await
        .unwrap_err();
    assert!(error.is::<PacketDnsScopeRetired>());
    projection.set_aux_binding(aux, true).unwrap();
    assert!(
        controller
            .try_admit_bound_query(false, Some(held.projection_scope))
            .is_err()
    );
    let (mut client, mut stream) = tcp_pair().await;
    let peer = stream.peer_addr().unwrap();
    write_tcp_query(&mut client, &query).await;
    tokio::io::AsyncWriteExt::shutdown(&mut client)
        .await
        .unwrap();
    controller
        .serve_bound_tcp_dns(&mut stream, peer, held.projection_scope)
        .await
        .unwrap();
    // Closing with an unread request can reset the client before it observes EOF.
    let mut unread = Vec::new();
    crate::dns::transport::read_length_prefixed_into(&mut stream, &mut unread, None)
        .await
        .unwrap();
    assert_eq!(unread, query);
    drop(stream);
    let mut reply = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut client, &mut reply)
        .await
        .unwrap();
    assert!(reply.is_empty());
    projection.prepare_snapshot_publication().commit(next, None);
    let error = tokio::time::timeout(Duration::from_secs(1), packet_tcp)
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.is::<PacketDnsScopeRetired>());
    let mut byte = [0; 1];
    let mut read = std::pin::pin!(tokio::io::AsyncReadExt::read(&mut packet_client, &mut byte));
    assert!(futures::poll!(&mut read).is_pending());
    assert!(delayed.await.unwrap().wire().ends_with(&ip));
    assert!(fact(aux, 2).0.is_none());
    let late = controller
        .answer_query(&held, &query, DnsRequestMeta::EMPTY, IngressProfile::Tcp)
        .await;
    assert!(late.wire().ends_with(&ip));
    assert!(fact(aux, 2).0.is_none());
    assert!(fact(lan, 2).0.is_some());
    let fresh = controller.try_admit_packet_query(false, aux).unwrap();
    controller
        .answer_query(&fresh, &query, DnsRequestMeta::EMPTY, IngressProfile::Tcp)
        .await;
    assert!(fact(aux, 2).0.is_some());
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
}

#[cfg(target_os = "linux")]
fn host_dns_test_router() -> Arc<Router> {
    Arc::new(
        Router::from_config(
            &honk_config::parser::parse_dae_config(
                "routing { domain(suffix: example.com) -> block\n fallback: direct }",
            )
            .unwrap()
            .routing,
        )
        .unwrap(),
    )
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn host_dns_fences_retired_executions_and_keeps_surviving_facts() {
    use crate::control::netstack::auxiliary_scope;
    use crate::dns::outcome::ProjectionSource;
    use crate::dns::projection::{ProjectionObservation, RoutingProjectionSnapshot};
    use honk_outbound::alive::IpVersion;
    use std::net::IpAddr;

    let (controller, _) = test_controller(Vec::new(), Duration::ZERO);
    let projection = &controller.routing_projection;
    let router = host_dns_test_router();
    let budget = honk_netstack::MemoryBudget::new(12 << 20);
    let (a, owner_a) = auxiliary_scope(1500, &budget).unwrap();
    let (b, owner_b) = auxiliary_scope(1500, &budget).unwrap();
    let shared = ScopeId::allocate().unwrap();
    let standalone = ScopeId::allocate().unwrap();
    let ports = [a, b];
    let [a, b] = &ports;
    projection
        .register_host_scopes(shared, standalone, &ports, &budget)
        .unwrap();
    controller.register_packet_scopes(&ports).unwrap();
    let (standalone_query, offline) = controller.listener_query_scopes(standalone);
    let offline = offline.unwrap();
    assert!(!projection.query_scope_is_current(offline));
    assert!(projection.packet_query_scope(shared).is_none());
    assert!(projection.set_host_binding(a.scope(), 2, true).is_err());

    let mut driver_a = owner_a.hand_off();
    let mut driver_b = owner_b.hand_off();
    driver_a.resume_auxiliary(1500, || true).unwrap();
    driver_b.resume_auxiliary(1500, || true).unwrap();
    let stamp_a = a.binding();
    let stamp_b = b.binding();
    projection
        .set_host_binding(a.scope(), stamp_a, true)
        .unwrap();
    projection
        .set_host_binding(b.scope(), stamp_b, true)
        .unwrap();
    let query_a = controller
        .try_admit_packet_query(false, a.scope())
        .unwrap()
        .projection_scope;
    let query_b = controller
        .try_admit_packet_query(false, b.scope())
        .unwrap()
        .projection_scope;
    let listener = controller.listener_query_scopes(standalone).1.unwrap();
    assert_ne!(query_a, query_b);

    let current = Arc::new(RoutingProjectionSnapshot::new(1, Arc::clone(&router)));
    projection
        .prepare_snapshot_publication()
        .commit(Arc::clone(&current), None);
    let retained = [IpAddr::from([192, 0, 2, 17])];
    let delayed = [IpAddr::from([192, 0, 2, 18])];
    let until = tokio::time::Instant::now() + Duration::from_secs(60);
    let positive = ProjectionObservation::Positive {
        domain: "example.com",
        family: IpVersion::V4,
        ips: &retained,
        expires_at: until,
        source: ProjectionSource::Fresh,
    };
    let cached = ProjectionObservation::Positive {
        domain: "example.com",
        family: IpVersion::V4,
        ips: &delayed,
        expires_at: until,
        source: ProjectionSource::CacheEntry(1),
    };
    let negative = ProjectionObservation::ClearName {
        domain: "example.com",
    };
    let bitmap = |scope, ip, generation| {
        controller
            .packet_domain_bitmap(scope, ip, &router, generation)
            .unwrap()
            .bitmap
    };
    assert!(projection.try_submit(query_a, &current, positive));
    assert!(projection.try_submit(standalone_query.unwrap(), &current, positive));
    assert!(bitmap(b.scope(), retained[0], 1).is_some());
    assert!(projection.try_submit_cache_hit(offline, &current, cached));
    assert!(bitmap(shared, delayed[0], 1).is_none());

    let next = Arc::new(RoutingProjectionSnapshot::new(2, Arc::clone(&router)));
    let waiting = projection
        .submit_after_publication(|| projection.try_submit_cache_hit(query_a, &next, cached));
    tokio::pin!(waiting);
    assert!(futures::poll!(waiting.as_mut()).is_pending());
    driver_a.begin_auxiliary_pause().unwrap();
    assert!(!projection.query_scope_is_current(query_a));
    assert!(projection.query_scope_is_current(listener));
    projection
        .set_host_binding(a.scope(), stamp_a, false)
        .unwrap();
    projection
        .prepare_snapshot_publication()
        .commit(Arc::clone(&next), None);
    waiting.await;
    assert!(projection.try_submit(query_a, &next, negative));
    assert!(projection.try_submit(query_b, &current, negative));
    assert!(bitmap(b.scope(), delayed[0], 2).is_none());
    assert!(bitmap(b.scope(), retained[0], 2).is_some());
    assert!(bitmap(a.scope(), retained[0], 2).is_none());

    projection
        .set_host_binding(b.scope(), stamp_b, false)
        .unwrap();
    driver_b.begin_auxiliary_pause().unwrap();
    driver_a.drain_auxiliary().await.unwrap();
    driver_a.resume_auxiliary(1500, || true).unwrap();
    projection
        .set_host_binding(a.scope(), a.binding(), true)
        .unwrap();
    assert!(!projection.query_scope_is_current(listener));
    assert!(projection.try_submit(listener, &next, positive));
    assert!(bitmap(shared, retained[0], 2).is_none());
    assert!(bitmap(standalone, retained[0], 2).is_some());
    let fresh = controller.try_admit_packet_query(false, a.scope()).unwrap();
    assert!(projection.try_submit(fresh.projection_scope, &next, positive));
    assert!(bitmap(shared, retained[0], 2).is_some());
    assert!(projection.try_submit(fresh.projection_scope, &next, negative));
    assert!(bitmap(shared, retained[0], 2).is_none());

    projection
        .set_host_binding(a.scope(), a.binding(), false)
        .unwrap();
    drop((fresh, driver_a, driver_b));
    owner_a.shutdown().await;
    owner_b.shutdown().await;
    controller.shutdown(Duration::from_secs(1)).await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires disposable XDP VM and real BPF maps"]
async fn kernel_gateway_host_dns_fences_queued_fills() {
    use crate::control::netstack::auxiliary_scope;
    use crate::dns::outcome::ProjectionSource;
    use crate::dns::projection::{ProjectionObservation, RoutingProjectionSnapshot};
    use crate::xdp::gateway::dns::GatewayDnsBank;
    use honk_ebpf_common::xdp_gateway::{GATEWAY_REALM_CAPACITY, GatewayDnsKey, LocalAddressKey};
    use honk_outbound::alive::IpVersion;
    use std::net::IpAddr;
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid only reads the calling process's credentials.
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(
        std::fs::read_to_string("/proc/cmdline")
            .unwrap()
            .contains("virtme.")
    );
    let netns = std::fs::metadata("/proc/self/ns/net").unwrap().ino();
    assert_ne!(netns, std::fs::metadata("/proc/1/ns/net").unwrap().ino());
    assert_ne!(
        netns.to_string(),
        std::env::var("HONK_XDP_PARENT_NETNS").unwrap()
    );
    assert_eq!(netns, std::fs::metadata("/run/netns/dut").unwrap().ino());
    assert!(matches!(
        std::env::var("HONK_CI_VM_LANE").as_deref(),
        Ok("floor" | "recent")
    ));
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap()
            .trim(),
        std::env::var("HONK_CI_EXPECTED_KERNEL").unwrap()
    );

    let (controller, _) = test_controller(Vec::new(), Duration::ZERO);
    let projection = &controller.routing_projection;
    let router = host_dns_test_router();
    let snapshot = Arc::new(RoutingProjectionSnapshot::new(1, Arc::clone(&router)));
    projection
        .prepare_snapshot_publication()
        .commit(Arc::clone(&snapshot), None);
    let budget = honk_netstack::MemoryBudget::new(32 << 20);
    let (a, owner_a) = auxiliary_scope(1500, &budget).unwrap();
    let (b, owner_b) = auxiliary_scope(1500, &budget).unwrap();
    let ports = [a, b];
    let [a, b] = &ports;
    let shared = ScopeId::allocate().unwrap();
    let standalone = ScopeId::allocate().unwrap();
    projection
        .register_host_scopes(shared, standalone, &ports, &budget)
        .unwrap();
    controller.register_packet_scopes(&ports).unwrap();
    let realm = GATEWAY_REALM_CAPACITY;
    let bank = GatewayDnsBank::new(&budget, [0; 32], &[(shared, realm)]).unwrap();
    assert!(projection.activate_gateway_dns(Some(Arc::clone(&bank)), 1, || true));
    assert!(bank.ticket(shared).is_none());

    let mut driver_a = owner_a.hand_off();
    let mut driver_b = owner_b.hand_off();
    driver_a.resume_auxiliary(1500, || true).unwrap();
    driver_b.resume_auxiliary(1500, || true).unwrap();
    projection
        .set_host_binding(a.scope(), a.binding(), true)
        .unwrap();
    projection
        .set_host_binding(b.scope(), b.binding(), true)
        .unwrap();
    let ips: Vec<_> = (1..=17).map(|i| IpAddr::from([192, 0, 2, i])).collect();
    let query_a = projection.packet_query_scope(a.scope()).unwrap();
    let query_b = projection.packet_query_scope(b.scope()).unwrap();
    assert!(projection.try_submit(
        query_a,
        &snapshot,
        ProjectionObservation::Positive {
            domain: "example.com",
            family: IpVersion::V4,
            ips: &ips,
            expires_at: tokio::time::Instant::now() + Duration::from_secs(60),
            source: ProjectionSource::Fresh,
        }
    ));
    let (_, epoch) = bank.ticket(shared).unwrap();
    let row = |ip| {
        bank.maps()
            .lookup(&GatewayDnsKey {
                export_epoch: epoch,
                realm_id: realm,
                reserved: 0,
                canonical_dst: LocalAddressKey::from(ip).address,
            })
            .unwrap()
    };
    let tail = ips[16];
    let facts = |scope| {
        projection
            .packet_domain_bitmap(scope, tail, &router, 1)
            .unwrap()
    };
    assert!(row(ips[0]).is_some());
    assert!(row(tail).is_none());
    projection.hot_fill_packet_domain(facts(a.scope()));
    let in_flight = bank.take_fill().unwrap();
    projection.hot_fill_packet_domain(facts(b.scope()));
    let delayed_a = facts(a.scope());
    projection
        .set_host_binding(a.scope(), a.binding(), false)
        .unwrap();
    assert_eq!(bank.ticket(shared), Some((realm, epoch)));
    assert_eq!(bank.take_fill().unwrap().query, query_b);
    projection.hot_fill_packet_domain(delayed_a);
    assert!(bank.take_fill().is_none());

    let skipped = bank.stats().skipped;
    assert!(bank.queue_fill(in_flight));
    tokio::time::timeout(Duration::from_secs(2), async {
        while bank.stats().skipped == skipped {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(row(tail).is_none());
    assert!(row(ips[0]).is_some());

    projection.hot_fill_packet_domain(facts(b.scope()));
    tokio::time::timeout(Duration::from_secs(2), async {
        while row(tail).is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    projection.hot_fill_packet_domain(facts(b.scope()));
    projection
        .set_host_binding(b.scope(), b.binding(), false)
        .unwrap();
    assert!(bank.ticket(shared).is_none());
    assert!(bank.take_fill().is_none());

    drop((driver_a, driver_b));
    owner_a.shutdown().await;
    owner_b.shutdown().await;
    controller.shutdown(Duration::from_secs(1)).await;
}
