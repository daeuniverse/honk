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
