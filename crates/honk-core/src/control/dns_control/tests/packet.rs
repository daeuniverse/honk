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
