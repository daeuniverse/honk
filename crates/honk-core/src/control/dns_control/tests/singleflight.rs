use super::*;

#[test]
fn udp_profile_uses_exact_edns_advertised_size() {
    let mut query = query_with_txid("example.com", 1);
    query[10..12].copy_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);

    assert_eq!(
        crate::dns::query::udp_ingress_profile(&query),
        crate::dns::query::IngressProfile::Udp {
            advertised_size: 1232,
        }
    );
    assert_eq!(
        crate::dns::query::udp_ingress_profile(&query_with_txid("example.com", 2)),
        crate::dns::query::IngressProfile::Udp {
            advertised_size: 512,
        }
    );
}

#[tokio::test]
async fn singleflight_dedups_and_restores_txid() {
    let (controller, upstream) = test_controller(
        response_with_txid("example.com", 0x1111),
        Duration::from_millis(100),
    );
    let first = query_with_txid("example.com", 0xaaaa);
    let second = query_with_txid("example.com", 0xbbbb);

    let (first_response, second_response) = tokio::join!(
        controller.answer_query_for_test(
            &first,
            crate::dns::query::DnsRequestMeta::EMPTY,
            crate::dns::query::IngressProfile::Internal,
        ),
        controller.answer_query_for_test(
            &second,
            crate::dns::query::DnsRequestMeta::EMPTY,
            crate::dns::query::IngressProfile::Internal,
        ),
    );

    assert_eq!(&first_response[0..2], &first[0..2]);
    assert_eq!(&second_response[0..2], &second[0..2]);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
}

fn query_with_edns_option(txid: u16) -> Vec<u8> {
    let mut query = query_with_txid("example.com", txid);
    query[10..12].copy_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 5, 0, 12, 0, 1, 0]);
    query
}

#[tokio::test]
async fn ineligible_queries_bypass_singleflight() {
    let (controller, upstream) = test_controller(
        response_with_txid("example.com", 0x1111),
        Duration::from_millis(100),
    );
    let first = query_with_edns_option(0xaaaa);
    let second = query_with_edns_option(0xbbbb);

    let _ = tokio::join!(
        controller.answer_query_for_test(
            &first,
            crate::dns::query::DnsRequestMeta::EMPTY,
            crate::dns::query::IngressProfile::Internal,
        ),
        controller.answer_query_for_test(
            &second,
            crate::dns::query::DnsRequestMeta::EMPTY,
            crate::dns::query::IngressProfile::Internal,
        ),
    );

    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn expired_singleflight_waiter_keeps_successor_route() {
    struct ChangingUpstream(AtomicUsize);
    #[async_trait::async_trait]
    impl DnsUpstreamPool for ChangingUpstream {
        async fn query(&self, _: &str, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
            let first = self.0.fetch_add(1, Ordering::SeqCst) == 0;
            if first {
                tokio::task::yield_now().await;
            }
            Ok(a_response(raw, [192, 0, 2, if first { 1 } else { 2 }]))
        }
    }

    let upstream = Arc::new(ChangingUpstream(AtomicUsize::new(0)));
    let forwarder = Arc::new(
        DnsForwarder::new(
            upstream.clone(),
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(8))),
            Arc::new(
                crate::dns::routing::DnsRouter::new_from_dns_config(&Default::default()).unwrap(),
            ),
        )
        .with_cache_enabled(false),
    );
    let (controller, _) = projection_controller(forwarder);
    let snapshot = Arc::clone(controller.runtime_provider().current().routing_projection());
    let query = query_with_txid("example.com", 1);
    let answer = || {
        controller.answer_query_for_test(&query, DnsRequestMeta::EMPTY, IngressProfile::Internal)
    };
    let ips = crate::dns::forwarder::extract_answer_ips;
    let old = std::net::IpAddr::from([192, 0, 2, 1]);
    let new = std::net::IpAddr::from([192, 0, 2, 2]);
    let leader = answer();
    let waiter = answer();
    tokio::pin!(leader, waiter);
    assert!(futures::poll!(leader.as_mut()).is_pending());
    assert!(futures::poll!(waiter.as_mut()).is_pending());
    assert_eq!(ips(&leader.await), [old]);
    tokio::time::advance(Duration::from_secs(31)).await;
    assert_eq!(ips(&answer().await), [new]);
    assert_eq!(controller.project_routes(&snapshot)[0].0, new);
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(ips(&waiter.await), [old]);
    assert_eq!(upstream.0.load(Ordering::SeqCst), 2);
    let routes = controller.project_routes(&snapshot);
    assert_eq!(
        routes.iter().map(|(ip, _)| *ip).collect::<Vec<_>>(),
        [new],
        "expired waiter withdrew the successor route"
    );
    tokio::time::advance(Duration::from_secs(20)).await;
    controller.routing_projection.submit(
        ScopeId::HOST,
        Arc::clone(&snapshot),
        crate::dns::projection::ProjectionObservation::Retain,
    );
    assert!(controller.project_routes(&snapshot).is_empty());
    controller.shutdown(Duration::from_secs(1)).await;
}
