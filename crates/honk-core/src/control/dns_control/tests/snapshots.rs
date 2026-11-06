use super::*;

#[tokio::test]
async fn snapshot_publication_does_not_wait_for_answer_query_exchange() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let old = snapshot_forwarder(Arc::new(SnapshotUpstream {
        ip: [192, 0, 2, 1],
        calls: AtomicUsize::new(0),
        entered: Some(entered.clone()),
        release: Some(release.clone()),
    }));
    let controller = snapshot_controller(old);
    let query = crate::dns::forwarder::build_dns_query("example.com", 1);
    let running = {
        let controller = controller.clone();
        let query = query.clone();
        tokio::spawn(async move {
            controller
                .answer_query_for_test(
                    &query,
                    crate::dns::query::DnsRequestMeta::EMPTY,
                    crate::dns::query::IngressProfile::Internal,
                )
                .await
        })
    };
    entered.notified().await;
    let new = snapshot_forwarder(Arc::new(SnapshotUpstream {
        ip: [198, 51, 100, 2],
        calls: AtomicUsize::new(0),
        entered: None,
        release: None,
    }));

    let publication = tokio::time::timeout(
        Duration::from_millis(100),
        publish_snapshot_forwarder(&controller, new),
    )
    .await;
    if publication.is_err() {
        release.notify_waiters();
        let _ = running.await;
        panic!("snapshot publication waited for the old upstream exchange");
    }
    assert!(!running.is_finished(), "old query must remain paused");
    release.notify_waiters();
    let old_response = running.await.expect("old query task");
    let new_response = controller
        .answer_query_for_test(
            &query,
            crate::dns::query::DnsRequestMeta::EMPTY,
            crate::dns::query::IngressProfile::Internal,
        )
        .await;

    assert_eq!(
        crate::dns::forwarder::extract_answer_ips(&old_response),
        ["192.0.2.1".parse::<std::net::IpAddr>().expect("old IP")]
    );
    assert_eq!(
        crate::dns::forwarder::extract_answer_ips(&new_response),
        ["198.51.100.2".parse::<std::net::IpAddr>().expect("new IP")]
    );
}

#[tokio::test]
async fn admitted_query_keeps_shared_udp_quota_after_publication() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let controller = snapshot_controller(snapshot_forwarder(Arc::new(SnapshotUpstream {
        ip: [192, 0, 2, 9],
        calls: AtomicUsize::new(0),
        entered: Some(entered.clone()),
        release: Some(release.clone()),
    })));
    let old_admission = controller
        .try_admit_packet_query(true)
        .expect("old-generation packet UDP admission");
    assert!(controller.try_admit_query(true).is_err());
    assert!(controller.try_admit_packet_query(true).is_err());
    let query = crate::dns::forwarder::build_dns_query("example.com", 1);
    let running = {
        let controller = controller.clone();
        tokio::spawn(async move {
            controller
                .answer_query(
                    &old_admission,
                    &query,
                    crate::dns::query::DnsRequestMeta::EMPTY,
                    crate::dns::query::IngressProfile::Udp {
                        advertised_size: 512,
                    },
                )
                .await
        })
    };
    entered.notified().await;

    publish_snapshot_forwarder(
        &controller,
        snapshot_forwarder(Arc::new(SnapshotUpstream {
            ip: [198, 51, 100, 9],
            calls: AtomicUsize::new(0),
            entered: None,
            release: None,
        })),
    )
    .await;
    assert!(controller.try_admit_query(true).is_err());
    assert!(controller.try_admit_packet_query(true).is_err());
    let new_admission = controller
        .try_admit_query(false)
        .expect("TCP remains admissible while the shared UDP quota is occupied");
    let new_response = tokio::time::timeout(
        Duration::from_secs(1),
        controller.answer_query(
            &new_admission,
            &crate::dns::forwarder::build_dns_query("example.com", 1),
            crate::dns::query::DnsRequestMeta::EMPTY,
            crate::dns::query::IngressProfile::Tcp,
        ),
    )
    .await
    .expect("new query must complete while the predecessor remains blocked");
    assert_eq!(
        crate::dns::forwarder::extract_answer_ips(new_response.wire()),
        ["198.51.100.9".parse::<std::net::IpAddr>().unwrap()]
    );
    assert!(!running.is_finished());

    release.notify_waiters();
    let old_response = running.await.expect("old-generation query task");
    assert_eq!(
        crate::dns::forwarder::extract_answer_ips(old_response.wire()),
        ["192.0.2.9".parse::<std::net::IpAddr>().expect("old IP")]
    );
    let _new_udp = controller
        .try_admit_query(true)
        .expect("old query completion releases its shared UDP permit");
    assert!(controller.try_admit_query(true).is_err());
}

#[tokio::test]
async fn forced_retirement_does_not_reissue_held_udp_permits() {
    let forwarder = || {
        snapshot_forwarder(Arc::new(SnapshotUpstream {
            ip: [192, 0, 2, 9],
            calls: AtomicUsize::new(0),
            entered: None,
            release: None,
        }))
    };
    let controller = snapshot_controller(forwarder());
    let held = controller.try_admit_packet_query(true).unwrap();
    for _ in 0..=crate::dns::runtime::MAX_RETIRED_RUNTIMES {
        publish_snapshot_forwarder(&controller, forwarder()).await;
        assert!(controller.try_admit_query(true).is_err());
        assert!(controller.try_admit_packet_query(true).is_err());
    }
    tokio::time::timeout(Duration::from_secs(1), held.runtime.runtime().wait_closed())
        .await
        .expect("cap-evicted generation closes even while its caller retains admission");
    assert!(controller.try_admit_query(true).is_err());
    assert!(controller.try_admit_packet_query(true).is_err());
    let _tcp = controller
        .try_admit_query(false)
        .expect("TCP remains admissible");
    drop(held);
    let _udp = controller
        .try_admit_query(true)
        .expect("caller drop returns the shared permit");
    assert!(controller.try_admit_query(true).is_err());
}

#[tokio::test]
async fn retirement_cancels_stalled_reply_but_allows_ready_servfail() {
    let (controller, _) = test_controller(Vec::new(), Duration::ZERO);
    let admission = controller.try_admit_query(true).unwrap();
    let ready_admission = controller.try_admit_query(true).unwrap();
    let (entered, started) = tokio::sync::oneshot::channel();
    let mut stalled = tokio::spawn(async move {
        admission
            .run_reply(async {
                entered.send(()).unwrap();
                std::future::pending::<()>().await;
            })
            .await
    });
    started.await.unwrap();
    let shutdown = controller.shutdown(Duration::from_secs(1));
    tokio::pin!(shutdown);
    let cancelled = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::select! {
            biased;
            _ = &mut shutdown => panic!("shutdown acknowledged a retained DNS reply lease"),
            result = &mut stalled => result.unwrap(),
        }
    })
    .await
    .expect("retirement must cancel stalled reply I/O");
    assert!(cancelled.is_err());

    let (reply, received) = tokio::sync::oneshot::channel();
    ready_admission
        .run_reply(async {
            reply.send(crate::dns::response::build_dns_servfail(
                &crate::dns::forwarder::build_dns_query("example.com", 1),
            ))
        })
        .await
        .expect("ready terminal reply must win over retirement")
        .unwrap();
    assert_eq!(received.await.unwrap()[3] & 0x0f, 2);
    drop(ready_admission);
    tokio::time::timeout(Duration::from_secs(1), shutdown)
        .await
        .expect("released replies must allow shutdown to join");
}

#[tokio::test]
async fn resolve_domain_keeps_old_snapshot_without_blocking_publication() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let old = snapshot_forwarder(Arc::new(SnapshotUpstream {
        ip: [192, 0, 2, 3],
        calls: AtomicUsize::new(0),
        entered: Some(entered.clone()),
        release: Some(release.clone()),
    }));
    let controller = snapshot_controller(old);
    let running = {
        let controller = controller.clone();
        tokio::spawn(async move { controller.resolve_domain("example.com").await })
    };
    entered.notified().await;
    let new = snapshot_forwarder(Arc::new(SnapshotUpstream {
        ip: [198, 51, 100, 4],
        calls: AtomicUsize::new(0),
        entered: None,
        release: None,
    }));

    let publication = tokio::time::timeout(
        Duration::from_millis(100),
        publish_snapshot_forwarder(&controller, new),
    )
    .await;
    if publication.is_err() {
        release.notify_waiters();
        let _ = running.await;
        panic!("snapshot publication waited for resolve_domain");
    }
    assert!(!running.is_finished(), "old lookup must remain paused");
    release.notify_waiters();
    let old_ips = running
        .await
        .expect("old lookup task")
        .expect("old lookup result");
    let new_ips = controller
        .resolve_domain("example.com")
        .await
        .expect("new lookup result");

    assert_eq!(
        old_ips,
        ["192.0.2.3".parse::<std::net::IpAddr>().expect("old IP")]
    );
    assert_eq!(
        new_ips,
        ["198.51.100.4".parse::<std::net::IpAddr>().expect("new IP")]
    );
}

#[tokio::test(start_paused = true)]
async fn projection_rollback_preserves_cached_deadline() {
    for expire_while_waiting in [false, true] {
        let upstream = Arc::new(SnapshotUpstream {
            ip: [192, 0, 2, 10],
            calls: AtomicUsize::new(0),
            entered: None,
            release: None,
        });
        let forwarder = Arc::new(DnsForwarder::new(
            upstream.clone(),
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                16,
            ))),
            Arc::new(
                crate::dns::routing::DnsRouter::new_from_dns_config(
                    &honk_config::dns::DnsConfig::default(),
                )
                .unwrap(),
            ),
        ));
        let (controller, _) = projection_controller(forwarder);
        let admission = controller.try_admit_query(true).unwrap();
        let runtime = admission.runtime.runtime();
        let snapshot = Arc::clone(runtime.routing_projection());
        let query = query_with_txid("example.com", 0x3141);
        let ingress = IngressProfile::Udp {
            advertised_size: 512,
        };
        let warm = controller
            .dns_service
            .resolve_client_outcome_with_runtime(
                &admission.runtime,
                &query,
                DnsRequestMeta::EMPTY,
                ingress,
                None,
            )
            .await
            .unwrap();
        let lifetime = warm.expiry().ttl();
        assert!(lifetime > Duration::from_secs(2));
        let original_deadline = tokio::time::Instant::now() + lifetime;
        let publication = controller.prepare_projection_publication();
        let mut answer =
            Box::pin(controller.answer_query(&admission, &query, DnsRequestMeta::EMPTY, ingress));
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(answer.as_mut().poll(cx).is_pending())
            })
            .await
        );
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(if expire_while_waiting {
            lifetime + Duration::from_secs(1)
        } else {
            lifetime / 2
        })
        .await;
        // A rejected publication retains the generation instead of fencing this answer out.
        drop(publication);
        let answer = tokio::time::timeout(Duration::from_secs(1), answer)
            .await
            .unwrap();
        let outcome = answer.0.unwrap();
        assert_eq!(outcome.provenance(), crate::dns::outcome::Provenance::Cache);
        if expire_while_waiting {
            assert!(
                controller.project_routes(&snapshot).is_empty(),
                "an expired answer must not be available for a reload prefill"
            );
        } else {
            assert_eq!(
                controller.project_routes(&snapshot)[0].0,
                "192.0.2.10".parse::<std::net::IpAddr>().unwrap()
            );
            tokio::time::advance(
                original_deadline.saturating_duration_since(tokio::time::Instant::now())
                    + Duration::from_secs(1),
            )
            .await;
            controller.routing_projection.submit(
                Arc::clone(&snapshot),
                crate::dns::projection::ProjectionObservation::Retain,
            );
            assert!(
                controller.project_routes(&snapshot).is_empty(),
                "publication waiting must not restart the cached routing lifetime"
            );
        }
        drop(admission);
        controller.shutdown(Duration::from_secs(1)).await;
    }
}

#[tokio::test(start_paused = true)]
async fn projection_wait_cancellation_releases_lease_without_publishing() {
    for release_with_cancellation in [false, true] {
        let upstream = Arc::new(SnapshotUpstream {
            ip: [192, 0, 2, 11],
            calls: AtomicUsize::new(0),
            entered: None,
            release: None,
        });
        let (controller, _) = projection_controller(snapshot_forwarder(upstream.clone()));
        let provider = controller.runtime_provider();
        let snapshot = Arc::clone(provider.current().routing_projection());
        let admission = controller.try_admit_query(true).unwrap();
        let query = query_with_txid("example.com", 0x2718);
        let mut publication = Some(controller.prepare_projection_publication());
        let mut answer = Box::pin(async {
            let answer = controller
                .answer_query(
                    &admission,
                    &query,
                    DnsRequestMeta::EMPTY,
                    IngressProfile::Udp {
                        advertised_size: 512,
                    },
                )
                .await;
            drop(admission);
            answer
        });
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(answer.as_mut().poll(cx).is_pending())
            })
            .await
        );
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
        provider.begin_pause();
        if release_with_cancellation {
            drop(publication.take());
        }
        let answer = tokio::time::timeout(Duration::from_secs(1), answer)
            .await
            .expect("runtime cancellation must stop the projection waiter");
        assert_eq!(answer.wire()[3] & 0x0f, 2);
        assert_eq!(provider.current().lease_count(), 0);
        assert!(controller.project_routes(&snapshot).is_empty());
        tokio::time::timeout(Duration::from_secs(1), provider.finish_pause())
            .await
            .unwrap()
            .unwrap();
        drop(publication);
        controller.shutdown(Duration::from_secs(1)).await;
    }
}
