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
async fn admitted_query_keeps_old_generation_quota_after_publication() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let controller = snapshot_controller(snapshot_forwarder(Arc::new(SnapshotUpstream {
        ip: [192, 0, 2, 9],
        calls: AtomicUsize::new(0),
        entered: Some(entered.clone()),
        release: Some(release.clone()),
    })));
    let old_admission = controller
        .try_admit_query(true)
        .expect("old-generation UDP admission");
    assert!(controller.try_admit_query(true).is_err());
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
    let new_admission = controller
        .try_admit_query(true)
        .expect("new-generation UDP quota must be independent");
    let new_response = tokio::time::timeout(
        Duration::from_secs(1),
        controller.answer_query(
            &new_admission,
            &crate::dns::forwarder::build_dns_query("example.com", 1),
            crate::dns::query::DnsRequestMeta::EMPTY,
            crate::dns::query::IngressProfile::Udp {
                advertised_size: 512,
            },
        ),
    )
    .await
    .expect("new query must complete while the predecessor remains blocked");
    assert_eq!(
        crate::dns::forwarder::extract_answer_ips(&new_response),
        ["198.51.100.9".parse::<std::net::IpAddr>().unwrap()]
    );
    assert!(!running.is_finished());

    release.notify_waiters();
    let old_response = running.await.expect("old-generation query task");
    assert_eq!(
        crate::dns::forwarder::extract_answer_ips(&old_response),
        ["192.0.2.9".parse::<std::net::IpAddr>().expect("old IP")]
    );
}

#[tokio::test]
async fn retirement_cancels_stalled_reply_but_allows_ready_servfail() {
    let (controller, _) = test_controller(Vec::new(), Duration::ZERO);
    let admission = controller.try_admit_query(true).unwrap();
    let ready_admission = controller.try_admit_query(true).unwrap();
    let (entered, started) = tokio::sync::oneshot::channel();
    let stalled = tokio::spawn(async move {
        admission
            .run_reply(async {
                entered.send(()).unwrap();
                std::future::pending::<()>().await;
            })
            .await
    });
    started.await.unwrap();
    controller.shutdown(Duration::from_secs(1)).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), stalled)
            .await
            .expect("retirement must cancel stalled reply I/O")
            .unwrap()
            .is_err()
    );

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
    let old_ips = running.await.expect("old lookup task");
    let new_ips = controller.resolve_domain("example.com").await;

    assert_eq!(
        old_ips,
        ["192.0.2.3".parse::<std::net::IpAddr>().expect("old IP")]
    );
    assert_eq!(
        new_ips,
        ["198.51.100.4".parse::<std::net::IpAddr>().expect("new IP")]
    );
}
