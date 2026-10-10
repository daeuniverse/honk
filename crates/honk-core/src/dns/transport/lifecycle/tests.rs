use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::idle_pool::{IdlePoolState, close_idle_pool, idle_pool_exchange};
use super::*;
use std::time::Duration;

use honk_config::dns::{DnsRouting, DnsUpstream};
use honk_config::node::Node;
use honk_config::types::{DnsProtocol, NodeProtocol};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;

use crate::dns::forwarder::DnsUpstreamPool;
use crate::dns::routing::DnsRouter;
use crate::dns::upstream_pool::UpstreamPool;
use crate::routing::Router;

#[tokio::test]
async fn acquisition_initializes_once_when_128_callers_race() {
    let before = crate::stats::dns_snapshot();
    // Given
    let slot = Arc::new(LifecycleSlot::new());
    let initializations = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(tokio::sync::Barrier::new(128));
    let mut callers = tokio::task::JoinSet::new();
    for _ in 0..128 {
        let slot = Arc::clone(&slot);
        let initializations = Arc::clone(&initializations);
        let gate = Arc::clone(&gate);
        callers.spawn(async move {
            gate.wait().await;
            slot.acquire(|| async {
                initializations.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
                Ok::<_, anyhow::Error>(7_u8)
            })
            .await
            .map(|(value, _)| value)
        });
    }

    // When
    while let Some(result) = callers.join_next().await {
        assert_eq!(*result.expect("caller task").expect("acquire"), 7);
    }

    // Then
    assert_eq!(initializations.load(Ordering::SeqCst), 1);
    assert_eq!(slot.init_count(), 1);
    assert_eq!(slot.state(), LifecycleState::Ready);
    assert!(crate::stats::dns_snapshot().delta(before).transport_init >= 1);
}

#[tokio::test]
async fn builder_abort_wakes_waiters_and_allows_recovery() {
    // Given
    let slot = Arc::new(LifecycleSlot::new());
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (_release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let leader_slot = Arc::clone(&slot);
    let leader = tokio::spawn(async move {
        leader_slot
            .acquire(|| async move {
                let _ = started_tx.send(());
                let _ = release_rx.await;
                Ok::<_, anyhow::Error>(1_u8)
            })
            .await
            .map(|(value, _)| value)
    });
    started_rx.await.expect("builder started");
    let gate = Arc::new(tokio::sync::Barrier::new(129));
    let mut waiters = tokio::task::JoinSet::new();
    for _ in 0..128 {
        let slot = Arc::clone(&slot);
        let gate = Arc::clone(&gate);
        waiters.spawn(async move {
            gate.wait().await;
            slot.acquire(|| async { Ok::<_, anyhow::Error>(2_u8) })
                .await
                .map(|(value, _)| value)
        });
    }
    gate.wait().await;
    tokio::task::yield_now().await;

    // When
    leader.abort();
    let _ = leader.await;

    // Then
    while let Some(result) = waiters.join_next().await {
        let error = result
            .expect("waiter task")
            .expect_err("cancelled generation fails");
        assert!(error.to_string().contains("cancelled"));
    }
    let recovered = slot
        .acquire(|| async { Ok::<_, anyhow::Error>(3_u8) })
        .await
        .map(|(value, _)| value)
        .expect("retry succeeds");
    assert_eq!(*recovered, 3);
    assert_eq!(slot.init_count(), 2);
}

#[tokio::test]
async fn builder_error_is_fanned_out_to_waiters() {
    // Given
    let slot = Arc::new(LifecycleSlot::new());
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let leader_slot = Arc::clone(&slot);
    let leader = tokio::spawn(async move {
        leader_slot
            .acquire(|| async move {
                let _ = started_tx.send(());
                let _ = release_rx.await;
                Err(
                    anyhow::Error::new(honk_outbound::proxy::PacketRejection::Policy)
                        .context("malformed handshake"),
                )
            })
            .await
            .map(|(value, _)| value)
    });
    started_rx.await.expect("builder started");
    let gate = Arc::new(tokio::sync::Barrier::new(129));
    let mut waiters = tokio::task::JoinSet::new();
    for _ in 0..128 {
        let slot = Arc::clone(&slot);
        let gate = Arc::clone(&gate);
        waiters.spawn(async move {
            gate.wait().await;
            slot.acquire(|| async { Ok::<_, anyhow::Error>(9_u8) })
                .await
                .map(|(value, _)| value)
        });
    }
    gate.wait().await;
    tokio::task::yield_now().await;

    // When
    release_tx.send(()).expect("release builder");

    // Then
    let assert_shared_error = |error: anyhow::Error| {
        assert!(error.to_string().contains("malformed handshake"));
        assert!(honk_outbound::proxy::is_packet_rejection(&error));
        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<honk_outbound::proxy::PacketRejection>(),
            Some(&honk_outbound::proxy::PacketRejection::Policy)
        );
    };
    assert_shared_error(
        leader
            .await
            .expect("leader task")
            .expect_err("builder fails"),
    );
    while let Some(result) = waiters.join_next().await {
        assert_shared_error(
            result
                .expect("waiter task")
                .expect_err("same generation fails"),
        );
    }
}

#[tokio::test]
async fn close_is_idempotent() {
    // Given
    let slot = LifecycleSlot::new();
    let closes = Arc::new(AtomicUsize::new(0));
    slot.acquire(|| async { Ok::<_, anyhow::Error>(5_u8) })
        .await
        .map(|(value, _)| value)
        .expect("resource");

    // When
    let first_closes = Arc::clone(&closes);
    slot.close(move |_| async move {
        first_closes.fetch_add(1, Ordering::SeqCst);
    })
    .await;
    let second_closes = Arc::clone(&closes);
    slot.close(move |_| async move {
        second_closes.fetch_add(1, Ordering::SeqCst);
    })
    .await;

    // Then
    assert_eq!(closes.load(Ordering::SeqCst), 1);
    assert_eq!(slot.close_count(), 1);
    assert_eq!(slot.state(), LifecycleState::Closed);
}

#[tokio::test]
async fn repeated_builder_interruption_never_leaves_a_stale_slot() {
    // Given
    let slot = Arc::new(LifecycleSlot::new());

    // When
    for _ in 0..3 {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let slot_for_builder = Arc::clone(&slot);
        let builder = tokio::spawn(async move {
            slot_for_builder
                .acquire(|| async move {
                    let _ = started_tx.send(());
                    std::future::pending::<anyhow::Result<u8>>().await
                })
                .await
                .map(|(value, _)| value)
        });
        started_rx.await.expect("builder started");
        builder.abort();
        let _ = builder.await;
        assert_eq!(slot.state(), LifecycleState::Closed);
    }
    let value = slot
        .acquire(|| async { Ok::<_, anyhow::Error>(11_u8) })
        .await
        .map(|(value, _)| value)
        .expect("recovered resource");

    // Then
    assert_eq!(*value, 11);
    assert_eq!(slot.init_count(), 4);
}

#[tokio::test]
async fn cancelled_close_preserves_cleanup_for_waiting_close() {
    let slot = LifecycleSlot::new();
    let resource = slot
        .acquire(|| async { Ok::<_, anyhow::Error>(AtomicUsize::new(0)) })
        .await
        .map(|(value, _)| value)
        .expect("resource");
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mut first = Box::pin(slot.close(|resource| async move {
        release_rx.await.expect("release original cleanup");
        resource.fetch_add(1, Ordering::SeqCst);
    }));
    assert!(futures::poll!(first.as_mut()).is_pending());
    let mut second = Box::pin(slot.close(|_| async {
        panic!("a second closer must not replace the original cleanup");
    }));
    assert!(futures::poll!(second.as_mut()).is_pending());

    drop(first);
    assert!(futures::poll!(second.as_mut()).is_pending());
    release_tx.send(()).expect("original cleanup retained");
    tokio::time::timeout(Duration::from_secs(1), second)
        .await
        .expect("waiting close finishes original cleanup");

    assert_eq!(resource.load(Ordering::SeqCst), 1);
    assert_eq!(slot.close_count(), 1);
    assert_eq!(slot.state(), LifecycleState::Closed);
}

#[tokio::test]
async fn cancelled_close_allows_acquire_to_finish_original_teardown() {
    let slot = LifecycleSlot::new();
    let resource = slot
        .acquire(|| async { Ok::<_, anyhow::Error>(AtomicUsize::new(0)) })
        .await
        .map(|(value, _)| value)
        .expect("resource");
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mut closing = Box::pin(slot.close(|resource| async move {
        release_rx.await.expect("release original cleanup");
        resource.store(1, Ordering::SeqCst);
    }));
    assert!(futures::poll!(closing.as_mut()).is_pending());
    drop(closing);

    let mut acquiring = Box::pin(slot.acquire(|| async {
        assert_eq!(resource.load(Ordering::SeqCst), 1, "cleanup precedes build");
        Ok::<_, anyhow::Error>(AtomicUsize::new(0))
    }));
    assert!(futures::poll!(acquiring.as_mut()).is_pending());
    release_tx.send(()).expect("original cleanup retained");
    let (replacement, _) = tokio::time::timeout(Duration::from_secs(1), acquiring)
        .await
        .expect("ordinary acquire resumes teardown")
        .expect("replacement");

    assert!(!Arc::ptr_eq(&resource, &replacement));
    assert_eq!(resource.load(Ordering::SeqCst), 1);
    assert_eq!(replacement.load(Ordering::SeqCst), 0);
    assert_eq!(slot.init_count(), 2);
    assert_eq!(slot.close_count(), 1);
}

#[tokio::test]
async fn retained_failure_does_not_keep_driver_alive() {
    use super::super::owned_task::OwnedTask;

    let active = Arc::new(AtomicUsize::new(0));
    let (started, running) = tokio::sync::oneshot::channel();
    let slot = LifecycleSlot::new();
    let session = slot
        .acquire(|| async {
            Ok(OwnedTask::spawn(
                async move {
                    started.send(()).unwrap();
                    std::future::pending::<()>().await;
                },
                Arc::clone(&active),
            ))
        })
        .await
        .map(|(value, _)| value)
        .unwrap();
    running.await.unwrap();
    let error = anyhow::Error::new(SessionFailure::new(
        session,
        std::io::Error::from(std::io::ErrorKind::ConnectionReset).into(),
    ));
    drop(slot);
    tokio::time::timeout(Duration::from_secs(1), async {
        while active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retaining an error must not retain its driver");
    assert_eq!(
        error
            .root_cause()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind(),
        std::io::ErrorKind::ConnectionReset
    );
    assert!(SessionFailure::<OwnedTask>::session(&error).is_none());
}

#[tokio::test]
async fn stale_retirement_cannot_close_a_replacement() {
    let slot = LifecycleSlot::new();
    let original = slot
        .acquire(|| async { Ok::<_, anyhow::Error>(AtomicUsize::new(0)) })
        .await
        .map(|(value, _)| value)
        .expect("original");
    let failure = anyhow::Error::new(SessionFailure::new(
        Arc::clone(&original),
        anyhow::Error::new(honk_outbound::proxy::PacketRejection::Capacity)
            .context("query refused"),
    ));
    let failure = anyhow::Error::new(SharedError::new(failure)).context("upstream exchange");
    assert!(honk_outbound::proxy::is_packet_rejection(&failure));

    slot.retire(&original, |resource| async move {
        resource.fetch_add(1, Ordering::SeqCst);
    })
    .await;
    let observed = SessionFailure::<AtomicUsize>::session(&failure).expect("failed session");
    let replacement = slot
        .acquire(|| async { Ok::<_, anyhow::Error>(AtomicUsize::new(0)) })
        .await
        .map(|(value, _)| value)
        .expect("replacement");

    slot.retire(&observed, |resource| async move {
        resource.fetch_add(1, Ordering::SeqCst);
    })
    .await;
    let current = slot
        .acquire(|| async { panic!("replacement must remain available") })
        .await
        .map(|(value, _)| value)
        .expect("current session");
    assert!(Arc::ptr_eq(&current, &replacement));
    assert_eq!(replacement.load(Ordering::SeqCst), 0);
    assert_eq!(original.load(Ordering::SeqCst), 1);
    assert_eq!(slot.close_count(), 1);
}

#[tokio::test]
async fn stale_retirement_does_not_wait_for_another_build() {
    let slot = LifecycleSlot::new();
    let original = slot
        .acquire(|| async { Ok::<_, anyhow::Error>(1_u8) })
        .await
        .map(|(value, _)| value)
        .expect("original");
    slot.retire(&original, |_| async {}).await;
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mut building = Box::pin(slot.acquire(|| async move {
        release_rx.await.expect("release replacement build");
        Ok::<_, anyhow::Error>(2_u8)
    }));
    assert!(futures::poll!(building.as_mut()).is_pending());

    tokio::time::timeout(
        Duration::from_secs(1),
        slot.retire(&original, |_| async { panic!("cannot retire a builder") }),
    )
    .await
    .expect("stale retirement does not wait for a different build");
    release_tx.send(()).expect("release replacement");
    assert_eq!(*building.await.expect("replacement").0, 2);
    assert_eq!(slot.close_count(), 1);
}

#[tokio::test]
async fn concurrent_closer_cannot_close_a_replacement() {
    let slot = LifecycleSlot::new();
    let original = slot
        .acquire(|| async { Ok::<_, anyhow::Error>(AtomicUsize::new(0)) })
        .await
        .map(|(value, _)| value)
        .expect("original");
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mut first = Box::pin(slot.close(|resource| async move {
        release_rx.await.expect("release original cleanup");
        resource.fetch_add(1, Ordering::SeqCst);
    }));
    assert!(futures::poll!(first.as_mut()).is_pending());
    let mut second = Box::pin(slot.close(|resource| async move {
        resource.fetch_add(1, Ordering::SeqCst);
    }));
    assert!(futures::poll!(second.as_mut()).is_pending());

    release_tx.send(()).expect("release original");
    first.await;
    let replacement = slot
        .acquire(|| async { Ok::<_, anyhow::Error>(AtomicUsize::new(0)) })
        .await
        .map(|(value, _)| value)
        .expect("replacement");
    second.await;

    let current = slot
        .acquire(|| async { panic!("replacement must remain available") })
        .await
        .map(|(value, _)| value)
        .expect("current session");
    assert!(Arc::ptr_eq(&current, &replacement));
    assert_eq!(original.load(Ordering::SeqCst), 1);
    assert_eq!(replacement.load(Ordering::SeqCst), 0);
    assert_eq!(slot.close_count(), 1);
}
async fn assert_close_excludes_inflight_return() {
    // Given
    let lifecycle = Arc::new(tokio::sync::RwLock::new(IdlePoolState::Open));
    let idle = Arc::new(Mutex::new(Vec::<DuplexStream>::new()));
    let (client, mut server) = tokio::io::duplex(256);
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let mut length = [0_u8; 2];
        server.read_exact(&mut length).await.expect("query length");
        let mut query = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        server.read_exact(&mut query).await.expect("query");
        let _ = request_tx.send(());
        let _ = response_rx.await;
        let response = [0_u8; 12];
        server
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .expect("response length");
        server.write_all(&response).await.expect("response");
    });
    let exchange_lifecycle = Arc::clone(&lifecycle);
    let exchange_idle = Arc::clone(&idle);
    let exchange = tokio::spawn(async move {
        idle_pool_exchange(
            &exchange_lifecycle,
            &exchange_idle,
            || async { Ok::<_, anyhow::Error>(client) },
            &[0_u8; 12],
            Duration::from_secs(1),
            None,
        )
        .await
    });
    request_rx.await.expect("exchange in flight");
    let close_lifecycle = Arc::clone(&lifecycle);
    let close_idle = Arc::clone(&idle);
    let mut close = tokio::spawn(async move {
        close_idle_pool(&close_lifecycle, &close_idle, Duration::from_secs(1)).await;
    });

    // When
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut close)
            .await
            .is_err(),
        "close returned before the exchange lease"
    );
    response_tx.send(()).expect("release response");
    exchange
        .await
        .expect("exchange task")
        .expect("exchange response");
    close.await.expect("close task");
    server_task.await.expect("server task");

    // Then
    assert_eq!(idle.lock().len(), 0);
    let error = idle_pool_exchange(
        &lifecycle,
        &idle,
        || async { Ok::<_, anyhow::Error>(tokio::io::duplex(64).0) },
        &[0_u8; 12],
        Duration::from_secs(1),
        None,
    )
    .await
    .expect_err("closed pool rejects exchange");
    assert!(error.to_string().contains("closed"));
}

#[tokio::test]
async fn tcp_inflight_stream_cannot_return_after_close() {
    assert_close_excludes_inflight_return().await;
}

#[tokio::test]
async fn dot_inflight_stream_cannot_return_after_close() {
    assert_close_excludes_inflight_return().await;
}
#[tokio::test]
async fn tcp_transport_lifecycle_is_single_flight_and_closes_once() {
    // Given
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        for _ in 0..128 {
            let (mut stream, _) = listener.accept().await.expect("accept");
            connections.spawn(async move {
                let mut length = [0_u8; 2];
                stream.read_exact(&mut length).await.expect("query length");
                let query_length = usize::from(u16::from_be_bytes(length));
                let mut query = vec![0_u8; query_length];
                stream.read_exact(&mut query).await.expect("query");
                let mut response = vec![0_u8; 12];
                response[..2].copy_from_slice(&query[..2]);
                response[2] = 0x81;
                response[3] = 0x80;
                stream
                    .write_all(&(response.len() as u16).to_be_bytes())
                    .await
                    .expect("response length");
                stream.write_all(&response).await.expect("response");
            });
        }
        while let Some(connection) = connections.join_next().await {
            connection.expect("connection task");
        }
    });
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            fallback: "tcp".to_string(),
            ..Default::default()
        })
        .expect("router"),
    );
    let pool = Arc::new(
        UpstreamPool::new(
            &[DnsUpstream {
                name: "tcp".to_string(),
                address: address.to_string(),
                protocol: DnsProtocol::Tcp,
                tls_server_name: None,
                outbound: None,
            }],
            router,
        )
        .expect("pool"),
    );
    let query = Arc::new(vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    let gate = Arc::new(tokio::sync::Barrier::new(128));
    let mut callers = tokio::task::JoinSet::new();
    for _ in 0..128 {
        let pool = Arc::clone(&pool);
        let query = Arc::clone(&query);
        let gate = Arc::clone(&gate);
        callers.spawn(async move {
            gate.wait().await;
            pool.query("tcp", &query).await
        });
    }

    // When
    while let Some(response) = callers.join_next().await {
        assert_eq!(
            response.expect("query task").expect("query response").len(),
            12
        );
    }
    pool.close().await;
    pool.close().await;
    server.await.expect("server task");

    // Then
    let stats = pool.lifecycle_stats();
    assert_eq!(stats.init_count, 1);
    assert_eq!(stats.close_count, 1);
    assert_eq!(stats.tasks, 0);
    assert!(pool.query("tcp", &query).await.is_err());
}

#[tokio::test]
async fn proxied_quic_transports_use_packet_outbound() {
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            fallback: "doq".to_string(),
            ..Default::default()
        })
        .expect("router"),
    );
    let proxy = Node {
        name: "proxy".to_string(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Block),
        ..Default::default()
    };
    let upstreams = [
        DnsUpstream {
            name: "doq".to_string(),
            address: "127.0.0.1:853".to_string(),
            protocol: DnsProtocol::Quic,
            tls_server_name: Some("dns.test".to_string()),
            outbound: Some("proxy".to_string()),
        },
        DnsUpstream {
            name: "doh3".to_string(),
            address: "127.0.0.1:443/dns-query".to_string(),
            protocol: DnsProtocol::H3,
            tls_server_name: Some("dns.test".to_string()),
            outbound: Some("proxy".to_string()),
        },
    ];
    let registry = Arc::new(crate::proxy::ProxyRegistry::default_resolver().expect("registry"));
    let pool =
        UpstreamPool::new_with_proxy(&upstreams, router, Some(registry), vec![proxy], Vec::new())
            .expect("pool");
    let query = [0_u8; 12];

    let doq = pool.query("doq", &query).await.expect_err("blocked DoQ");
    let doh3 = pool.query("doh3", &query).await.expect_err("blocked DoH3");
    let doq_chain = format!("{doq:#}");
    let doh3_chain = format!("{doh3:#}");

    assert!(doq_chain.contains("UDP connection blocked"), "{doq_chain}");
    assert!(
        doh3_chain.contains("UDP connection blocked"),
        "{doh3_chain}"
    );
    assert!(!doq_chain.contains("does not support outbound"));
    assert!(!doh3_chain.contains("does not support outbound"));
    assert_eq!(pool.lifecycle_stats().init_count, 2);
}

#[tokio::test]
async fn proxied_quic_without_registry_fails_closed() {
    let upstream = DnsUpstream {
        name: "doq".into(),
        address: "127.0.0.1:853".into(),
        protocol: DnsProtocol::Quic,
        tls_server_name: Some("dns.test".into()),
        outbound: Some("proxy".into()),
    };
    let proxy = Node {
        name: "proxy".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Block),
        ..Default::default()
    };
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            fallback: "doq".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    let pool =
        UpstreamPool::new_with_proxy(&[upstream], router, None, vec![proxy], vec![]).unwrap();

    let error = pool.query("doq", &[0; 12]).await.unwrap_err();
    let error_chain = format!("{error:#}");
    assert!(
        error_chain.contains("without a proxy registry"),
        "{error_chain}"
    );
}

#[tokio::test]
async fn overlapping_close_waits_for_inflight_query_drain() {
    // Given
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("listener address");
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut length = [0_u8; 2];
        stream.read_exact(&mut length).await.expect("query length");
        let mut query = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut query).await.expect("query");
        let _ = request_tx.send(());
        let _ = response_rx.await;
        let mut response = vec![0_u8; 12];
        response[..2].copy_from_slice(&query[..2]);
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .expect("response length");
        stream.write_all(&response).await.expect("response");
    });
    let pool = Arc::new(
        UpstreamPool::new(
            &[DnsUpstream {
                name: "tcp".to_string(),
                address: address.to_string(),
                protocol: DnsProtocol::Tcp,
                tls_server_name: None,
                outbound: None,
            }],
            Arc::new(
                DnsRouter::new(&DnsRouting {
                    fallback: "tcp".to_string(),
                    ..Default::default()
                })
                .expect("router"),
            ),
        )
        .expect("pool"),
    );
    let query_pool = Arc::clone(&pool);
    let query = tokio::spawn(async move { query_pool.query("tcp", &[0_u8; 12]).await });
    request_rx.await.expect("query reached server");
    let first_pool = Arc::clone(&pool);
    let first_close = tokio::spawn(async move { first_pool.close().await });
    tokio::task::yield_now().await;
    let second_pool = Arc::clone(&pool);
    let mut second_close = tokio::spawn(async move { second_pool.close().await });

    // When
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut second_close)
            .await
            .is_err(),
        "second close returned before the inflight transport drained"
    );
    response_tx.send(()).expect("release response");
    query
        .await
        .expect("query task")
        .expect("query response after release");
    first_close.await.expect("first close task");
    second_close.await.expect("second close task");
    server.await.expect("server task");

    // Then
    let stats = pool.lifecycle_stats();
    assert_eq!(stats.close_count, 1);
    assert_eq!(stats.tasks, 0);
}

#[tokio::test]
async fn query_paused_in_leaf_routing_cannot_publish_after_close() {
    // Given
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut length = [0_u8; 2];
        stream.read_exact(&mut length).await.expect("query length");
        let mut query = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut query).await.expect("query");
        let response = vec![0_u8; 12];
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .expect("response length");
        stream.write_all(&response).await.expect("response");
    });
    let pool = Arc::new(
        UpstreamPool::new(
            &[DnsUpstream {
                name: "tcp".to_string(),
                address: address.to_string(),
                protocol: DnsProtocol::Tcp,
                tls_server_name: None,
                outbound: None,
            }],
            Arc::new(
                DnsRouter::new(&DnsRouting {
                    fallback: "tcp".to_string(),
                    ..Default::default()
                })
                .expect("dns router"),
            ),
        )
        .expect("pool"),
    );
    let traffic = Arc::new(tokio::sync::RwLock::new(
        Router::new(&[], "direct").expect("traffic router"),
    ));
    pool.set_traffic_router(Some(Arc::clone(&traffic)));
    let baseline_refs = Arc::strong_count(&traffic);
    let write_guard = traffic.write().await;
    let query_pool = Arc::clone(&pool);
    let query = tokio::spawn(async move { query_pool.query("tcp", &[0_u8; 12]).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while Arc::strong_count(&traffic) == baseline_refs {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("query paused in leaf routing");

    // When
    tokio::time::timeout(Duration::from_secs(1), pool.close())
        .await
        .expect("leaf routing must not hold a query-admission permit");
    drop(write_guard);
    let result = query.await.expect("query task");
    server.abort();
    let _ = server.await;

    // Then
    assert!(
        result
            .expect_err("closed pool rejects publication")
            .to_string()
            .contains("closed")
    );
    let stats = pool.lifecycle_stats();
    assert_eq!(stats.init_count, 0);
    assert_eq!(stats.close_count, 0);
    assert_eq!(stats.tasks, 0);
}

#[tokio::test]
async fn stalled_tls_setups_use_dial_timeout_for_dot_and_doh() {
    for protocol in [DnsProtocol::Tls, DnsProtocol::Https] {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let mut _connections = Vec::new();
            for _ in 0..2 {
                _connections.push(listener.accept().await.expect("accept").0);
            }
            std::future::pending::<()>().await;
        });
        let endpoint = match protocol {
            DnsProtocol::Https => format!("localhost:{}/dns-query", address.port()),
            _ => address.to_string(),
        };
        let pool = UpstreamPool::new(
            &[DnsUpstream {
                name: "tls".to_string(),
                address: endpoint,
                protocol,
                tls_server_name: Some("localhost".to_string()),
                outbound: None,
            }],
            Arc::new(
                DnsRouter::new(&DnsRouting {
                    fallback: "tls".to_string(),
                    ..Default::default()
                })
                .expect("router"),
            ),
        )
        .expect("pool")
        .with_timeouts(Duration::from_secs(5), Duration::from_millis(20));

        let result = tokio::time::timeout(Duration::from_secs(1), pool.query("tls", &[0_u8; 12]))
            .await
            .expect("TLS setup ignored dial timeout")
            .expect_err("stalled TLS setup must fail");
        let error_chain = format!("{result:#}");

        assert!(
            error_chain.contains("timed out"),
            "unexpected {protocol:?} setup error: {error_chain}"
        );
        pool.close().await;
        assert_eq!(pool.lifecycle_stats().tasks, 0);
        server.abort();
        let _ = server.await;
    }
}
