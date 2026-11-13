use super::*;
use crate::connection_tracker::{CloseOutcome, ConnectionEntry, ConnectionTracker};
use crate::control::retirement_worker::{RetirementPort, spawn_retirement_worker};
use crate::ebpf::{EbpfBackend, mock::MockEbpfBackend};
use honk_ebpf_common::{
    RedirectEntry, RedirectTuple,
    conn::{ConnState, UdpDecisionState},
};

pub(in crate::control::udp_endpoint) fn tracked_entry(
    id: &str,
    client: SocketAddr,
    dst: SocketAddr,
) -> ConnectionEntry {
    ConnectionEntry {
        id: id.to_owned(),
        source: client.to_string(),
        destination: dst.to_string(),
        proxy: "direct".into(),
        #[cfg(feature = "native-api")]
        routed_outbound: None,
        #[cfg(feature = "native-api")]
        native_flow_id: None,
        rule: String::new(),
        rule_payload: String::new(),
        chains: Vec::new(),
        upload: Arc::new(AtomicU64::new(0)),
        download: Arc::new(AtomicU64::new(0)),
        start_time: Instant::now(),
        domain: None,
        network: "udp".into(),
        process: None,
        process_path: None,
    }
}

#[tokio::test]
async fn udp_close_waits_for_driver_and_exact_backend_ack() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for (mismatch, already_retiring) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let pool = Arc::new(UdpEndpointPool::new());
            let stats = Arc::new(StatsManager::new());
            let tracker = Arc::new(ConnectionTracker::new());
            tracker.enable();
            let backend: Arc<tokio::sync::RwLock<Box<dyn EbpfBackend>>> =
                Arc::new(tokio::sync::RwLock::new(Box::new(MockEbpfBackend::new())));
            let (fatal, mut failures) = mpsc::unbounded_channel();
            let pins = Arc::new(crate::control::connection::handoff::TcpFlowPins::default());
            let port = Arc::new(RetirementPort::default());
            let worker = spawn_retirement_worker(
                Arc::clone(&pool),
                Arc::clone(&backend),
                Arc::clone(&tracker),
                fatal,
                Arc::clone(&pins),
                Arc::clone(&port),
            );
            let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let destination = upstream.local_addr().unwrap();
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let source = client.local_addr().unwrap();
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            socket.connect(destination).await.unwrap();
            let socket_handle = Arc::downgrade(&socket);
            let endpoint = Arc::new(UdpEndpoint::new(
                transport(socket, destination),
                destination,
                uuid::Uuid::new_v4(),
            ));
            endpoint.record_pending_reply_peer(destination);
            let weak = Arc::downgrade(&endpoint);
            let mut lease = match pool.reserve_owned_or_enqueue(
                source,
                destination,
                Bytes::from_static(b"live"),
                101,
                None,
                Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
                &stats,
            ) {
                EndpointReservation::Initializing(lease) => lease,
                _ => panic!("fresh owned endpoint"),
            };
            let generation = lease.generation();
            let key = crate::control::connection::build_tuples_key(
                destination.ip(),
                destination.port(),
                source.ip(),
                source.port(),
                17,
            );
            backend
                .write()
                .await
                .udp_conn_state_store(
                    &key,
                    &ConnState {
                        decision_token: 101,
                        state: UdpDecisionState::Proxy as u8,
                        ..Default::default()
                    },
                )
                .unwrap();
            let queue = lease.take_queue_receiver().unwrap();
            let mut driver = pool.spawn_driver(
                source,
                destination,
                generation,
                101,
                Arc::clone(&endpoint),
                queue,
                test_reply_socket().await,
                Arc::new(honk_outbound::alive::AliveDialerSet::new()),
                Arc::clone(&stats),
                stats.outbound_tracker("direct", crate::stats::OutboundKind::Builtin),
            );
            driver.wait_ready().await.unwrap();
            assert!(lease.commit_ready(Arc::clone(&endpoint)));
            let id = pool
                .register_ready_tracker(
                    source,
                    destination,
                    101,
                    generation,
                    &endpoint,
                    &tracker,
                    vec!["captured-parent".into()],
                    || tracked_entry("owned-udp", source, destination),
                )
                .unwrap()
                .unwrap();
            driver.start(lease.take_first().unwrap()).unwrap();
            driver.wait_first_ack().await.unwrap();
            drop(lease);
            drop(endpoint);
            let mut bytes = [0; 4];
            upstream.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"live");
            let selected = tracker
                .snapshot_group("captured-parent", Some("udp"))
                .pop()
                .unwrap();
            let mut locked = backend.write().await;
            if mismatch {
                locked
                    .redirect_track_store(
                        &RedirectTuple::from_tuples(&key),
                        &RedirectEntry {
                            decision_token: 202,
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
            if already_retiring {
                pool.remove(source, destination);
            }
            let pending = tracker.start_close(selected);
            let mut duplicate = Box::pin(tracker.close_id(&id));
            assert!(futures::poll!(&mut duplicate).is_pending());
            let mut bulk = Box::pin(tracker.close_matching(Some("udp"), None, 1000));
            assert!(futures::poll!(&mut bulk).is_pending());
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
            assert!(
                socket_handle.upgrade().is_none(),
                "endpoint released its UDP socket"
            );
            let mut pending = Box::pin(pending.wait());
            assert!(futures::poll!(&mut pending).is_pending());
            assert!(locked.conn_state_lookup(&key).unwrap().is_some());
            drop(locked);
            if mismatch {
                assert_eq!(pending.await, CloseOutcome::Failed);
                assert_eq!(duplicate.await, CloseOutcome::Failed);
                assert!(bulk.await.unwrap().failed);
                assert_eq!(tracker.close_id(&id).await, CloseOutcome::Failed);
                assert!(failures.recv().await.is_some());
                assert!(matches!(
                    pool.endpoints
                        .get(&EndpointKey::new(source, destination))
                        .unwrap()
                        .value(),
                    EndpointEntry::Retiring { .. }
                ));
                assert_eq!(
                    backend
                        .read()
                        .await
                        .conn_state_lookup(&key)
                        .unwrap()
                        .unwrap()
                        .decision_token,
                    101
                );
            } else {
                assert_eq!(pending.await, CloseOutcome::Closed);
                assert_eq!(duplicate.await, CloseOutcome::Closed);
                assert_eq!(bulk.await.unwrap().closed, 1);
                assert!(tracker.snapshot().is_empty());
                assert!(
                    backend
                        .read()
                        .await
                        .conn_state_lookup(&key)
                        .unwrap()
                        .is_none()
                );
                let replacement = match pool.reserve_owned_or_enqueue(
                    source,
                    destination,
                    Bytes::from_static(b"new"),
                    202,
                    None,
                    Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
                    &stats,
                ) {
                    EndpointReservation::Initializing(lease) => lease,
                    _ => panic!("acknowledged retirement permits tuple reuse"),
                };
                assert!(!pool.close_exact(source, destination, 101, generation));
                assert!(replacement.still_initializing());
                drop(replacement);
                assert!(pool.shutdown().await.joined);
                assert!(failures.try_recv().is_err());
            }
            pool.remove_sink.lock().take();
            port.sink.lock().take();
            worker.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn udp_close_without_exact_pool_owner_completes_all_claims() {
    use crate::connection_tracker::{CloseAction, CloseSignal, ConnectionOwner};
    tokio::time::timeout(Duration::from_secs(2), async {
        for lost_pool in [false, true] {
            let pool = Arc::new(UdpEndpointPool::new());
            let weak_pool = Arc::downgrade(&pool);
            let retained_pool = (!lost_pool).then_some(pool);
            let tracker = ConnectionTracker::new();
            let signal = CloseSignal::new();
            let source = "127.0.0.1:10001".parse().unwrap();
            let destination = "127.0.0.1:10002".parse().unwrap();
            tracker.register_owned(
                tracked_entry("missing-owner", source, destination),
                ConnectionOwner {
                    signal: Arc::clone(&signal),
                    action: CloseAction::Udp {
                        pool: weak_pool,
                        client: source,
                        destination,
                        token: 101,
                        generation: 1,
                    },
                    groups: Vec::new(),
                },
            );
            let stale = tracker
                .snapshot_close(None, None, 1000)
                .unwrap()
                .pop()
                .unwrap();
            let first = tracker.start_close(
                tracker
                    .snapshot_close(None, None, 1000)
                    .unwrap()
                    .pop()
                    .unwrap(),
            );
            assert_eq!(first.wait().await, CloseOutcome::Failed);
            assert_eq!(
                tracker.close_id("missing-owner").await,
                CloseOutcome::Failed
            );
            assert!(
                tracker
                    .close_matching(None, None, 1000)
                    .await
                    .unwrap()
                    .failed
            );
            signal.finish(true);
            assert_eq!(
                tracker.close_id("missing-owner").await,
                CloseOutcome::Failed
            );
            let replacement = CloseSignal::new();
            tracker.register_owned(
                tracked_entry("missing-owner", source, destination),
                ConnectionOwner {
                    signal: Arc::clone(&replacement),
                    action: CloseAction::Tcp,
                    groups: Vec::new(),
                },
            );
            assert_eq!(tracker.close_selected(stale).await, CloseOutcome::Gone);
            let mut cancelled = Box::pin(replacement.cancelled());
            assert!(futures::poll!(&mut cancelled).is_pending());
            tracker.remove("missing-owner");
            assert_eq!(tracker.close_id("missing-owner").await, CloseOutcome::Gone);
            tracker.register(tracked_entry("unowned", source, destination));
            assert_eq!(tracker.close_id("unowned").await, CloseOutcome::NotClosable);
            drop(retained_pool);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn udp_exact_ack_completes_claim_before_tombstone_disappears() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let pool = Arc::new(UdpEndpointPool::new());
        let (removals, mut removed) = mpsc::channel(1);
        pool.set_remove_sink(removals);
        let stats = StatsManager::new();
        let tracker = ConnectionTracker::new();
        tracker.enable();
        let source = "127.0.0.1:10001".parse().unwrap();
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = upstream.local_addr().unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        socket.connect(destination).await.unwrap();
        let socket_handle = Arc::downgrade(&socket);
        let endpoint = Arc::new(UdpEndpoint::new(
            transport(socket, destination),
            destination,
            uuid::Uuid::new_v4(),
        ));
        let mut lease = match pool.reserve_owned_or_enqueue(
            source,
            destination,
            Bytes::from_static(b"live"),
            101,
            None,
            Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("fresh owned endpoint"),
        };
        let generation = lease.generation();
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        pool.register_ready_tracker(
            source,
            destination,
            101,
            generation,
            &endpoint,
            &tracker,
            Vec::new(),
            || tracked_entry("acknowledged", source, destination),
        )
        .unwrap();
        let selected = tracker
            .snapshot_close(None, None, 1000)
            .unwrap()
            .pop()
            .unwrap();
        let signal = Arc::clone(&endpoint.retirement.0.close);
        let key = crate::control::connection::build_tuples_key(
            destination.ip(),
            destination.port(),
            source.ip(),
            source.port(),
            17,
        );
        let mut backend = MockEbpfBackend::new();
        backend
            .udp_conn_state_store(
                &key,
                &ConnState {
                    decision_token: 101,
                    state: UdpDecisionState::Proxy as u8,
                    ..Default::default()
                },
            )
            .unwrap();
        drop(lease);
        let pending = tracker.start_close(selected);
        drop(endpoint);
        let removal = removed.recv().await.unwrap();
        assert!(pool.wait_removal_io(&removal).await);
        assert!(
            socket_handle.upgrade().is_none(),
            "endpoint released its UDP socket"
        );
        let mut outcomes = [crate::ebpf::RetireOutcome::NotRun];
        backend
            .retire_batch(
                &[crate::ebpf::RetireRequest {
                    key,
                    kind: crate::ebpf::RetireKind::Udp {
                        token: 101,
                        incarnation: removal.owner.incarnation(),
                        pending_only: false,
                    },
                }],
                &mut outcomes,
            )
            .unwrap();
        assert_eq!(outcomes[0], crate::ebpf::RetireOutcome::ConnRetired);
        tracker.remove("acknowledged");
        assert!(pool.complete_removal(source, destination, removal.owner, generation));
        assert!(!pool.close_exact(source, destination, 101, generation));
        assert_eq!(pending.wait().await, CloseOutcome::Closed);
        signal.finish(false);
        assert_eq!(
            crate::connection_tracker::CloseRequest::Pending(signal)
                .wait()
                .await,
            CloseOutcome::Closed
        );
        assert_eq!(tracker.close_id("acknowledged").await, CloseOutcome::Gone);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn token_zero_endpoint_retirement_cannot_select_recreated_kernel_flow() {
    for raw_dns in [false, true] {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let tracker = Arc::new(ConnectionTracker::new());
        let source: SocketAddr = "192.0.2.10:40000".parse().unwrap();
        let destination: SocketAddr = if raw_dns {
            "203.0.113.53:53"
        } else {
            "203.0.113.10:443"
        }
        .parse()
        .unwrap();
        let key = crate::control::connection::build_tuples_key(
            destination.ip(),
            destination.port(),
            source.ip(),
            source.port(),
            17,
        );
        // Published, userspace-owned routing makes token-zero retirement
        // eligible, so only the captured incarnation preserves the replacement.
        let published = honk_ebpf_common::RoutingMeta {
            raw: honk_ebpf_common::ROUTING_META_FLAG_PUBLISHED | 2,
        };
        let mut mock = MockEbpfBackend::new();
        mock.udp_conn_state_store(
            &key,
            &ConnState {
                incarnation: if raw_dns { 22 } else { 11 },
                meta: published,
                ..Default::default()
            },
        )
        .unwrap();
        let backend: Arc<tokio::sync::RwLock<Box<dyn EbpfBackend>>> =
            Arc::new(tokio::sync::RwLock::new(Box::new(mock)));
        let pins = Arc::new(crate::control::connection::handoff::TcpFlowPins::default());
        let (fatal, mut failures) = mpsc::unbounded_channel();
        let port = Arc::new(RetirementPort::default());
        let worker = spawn_retirement_worker(
            Arc::clone(&pool),
            Arc::clone(&backend),
            tracker,
            fatal,
            Arc::clone(&pins),
            Arc::clone(&port),
        );
        let lease = match pool.reserve_or_enqueue_at(
            source,
            destination,
            b"old",
            None,
            UdpFlowOwner::new(0, (!raw_dns).then_some(11)).unwrap(),
            pool.initialization_epoch(),
            Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            queue_now(),
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("original endpoint must reserve"),
        };
        backend
            .write()
            .await
            .udp_conn_state_store(
                &key,
                &ConnState {
                    incarnation: 22,
                    meta: published,
                    ..Default::default()
                },
            )
            .unwrap();
        drop(lease);
        assert!(pool.shutdown().await.joined);
        assert_eq!(
            backend
                .read()
                .await
                .conn_state_lookup(&key)
                .unwrap()
                .unwrap()
                .incarnation,
            22
        );
        assert!(failures.try_recv().is_err());
        port.sink.lock().take();
        worker.await.unwrap();
    }
}
