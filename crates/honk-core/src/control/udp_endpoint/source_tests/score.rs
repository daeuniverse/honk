use super::*;
use honk_outbound::group::{GroupManager, ScoreVerificationState, SelectionNetwork};
use std::pin::Pin;
use std::task::Poll;

struct ScoreSourceFixture {
    events: mpsc::UnboundedReceiver<WireEvent>,
    wire_task: tokio::task::JoinHandle<()>,
    node: Node,
    generation: Arc<OutboundRuntimeRegistry>,
    runtime: Arc<honk_outbound::runtime::NodeRuntime>,
    client: UdpSocket,
    client_addr: SocketAddr,
    targets: [SocketAddr; 4],
    pool: Arc<UdpEndpointPool>,
    stats: Arc<StatsManager>,
    alive: Arc<honk_outbound::alive::AliveDialerSet>,
    manager: GroupManager,
}

impl ScoreSourceFixture {
    async fn new() -> Self {
        let (server, events, wire_task) = start_wire_peer().await;
        let (node, generation, runtime) = source_runtime(server, 4);
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let sockets: [_; 4] =
            std::array::from_fn(|_| std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
        let targets = sockets
            .each_ref()
            .map(|socket| socket.local_addr().unwrap());
        let pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
            4,
            Arc::new(SourceReplySocketFactory::new(sockets)),
        ));
        let stats = Arc::new(StatsManager::new());
        let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
        let manager = GroupManager::new(
            &[honk_config::group::Group {
                name: "score".into(),
                policy: honk_config::group::GroupPolicy::Score,
                nodes: vec![node.id],
                ..Default::default()
            }],
            std::slice::from_ref(&node),
        );
        Self {
            events,
            wire_task,
            node,
            generation,
            runtime,
            client,
            client_addr,
            targets,
            pool,
            stats,
            alive,
            manager,
        }
    }

    async fn prepare_flow(
        &self,
        target: SocketAddr,
    ) -> (
        Arc<UdpEndpoint>,
        Arc<SourceOwner>,
        impl Future<Output = super::super::driver::UdpDriverResult> + use<>,
        oneshot::Receiver<io::Result<()>>,
    ) {
        let mut lease = reserve_source(
            &self.pool,
            &self.stats,
            self.client_addr,
            target,
            self.node.id,
        );
        let attachment = attach_source(
            &self.pool,
            &self.generation,
            &self.runtime,
            self.client_addr,
            target,
            &self.alive,
            &self.stats,
        )
        .await;
        let owner = attachment.owner();
        let reporter = self
            .manager
            .feedback_for_group_node("score", self.node.id, score_context(target))
            .unwrap()
            .start();
        reporter.setup_succeeded();
        let endpoint = source_endpoint(
            &self.pool,
            attachment,
            target,
            &self.stats,
            self.node.id,
            Some(reporter),
        );
        let queue_rx = lease.take_queue_receiver().unwrap();
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        let initial = UdpDriverStart {
            first: lease.take_first().unwrap(),
            followers: Vec::new(),
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        let context = UdpDriverContext {
            reply_socket: Arc::clone(endpoint.source_reply_socket()),
            client_dst: endpoint.relay_addr,
            endpoint: Arc::clone(&endpoint),
            queue_rx,
            reply_socket_factory: Arc::new(SystemUdpReplySocketFactory),
            reply_socket_slots: Arc::new(Semaphore::new(MAX_REPLY_SOCKETS_PER_ENDPOINT)),
            client_addr: self.client_addr,
            alive_set: Arc::clone(&self.alive),
            outbound_tracker: self
                .stats
                .outbound_tracker("core-source-vless", crate::stats::OutboundKind::Node),
            stats: Arc::clone(&self.stats),
            health_family: honk_outbound::alive::IpVersion::V4,
        };
        (
            endpoint,
            owner,
            super::super::run_endpoint_driver(context, initial, ack_tx),
            ack_rx,
        )
    }

    async fn shutdown(self) {
        assert!(self.pool.shutdown().await.joined);
        self.generation.shutdown().await;
        self.wire_task.abort();
        let _ = self.wire_task.await;
    }
}

async fn poll_once_pending<F: Future>(mut future: Pin<&mut F>) {
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

fn verification_state(manager: &GroupManager) -> ScoreVerificationState {
    manager
        .score_verification_for_network("score", SelectionNetwork::Udp)
        .unwrap()
        .1
        .state
}

#[tokio::test(flavor = "current_thread")]
async fn replies_before_send_ack_qualify_four_live_source_flows() {
    let mut fixture = ScoreSourceFixture::new().await;
    let mut replies = HashMap::new();
    let mut endpoints = Vec::new();
    let mut drivers = Vec::new();
    for (index, target) in fixture.targets.into_iter().enumerate() {
        let (endpoint, _, driver, mut ack_rx) = fixture.prepare_flow(target).await;
        let mut driver = Box::pin(driver);
        poll_once_pending(driver.as_mut()).await;
        let frame = tokio::time::timeout(
            Duration::from_secs(2),
            next_data_frame(&mut fixture.events, &mut replies),
        )
        .await
        .unwrap();
        assert_eq!(frame.target, Some(target));
        assert_eq!(frame.payload.as_deref(), Some(b"held".as_slice()));
        replies[&frame.connection]
            .send((target, b"r".to_vec()))
            .unwrap();
        assert_eq!(
            receive_reply(&fixture.client).await,
            (b"r".to_vec(), target)
        );
        assert_eq!(endpoint.download.load(Ordering::Relaxed), 1);
        assert_eq!(endpoint.upload.load(Ordering::Relaxed), 0);
        assert!(matches!(
            ack_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(
            verification_state(&fixture.manager),
            ScoreVerificationState::Provisional
        );

        // The source receiver runs independently while this driver waits at writer ACK.
        poll_once_pending(driver.as_mut()).await;
        tokio::time::timeout(Duration::from_secs(2), ack_rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(endpoint.upload.load(Ordering::Relaxed), 4);
        assert_eq!(
            verification_state(&fixture.manager),
            if index == 3 {
                ScoreVerificationState::ObservedUsable
            } else {
                ScoreVerificationState::Provisional
            },
            "only the fourth distinct accepted flow may establish availability"
        );
        endpoints.push(endpoint);
        drivers.push(driver);
    }

    // No driver has completed, and no reporter has settled or lost its final handle.
    assert_eq!(
        verification_state(&fixture.manager),
        ScoreVerificationState::ObservedUsable
    );
    for (index, endpoint) in endpoints.iter().enumerate() {
        endpoint.finish_score(if index % 2 == 0 {
            ScoreOutcome::Success
        } else {
            ScoreOutcome::Cancelled
        });
        endpoint.finish_score(ScoreOutcome::Success);
        endpoint.finish_score(ScoreOutcome::Cancelled);
    }
    assert_eq!(
        verification_state(&fixture.manager),
        ScoreVerificationState::ObservedUsable
    );
    drop(drivers);
    drop(endpoints);
    fixture.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn reply_while_queued_for_source_gate_cannot_replace_fourth_flow() {
    let mut fixture = ScoreSourceFixture::new().await;
    let mut replies = HashMap::new();
    let mut endpoints: Vec<Arc<UdpEndpoint>> = Vec::new();
    let mut drivers = Vec::new();
    let mut connection = 0;
    for (index, target) in fixture.targets.into_iter().enumerate() {
        let (endpoint, _, driver, ack_rx) = fixture.prepare_flow(target).await;
        let mut driver = Box::pin(driver);
        let mut gate_send = (index == 3).then(|| {
            let gate_endpoint = Arc::clone(&endpoints[0]);
            Box::pin(async move { gate_endpoint.send_packet(b"gate", false).await })
        });
        if let Some(send) = &mut gate_send {
            poll_once_pending(send.as_mut()).await;
        }
        poll_once_pending(driver.as_mut()).await;
        let frame = tokio::time::timeout(
            Duration::from_secs(2),
            next_data_frame(&mut fixture.events, &mut replies),
        )
        .await
        .unwrap();
        if index == 3 {
            assert_eq!(frame.target, Some(fixture.targets[0]));
            assert_eq!(frame.payload.as_deref(), Some(b"gate".as_slice()));
        } else {
            assert_eq!(frame.target, Some(target));
            assert_eq!(frame.payload.as_deref(), Some(b"held".as_slice()));
        }
        connection = frame.connection;
        replies[&connection].send((target, b"r".to_vec())).unwrap();
        assert_eq!(
            receive_reply(&fixture.client).await,
            (b"r".to_vec(), target)
        );
        assert_eq!(endpoint.download.load(Ordering::Relaxed), 1);
        assert_eq!(endpoint.upload.load(Ordering::Relaxed), 0);
        if let Some(send) = gate_send {
            // Keeping the sibling future unpolled holds the real source send gate.
            send.await.unwrap();
            poll_once_pending(driver.as_mut()).await;
            let frame = tokio::time::timeout(
                Duration::from_secs(2),
                next_data_frame(&mut fixture.events, &mut replies),
            )
            .await
            .unwrap();
            assert_eq!(frame.target, Some(target));
            assert_eq!(frame.payload.as_deref(), Some(b"held".as_slice()));
        }
        poll_once_pending(driver.as_mut()).await;
        tokio::time::timeout(Duration::from_secs(2), ack_rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(endpoint.upload.load(Ordering::Relaxed), 4);
        assert_eq!(
            verification_state(&fixture.manager),
            ScoreVerificationState::Provisional
        );
        endpoints.push(endpoint);
        drivers.push(driver);
    }

    for (index, endpoint) in endpoints[..3].iter().enumerate() {
        endpoint.finish_score(if index == 1 {
            ScoreOutcome::Cancelled
        } else {
            ScoreOutcome::Success
        });
        endpoint.finish_score(ScoreOutcome::Success);
        endpoint.finish_score(ScoreOutcome::Cancelled);
    }
    assert_eq!(
        verification_state(&fixture.manager),
        ScoreVerificationState::Provisional,
        "live progress and repeated Success/neutral settlement cannot credit the same flow twice"
    );
    replies[&connection]
        .send((fixture.targets[3], b"fresh".to_vec()))
        .unwrap();
    assert_eq!(
        receive_reply(&fixture.client).await,
        (b"fresh".to_vec(), fixture.targets[3])
    );
    assert_eq!(
        verification_state(&fixture.manager),
        ScoreVerificationState::ObservedUsable
    );
    drop(drivers);
    drop(endpoints);
    fixture.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn unaccepted_source_send_cannot_reconcile_delivered_reply() {
    for disposition in ["accepted", "cancelled", "retired", "failed"] {
        let mut fixture = ScoreSourceFixture::new().await;
        let mut replies = HashMap::new();
        let mut endpoints = Vec::new();
        let mut drivers = Vec::new();
        for (index, target) in fixture.targets.into_iter().enumerate() {
            let (endpoint, owner, driver, ack_rx) = fixture.prepare_flow(target).await;
            let mut driver = Box::pin(driver);
            poll_once_pending(driver.as_mut()).await;
            let frame = tokio::time::timeout(
                Duration::from_secs(2),
                next_data_frame(&mut fixture.events, &mut replies),
            )
            .await
            .unwrap();
            assert_eq!(frame.target, Some(target));
            assert_eq!(frame.payload.as_deref(), Some(b"held".as_slice()));
            replies[&frame.connection]
                .send((target, b"r".to_vec()))
                .unwrap();
            assert_eq!(
                receive_reply(&fixture.client).await,
                (b"r".to_vec(), target)
            );
            assert_eq!(endpoint.download.load(Ordering::Relaxed), 1);
            assert_eq!(endpoint.upload.load(Ordering::Relaxed), 0);
            if index < 3 || disposition == "accepted" {
                poll_once_pending(driver.as_mut()).await;
                tokio::time::timeout(Duration::from_secs(2), ack_rx)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(endpoint.upload.load(Ordering::Relaxed), 4);
                drivers.push(driver);
            } else {
                if disposition == "failed" {
                    owner.fail(ScoreOutcome::NodeFailure);
                } else {
                    endpoint.kill();
                }
                if disposition == "cancelled" {
                    drop(driver);
                    assert!(ack_rx.await.is_err());
                    endpoint.finish_score(ScoreOutcome::Cancelled);
                } else {
                    let result = tokio::time::timeout(Duration::from_secs(2), driver)
                        .await
                        .unwrap();
                    assert_eq!(
                        result.result.unwrap_err().kind(),
                        io::ErrorKind::ConnectionAborted
                    );
                    assert_eq!(
                        ack_rx.await.unwrap().unwrap_err().kind(),
                        io::ErrorKind::ConnectionAborted
                    );
                    endpoint.finish_score(result.outcome);
                }
                endpoint.finish_score(ScoreOutcome::Success);
                endpoint.finish_score(ScoreOutcome::Cancelled);
                assert_eq!(
                    endpoint.upload.load(Ordering::Relaxed),
                    0,
                    "{disposition} send must not count accepted TX"
                );
            }
            assert_eq!(
                verification_state(&fixture.manager),
                if index == 3 && disposition == "accepted" {
                    ScoreVerificationState::ObservedUsable
                } else {
                    ScoreVerificationState::Provisional
                },
                "{disposition} send must only contribute credit after successful acceptance"
            );
            endpoints.push(endpoint);
        }
        drop(drivers);
        drop(endpoints);
        fixture.shutdown().await;
    }
}
