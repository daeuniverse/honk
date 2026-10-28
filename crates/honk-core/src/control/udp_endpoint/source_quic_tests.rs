use super::driver::UdpDriverHandle;
use super::*;
use crate::control::tests::support::{QuicStreamHold, QuicUdpMode, QuicUdpPacket, QuicUdpPeer};
use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
use honk_outbound::group::{
    GroupManager, ScoreSelectionContext, ScoreVerificationState, SelectionNetwork,
};
use honk_outbound::runtime::{NodeRuntime, OutboundRuntimeRegistry};
use std::collections::HashMap;

const MODES: [QuicUdpMode; 3] = [
    QuicUdpMode::Hysteria2,
    QuicUdpMode::TuicDatagram,
    QuicUdpMode::TuicStream,
];
pub(super) const TEST_TIMEOUT: Duration = Duration::from_secs(2);
pub(super) const SHORT_WAIT: Duration = Duration::from_millis(20);
const TEST_TARGETS: usize = 8;
const TEST_ENDPOINTS: usize = 16;
const TEST_PACKET_SIZE: usize = 256;

// QUIC counters are process-wide; a module mutex cannot isolate other suites.
fn run_metrics_in_child(name: &str) -> bool {
    const CHILD: &str = "HONK_QUIC_SOURCE_METRICS_CHILD";
    let name = format!("control::udp_endpoint::source_quic_tests::{name}");
    if std::env::var(CHILD).as_deref() == Ok(name.as_str()) {
        return false;
    }
    let executable = std::env::current_exe().unwrap();
    let listed = std::process::Command::new(&executable)
        .args(["--exact", &name, "--list", "--format", "terse"])
        .output()
        .unwrap();
    assert!(listed.status.success());
    assert_eq!(
        String::from_utf8(listed.stdout).unwrap().trim(),
        format!("{name}: test")
    );
    let status = std::process::Command::new(executable)
        .args(["--exact", &name, "--test-threads=1", "--nocapture"])
        .env(CHILD, &name)
        .status()
        .unwrap();
    assert!(status.success());
    true
}

#[derive(Debug)]
pub(super) struct BoundReplies(pub(super) HashMap<(ScopeId, SocketAddr), std::net::UdpSocket>);

impl UdpReplySocketFactory for BoundReplies {
    fn create(&self, scope: ScopeId, source: SocketAddr) -> io::Result<ReplySocketFd> {
        let socket = self
            .0
            .get(&(scope, source))
            .ok_or_else(|| io::Error::other("unreserved reply source"))?
            .try_clone()?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket).map(ReplySocketFd::Kernel)
    }
}

struct Fixture {
    peer: QuicUdpPeer,
    generation: Arc<OutboundRuntimeRegistry>,
    runtime: Arc<NodeRuntime>,
    pool: Arc<UdpEndpointPool>,
    client: UdpSocket,
    targets: Vec<UdpSocket>,
    stats: Arc<StatsManager>,
    alive: Arc<AliveDialerSet>,
    score: GroupManager,
    path: SourcePath,
    family: IpVersion,
}

impl Fixture {
    async fn new(mode: QuicUdpMode, ipv6: bool) -> Self {
        Self::with_scopes(mode, ipv6, &[ScopeId::HOST]).await
    }

    async fn with_scopes(mode: QuicUdpMode, ipv6: bool, scopes: &[ScopeId]) -> Self {
        let bind: SocketAddr = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" }
            .parse()
            .unwrap();
        let peer = QuicUdpPeer::start(mode, bind).await.unwrap();
        Self::with_peer(mode, bind, peer, scopes).await
    }

    async fn with_peer(
        mode: QuicUdpMode,
        bind: SocketAddr,
        peer: QuicUdpPeer,
        scopes: &[ScopeId],
    ) -> Self {
        let ipv6 = bind.is_ipv6();
        let generation =
            Arc::new(OutboundRuntimeRegistry::build(std::slice::from_ref(&peer.node)).unwrap());
        let runtime = generation.get(&peer.node.id).unwrap();
        let mut bound = HashMap::new();
        let mut targets = Vec::new();
        for _ in 0..TEST_TARGETS {
            let socket = std::net::UdpSocket::bind(bind).unwrap();
            socket.set_nonblocking(true).unwrap();
            for &scope in scopes {
                bound.insert(
                    (scope, socket.local_addr().unwrap()),
                    socket.try_clone().unwrap(),
                );
            }
            targets.push(UdpSocket::from_std(socket).unwrap());
        }
        let score = GroupManager::new(
            &[honk_config::node::Group {
                name: "score".into(),
                policy: honk_config::node::GroupPolicy::Score,
                nodes: vec![peer.node.id],
                ..Default::default()
            }],
            std::slice::from_ref(&peer.node),
        );
        Self {
            peer,
            generation,
            runtime,
            pool: Arc::new(UdpEndpointPool::with_reply_socket_factory(
                TEST_ENDPOINTS,
                Arc::new(BoundReplies(bound)),
            )),
            client: UdpSocket::bind(bind).await.unwrap(),
            targets,
            stats: Arc::new(StatsManager::new()),
            alive: Arc::new(AliveDialerSet::new()),
            score,
            path: if mode == QuicUdpMode::Hysteria2 {
                SourcePath::Hysteria2
            } else {
                SourcePath::Tuic
            },
            family: if ipv6 { IpVersion::V6 } else { IpVersion::V4 },
        }
    }

    fn target(&self, index: usize) -> SocketAddr {
        self.targets[index].local_addr().unwrap()
    }
    fn client(&self) -> SocketAddr {
        self.client.local_addr().unwrap()
    }

    async fn prepare(
        &self,
        scope: ScopeId,
        client: SocketAddr,
        target: SocketAddr,
        rewrite: Option<SocketAddr>,
        speculative: bool,
    ) -> SourcePreparation {
        self.pool
            .prepare_source(
                scope,
                &honk_outbound::proxy::ProxyRegistry::new(),
                Arc::clone(&self.generation),
                Arc::clone(&self.runtime),
                client,
                self.path,
                rewrite,
                target,
                None,
                TEST_TIMEOUT,
                Arc::clone(&self.alive),
                Arc::clone(&self.stats),
                self.family,
                speculative,
            )
            .await
            .unwrap()
    }

    fn reserve(
        &self,
        scope: ScopeId,
        client: SocketAddr,
        target: SocketAddr,
        payload: &[u8],
    ) -> UdpInitLease {
        let slow = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let EndpointReservation::Initializing(lease) =
            self.pool
                .reserve_or_enqueue(scope, client, target, payload, slow, &self.stats)
        else {
            panic!("expected vacant endpoint");
        };
        assert!(lease.bind_selected_node(self.peer.node.id));
        lease
    }

    async fn install(
        &self,
        mut lease: UdpInitLease,
        attachment: SourceAttachment,
        client: SocketAddr,
        target: SocketAddr,
        original: SocketAddr,
    ) -> (Arc<UdpEndpoint>, UdpDriverHandle) {
        let reporter = self
            .score
            .feedback_for_group_node(
                "score",
                self.peer.node.id,
                ScoreSelectionContext {
                    network: SelectionNetwork::Udp,
                    probe_domain: ProbeDomain::DataUdp,
                    target_family: Some(self.family),
                    health_family: self.family,
                    target: Some(original.into()),
                },
            )
            .unwrap()
            .start();
        reporter.setup_succeeded();
        let reply = Arc::new(
            self.pool
                .create_reply_socket(lease.scope(), original)
                .unwrap(),
        );
        let endpoint = UdpEndpoint::new_source_scored(
            attachment,
            target,
            None,
            reply,
            self.stats
                .outbound_tracker(&self.peer.node.name, crate::stats::OutboundKind::Node),
            self.peer.node.id,
            self.family,
            Some(reporter),
        );
        #[cfg(feature = "native-api")]
        let mut endpoint = endpoint;
        #[cfg(feature = "native-api")]
        endpoint
            .native
            .set_observer(honk_outbound::runtime::flow_observation::current());
        let endpoint = Arc::new(endpoint);
        let queue = lease.take_queue_receiver().unwrap();
        let mut driver = self.pool.spawn_driver(
            lease.scope(),
            client,
            original,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue,
            Arc::clone(endpoint.source_reply_socket()),
            Arc::clone(&self.alive),
            Arc::clone(&self.stats),
            self.stats
                .outbound_tracker(&self.peer.node.name, crate::stats::OutboundKind::Node),
        );
        driver.wait_ready().await.unwrap();
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        driver.start(lease.take_first().unwrap()).unwrap();
        (endpoint, driver)
    }

    async fn flow(&self, index: usize, payload: &[u8]) -> Arc<UdpEndpoint> {
        let target = self.target(index);
        let lease = self.reserve(honk_datapath::ScopeId::HOST, self.client(), target, payload);
        let attachment = self
            .prepare(
                honk_datapath::ScopeId::HOST,
                self.client(),
                target,
                None,
                false,
            )
            .await
            .commit(&self.pool)
            .await
            .unwrap();
        let (endpoint, mut driver) = self
            .install(lease, attachment, self.client(), target, target)
            .await;
        driver.wait_first_ack().await.unwrap();
        endpoint
    }

    async fn packet(&mut self) -> QuicUdpPacket {
        tokio::time::timeout(TEST_TIMEOUT, self.peer.packets.recv())
            .await
            .expect("proxy wire packet timed out")
            .expect("peer failed")
    }

    async fn shutdown(self) {
        assert!(self.pool.shutdown().await.joined);
        self.generation.shutdown().await;
        assert!(!self.generation.tasks_failed());
        self.peer.close().await.unwrap();
    }
}

pub(super) async fn received(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = [0; TEST_PACKET_SIZE];
    let (n, source) = tokio::time::timeout(TEST_TIMEOUT, socket.recv_from(&mut buf))
        .await
        .expect("UDP receive timed out")
        .unwrap();
    (buf[..n].to_vec(), source)
}

pub(super) async fn no_reply(socket: &UdpSocket) {
    let mut buf = [0; TEST_PACKET_SIZE];
    assert!(
        tokio::time::timeout(SHORT_WAIT, socket.recv_from(&mut buf))
            .await
            .is_err(),
        "forbidden source reached client"
    );
}

#[tokio::test]
async fn quic_source_send_outcomes_preserve_siblings() {
    if run_metrics_in_child("quic_source_send_outcomes_preserve_siblings") {
        return;
    }
    for mode in MODES {
        let mut f = Fixture::new(mode, false).await;
        let sibling = f.flow(0, b"sibling").await;
        let packet = f.packet().await;
        let target = f.target(1);
        let attachment = f
            .prepare(
                honk_datapath::ScopeId::HOST,
                f.client(),
                target,
                None,
                false,
            )
            .await
            .commit(&f.pool)
            .await
            .unwrap();
        let owner = attachment.owner();
        owner.set_send_timeout_for_test(SHORT_WAIT);
        let timeouts = honk_outbound::quic::quic_stats_snapshot().send_timeouts;
        let gate = owner.hold_send_gate_for_test().await;
        let lease = f.reserve(
            honk_datapath::ScopeId::HOST,
            f.client(),
            target,
            b"must-not-send",
        );
        let (queued, mut driver) = f
            .install(lease, attachment, f.client(), target, target)
            .await;
        assert_eq!(
            driver.wait_first_ack().await.unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(queued.upload.load(Ordering::Relaxed), 0);
        drop(gate);
        assert!(
            tokio::time::timeout(SHORT_WAIT, f.peer.packets.recv())
                .await
                .is_err(),
            "gate-only timeout emitted a packet"
        );
        assert!(
            f.alive
                .is_alive_for(f.peer.node.id, ProbeDomain::DataUdp, f.family)
        );
        assert_eq!(
            honk_outbound::quic::quic_stats_snapshot().send_timeouts,
            timeouts
        );
        assert!(matches!(
            f.pool.fast_path_enqueue(
                honk_datapath::ScopeId::HOST,
                f.client(),
                f.target(0),
                b"after-timeout",
                &f.stats
            ),
            Some(EndpointReservation::Enqueued)
        ));
        let next = f.packet().await;
        assert_eq!(
            (packet.connection, packet.session, packet.mapping),
            (next.connection, next.session, next.mapping)
        );
        assert_eq!(next.payload, b"after-timeout");
        f.targets[0]
            .send_to(b"still-alive", packet.mapping)
            .await
            .unwrap();
        assert_eq!(
            received(&f.client).await,
            (b"still-alive".to_vec(), f.target(0))
        );
        let cancelled_target = f.target(3);
        let attachment = f
            .prepare(
                honk_datapath::ScopeId::HOST,
                f.client(),
                cancelled_target,
                None,
                false,
            )
            .await
            .commit(&f.pool)
            .await
            .unwrap();
        let gate = owner.hold_send_gate_for_test().await;
        let lease = f.reserve(
            honk_datapath::ScopeId::HOST,
            f.client(),
            cancelled_target,
            b"cancelled-in-queue",
        );
        let (cancelled, mut driver) = f
            .install(
                lease,
                attachment,
                f.client(),
                cancelled_target,
                cancelled_target,
            )
            .await;
        f.pool
            .remove(honk_datapath::ScopeId::HOST, f.client(), cancelled_target);
        drop(gate);
        assert_eq!(
            driver.wait_first_ack().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(cancelled.upload.load(Ordering::Relaxed), 0);
        assert!(
            tokio::time::timeout(SHORT_WAIT, f.peer.packets.recv())
                .await
                .is_err()
        );
        assert_eq!(
            honk_outbound::quic::quic_stats_snapshot().send_timeouts,
            timeouts
        );
        f.targets[0]
            .send_to(b"survived-retirement", packet.mapping)
            .await
            .unwrap();
        assert_eq!(
            received(&f.client).await,
            (b"survived-retirement".to_vec(), f.target(0))
        );
        drop(cancelled);
        drop((queued, sibling, owner));
        f.shutdown().await;
    }
}

#[tokio::test]
async fn tuic_source_accepts_first_and_later_empty_payloads() {
    for mode in [QuicUdpMode::TuicDatagram, QuicUdpMode::TuicStream] {
        let mut f = Fixture::new(mode, false).await;
        let endpoint = f.flow(0, b"").await;
        let first = f.packet().await;
        assert!(first.payload.is_empty());
        assert_eq!(received(&f.targets[0]).await, (Vec::new(), first.mapping));
        f.targets[0].send_to(b"", first.mapping).await.unwrap();
        assert_eq!(received(&f.client).await, (Vec::new(), f.target(0)));
        assert!(matches!(
            f.pool.fast_path_enqueue(
                honk_datapath::ScopeId::HOST,
                f.client(),
                f.target(0),
                b"",
                &f.stats
            ),
            Some(EndpointReservation::Enqueued)
        ));
        let second = f.packet().await;
        assert!(second.payload.is_empty());
        assert_eq!(
            (first.connection, first.session),
            (second.connection, second.session)
        );
        drop(endpoint);
        f.shutdown().await;
    }
}

#[tokio::test]
async fn quic_source_stream_io_timeout_and_retirement_settle_once() {
    if run_metrics_in_child("quic_source_stream_io_timeout_and_retirement_settle_once") {
        return;
    }
    for retire in [false, true] {
        let mode = QuicUdpMode::TuicStream;
        let bind = "127.0.0.1:0".parse().unwrap();
        let hold = Arc::new(QuicStreamHold::default());
        let peer = QuicUdpPeer::start_with_stream_hold(mode, bind, Some(Arc::clone(&hold)))
            .await
            .unwrap();
        let mut f = Fixture::with_peer(mode, bind, peer, &[ScopeId::HOST]).await;
        hold.release.notify_one();
        let sibling = f.flow(0, b"sibling").await;
        hold.entered.notified().await;
        let first = f.packet().await;
        let target = f.target(1);
        let attachment = f
            .prepare(
                honk_datapath::ScopeId::HOST,
                f.client(),
                target,
                None,
                false,
            )
            .await
            .commit(&f.pool)
            .await
            .unwrap();
        let owner = attachment.owner();
        owner.set_send_timeout_for_test(SHORT_WAIT);
        let before = honk_outbound::quic::quic_stats_snapshot().send_timeouts;
        let lease = f.reserve(
            honk_datapath::ScopeId::HOST,
            f.client(),
            target,
            &[0x5a; TEST_PACKET_SIZE],
        );
        let (endpoint, mut driver) = f
            .install(lease, attachment, f.client(), target, target)
            .await;
        tokio::time::timeout(TEST_TIMEOUT, hold.entered.notified())
            .await
            .unwrap();
        // The peer has read the command, while its 64-byte QUIC stream window
        // prevents the complete UDP frame from being accepted by write_all.
        if retire {
            f.pool
                .remove(honk_datapath::ScopeId::HOST, f.client(), target);
            hold.release.notify_one();
            assert_eq!(
                driver.wait_first_ack().await.unwrap_err().kind(),
                io::ErrorKind::ConnectionAborted
            );
            let sent = f.packet().await;
            assert_eq!(sent.payload, [0x5a; TEST_PACKET_SIZE]);
            assert_eq!(
                (sent.connection, sent.session),
                (first.connection, first.session)
            );
            assert_eq!(
                honk_outbound::quic::quic_stats_snapshot().send_timeouts,
                before
            );
            f.targets[0]
                .send_to(b"surviving-sibling", first.mapping)
                .await
                .unwrap();
            assert_eq!(
                received(&f.client).await,
                (b"surviving-sibling".to_vec(), f.target(0))
            );
        } else {
            assert_eq!(
                driver.wait_first_ack().await.unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
            assert_eq!(
                honk_outbound::quic::quic_stats_snapshot().send_timeouts,
                before + 1,
                "driver must classify the retained QUIC token as timeout, not Drop failure"
            );
            hold.release.notify_one();
            tokio::time::timeout(TEST_TIMEOUT, hold.truncated.notified())
                .await
                .expect("partial TUIC request was not rejected");
        }
        assert_eq!(endpoint.upload.load(Ordering::Relaxed), 0);
        assert!(
            tokio::time::timeout(SHORT_WAIT, f.peer.packets.recv())
                .await
                .is_err(),
            "ambiguous send replayed"
        );
        drop((endpoint, sibling, owner));
        f.shutdown().await;
    }
}

#[tokio::test]
async fn hy2_source_sends_empty_request_but_rejects_empty_reply() {
    let mut f = Fixture::new(QuicUdpMode::Hysteria2, false).await;
    let endpoint = f.flow(0, b"").await;
    let packet = f.packet().await;
    assert!(packet.payload.is_empty());
    assert_eq!(received(&f.targets[0]).await, (Vec::new(), packet.mapping));
    f.targets[0].send_to(b"", packet.mapping).await.unwrap();
    no_reply(&f.client).await;
    assert!(!endpoint.has_reply());
    assert_eq!(endpoint.download.load(Ordering::Relaxed), 0);
    drop(endpoint);
    f.shutdown().await;
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn native_quic_source_records_current_view_and_reused_peer() {
    use crate::control::tests::support::NativeFlowApi;
    let api = NativeFlowApi::new().await;
    for mode in MODES {
        let mut f = Fixture::new(mode, false).await;
        let network = crate::observe::vocab::Network::Udp;
        let flows = std::array::from_fn::<_, 3, _>(|index| {
            Arc::new(
                api.flows
                    .begin(network, f.client(), f.target(index))
                    .unwrap(),
            )
        });
        let mut pending = Vec::new();
        for (index, flow) in flows.iter().enumerate().take(2) {
            let operation =
                std::pin::pin!(f.prepare(ScopeId::HOST, f.client(), f.target(index), None, false));
            let observer = flow.observer(5, None, "dial_target").unwrap();
            pending.push(observer.scope(operation).await);
        }
        let (mut pending, mut association) = (pending.into_iter(), None);
        for (index, flow) in flows.iter().enumerate() {
            let target = f.target(index);
            let attempt = uuid::Uuid::new_v4();
            let observer = flow.observer(7, Some(attempt), "dial_target").unwrap();
            let prepared = match pending.next() {
                Some(prepared) => prepared,
                None => {
                    f.prepare(
                        honk_datapath::ScopeId::HOST,
                        f.client(),
                        target,
                        None,
                        false,
                    )
                    .await
                }
            };
            let lease = f.reserve(
                honk_datapath::ScopeId::HOST,
                f.client(),
                target,
                b"observed",
            );
            let mut driver = {
                let operation = std::pin::pin!(async {
                    let attachment = prepared.commit(&f.pool).await.unwrap();
                    f.install(lease, attachment, f.client(), target, target)
                        .await
                        .1
                });
                observer.scope(operation).await
            };
            driver.wait_first_ack().await.unwrap();
            let packet = f.packet().await;
            let identity = (packet.connection, packet.session, packet.mapping);
            assert_eq!(*association.get_or_insert(identity), identity);
            let detail = api.detail(flow.id()).await;
            let steps = detail["trace"]["steps"].as_array().unwrap();
            let requests: Vec<_> = steps
                .iter()
                .filter(|step| step["data"]["milestone"] == "target_request_sent")
                .collect();
            assert_eq!(requests.len(), 1);
            let generation = &requests[0]["generation_id"];
            assert!(generation.as_str().unwrap().ends_with(":7"));
            assert_eq!(requests[0]["data"]["attempt_id"], attempt.to_string());
            if index > 0 {
                let current: Vec<_> = steps
                    .iter()
                    .filter(|step| step["generation_id"] == *generation)
                    .collect();
                let attached: Vec<_> = current
                    .iter()
                    .filter(|step| step["data"]["reason"] == "transport_attached")
                    .collect();
                assert_eq!(attached.len(), 1);
                assert_eq!(attached[0]["data"]["server_addr"], f.peer.node.address);
                assert_eq!(attached[0]["data"]["attempt_id"], attempt.to_string());
                assert!(!current.iter().any(|step| {
                    step["data"]["reason"] == "session_open_succeeded"
                        || step["stage"] == "outbound"
                }));
            }
        }
        f.shutdown().await;
    }
    api.shutdown().await;
}

mod association;
mod scopes;
