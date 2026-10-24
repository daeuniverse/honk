//! `SourcePath::Shared` over an in-memory `MultiTargetTransport` that reports
//! the real peer of every reply. Hy2/TUIC/VLESS keep their own suites.

use super::driver::UdpDriverHandle;
use super::source::{PreparedSourceTransport, ReplyAdmissionHook, SourceScope};
use super::source_quic_tests::{BoundReplies, TEST_TIMEOUT, no_reply, received};
use super::*;
use async_trait::async_trait;
use honk_config::node::{Node, OutboundConfig};
use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
use honk_outbound::group::{
    GroupManager, ScoreSelectionContext, ScoreVerificationState, SelectionNetwork,
};
use honk_outbound::proxy::{MultiTargetTransport, PacketTransport, PreparedUdpTransport};
use honk_outbound::runtime::{NodeRuntime, OutboundRuntimeRegistry};
use std::collections::HashMap;
use std::sync::Weak;

const TARGETS: usize = 8;

type Reply = io::Result<(Vec<u8>, SocketAddr)>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Sent {
    target: SocketAddr,
    domain: Option<String>,
    data: Vec<u8>,
    confirmed: bool,
}

/// Records every `send_to`, and returns whatever the test injects from any peer.
#[derive(Debug)]
struct MemoryTransport {
    live: Arc<AtomicUsize>,
    sent: Mutex<Vec<Sent>>,
    fixed_target_sends: AtomicUsize,
    fail_send: AtomicBool,
    stall_before_admission: AtomicBool,
    cancelled_sends: AtomicUsize,
    stall_mid_frame: AtomicBool,
    torn: AtomicBool,
    inject: mpsc::UnboundedSender<Reply>,
    replies: tokio::sync::Mutex<mpsc::UnboundedReceiver<Reply>>,
}

impl MemoryTransport {
    fn new(live: &Arc<AtomicUsize>) -> Arc<Self> {
        live.fetch_add(1, Ordering::SeqCst);
        let (inject, replies) = mpsc::unbounded_channel();
        Arc::new(Self {
            live: Arc::clone(live),
            sent: Mutex::new(Vec::new()),
            fixed_target_sends: AtomicUsize::new(0),
            fail_send: AtomicBool::new(false),
            stall_before_admission: AtomicBool::new(false),
            cancelled_sends: AtomicUsize::new(0),
            stall_mid_frame: AtomicBool::new(false),
            torn: AtomicBool::new(false),
            inject,
            replies: tokio::sync::Mutex::new(replies),
        })
    }

    fn reply(&self, peer: SocketAddr, data: &[u8]) {
        self.inject.send(Ok((data.to_vec(), peer))).unwrap();
    }

    fn fail_recv(&self) {
        self.inject
            .send(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "memory transport closed",
            )))
            .unwrap();
    }

    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().clone()
    }

    async fn wait_sent(&self, count: usize) -> Vec<Sent> {
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                let sent = self.sent();
                if sent.len() >= count {
                    return sent;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("transport did not receive the datagram")
    }
}

impl Drop for MemoryTransport {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl PacketTransport for MemoryTransport {
    fn relay_addr(&self) -> SocketAddr {
        "127.0.0.1:1".parse().unwrap()
    }

    /// Datagrams, like Hy2 and TUIC: an admitted write that times out is
    /// packet-local congestion, not a torn frame.
    fn send_timeout_is_congestion(&self) -> bool {
        true
    }

    async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
        self.fixed_target_sends.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("shared source must use send_to"))
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let reply = self.replies.lock().await.recv().await;
        let (data, peer) = reply.ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))??;
        buf[..data.len()].copy_from_slice(&data);
        Ok((data.len(), peer))
    }
}

#[async_trait]
impl MultiTargetTransport for MemoryTransport {
    async fn send_to(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        confirmed: bool,
        admitted: Option<&AtomicBool>,
    ) -> io::Result<()> {
        if self.torn.load(Ordering::SeqCst) {
            return Err(honk_outbound::proxy::FrameInterrupted.into());
        }
        if self.stall_mid_frame.load(Ordering::SeqCst) {
            self.torn.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
        }
        if self.fail_send.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "memory transport closed",
            ));
        }
        if self.stall_before_admission.load(Ordering::SeqCst) {
            let _cancelled = CountOnDrop(&self.cancelled_sends);
            std::future::pending::<()>().await;
        }
        self.sent.lock().push(Sent {
            target,
            domain: domain.map(str::to_owned),
            data: data.to_vec(),
            confirmed,
        });
        if let Some(admitted) = admitted {
            admitted.store(true, Ordering::Release);
        }

        Ok(())
    }

    fn carrier_addr(&self) -> Option<SocketAddr> {
        Some("127.0.0.1:2".parse().unwrap())
    }

    fn frame_stream_torn(&self) -> bool {
        self.torn.load(Ordering::SeqCst)
    }
}

struct CountOnDrop<'a>(&'a AtomicUsize);

impl Drop for CountOnDrop<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct Fixture {
    node: Node,
    generation: Arc<OutboundRuntimeRegistry>,
    runtime: Arc<NodeRuntime>,
    pool: Arc<UdpEndpointPool>,
    client: UdpSocket,
    targets: Vec<UdpSocket>,
    stats: Arc<StatsManager>,
    alive: Arc<AliveDialerSet>,
    score: GroupManager,
    family: IpVersion,
    live: Arc<AtomicUsize>,
    built: Mutex<Vec<Weak<MemoryTransport>>>,
}

impl Fixture {
    async fn new(ipv6: bool, capacity: usize) -> Self {
        let bind: SocketAddr = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" }
            .parse()
            .unwrap();
        let mut node = Node {
            name: "shared-source".into(),
            address: "127.0.0.1:1080".into(),
            host: "127.0.0.1".into(),
            port: 1080,
            outbound: OutboundConfig::Socks5(Default::default()),
            ..Default::default()
        };
        node.id = node.derive_id();
        let generation =
            Arc::new(OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap());
        let runtime = generation.get(&node.id).unwrap();
        let mut bound = HashMap::new();
        let mut targets = Vec::new();
        for _ in 0..TARGETS {
            let socket = std::net::UdpSocket::bind(bind).unwrap();
            socket.set_nonblocking(true).unwrap();
            bound.insert(socket.local_addr().unwrap(), socket.try_clone().unwrap());
            targets.push(UdpSocket::from_std(socket).unwrap());
        }
        let score = GroupManager::new(
            &[honk_config::node::Group {
                name: "score".into(),
                policy: honk_config::node::GroupPolicy::Score,
                nodes: vec![node.id],
                ..Default::default()
            }],
            std::slice::from_ref(&node),
        );
        Self {
            node,
            generation,
            runtime,
            pool: Arc::new(UdpEndpointPool::with_reply_socket_factory(
                capacity,
                Arc::new(BoundReplies(bound)),
            )),
            client: UdpSocket::bind(bind).await.unwrap(),
            targets,
            stats: Arc::new(StatsManager::new()),
            alive: Arc::new(AliveDialerSet::new()),
            score,
            family: if ipv6 { IpVersion::V6 } else { IpVersion::V4 },
            live: Arc::new(AtomicUsize::new(0)),
            built: Mutex::new(Vec::new()),
        }
    }

    fn target(&self, index: usize) -> SocketAddr {
        self.targets[index].local_addr().unwrap()
    }

    fn client(&self) -> SocketAddr {
        self.client.local_addr().unwrap()
    }

    /// The one transport still alive.
    fn transport(&self) -> Arc<MemoryTransport> {
        let alive: Vec<_> = self.built.lock().iter().filter_map(Weak::upgrade).collect();
        assert_eq!(alive.len(), 1, "expected exactly one live transport");
        alive.into_iter().next().unwrap()
    }

    /// A fresh preparation around its own in-memory transport, as a protocol's
    /// the registered shared-source capability would return.
    fn fresh(&self, client: SocketAddr, rewrite: Option<SocketAddr>) -> SourcePreparation {
        let transport = MemoryTransport::new(&self.live);
        self.built.lock().push(Arc::downgrade(&transport));
        SourcePreparation::Fresh {
            scope: SourceScope::new(&self.runtime, client, SourcePath::Shared, rewrite),
            prepared: PreparedSourceTransport::Shared(PreparedUdpTransport::ready(transport)),
            source_permit: self.pool.source_slots.clone().try_acquire_owned().unwrap(),
            runtime: Arc::clone(&self.runtime),
            alive_set: Arc::clone(&self.alive),
            stats: Arc::clone(&self.stats),
            node_id: self.node.id,
            node_name: self.node.name.clone(),
            health_family: self.family,
        }
    }

    /// Attach to a live source through the production `prepare_source`, or
    /// publish a fresh one when the scope has no owner.
    async fn attach(
        &self,
        client: SocketAddr,
        target: SocketAddr,
        rewrite: Option<SocketAddr>,
    ) -> SourceAttachment {
        let scope = SourceScope::new(&self.runtime, client, SourcePath::Shared, rewrite);
        let preparation = if self.pool.sources.contains_key(&scope) {
            self.pool
                .prepare_source(
                    &honk_outbound::proxy::ProxyRegistry::new(),
                    Arc::clone(&self.generation),
                    Arc::clone(&self.runtime),
                    client,
                    SourcePath::Shared,
                    rewrite,
                    target,
                    None,
                    TEST_TIMEOUT,
                    Arc::clone(&self.alive),
                    Arc::clone(&self.stats),
                    self.family,
                    false,
                )
                .await
                .unwrap()
        } else {
            self.fresh(client, rewrite)
        };
        preparation.commit(&self.pool).await.unwrap()
    }

    fn reserve(&self, client: SocketAddr, target: SocketAddr, payload: &[u8]) -> UdpInitLease {
        let slow = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let EndpointReservation::Initializing(lease) =
            self.pool
                .reserve_or_enqueue(client, target, payload, slow, &self.stats)
        else {
            panic!("expected vacant endpoint");
        };
        assert!(lease.bind_selected_node(self.node.id));
        lease
    }

    fn enqueue(&self, client: SocketAddr, target: SocketAddr, payload: &[u8]) {
        let slow = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        assert!(matches!(
            self.pool
                .reserve_or_enqueue(client, target, payload, slow, &self.stats),
            EndpointReservation::Enqueued
        ));
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
                self.node.id,
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
        let endpoint = Arc::new(UdpEndpoint::new_source_scored(
            attachment,
            target,
            None,
            Arc::new(self.pool.create_reply_socket(original).unwrap()),
            self.stats
                .outbound_tracker(&self.node.name, crate::stats::OutboundKind::Node),
            self.node.id,
            self.family,
            Some(reporter),
        ));
        let queue = lease.take_queue_receiver().unwrap();
        let mut driver = self.pool.spawn_driver(
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
                .outbound_tracker(&self.node.name, crate::stats::OutboundKind::Node),
        );
        driver.wait_ready().await.unwrap();
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        driver.start(lease.take_first().unwrap()).unwrap();
        (endpoint, driver)
    }

    async fn flow(&self, index: usize, payload: &[u8]) -> Arc<UdpEndpoint> {
        let target = self.target(index);
        let lease = self.reserve(self.client(), target, payload);
        let attachment = self.attach(self.client(), target, None).await;
        let (endpoint, mut driver) = self
            .install(lease, attachment, self.client(), target, target)
            .await;
        driver.wait_first_ack().await.unwrap();
        endpoint
    }

    async fn wait_until(&self, what: &str, mut done: impl FnMut() -> bool) {
        tokio::time::timeout(TEST_TIMEOUT, async {
            while !done() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
    }

    async fn shutdown(self) {
        assert!(self.pool.shutdown().await.joined);
        self.generation.shutdown().await;
        assert!(!self.generation.tasks_failed());
        assert_eq!(self.live.load(Ordering::SeqCst), 0, "transport leaked");
    }
}

#[tokio::test]
async fn shared_source_serves_every_destination_through_one_transport() {
    for ipv6 in [false, true] {
        let f = Fixture::new(ipv6, 16).await;
        let (client, a, b, c) = (f.client(), f.target(0), f.target(1), f.target(2));
        let lease_a = f.reserve(client, a, b"to-a");
        let lease_b = f.reserve(client, b, b"to-b");
        // Two preparations race to publish; one transport must survive.
        let (pa, pb) = (f.fresh(client, None), f.fresh(client, None));
        assert_eq!(f.live.load(Ordering::SeqCst), 2);
        let (aa, ab) = tokio::join!(pa.commit(&f.pool), pb.commit(&f.pool));
        let (ea, mut da) = f.install(lease_a, aa.unwrap(), client, a, a).await;
        let (eb, mut db) = f.install(lease_b, ab.unwrap(), client, b, b).await;
        da.wait_first_ack().await.unwrap();
        db.wait_first_ack().await.unwrap();
        assert_eq!(
            f.live.load(Ordering::SeqCst),
            1,
            "losing preparation leaked"
        );
        let transport = f.transport();

        // Each view's first datagram is confirmed, steady ones are not.
        let mut sent = transport.wait_sent(2).await;
        sent.sort_by_key(|sent| sent.target);
        let mut expected = vec![
            Sent {
                target: a,
                domain: None,
                data: b"to-a".to_vec(),
                confirmed: true,
            },
            Sent {
                target: b,
                domain: None,
                data: b"to-b".to_vec(),
                confirmed: true,
            },
        ];
        expected.sort_by_key(|sent| sent.target);
        assert_eq!(sent, expected);
        f.enqueue(client, a, b"a-steady");
        f.enqueue(client, b, b"b-steady");
        let sent = transport.wait_sent(4).await;
        for (target, payload) in [(a, b"a-steady"), (b, b"b-steady")] {
            assert!(
                sent[2..].contains(&Sent {
                    target,
                    domain: None,
                    data: payload.to_vec(),
                    confirmed: false,
                }),
                "steady send must not be confirmed"
            );
        }
        assert_eq!(transport.fixed_target_sends.load(Ordering::SeqCst), 0);

        // A never-contacted peer reaches the client with its own source and
        // creates neither endpoint nor Score credit.
        transport.reply(c, b"never-contacted-c");
        assert_eq!(
            received(&f.client).await,
            (b"never-contacted-c".to_vec(), c)
        );
        assert!(!ea.has_reply() && !eb.has_reply());
        assert_eq!(ea.download.load(Ordering::Relaxed), 0);
        assert_eq!(eb.download.load(Ordering::Relaxed), 0);
        assert_eq!(
            f.score
                .score_verification_for_network("score", SelectionNetwork::Udp)
                .unwrap()
                .1
                .state,
            ScoreVerificationState::Provisional
        );
        assert!(
            !f.pool.endpoints.contains_key(&EndpointKey::new(client, c)),
            "foreign replies cannot create flow authority"
        );

        for (peer, payload) in [(a, b"reply-a".as_slice()), (b, b"reply-b".as_slice())] {
            transport.reply(peer, payload);
            assert_eq!(received(&f.client).await, (payload.to_vec(), peer));
        }
        assert!(ea.has_reply() && eb.has_reply());
        assert_eq!(ea.download.load(Ordering::Relaxed), 7);
        drop((ea, eb, transport));
        f.shutdown().await;
    }
}

#[tokio::test]
async fn shared_source_domain_target_keeps_its_name_and_projects_replies() {
    let f = Fixture::new(false, 16).await;
    let (client, original, other) = (f.client(), f.target(0), f.target(1));
    let lease = f.reserve(client, original, b"to-domain");
    let attachment = f.attach(client, original, Some(original)).await;
    let (endpoint, mut driver) = f
        .install(lease, attachment, client, original, original)
        .await;
    driver.wait_first_ack().await.unwrap();
    let transport = f.transport();
    assert_eq!(transport.sent()[0].target, original);
    // RewriteTo scopes project every reply to the original destination and
    // never fall back to foreign delivery once the endpoint is gone. A pending
    // attachment keeps the source alive past its only view.
    let pending = f.attach(client, original, Some(original)).await;
    transport.reply(other, b"projected");
    assert_eq!(received(&f.client).await, (b"projected".to_vec(), original));
    f.pool.remove(client, original);
    drop((endpoint, driver));
    f.wait_until("projected endpoint to leave the pool", || f.pool.is_empty())
        .await;
    transport.reply(other, b"no-foreign-rewrite");
    no_reply(&f.client).await;
    drop((pending, transport));
    f.shutdown().await;
}

#[tokio::test]
async fn shared_source_foreign_reply_requires_vacant_live_owner() {
    let f = Fixture::new(false, 16).await;
    let (client, a, b, c, d) = (
        f.client(),
        f.target(0),
        f.target(1),
        f.target(2),
        f.target(3),
    );
    let ea = f.flow(0, b"a").await;
    let eb = f.flow(1, b"b").await;
    let transport = f.transport();

    // Initializing tuple: not foreign.
    let initializing = f.reserve(client, c, b"initializing");
    transport.reply(c, b"blocked-initializing");
    no_reply(&f.client).await;
    drop(initializing);

    // A tuple owned by another source scope: not foreign.
    let lease = f.reserve(client, d, b"other-owner");
    let attachment = f.attach(client, d, Some(d)).await;
    let (other, mut driver) = f.install(lease, attachment, client, d, d).await;
    driver.wait_first_ack().await.unwrap();
    transport.reply(d, b"wrong-owner");
    no_reply(&f.client).await;

    // Retiring tuple: not foreign, sibling views keep working.
    f.pool.remove(client, a);
    transport.reply(a, b"retiring");
    no_reply(&f.client).await;
    drop(ea);
    transport.reply(a, b"retired");
    no_reply(&f.client).await;
    transport.reply(b, b"sibling-lives");
    assert_eq!(received(&f.client).await, (b"sibling-lives".to_vec(), b));
    assert!(eb.has_reply());
    drop((eb, other, transport));
    f.shutdown().await;
}

#[tokio::test]
async fn shared_source_forgets_the_oldest_retired_peer() {
    use super::source::SourceEndpoint;

    let f = Fixture::new(false, 16).await;
    let (client, oldest, recent) = (f.client(), f.target(1), f.target(2));
    let endpoint = f.flow(0, b"bound").await;
    let transport = f.transport();
    let reply_socket = Arc::new(f.pool.create_reply_socket(f.target(0)).unwrap());
    // 65 later retirements push `oldest` out of the 64-peer fence.
    let retired = std::iter::once(oldest)
        .chain((0..64).map(|index| SocketAddr::from(([192, 0, 2, 1], 10000 + index))))
        .chain([recent]);
    for target in retired {
        let view = SourceEndpoint::new(
            f.attach(client, target, None).await,
            target,
            None,
            Arc::clone(&reply_socket),
            f.stats
                .outbound_tracker(&f.node.name, crate::stats::OutboundKind::Node),
        );
        view.retire(&AtomicBool::new(false));
    }
    transport.reply(recent, b"late");
    no_reply(&f.client).await;
    transport.reply(oldest, b"foreign");
    assert_eq!(received(&f.client).await, (b"foreign".to_vec(), oldest));
    drop((endpoint, transport, reply_socket));
    f.shutdown().await;
}

#[tokio::test]
async fn shared_source_terminal_error_retires_every_view() {
    for fail_send in [false, true] {
        let f = Fixture::new(false, 16).await;
        let (client, a) = (f.client(), f.target(0));
        let ea = f.flow(0, b"a").await;
        let eb = f.flow(1, b"b").await;
        let transport = f.transport();
        if fail_send {
            transport.fail_send.store(true, Ordering::SeqCst);
            f.enqueue(client, a, b"fails");
        } else {
            transport.fail_recv();
        }
        f.wait_until("every sibling view to retire", || {
            ea.dead.load(Ordering::Acquire)
                && eb.dead.load(Ordering::Acquire)
                && f.pool.sources.is_empty()
        })
        .await;
        drop((ea, eb, transport));
        f.wait_until("endpoint removal", || f.pool.is_empty()).await;
        f.shutdown().await;
    }
}

/// A send still waiting before the transport admits its datagram is
/// packet-local, whatever the carrier: it cannot tear down sibling views, even
/// though a non-QUIC transport also gets an (inactive) QUIC attempt.
#[tokio::test]
async fn shared_source_unadmitted_send_timeout_keeps_sibling_views() {
    let f = Fixture::new(false, 16).await;
    let (client, a, b) = (f.client(), f.target(0), f.target(1));
    let ea = f.flow(0, b"a").await;
    let eb = f.flow(1, b"b").await;
    let transport = f.transport();
    f.pool
        .sources
        .iter()
        .next()
        .unwrap()
        .set_send_timeout_for_test(Duration::from_millis(20));

    transport
        .stall_before_admission
        .store(true, Ordering::SeqCst);
    f.enqueue(client, a, b"stalls");
    f.wait_until("stalled send to hit its deadline", || {
        transport.cancelled_sends.load(Ordering::SeqCst) == 1
    })
    .await;
    transport
        .stall_before_admission
        .store(false, Ordering::SeqCst);
    f.enqueue(client, b, b"after");
    f.wait_until("sibling send or retirement", || {
        transport.sent().len() == 3 || eb.dead.load(Ordering::Acquire)
    })
    .await;
    assert!(!ea.dead.load(Ordering::Acquire) && !eb.dead.load(Ordering::Acquire));
    assert_eq!(transport.sent()[2].data, b"after");
    drop((ea, eb, transport));
    f.shutdown().await;
}

/// Unadmitted deadlines stay packet-local only while the uplink still admits
/// datagrams: once a run of them has lasted the stall limit, the next one fails
/// the source and charges the node, so replies cannot keep it alive.
#[tokio::test]
async fn shared_source_uplink_stalled_past_the_limit_fails_the_node() {
    let f = Fixture::new(false, 16).await;
    let (client, a) = (f.client(), f.target(0));
    let ea = f.flow(0, b"a").await;
    let transport = f.transport();
    let owner = f
        .pool
        .sources
        .iter()
        .next()
        .map(|entry| Arc::clone(entry.value()))
        .unwrap();
    owner.set_send_timeout_for_test(Duration::from_millis(20));
    let node_alive = |f: &Fixture| {
        f.alive
            .is_alive_for(f.node.id, ProbeDomain::DataUdp, f.family)
    };
    for _ in 0..49 {
        f.alive
            .report_unavailable_traffic(f.node.id, ProbeDomain::DataUdp, f.family);
    }
    assert!(node_alive(&f));

    transport
        .stall_before_admission
        .store(true, Ordering::SeqCst);
    owner.uplink_stall.backdate_for_test();
    drop(owner);
    f.enqueue(client, a, b"stalls");
    f.wait_until("source to retire", || f.pool.sources.is_empty())
        .await;
    assert!(
        !node_alive(&f),
        "an uplink that admits nothing is evidence against the node"
    );
    drop((ea, transport));
    f.shutdown().await;
}

/// An admitted datagram ends the stall run, so the deadline after it starts a
/// new run instead of failing the source.
#[tokio::test]
async fn shared_source_uplink_stall_restarts_after_progress() {
    let f = Fixture::new(false, 16).await;
    let (client, a) = (f.client(), f.target(0));
    let ea = f.flow(0, b"a").await;
    let transport = f.transport();
    let owner = f
        .pool
        .sources
        .iter()
        .next()
        .map(|entry| Arc::clone(entry.value()))
        .unwrap();
    owner.set_send_timeout_for_test(Duration::from_millis(20));
    let node_alive = |f: &Fixture| {
        f.alive
            .is_alive_for(f.node.id, ProbeDomain::DataUdp, f.family)
    };
    for _ in 0..49 {
        f.alive
            .report_unavailable_traffic(f.node.id, ProbeDomain::DataUdp, f.family);
    }

    owner.uplink_stall.backdate_for_test();
    f.enqueue(client, a, b"progress");
    transport.wait_sent(2).await;
    transport
        .stall_before_admission
        .store(true, Ordering::SeqCst);
    f.enqueue(client, a, b"after progress");
    f.wait_until("deadline after progress", || {
        transport.cancelled_sends.load(Ordering::SeqCst) == 1
    })
    .await;
    assert!(!ea.dead.load(Ordering::Acquire) && !f.pool.sources.is_empty());
    assert!(node_alive(&f));
    drop((ea, transport, owner));
    f.shutdown().await;
}

/// The stall run only counts deadlines the transport never admitted: a
/// datagram the driver admitted is progress, so a deadline past the limit
/// that follows an admitted send leaves the source and its node alive.
#[tokio::test]
async fn shared_source_admitted_progress_clears_the_stall_run() {
    let f = Fixture::new(false, 16).await;
    let (client, a) = (f.client(), f.target(0));
    let ea = f.flow(0, b"a").await;
    let transport = f.transport();
    let owner = f
        .pool
        .sources
        .iter()
        .next()
        .map(|entry| Arc::clone(entry.value()))
        .unwrap();
    owner.set_send_timeout_for_test(Duration::from_millis(20));
    for _ in 0..49 {
        f.alive
            .report_unavailable_traffic(f.node.id, ProbeDomain::DataUdp, f.family);
    }

    // A run is already due; the admitted send lands in it before the next
    // deadline is charged.
    owner.uplink_stall.backdate_for_test();
    f.enqueue(client, a, b"admitted");
    transport.wait_sent(2).await;
    transport
        .stall_before_admission
        .store(true, Ordering::SeqCst);
    f.enqueue(client, a, b"stalls");
    f.wait_until("the unadmitted deadline", || {
        transport.cancelled_sends.load(Ordering::SeqCst) == 1
    })
    .await;
    assert!(
        !ea.dead.load(Ordering::Acquire) && !f.pool.sources.is_empty(),
        "the admitted send cleared the run, so this one is a fresh start"
    );
    assert!(
        f.alive
            .is_alive_for(f.node.id, ProbeDomain::DataUdp, f.family),
        "a fresh run does not charge the node"
    );
    drop((ea, transport, owner));
    f.shutdown().await;
}

/// A view retired while its frame write is in flight tears the stream its
/// siblings share. The sibling's refusal echoes that local cancellation, so
/// the source retires without charging the node.
#[tokio::test]
async fn shared_source_view_cancelled_mid_frame_does_not_blame_the_node() {
    let f = Fixture::new(false, 16).await;
    let (client, a, b) = (f.client(), f.target(0), f.target(1));
    let ea = f.flow(0, b"a").await;
    let eb = f.flow(1, b"b").await;
    let transport = f.transport();
    let node_alive = |f: &Fixture| {
        f.alive
            .is_alive_for(f.node.id, ProbeDomain::DataUdp, f.family)
    };
    for _ in 0..49 {
        f.alive
            .report_unavailable_traffic(f.node.id, ProbeDomain::DataUdp, f.family);
    }
    assert!(node_alive(&f));

    transport.stall_mid_frame.store(true, Ordering::SeqCst);
    let mut torn = Box::pin(eb.send_packet(b"torn", false));
    let stuck = std::future::poll_fn(|cx| {
        std::task::Poll::Ready(Future::poll(torn.as_mut(), cx).is_pending())
    })
    .await;
    assert!(stuck, "the frame write must stop mid-frame");
    f.pool.remove(client, b);
    drop(torn);
    transport.stall_mid_frame.store(false, Ordering::SeqCst);

    f.enqueue(client, a, b"sibling");
    f.wait_until("source to retire", || f.pool.sources.is_empty())
        .await;
    assert!(
        node_alive(&f),
        "a locally cancelled write is not evidence against the node"
    );
    drop((ea, eb, transport));
    f.shutdown().await;
}

#[tokio::test]
async fn shared_source_dropped_preparation_releases_everything() {
    let f = Fixture::new(false, 1).await;
    let preparation = f.fresh(f.client(), None);
    assert_eq!(f.live.load(Ordering::SeqCst), 1);
    assert_eq!(f.pool.source_slots.available_permits(), 0);
    drop(preparation);
    assert_eq!(f.live.load(Ordering::SeqCst), 0);
    assert_eq!(f.pool.source_slots.available_permits(), 1);
    assert!(f.pool.sources.is_empty());
    f.shutdown().await;
}

#[tokio::test]
async fn shared_source_keeps_last_endpoint_slot_until_receiver_exits() {
    let f = Fixture::new(false, 1).await;
    let (client, a, c) = (f.client(), f.target(0), f.target(2));
    let endpoint = f.flow(0, b"a").await;
    let transport = f.transport();
    let owner = f
        .pool
        .sources
        .iter()
        .next()
        .map(|entry| Arc::clone(entry.value()))
        .unwrap();
    // Park the receiver inside a foreign delivery, past the view's retirement.
    let hook = Arc::new(ReplyAdmissionHook::default());
    *owner.foreign_reply_hook.lock() = Some(Arc::clone(&hook));
    drop(owner);
    transport.reply(c, b"foreign");
    hook.entered.notified().await;

    f.pool.remove(client, a);
    drop(endpoint);
    f.wait_until("retired view to leave the pool", || f.pool.is_empty())
        .await;
    assert_eq!(f.pool.endpoint_slots.available_permits(), 0);
    let slow = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    assert!(matches!(
        f.pool
            .reserve_or_enqueue(client, f.target(1), b"new", slow, &f.stats),
        EndpointReservation::CapacityRejected
    ));

    hook.release.notify_one();
    drop(transport);
    f.wait_until("receiver to release the endpoint slot", || {
        f.pool.endpoint_slots.available_permits() == 1
    })
    .await;
    assert_eq!(
        f.live.load(Ordering::SeqCst),
        0,
        "slot outlived the transport"
    );
    assert_eq!(received(&f.client).await, (b"foreign".to_vec(), c));
    let slow = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    assert!(matches!(
        f.pool
            .reserve_or_enqueue(client, f.target(1), b"new", slow, &f.stats),
        EndpointReservation::Initializing(_)
    ));
    f.shutdown().await;
}

/// A pending attachment keeps the source alive past its last bound view, so the
/// view's endpoint slot must stay held until that attachment is gone and the
/// receiver has exited.
#[tokio::test]
async fn shared_source_keeps_endpoint_slot_while_an_attachment_outlives_the_last_view() {
    let f = Fixture::new(false, 1).await;
    let (client, a) = (f.client(), f.target(0));
    let endpoint = f.flow(0, b"a").await;
    let transport = f.transport();
    let pending = f.attach(client, f.target(1), None).await;

    f.pool.remove(client, a);
    drop(endpoint);
    f.wait_until("retired view to leave the pool", || f.pool.is_empty())
        .await;
    assert_eq!(
        f.pool.endpoint_slots.available_permits(),
        0,
        "the source I/O outlives the view while an attachment is pending"
    );

    drop(pending);
    drop(transport);
    f.wait_until("receiver to release the endpoint slot", || {
        f.pool.endpoint_slots.available_permits() == 1
    })
    .await;
    assert_eq!(f.live.load(Ordering::SeqCst), 0);
    f.shutdown().await;
}
