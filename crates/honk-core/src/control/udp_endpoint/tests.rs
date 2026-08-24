use super::*;

fn transport(
    sock: Arc<UdpSocket>,
    relay: SocketAddr,
) -> Arc<dyn honk_outbound::proxy::PacketTransport> {
    Arc::new(honk_outbound::proxy::UdpSocketTransport::new(sock, relay))
}

#[tokio::test]
async fn first_reply_metric_and_alive_reporting_are_throttled() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay = "127.0.0.1:53".parse().unwrap();
    let endpoint = UdpEndpoint::new(transport(socket, relay), relay, uuid::Uuid::new_v4());

    assert!(endpoint.take_first_reply_metric().is_some());
    assert!(endpoint.take_first_reply_metric().is_none());
    assert!(endpoint.take_alive_report_slot());
    assert!(!endpoint.take_alive_report_slot());
    endpoint
        .next_alive_report_at
        .store(monotonic_nanos().saturating_sub(1), Ordering::Relaxed);
    assert!(endpoint.take_alive_report_slot());
}

#[tokio::test]
async fn explicit_retirement_is_neutral_until_a_reply_makes_it_useful() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay = "127.0.0.1:53".parse().unwrap();
    let endpoint = UdpEndpoint::new(transport(socket, relay), relay, uuid::Uuid::new_v4());
    let result = Err(io::Error::new(io::ErrorKind::BrokenPipe, "retired"));
    endpoint.kill();

    assert_eq!(
        score_driver_outcome(&endpoint, &result),
        ScoreOutcome::Cancelled
    );
    endpoint.has_reply.store(true, Ordering::Relaxed);
    assert_eq!(
        score_driver_outcome(&endpoint, &result),
        ScoreOutcome::Success
    );
}

#[tokio::test]
async fn send_timeout_after_reply_is_not_idle_success() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay = "127.0.0.1:53".parse().unwrap();
    let endpoint = UdpEndpoint::new(transport(socket, relay), relay, uuid::Uuid::new_v4());
    endpoint.has_reply.store(true, Ordering::Relaxed);

    let send_timeout = Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "UDP PacketTransport send timed out",
    ));
    assert_eq!(
        score_driver_outcome(&endpoint, &send_timeout),
        ScoreOutcome::Io(io::ErrorKind::TimedOut)
    );

    let idle_timeout = Err(io::Error::new(io::ErrorKind::TimedOut, ReplyIdleTimeout));
    assert_eq!(
        score_driver_outcome(&endpoint, &idle_timeout),
        ScoreOutcome::Success
    );
}

async fn recv_and_ack(
    pool: &UdpEndpointPool,
    rx: &mut mpsc::Receiver<EndpointRemoval>,
) -> Option<EndpointRemoval> {
    let removal = rx.recv().await?;
    assert!(pool.complete_removal(
        removal.client,
        removal.dst,
        removal.decision_token,
        removal.generation,
    ));
    Some(removal)
}

fn try_recv_and_ack(
    pool: &UdpEndpointPool,
    rx: &mut mpsc::Receiver<EndpointRemoval>,
) -> Result<EndpointRemoval, mpsc::error::TryRecvError> {
    let removal = rx.try_recv()?;
    assert!(pool.complete_removal(
        removal.client,
        removal.dst,
        removal.decision_token,
        removal.generation,
    ));
    Ok(removal)
}
#[test]
fn pool_constructors_use_max_or_explicit_capacity() {
    assert_eq!(
        UdpEndpointPool::new().endpoint_slots.available_permits(),
        MAX_ENDPOINTS
    );
    assert_eq!(
        UdpEndpointPool::with_capacity_limit(3)
            .endpoint_slots
            .available_permits(),
        3
    );
    assert_eq!(
        UdpEndpointPool::with_capacity_limit(usize::MAX)
            .endpoint_slots
            .available_permits(),
        MAX_ENDPOINTS
    );
}

#[allow(clippy::too_many_arguments)]
async fn run_endpoint_driver(
    endpoint: Arc<UdpEndpoint>,
    queue_rx: mpsc::Receiver<QueuedDatagram>,
    reply_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    client_dst: SocketAddr,
    alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    stats: Arc<StatsManager>,
    outbound_name: String,
    first: QueuedDatagram,
    first_ack: oneshot::Sender<io::Result<()>>,
) -> io::Result<()> {
    let outbound_tracker = stats.outbound_tracker(&outbound_name);
    super::run_endpoint_driver(
        UdpDriverContext {
            endpoint,
            queue_rx,
            reply_socket,
            reply_socket_factory: Arc::new(SystemUdpReplySocketFactory),
            client_addr,
            client_dst,
            alive_set,
            stats,
            outbound_tracker,
            health_family: honk_outbound::alive::IpVersion::V4,
        },
        UdpDriverStart {
            first,
            followers: Vec::new(),
        },
        first_ack,
    )
    .await
}

fn make_addr(ip: &str, port: u16) -> SocketAddr {
    format!("{}:{}", ip, port).parse().unwrap()
}

#[derive(Debug)]
enum DriverSendAction {
    Ok,
    Error,
    Congestion,
    Panic,
    Pending,
    WaitThenOk(Arc<tokio::sync::Notify>),
    WaitThenError(Arc<tokio::sync::Notify>),
}

#[derive(Debug)]
enum DriverReceiveAction {
    Pending,
    Error,
    Packet { data: Vec<u8>, source: SocketAddr },
    WaitThenError(Arc<tokio::sync::Notify>),
}

#[derive(Debug)]
struct ScriptedPacketTransport {
    relay: SocketAddr,
    actions: Mutex<std::collections::VecDeque<DriverSendAction>>,
    recv_actions: Mutex<std::collections::VecDeque<DriverReceiveAction>>,
    sent: Mutex<Vec<Vec<u8>>>,
    confirmed_sends: std::sync::atomic::AtomicUsize,
    send_progress: tokio::sync::Notify,
    allows_full_cone_replies: bool,
}

impl ScriptedPacketTransport {
    fn new(relay: SocketAddr, actions: impl IntoIterator<Item = DriverSendAction>) -> Self {
        Self {
            relay,
            actions: Mutex::new(actions.into_iter().collect()),
            recv_actions: Mutex::new(std::collections::VecDeque::new()),
            sent: Mutex::new(Vec::new()),
            confirmed_sends: std::sync::atomic::AtomicUsize::new(0),
            send_progress: tokio::sync::Notify::new(),
            allows_full_cone_replies: false,
        }
    }

    fn with_receive_actions(
        relay: SocketAddr,
        send_actions: impl IntoIterator<Item = DriverSendAction>,
        recv_actions: impl IntoIterator<Item = DriverReceiveAction>,
    ) -> Self {
        Self {
            relay,
            actions: Mutex::new(send_actions.into_iter().collect()),
            recv_actions: Mutex::new(recv_actions.into_iter().collect()),
            sent: Mutex::new(Vec::new()),
            confirmed_sends: std::sync::atomic::AtomicUsize::new(0),
            send_progress: tokio::sync::Notify::new(),
            allows_full_cone_replies: false,
        }
    }

    fn allowing_full_cone_replies(mut self) -> Self {
        self.allows_full_cone_replies = true;
        self
    }

    fn sent_packets(&self) -> Vec<Vec<u8>> {
        self.sent.lock().clone()
    }

    fn confirmed_send_count(&self) -> usize {
        self.confirmed_sends
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn wait_for_send_count(&self, count: usize) {
        loop {
            if self.sent.lock().len() >= count {
                return;
            }
            self.send_progress.notified().await;
        }
    }
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketTransport for ScriptedPacketTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay
    }

    fn allows_full_cone_replies(&self) -> bool {
        self.allows_full_cone_replies
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        self.sent.lock().push(data.to_vec());
        self.send_progress.notify_waiters();
        let action = self
            .actions
            .lock()
            .pop_front()
            .unwrap_or(DriverSendAction::Ok);
        match action {
            DriverSendAction::Ok => Ok(()),
            DriverSendAction::Error => Err(io::Error::other("scripted UDP send failure")),
            DriverSendAction::Congestion => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "scripted UDP send congestion",
            )),
            DriverSendAction::Panic => panic!("scripted UDP send panic"),
            DriverSendAction::Pending => std::future::pending::<io::Result<()>>().await,
            DriverSendAction::WaitThenOk(release) => {
                release.notified().await;
                Ok(())
            }
            DriverSendAction::WaitThenError(release) => {
                release.notified().await;
                Err(io::Error::other("released scripted UDP send failure"))
            }
        }
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> io::Result<()> {
        self.confirmed_sends
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.send_packet(data).await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let action = self
            .recv_actions
            .lock()
            .pop_front()
            .unwrap_or(DriverReceiveAction::Pending);
        match action {
            DriverReceiveAction::Pending => {
                std::future::pending::<io::Result<(usize, SocketAddr)>>().await
            }
            DriverReceiveAction::Error => Err(io::Error::other("scripted UDP receive failure")),
            DriverReceiveAction::Packet { data, source } => {
                buf[..data.len()].copy_from_slice(&data);
                Ok((data.len(), source))
            }
            DriverReceiveAction::WaitThenError(release) => {
                release.notified().await;
                Err(io::Error::other("released scripted UDP receive failure"))
            }
        }
    }
}

fn reserve_driver_packets(
    pool: &Arc<UdpEndpointPool>,
    stats: &StatsManager,
    client: SocketAddr,
    dst: SocketAddr,
    first_data: &[u8],
    followers: &[&[u8]],
) -> (QueuedDatagram, mpsc::Receiver<QueuedDatagram>) {
    let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, first_data, first_permit, stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("driver test must reserve a fresh lease"),
    };
    for follower in followers {
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        assert!(matches!(
            pool.reserve_or_enqueue(client, dst, follower, slow_permit, stats),
            EndpointReservation::Enqueued
        ));
    }
    let queue_rx = lease.take_queue_receiver().unwrap();
    let first = lease.take_first().unwrap();
    // The direct worker tests drive `run_endpoint_driver`; dropping the
    // uncommitted lease closes the producer while preserving queued FIFO
    // messages in the receiver.
    drop(lease);
    (first, queue_rx)
}

const TEST_NODE_ID: uuid::Uuid = uuid::Uuid::from_u128(0x7e57);
const DEAD_NODE_ID: uuid::Uuid = uuid::Uuid::from_u128(0xdead);
const OTHER_NODE_ID: uuid::Uuid = uuid::Uuid::from_u128(0x07e4);
const JANITOR_NODE_ID: uuid::Uuid = uuid::Uuid::from_u128(0x9a17);

fn driver_test_endpoint(
    transport: Arc<ScriptedPacketTransport>,
    relay: SocketAddr,
) -> Arc<UdpEndpoint> {
    let transport: Arc<dyn honk_outbound::proxy::PacketTransport> = transport;
    Arc::new(UdpEndpoint::new(transport, relay, TEST_NODE_ID))
}

#[test]
fn fixed_peer_validation_survives_establishment() {
    let expected = make_addr("192.0.2.1", 53);
    let unexpected = make_addr("192.0.2.2", 53);
    let transport = Arc::new(ScriptedPacketTransport::new(expected, []));
    let endpoint = driver_test_endpoint(transport, expected);
    endpoint.record_pending_reply_peer(expected);
    assert!(endpoint.validate_reply_peer(expected));
    endpoint.mark_reply();
    assert!(!endpoint.validate_reply_peer(unexpected));
}

async fn test_reply_socket() -> Arc<UdpSocket> {
    Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
}

#[derive(Debug)]
struct InjectedReplySocketFactory {
    sockets: Mutex<std::collections::HashMap<SocketAddr, std::net::UdpSocket>>,
    created: Mutex<Vec<SocketAddr>>,
}

impl InjectedReplySocketFactory {
    fn new(sockets: impl IntoIterator<Item = std::net::UdpSocket>) -> Self {
        Self {
            sockets: Mutex::new(
                sockets
                    .into_iter()
                    .map(|socket| (socket.local_addr().unwrap(), socket))
                    .collect(),
            ),
            created: Mutex::new(Vec::new()),
        }
    }

    fn created(&self) -> Vec<SocketAddr> {
        self.created.lock().clone()
    }
}

impl UdpReplySocketFactory for InjectedReplySocketFactory {
    fn create(&self, source: SocketAddr) -> io::Result<UdpSocket> {
        let socket = self.sockets.lock().remove(&source).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no injected reply socket for {source}"),
            )
        })?;
        socket.set_nonblocking(true)?;
        self.created.lock().push(source);
        UdpSocket::from_std(socket)
    }
}

fn commit_ready(
    pool: &Arc<UdpEndpointPool>,
    client: SocketAddr,
    dst: SocketAddr,
    proxy_socket: Arc<dyn honk_outbound::proxy::PacketTransport>,
    relay: SocketAddr,
    node_id: uuid::Uuid,
) -> Arc<UdpEndpoint> {
    let stats = StatsManager::new();
    let slow_permit = Arc::new(Semaphore::new(1))
        .try_acquire_owned()
        .expect("test slow permit");
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"test", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("expected a new initializer lease"),
    };
    let endpoint = Arc::new(UdpEndpoint::new(proxy_socket, relay, node_id));
    assert!(lease.commit_ready(Arc::clone(&endpoint)));
    endpoint
}

#[test]
fn test_endpoint_key() {
    // Key is (client, dst) not (client, relay)
    let a = EndpointKey::new(make_addr("1.2.3.4", 80), make_addr("5.6.7.8", 443));
    let b = EndpointKey::new(make_addr("1.2.3.4", 80), make_addr("5.6.7.8", 443));
    let c = EndpointKey::new(make_addr("1.2.3.5", 80), make_addr("5.6.7.8", 443));
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn test_endpoint_key_ipv6() {
    let a = EndpointKey::new(
        make_addr("[2001:db8::1]", 8080),
        make_addr("[2001:db8::2]", 9090),
    );
    let b = EndpointKey::new(
        make_addr("[2001:db8::1]", 8080),
        make_addr("[2001:db8::2]", 9090),
    );
    assert_eq!(a, b);
}

#[test]
fn test_pool_empty_operations() {
    let pool = UdpEndpointPool::new();
    assert!(pool.is_empty());
    assert_eq!(pool.len(), 0);
    assert_eq!(pool.janitor_cycle(), 0);
}

#[test]
fn test_pool_get() {
    let pool = UdpEndpointPool::new();
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    assert!(pool.get(client, dst).is_none());
}

#[test]
fn udp_init_lease_reserves_one_initializing_incarnation_per_key() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = StatsManager::new();
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let first = pool.reserve_or_enqueue(client, dst, b"first", first_permit, &stats);
    assert!(matches!(first, EndpointReservation::Initializing(_)));

    let follower_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    assert!(matches!(
        pool.reserve_or_enqueue(client, dst, b"follower", follower_permit, &stats),
        EndpointReservation::Enqueued
    ));
    assert_eq!(pool.len(), 1);
}

#[test]
fn udp_init_lease_old_generation_cannot_remove_replacement() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = StatsManager::new();
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let first = match pool.reserve_or_enqueue(client, dst, b"old", first_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("first reservation must initialize"),
    };
    let key = first.key;
    let old_generation = first.generation();
    let old_token = first.decision_token();
    drop(first);

    let replacement_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let replacement =
        match pool.reserve_or_enqueue(client, dst, b"replacement", replacement_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("replacement reservation must initialize"),
        };
    pool.retire_if_same(key, old_token, old_generation);
    assert_eq!(pool.len(), 1, "old cleanup must not remove replacement");
    drop(replacement);
    assert!(pool.is_empty());
}

#[test]
fn udp_owned_admission_transfers_allocations_and_preserves_identity() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = StatsManager::new();
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 443);
    let slow_slots = Arc::new(Semaphore::new(1));
    let payload = Bytes::from(vec![0x41; 37]);
    let payload_ptr = payload.as_ptr();
    let slow_permit = slow_slots.clone().try_acquire_owned().unwrap();
    let mut lease =
        match pool.reserve_owned_or_enqueue(client, dst, payload, 41, None, slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("owned first payload must initialize"),
        };
    assert_eq!(lease.first_payload().as_ptr(), payload_ptr);
    assert_eq!(lease.decision_token(), 41);
    assert!(lease.dns_checked());
    assert_eq!(slow_slots.available_permits(), 0);
    assert_eq!(
        pool.global_payload_bytes.available_permits(),
        GLOBAL_PAYLOAD_CAPACITY - 37
    );

    let mut receiver = lease.take_queue_receiver().unwrap();
    let follower = Bytes::from(vec![0x42; 19]);
    let follower_ptr = follower.as_ptr();
    let follower_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    assert!(matches!(
        pool.reserve_owned_or_enqueue(
            client,
            dst,
            follower,
            41,
            Some(lease.generation()),
            follower_permit,
            &stats,
        ),
        EndpointReservation::Enqueued
    ));
    let queued = receiver.try_recv().unwrap();
    assert_eq!(queued.data.as_ptr(), follower_ptr);
    drop(queued);
    drop(lease.take_first());
    drop(lease);
    assert_eq!(slow_slots.available_permits(), 1);
    assert_eq!(
        pool.global_payload_bytes.available_permits(),
        GLOBAL_PAYLOAD_CAPACITY
    );
}

#[test]
fn udp_retiring_tombstone_requires_exact_ack_before_tuple_reuse() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = StatsManager::new();
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 443);
    let (removed_tx, mut removed_rx) = mpsc::channel(4);
    pool.set_remove_sink(removed_tx);
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let lease = match pool.reserve_owned_or_enqueue(
        client,
        dst,
        Bytes::from_static(b"held"),
        77,
        None,
        slow_permit,
        &stats,
    ) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("staged payload must initialize"),
    };
    let generation = lease.generation();
    assert!(pool.retire_staged_identity(client, dst, 77, generation));
    assert!(!lease.still_initializing());
    assert!(matches!(
        pool.reserve_or_enqueue(
            client,
            dst,
            b"too-early",
            Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            &stats,
        ),
        EndpointReservation::QueueClosed
    ));
    assert!(!pool.complete_removal(client, dst, 78, generation));
    assert!(!pool.complete_removal(client, dst, 77, generation + 1));
    let removal = removed_rx.try_recv().unwrap();
    assert_eq!(removal.decision_token, 77);
    assert_eq!(removal.generation, generation);
    assert!(pool.complete_removal(client, dst, 77, generation));

    let replacement = match pool.reserve_or_enqueue(
        client,
        dst,
        b"replacement",
        Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
        &stats,
    ) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("acknowledged tombstone must allow replacement"),
    };
    assert_ne!(replacement.generation(), generation);
    assert!(!pool.complete_removal(client, dst, 77, generation));
    assert!(replacement.still_initializing());
    drop(replacement);
    let replacement_removal = removed_rx.try_recv().unwrap();
    assert!(pool.complete_removal(
        replacement_removal.client,
        replacement_removal.dst,
        replacement_removal.decision_token,
        replacement_removal.generation,
    ));
}

#[test]
fn udp_kernel_handoff_preserves_terminal_identity_until_ack() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = StatsManager::new();
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 443);
    let (removed_tx, mut removed_rx) = mpsc::channel(1);
    pool.set_remove_sink(removed_tx);
    let mut lease = match pool.reserve_owned_or_enqueue(
        client,
        dst,
        Bytes::from_static(b"held"),
        91,
        None,
        Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
        &stats,
    ) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("staged payload must initialize"),
    };
    let generation = lease.generation();
    assert!(lease.commit_kernel_handoff());
    let removal = removed_rx.try_recv().unwrap();
    assert_eq!(removal.reason, RemovalReason::KernelHandoff);
    assert_eq!(removal.decision_token, 91);
    assert_eq!(removal.generation, generation);
    assert!(matches!(
        pool.reserve_owned_or_enqueue(
            client,
            dst,
            Bytes::from_static(b"late"),
            91,
            Some(generation),
            Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            &stats,
        ),
        EndpointReservation::QueueClosed
    ));
    assert!(pool.complete_removal(client, dst, 91, generation));
}

#[tokio::test]
async fn udp_exact_retirement_cancels_matching_initializer() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = StatsManager::new();
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 443);
    let (removed_tx, mut removed_rx) = mpsc::channel(1);
    pool.set_remove_sink(removed_tx);
    let lease = match pool.reserve_owned_or_enqueue(
        client,
        dst,
        Bytes::from_static(b"held"),
        97,
        None,
        Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
        &stats,
    ) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("staged payload must initialize"),
    };
    let generation = lease.generation();
    let cancellation = lease.wait_cancellation();

    assert!(pool.retire_staged_identity(client, dst, 97, generation));
    tokio::time::timeout(Duration::from_millis(100), cancellation)
        .await
        .expect("exact retirement must wake the initializer");
    let removal = removed_rx.try_recv().unwrap();
    assert!(pool.complete_removal(
        removal.client,
        removal.dst,
        removal.decision_token,
        removal.generation,
    ));
    drop(lease);
}

#[test]
fn udp_live_reconstruction_enqueues_owned_payload_by_token() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = StatsManager::new();
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 443);
    let relay = make_addr("192.168.1.1", 1080);
    let mut lease = match pool.reserve_owned_or_enqueue(
        client,
        dst,
        Bytes::from_static(b"first"),
        101,
        None,
        Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
        &stats,
    ) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("staged payload must initialize"),
    };
    let generation = lease.generation();
    let mut receiver = lease.take_queue_receiver().unwrap();
    let initializing_payload = Bytes::from(vec![0x44; 19]);
    let initializing_ptr = initializing_payload.as_ptr();
    assert!(matches!(
        pool.enqueue_owned_by_token(client, dst, initializing_payload, 101, &stats),
        Ok(found) if found == generation
    ));
    let queued = receiver.try_recv().unwrap();
    assert_eq!(queued.data.as_ptr(), initializing_ptr);
    drop(queued);
    let endpoint = driver_test_endpoint(Arc::new(ScriptedPacketTransport::new(relay, [])), relay);
    assert!(lease.commit_ready(endpoint));

    let payload = Bytes::from(vec![0x55; 23]);
    let payload_ptr = payload.as_ptr();
    assert!(matches!(
        pool.enqueue_owned_by_token(client, dst, payload, 101, &stats),
        Ok(found) if found == generation
    ));
    let queued = receiver.try_recv().unwrap();
    assert_eq!(queued.data.as_ptr(), payload_ptr);
    drop(queued);
    assert!(matches!(
        pool.reserve_owned_or_enqueue(
            client,
            dst,
            Bytes::from_static(b"stale"),
            101,
            Some(generation + 1),
            Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            &stats,
        ),
        EndpointReservation::IdentityMismatch
    ));
    pool.remove(client, dst);
}

#[test]
fn udp_fast_path_queue_has_exact_flow_bound_and_drops_newest() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = StatsManager::new();
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let lease = match pool.reserve_or_enqueue(client, dst, b"first", first_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("first reservation must initialize"),
    };
    for _ in 0..FLOW_QUEUE_CAPACITY - 1 {
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        assert!(matches!(
            pool.reserve_or_enqueue(client, dst, b"follower", permit, &stats),
            EndpointReservation::Enqueued
        ));
    }
    let overflow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    assert!(matches!(
        pool.reserve_or_enqueue(client, dst, b"newest", overflow_permit, &stats),
        EndpointReservation::QueueFull
    ));
    let snapshot = stats.udp_snapshot();
    assert_eq!(snapshot.queue_accepted, (FLOW_QUEUE_CAPACITY - 1) as u64);
    assert_eq!(snapshot.flow_queue_full, 1);
    drop(lease);
}

#[test]
fn udp_fast_path_queue_has_exact_global_payload_bound() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = StatsManager::new();
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let payload = vec![0x42; GLOBAL_PAYLOAD_CAPACITY];
    let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let lease = match pool.reserve_or_enqueue(client, dst, &payload, first_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("global-capacity packet must reserve"),
    };
    let follower_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    assert!(matches!(
        pool.reserve_or_enqueue(client, dst, b"x", follower_permit, &stats),
        EndpointReservation::QueueFull
    ));
    assert_eq!(stats.udp_snapshot().global_payload_full, 1);
    drop(lease);
}

#[test]
fn udp_fast_path_queue_closed_entry_retires_and_allows_recreation() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = StatsManager::new();
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let lease = match pool.reserve_or_enqueue(client, dst, b"first", first_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("closed queue fixture must initialize"),
    };
    drop(lease.take_queue_receiver().unwrap());

    // Initializing is a fast-path miss; closed-queue retirement happens on
    // the slow reserve_or_enqueue path, which then creates a replacement.
    assert!(
        pool.fast_path_enqueue(client, dst, b"after-close", &stats)
            .is_none(),
        "Initializing (even closed) is never a direct fast-path hit"
    );
    let next_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let replacement =
        match pool.reserve_or_enqueue(client, dst, b"replacement", next_permit, &stats) {
            EndpointReservation::Initializing(next) => next,
            _ => panic!("closed queue must allow recreation as Initializing"),
        };
    // The closed Initializing generation was retired; only the replacement remains.
    // The old lease identity cannot retire the newer generation.
    drop(lease);
    assert_eq!(pool.len(), 1);
    assert!(replacement.still_initializing());
    drop(replacement);
    assert!(pool.is_empty());
}

#[tokio::test]
async fn udp_init_lease_registers_cancellation_before_publishing() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let hook = Arc::new(ReservationPublicationHook {
        published: Arc::new(std::sync::Barrier::new(2)),
        resume: Arc::new(std::sync::Barrier::new(2)),
    });
    pool.set_reservation_publication_hook(Some(Arc::clone(&hook)));

    let (lease_tx, lease_rx) = std::sync::mpsc::sync_channel(1);
    let reserving_pool = Arc::clone(&pool);
    let reserving_stats = Arc::clone(&stats);
    let reserver = std::thread::spawn(move || {
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let lease = match reserving_pool.reserve_or_enqueue(
            client,
            dst,
            b"first",
            slow_permit,
            &reserving_stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("publication fixture must reserve an initializer"),
        };
        lease_tx.send(lease).unwrap();
    });

    hook.published.wait();
    let mut cancellation_sent = pool.cancel_epoch.subscribe();
    let cancelling_pool = Arc::clone(&pool);
    let cancelling =
        tokio::spawn(async move { cancelling_pool.cancel_initializers_and_wait().await });
    cancellation_sent
        .changed()
        .await
        .expect("cancellation sender must remain live");
    let active_at_publication = pool.active_initializers.load(Ordering::Acquire);

    hook.resume.wait();
    let lease = tokio::task::spawn_blocking(move || lease_rx.recv().unwrap())
        .await
        .unwrap();
    let lease_cancellation = lease.cancellation();
    let cancellation_was_observed = lease_cancellation.has_changed().unwrap();
    drop(lease);
    assert!(cancelling.await.unwrap());
    reserver.join().unwrap();
    pool.set_reservation_publication_hook(None);

    assert_eq!(
        active_at_publication, 1,
        "a published initializer must already keep cancellation waiters active"
    );
    assert!(
        cancellation_was_observed,
        "the lease must observe cancellation sent while publication was paused"
    );
    assert!(pool.is_empty());
}

#[tokio::test]
async fn udp_init_lease_reload_cancellation_drops_slot_before_returning() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = StatsManager::new();
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let lease = match pool.reserve_or_enqueue(client, dst, b"first", first_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("first reservation must initialize"),
    };
    let mut cancellation = lease.cancellation();
    let cancelling_pool = Arc::clone(&pool);
    let cancelled =
        tokio::spawn(async move { cancelling_pool.cancel_initializers_and_wait().await });
    tokio::time::timeout(Duration::from_secs(1), cancellation.changed())
        .await
        .expect("reload cancellation was not broadcast")
        .expect("reload cancellation sender closed");
    drop(lease);
    assert!(cancelled.await.unwrap());
    assert!(pool.is_empty());

    let next_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    assert!(matches!(
        pool.reserve_or_enqueue(client, dst, b"next", next_permit, &stats),
        EndpointReservation::Initializing(_)
    ));
}

#[tokio::test]
async fn udp_init_lease_cancellation_before_commit_fences_ready_publication() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("fence fixture must reserve an initializer"),
    };
    let mut cancellation = lease.cancellation();
    let cancelling_pool = Arc::clone(&pool);
    let cancelling =
        tokio::spawn(async move { cancelling_pool.cancel_initializers_and_wait().await });
    tokio::time::timeout(Duration::from_secs(1), cancellation.changed())
        .await
        .expect("test barrier must observe cancellation")
        .expect("cancellation sender must remain live");

    let relay = make_addr("192.168.1.1", 1080);
    let endpoint = Arc::new(UdpEndpoint::new(
        Arc::new(ScriptedPacketTransport::new(relay, []))
            as Arc<dyn honk_outbound::proxy::PacketTransport>,
        relay,
        TEST_NODE_ID,
    ));
    assert!(
        !lease.commit_ready(endpoint),
        "cancellation that linearizes first must fence the old commit"
    );
    drop(lease);
    assert!(cancelling.await.unwrap());
    assert!(pool.is_empty());
}

#[tokio::test]
async fn udp_init_lease_commit_before_cancellation_keeps_ready_endpoint() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = StatsManager::new();
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("fence fixture must reserve an initializer"),
    };
    let relay = make_addr("192.168.1.1", 1080);
    let endpoint = Arc::new(UdpEndpoint::new(
        Arc::new(ScriptedPacketTransport::new(relay, []))
            as Arc<dyn honk_outbound::proxy::PacketTransport>,
        relay,
        TEST_NODE_ID,
    ));
    assert!(lease.commit_ready(Arc::clone(&endpoint)));
    drop(lease);

    assert!(pool.cancel_initializers_and_wait().await);
    assert!(
        Arc::ptr_eq(&pool.get(client, dst).unwrap(), &endpoint),
        "an ordinary reload only cancels Initializing work"
    );
    pool.remove(client, dst);
}

#[test]
fn udp_init_lease_drop_notifies_registered_tracker_once() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = StatsManager::new();
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
    pool.set_remove_sink(removed_tx);
    let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let lease = match pool.reserve_or_enqueue(client, dst, b"first", first_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("first reservation must initialize"),
    };
    assert!(lease.set_tracker_id("tracker-before-commit".to_owned()));

    drop(lease);

    assert_eq!(
        try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
        EndpointRemoval {
            client,
            dst,
            decision_token: 0,
            generation: 1,
            conn_id: Some("tracker-before-commit".to_owned()),
            reason: RemovalReason::UserspaceEndpointRetired,
        }
    );
    assert!(matches!(
        removed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn udp_init_lease_abort_and_panic_release_generation_for_reuse() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);

    let (reserved_tx, reserved_rx) = oneshot::channel();
    let abort_pool = Arc::clone(&pool);
    let abort_stats = Arc::clone(&stats);
    let aborted = tokio::spawn(async move {
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let lease =
            match abort_pool.reserve_or_enqueue(client, dst, b"abort", slow_permit, &abort_stats) {
                EndpointReservation::Initializing(lease) => lease,
                _ => panic!("abort test must initialize"),
            };
        let _lease = lease;
        reserved_tx.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    reserved_rx.await.unwrap();
    aborted.abort();
    assert!(aborted.await.unwrap_err().is_cancelled());
    assert!(pool.is_empty(), "aborted initializer must drop its lease");

    let panic_pool = Arc::clone(&pool);
    let panic_stats = Arc::clone(&stats);
    let panicked = tokio::spawn(async move {
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let _lease =
            match panic_pool.reserve_or_enqueue(client, dst, b"panic", slow_permit, &panic_stats) {
                EndpointReservation::Initializing(lease) => lease,
                _ => panic!("panic test must initialize"),
            };
        panic!("intentional initializer panic");
    });
    assert!(panicked.await.unwrap_err().is_panic());
    assert!(pool.is_empty(), "panicked initializer must drop its lease");

    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let next = pool.reserve_or_enqueue(client, dst, b"next", slow_permit, &stats);
    assert!(matches!(next, EndpointReservation::Initializing(_)));
}

#[tokio::test]
async fn udp_ready_endpoint_survives_ordinary_reload_cancellation() {
    // Real driver: ready → commit → first/ack, leave receive pending,
    // production reload cancellation, then prove the mapping still
    // accepts and delivers traffic before deterministic cleanup.
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let transport = Arc::new(ScriptedPacketTransport::with_receive_actions(
        relay,
        [DriverSendAction::Ok, DriverSendAction::Ok],
        [DriverReceiveAction::Pending],
    ));
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("reload-ready fixture must initialize"),
    };
    let endpoint = Arc::new(UdpEndpoint::new(
        transport.clone() as Arc<dyn honk_outbound::proxy::PacketTransport>,
        relay,
        TEST_NODE_ID,
    ));
    let queue_rx = lease.take_queue_receiver().unwrap();
    let mut driver = pool.spawn_driver(
        client,
        dst,
        lease.generation(),
        lease.decision_token(),
        Arc::clone(&endpoint),
        queue_rx,
        test_reply_socket().await,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "test-node".to_owned(),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease.commit_ready(Arc::clone(&endpoint)));
    driver.start(lease.take_first().unwrap()).unwrap();
    driver.wait_first_ack().await.unwrap();
    drop(lease);

    assert!(pool.cancel_initializers_and_wait().await);
    assert!(
        Arc::ptr_eq(&pool.get(client, dst).unwrap(), &endpoint),
        "ordinary reload cancels Initializing work only"
    );

    // Post-reload: steady packet must still enqueue and reach transport.
    let follower_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    assert!(matches!(
        pool.reserve_or_enqueue(client, dst, b"after-reload", follower_permit, &stats),
        EndpointReservation::Enqueued
    ));
    transport.wait_for_send_count(2).await;
    assert_eq!(
        transport.sent_packets(),
        vec![b"first".to_vec(), b"after-reload".to_vec()]
    );

    pool.remove(client, dst);
    tokio::task::yield_now().await;
    assert!(pool.is_empty());
}

#[tokio::test]
async fn udp_endpoint_replies_from_each_accepted_transport_source() {
    let source_socket_a = std::net::UdpSocket::bind("127.0.0.2:0").unwrap();
    let source_socket_b = std::net::UdpSocket::bind("127.0.0.3:0").unwrap();
    let source_a = source_socket_a.local_addr().unwrap();
    let source_b = source_socket_b.local_addr().unwrap();
    let factory = Arc::new(InjectedReplySocketFactory::new([
        source_socket_a,
        source_socket_b,
    ]));
    let pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        1,
        factory.clone(),
    ));
    let stats = Arc::new(StatsManager::new());
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = client_socket.local_addr().unwrap();
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, source_a, b"request", slow_permit, &stats)
    {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("reply-source fixture must initialize"),
    };
    let transport = Arc::new(
        ScriptedPacketTransport::with_receive_actions(
            source_a,
            [DriverSendAction::Ok],
            [
                DriverReceiveAction::Packet {
                    data: b"from-b".to_vec(),
                    source: source_b,
                },
                DriverReceiveAction::Packet {
                    data: b"from-a".to_vec(),
                    source: source_a,
                },
                DriverReceiveAction::Packet {
                    data: b"from-b-again".to_vec(),
                    source: source_b,
                },
                DriverReceiveAction::Pending,
            ],
        )
        .allowing_full_cone_replies(),
    );
    let endpoint = driver_test_endpoint(transport, source_a);
    endpoint.record_pending_reply_peer(source_a);
    let queue_rx = lease.take_queue_receiver().unwrap();
    let reply_socket = Arc::new(pool.create_reply_socket(source_a).unwrap());
    let mut driver = pool.spawn_driver(
        client,
        source_a,
        lease.generation(),
        lease.decision_token(),
        Arc::clone(&endpoint),
        queue_rx,
        reply_socket,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "test-node".to_owned(),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease.commit_ready(endpoint));
    driver.start(lease.take_first().unwrap()).unwrap();
    drop(lease);
    driver.wait_first_ack().await.unwrap();

    let mut buf = [0u8; 16];
    for (expected_payload, expected_source) in [
        (b"from-b".as_slice(), source_b),
        (b"from-a".as_slice(), source_a),
        (b"from-b-again".as_slice(), source_b),
    ] {
        let (n, source) =
            tokio::time::timeout(Duration::from_secs(1), client_socket.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buf[..n], expected_payload);
        assert_eq!(source, expected_source);
    }
    assert_eq!(factory.created(), vec![source_a, source_b]);

    driver.abort();
    assert!(pool.shutdown().await);
}

#[tokio::test]
async fn udp_endpoint_worker_sends_first_then_fifo_followers() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let (first, queue_rx) =
        reserve_driver_packets(&pool, &stats, client, dst, b"first", &[b"second", b"third"]);
    let transport = Arc::new(ScriptedPacketTransport::new(
        relay,
        [
            DriverSendAction::Ok,
            DriverSendAction::Ok,
            DriverSendAction::Ok,
        ],
    ));
    let endpoint = driver_test_endpoint(Arc::clone(&transport), relay);
    let (first_ack_tx, first_ack_rx) = oneshot::channel();
    let worker = tokio::spawn(run_endpoint_driver(
        endpoint,
        queue_rx,
        test_reply_socket().await,
        client,
        dst,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "test-node".to_owned(),
        first,
        first_ack_tx,
    ));

    first_ack_rx.await.unwrap().unwrap();
    transport.wait_for_send_count(3).await;
    assert_eq!(
        transport.sent_packets(),
        vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
    );
    assert_eq!(transport.confirmed_send_count(), 1);
    assert_eq!(stats.udp_snapshot().first_send_latency.count, 1);
    worker.abort();
}

#[tokio::test(start_paused = true)]
async fn udp_endpoint_worker_treats_stream_send_timeout_as_connection_dead() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let (first, queue_rx) = reserve_driver_packets(&pool, &stats, client, dst, b"first", &[]);
    let transport = Arc::new(ScriptedPacketTransport::new(
        relay,
        [DriverSendAction::Pending],
    ));
    let endpoint = driver_test_endpoint(transport, relay);
    let (first_ack_tx, first_ack_rx) = oneshot::channel();
    let worker = tokio::spawn(run_endpoint_driver(
        endpoint,
        queue_rx,
        test_reply_socket().await,
        client,
        dst,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "test-node".to_owned(),
        first,
        first_ack_tx,
    ));

    tokio::task::yield_now().await;
    tokio::time::advance(TRANSPORT_SEND_TIMEOUT).await;
    assert_eq!(
        first_ack_rx.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        worker.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );

    assert_eq!(stats.udp_snapshot().first_send_failures, 1);
}

#[tokio::test(start_paused = true)]
async fn udp_endpoint_worker_keeps_flow_alive_on_congested_steady_send() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let (first, queue_rx) =
        reserve_driver_packets(&pool, &stats, client, dst, b"first", &[b"steady"]);
    let transport = Arc::new(ScriptedPacketTransport::new(
        relay,
        [DriverSendAction::Ok, DriverSendAction::Congestion],
    ));
    let endpoint = driver_test_endpoint(Arc::clone(&transport), relay);
    let (first_ack_tx, first_ack_rx) = oneshot::channel();
    let worker = tokio::spawn(run_endpoint_driver(
        endpoint,
        queue_rx,
        test_reply_socket().await,
        client,
        dst,
        Arc::clone(&alive),
        Arc::clone(&stats),
        "test-node".to_owned(),
        first,
        first_ack_tx,
    ));

    assert!(first_ack_rx.await.unwrap().is_ok());
    transport.wait_for_send_count(2).await;
    assert_eq!(
        worker.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(stats.udp_snapshot().first_send_failures, 0);
    assert!(
        alive
            .get_probe_history(
                TEST_NODE_ID,
                honk_outbound::alive::ProbeDomain::DataUdp,
                honk_outbound::alive::IpVersion::V4,
            )
            .is_empty(),
        "send congestion must not report the node unavailable"
    );
}

#[tokio::test]
async fn udp_endpoint_worker_blocked_flow_does_not_block_another() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let relay = make_addr("192.168.1.1", 1080);
    let blocked_client = make_addr("10.0.0.1", 12345);
    let ready_client = make_addr("10.0.0.2", 12345);
    let dst = make_addr("8.8.8.8", 53);

    let (blocked_first, blocked_rx) =
        reserve_driver_packets(&pool, &stats, blocked_client, dst, b"blocked", &[]);
    let blocked_transport = Arc::new(ScriptedPacketTransport::new(
        relay,
        [DriverSendAction::Pending],
    ));
    let (blocked_ack_tx, _blocked_ack_rx) = oneshot::channel();
    let blocked_worker = tokio::spawn(run_endpoint_driver(
        driver_test_endpoint(Arc::clone(&blocked_transport), relay),
        blocked_rx,
        test_reply_socket().await,
        blocked_client,
        dst,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "test-node".to_owned(),
        blocked_first,
        blocked_ack_tx,
    ));
    blocked_transport.wait_for_send_count(1).await;

    let (ready_first, ready_rx) =
        reserve_driver_packets(&pool, &stats, ready_client, dst, b"other-flow", &[]);
    let ready_transport = Arc::new(ScriptedPacketTransport::new(relay, [DriverSendAction::Ok]));
    let (ready_ack_tx, ready_ack_rx) = oneshot::channel();
    let ready_worker = tokio::spawn(run_endpoint_driver(
        driver_test_endpoint(Arc::clone(&ready_transport), relay),
        ready_rx,
        test_reply_socket().await,
        ready_client,
        dst,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        stats,
        "test-node".to_owned(),
        ready_first,
        ready_ack_tx,
    ));

    tokio::time::timeout(Duration::from_secs(1), ready_ack_rx)
        .await
        .expect("blocked flow must not delay another endpoint driver")
        .unwrap()
        .unwrap();
    assert_eq!(ready_transport.sent_packets(), vec![b"other-flow".to_vec()]);
    blocked_worker.abort();
    ready_worker.abort();
}

#[tokio::test]
async fn udp_endpoint_node_death_stops_after_blocked_first_send() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let (first, queue_rx) =
        reserve_driver_packets(&pool, &stats, client, dst, b"first", &[b"follower"]);
    let release = Arc::new(tokio::sync::Notify::new());
    let transport = Arc::new(ScriptedPacketTransport::new(
        relay,
        [
            DriverSendAction::WaitThenOk(Arc::clone(&release)),
            DriverSendAction::Ok,
        ],
    ));
    let endpoint = driver_test_endpoint(Arc::clone(&transport), relay);
    let (first_ack_tx, first_ack_rx) = oneshot::channel();
    let worker = tokio::spawn(run_endpoint_driver(
        Arc::clone(&endpoint),
        queue_rx,
        test_reply_socket().await,
        client,
        dst,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "test-node".to_owned(),
        first,
        first_ack_tx,
    ));
    transport.wait_for_send_count(1).await;
    endpoint.kill();
    release.notify_waiters();
    first_ack_rx.await.unwrap().unwrap();
    assert_eq!(
        worker.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert_eq!(transport.sent_packets(), vec![b"first".to_vec()]);
}

#[tokio::test]
async fn udp_endpoint_node_death_stops_after_blocked_steady_send() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let (first, queue_rx) = reserve_driver_packets(
        &pool,
        &stats,
        client,
        dst,
        b"first",
        &[b"steady", b"follower"],
    );
    let release = Arc::new(tokio::sync::Notify::new());
    let transport = Arc::new(ScriptedPacketTransport::new(
        relay,
        [
            DriverSendAction::Ok,
            DriverSendAction::WaitThenOk(Arc::clone(&release)),
            DriverSendAction::Ok,
        ],
    ));
    let endpoint = driver_test_endpoint(Arc::clone(&transport), relay);
    let (first_ack_tx, first_ack_rx) = oneshot::channel();
    let worker = tokio::spawn(run_endpoint_driver(
        Arc::clone(&endpoint),
        queue_rx,
        test_reply_socket().await,
        client,
        dst,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "test-node".to_owned(),
        first,
        first_ack_tx,
    ));
    first_ack_rx.await.unwrap().unwrap();
    transport.wait_for_send_count(2).await;
    endpoint.kill();
    release.notify_waiters();
    assert_eq!(
        worker.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert_eq!(
        transport.sent_packets(),
        vec![b"first".to_vec(), b"steady".to_vec()]
    );
}

#[tokio::test(start_paused = true)]
async fn udp_endpoint_driver_reply_idle_timeout_cleans_up_once() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
    pool.set_remove_sink(removed_tx);
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("idle fixture must initialize"),
    };
    let transport = Arc::new(ScriptedPacketTransport::new(relay, [DriverSendAction::Ok]));
    let endpoint = driver_test_endpoint(transport, relay);
    endpoint.set_tracker("idle-tracker".to_owned());
    assert!(lease.set_tracker_id("idle-tracker".to_owned()));
    let queue_rx = lease.take_queue_receiver().unwrap();
    let mut driver = pool.spawn_driver(
        client,
        dst,
        lease.generation(),
        lease.decision_token(),
        Arc::clone(&endpoint),
        queue_rx,
        test_reply_socket().await,
        Arc::clone(&alive),
        Arc::clone(&stats),
        "test-node".to_owned(),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease.commit_ready(endpoint));
    driver.start(lease.take_first().unwrap()).unwrap();
    drop(lease);
    driver.wait_first_ack().await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(REPLY_IDLE_TIMEOUT).await;
    assert_eq!(
        recv_and_ack(&pool, &mut removed_rx).await,
        Some(EndpointRemoval {
            client,
            dst,
            decision_token: 0,
            generation: 1,
            conn_id: Some("idle-tracker".to_owned()),
            reason: RemovalReason::UserspaceEndpointRetired,
        })
    );
    assert!(pool.is_empty());
    let history = alive.get_probe_history(
        TEST_NODE_ID,
        honk_outbound::alive::ProbeDomain::DataUdp,
        honk_outbound::alive::IpVersion::V4,
    );
    assert_eq!(history.len(), 1);
    assert!(!history[0].success);
    assert_eq!(
        pool.global_payload_bytes.available_permits(),
        GLOBAL_PAYLOAD_CAPACITY
    );
    assert!(matches!(
        removed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn udp_endpoint_pool_shutdown_joins_blocked_ready_driver() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let client = make_addr("10.0.0.9", 43000);
    let dst = make_addr("8.8.4.4", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
    pool.set_remove_sink(removed_tx);
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("shutdown fixture must initialize"),
    };
    lease.set_connection_guard(stats.track_connection("shutdown-node"));
    let transport = Arc::new(ScriptedPacketTransport::with_receive_actions(
        relay,
        [DriverSendAction::Ok],
        [DriverReceiveAction::Pending],
    ));
    let endpoint = driver_test_endpoint(transport, relay);
    endpoint.set_tracker("shutdown-tracker".to_owned());
    assert!(lease.set_tracker_id("shutdown-tracker".to_owned()));
    let queue_rx = lease.take_queue_receiver().unwrap();
    let mut driver = pool.spawn_driver(
        client,
        dst,
        lease.generation(),
        lease.decision_token(),
        Arc::clone(&endpoint),
        queue_rx,
        test_reply_socket().await,
        Arc::clone(&alive),
        Arc::clone(&stats),
        "shutdown-node".to_owned(),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease.commit_ready(Arc::clone(&endpoint)));
    driver.start(lease.take_first().unwrap()).unwrap();
    drop(lease);
    driver.wait_first_ack().await.unwrap();
    assert_eq!(pool.driver_count(), 1);
    assert_eq!(stats.snapshot()["shutdown-node"].active_conns, 1);

    let ack_pool = Arc::clone(&pool);
    let removal_ack = tokio::spawn(async move {
        let removal = recv_and_ack(&ack_pool, &mut removed_rx).await;
        let closed = removed_rx.recv().await;
        (removal, closed)
    });
    assert!(pool.shutdown().await);
    let (removal, removal_channel_closed) = removal_ack.await.unwrap();

    assert!(pool.is_terminal());
    assert!(pool.is_empty());
    assert_eq!(pool.driver_count(), 0);
    assert!(endpoint.dead.load(Ordering::Acquire));
    assert_eq!(stats.snapshot()["shutdown-node"].active_conns, 0);
    assert!(
        alive
            .get_probe_history(
                TEST_NODE_ID,
                honk_outbound::alive::ProbeDomain::DataUdp,
                honk_outbound::alive::IpVersion::V4,
            )
            .is_empty()
    );
    assert_eq!(
        removal,
        Some(EndpointRemoval {
            client,
            dst,
            decision_token: 0,
            generation: 1,
            conn_id: Some("shutdown-tracker".to_owned()),
            reason: RemovalReason::UserspaceEndpointRetired,
        })
    );
    assert_eq!(removal_channel_closed, None);
    assert_eq!(
        pool.global_payload_bytes.available_permits(),
        GLOBAL_PAYLOAD_CAPACITY
    );
    assert!(matches!(
        pool.fast_path_enqueue(client, dst, b"late-fast", &stats),
        Some(EndpointReservation::QueueClosed)
    ));
    let rejected = pool.reserve_or_enqueue(
        client,
        dst,
        b"late",
        Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
        &stats,
    );
    assert!(matches!(rejected, EndpointReservation::QueueClosed));
}

#[tokio::test(start_paused = true)]
async fn udp_endpoint_pool_shutdown_aborts_stuck_initializer_task() {
    let pool = Arc::new(UdpEndpointPool::new());
    let endpoint_capacity = pool.endpoint_slots.available_permits();
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.10", 43001);
    let dst = make_addr("1.1.1.1", 53);
    let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
    pool.set_remove_sink(removed_tx);
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"held", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("stuck initializer fixture must initialize"),
    };
    lease.set_connection_guard(stats.track_connection("stuck-initializer"));
    assert!(lease.set_tracker_id("stuck-tracker".to_owned()));
    assert!(pool.spawn_slow_path(async move {
        std::future::pending::<()>().await;
        drop(lease);
    }));
    tokio::task::yield_now().await;
    assert_eq!(pool.slow_task_count(), 1);
    assert_eq!(stats.snapshot()["stuck-initializer"].active_conns, 1);

    let ack_pool = Arc::clone(&pool);
    let removal_ack = tokio::spawn(async move {
        let removal = recv_and_ack(&ack_pool, &mut removed_rx).await;
        let closed = removed_rx.recv().await;
        (removal, closed)
    });
    assert!(pool.shutdown().await);
    let (removal, removal_channel_closed) = removal_ack.await.unwrap();

    assert_eq!(pool.slow_task_count(), 0);
    assert!(!pool.spawn_slow_path(async {}));
    assert!(pool.is_empty());
    assert_eq!(stats.snapshot()["stuck-initializer"].active_conns, 0);
    assert_eq!(
        removal,
        Some(EndpointRemoval {
            client,
            dst,
            decision_token: 0,
            generation: 1,
            conn_id: Some("stuck-tracker".to_owned()),
            reason: RemovalReason::UserspaceEndpointRetired,
        })
    );
    assert_eq!(removal_channel_closed, None);
    assert_eq!(
        pool.global_payload_bytes.available_permits(),
        GLOBAL_PAYLOAD_CAPACITY
    );
    assert_eq!(pool.endpoint_slots.available_permits(), endpoint_capacity);
}

#[tokio::test]
async fn udp_endpoint_driver_receive_and_reply_errors_clean_up() {
    for (client, transport) in [
        (
            make_addr("10.0.0.1", 12345),
            Arc::new(ScriptedPacketTransport::with_receive_actions(
                make_addr("192.168.1.1", 1080),
                [DriverSendAction::Ok],
                [DriverReceiveAction::Error],
            )),
        ),
        (
            make_addr("[::1]", 12345),
            Arc::new(ScriptedPacketTransport::with_receive_actions(
                make_addr("192.168.1.1", 1080),
                [DriverSendAction::Ok],
                [DriverReceiveAction::Packet {
                    data: b"reply".to_vec(),
                    source: make_addr("192.168.1.1", 1080),
                }],
            )),
        ),
    ] {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("receive-error fixture must initialize"),
        };
        let endpoint = driver_test_endpoint(transport, relay);
        endpoint.record_pending_reply_peer(relay);
        endpoint.set_tracker("receive-tracker".to_owned());
        assert!(lease.set_tracker_id("receive-tracker".to_owned()));
        let queue_rx = lease.take_queue_receiver().unwrap();
        let mut driver = pool.spawn_driver(
            client,
            dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue_rx,
            test_reply_socket().await,
            Arc::clone(&alive),
            Arc::clone(&stats),
            "test-node".to_owned(),
        );
        driver.wait_ready().await.unwrap();
        assert!(lease.commit_ready(endpoint));
        driver.start(lease.take_first().unwrap()).unwrap();
        drop(lease);
        driver.wait_first_ack().await.unwrap();
        assert_eq!(
            recv_and_ack(&pool, &mut removed_rx).await,
            Some(EndpointRemoval {
                client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: Some("receive-tracker".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            })
        );
        assert!(pool.is_empty());
        let history = alive.get_probe_history(
            TEST_NODE_ID,
            honk_outbound::alive::ProbeDomain::DataUdp,
            honk_outbound::alive::IpVersion::V4,
        );
        assert_eq!(history.len(), 1);
        assert!(!history[0].success);
        assert!(matches!(
            removed_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }
}

#[tokio::test]
async fn udp_endpoint_receive_failure_cancels_blocked_steady_send_and_releases_permits() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
    pool.set_remove_sink(removed_tx);
    let receive_failure = Arc::new(tokio::sync::Notify::new());
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("blocked-send fixture must initialize"),
    };
    for data in [b"steady".as_slice(), b"queued".as_slice()] {
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        assert!(matches!(
            pool.reserve_or_enqueue(client, dst, data, permit, &stats),
            EndpointReservation::Enqueued
        ));
    }
    let transport = Arc::new(ScriptedPacketTransport::with_receive_actions(
        relay,
        [DriverSendAction::Ok, DriverSendAction::Pending],
        [DriverReceiveAction::WaitThenError(Arc::clone(
            &receive_failure,
        ))],
    ));
    let endpoint = driver_test_endpoint(Arc::clone(&transport), relay);
    endpoint.set_tracker("blocked-receive-tracker".to_owned());
    assert!(lease.set_tracker_id("blocked-receive-tracker".to_owned()));
    let queue_rx = lease.take_queue_receiver().unwrap();
    let mut driver = pool.spawn_driver(
        client,
        dst,
        lease.generation(),
        lease.decision_token(),
        Arc::clone(&endpoint),
        queue_rx,
        test_reply_socket().await,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "test-node".to_owned(),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease.commit_ready(endpoint));
    driver.start(lease.take_first().unwrap()).unwrap();
    drop(lease);
    driver.wait_first_ack().await.unwrap();
    transport.wait_for_send_count(2).await;
    receive_failure.notify_waiters();
    assert_eq!(
        recv_and_ack(&pool, &mut removed_rx).await,
        Some(EndpointRemoval {
            client,
            dst,
            decision_token: 0,
            generation: 1,
            conn_id: Some("blocked-receive-tracker".to_owned()),
            reason: RemovalReason::UserspaceEndpointRetired,
        })
    );
    assert!(pool.is_empty());
    assert_eq!(
        pool.global_payload_bytes.available_permits(),
        GLOBAL_PAYLOAD_CAPACITY
    );
    assert!(matches!(
        removed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn udp_endpoint_worker_failure_removes_tracker_once() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
    pool.set_remove_sink(removed_tx);
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("worker cleanup test must initialize"),
    };
    let transport = Arc::new(ScriptedPacketTransport::new(
        relay,
        [DriverSendAction::Error],
    ));
    let endpoint = driver_test_endpoint(transport, relay);
    endpoint.set_tracker("worker-tracker".to_owned());
    assert!(lease.set_tracker_id("worker-tracker".to_owned()));
    let queue_rx = lease.take_queue_receiver().unwrap();
    let mut driver = pool.spawn_driver(
        client,
        dst,
        lease.generation(),
        lease.decision_token(),
        Arc::clone(&endpoint),
        queue_rx,
        test_reply_socket().await,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "test-node".to_owned(),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease.commit_ready(endpoint));
    driver.start(lease.take_first().unwrap()).unwrap();
    assert!(driver.wait_first_ack().await.is_err());

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), recv_and_ack(&pool, &mut removed_rx))
            .await
            .unwrap(),
        Some(EndpointRemoval {
            client,
            dst,
            decision_token: 0,
            generation: 1,
            conn_id: Some("worker-tracker".to_owned()),
            reason: RemovalReason::UserspaceEndpointRetired,
        })
    );
    tokio::task::yield_now().await;
    assert!(matches!(
        removed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(pool.is_empty());
}

#[tokio::test]
async fn udp_endpoint_driver_panic_releases_all_resources_exactly_once() {
    let pool = Arc::new(UdpEndpointPool::with_capacity_limit(1));
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
    pool.set_remove_sink(removed_tx);
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"panic", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("panic fixture must initialize"),
    };
    lease.set_connection_guard(stats.track_connection("driver-node"));
    assert!(lease.set_tracker_id("panic-tracker".to_owned()));
    let transport = Arc::new(ScriptedPacketTransport::new(
        relay,
        [DriverSendAction::Panic],
    ));
    let endpoint = driver_test_endpoint(transport, relay);
    endpoint.set_tracker("panic-tracker".to_owned());
    let queue_rx = lease.take_queue_receiver().unwrap();
    let mut driver = pool.spawn_driver(
        client,
        dst,
        lease.generation(),
        lease.decision_token(),
        Arc::clone(&endpoint),
        queue_rx,
        test_reply_socket().await,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "driver-node".to_owned(),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease.commit_ready(Arc::clone(&endpoint)));
    driver.start(lease.take_first().unwrap()).unwrap();
    drop(lease);

    assert!(driver.wait_first_ack().await.is_err());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), recv_and_ack(&pool, &mut removed_rx))
            .await
            .expect("panic cleanup must notify the removal sink"),
        Some(EndpointRemoval {
            client,
            dst,
            decision_token: 0,
            generation: 1,
            conn_id: Some("panic-tracker".to_owned()),
            reason: RemovalReason::UserspaceEndpointRetired,
        })
    );
    assert!(pool.is_empty());
    assert_eq!(endpoint.ref_count(), 0, "endpoint.release must run once");
    assert_eq!(pool.endpoint_slots.available_permits(), 1);
    assert_eq!(
        pool.global_payload_bytes.available_permits(),
        GLOBAL_PAYLOAD_CAPACITY
    );
    assert_eq!(
        stats.snapshot().get("driver-node").unwrap().active_conns,
        0,
        "the Ready guard must be dropped by panic cleanup"
    );
    assert!(matches!(
        removed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn udp_endpoint_driver_abort_releases_ready_mapping_and_allows_reuse() {
    let pool = Arc::new(UdpEndpointPool::with_capacity_limit(1));
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
    pool.set_remove_sink(removed_tx);
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"abort", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("abort fixture must initialize"),
    };
    lease.set_connection_guard(stats.track_connection("driver-node"));
    assert!(lease.set_tracker_id("abort-tracker".to_owned()));
    let transport = Arc::new(ScriptedPacketTransport::new(relay, [DriverSendAction::Ok]));
    let endpoint = driver_test_endpoint(transport, relay);
    endpoint.set_tracker("abort-tracker".to_owned());
    let queue_rx = lease.take_queue_receiver().unwrap();
    let mut driver = pool.spawn_driver(
        client,
        dst,
        lease.generation(),
        lease.decision_token(),
        Arc::clone(&endpoint),
        queue_rx,
        test_reply_socket().await,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "driver-node".to_owned(),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease.commit_ready(Arc::clone(&endpoint)));
    driver.start(lease.take_first().unwrap()).unwrap();
    driver.wait_first_ack().await.unwrap();
    drop(lease);

    driver.abort();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), recv_and_ack(&pool, &mut removed_rx))
            .await
            .expect("aborted driver must notify the removal sink"),
        Some(EndpointRemoval {
            client,
            dst,
            decision_token: 0,
            generation: 1,
            conn_id: Some("abort-tracker".to_owned()),
            reason: RemovalReason::UserspaceEndpointRetired,
        })
    );
    assert!(pool.is_empty());
    assert_eq!(endpoint.ref_count(), 0, "endpoint.release must run once");
    assert_eq!(pool.endpoint_slots.available_permits(), 1);
    assert_eq!(
        stats.snapshot().get("driver-node").unwrap().active_conns,
        0,
        "the Ready guard must be dropped by abort cleanup"
    );

    let replacement_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let replacement =
        match pool.reserve_or_enqueue(client, dst, b"replacement", replacement_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("abort cleanup must release capacity for a new generation"),
        };
    assert!(replacement.still_initializing());
    assert_eq!(
        pool.len(),
        1,
        "old abort cleanup must not touch replacement"
    );
    drop(replacement);
}

#[tokio::test]
async fn udp_endpoint_worker_old_generation_cannot_remove_replacement() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
    pool.set_remove_sink(removed_tx);
    let release = Arc::new(tokio::sync::Notify::new());
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut old_lease = match pool.reserve_or_enqueue(client, dst, b"old", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("old worker must initialize"),
    };
    let old_transport = Arc::new(ScriptedPacketTransport::new(
        relay,
        [DriverSendAction::WaitThenError(Arc::clone(&release))],
    ));
    let old_endpoint = driver_test_endpoint(old_transport.clone(), relay);
    old_endpoint.set_tracker("old-tracker".to_owned());
    assert!(old_lease.set_tracker_id("old-tracker".to_owned()));
    let old_queue_rx = old_lease.take_queue_receiver().unwrap();
    let mut old_driver = pool.spawn_driver(
        client,
        dst,
        old_lease.generation(),
        old_lease.decision_token(),
        Arc::clone(&old_endpoint),
        old_queue_rx,
        test_reply_socket().await,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "test-node".to_owned(),
    );
    old_driver.wait_ready().await.unwrap();
    assert!(old_lease.commit_ready(old_endpoint));
    old_driver.start(old_lease.take_first().unwrap()).unwrap();
    old_transport.wait_for_send_count(1).await;

    pool.remove(client, dst);
    assert_eq!(
        try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
        EndpointRemoval {
            client,
            dst,
            decision_token: 0,
            generation: 1,
            conn_id: Some("old-tracker".to_owned()),
            reason: RemovalReason::UserspaceEndpointRetired,
        }
    );
    let replacement_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let replacement =
        pool.reserve_or_enqueue(client, dst, b"replacement", replacement_permit, &stats);
    assert!(matches!(replacement, EndpointReservation::Initializing(_)));

    release.notify_waiters();
    assert!(old_driver.wait_first_ack().await.is_err());
    tokio::task::yield_now().await;
    assert_eq!(
        pool.len(),
        1,
        "old worker cleanup must not remove replacement"
    );
    assert!(matches!(
        removed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    drop(replacement);
}

#[tokio::test]
async fn udp_endpoint_node_death_before_dial_sends_nothing() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
    pool.set_remove_sink(removed_tx);
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("death-before-dial fixture must initialize"),
    };
    let generation = lease.generation();
    assert!(lease.bind_selected_node(DEAD_NODE_ID));
    // Simulate death winning immediately after bind, before dial await.
    pool.remove_by_node(DEAD_NODE_ID);
    assert!(
        !lease.still_initializing(),
        "bound Initializing entry must be generation-safely removed"
    );
    // No tracker was attached yet, so sink sees None conn_id.
    assert_eq!(
        try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
        EndpointRemoval {
            client,
            dst,
            decision_token: 0,
            generation: 1,
            conn_id: None,
            reason: RemovalReason::UserspaceEndpointRetired,
        }
    );
    assert!(pool.is_empty());

    let relay = make_addr("192.168.1.1", 1080);
    let transport = Arc::new(ScriptedPacketTransport::new(relay, [DriverSendAction::Ok]));
    let endpoint = Arc::new(UdpEndpoint::new(
        transport.clone() as Arc<dyn honk_outbound::proxy::PacketTransport>,
        relay,
        DEAD_NODE_ID,
    ));
    assert!(
        !lease.commit_ready(endpoint),
        "commit after death-before-dial must fail"
    );
    drop(lease);
    assert!(transport.sent_packets().is_empty());

    // A newer generation must not be deleted by the old lease Drop.
    let replacement_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let replacement =
        match pool.reserve_or_enqueue(client, dst, b"next", replacement_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("replacement must initialize"),
        };
    assert_ne!(replacement.generation(), generation);
    assert!(replacement.still_initializing());
    drop(replacement);
}

#[tokio::test]
async fn udp_endpoint_node_death_during_dial_sends_nothing() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
    pool.set_remove_sink(removed_tx);
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("death-during-dial fixture must initialize"),
    };
    assert!(lease.bind_selected_node(DEAD_NODE_ID));
    assert!(lease.set_tracker_id("during-dial".to_owned()));
    // Death arrives while dial would be in flight.
    pool.remove_by_node(DEAD_NODE_ID);
    assert!(!lease.still_initializing());
    assert_eq!(
        try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
        EndpointRemoval {
            client,
            dst,
            decision_token: 0,
            generation: 1,
            conn_id: Some("during-dial".to_owned()),
            reason: RemovalReason::UserspaceEndpointRetired,
        }
    );

    let relay = make_addr("192.168.1.1", 1080);
    let transport = Arc::new(ScriptedPacketTransport::new(relay, [DriverSendAction::Ok]));
    let endpoint = Arc::new(UdpEndpoint::new(
        transport.clone() as Arc<dyn honk_outbound::proxy::PacketTransport>,
        relay,
        DEAD_NODE_ID,
    ));
    // Even if dial "succeeded", commit and start must not send.
    assert!(lease.take_queue_receiver().is_none());
    assert!(!lease.commit_ready(endpoint));
    assert!(lease.take_first().is_some());
    drop(lease);
    assert!(transport.sent_packets().is_empty());
    assert!(matches!(
        removed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn udp_endpoint_node_death_before_commit_sends_nothing() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
    pool.set_remove_sink(removed_tx);
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("death-before-commit fixture must initialize"),
    };
    assert!(lease.bind_selected_node(DEAD_NODE_ID));
    let transport = Arc::new(ScriptedPacketTransport::new(relay, [DriverSendAction::Ok]));
    let endpoint = Arc::new(UdpEndpoint::new(
        transport.clone() as Arc<dyn honk_outbound::proxy::PacketTransport>,
        relay,
        DEAD_NODE_ID,
    ));
    endpoint.set_tracker("before-commit".to_owned());
    assert!(lease.set_tracker_id("before-commit".to_owned()));
    let queue_rx = lease.take_queue_receiver().unwrap();
    let mut driver = pool.spawn_driver(
        client,
        dst,
        lease.generation(),
        lease.decision_token(),
        Arc::clone(&endpoint),
        queue_rx,
        test_reply_socket().await,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "dead-node".to_owned(),
    );
    driver.wait_ready().await.unwrap();

    // Death wins after driver-ready, before commit_ready.
    pool.remove_by_node(DEAD_NODE_ID);
    assert!(!lease.still_initializing());
    assert_eq!(
        try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
        EndpointRemoval {
            client,
            dst,
            decision_token: 0,
            generation: 1,
            conn_id: Some("before-commit".to_owned()),
            reason: RemovalReason::UserspaceEndpointRetired,
        }
    );
    assert!(pool.is_empty());
    assert!(
        !lease.commit_ready(endpoint),
        "commit after death-before-commit must fail"
    );
    // Dropping the driver handle closes `start` without delivering the
    // first packet; the task exits with send_count=0.
    drop(driver);
    drop(lease);
    assert!(transport.sent_packets().is_empty());
    tokio::task::yield_now().await;
    assert!(matches!(
        removed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn udp_endpoint_node_death_before_driver_start_sends_nothing() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = make_addr("10.0.0.1", 12345);
    let dst = make_addr("8.8.8.8", 53);
    let relay = make_addr("192.168.1.1", 1080);
    let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
    pool.set_remove_sink(removed_tx);
    let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("node-death fixture must initialize"),
    };
    let transport = Arc::new(ScriptedPacketTransport::new(relay, [DriverSendAction::Ok]));
    let proxy_socket: Arc<dyn honk_outbound::proxy::PacketTransport> = transport.clone();
    let endpoint = Arc::new(UdpEndpoint::new(proxy_socket, relay, DEAD_NODE_ID));
    endpoint.set_tracker("dead-before-start".to_owned());
    assert!(lease.set_tracker_id("dead-before-start".to_owned()));
    let queue_rx = lease.take_queue_receiver().unwrap();
    let mut driver = pool.spawn_driver(
        client,
        dst,
        lease.generation(),
        lease.decision_token(),
        Arc::clone(&endpoint),
        queue_rx,
        test_reply_socket().await,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "dead-node".to_owned(),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease.commit_ready(endpoint));

    pool.remove_by_node(DEAD_NODE_ID);
    assert_eq!(
        try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
        EndpointRemoval {
            client,
            dst,
            decision_token: 0,
            generation: 1,
            conn_id: Some("dead-before-start".to_owned()),
            reason: RemovalReason::UserspaceEndpointRetired,
        }
    );
    assert!(pool.is_empty(), "acknowledged node death must remove Ready");
    let replacement_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let replacement =
        pool.reserve_or_enqueue(client, dst, b"replacement", replacement_permit, &stats);
    assert!(matches!(replacement, EndpointReservation::Initializing(_)));

    driver.start(lease.take_first().unwrap()).unwrap();
    drop(lease);
    assert!(
        driver.wait_first_ack().await.is_err(),
        "a start after node death must not reach PacketTransport"
    );
    assert!(transport.sent_packets().is_empty());
    tokio::task::yield_now().await;
    assert_eq!(
        pool.len(),
        1,
        "old driver cleanup must preserve replacement"
    );
    assert!(matches!(
        removed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    drop(replacement);
}

#[test]
fn test_remove_by_node() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = StatsManager::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let proxy = Arc::new(
        rt.block_on(tokio::net::UdpSocket::bind("127.0.0.1:0"))
            .unwrap(),
    );
    let relay = make_addr("192.168.1.1", 1080);
    let dst = make_addr("8.8.8.8", 53);
    commit_ready(
        &pool,
        make_addr("10.0.0.1", 12345),
        dst,
        transport(proxy.clone(), relay),
        relay,
        DEAD_NODE_ID,
    );
    commit_ready(
        &pool,
        make_addr("10.0.0.2", 12345),
        dst,
        transport(proxy.clone(), relay),
        relay,
        OTHER_NODE_ID,
    );
    let init_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let initializing = match pool.reserve_or_enqueue(
        make_addr("10.0.0.3", 12345),
        dst,
        b"init",
        init_permit,
        &stats,
    ) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("unbound initializing fixture"),
    };
    // Unbound Initializing must not be attributed to the dead node yet.
    assert_eq!(pool.len(), 3);
    pool.remove_by_node(DEAD_NODE_ID);
    assert_eq!(pool.len(), 2);
    assert!(pool.get(make_addr("10.0.0.1", 12345), dst).is_none());
    assert!(pool.get(make_addr("10.0.0.2", 12345), dst).is_some());
    assert!(initializing.still_initializing());

    assert!(initializing.bind_selected_node(DEAD_NODE_ID));
    pool.remove_by_node(DEAD_NODE_ID);
    assert!(
        !initializing.still_initializing(),
        "bound Initializing must be removed generation-safely"
    );
    assert_eq!(pool.len(), 1);
    drop(initializing);
}

#[tokio::test]
async fn udp_endpoint_node_and_janitor_cleanup_notify_tracker_once() {
    let pool = Arc::new(UdpEndpointPool::new());
    let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
    pool.set_remove_sink(removed_tx);
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay = make_addr("192.168.1.1", 1080);
    let dst = make_addr("8.8.8.8", 53);
    let node_client = make_addr("10.0.0.1", 12345);
    let node_endpoint = commit_ready(
        &pool,
        node_client,
        dst,
        transport(proxy.clone(), relay),
        relay,
        DEAD_NODE_ID,
    );
    node_endpoint.set_tracker("node-tracker".to_owned());

    pool.remove_by_node(DEAD_NODE_ID);
    assert_eq!(
        try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
        EndpointRemoval {
            client: node_client,
            dst,
            decision_token: 0,
            generation: 1,
            conn_id: Some("node-tracker".to_owned()),
            reason: RemovalReason::UserspaceEndpointRetired,
        }
    );

    let janitor_client = make_addr("10.0.0.2", 12345);
    let janitor_endpoint = commit_ready(
        &pool,
        janitor_client,
        dst,
        transport(proxy, relay),
        relay,
        JANITOR_NODE_ID,
    );
    janitor_endpoint.set_tracker("janitor-tracker".to_owned());
    janitor_endpoint.release();
    janitor_endpoint
        .expires_at
        .store(monotonic_nanos() - 1, Ordering::Relaxed);

    assert_eq!(pool.janitor_cycle(), 1);
    assert_eq!(
        try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
        EndpointRemoval {
            client: janitor_client,
            dst,
            decision_token: 0,
            generation: 2,
            conn_id: Some("janitor-tracker".to_owned()),
            reason: RemovalReason::UserspaceEndpointRetired,
        }
    );
    assert!(matches!(
        removed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}
