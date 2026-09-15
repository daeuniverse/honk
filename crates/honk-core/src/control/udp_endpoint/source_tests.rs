use super::*;
use crate::control::udp_endpoint::source::{SourceReplyTarget, SourceScope};
use honk_config::node::{Node, OutboundConfig, VlessConfig, VlessUdpEncoding, VlessUdpPath};
use honk_outbound::runtime::OutboundRuntimeRegistry;
use std::collections::{HashMap, VecDeque};
use std::future::{Future, poll_fn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
mod cross_source;
mod regressions;

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const OPTION_DATA: u8 = 1;
const NETWORK_UDP: u8 = 2;
const ATYP_IPV4: u8 = 1;

#[derive(Debug)]
struct SourceReplySocketFactory {
    sockets: Mutex<HashMap<SocketAddr, VecDeque<std::net::UdpSocket>>>,
}

impl SourceReplySocketFactory {
    fn new(sockets: impl IntoIterator<Item = std::net::UdpSocket>) -> Self {
        let mut by_addr: HashMap<_, VecDeque<_>> = HashMap::new();
        for socket in sockets {
            by_addr
                .entry(socket.local_addr().unwrap())
                .or_default()
                .push_back(socket);
        }
        Self {
            sockets: Mutex::new(by_addr),
        }
    }
}

impl UdpReplySocketFactory for SourceReplySocketFactory {
    fn create(&self, source: SocketAddr) -> io::Result<UdpSocket> {
        let socket = self
            .sockets
            .lock()
            .get_mut(&source)
            .and_then(VecDeque::pop_front);
        let socket = match socket {
            Some(socket) => socket,
            None => std::net::UdpSocket::bind(source)?,
        };
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    }
}

#[derive(Debug)]
struct WireFrame {
    connection: u64,
    session_id: u16,
    status: u8,
    target: Option<SocketAddr>,
    global_id: Option<[u8; 8]>,
    payload: Option<Vec<u8>>,
}

#[derive(Debug)]
enum WireEvent {
    Connected {
        connection: u64,
        replies: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    },
    Frame(WireFrame),
    Closed(io::ErrorKind),
}

async fn read_wire_frame(
    connection: u64,
    reader: &mut tokio::net::tcp::OwnedReadHalf,
) -> io::Result<WireFrame> {
    let metadata_len = reader.read_u16().await? as usize;
    let mut metadata = vec![0; metadata_len];
    reader.read_exact(&mut metadata).await?;
    if metadata.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short Cool metadata",
        ));
    }
    let status = metadata[2];
    let payload = if metadata[3] & OPTION_DATA != 0 {
        let len = reader.read_u16().await? as usize;
        let mut payload = vec![0; len];
        reader.read_exact(&mut payload).await?;
        Some(payload)
    } else {
        None
    };
    let target = (metadata.len() >= 12 && metadata[4] == NETWORK_UDP && metadata[7] == ATYP_IPV4)
        .then(|| {
            SocketAddr::from((
                [metadata[8], metadata[9], metadata[10], metadata[11]],
                u16::from_be_bytes([metadata[5], metadata[6]]),
            ))
        });
    let global_id = (metadata.len() == 20).then(|| {
        let mut id = [0; 8];
        id.copy_from_slice(&metadata[12..20]);
        id
    });
    Ok(WireFrame {
        connection,
        session_id: u16::from_be_bytes([metadata[0], metadata[1]]),
        status,
        target,
        global_id,
        payload,
    })
}

fn reply_frame(peer: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let SocketAddr::V4(peer) = peer else {
        panic!("source test peer must be IPv4");
    };
    let mut metadata = vec![0, 0, STATUS_KEEP, OPTION_DATA, NETWORK_UDP];
    metadata.extend_from_slice(&peer.port().to_be_bytes());
    metadata.push(ATYP_IPV4);
    metadata.extend_from_slice(&peer.ip().octets());
    let mut frame = Vec::with_capacity(2 + metadata.len() + 2 + payload.len());
    frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    frame.extend_from_slice(&metadata);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

async fn run_wire_connection(
    connection: u64,
    mut socket: tokio::net::TcpStream,
    events: mpsc::UnboundedSender<WireEvent>,
) -> io::Result<()> {
    let mut request = [0; 18];
    socket.read_exact(&mut request).await?;
    let mut addon_and_command = vec![0; usize::from(request[17]) + 1];
    socket.read_exact(&mut addon_and_command).await?;
    if addon_and_command.last() != Some(&3) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a VLESS Mux carrier",
        ));
    }
    socket.write_all(&[0, 0]).await?;
    let (mut reader, mut writer) = socket.into_split();
    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel();
    events
        .send(WireEvent::Connected {
            connection,
            replies: reply_tx,
        })
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "source test ended"))?;
    loop {
        tokio::select! {
            frame = read_wire_frame(connection, &mut reader) => {
                events
                    .send(WireEvent::Frame(frame?))
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "source test ended"))?;
            }
            reply = reply_rx.recv() => {
                let Some((peer, payload)) = reply else { return Ok(()); };
                writer.write_all(&reply_frame(peer, &payload)).await?;
            }
        }
    }
}

async fn start_wire_peer() -> (
    SocketAddr,
    mpsc::UnboundedReceiver<WireEvent>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let mut connection = 0;
        let mut handlers = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (socket, _) = accepted.unwrap();
                    connection += 1;
                    handlers.spawn(run_wire_connection(connection, socket, events_tx.clone()));
                }
                result = handlers.join_next(), if !handlers.is_empty() => {
                    match result {
                        Some(Ok(Err(error)))
                            if matches!(
                                error.kind(),
                                io::ErrorKind::UnexpectedEof
                                    | io::ErrorKind::ConnectionReset
                                    | io::ErrorKind::BrokenPipe
                            ) => {}
                        Some(Ok(Err(error))) => {
                            let _ = events_tx.send(WireEvent::Closed(error.kind()));
                        }
                        Some(Err(error)) => panic!("wire handler panicked: {error}"),
                        Some(Ok(Ok(()))) | None => {}
                    }
                }
            }
        }
    });
    (address, events_rx, task)
}

fn vless_node(server: SocketAddr) -> Node {
    let mut node = Node {
        name: "core-source-vless".into(),
        address: server.to_string(),
        host: server.ip().to_string(),
        port: server.port(),
        outbound: OutboundConfig::Vless(VlessConfig {
            uuid: Some("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3".into()),
            udp_encoding: VlessUdpEncoding::Xudp,
            ..Default::default()
        }),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

fn reserve_source(
    pool: &Arc<UdpEndpointPool>,
    stats: &StatsManager,
    client: SocketAddr,
    target: SocketAddr,
    node_id: uuid::Uuid,
) -> UdpInitLease {
    let slow = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let lease = match pool.reserve_or_enqueue(client, target, b"held", slow, stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("source test expected a fresh endpoint"),
    };
    assert!(lease.bind_selected_node(node_id));
    lease
}

fn install_source(
    pool: &Arc<UdpEndpointPool>,
    mut lease: UdpInitLease,
    attachment: SourceAttachment,
    target: SocketAddr,
    stats: &StatsManager,
    node_id: uuid::Uuid,
) -> Arc<UdpEndpoint> {
    let reply_socket = Arc::new(pool.create_reply_socket(target).unwrap());
    let endpoint = Arc::new(UdpEndpoint::new_source_scored(
        attachment,
        target,
        None,
        reply_socket,
        stats.outbound_tracker("core-source-vless"),
        node_id,
        honk_outbound::alive::IpVersion::V4,
        None,
    ));
    assert!(lease.commit_ready(Arc::clone(&endpoint)));
    endpoint
}

async fn next_wire_frame(
    events: &mut mpsc::UnboundedReceiver<WireEvent>,
    replies: &mut HashMap<u64, mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>>,
) -> WireFrame {
    loop {
        match events.recv().await.unwrap() {
            WireEvent::Connected {
                connection,
                replies: sender,
            } => {
                replies.insert(connection, sender);
            }
            WireEvent::Frame(frame) => return frame,
            WireEvent::Closed(kind) => panic!("source wire connection failed: {kind:?}"),
        }
    }
}

async fn next_data_frame(
    events: &mut mpsc::UnboundedReceiver<WireEvent>,
    replies: &mut HashMap<u64, mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>>,
) -> WireFrame {
    loop {
        let frame = next_wire_frame(events, replies).await;
        if frame.payload.is_some() {
            return frame;
        }
    }
}

async fn receive_reply(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut data = [0; 64];
    let (len, peer) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut data))
        .await
        .expect("source reply timed out")
        .unwrap();
    (data[..len].to_vec(), peer)
}

async fn assert_no_reply(socket: &UdpSocket) {
    let mut data = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), socket.recv_from(&mut data))
            .await
            .is_err(),
        "dropped source reply reached the client"
    );
}

async fn wait_source_removed(pool: &UdpEndpointPool, scope: &SourceScope) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let changed = pool.source_changed.notified();
            if pool.sources.get(scope).is_none() {
                break;
            }
            changed.await;
        }
    })
    .await
    .expect("source owner did not retire");
}

#[test]
fn scope_normalizes_client_and_partitions_owners() {
    let node = honk_config::Config::builtin_direct_node();
    let first_guard = honk_outbound::runtime::NodeRuntime::try_ephemeral_guarded(&node).unwrap();
    let second_guard = honk_outbound::runtime::NodeRuntime::try_ephemeral_guarded(&node).unwrap();
    let first_runtime = first_guard.runtime();
    let second_runtime = second_guard.runtime();
    let client: SocketAddr = "192.0.2.1:1234".parse().unwrap();
    let mapped_client: SocketAddr = "[::ffff:192.0.2.1]:1234".parse().unwrap();
    let rewritten: SocketAddr = "198.51.100.8:53".parse().unwrap();
    let mapped_rewritten: SocketAddr = "[::ffff:198.51.100.8]:53".parse().unwrap();

    let scope = SourceScope::new(&first_runtime, client, VlessUdpPath::Xudp, None);
    assert_eq!(
        scope,
        SourceScope::new(&first_runtime, mapped_client, VlessUdpPath::Xudp, None)
    );
    assert_ne!(
        scope,
        SourceScope::new(&second_runtime, client, VlessUdpPath::Xudp, None)
    );
    assert_ne!(
        scope,
        SourceScope::new(&first_runtime, client, VlessUdpPath::CoolShared, None)
    );
    assert_ne!(
        scope,
        SourceScope::new(&first_runtime, client, VlessUdpPath::Xudp, Some(rewritten))
    );
    assert_eq!(
        SourceScope::new(&first_runtime, client, VlessUdpPath::Xudp, Some(rewritten)),
        SourceScope::new(
            &first_runtime,
            client,
            VlessUdpPath::Xudp,
            Some(mapped_rewritten),
        )
    );
}

#[tokio::test]
async fn source_scope_shares_wire_demuxes_and_replaces_exact_owner() {
    let (server, mut events, wire_task) = start_wire_peer().await;
    let node = vless_node(server);
    let generation = Arc::new(
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
            std::slice::from_ref(&node),
            8,
            8,
            8,
            None,
        )
        .unwrap()
        .0,
    );
    let runtime = generation.get(&node.id).unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let client_two = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_two_addr = client_two.local_addr().unwrap();
    let raw_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let raw_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let raw_c = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let raw_d = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target_a = raw_a.local_addr().unwrap();
    let target_b = raw_b.local_addr().unwrap();
    let target_c = raw_c.local_addr().unwrap();
    let target_d = raw_d.local_addr().unwrap();
    let pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        8,
        Arc::new(SourceReplySocketFactory::new([raw_a, raw_b, raw_c, raw_d])),
    ));
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let (removed_tx, mut removed_rx) = mpsc::channel(8);
    pool.set_remove_sink(removed_tx);

    let lease_a = reserve_source(&pool, &stats, client_addr, target_a, node.id);
    let lease_b = reserve_source(&pool, &stats, client_addr, target_b, node.id);
    let prepare_a = pool.prepare_vless_source(
        Arc::clone(&generation),
        Arc::clone(&runtime),
        client_addr,
        VlessUdpPath::Xudp,
        None,
        target_a,
        None,
        Duration::from_secs(2),
        Arc::clone(&alive),
        Arc::clone(&stats),
        honk_outbound::alive::IpVersion::V4,
    );
    let prepare_b = pool.prepare_vless_source(
        Arc::clone(&generation),
        Arc::clone(&runtime),
        client_addr,
        VlessUdpPath::Xudp,
        None,
        target_b,
        None,
        Duration::from_secs(2),
        Arc::clone(&alive),
        Arc::clone(&stats),
        honk_outbound::alive::IpVersion::V4,
    );
    let (prepared_a, prepared_b) = tokio::join!(prepare_a, prepare_b);
    let (attachment_a, attachment_b) = tokio::join!(
        prepared_a.unwrap().commit(&pool),
        prepared_b.unwrap().commit(&pool),
    );
    let attachment_a = attachment_a.unwrap();
    let attachment_b = attachment_b.unwrap();
    let owner = attachment_a.owner();
    assert!(Arc::ptr_eq(&owner, &attachment_b.owner()));
    let scope = SourceScope::new(&runtime, client_addr, VlessUdpPath::Xudp, None);
    let endpoint_a = install_source(&pool, lease_a, attachment_a, target_a, &stats, node.id);
    let endpoint_b = install_source(&pool, lease_b, attachment_b, target_b, &stats, node.id);
    let mut replies = HashMap::new();
    let empty = endpoint_b.send_packet(b"", true).await.unwrap_err();
    assert_eq!(
        honk_outbound::proxy::packet_error_class(&empty),
        honk_outbound::proxy::PacketErrorClass::Rejected,
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            next_wire_frame(&mut events, &mut replies),
        )
        .await
        .is_err(),
        "empty source NEW must not reach the wire"
    );

    endpoint_a.send_packet(b"to-a", true).await.unwrap();
    endpoint_a.tracker_upload(4);
    endpoint_b.send_packet(b"to-b", true).await.unwrap();
    endpoint_b.tracker_upload(4);
    let first = next_wire_frame(&mut events, &mut replies).await;
    let second = next_wire_frame(&mut events, &mut replies).await;
    assert_eq!(
        (first.status, first.target, first.payload.as_deref()),
        (STATUS_NEW, Some(target_a), Some(&b"to-a"[..]))
    );
    assert_eq!(
        (second.status, second.target, second.payload.as_deref()),
        (STATUS_KEEP, Some(target_b), Some(&b"to-b"[..]))
    );
    assert_eq!(first.connection, second.connection);
    let global_id = first.global_id.expect("source NEW must carry GlobalID");
    assert_eq!(second.global_id, None);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            next_wire_frame(&mut events, &mut replies),
        )
        .await
        .is_err(),
        "only one source child may publish NEW"
    );

    replies[&first.connection]
        .send((target_a, b"reply-a".to_vec()))
        .unwrap();
    assert_eq!(
        receive_reply(&client).await,
        (b"reply-a".to_vec(), target_a)
    );
    endpoint_b.source_flow_idle_expired();
    assert!(pool.sources.get(&scope).is_some());
    assert!(!endpoint_b.dead.load(Ordering::Acquire));
    assert_eq!(endpoint_a.byte_counters().1.load(Ordering::Relaxed), 7);
    assert_eq!(endpoint_b.byte_counters().1.load(Ordering::Relaxed), 0);
    replies[&first.connection]
        .send((target_b, b"reply-b".to_vec()))
        .unwrap();
    assert_eq!(
        receive_reply(&client).await,
        (b"reply-b".to_vec(), target_b)
    );
    assert_eq!(endpoint_a.byte_counters().1.load(Ordering::Relaxed), 7);
    assert_eq!(endpoint_b.byte_counters().1.load(Ordering::Relaxed), 7);
    let lease_two = reserve_source(&pool, &stats, client_two_addr, target_c, node.id);
    let prepared_two = pool
        .prepare_vless_source(
            Arc::clone(&generation),
            Arc::clone(&runtime),
            client_two_addr,
            VlessUdpPath::Xudp,
            None,
            target_c,
            None,
            Duration::from_secs(2),
            Arc::clone(&alive),
            Arc::clone(&stats),
            honk_outbound::alive::IpVersion::V4,
        )
        .await
        .unwrap();
    let attachment_two = prepared_two.commit(&pool).await.unwrap();
    let owner_two = attachment_two.owner();
    assert!(!Arc::ptr_eq(&owner, &owner_two));
    let scope_two = SourceScope::new(&runtime, client_two_addr, VlessUdpPath::Xudp, None);
    let endpoint_two = install_source(&pool, lease_two, attachment_two, target_c, &stats, node.id);
    endpoint_two.send_packet(b"scope-two", true).await.unwrap();
    let second_scope = next_data_frame(&mut events, &mut replies).await;
    assert_eq!(
        (second_scope.status, second_scope.target),
        (STATUS_NEW, Some(target_c))
    );
    assert_ne!(second_scope.connection, first.connection);
    assert_ne!(second_scope.global_id, Some(global_id));
    replies[&second_scope.connection]
        .send((target_c, b"scope-two-reply".to_vec()))
        .unwrap();
    assert_eq!(
        receive_reply(&client_two).await,
        (b"scope-two-reply".to_vec(), target_c),
    );
    let stale_two = pool
        .prepare_vless_source(
            Arc::clone(&generation),
            Arc::clone(&runtime),
            client_two_addr,
            VlessUdpPath::Xudp,
            None,
            target_b,
            None,
            Duration::from_secs(2),
            Arc::clone(&alive),
            Arc::clone(&stats),
            honk_outbound::alive::IpVersion::V4,
        )
        .await
        .unwrap();
    assert!(Arc::ptr_eq(
        &owner_two,
        &stale_two.attached_owner().unwrap(),
    ));
    let identity_two = endpoint_identity(&pool, client_two_addr, target_c).unwrap();
    assert!(pool.retire_if_same(
        EndpointKey::new(client_two_addr, target_c),
        identity_two.0,
        identity_two.1,
    ));
    let removed_two = removed_rx.recv().await.unwrap();
    assert!(pool.complete_removal(
        client_two_addr,
        target_c,
        removed_two.decision_token,
        removed_two.generation,
    ));
    drop(endpoint_two);
    wait_source_removed(&pool, &scope_two).await;
    let Err(stale_error) = stale_two.commit(&pool).await else {
        panic!("retired source attachment must reject commit");
    };
    assert_eq!(
        honk_outbound::proxy::packet_rejection(&stale_error),
        Some(honk_outbound::proxy::PacketRejection::Cancelled),
    );
    drop(owner_two);
    let retired = tokio::time::timeout(
        Duration::from_secs(1),
        next_wire_frame(&mut events, &mut replies),
    )
    .await
    .expect("retired sent source must emit its END");
    assert_eq!(
        (
            retired.connection,
            retired.session_id,
            retired.status,
            retired.payload
        ),
        (second_scope.connection, second_scope.session_id, 3, None),
    );

    let cancelled = pool
        .prepare_vless_source(
            Arc::clone(&generation),
            Arc::clone(&runtime),
            client_addr,
            VlessUdpPath::Xudp,
            None,
            target_c,
            None,
            Duration::from_secs(2),
            Arc::clone(&alive),
            Arc::clone(&stats),
            honk_outbound::alive::IpVersion::V4,
        )
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&owner, &cancelled.attached_owner().unwrap()));
    drop(cancelled);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            next_wire_frame(&mut events, &mut replies),
        )
        .await
        .is_err(),
        "cancelled attachment must not emit NEW"
    );

    pool.remove(client_addr, target_a);
    assert!(matches!(
        pool.classify_source_reply(&owner, target_a),
        SourceReplyTarget::Drop
    ));
    replies[&first.connection]
        .send((target_a, b"retiring-a".to_vec()))
        .unwrap();
    assert_no_reply(&client).await;
    let removed_a = removed_rx.recv().await.unwrap();
    assert!(pool.complete_removal(
        client_addr,
        target_a,
        removed_a.decision_token,
        removed_a.generation
    ));
    drop(endpoint_a);
    assert!(
        matches!(pool.classify_source_reply(&owner, target_a), SourceReplyTarget::Foreign(peer) if peer == target_a)
    );
    replies[&first.connection]
        .send((target_a, b"foreign-a".to_vec()))
        .unwrap();
    assert_eq!(
        receive_reply(&client).await,
        (b"foreign-a".to_vec(), target_a)
    );

    endpoint_b.send_packet(b"b-alive", false).await.unwrap();
    let b_alive = next_data_frame(&mut events, &mut replies).await;
    assert_eq!(
        (b_alive.connection, b_alive.status, b_alive.target),
        (first.connection, STATUS_KEEP, Some(target_b))
    );
    replies[&first.connection]
        .send((target_b, b"still-b".to_vec()))
        .unwrap();
    assert_eq!(
        receive_reply(&client).await,
        (b"still-b".to_vec(), target_b)
    );

    let flow_lease = reserve_source(&pool, &stats, client_addr, target_a, node.id);
    let flow_identity = (flow_lease.decision_token(), flow_lease.generation());
    assert!(matches!(
        pool.classify_source_reply(&owner, target_a),
        SourceReplyTarget::Drop,
    ));
    replies[&first.connection]
        .send((target_a, b"initializing".to_vec()))
        .unwrap();
    assert_no_reply(&client).await;
    let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let flow_transport: Arc<dyn honk_outbound::proxy::PacketTransport> =
        Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
            Arc::clone(&relay),
            relay.local_addr().unwrap(),
        ));
    let flow_endpoint = Arc::new(UdpEndpoint::new(
        flow_transport,
        relay.local_addr().unwrap(),
        node.id,
    ));
    let mut flow_lease = flow_lease;
    assert!(flow_lease.commit_ready(Arc::clone(&flow_endpoint)));
    drop(flow_lease);
    assert!(matches!(
        pool.classify_source_reply(&owner, target_a),
        SourceReplyTarget::Drop
    ));
    assert!(pool.retire_if_same(
        EndpointKey::new(client_addr, target_a),
        flow_identity.0,
        flow_identity.1
    ));
    replies[&first.connection]
        .send((target_a, b"wrong-owner".to_vec()))
        .unwrap();
    assert_no_reply(&client).await;
    let removed_flow = removed_rx.recv().await.unwrap();
    assert!(pool.complete_removal(
        client_addr,
        target_a,
        removed_flow.decision_token,
        removed_flow.generation
    ));

    let lease_d = reserve_source(&pool, &stats, client_addr, target_d, node.id);
    let prepared_d = pool
        .prepare_vless_source(
            Arc::clone(&generation),
            Arc::clone(&runtime),
            client_addr,
            VlessUdpPath::Xudp,
            None,
            target_d,
            None,
            Duration::from_secs(2),
            Arc::clone(&alive),
            Arc::clone(&stats),
            honk_outbound::alive::IpVersion::V4,
        )
        .await
        .unwrap();
    let attachment_d = prepared_d.commit(&pool).await.unwrap();
    assert!(Arc::ptr_eq(&owner, &attachment_d.owner()));
    let endpoint_d = install_source(&pool, lease_d, attachment_d, target_d, &stats, node.id);
    // Model B being retired while its send is pending before backend queue
    // admission: backend rolls the SID back and emits no terminal, leaving only
    // Core's per-view retirement intent until another event arrives.
    endpoint_b.mark_source_send_active_for_test();
    let identity_b = endpoint_identity(&pool, client_addr, target_b).unwrap();
    assert!(pool.retire_if_same(
        EndpointKey::new(client_addr, target_b),
        identity_b.0,
        identity_b.1,
    ));
    for _ in 0..49 {
        alive.report_unavailable_traffic(
            node.id,
            honk_outbound::alive::ProbeDomain::DataUdp,
            honk_outbound::alive::IpVersion::V4,
        );
    }
    assert!(alive.is_alive_for(
        node.id,
        honk_outbound::alive::ProbeDomain::DataUdp,
        honk_outbound::alive::IpVersion::V4,
    ));
    let remote_end = io::Error::new(io::ErrorKind::ConnectionAborted, "remote source END");
    assert!(!owner.handle_transport_error(&remote_end));
    owner.fail(ScoreOutcome::Io(remote_end.kind()));
    assert!(!alive.is_alive_for(
        node.id,
        honk_outbound::alive::ProbeDomain::DataUdp,
        honk_outbound::alive::IpVersion::V4,
    ));
    assert!(endpoint_d.dead.load(Ordering::Acquire));
    for _ in 0..2 {
        let removed = removed_rx.recv().await.unwrap();
        assert!(pool.complete_removal(
            removed.client,
            removed.dst,
            removed.decision_token,
            removed.generation,
        ));
    }
    drop(endpoint_b);
    drop(endpoint_d);
    wait_source_removed(&pool, &scope).await;

    let lease_c = reserve_source(&pool, &stats, client_addr, target_c, node.id);
    let prepared_c = pool
        .prepare_vless_source(
            Arc::clone(&generation),
            Arc::clone(&runtime),
            client_addr,
            VlessUdpPath::Xudp,
            None,
            target_c,
            None,
            Duration::from_secs(2),
            Arc::clone(&alive),
            Arc::clone(&stats),
            honk_outbound::alive::IpVersion::V4,
        )
        .await
        .unwrap();
    let attachment_c = prepared_c.commit(&pool).await.unwrap();
    let replacement = attachment_c.owner();
    assert!(!Arc::ptr_eq(&owner, &replacement));
    let endpoint_c = install_source(&pool, lease_c, attachment_c, target_c, &stats, node.id);
    owner.fail(ScoreOutcome::Io(io::ErrorKind::ConnectionReset));
    drop(owner);
    endpoint_c.send_packet(b"to-c", true).await.unwrap();
    let replacement_new = next_data_frame(&mut events, &mut replies).await;
    assert_eq!(
        (replacement_new.status, replacement_new.target),
        (STATUS_NEW, Some(target_c))
    );
    assert_eq!(replacement_new.global_id, Some(global_id));
    replies[&replacement_new.connection]
        .send((target_c, b"reply-c".to_vec()))
        .unwrap();
    assert_eq!(
        receive_reply(&client).await,
        (b"reply-c".to_vec(), target_c)
    );

    let identity_c = endpoint_identity(&pool, client_addr, target_c).unwrap();
    assert!(pool.retire_if_same(
        EndpointKey::new(client_addr, target_c),
        identity_c.0,
        identity_c.1
    ));
    let removed_c = removed_rx.recv().await.unwrap();
    assert!(pool.complete_removal(
        client_addr,
        target_c,
        removed_c.decision_token,
        removed_c.generation
    ));
    drop(endpoint_c);
    drop(replacement);
    assert!(pool.shutdown().await);
    generation.shutdown().await;
    wire_task.abort();
    let _ = wire_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn post_admission_view_cancel_is_health_neutral() {
    let (server, mut events, wire_task) = start_wire_peer().await;
    let node = vless_node(server);
    let generation = Arc::new(
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
            std::slice::from_ref(&node),
            2,
            2,
            2,
            None,
        )
        .unwrap()
        .0,
    );
    let runtime = generation.get(&node.id).unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let raw_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let raw_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target_a = raw_a.local_addr().unwrap();
    let target_b = raw_b.local_addr().unwrap();
    let pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        2,
        Arc::new(SourceReplySocketFactory::new([raw_a, raw_b])),
    ));
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let (removed_tx, mut removed_rx) = mpsc::channel(4);
    pool.set_remove_sink(removed_tx);

    let lease_a = reserve_source(&pool, &stats, client_addr, target_a, node.id);
    let lease_b = reserve_source(&pool, &stats, client_addr, target_b, node.id);
    let prepare_a = pool.prepare_vless_source(
        Arc::clone(&generation),
        Arc::clone(&runtime),
        client_addr,
        VlessUdpPath::Xudp,
        None,
        target_a,
        None,
        Duration::from_secs(2),
        Arc::clone(&alive),
        Arc::clone(&stats),
        honk_outbound::alive::IpVersion::V4,
    );
    let prepare_b = pool.prepare_vless_source(
        Arc::clone(&generation),
        Arc::clone(&runtime),
        client_addr,
        VlessUdpPath::Xudp,
        None,
        target_b,
        None,
        Duration::from_secs(2),
        Arc::clone(&alive),
        Arc::clone(&stats),
        honk_outbound::alive::IpVersion::V4,
    );
    let (prepared_a, prepared_b) = tokio::join!(prepare_a, prepare_b);
    let (attachment_a, attachment_b) = tokio::join!(
        prepared_a.unwrap().commit(&pool),
        prepared_b.unwrap().commit(&pool),
    );
    let attachment_a = attachment_a.unwrap();
    let attachment_b = attachment_b.unwrap();
    let owner = attachment_a.owner();
    assert!(Arc::ptr_eq(&owner, &attachment_b.owner()));
    let scope = SourceScope::new(&runtime, client_addr, VlessUdpPath::Xudp, None);
    let endpoint_a = install_source(&pool, lease_a, attachment_a, target_a, &stats, node.id);
    let endpoint_b = install_source(&pool, lease_b, attachment_b, target_b, &stats, node.id);

    endpoint_a.send_packet(b"first", true).await.unwrap();
    let mut replies = HashMap::new();
    let first = next_data_frame(&mut events, &mut replies).await;
    replies[&first.connection]
        .send((target_a, b"healthy".to_vec()))
        .unwrap();
    assert_eq!(
        receive_reply(&client).await,
        (b"healthy".to_vec(), target_a)
    );
    for _ in 0..49 {
        alive.report_unavailable_traffic(
            node.id,
            honk_outbound::alive::ProbeDomain::DataUdp,
            honk_outbound::alive::IpVersion::V4,
        );
    }
    assert!(alive.is_alive_for(
        node.id,
        honk_outbound::alive::ProbeDomain::DataUdp,
        honk_outbound::alive::IpVersion::V4,
    ));

    let mut pending_send = Box::pin(endpoint_b.send_packet(b"cancel-after-admission", false));
    let pending =
        poll_fn(|cx| std::task::Poll::Ready(Future::poll(pending_send.as_mut(), cx).is_pending()))
            .await;
    assert!(
        pending,
        "single poll must stop at the carrier writer acknowledgement"
    );
    let identity_b = endpoint_identity(&pool, client_addr, target_b).unwrap();
    assert!(pool.retire_if_same(
        EndpointKey::new(client_addr, target_b),
        identity_b.0,
        identity_b.1,
    ));
    drop(pending_send);
    wait_source_removed(&pool, &scope).await;
    assert!(alive.is_alive_for(
        node.id,
        honk_outbound::alive::ProbeDomain::DataUdp,
        honk_outbound::alive::IpVersion::V4,
    ));
    for _ in 0..2 {
        let removed = removed_rx.recv().await.unwrap();
        assert!(pool.complete_removal(
            removed.client,
            removed.dst,
            removed.decision_token,
            removed.generation,
        ));
    }
    drop(endpoint_a);
    drop(endpoint_b);
    drop(owner);
    assert!(pool.shutdown().await);
    generation.shutdown().await;
    wire_task.abort();
    let _ = wire_task.await;
}
fn endpoint_identity(
    pool: &UdpEndpointPool,
    client: SocketAddr,
    target: SocketAddr,
) -> Option<(u32, u64)> {
    pool.endpoints
        .get(&EndpointKey::new(client, target))
        .and_then(|entry| match entry.value() {
            EndpointEntry::Ready(ready) => Some((ready.decision_token, ready.generation)),
            EndpointEntry::Initializing(_) | EndpointEntry::Retiring { .. } => None,
        })
}
