use super::*;
use crate::control::tests::support::{canonical_socks5, dns_query_payload};
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

struct Peer {
    group: String,
    node: honk_config::node::Node,
    seen: mpsc::Receiver<Vec<u8>>,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Peer {
    async fn start(name: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay.local_addr().unwrap().port();
        let node = canonical_socks5(
            &format!("node-{name}"),
            "127.0.0.1",
            listener.local_addr().unwrap().port(),
            None,
        );
        let (events, seen) = mpsc::channel(32);
        let (stop, mut stopping) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut controls = tokio::task::JoinSet::new();
            let mut packet = vec![0; 65_536];
            loop {
                tokio::select! {
                    _ = &mut stopping => break,
                    Some(result) = controls.join_next(), if !controls.is_empty() => { result.unwrap(); },
                    accepted = listener.accept() => {
                        let (mut stream, _) = accepted.unwrap();
                        controls.spawn(async move {
                            let mut greeting = [0; 3];
                            if stream.read_exact(&mut greeting).await.is_err() { return; }
                            assert_eq!(greeting, [5, 1, 0]);
                            stream.write_all(&[5, 0]).await.unwrap();
                            let mut request = [0; 4];
                            stream.read_exact(&mut request).await.unwrap();
                            assert_eq!(&request[..3], &[5, 3, 0]);
                            let address_length = match request[3] {
                                1 => 6,
                                4 => 18,
                                3 => usize::from(stream.read_u8().await.unwrap()) + 2,
                                other => panic!("unexpected associate address {other}"),
                            };
                            stream.read_exact(&mut vec![0; address_length]).await.unwrap();
                            let mut response = vec![5, 0, 0, 1, 127, 0, 0, 1];
                            response.extend_from_slice(&relay_port.to_be_bytes());
                            stream.write_all(&response).await.unwrap();
                            let _ = stream.read(&mut [0; 1]).await;
                        });
                    }
                    received = relay.recv_from(&mut packet) => {
                        let (length, client) = received.unwrap();
                        assert_eq!(&packet[..3], &[0, 0, 0]);
                        let offset = match packet[3] {
                            1 => 10,
                            4 => 22,
                            3 => usize::from(packet[4]) + 7,
                            other => panic!("unexpected UDP address {other}"),
                        };
                        assert!(length >= offset);
                        let port = u16::from_be_bytes(packet[offset - 2..offset].try_into().unwrap());
                        if port == 53 {
                            events.send(packet[offset..length].to_vec()).await.unwrap();
                        } else if length >= offset + 12 {
                            packet[offset + 2] |= 0x80;
                        }
                        relay.send_to(&packet[..length], client).await.unwrap();
                    }
                }
            }
            controls.abort_all();
            while let Some(result) = controls.join_next().await {
                assert!(result.is_ok() || result.unwrap_err().is_cancelled());
            }
        });
        Self {
            group: name.to_owned(),
            node,
            seen,
            stop,
            task,
        }
    }

    async fn close(self) {
        let _ = self.stop.send(());
        self.task.await.unwrap();
    }
}

fn config(peers: &[&Peer]) -> honk_config::Config {
    let mut config = honk_config::Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.global.tcp_check_url.clear();
    config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
    config.global.preconnect_node_count = 0;
    config.global.udp_warm_node_count = 0;
    for peer in peers {
        config.nodes.push(peer.node.clone());
        config.groups.push(honk_config::node::Group {
            name: peer.group.clone(),
            nodes: vec![peer.node.id],
            ..Default::default()
        });
    }
    config
}

async fn plane(config: honk_config::Config) -> (ControlPlane, TcpListener) {
    let resolver = crate::dns::DnsResolver::new(&config.dns).unwrap();
    let forwarder = resolver.forwarder();
    let router = crate::routing::Router::from_config(&config.routing).unwrap();
    let plane = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(honk_outbound::proxy::ProxyRegistry::default_resolver().unwrap()),
        resolver,
        forwarder,
    )
    .unwrap();
    let health = TcpListener::bind("127.0.0.1:0").await.unwrap();
    plane
        .alive_set
        .set_direct_check_addr(health.local_addr().unwrap().to_string());
    (plane, health)
}

fn packet(source: SocketAddr, destination: SocketAddr, dscp: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; payload.len() + 64];
    let length = wire::udp::emit_packet(&mut packet, source, destination, payload).unwrap();
    packet.truncate(length);
    assert!(source.is_ipv4());
    packet[1] = dscp << 2;
    packet[10..12].fill(0);
    let mut sum: u32 = packet[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|word| u32::from(u16::from_be_bytes(*word)))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet
}

async fn reply_payload(
    scope: &PacketScope,
    source: SocketAddr,
    destination: SocketAddr,
) -> Vec<u8> {
    let output = scope.next_output().await.unwrap();
    let ip = wire::parse_ip(output.packet()).unwrap();
    assert_eq!((ip.src, ip.dst), (destination.ip(), source.ip()));
    let udp = &output.packet()[ip.payload];
    assert!(wire::udp::verify_checksum(ip.src, ip.dst, udp));
    let (from, to, payload) = wire::udp::parse(udp).unwrap();
    assert_eq!((from, to), (destination.port(), source.port()));
    let payload = udp[payload].to_vec();
    output.release();
    payload
}

async fn reply(scope: &PacketScope, source: SocketAddr, destination: SocketAddr, expected: &[u8]) {
    assert_eq!(reply_payload(scope, source, destination).await, expected);
}

#[tokio::test]
async fn raw_udp53_dscp_change_cannot_reuse_the_previous_outbound() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut alpha = Peer::start("alpha").await;
        let beta = Peer::start("beta").await;
        let mut config = config(&[&alpha, &beta]);
        config.routing.default_outbound = "alpha".into();
        config.routing.rules.push(RoutingRule {
            name: "dscp-beta".into(),
            condition: RoutingCondition {
                dscp: vec!["46".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("beta".into()),
            priority: 0,
            must: false,
            mark: 0,
        });
        let (plane, _health) = plane(config).await;
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 4)
            .await
            .unwrap();
        let source = "192.0.2.10:41000".parse().unwrap();
        let destination = "198.51.100.53:53".parse().unwrap();
        endpoints
            .receive(
                scope.scope(),
                &packet(source, destination, 0, b"first"),
                Instant::now(),
            )
            .unwrap();
        assert_eq!(alpha.seen.recv().await.unwrap(), b"first");
        reply(&scope, source, destination, b"first").await;
        endpoints
            .receive(
                scope.scope(),
                &packet(source, destination, 46, b"wrong-owner"),
                Instant::now(),
            )
            .unwrap();
        endpoints
            .receive(
                scope.scope(),
                &packet(source, destination, 0, b"same-owner"),
                Instant::now(),
            )
            .unwrap();
        assert_eq!(alpha.seen.recv().await.unwrap(), b"same-owner");
        reply(&scope, source, destination, b"same-owner").await;
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
        alpha.close().await;
        beta.close().await;
    })
    .await
    .expect("raw DNS route identity must reject a changed DSCP decision");
}

#[tokio::test]
async fn nonfinal_raw_udp53_keeps_sniffing_but_cannot_alias_a_must_route() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let alpha = Peer::start("alpha").await;
        let mut beta = Peer::start("beta").await;
        let mut config = config(&[&alpha, &beta]);
        config.global.dial_mode = "domain++".into();
        config.routing.default_outbound = "alpha".into();
        config.routing.rules.push(RoutingRule {
            name: "must-alpha".into(),
            condition: RoutingCondition {
                dscp: vec!["46".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("alpha".into()),
            priority: 0,
            must: true,
            mark: 0,
        });
        config.routing.rules.push(RoutingRule {
            name: "sniff-beta".into(),
            condition: RoutingCondition {
                domain: vec!["example.com".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("beta".into()),
            priority: 1,
            must: false,
            mark: 0,
        });
        let (plane, _health) = plane(config).await;
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 4)
            .await
            .unwrap();
        let source = "192.0.2.10:41000".parse().unwrap();
        let destination = "198.51.100.53:53".parse().unwrap();
        let initial = crate::control::quic::test_utils::rfc9001_client_initial();
        endpoints
            .receive(
                scope.scope(),
                &packet(source, destination, 0, &initial),
                Instant::now(),
            )
            .unwrap();
        assert_eq!(beta.seen.recv().await.unwrap(), initial);
        reply(&scope, source, destination, &initial).await;
        endpoints
            .receive(
                scope.scope(),
                &packet(source, destination, 46, b"must-alpha"),
                Instant::now(),
            )
            .unwrap();
        endpoints
            .receive(
                scope.scope(),
                &packet(source, destination, 0, b"still-beta"),
                Instant::now(),
            )
            .unwrap();
        assert_eq!(beta.seen.recv().await.unwrap(), b"still-beta");
        reply(&scope, source, destination, b"still-beta").await;
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
        alpha.close().await;
        beta.close().await;
    })
    .await
    .expect("fallback identity must preserve sniffing and must finality");
}

#[tokio::test]
async fn packet_udp_dns_policy_and_controller_preserve_wire_reply_ownership() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for disposition in ["controller", "block", "must"] {
            let mut proxy = Peer::start("dns-raw").await;
            let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut config = config(&[&proxy]);
            config.dns.upstream = vec![honk_config::dns::DnsUpstream {
                name: "loopback".into(),
                address: dns.local_addr().unwrap().to_string(),
                protocol: honk_config::types::DnsProtocol::Udp,
                tls_server_name: None,
                outbound: None,
            }];
            config.dns.routing.fallback = "loopback".into();
            config.routing.default_outbound = if disposition == "block" {
                "block"
            } else {
                "direct"
            }
            .into();
            config.routing.rules.push(RoutingRule {
                name: "projected-domain".into(),
                condition: RoutingCondition {
                    domain: vec!["a.com".into()],
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple("direct".into()),
                priority: 0,
                must: false,
                mark: 0,
            });
            if disposition == "must" {
                config.routing.rules.push(RoutingRule {
                    name: "raw-must".into(),
                    condition: RoutingCondition {
                        protocol: vec!["udp".into()],
                        ..Default::default()
                    },
                    outbound: RoutingOutbound::Simple("dns-raw".into()),
                    priority: 0,
                    must: true,
                    mark: 0,
                });
            }
            let (plane, _health) = plane(config).await;
            let backend = Arc::clone(&plane.ebpf);
            let budget = MemoryBudget::new(32 << 20);
            let (scope, scope_owner) = scope(&budget);
            let (endpoints, owner) =
                PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 2)
                    .await
                    .unwrap();
            let source = "192.0.2.10:41000".parse().unwrap();
            let destination = "198.51.100.53:53".parse().unwrap();
            let query = dns_query_payload();
            endpoints
                .receive(
                    scope.scope(),
                    &packet(source, destination, 0, &query),
                    Instant::now(),
                )
                .unwrap();
            if disposition == "controller" {
                let mut response = [0; 1024];
                let (length, sender) = dns.recv_from(&mut response).await.unwrap();
                assert_eq!(
                    crate::dns::forwarder::parse_dns_question(&response[..length]),
                    Some(("a.com".to_owned(), 1)),
                );
                response[2] = 0x81;
                response[3] = 0x80;
                response[6..8].copy_from_slice(&1u16.to_be_bytes());
                let answer = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 99];
                response[length..length + answer.len()].copy_from_slice(&answer);
                dns.send_to(&response[..length + answer.len()], sender)
                    .await
                    .unwrap();
                let received = reply_payload(&scope, source, destination).await;
                assert_eq!(&received[..2], &query[..2]);
                assert_ne!(received[2] & 0x80, 0);
                assert_eq!(received[3] & 0x0f, 0);
                assert_eq!(
                    crate::dns::forwarder::parse_dns_question(&received),
                    Some(("a.com".to_owned(), 1))
                );
                assert_eq!(
                    crate::dns::forwarder::extract_answer_ips(&received),
                    vec!["203.0.113.99".parse::<std::net::IpAddr>().unwrap()]
                );
            } else if disposition == "must" {
                let mut unexpected = [0; 1024];
                tokio::select! {
                    received = proxy.seen.recv() => assert_eq!(received.unwrap(), query),
                    received = dns.recv_from(&mut unexpected) => {
                        panic!("must UDP query reached the DNS controller: {received:?}");
                    }
                }
                reply(&scope, source, destination, &query).await;
            } else {
                assert!(
                    tokio::time::timeout(Duration::from_millis(100), scope.next_output())
                        .await
                        .is_err()
                );
            }
            assert!(dns.try_recv_from(&mut [0; 1024]).is_err());
            assert!(backend.read().await.projection_map_snapshot().is_empty());
            endpoints.shutdown().await.unwrap();
            owner.run().await.unwrap();
            proxy.close().await;
        }
    })
    .await
    .expect("UDP53 policy must precede controller and raw transport admission");
}

fn fragments(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<Vec<u8>> {
    let now = Instant::now();
    let mut config = StackConfig::new([91; 32]);
    config.mode = Mode::Transparent {
        exclude: ExcludeSet::default(),
    };
    config.mtu = 1280;
    let mut sender = honk_netstack::Stack::new(config, now);
    let mut output = [0; 1280];
    let first = sender
        .udp_send_from(source, destination, payload, &mut output)
        .unwrap();
    let mut packets = vec![output[..first].to_vec()];
    while let Some(length) = sender.poll_transmit(now, &mut output) {
        packets.push(output[..length].to_vec());
    }
    packets
}

#[test]
fn owned_reassembly_bytes_outlive_initializer_pool_and_stack_without_copy() {
    let budget = MemoryBudget::new(32 << 20);
    let (scope, owner) = scope(&budget);
    let source = "192.0.2.10:41000".parse().unwrap();
    let destination = "198.51.100.1:443".parse().unwrap();
    let body = vec![0x5a; 4000];
    let now = Instant::now();
    let mut completed = None;
    for packet in fragments(source, destination, &body) {
        match scope.receive(&packet, now) {
            Rx::Consumed => {}
            Rx::TransparentOwned {
                packet, payload, ..
            } => completed = Some((packet, payload)),
            other => panic!("unexpected reassembly result {other:?}"),
        }
    }
    let (packet, payload) = completed.unwrap();
    let packet_bytes = packet.len();
    let original = packet[payload.clone()].as_ptr();
    let data = FundedDatagram::from_packet(packet, payload, &budget).unwrap();
    let pool = Arc::new(
        UdpEndpointPool::with_packet_reply_factory(
            1,
            Arc::new(Replies(Arc::from([scope.clone()]))),
            Arc::clone(&budget),
        )
        .unwrap(),
    );
    let (removed, mut removals) = mpsc::channel(1);
    pool.set_remove_sink(removed);
    let stats = crate::stats::StatsManager::new();
    let EndpointReservation::Initializing(lease) = pool.reserve_payload_or_enqueue_at(
        scope.scope(),
        source,
        destination,
        DatagramPayload::Funded(data),
        None,
        crate::ebpf::UdpFlowOwner::packet(),
        pool.initialization_epoch(),
        Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap(),
        super::super::super::udp_endpoint::queue_now(),
        &stats,
    ) else {
        panic!("owned packet admission refused")
    };
    let retained = lease.first_payload();
    assert_eq!(retained.as_ptr(), original);
    drop(lease);
    pool.finish_removal(&removals.try_recv().unwrap(), true);
    drop(pool);
    drop(owner);
    drop(scope);
    assert_eq!(retained.as_ref(), body);
    assert!(budget.used() >= packet_bytes);
    let clone = retained.clone();
    drop(retained);
    assert!(budget.used() >= packet_bytes);
    drop(clone);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn fragmented_packet_udp_reaches_real_outbound_and_returns_every_byte() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = upstream.local_addr().unwrap();
        let source = "192.0.2.10:41000".parse().unwrap();
        let body: Vec<u8> = (0..4000).map(|index| (index % 251) as u8).collect();
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (plane, _health) = local_plane().await;
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1)
            .await
            .unwrap();
        let now = Instant::now();
        for packet in fragments(source, destination, &body) {
            endpoints.receive(scope.scope(), &packet, now).unwrap();
        }
        let mut received = [0; 8192];
        let (length, peer) = upstream.recv_from(&mut received).await.unwrap();
        assert_eq!(&received[..length], body);
        upstream.send_to(&received[..length], peer).await.unwrap();
        let mut config = StackConfig::new([92; 32]);
        config.mode = Mode::Transparent {
            exclude: ExcludeSet::default(),
        };
        let mut receiver = honk_netstack::Stack::new(config, Instant::now());
        loop {
            let output = scope.next_output().await.unwrap();
            let result = receiver.receive(Instant::now(), output.packet());
            output.release();
            match result {
                Rx::Consumed => {}
                Rx::TransparentOwned {
                    src,
                    dst,
                    packet,
                    payload,
                    ..
                } => {
                    assert_eq!((src, dst), (destination, source));
                    assert_eq!(&packet[payload], body);
                    break;
                }
                other => panic!("unexpected reply fragment {other:?}"),
            }
        }
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
        drop(endpoints);
        drop(scope);
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("owned reassembly must traverse the actual UDP dispatcher");
}
