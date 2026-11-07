use super::*;
use crate::control::netstack::{FlowIo, OutputLease, PacketOwner, PacketScope, RuntimeLimits};
use crate::control::tests::support::{canonical_socks5, dns_query_payload};
use anyhow::Context as _;
use honk_netstack::{ExcludeSet, FlowId, MemoryBudget, Mode, Stack, StreamError, TcpState};
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

struct Wire {
    scope: PacketScope,
    owner: Option<PacketOwner>,
    client: Stack,
    id: FlowId,
    now: std::time::Instant,
    received: Vec<u8>,
    eof: bool,
    hold_data: bool,
    held: Option<OutputLease>,
    budget: Arc<MemoryBudget>,
    qualified_rx: usize,
}

impl Wire {
    fn connect(destination: SocketAddr) -> anyhow::Result<(Self, FlowIo)> {
        let now = std::time::Instant::now();
        let budget = MemoryBudget::new(64 << 20);
        let mut cfg = honk_netstack::Config::new([31; 32]);
        cfg.max_flows = 8;
        cfg.memory_limit = 2 << 20;
        cfg.half_open_max = 8;
        cfg.tcp_rcv_buf_max = 64 << 10;
        cfg.tcp_snd_buf_max = 64 << 10;
        cfg.mode = Mode::Transparent {
            exclude: ExcludeSet::default(),
        };
        let (scope, owner) = PacketScope::new(
            cfg,
            Arc::clone(&budget),
            RuntimeLimits {
                max_slots: 8,
                control_frames: 2,
                bulk_frames: 2,
                max_waiters: 8,
            },
            now,
        )?;
        let mut cfg = honk_netstack::Config::new([47; 32]);
        cfg.local_v4 = Some("10.0.0.2".parse()?);
        cfg.local_v6 = Some("fd00::2".parse()?);
        cfg.max_flows = 8;
        cfg.tcp_rcv_buf_max = 64 << 10;
        cfg.tcp_snd_buf_max = 64 << 10;
        cfg.shared_budget = Some(Arc::clone(&budget));
        let mut client = Stack::new(cfg, now);
        let id = client
            .tcp_connect(now, destination)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let mut wire = Self {
            scope,
            owner: Some(owner),
            client,
            id,
            now,
            received: Vec::new(),
            eof: false,
            hold_data: false,
            held: None,
            budget,
            qualified_rx: 0,
        };
        wire.pump();
        let (syn, flow) = wire.scope.poll_accept().expect("real peer SYN admitted");
        assert_eq!(syn.original_dst, destination);
        assert_eq!(flow.local_addr(), destination);
        assert_eq!(flow.peer_addr(), syn.client);
        assert_ne!(flow.scope(), honk_datapath::ScopeId::HOST);
        wire.pump();
        assert_eq!(wire.client.tcp_state(id), Some(TcpState::Established));
        assert_eq!(
            wire.qualified_rx, 0,
            "handshake alone has no winning outbound"
        );
        Ok((wire, flow))
    }

    fn pump(&mut self) {
        self.now = self.now.max(std::time::Instant::now());
        let mut packet = [0; 2048];
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        for _ in 0..8 {
            self.client.handle_timeout(self.now);
            for _ in 0..64 {
                let Some(length) = self.client.poll_transmit(self.now, &mut packet) else {
                    break;
                };
                let (_, received) =
                    self.scope
                        .receive_with_source(&packet[..length], self.now, false, |_, _| true);
                self.qualified_rx += usize::from(received.qualified_rx);
            }
            self.scope.drive(self.now);
            for _ in 0..64 {
                let Poll::Ready(Some(output)) = self.scope.poll_output(&mut cx) else {
                    break;
                };
                assert_eq!(output.scope(), self.scope.scope());
                let ip =
                    honk_netstack::wire::parse_ip(output.packet()).expect("complete IP output");
                let segment = &output.packet()[ip.payload];
                let (_, offset) = honk_netstack::wire::tcp::parse(segment).expect("TCP output");
                let data = segment.len() > offset;
                let _ = self.client.receive(self.now, output.packet());
                if self.hold_data && data && self.held.is_none() {
                    assert!(output.flow_id().is_some());
                    self.held = Some(output);
                } else {
                    output.release();
                }
            }
            while self.client.poll_event().is_some() {}
            loop {
                match self.client.tcp_read(self.id, &mut packet) {
                    Ok(0) | Err(StreamError::Closed | StreamError::Reset | StreamError::Stale) => {
                        self.eof = true;
                        break;
                    }
                    Ok(length) => {
                        self.received.extend_from_slice(&packet[..length]);
                        assert!(self.received.len() <= 64 << 10);
                    }
                    Err(StreamError::WouldBlock) => break,
                    Err(error) => panic!("packet client read: {error:?}"),
                }
            }
        }
    }

    async fn until(&mut self, mut done: impl FnMut(&mut Self) -> bool) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                self.pump();
                if done(self) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        Ok(())
    }

    fn send(&mut self, bytes: &[u8]) {
        assert_eq!(self.client.tcp_write(self.id, bytes), Ok(bytes.len()));
        self.pump();
    }

    async fn settle(
        &mut self,
        task: &tokio::task::JoinHandle<anyhow::Result<()>>,
    ) -> anyhow::Result<()> {
        self.until(|wire| {
            wire.now += Duration::from_secs(130);
            task.is_finished()
        })
        .await
    }

    async fn finish(mut self) {
        self.held = None;
        self.scope.shutdown(true);
        self.pump();
        self.owner.take().expect("one runtime owner").run().await;
        let budget = Arc::clone(&self.budget);
        drop(self);
        assert_eq!(budget.used(), 0);
    }
}

fn config() -> Config {
    let mut config = Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.global.nfqueue_enable = false;
    config.global.store_subscribe = false;
    config.global.preconnect_node_count = 0;
    config.routing.default_outbound = "direct".into();
    config
}

fn plane(config: Config) -> anyhow::Result<ControlPlane> {
    let resolver = DnsResolver::new(&config.dns)?;
    let forwarder = resolver.forwarder();
    let router = Router::from_config(&config.routing)?;
    ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(ProxyRegistry::default_resolver()?),
        resolver,
        forwarder,
    )
}

#[tokio::test]
async fn packet_tcp_routes_real_loopback_and_keeps_close_until_output_release() -> anyhow::Result<()>
{
    tokio::time::timeout(Duration::from_secs(20), async {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let upstream = TcpListener::bind(bind).await?;
            let (mut wire, flow) = Wire::connect(upstream.local_addr()?)?;
            let plane = plane(config())?;
            let handle = plane.spawn_handle();
            handle.connection_tracker.enable();
            let worker = handle.clone();
            let serving = tokio::spawn(async move { worker.serve_packet_connection(flow).await });
            let (mut server, _) =
                tokio::time::timeout(Duration::from_secs(5), upstream.accept()).await??;
            wire.send(b"packet request");
            let mut request = [0; 14];
            server.read_exact(&mut request).await?;
            assert_eq!(&request, b"packet request");
            wire.hold_data = true;
            server.write_all(b"loopback response").await?;
            wire.until(|wire| wire.received.len() == 17).await?;
            assert_eq!(wire.received, b"loopback response");
            assert!(
                wire.qualified_rx > 0,
                "later accepted input observes the real successful winner"
            );
            assert!(wire.held.is_some());
            let connections = handle.connection_tracker.snapshot();
            assert_eq!(connections.len(), 1);
            assert_eq!(connections[0].upload, 14);
            assert_eq!(connections[0].download, 17);
            assert!(handle.tcp_flow_pins.snapshot().is_empty());
            let selected = handle
                .connection_tracker
                .snapshot_close(Some("tcp"), None, 1)
                .expect("one bounded selection")
                .pop()
                .expect("tracked packet flow");
            let request = handle.connection_tracker.start_close(selected);
            let closing = tokio::spawn(async move { request.wait().await });
            serving.abort();
            assert!(serving.await.expect_err("cancel core task").is_cancelled());
            wire.pump();
            assert_eq!(handle.connection_tracker.snapshot().len(), 1);
            assert!(
                !closing.is_finished(),
                "an exported packet is still owned by its consumer"
            );
            wire.held.take().unwrap().release();
            wire.pump();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), closing).await??,
                crate::connection_tracker::CloseOutcome::Closed
            );
            assert!(handle.connection_tracker.snapshot().is_empty());
            wire.finish().await;
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn admitted_packet_tcp_keeps_route_and_mode_after_publication() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let upstream = TcpListener::bind("127.0.0.1:0").await?;
        let (mut wire, mut flow) = Wire::connect(upstream.local_addr()?)?;
        let mut plane = plane(config())?;
        let mode = Arc::new(parking_lot::RwLock::new(crate::mode::ModeState::new(
            "Rule", "block",
        )));
        plane.set_mode_state(Arc::clone(&mode));
        let handle = plane.spawn_handle();
        let mut snapshot = handle
            .prepare_packet_routing_snapshot(
                flow.scope(),
                flow.peer_addr(),
                flow.local_addr(),
                "tcp",
                flow.dscp(),
                #[cfg(feature = "native-api")]
                false,
            )
            .await?;
        snapshot.admission_final = true;
        flow.set_routing(Some(
            crate::control::packet_endpoint::EndpointAdmission::new(snapshot, &wire.budget)?,
        ));
        let mut next = config();
        next.routing.default_outbound = "block".into();
        *handle.router.write().await = Router::from_config(&next.routing)?;
        *handle.config.write().await = Arc::new(next);
        *mode.write() = crate::mode::ModeState::new("Global", "block");
        let worker = handle.clone();
        let serving = tokio::spawn(async move { worker.serve_packet_connection(flow).await });
        let (mut server, _) =
            tokio::time::timeout(Duration::from_secs(5), upstream.accept()).await??;
        wire.send(b"admitted");
        let mut bytes = [0; 8];
        server.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"admitted");
        serving.abort();
        assert!(serving.await.unwrap_err().is_cancelled());
        wire.finish().await;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn packet_tcp_sniffing_preserves_domain_plus_and_initial_must() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
        for (mode, must, blocked, initial) in [
            ("domain+", false, false, "traffic"),
            ("domain++", false, true, "traffic"),
            ("domain++", true, false, "traffic"),
            ("domain++", false, true, "direct"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let (mut wire, flow) = Wire::connect(listener.local_addr()?)?;
            let mut config = config();
            let direct = config
                .nodes
                .iter()
                .find(|node| node.protocol() == honk_config::types::NodeProtocol::Direct)
                .unwrap()
                .id;
            config.groups = vec![Group {
                name: "traffic".into(),
                nodes: vec![direct],
                ..Default::default()
            }];
            config.routing.default_outbound = initial.into();
            config.global.dial_mode = mode.into();
            config.routing.rules.push(RoutingRule {
                name: "sniffed-block".into(),
                condition: RoutingCondition {
                    domain: vec!["blocked.example".into()],
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple("block".into()),
                priority: 0,
                must: false,
                mark: 0,
            });
            if must {
                config.routing.rules.push(RoutingRule {
                    name: "initial-must".into(),
                    condition: RoutingCondition {
                        protocol: vec!["tcp".into()],
                        ..Default::default()
                    },
                    outbound: RoutingOutbound::Simple("traffic".into()),
                    priority: 0,
                    must: true,
                    mark: 0,
                });
            }
            let plane = plane(config)?;
            let handle = plane.spawn_handle();
            let worker = handle.clone();
            let serving = tokio::spawn(async move { worker.serve_packet_connection(flow).await });
            let request = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n";
            wire.send(request);
            if blocked {
                wire.until(|_| serving.is_finished())
                    .await
                    .with_context(|| format!("{mode}: blocked task completion"))?;
                serving.await??;
                assert_eq!(wire.qualified_rx, 0, "sniffed Block never marks the flow");
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), listener.accept())
                        .await
                        .is_err()
                );
            } else {
                let (mut server, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .with_context(|| {
                            format!(
                                "{mode} must={must}: upstream accept; serving_finished={}",
                                serving.is_finished()
                            )
                        })??;
                let mut received = vec![0; request.len()];
                server.read_exact(&mut received).await?;
                assert_eq!(received, request);
                server.write_all(b"routed").await?;
                wire.until(|wire| wire.received.len() == 6)
                    .await
                    .with_context(|| format!("{mode} must={must}: response"))?;
                assert_eq!(wire.received, b"routed");
                wire.client.tcp_shutdown(wire.id).unwrap();
                server.shutdown().await?;
                wire.until(|wire| wire.eof)
                    .await
                    .with_context(|| format!("{mode} must={must}: EOF"))?;
                wire.settle(&serving)
                    .await
                    .with_context(|| format!("{mode} must={must}: retirement"))?;
                serving.await??;
            }
            assert!(handle.tcp_flow_pins.snapshot().is_empty());
            wire.finish().await;
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn packet_tcp_dns_policy_precedes_framed_controller_and_must_uses_real_proxy()
-> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
        let dns = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let socket = Arc::clone(&dns);
        let counted = Arc::clone(&calls);
        let dns_server = tokio::spawn(async move {
            let mut packet = [0; 2048];
            for _ in 0..2 {
                let (length, peer) = socket.recv_from(&mut packet).await?;
                counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                packet[2] = 0x81;
                packet[3] = 0x80;
                socket.send_to(&packet[..length], peer).await?;
            }
            Ok::<_, std::io::Error>(())
        });
        let destination = "198.51.100.53:53".parse()?;
        let query = dns_query_payload();
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&query);
        for disposition in ["block", "controller", "must"] {
            let proxy = TcpListener::bind("127.0.0.1:0").await?;
            let (mut wire, flow) = Wire::connect(destination)?;
            let mut config = config();
            config.dns.upstream = vec![honk_config::dns::DnsUpstream {
                name: "default".into(),
                address: dns.local_addr()?.to_string(),
                protocol: honk_config::types::DnsProtocol::Udp,
                tls_server_name: None,
                outbound: None,
            }];
            config.dns.routing.fallback = "default".into();
            if disposition == "block" {
                config.routing.default_outbound = "block".into();
            } else if disposition == "must" {
                let node =
                    canonical_socks5("dns-peer", "127.0.0.1", proxy.local_addr()?.port(), None);
                config.groups = vec![Group {
                    name: "dns-raw".into(),
                    nodes: vec![node.id],
                    ..Default::default()
                }];
                config.nodes.push(node);
                config.routing.rules.push(RoutingRule {
                    name: "dns-must".into(),
                    condition: RoutingCondition {
                        protocol: vec!["tcp".into()],
                        ..Default::default()
                    },
                    outbound: RoutingOutbound::Simple("dns-raw".into()),
                    priority: 0,
                    must: true,
                    mark: 0,
                });
            }
            let plane = plane(config)?;
            plane
                .dns_controller
                .register_packet_scopes(std::slice::from_ref(&wire.scope))?;
            let handle = plane.spawn_handle();
            let worker = handle.clone();
            let serving = tokio::spawn(async move { worker.serve_packet_connection(flow).await });
            wire.send(&framed);
            match disposition {
                "block" => {
                    wire.until(|_| serving.is_finished()).await?;
                    serving.await??;
                    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
                    assert_eq!(wire.qualified_rx, 0);
                }
                "controller" => {
                    wire.until(|wire| wire.received.len() == framed.len())
                        .await?;
                    let mut expected = framed.clone();
                    expected[4] = 0x81;
                    expected[5] = 0x80;
                    assert_eq!(wire.received, expected);
                    wire.send(&framed);
                    wire.until(|wire| wire.received.len() == framed.len() * 2)
                        .await?;
                    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 2);
                    wire.send(&[0, 1, 0xff]);
                    wire.until(|wire| wire.eof).await?;
                    assert_eq!(wire.received.len(), framed.len() * 2);
                    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 2);
                    assert_eq!(
                        wire.qualified_rx, 0,
                        "per-query DNS authority never marks the stream"
                    );
                    wire.client.tcp_shutdown(wire.id).unwrap();
                    wire.settle(&serving).await?;
                    serving.await??;
                }
                "must" => {
                    let (mut server, _) =
                        tokio::time::timeout(Duration::from_secs(5), proxy.accept()).await??;
                    let mut hello = [0; 3];
                    server.read_exact(&mut hello).await?;
                    assert_eq!(hello, [5, 1, 0]);
                    server.write_all(&[5, 0]).await?;
                    let mut request = [0; 10];
                    server.read_exact(&mut request).await?;
                    assert_eq!(request, [5, 1, 0, 1, 198, 51, 100, 53, 0, 53]);
                    server.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
                    let mut received = vec![0; framed.len()];
                    server.read_exact(&mut received).await?;
                    assert_eq!(received, framed);
                    server.write_all(b"raw-not-dns").await?;
                    wire.until(|wire| wire.received.len() == 11).await?;
                    assert_eq!(wire.received, b"raw-not-dns");
                    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 2);
                    wire.client.tcp_shutdown(wire.id).unwrap();
                    server.shutdown().await?;
                    wire.until(|wire| wire.eof).await?;
                    wire.settle(&serving).await?;
                    serving.await??;
                }
                _ => unreachable!(),
            }
            assert!(handle.tcp_flow_pins.snapshot().is_empty());
            plane.dns_controller.shutdown(Duration::from_secs(1)).await;
            drop(handle);
            drop(plane);
            wire.finish().await;
        }
        tokio::time::timeout(Duration::from_secs(5), dns_server).await???;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn packet_tcp_uses_dns_learned_domain_without_a_sniffed_name() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};

        let blocked = TcpListener::bind("127.0.0.1:0").await?;
        let direct = TcpListener::bind("127.0.0.1:0").await?;
        let dns = UdpSocket::bind("127.0.0.1:0").await?;
        let mut config = config();
        config.dns.upstream = vec![honk_config::dns::DnsUpstream {
            name: "loopback".into(),
            address: dns.local_addr()?.to_string(),
            protocol: honk_config::types::DnsProtocol::Udp,
            tls_server_name: None,
            outbound: None,
        }];
        config.dns.routing.fallback = "loopback".into();
        config.routing.rules.push(RoutingRule {
            name: "learned-block".into(),
            condition: RoutingCondition {
                domain: vec!["a.com".into()],
                port: vec![blocked.local_addr()?.port().to_string()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("block".into()),
            priority: 0,
            must: false,
            mark: 0,
        });
        let (mut wire, flow) = Wire::connect("198.51.100.53:53".parse()?)?;
        let plane = plane(config)?;
        plane
            .dns_controller
            .register_packet_scopes(std::slice::from_ref(&wire.scope))?;
        let handle = plane.spawn_handle();
        let worker = handle.clone();
        let serving = tokio::spawn(async move { worker.serve_packet_connection(flow).await });
        let query = dns_query_payload();
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&query);
        wire.send(&framed);
        let mut response = [0; 1024];
        let (length, sender) = dns.recv_from(&mut response).await?;
        assert_eq!(
            crate::dns::forwarder::parse_dns_question(&response[..length]),
            Some(("a.com".into(), 1))
        );
        response[2] = 0x81;
        response[3] = 0x80;
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        let answer = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1];
        response[length..length + answer.len()].copy_from_slice(&answer);
        dns.send_to(&response[..length + answer.len()], sender)
            .await?;
        wire.until(|wire| {
            wire.received.len() >= 2
                && wire.received.len()
                    == usize::from(u16::from_be_bytes([wire.received[0], wire.received[1]])) + 2
        })
        .await?;
        assert_eq!(
            crate::dns::forwarder::extract_answer_ips(&wire.received[2..]),
            ["127.0.0.1".parse::<std::net::IpAddr>()?]
        );
        serving.abort();
        assert!(serving.await.unwrap_err().is_cancelled());
        wire.pump();

        let destination = blocked.local_addr()?;
        let accepting = tokio::spawn(async move { blocked.accept().await });
        for blocked in [false, true] {
            let destination = if blocked {
                destination
            } else {
                direct.local_addr()?
            };
            wire.id = wire
                .client
                .tcp_connect(wire.now, destination)
                .map_err(|error| anyhow::anyhow!("{error:?}"))?;
            wire.received.clear();
            wire.eof = false;
            wire.pump();
            let (_, flow) = wire.scope.poll_accept().expect("numeric TCP SYN admitted");
            wire.pump();
            let worker = handle.clone();
            let serving = tokio::spawn(async move { worker.serve_packet_connection(flow).await });
            if blocked {
                wire.until(|_| serving.is_finished() || accepting.is_finished())
                    .await?;
                assert!(
                    !accepting.is_finished(),
                    "DNS-learned Block reached the fallback Direct TCP peer"
                );
                serving.await??;
            } else {
                let (mut server, _) = direct.accept().await?;
                wire.send(b"numeric-direct-control");
                let mut bytes = [0; 22];
                server.read_exact(&mut bytes).await?;
                assert_eq!(&bytes, b"numeric-direct-control");
                server.write_all(b"numeric-reply").await?;
                wire.until(|wire| wire.received.len() == 13).await?;
                assert_eq!(wire.received, b"numeric-reply");
                serving.abort();
                assert!(serving.await.unwrap_err().is_cancelled());
                wire.pump();
            }
        }
        accepting.abort();
        assert!(accepting.await.unwrap_err().is_cancelled());
        assert!(plane.ebpf.read().await.projection_map_snapshot().is_empty());
        plane.dns_controller.shutdown(Duration::from_secs(1)).await;
        drop(handle);
        drop(plane);
        wire.finish().await;
        Ok(())
    })
    .await?
}
