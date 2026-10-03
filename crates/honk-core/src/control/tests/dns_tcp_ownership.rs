#![cfg(all(feature = "ebpf", target_os = "linux"))]

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn isolated<F, Fut>(test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>>,
{
    std::thread::spawn(move || -> anyhow::Result<()> {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)?;
        let mut netlink = crate::netlink::NlSock::new()?;
        let (loopback, _) = netlink.get_link("lo")?;
        netlink.set_link_up(loopback, true)?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(test())
    })
    .join()
    .expect("isolated TCP DNS test thread")
    .expect("isolated TCP DNS contract");
}

async fn dns_pair(bind: &str) -> anyhow::Result<(TcpListener, TcpStream, TcpStream, SocketAddr)> {
    let listener = TcpListener::bind(bind).await?;
    let client = TcpStream::connect(listener.local_addr()?).await?;
    let (accepted, peer) = listener.accept().await?;
    Ok((listener, client, accepted, peer))
}

#[derive(Debug)]
struct NodeDial;

#[async_trait::async_trait]
impl honk_outbound::proxy::TcpOutbound for NodeDial {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::ProxyStream> {
        let proxy_target = SocketAddr::new(node.address.parse()?, node.port);
        Ok(honk_outbound::proxy::ProxyStream {
            stream: Box::new(TcpStream::connect(proxy_target).await?),
            target_addr: target,
            target_domain: target_domain.map(str::to_owned),
        })
    }
}

fn dns_plane(
    destination: SocketAddr,
    peer: SocketAddr,
    route: Option<(u8, u8)>,
) -> anyhow::Result<(ControlPlane, Arc<AtomicUsize>)> {
    let node = udp_test_node();
    let config = udp_test_config(
        "group-a",
        vec![node.clone()],
        vec![
            Group {
                name: "group-a".into(),
                nodes: vec![node.id],
                ..Default::default()
            },
            Group {
                name: "group-b".into(),
                nodes: vec![node.id],
                ..Default::default()
            },
        ],
    );
    dns_plane_with_handler(
        config,
        destination,
        peer,
        route,
        Arc::new(UdpTestHandler {
            mode: UdpTestMode::TcpConnect,
        }),
    )
}

fn dns_plane_with_handler<T>(
    mut config: Config,
    destination: SocketAddr,
    peer: SocketAddr,
    route: Option<(u8, u8)>,
    handler: Arc<T>,
) -> anyhow::Result<(ControlPlane, Arc<AtomicUsize>)>
where
    T: honk_outbound::proxy::TcpOutbound + 'static,
{
    config.ensure_builtin_nodes();
    config.global.nfqueue_enable = false;
    config.global.dial_mode = "ip".into();
    config.global.preconnect_node_count = 0;
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
    let backend = crate::ebpf::mock::MockEbpfBackend::new();
    if let Some((outbound, must)) = route {
        let tuples = build_tuples_key(
            destination.ip(),
            destination.port(),
            peer.ip(),
            peer.port(),
            6,
        );
        let key: [u8; 40] = bytes_of(&tuples).try_into().expect("tuple key");
        backend.routing_handoffs.lock().insert(
            key,
            RoutingHandoffEntry {
                routing_generation: backend.routing_policy_generation() + 1,
                result: RoutingResult {
                    outbound,
                    must,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
    }
    let mut registry = ProxyRegistry::new();
    registry.register(honk_outbound::proxy::ProtocolEntry::new(
        NodeProtocol::Socks5,
        handler,
    ));
    registry.register(honk_outbound::proxy::ProtocolEntry::new(
        NodeProtocol::Block,
        Arc::new(honk_outbound::proxy::block::BlockHandler::new()),
    ));
    let mut plane = ControlPlane::new(
        config,
        Box::new(backend),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
        udp_test_forwarder(),
    )?;
    let queries = Arc::new(AtomicUsize::new(0));
    plane.dns_controller = production_dns_controller(Arc::clone(&queries), dns_response_payload());
    Ok((plane, queries))
}

fn proxy_node(name: &str, target: SocketAddr) -> Node {
    let mut node = udp_test_node();
    node.name = name.into();
    node.address = target.ip().to_string();
    node.port = target.port();
    node.id = node.derive_id();
    node
}

#[test]
#[ignore = "requires an isolated root network namespace; run via just test-netns"]
fn netns_tcp_dns_must_relays_original_frames_without_dns_processing() {
    isolated(|| async {
        for bind in ["127.0.0.1:53", "[::1]:53"] {
            let (listener, mut client, accepted, peer) = dns_pair(bind).await?;
            let destination = listener.local_addr()?;
            let (plane, queries) = dns_plane(destination, peer, Some((2, 1)))?;
            let handle = plane.spawn_handle();
            store_active_tcp_flow(&handle, destination, peer).await?;
            let task = tokio::spawn(async move { handle.serve_connection(accepted, peer).await });
            let query = dns_query_payload();
            let mut wire = (query.len() as u16).to_be_bytes().to_vec();
            wire.extend_from_slice(&query);
            wire.extend_from_slice(&[0, 1, 0xff]);
            client.write_all(&wire).await?;
            let (mut upstream, _) =
                tokio::time::timeout(Duration::from_secs(3), listener.accept()).await??;
            let mut received = vec![0; wire.len()];
            tokio::time::timeout(Duration::from_secs(3), upstream.read_exact(&mut received))
                .await??;
            assert_eq!(received, wire);
            assert_eq!(queries.load(Ordering::Relaxed), 0);
            let reply = [0, 3, b'r', b'a', b'w'];
            upstream.write_all(&reply).await?;
            let mut response = [0; 5];
            tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut response))
                .await??;
            assert_eq!(response, reply);
            client.shutdown().await?;
            upstream.shutdown().await?;
            drop(client);
            drop(upstream);
            tokio::time::timeout(Duration::from_secs(3), task).await???;
        }
        Ok(())
    });
}

#[test]
#[ignore = "requires an isolated root network namespace; run via just test-netns"]
fn netns_tcp_dns_missing_handoff_and_block_close_before_reading_frames() {
    isolated(|| async {
        for route in [
            None,
            Some((OutboundIndex::Block as u8, 0)),
            Some((OutboundIndex::Block as u8, 1)),
        ] {
            let (listener, mut client, accepted, peer) = dns_pair("127.0.0.1:53").await?;
            let destination = listener.local_addr()?;
            let (plane, queries) = dns_plane(destination, peer, route)?;
            let handle = plane.spawn_handle();
            store_active_tcp_flow(&handle, destination, peer).await?;
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                handle.serve_connection(accepted, peer),
            )
            .await?;
            if route.is_none() {
                assert!(result.is_err());
            } else {
                result?;
            }
            let mut byte = [0; 1];
            assert_eq!(client.read(&mut byte).await?, 0);
            assert_eq!(queries.load(Ordering::Relaxed), 0);
        }
        Ok(())
    });
}

#[test]
#[ignore = "requires an isolated root network namespace; run via just test-netns"]
fn netns_tcp_dns_queued_must_handoff_cannot_alias_reordered_group() {
    isolated(|| async {
        let (listener, mut client, accepted, peer) = dns_pair("127.0.0.1:53").await?;
        let destination = listener.local_addr()?;
        let (plane, _) = dns_plane(destination, peer, Some((2, 1)))?;
        let handle = plane.spawn_handle();
        store_active_tcp_flow(&handle, destination, peer).await?;
        let mut replacement = plane.config.read().await.as_ref().clone();
        replacement.groups.swap(0, 1);
        assert!(
            plane
                .apply_runtime_config(
                    replacement,
                    crate::config_diagnostics::DiagnosticBuckets::default(),
                    &DrainTracker::new(),
                )
                .await
                .accepted()
        );
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            handle.serve_connection(accepted, peer),
        )
        .await?;
        assert!(result.is_err());
        let mut byte = [0; 1];
        assert_eq!(client.read(&mut byte).await?, 0);
        Ok(())
    });
}

#[test]
#[ignore = "requires an isolated root network namespace; run via just test-netns"]
fn netns_tcp_dns_must_keeps_pinned_node_and_runtime_across_reload() {
    isolated(|| async {
        let (destination_listener, mut client, accepted, peer) = dns_pair("127.0.0.1:53").await?;
        let destination = destination_listener.local_addr()?;
        let old_listener = TcpListener::bind("127.0.0.1:0").await?;
        let new_listener = TcpListener::bind("127.0.0.1:0").await?;
        let old_node = proxy_node("old-node", old_listener.local_addr()?);
        let new_node = proxy_node("new-node", new_listener.local_addr()?);
        let config = udp_test_config(
            "group-a",
            vec![old_node.clone()],
            vec![Group {
                name: "group-a".into(),
                nodes: vec![old_node.id],
                ..Default::default()
            }],
        );
        let (plane, queries) = dns_plane_with_handler(
            config,
            destination,
            peer,
            Some((OutboundIndex::UserBase as u8, 1)),
            Arc::new(NodeDial),
        )?;
        let handle = plane.spawn_handle();
        store_active_tcp_flow(&handle, destination, peer).await?;
        let task = tokio::spawn(async move { handle.serve_connection(accepted, peer).await });

        let query = dns_query_payload();
        let mut wire = (query.len() as u16).to_be_bytes().to_vec();
        wire.extend_from_slice(&query);
        wire.extend_from_slice(&[0xde, 0xad, 0, 0xff]);
        client.write_all(&wire[..2]).await?;
        let (mut upstream, _) =
            tokio::time::timeout(Duration::from_secs(3), old_listener.accept()).await??;
        let mut received = vec![0; wire.len()];
        tokio::time::timeout(
            Duration::from_secs(3),
            upstream.read_exact(&mut received[..2]),
        )
        .await??;
        assert_eq!(&received[..2], &wire[..2]);

        let mut replacement = plane.config.read().await.as_ref().clone();
        replacement.nodes.retain(|node| node.id != old_node.id);
        replacement.nodes.push(new_node.clone());
        replacement
            .groups
            .iter_mut()
            .find(|group| group.name == "group-a")
            .expect("group-a")
            .nodes = vec![new_node.id];
        assert!(
            plane
                .apply_runtime_config(
                    replacement,
                    crate::config_diagnostics::DiagnosticBuckets::default(),
                    &DrainTracker::new(),
                )
                .await
                .accepted()
        );

        client.write_all(&wire[2..]).await?;
        tokio::time::timeout(
            Duration::from_secs(3),
            upstream.read_exact(&mut received[2..]),
        )
        .await??;
        assert_eq!(received, wire);
        assert_eq!(queries.load(Ordering::Relaxed), 0);

        let reply = [0, 3, b'o', b'l', b'd'];
        upstream.write_all(&reply).await?;
        let mut response = [0; 5];
        tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut response)).await??;
        assert_eq!(response, reply);
        client.shutdown().await?;
        upstream.shutdown().await?;
        drop(client);
        drop(upstream);
        tokio::time::timeout(Duration::from_secs(3), task).await???;
        Ok(())
    });
}
