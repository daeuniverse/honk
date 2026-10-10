use super::*;
use honk_config::node::{Udp443Policy, VlessMultiplex};

#[tokio::test]
async fn different_sources_share_only_aggregated_carriers() {
    for aggregated in [false, true] {
        let (server, mut events, wire_task) = start_wire_peer().await;
        let mut node = vless_node(server);
        let path = if aggregated {
            node.vless_mut().unwrap().multiplex = VlessMultiplex::xray(-1, 8, Udp443Policy::Allow);
            VlessUdpPath::CoolSeparate
        } else {
            VlessUdpPath::Xudp
        };
        node.vless_mut().unwrap().normalize();
        node.id = node.derive_id();
        let generation = Arc::new(
            OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
                std::slice::from_ref(&node),
                8,
                8,
                8,
                false,
                None,
            )
            .unwrap()
            .0,
        );
        let runtime = generation.get(&node.id).unwrap();
        let clients = [
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        ];
        let reply_sockets = [
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        ];
        let targets = reply_sockets
            .each_ref()
            .map(|socket| socket.local_addr().unwrap());
        let pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
            8,
            Arc::new(SourceReplySocketFactory::new(reply_sockets)),
        ));
        let stats = Arc::new(StatsManager::new());
        let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
        let mut endpoints = Vec::new();
        let mut frames = Vec::new();
        let mut replies = HashMap::new();
        for (client, target) in clients.iter().zip(targets) {
            let client = client.local_addr().unwrap();
            let lease = reserve_source(&pool, &stats, client, target, node.id);
            let attachment = pool
                .prepare_vless_source(
                    Arc::clone(&generation),
                    Arc::clone(&runtime),
                    client,
                    path,
                    None,
                    target,
                    None,
                    Duration::from_secs(2),
                    Arc::clone(&alive),
                    Arc::clone(&stats),
                    honk_outbound::alive::IpVersion::V4,
                )
                .await
                .unwrap()
                .commit(&pool)
                .await
                .unwrap();
            let endpoint = install_source(&pool, lease, attachment, target, &stats, node.id);
            endpoint.send_packet(b"first", true).await.unwrap();
            let frame = next_data_frame(&mut events, &mut replies).await;
            assert_eq!(frame.status, STATUS_NEW);
            assert_eq!(frame.target, Some(target));
            assert_eq!(frame.payload.as_deref(), Some(b"first".as_slice()));
            frames.push(frame);
            endpoints.push(endpoint);
        }
        assert!(frames[0].global_id.is_some());
        assert!(frames[1].global_id.is_some());
        assert_ne!(frames[0].global_id, frames[1].global_id);
        assert_eq!(frames[0].connection == frames[1].connection, aggregated);
        if aggregated {
            assert_ne!(frames[0].session_id, frames[1].session_id);
        } else {
            assert_eq!((frames[0].session_id, frames[1].session_id), (0, 0));
        }
        if aggregated {
            endpoints[0].kill();
        }
        endpoints[1].send_packet(b"survivor", false).await.unwrap();
        let keep = next_data_frame(&mut events, &mut replies).await;
        assert_eq!(
            (keep.connection, keep.session_id),
            (frames[1].connection, frames[1].session_id)
        );
        assert_eq!(keep.status, STATUS_KEEP);
        assert_eq!(keep.payload.as_deref(), Some(b"survivor".as_slice()));
        endpoints.clear();
        assert!(pool.shutdown().await.joined);
        generation.shutdown().await;
        wire_task.abort();
        let _ = wire_task.await;
    }
}

#[tokio::test]
async fn rewritten_sources_keep_distinct_original_reply_addresses() {
    let (server, mut events, wire_task) = start_wire_peer().await;
    let node = vless_node(server);
    let generation = Arc::new(OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap());
    let runtime = generation.get(&node.id).unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let reply_sockets = [
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
    ];
    let originals = reply_sockets
        .each_ref()
        .map(|socket| socket.local_addr().unwrap());
    let remote: SocketAddr = "192.0.2.10:9999".parse().unwrap();
    let pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        8,
        Arc::new(SourceReplySocketFactory::new(reply_sockets)),
    ));
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let mut endpoints = Vec::new();
    let mut frames = Vec::new();
    let mut replies = HashMap::new();
    for original in originals {
        let mut lease = reserve_source(&pool, &stats, client_addr, original, node.id);
        let attachment = pool
            .prepare_vless_source(
                Arc::clone(&generation),
                Arc::clone(&runtime),
                client_addr,
                VlessUdpPath::Xudp,
                Some(original),
                remote,
                None,
                Duration::from_secs(2),
                Arc::clone(&alive),
                Arc::clone(&stats),
                honk_outbound::alive::IpVersion::V4,
            )
            .await
            .unwrap()
            .commit(&pool)
            .await
            .unwrap();
        let endpoint = Arc::new(UdpEndpoint::new_source_scored(
            attachment,
            remote,
            None,
            Arc::new(pool.create_reply_socket(original).unwrap()),
            stats.outbound_tracker("core-source-vless", crate::stats::OutboundKind::Node),
            node.id,
            honk_outbound::alive::IpVersion::V4,
            None,
        ));
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        endpoint.send_packet(b"same-remote", true).await.unwrap();
        let frame = next_data_frame(&mut events, &mut replies).await;
        assert_eq!((frame.status, frame.target), (STATUS_NEW, Some(remote)));
        frames.push(frame);
        endpoints.push(endpoint);
    }
    assert_ne!(frames[0].connection, frames[1].connection);
    assert_ne!(frames[0].global_id, frames[1].global_id);
    for (frame, original) in frames.iter().zip(originals) {
        replies[&frame.connection]
            .send((remote, b"reply".to_vec()))
            .unwrap();
        assert_eq!(receive_reply(&client).await, (b"reply".to_vec(), original));
    }
    endpoints.clear();
    assert!(pool.shutdown().await.joined);
    generation.shutdown().await;
    wire_task.abort();
    let _ = wire_task.await;
}
