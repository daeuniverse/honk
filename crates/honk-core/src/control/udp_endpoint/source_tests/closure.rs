use super::*;
use crate::connection_tracker::{CloseOutcome, ConnectionTracker};
use crate::control::udp_endpoint::tests::closure::tracked_entry;
use crate::ebpf::{EbpfBackend, mock::MockEbpfBackend};

#[tokio::test(flavor = "current_thread")]
async fn close_source_view_drains_admitted_io_without_aborting_sibling() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (server, mut events, wire_task) = start_wire_peer().await;
        let node = vless_node(server);
        let generation =
            Arc::new(OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap());
        let runtime = generation.get(&node.id).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let raw_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let raw_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let target_a = raw_a.local_addr().unwrap();
        let target_b = raw_b.local_addr().unwrap();
        let pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
            4,
            Arc::new(SourceReplySocketFactory::new([raw_a, raw_b])),
        ));
        let stats = Arc::new(StatsManager::new());
        let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
        let tracker = Arc::new(ConnectionTracker::new());
        tracker.enable();
        let backend: Arc<tokio::sync::RwLock<Box<dyn EbpfBackend>>> =
            Arc::new(tokio::sync::RwLock::new(Box::new(MockEbpfBackend::new())));
        let (fatal, mut failures) = mpsc::unbounded_channel();
        let worker = crate::control::udp_removal::spawn_udp_removal_worker(
            Arc::clone(&pool),
            backend,
            Arc::clone(&tracker),
            fatal,
        );
        let attach = async |target| {
            pool.prepare_vless_source(
                Arc::clone(&generation),
                Arc::clone(&runtime),
                client_addr,
                VlessUdpPath::Xudp,
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
            .unwrap()
        };
        let lease_a = reserve_source(&pool, &stats, client_addr, target_a, node.id);
        let attachment_a = attach(target_a).await;
        let owner = attachment_a.owner();
        let identity_a = (lease_a.decision_token(), lease_a.generation());
        let endpoint_a = install_source(&pool, lease_a, attachment_a, target_a, &stats, node.id);
        let lease_b = reserve_source(&pool, &stats, client_addr, target_b, node.id);
        let attachment_b = attach(target_b).await;
        assert!(Arc::ptr_eq(&owner, &attachment_b.owner()));
        let endpoint_b = install_source(&pool, lease_b, attachment_b, target_b, &stats, node.id);
        let id = pool
            .register_ready_tracker(
                client_addr,
                target_a,
                identity_a.0,
                identity_a.1,
                &endpoint_a,
                &tracker,
                vec!["captured-group".into()],
                || tracked_entry("source-view", client_addr, target_a),
            )
            .unwrap()
            .unwrap();
        endpoint_a.send_packet(b"first", true).await.unwrap();
        let mut replies = HashMap::new();
        let first = next_data_frame(&mut events, &mut replies).await;
        let hook = Arc::new(source::ReplyAdmissionHook::default());
        *endpoint_a.source_reply_hook.lock() = Some(Arc::clone(&hook));
        replies[&first.connection]
            .send((target_a, b"admitted-reply".to_vec()))
            .unwrap();
        hook.entered.notified().await;

        let sending = Arc::clone(&endpoint_a);
        let mut admitted_send =
            Box::pin(async move { sending.send_packet(b"admitted-send", false).await });
        assert!(futures::poll!(&mut admitted_send).is_pending());
        let selected = tracker
            .snapshot_group("captured-group", Some("udp"))
            .pop()
            .unwrap();
        let close = tracker.start_close(selected);
        drop(endpoint_a);
        let mut duplicate = Box::pin(tracker.close_id(&id));
        assert!(futures::poll!(&mut duplicate).is_pending());
        admitted_send.await.unwrap();
        let frame = next_data_frame(&mut events, &mut replies).await;
        assert_eq!(frame.connection, first.connection);
        assert_eq!(frame.payload.as_deref(), Some(b"admitted-send".as_slice()));
        let mut close = Box::pin(close.wait());
        assert!(futures::poll!(&mut close).is_pending());
        hook.release.notify_one();
        assert_eq!(
            receive_reply(&client).await,
            (b"admitted-reply".to_vec(), target_a)
        );
        assert_eq!(close.await, CloseOutcome::Closed);
        assert_eq!(duplicate.await, CloseOutcome::Closed);
        assert!(matches!(
            pool.classify_source_reply(&owner, target_a),
            SourceReplyTarget::Drop
        ));
        replies[&first.connection]
            .send((target_a, b"late-closed-view".to_vec()))
            .unwrap();
        assert_no_reply(&client).await;

        endpoint_b.send_packet(b"sibling", false).await.unwrap();
        let sibling = next_data_frame(&mut events, &mut replies).await;
        assert_eq!(
            (sibling.connection, sibling.target),
            (first.connection, Some(target_b))
        );
        replies[&first.connection]
            .send((target_b, b"sibling-reply".to_vec()))
            .unwrap();
        assert_eq!(
            receive_reply(&client).await,
            (b"sibling-reply".to_vec(), target_b)
        );

        let replacement_lease = reserve_source(&pool, &stats, client_addr, target_a, node.id);
        let replacement_attachment = attach(target_a).await;
        assert!(Arc::ptr_eq(&owner, &replacement_attachment.owner()));
        let replacement = install_source(
            &pool,
            replacement_lease,
            replacement_attachment,
            target_a,
            &stats,
            node.id,
        );
        assert!(!pool.close_exact(client_addr, target_a, identity_a.0, identity_a.1));
        replacement
            .send_packet(b"replacement", false)
            .await
            .unwrap();
        let new_frame = next_data_frame(&mut events, &mut replies).await;
        assert_eq!(new_frame.connection, first.connection);
        replies[&first.connection]
            .send((target_a, b"replacement-reply".to_vec()))
            .unwrap();
        assert_eq!(
            receive_reply(&client).await,
            (b"replacement-reply".to_vec(), target_a)
        );
        drop(replacement);
        drop(endpoint_b);
        assert!(pool.shutdown().await.joined);
        assert!(failures.try_recv().is_err());
        worker.await.unwrap();
        drop(owner);
        generation.shutdown().await;
        wire_task.abort();
        let _ = wire_task.await;
    })
    .await
    .unwrap();
}
