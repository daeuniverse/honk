use super::*;

#[tokio::test]
async fn composed_source_installation_drops_a_second_prepared_carrier() {
    use honk_outbound::ProxyRegistry;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn accept_association(listener: &TcpListener) -> TcpStream {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        let mut connect = [0; 10];
        stream.read_exact(&mut connect).await.unwrap();
        assert_eq!(connect, [5, 1, 0, 1, 192, 0, 2, 1, 1, 187]);
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut associate = [0; 68];
        stream.read_exact(&mut associate).await.unwrap();
        assert_eq!(associate[58], 3);
        stream
    }

    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = Node::from_share_link(&format!(
            "socks5://{}#front",
            listener.local_addr().unwrap(),
        ))
        .unwrap();
        let mut exit = Node::from_share_link("trojan://secret@192.0.2.1:443#exit").unwrap();
        exit.trojan_mut().unwrap().tls.enabled = false;
        exit.id = exit.derive_id();
        let chain = Node::chain_from_nodes("via", &[&front, &exit]).unwrap();
        let id = chain.id;
        let generation = Arc::new(OutboundRuntimeRegistry::build(&[chain, front, exit]).unwrap());
        let runtime = generation.get(&id).unwrap();
        let pool = Arc::new(UdpEndpointPool::with_capacity_limit(2));
        let proxy = ProxyRegistry::default_resolver().unwrap();
        let alive = Arc::new(AliveDialerSet::new());
        let stats = Arc::new(StatsManager::new());
        let prepare = |port| {
            pool.prepare_source(
                &proxy,
                Arc::clone(&generation),
                Arc::clone(&runtime),
                "127.0.0.1:12345".parse().unwrap(),
                SourcePath::Shared,
                None,
                SocketAddr::from(([192, 0, 2, 2], port)),
                None,
                TEST_TIMEOUT,
                Arc::clone(&alive),
                Arc::clone(&stats),
                IpVersion::V4,
                true,
            )
        };
        let (a, mut wire_a) = tokio::join!(prepare(53), accept_association(&listener));
        let (b, mut wire_b) = tokio::join!(prepare(54), accept_association(&listener));
        let a = a.unwrap();
        let b = b.unwrap();
        assert!(matches!(&a, SourcePreparation::Fresh { .. }));
        assert!(matches!(&b, SourcePreparation::Fresh { .. }));
        assert_eq!(pool.source_slots.available_permits(), 0);

        let SourcePreparation::Fresh {
            scope,
            prepared: PreparedSourceTransport::Shared(prepared),
            source_permit,
            runtime,
            alive_set,
            stats,
            node_id,
            node_name,
            health_family,
            evidence,
        } = b
        else {
            panic!("expected a fresh composed source");
        };
        let (enter, entered) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let b = SourcePreparation::Fresh {
            scope,
            prepared: PreparedSourceTransport::Shared(PreparedUdpTransport::new(async move {
                let transport = prepared.commit().await?;
                enter.send(()).unwrap();
                released.await.unwrap();
                Ok(transport)
            })),
            source_permit,
            runtime,
            alive_set,
            stats,
            node_id,
            node_name,
            health_family,
            evidence,
        };
        let (a, b) = tokio::join!(
            async {
                entered.await.unwrap();
                let winner = a.commit(&pool).await.unwrap();
                release.send(()).unwrap();
                winner
            },
            b.commit(&pool)
        );
        let b = b.unwrap();
        assert!(Arc::ptr_eq(&a.owner(), &b.owner()));
        assert_eq!(pool.sources.len(), 1);
        assert_eq!(pool.source_slots.available_permits(), 1);
        assert_eq!(
            wire_b.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof,
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), wire_a.read_u8())
                .await
                .is_err()
        );
        drop((a, b));
        assert!(pool.shutdown().await.joined);
        assert_eq!(pool.source_slots.available_permits(), 2);
        assert_eq!(
            wire_a.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof,
        );
        generation.shutdown().await;
    })
    .await
    .expect("both preparations must settle around one source owner");
}

#[tokio::test]
async fn collapsed_first_datagram_uses_the_selecting_view_until_admission() {
    use crate::control::reload::resolve_group_outbound_plan_for_target;
    use honk_outbound::group::{ExitCollapse, SelectorNetworks};
    use honk_outbound::proxy::{PacketRejection, packet_rejection};

    let fixture = Fixture::new(false, 4).await;
    let sibling = fixture.flow(0, b"bare sibling").await;
    let direct = honk_config::Config::builtin_direct_node();
    let block = honk_config::Config::builtin_block_node();
    let cases = [
        (fixture.node.clone(), ExitCollapse::Member),
        #[cfg(feature = "rprx")]
        (
            Node::from_share_link("vless://b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3@127.0.0.1:2443?security=none&packetEncoding=none#exit").unwrap(),
            ExitCollapse::Direct,
        ),
    ];
    for (exit, collapse) in cases {
        let selected = if collapse == ExitCollapse::Member {
            &exit
        } else {
            &direct
        };
        let nodes = [exit.clone(), direct.clone(), block.clone()];
        let group = honk_config::group::Group {
            name: "g".into(),
            nodes: vec![selected.id, block.id],
            exit: Some(exit.name.clone()),
            ..Default::default()
        };
        let manager = Arc::new(GroupManager::with_alive_set(
            &[group],
            &nodes,
            Some(Arc::clone(&fixture.alive)),
        ));
        manager.publish_route_health();
        let generation = if collapse == ExitCollapse::Member {
            Arc::clone(&fixture.generation)
        } else {
            Arc::new(OutboundRuntimeRegistry::build(&nodes).unwrap())
        };
        let target = fixture.target(1);
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Udp,
            ProbeDomain::DataUdp,
            fixture.family,
        );
        for withdraw in [true, false] {
            manager
                .set_selector_choice("g", &selected.name, SelectorNetworks::Udp)
                .unwrap();
            let plan = resolve_group_outbound_plan_for_target(&manager, "g", &context);
            assert_eq!(plan.targets[0].collapse, collapse);
            let evidence = UdpTrafficEvidence::capture_route(
                &manager,
                &generation,
                &plan.targets[0],
                &plan.selection_chains[0],
                &plan.final_owners[0],
                plan.route_revision,
                plan.health_family,
            )
            .unwrap();
            let (mut endpoint, wire) = if collapse == ExitCollapse::Member {
                let attachment = fixture.attach(fixture.client(), target, None).await;
                let endpoint = UdpEndpoint::new_source_scored(
                    attachment,
                    target,
                    None,
                    Arc::new(fixture.pool.create_reply_socket(target).unwrap()),
                    fixture
                        .stats
                        .outbound_tracker(&exit.name, crate::stats::OutboundKind::Node),
                    exit.id,
                    fixture.family,
                    None,
                );
                let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
                assert!(endpoint.commit_source_binding(permit));
                (endpoint, fixture.transport())
            } else {
                let wire = MemoryTransport::new(&fixture.live);
                (
                    UdpEndpoint::new(wire.clone(), wire.relay_addr(), exit.id),
                    wire,
                )
            };
            endpoint.set_traffic_evidence(Some(Arc::new(evidence)));
            let before = wire.sent();
            let held = wire.first_send_credit.acquire().await.unwrap();
            let mut send = std::pin::pin!(endpoint.send_packet(b"first", true));
            assert!(futures::poll!(send.as_mut()).is_pending());
            if withdraw {
                manager
                    .set_selector_choice("g", "block", SelectorNetworks::Udp)
                    .unwrap();
            }
            drop(held);
            if withdraw {
                assert_eq!(
                    packet_rejection(&send.await.unwrap_err().into()),
                    Some(PacketRejection::Cancelled)
                );
                assert_eq!(wire.sent(), before);
            } else {
                send.await.unwrap();
                let sent = wire.sent();
                assert_eq!(&sent[..before.len()], before.as_slice());
                assert_eq!(
                    &sent[before.len()..],
                    &[Sent {
                        target: endpoint.relay_addr,
                        domain: None,
                        data: b"first".to_vec(),
                        confirmed: true
                    }]
                );
            }
        }
        if collapse == ExitCollapse::Direct {
            generation.shutdown().await;
        }
    }
    sibling.send_packet(b"still usable", false).await.unwrap();
    assert_eq!(
        fixture.transport().sent().last().unwrap().data,
        b"still usable"
    );
    drop(sibling);
    fixture.shutdown().await;
}
