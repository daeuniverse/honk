use super::*;

#[cfg(feature = "ebpf")]
impl ControlPlane {
    pub(crate) fn native_projection_for_test(
        &self,
    ) -> Arc<crate::dns::projection::RoutingProjection> {
        self.dns_controller.routing_projection()
    }
}

#[cfg(feature = "ebpf")]
impl PacketEndpoints {
    pub(crate) fn hold_native_source_for_test(
        &self,
        scope: ScopeId,
        address: std::net::IpAddr,
    ) -> io::Result<impl Drop + use<>> {
        self.shared
            .scopes
            .iter()
            .find(|owned| owned.scope() == scope)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "source fixture scope is not owned")
            })?
            .hold_source(address)
    }
}

#[tokio::test]
async fn controller_dns_claim_retains_its_actual_source_work() {
    let budget = MemoryBudget::new(32 << 20);
    let (scope, scope_owner) = scope(&budget);
    let (plane, _health) = local_plane().await;
    let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1)
        .await
        .unwrap();
    let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.9:53".parse().unwrap();
    assert!(!endpoints.retains(scope.scope(), source, destination, 17));
    let work = scope.hold_source(source.ip()).unwrap();
    assert!(endpoints.retains(scope.scope(), source, destination, 17));
    assert!(!endpoints.retained_transport(scope.scope(), source, destination, 17));
    let unrelated = SocketAddr::new(source.ip(), source.port() + 1);
    assert!(endpoints.retains(scope.scope(), unrelated, destination, 17));
    assert!(!endpoints.retained_transport(scope.scope(), unrelated, destination, 17));
    assert!(!endpoints.retained_transport(scope.scope(), source, destination, 6));
    assert!(!endpoints.retains(
        scope.scope(),
        source,
        SocketAddr::new(destination.ip(), 54),
        17
    ));
    drop(work);
    assert!(!endpoints.retains(scope.scope(), source, destination, 17));
    endpoints.shutdown().await.unwrap();
    owner.run().await.unwrap();
}

#[tokio::test]
async fn source_receipts_preserve_udp_queue_pressure_and_reject_unowned_scopes() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (plane, _health) = local_plane().await;
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1)
            .await
            .unwrap();
        let permits: Vec<_> = (0..INGRESS_CAPACITY)
            .map(|_| endpoints.sender.try_reserve().unwrap())
            .collect();
        let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.9:443".parse().unwrap();
        let expected = ValidatedSource {
            src: source,
            dst: destination,
            protocol: wire::PROTO_UDP,
            tcp_flags: None,
        };
        let mut packet = [0; 128];
        let length =
            wire::udp::emit_packet(&mut packet, source, destination, b"source-before-work")
                .unwrap();
        let now = Instant::now();
        let mut observed = Vec::new();
        let error = endpoints
            .receive_with_source(scope.scope(), &packet[..length], now, false, |source, _| {
                observed.push(source);
                true
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(
            observed,
            vec![expected],
            "a receipt is validity, not UDP queue admission"
        );
        assert_eq!(
            endpoints
                .receive(scope.scope(), &packet[..length], now)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            endpoints
                .receive_with_source(scope.scope(), &packet[..length], now, false, |_, _| false)
                .unwrap(),
            PacketReceive {
                source: Some(expected),
                source_context: None,
                taken_over: false,
                qualified_rx: false
            }
        );
        assert_eq!(
            endpoints.sender.capacity(),
            0,
            "source refusal must not consume reserved work slots"
        );
        packet[length - 1] ^= 1;
        assert_eq!(
            endpoints
                .receive_with_source(scope.scope(), &packet[..length], now, false, |_, _| panic!(
                    "bad checksum reported a source"
                ))
                .unwrap(),
            PacketReceive::default()
        );
        let foreign = ScopeId::allocate().unwrap();
        assert_eq!(
            endpoints
                .receive_with_source(foreign, &packet[..length], now, false, |_, _| panic!(
                    "unowned scope reached the parser"
                ))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        endpoints.close();
        drop(permits);
        assert!(
            endpoints.capture_ready().is_err(),
            "capture readiness must not reopen closing admission"
        );
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("source receipt pressure fixture must join");
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn observed_routing_admission_funds_its_real_route_and_transfers_the_charge() {
    let (mut plane, _health) = local_plane().await;
    let _native = crate::native_api::observation::NativeObservation::attach(&mut plane).await;
    let handle = plane.spawn_handle();
    let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.9:443".parse().unwrap();
    let budget = MemoryBudget::new(1 << 20);
    let scope = ScopeId::allocate().unwrap();
    let plain = handle
        .prepare_packet_routing_snapshot(scope, source, destination, "tcp", 0, None, false)
        .await
        .unwrap();
    let plain = EndpointAdmission::new(plain, &budget).unwrap();
    let plain_bytes = budget.used();
    drop(plain);
    assert_eq!(budget.used(), 0);
    let observed = handle
        .prepare_packet_routing_snapshot(scope, source, destination, "tcp", 0, None, true)
        .await
        .unwrap();
    let insufficient = MemoryBudget::new(plain_bytes);
    let error = EndpointAdmission::new(observed, &insufficient).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(insufficient.used(), 0);
    let observed = handle
        .prepare_packet_routing_snapshot(scope, source, destination, "tcp", 0, None, true)
        .await
        .unwrap();
    let admission = EndpointAdmission::new(observed, &budget).unwrap();
    let charged = budget.used();
    assert!(charged > plain_bytes);
    let snapshot = admission.into_snapshot();
    assert_eq!(budget.used(), charged);
    drop(snapshot);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn udp_qualification_requires_ready_enqueue_not_pending_or_refused_work() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = upstream.local_addr().unwrap();
        let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (plane, _health) = local_plane().await;
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1)
            .await
            .unwrap();
        let owner = tokio::spawn(owner.run());
        let mut packet = [0; 128];
        let length = wire::udp::emit_packet(&mut packet, source, destination, b"pending").unwrap();
        let receive = |bytes: &[u8]| {
            endpoints
                .receive_with_source(scope.scope(), bytes, Instant::now(), false, |_, _| true)
                .unwrap()
        };
        let slow = Arc::clone(&endpoints.shared.udp_slots)
            .try_acquire_many_owned(endpoints.shared.udp_slots.available_permits() as u32)
            .unwrap();
        let refused = receive(&packet[..length]);
        assert!(refused.source.is_some());
        assert!(
            !refused.qualified_rx,
            "missing slow permit is successful no-op, not admission"
        );
        assert!(
            !refused.taken_over,
            "slow-path refusal cannot transfer ownership"
        );
        drop(slow);
        let initializing = receive(&packet[..length]);
        assert!(
            !initializing.qualified_rx,
            "new initializer has unknown policy"
        );
        assert!(
            initializing.taken_over,
            "actual initializer owns the first datagram"
        );
        let queued = receive(&packet[..length]);
        assert!(!queued.qualified_rx, "Initializing enqueue is not Ready");
        assert!(
            queued.taken_over,
            "initializing owner accepted the queued datagram"
        );
        let mut bytes = [0; 128];
        for _ in 0..2 {
            let (n, _) = upstream.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..n], b"pending");
        }
        let length = wire::udp::emit_packet(&mut packet, source, destination, &[]).unwrap();
        let slow = Arc::clone(&endpoints.shared.udp_slots)
            .try_acquire_many_owned(endpoints.shared.udp_slots.available_permits() as u32)
            .unwrap();
        let ready = receive(&packet[..length]);
        assert!(
            ready.qualified_rx,
            "Ready zero-length UDP needs no slow permit"
        );
        assert!(ready.taken_over, "Ready enqueue owns zero-length UDP");
        assert_eq!(upstream.recv_from(&mut bytes).await.unwrap().0, 0);
        let mut aggregate = [0; 128];
        let split_len =
            wire::udp::emit_packet(&mut aggregate, source, destination, b"abcDEFx").unwrap();
        let meta = RxMeta {
            csum: honk_netstack::Csum::Partial {
                start: 20,
                offset: 6,
            },
            gso: Some(honk_netstack::GsoRx {
                kind: honk_netstack::GsoKind::UdpL4,
                size: 3,
            }),
        };
        let exhausted = budget.reserve(budget.limit() - budget.used()).unwrap();
        let error = endpoints
            .receive_with_meta_source(
                scope.scope(),
                &aggregate[..split_len],
                meta,
                Instant::now(),
                false,
                |_, _| true,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        drop(exhausted);
        let before_split = budget.used();
        let received = endpoints
            .receive_with_meta_source(
                scope.scope(),
                &aggregate[..split_len],
                meta,
                Instant::now(),
                false,
                |_, _| true,
            )
            .unwrap();
        assert!(received.source.is_some());
        assert!(
            received.qualified_rx,
            "every split chunk reaches the Ready owner"
        );
        assert!(
            received.taken_over,
            "Ready owner accepted the split datagrams"
        );
        assert!(
            budget.used() > before_split,
            "all copied datagrams are funded"
        );
        aggregate.fill(0);
        for expected in [b"abc".as_slice(), b"DEF", b"x"] {
            let (n, _) = upstream.recv_from(&mut bytes).await.unwrap();
            assert_eq!(
                &bytes[..n],
                expected,
                "RX reuse cannot change queued chunks"
            );
        }
        let mut enqueued = 0;
        for _ in 0..65 {
            let received = receive(&packet[..length]);
            if !received.qualified_rx {
                assert!(
                    !received.taken_over,
                    "full Ready queue did not accept the datagram"
                );
                break;
            }
            assert!(
                received.taken_over,
                "qualified Ready enqueue must own the datagram"
            );
            enqueued += 1;
        }
        assert_eq!(
            enqueued, 64,
            "Some(QueueFull) must not qualify a refused datagram"
        );
        drop(slow);
        let dns: SocketAddr = "198.51.100.1:53".parse().unwrap();
        let length = wire::udp::emit_packet(&mut packet, source, dns, b"unknown-query").unwrap();
        let dns_receive = receive(&packet[..length]);
        assert!(
            !dns_receive.qualified_rx,
            "controller DNS remains per-query unknown"
        );
        assert!(
            dns_receive.taken_over,
            "actual DNS queue owns the query before policy completion"
        );
        endpoints.close();
        assert_eq!(receive(&packet[..length]), PacketReceive::default());
        assert_eq!(
            endpoints
                .queue_datagram(&scope, source, dns, 0, None, None, |budget| {
                    FundedDatagram::copy_from(&[], budget)
                })
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        endpoints.shutdown().await.unwrap();
        owner.await.unwrap().unwrap();
    })
    .await
    .expect("qualification fixture must join real UDP owners");
}

#[tokio::test]
async fn host_udp_keeps_original_reply_facts_across_snapshot_changes_and_tuple_aliases() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let budget = MemoryBudget::new(64 << 20);
        let (scope, scope_owner) = scope(&budget);
        scope.prepare_host().unwrap();
        let (plane, _health) = local_plane().await;
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 2)
            .await
            .unwrap();
        let owner = tokio::spawn(owner.run());
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = upstream.local_addr().unwrap();
        let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let facts = HostSourceFacts {
            netns_cookie: 1,
            attachment: 2,
            socket_cookie: 31,
            return_generation: 3,
            output_ifindex: 4,
            skb_mark: 7,
            socket_mark: 0,
            pid: 0,
            pname: [0; 16],
            flags: 1,
            stage: honk_ebpf_common::host::HOST_STAGE_TUN_EGRESS,
            family: libc::AF_INET as u16,
            operation_incarnation: 1,
        };
        let mut current = facts;
        let mut packet = [0; 128];
        let mut received = [0; 128];
        let mut contexts = Vec::new();
        let mut peers = Vec::new();
        for payload in [b"first".as_slice(), b"changed", b"other"] {
            if payload == b"changed" {
                current.skb_mark = 8;
            }
            if payload == b"other" {
                current.socket_cookie = 32;
            }
            let ingress = HostIngress {
                facts: current,
                source_horizon: Instant::now() + Duration::from_secs(10),
            };
            let length = wire::udp::emit_packet(&mut packet, source, target, payload).unwrap();
            // TUN's owned vnet producer supplies Partial; VERIFY would drop this seed.
            let meta = if payload == b"first" {
                let ip = wire::parse_ip(&packet[..length]).unwrap();
                let start = ip.payload.start;
                let seed = !wire::checksum::Checksum::pseudo(
                    source.ip(),
                    target.ip(),
                    wire::PROTO_UDP,
                    length - start,
                )
                .finish();
                packet[start + 6..start + 8].copy_from_slice(&seed.to_be_bytes());
                honk_netstack::RxMeta {
                    csum: honk_netstack::Csum::Partial {
                        start: start as u16,
                        offset: 6,
                    },
                    gso: None,
                }
            } else {
                honk_netstack::RxMeta::VERIFY
            };
            let report = endpoints
                .receive_host_with_source(
                    scope.scope(),
                    &packet[..length],
                    meta,
                    Instant::now(),
                    &ingress,
                    None,
                    false,
                    |validated, context, captured, _| {
                        assert_eq!((validated.src, validated.dst), (source, target));
                        assert_eq!(*captured, current);
                        contexts.push(context);
                        true
                    },
                )
                .unwrap();
            assert_eq!(report.source_context, contexts.last().copied());
            assert_eq!(report.qualified_rx, payload == b"changed");
            let (length, peer) = upstream.recv_from(&mut received).await.unwrap();
            assert_eq!(&received[..length], payload);
            peers.push(peer);
        }
        assert_eq!(contexts[0].lineage, contexts[1].lineage);
        assert_ne!(contexts[0].snapshot, contexts[1].snapshot);
        assert_ne!(contexts[0].lineage, contexts[2].lineage);
        assert_eq!(peers[0], peers[1]);
        assert_ne!(peers[0], peers[2]);
        assert!(!endpoints.retains(scope.scope(), source, target, 17));
        for index in [0, 2] {
            assert!(endpoints.retains_with_lineage(
                scope.scope(),
                source,
                target,
                17,
                Some(contexts[index].lineage)
            ));
            upstream.send_to(b"reply", peers[index]).await.unwrap();
            let output = scope.next_output().await.unwrap();
            assert_eq!(output.transmit().source, Some(contexts[index]));
            let expected = if index == 0 { facts } else { current };
            assert_eq!(output.host_return(), Some(expected));
            let ip = wire::parse_ip(output.packet()).unwrap();
            let udp = &output.packet()[ip.payload];
            assert!(wire::udp::verify_checksum(ip.src, ip.dst, udp));
            let (_, _, payload) = wire::udp::parse(udp).unwrap();
            assert_eq!(&udp[payload], b"reply");
        }
        let expired = HostIngress {
            facts,
            source_horizon: Instant::now() - Duration::from_secs(1),
        };
        let length = wire::udp::emit_packet(&mut packet, source, target, b"expired").unwrap();
        assert!(
            endpoints
                .receive_host_with_source(
                    scope.scope(),
                    &packet[..length],
                    honk_netstack::RxMeta::VERIFY,
                    Instant::now(),
                    &expired,
                    None,
                    false,
                    |_, _, _, _| panic!("expired Host capture reached the source gate")
                )
                .is_err()
        );
        endpoints.shutdown().await.unwrap();
        owner.await.unwrap().unwrap();
    })
    .await
    .expect("Host UDP owners and replies must join");
}

#[tokio::test]
async fn host_dns_rejects_routing_captured_before_source_cell_reuse() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let budget = MemoryBudget::new(64 << 20);
        let (scope, scope_owner) = scope(&budget);
        scope.prepare_host().unwrap();
        let (plane, _health) = local_plane().await;
        let handle = plane.spawn_handle();
        let source = "192.0.2.10:41000".parse().unwrap();
        let destination = "198.51.100.9:53".parse().unwrap();
        let facts = HostSourceFacts {
            netns_cookie: 1,
            attachment: 2,
            socket_cookie: 31,
            return_generation: 3,
            output_ifindex: 4,
            skb_mark: 0,
            socket_mark: 0,
            pid: 0,
            pname: [0; 16],
            flags: 1,
            stage: 1,
            family: libc::AF_INET as u16,
            operation_incarnation: 1,
        };
        let original = scope.hold_host_source(&facts).unwrap();
        let context = original.context();
        let snapshot = handle
            .prepare_packet_routing_snapshot(
                scope.scope(),
                source,
                destination,
                "udp",
                0,
                Some(&original),
                #[cfg(feature = "native-api")]
                false,
            )
            .await
            .unwrap();
        let admission = EndpointAdmission::new(snapshot, &budget).unwrap();
        drop(original);
        let mut pressure: Vec<_> = (0..8 + 2 + 2)
            .map(|offset| {
                scope
                    .hold_host_source(&HostSourceFacts {
                        socket_cookie: 100 + offset,
                        ..facts
                    })
                    .unwrap()
            })
            .collect();
        drop(pressure.pop());
        let replacement = scope.hold_host_source(&facts).unwrap();
        assert_ne!(replacement.context(), context);
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 2)
            .await
            .unwrap();
        let owner = tokio::spawn(owner.run());
        let query = crate::control::tests::support::dns_query_payload();
        let result = endpoints.queue_datagram(
            &scope,
            source,
            destination,
            0,
            Some(admission),
            Some(PacketSource::Captured {
                context,
                facts: &facts,
            }),
            |budget| FundedDatagram::copy_from(&query, budget),
        );
        drop((replacement, pressure));
        endpoints.close();
        owner.await.unwrap().unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    })
    .await
    .expect("rejected DNS source handoff must join");
}

#[cfg(feature = "ebpf")]
#[tokio::test]
async fn native_source_work_excludes_same_ip_new_port_from_original_return() {
    use crate::control::core_forward::CapturedDecision;
    use crate::ebpf::native::{
        ImportedOriginal, NativeClaimIdentity, NativeOriginal, OriginalExtent,
    };
    use honk_datapath::forward::{Ingress, MarkProvenance, RouteQuery};
    use honk_ebpf_common::xdp::*;

    let budget = MemoryBudget::new(32 << 20);
    let (scope, scope_owner) = scope(&budget);
    let (mut plane, _health) = local_plane_with(|config| {
        config.datapath = Some(honk_config::datapath::DatapathConfig {
            backend: honk_config::datapath::Backend::Xdp,
            direct: Some(honk_config::datapath::DirectProfile::Native),
            interfaces: vec![honk_config::datapath::XdpInterface {
                name: "dut0".into(),
                role: honk_config::datapath::InterfaceRole::Lan,
            }],
            ..Default::default()
        });
        config.routing.default_outbound = "direct".into();
        config.routing.default_must = true;
        config.global.nfqueue_enable = false;
    })
    .await;
    plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("Rule", "direct"),
    )));
    plane.start_datapath_flags_coordinator().unwrap();
    let authority = plane.native_packet_policy().await.unwrap();
    let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1)
        .await
        .unwrap();
    let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
    let fresh = SocketAddr::new(source.ip(), source.port() + 1);
    let destination: SocketAddr = "198.51.100.9:53".parse().unwrap();
    let ingress = Ingress {
        scope: scope.scope(),
        namespace: 1,
        ifindex: 2,
        attachment: 1,
        mark: MarkProvenance::BeforeSkb,
    };
    let imported = ImportedOriginal {
        identity: NativeClaimIdentity {
            key: NativeKey {
                src_ip: crate::ebpf::maps::ip_addr_to_lpm_key(fresh.ip()).data,
                dst_ip: crate::ebpf::maps::ip_addr_to_lpm_key(destination.ip()).data,
                src_port: fresh.port().to_be(),
                dst_port: destination.port().to_be(),
                l4proto: 17,
                ip_version: 4,
                domain: 0,
                direction: 0,
                namespace_cookie: 1,
                zone: 0,
                zone_state: 2,
                reserved: [0; 5],
            },
            epoch: 3,
            incarnation: 3,
            scope: scope.scope().as_u64(),
        },
        producer: NativeImport {
            epoch: 3,
            incarnation: 3,
            expires_boottime_ns: u64::MAX,
            flags: NATIVE_IMPORT_COUNTED,
            reserved: 0,
        },
        executor: NATIVE_EXECUTOR_PENDING,
        state: NATIVE_PHASE_PENDING | 16,
    };
    let classify = || {
        let original = NativeOriginal {
            imported: &imported,
            authority: CaptureAuthority {
                namespace_cookie: 1,
                attachment_generation: 1,
                scope: scope.scope().as_u64(),
                config_generation: 1,
                ifindex: 2,
                reserved: 0,
            },
            ingress,
            facts: scope.scope(),
            realm_index: 0,
            rx_queue: 0,
            extent: OriginalExtent {
                frame_length: 60,
                l3_offset: 14,
                l3_length: 28,
                vlan_tci: [0; 2],
                vlan_proto: [0; 2],
                vlan_count: 0,
                inline_vlan_count: 0,
                dscp: 0,
            },
            basis_epoch: 3,
            basis_flags: 0,
            candidate: 1,
            retained_capture: endpoints.retains(scope.scope(), fresh, destination, 17),
        };
        authority
            .capture_original(
                &authority.try_read_policy().unwrap(),
                RouteQuery {
                    ingress,
                    source: fresh.ip(),
                    destination: destination.ip(),
                    traffic_class: 0,
                    protocol: 17,
                    ports: Some((fresh.port(), destination.port())),
                },
                scope.scope(),
                &original,
                &budget,
            )
            .unwrap()
    };
    assert!(matches!(classify(), CapturedDecision::TryNativeOriginal(_)));
    let work = scope.hold_source(source.ip()).unwrap();
    assert!(endpoints.retains(scope.scope(), fresh, destination, 17));
    assert!(!endpoints.retained_transport(scope.scope(), fresh, destination, 17));
    assert!(
        matches!(classify(), CapturedDecision::Endpoint(_)),
        "actual source-wide work excludes a new port from Native return"
    );
    drop(work);
    assert!(!endpoints.retains(scope.scope(), fresh, destination, 17));
    assert!(matches!(classify(), CapturedDecision::TryNativeOriginal(_)));
    endpoints.shutdown().await.unwrap();
    owner.run().await.unwrap();
}
