use super::*;

#[cfg(all(feature = "native-api", feature = "clash-api", target_os = "linux"))]
mod fatal;

async fn xdp_plane(mode: &str, selection: &str) -> (ControlPlane, tokio::net::TcpListener) {
    xdp_plane_with(mode, selection, |_| {}).await
}

async fn xdp_plane_with(
    mode: &str,
    selection: &str,
    configure: impl FnOnce(&mut honk_config::Config),
) -> (ControlPlane, tokio::net::TcpListener) {
    let (mut plane, health) = local_plane_with(|config| {
        config.global.nfqueue_enable = false;
        config.datapath = Some(honk_config::datapath::DatapathConfig {
            backend: honk_config::datapath::Backend::Xdp,
            direct: Some(honk_config::datapath::DirectProfile::Endpoint),
            interfaces: vec![honk_config::datapath::XdpInterface {
                name: "dut0".into(),
                role: honk_config::datapath::InterfaceRole::Lan,
            }],
            ..Default::default()
        });
        configure(config);
        config.validate_assembled().unwrap();
    })
    .await;
    plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new(mode, selection),
    )));
    plane.start_datapath_flags_coordinator().unwrap();
    (plane, health)
}

#[tokio::test]
async fn xdp_startup_initializes_exact_mode_flags_before_capture() {
    use honk_ebpf_common::{
        DATAPATH_FLAG_OFFLOAD_ALL as ALL, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as RULE,
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        for (mode, selection, expected) in [
            ("Rule", "block", RULE),
            ("Direct", "block", ALL),
            ("Global", "direct", ALL),
            ("Global", "block", 0),
        ] {
            let budget = MemoryBudget::new(32 << 20);
            let (scope, scope_owner) = scope(&budget);
            let (plane, _health) = xdp_plane(mode, selection).await;
            let backend = Arc::clone(&plane.ebpf);
            let flags = plane.datapath_flags_handle().unwrap();
            let restored = flags.snapshot();
            let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope, scope_owner)], 1)
                .await
                .unwrap();
            assert_eq!(backend.read().await.datapath_flags_write_log(), [expected]);
            flags.fence_nfqueue().await.unwrap();
            flags.reopen_nfqueue().await.unwrap();
            assert_eq!(flags.snapshot(), restored);
            assert_eq!(
                backend.read().await.datapath_flags_write_log(),
                [expected; 3]
            );
            endpoints.capture_ready().unwrap();
            endpoints.shutdown().await.unwrap();
            owner.run().await.unwrap();
        }
    })
    .await
    .expect("XDP startup must initialize software-only flags before capture");
}

#[tokio::test]
async fn xdp_flag_initialization_failure_retains_cleanup_until_output_returns() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (plane, _health) = xdp_plane("Direct", "block").await;
        let stopped = Arc::clone(&plane.shutdown_requested);
        let backend = Arc::clone(&plane.ebpf);
        let mut held_backend = backend.write().await;
        held_backend.arm_datapath_flags_write_fault(1).unwrap();
        let mut opening = Box::pin(PacketEndpoints::new(
            plane,
            vec![(scope.clone(), scope_owner)],
            1,
        ));
        assert!(futures::poll!(&mut opening).is_pending());
        scope
            .datagram_sender("198.51.100.1:53".parse().unwrap())
            .send_to(b"retained", "192.0.2.1:41000".parse().unwrap())
            .await
            .unwrap();
        let output = scope.next_output().await.unwrap();
        drop(held_backend);
        while !stopped.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        assert!(futures::poll!(&mut opening).is_pending());
        output.release();
        let error = opening
            .await
            .err()
            .expect("failed flags must reject startup");
        assert!(format!("{error:#}").contains("injected datapath flags write failure"));
        drop(scope);
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("failed XDP flags must retain joined packet cleanup");
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn cancelled_startup_never_activates_and_retains_exported_output() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for maintenance_waiting in [false, true] {
            let budget = MemoryBudget::new(32 << 20);
            let (scope, scope_owner) = scope(&budget);
            let (mut plane, _health) = local_plane().await;
            let native =
                crate::native_api::observation::NativeObservation::attach(&mut plane).await;
            let generation = plane.diagnostics.read().generation;
            let stopped = Arc::clone(&plane.shutdown_requested);
            let config = Arc::clone(&plane.config);
            let config_guard = if maintenance_waiting {
                None
            } else {
                Some(config.write().await)
            };
            let (entered, stage) = tokio::sync::oneshot::channel();
            let (release, released) = tokio::sync::oneshot::channel();
            if maintenance_waiting {
                scope.pause_startup(entered, released);
            }
            let mut opening = Box::pin(PacketEndpoints::new(
                plane,
                vec![(scope.clone(), scope_owner)],
                1,
            ));
            assert!(futures::poll!(&mut opening).is_pending());
            if maintenance_waiting {
                stage
                    .await
                    .expect("actual maintenance completed before the readiness checkpoint");
            }
            scope
                .datagram_sender("198.51.100.1:53".parse().unwrap())
                .send_to(b"retained", "192.0.2.1:41000".parse().unwrap())
                .await
                .unwrap();
            let output = scope.next_output().await.unwrap();
            drop(opening);
            drop(config_guard);
            let _ = release.send(());
            while !stopped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            assert!(native.core.activated_at(generation).is_none());
            assert!(output.packet().ends_with(b"retained"));
            output.release();
            assert!(scope.next_output().await.is_none());
            drop(scope);
            while budget.used() != 0 {
                tokio::task::yield_now().await;
            }
        }
    })
    .await
    .expect("cancelled startup must stay unactivated and finish owned cleanup");
}

#[tokio::test]
async fn elastic_tcp_admission_has_funded_task_slots_beyond_the_initial_floor() {
    use tokio::io::AsyncWriteExt;
    tokio::time::timeout(Duration::from_secs(10), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (mut plane, _health) = local_plane().await;
        plane.resource_budget.active_tcp_flows = 1;
        plane.concurrency_limit = Arc::new(tokio::sync::Semaphore::new(1));
        plane.tcp_admission_target.store(1, Ordering::Relaxed);
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1)
            .await
            .unwrap();
        let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (flow, _) = established_tcp(&scope, first.local_addr().unwrap()).await;
        let slot = Arc::clone(&endpoints.shared.tcp_slots)
            .acquire_owned()
            .await
            .unwrap();
        endpoints.sender.send(Work::Tcp(flow, slot)).await.unwrap();
        let (_first_peer, _) = first.accept().await.unwrap();
        let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (flow, _) = established_tcp(&scope, second.local_addr().unwrap()).await;
        let id = flow.flow_id();
        let slot = Arc::clone(&endpoints.shared.tcp_slots)
            .acquire_owned()
            .await
            .unwrap();
        endpoints.sender.send(Work::Tcp(flow, slot)).await.unwrap();
        let (mut peer, _) = second.accept().await.unwrap();
        peer.write_all(b"elastic").await.unwrap();
        loop {
            let output = scope.next_output().await.unwrap();
            let ip = wire::parse_ip(output.packet()).unwrap();
            let (_, offset) = wire::tcp::parse(&output.packet()[ip.payload.clone()]).unwrap();
            let payload = &output.packet()[ip.payload][offset..];
            if !payload.is_empty() {
                assert_eq!(output.flow_id(), Some(id));
                assert_eq!(payload, b"elastic");
                output.release();
                break;
            }
            output.release();
        }
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("elastic permits must admit real TCP work above the startup floor");
}

#[cfg(feature = "clash-api")]
#[tokio::test]
async fn normal_close_aborts_packet_protocol_before_waiting_for_selector_retirement() {
    use crate::control::{ControlCommand, client::ControlError, client::SelectionRequest};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_secs(10), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (plane, _health) = xdp_plane_with("Rule", "block", |config| {
            config.groups[0].interrupt_connections = true;
            config.routing.default_outbound = "packet-control".into();
        })
        .await;
        let commands = plane.command_sender();
        let tracker = Arc::clone(&plane.connection_tracker);
        tracker.enable();
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1)
            .await
            .unwrap();
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = upstream.local_addr().unwrap();
        let (flow, _) = established_tcp(&scope, destination).await;
        let source = flow.peer_addr();
        let permit = Arc::clone(&endpoints.shared.tcp_slots)
            .acquire_owned()
            .await
            .unwrap();
        endpoints
            .sender
            .send(Work::Tcp(flow, permit))
            .await
            .unwrap();
        let (mut server, _) = upstream.accept().await.unwrap();
        server.write_all(b"held selector output").await.unwrap();
        let output = loop {
            let output = scope.next_output().await.unwrap();
            if output.packet().ends_with(b"held selector output") {
                break output;
            }
            output.release();
        };
        let bytes = output.packet().to_vec();
        let late_permit = commands.clone().reserve_owned().await.unwrap();
        let (reply, selected) = tokio::sync::oneshot::channel();
        commands
            .send(ControlCommand::SetSelector {
                request: SelectionRequest::Name {
                    group: "packet-control".into(),
                    member: "block".into(),
                },
                reply,
            })
            .await
            .unwrap();
        assert_eq!(
            server.read(&mut [0; 1]).await.unwrap(),
            0,
            "the real selector interruption must close its loopback upstream"
        );
        let mut selected = Box::pin(selected);
        assert!(futures::poll!(&mut selected).is_pending());
        assert_eq!(tracker.snapshot().len(), 1);

        endpoints.close();
        commands.closed().await;
        let mut shutdown = Box::pin(endpoints.shutdown());
        let mut joined = Box::pin(owner.run());
        assert!(futures::poll!(&mut shutdown).is_pending());
        assert!(futures::poll!(&mut joined).is_pending());
        assert!(futures::poll!(&mut selected).is_pending());
        assert_eq!(tracker.snapshot().len(), 1);
        assert!(endpoints.retains(scope.scope(), source, destination, 6));
        assert_eq!(output.packet(), bytes);
        assert!(budget.used() > 0, "exported bytes must remain funded");

        output.release();
        let result = selected.await.unwrap().unwrap();
        #[cfg(feature = "native-api")]
        assert!(result.interrupted);
        #[cfg(not(feature = "native-api"))]
        let _ = result;
        assert!(tracker.snapshot().is_empty());
        assert!(futures::poll!(&mut shutdown).is_pending());
        assert!(futures::poll!(&mut joined).is_pending());
        let (reply, late_reply) = tokio::sync::oneshot::channel();
        late_permit.send(ControlCommand::SetSelector {
            request: SelectionRequest::Name {
                group: "packet-control".into(),
                member: "direct".into(),
            },
            reply,
        });
        assert!(matches!(
            late_reply.await.unwrap(),
            Err(ControlError::Unavailable)
        ));
        shutdown.await.unwrap();
        joined.await.unwrap();
        assert!(scope.next_output().await.is_none());
        drop(endpoints);
        drop(scope);
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("ordinary close must abort packet state and join without further peer ingress");
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn xdp_native_running_waits_for_actual_capture_activation() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (mut plane, _health) = xdp_plane("Rule", "block").await;
        *plane.ebpf.write().await = Box::new(crate::ebpf::userspace::UserspaceBackend::new(
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ));
        let mut phase = plane.observe_phase();
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope, scope_owner)], 1)
            .await
            .unwrap();
        assert_eq!(*phase.borrow(), super::super::super::EnginePhase::Starting);
        assert!(!endpoints.shared.capture_ready.load(Ordering::Acquire));
        endpoints.capture_ready().unwrap();
        while *phase.borrow() != super::super::super::EnginePhase::Running {
            phase.changed().await.unwrap();
        }
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("native Running must follow capture-ready notification");
}

#[tokio::test]
async fn xdp_reload_drains_queued_initializers_across_its_epoch_without_losing_other_work() {
    use crate::control::{ControlCommand, commands::ReloadOutcome};
    use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};

    tokio::time::timeout(Duration::from_secs(25), async {
        for cancel_reply in [false, true] {
            let budget = MemoryBudget::new(32 << 20);
            let (scope, scope_owner) = scope(&budget);
            let (plane, _health) = xdp_plane("Rule", "block").await;
            let config = Arc::clone(&plane.config);
            let commands = plane.command_sender();
            let mut candidate = (**config.read().await).clone();
            candidate.routing.rules.push(RoutingRule {
                name: "reload-dscp-block".into(),
                condition: RoutingCondition {
                    dscp: vec!["46".into()],
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple("block".into()),
                priority: 0,
                must: false,
                mark: 0,
            });
            let (endpoints, owner) =
                PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 4)
                    .await
                    .unwrap();
            let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (flow, _) = established_tcp(&scope, tcp.local_addr().unwrap()).await;
            let slot = Arc::clone(&endpoints.shared.tcp_slots)
                .acquire_owned()
                .await
                .unwrap();
            let output_scope = scope.clone();
            let (delivered, delivery) = tokio::sync::oneshot::channel();
            let adapter = tokio::spawn(async move {
                let mut delivered = Some(delivered);
                while let Some(output) = output_scope.next_output().await {
                    let ip = wire::parse_ip(output.packet()).unwrap();
                    let transport = &output.packet()[ip.payload.clone()];
                    match ip.proto {
                        wire::PROTO_TCP => {
                            assert!(wire::tcp::verify_checksum(ip.src, ip.dst, transport));
                            let (_, offset) = wire::tcp::parse(transport).unwrap();
                            if &transport[offset..] == b"post-reload output"
                                && let Some(delivered) = delivered.take()
                            {
                                let _ = delivered.send(());
                            }
                        }
                        wire::PROTO_UDP => {
                            assert!(wire::udp::verify_checksum(ip.src, ip.dst, transport))
                        }
                        _ => panic!("unexpected packet Endpoint output"),
                    }
                    output.release();
                }
            });
            let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let destination = upstream.local_addr().unwrap();
            let pool = &endpoints.shared.udp_pool;
            let epoch = pool.initialization_epoch();
            // Keep the real reload wait pending until a second lease crosses its epoch fence.
            let blocker = match pool.reserve_or_enqueue_at(
                scope.scope(),
                "192.0.2.10:41009".parse().unwrap(),
                destination,
                b"blocker",
                None,
                crate::ebpf::UdpFlowOwner::packet(),
                epoch,
                Arc::new(tokio::sync::Semaphore::new(1))
                    .try_acquire_owned()
                    .unwrap(),
                crate::control::udp_endpoint::queue_now(),
                &endpoints.shared.stats,
            ) {
                EndpointReservation::Initializing(lease) => lease,
                _ => panic!("expected a new UDP initializer reservation"),
            };
            let config_guard = config.write().await;
            let (result, applied) = tokio::sync::oneshot::channel();
            let mut applied = Some(applied);
            commands
                .send(ControlCommand::ReloadConfig {
                    request_id: 1,
                    config: Box::new(candidate),
                    diagnostics: Vec::new(),
                    #[cfg(feature = "native-api")]
                    sources: None,
                    #[cfg(feature = "native-api")]
                    expected_group_revision: None,
                    result,
                })
                .await
                .unwrap();
            while commands.capacity() != commands.max_capacity() {
                tokio::task::yield_now().await;
            }
            if cancel_reply {
                drop(applied.take());
            }
            let source = "192.0.2.10:41001".parse().unwrap();
            let late_source = "192.0.2.10:41002".parse().unwrap();
            let queue_initializer = |source| {
                endpoints
                    .queue_datagram(scope.scope(), source, destination, 0, None, |budget| {
                        FundedDatagram::copy_from(b"cancelled", budget)
                    })
                    .unwrap();
                assert!(endpoints.retains(scope.scope(), source, destination, 17));
            };
            queue_initializer(source);
            endpoints.sender.try_send(Work::Tcp(flow, slot)).unwrap();
            for payload in [b"first".as_slice(), b"second".as_slice()] {
                endpoints
                    .sender
                    .try_send(Work::Udp(Datagram {
                        scope: scope.scope(),
                        source: "192.0.2.10:41003".parse().unwrap(),
                        destination,
                        dscp: 0,
                        routing: None,
                        bytes: FundedDatagram::copy_from(payload, &budget).unwrap(),
                        source_work: scope.hold_source("192.0.2.10".parse().unwrap()).unwrap(),
                    }))
                    .unwrap();
            }
            let outcome = tokio::time::timeout(Duration::from_secs(3), async {
                drop(config_guard);
                while pool.initialization_epoch() == epoch {
                    tokio::task::yield_now().await;
                }
                queue_initializer(late_source);
                drop(blocker);
                match applied {
                    Some(applied) => Some(applied.await.unwrap().outcome),
                    None => {
                        while config.read().await.routing.rules.len() != 1 {
                            tokio::task::yield_now().await;
                        }
                        None
                    }
                }
            })
            .await
            .expect("reload must not wait for the five-second initializer timeout");
            if let Some(outcome) = outcome {
                assert!(
                    matches!(outcome, ReloadOutcome::Committed { .. }),
                    "{outcome:?}"
                );
            }
            assert_eq!(config.read().await.routing.rules.len(), 1);
            assert_eq!(endpoints.shared.stats.udp_snapshot().slow_permit_closed, 2);
            for source in [source, late_source] {
                assert!(!endpoints.retains(scope.scope(), source, destination, 17));
            }
            if cancel_reply {
                // An accepted reload with a lost supervisor handoff closes the owner;
                // work queued behind it must be disposed, not dispatched unacknowledged.
                endpoints.shutdown().await.unwrap();
                let mut packet = [0; 32];
                assert_eq!(
                    upstream.try_recv_from(&mut packet).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                assert!(
                    tcp.poll_accept(&mut std::task::Context::from_waker(std::task::Waker::noop()))
                        .is_pending()
                );
            } else {
                let (mut peer, _) = tcp.accept().await.unwrap();
                let mut received = [0; 32];
                for expected in [b"first".as_slice(), b"second".as_slice()] {
                    let (length, _) = upstream.recv_from(&mut received).await.unwrap();
                    assert_eq!(&received[..length], expected);
                }
                tokio::io::AsyncWriteExt::write_all(&mut peer, b"post-reload output")
                    .await
                    .unwrap();
                delivery
                    .await
                    .expect("real TCP response must reach the output consumer");
                drop(peer);
            }
            endpoints.shutdown().await.unwrap();
            owner.run().await.unwrap();
            adapter.await.unwrap();
        }
    })
    .await
    .expect("XDP reload must preserve non-lease ingress work");
}
