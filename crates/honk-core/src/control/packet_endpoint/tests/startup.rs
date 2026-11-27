use super::*;
use honk_config::datapath::Backend;

const PACKET_BACKENDS: [Backend; 2] = [Backend::Xdp, Backend::Tun];

async fn packet_plane(
    backend: Backend,
    mode: &str,
    selection: &str,
) -> (ControlPlane, tokio::net::TcpListener) {
    packet_plane_with(backend, mode, selection, |_| {}).await
}

async fn packet_plane_with(
    backend: Backend,
    mode: &str,
    selection: &str,
    configure: impl FnOnce(&mut honk_config::Config),
) -> (ControlPlane, tokio::net::TcpListener) {
    let (plane, health) = xdp_plane_with(mode, selection, configure).await;
    if backend == Backend::Tun {
        // Supervisor fixtures share ordinary process mark initialization; real TUN startup is VM-only.
        let mut accepted = plane.config.write().await;
        let mut config = (**accepted).clone();
        config.datapath = Some(honk_config::datapath::DatapathConfig {
            backend,
            direct: Some(honk_config::datapath::DirectProfile::Endpoint),
            tun: Some(honk_config::datapath::TunConfig {
                name: "honk0".into(),
                mtu: 1500,
                queues: 1,
                address4: Some("198.18.0.1".parse().unwrap()),
                address6: Some("fd00:686f:6e6b:100::1".parse().unwrap()),
                table: 202,
                rule_priority: 10000,
                host_facts: false,
                capture: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            }),
            ..Default::default()
        });
        config.validate_assembled().unwrap();
        *accepted = Arc::new(config);
    }
    (plane, health)
}
async fn start_packet(
    plane: ControlPlane,
    scopes: Vec<(PacketScope, PacketOwner)>,
    capacity: usize,
) -> anyhow::Result<(PacketEndpoints, PacketEndpointOwner, Vec<PacketDriver>)> {
    let tun = plane
        .config
        .read()
        .await
        .datapath
        .as_ref()
        .is_some_and(|datapath| datapath.backend == Backend::Tun);
    if !tun {
        let (endpoints, owner) = PacketEndpoints::new(plane, scopes, capacity).await?;
        return Ok((endpoints, owner, Vec::new()));
    }
    let dns_scope = scopes[0].0.scope();
    let (endpoints, mut owner, mut drivers) =
        PacketEndpoints::start_driven(plane, scopes, capacity, None, dns_scope).await?;
    std::future::poll_fn(|cx| {
        for driver in &mut drivers {
            driver.service(cx, Instant::now());
        }
        owner.poll_ready(cx)
    })
    .await?;
    Ok((endpoints, owner, drivers))
}

async fn join_packet(
    endpoints: PacketEndpoints,
    mut owner: PacketEndpointOwner,
    mut drivers: Vec<PacketDriver>,
) {
    endpoints.close();
    let (_, result) = std::future::poll_fn(|cx| {
        for driver in &mut drivers {
            driver.service(cx, Instant::now());
        }
        owner.poll_join_plane(cx)
    })
    .await
    .unwrap();
    result.unwrap();
}

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
async fn configured_packet_startup_initializes_exact_mode_flags_before_capture() {
    use honk_ebpf_common::{
        DATAPATH_FLAG_OFFLOAD_ALL as ALL, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as RULE,
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        for backend in PACKET_BACKENDS {
            for (mode, selection, expected) in [
                ("Rule", "block", RULE),
                ("Direct", "block", ALL),
                ("Global", "direct", ALL),
                ("Global", "block", 0),
            ] {
                let budget = MemoryBudget::new(32 << 20);
                let (scope, scope_owner) = scope(&budget);
                let (plane, _health) = packet_plane(backend, mode, selection).await;
                let policy = Arc::clone(&plane.ebpf);
                let flags = plane.datapath_flags_handle().unwrap();
                let restored = flags.snapshot();
                let (endpoints, owner, drivers) =
                    start_packet(plane, vec![(scope, scope_owner)], 1)
                        .await
                        .unwrap();
                assert_eq!(policy.read().await.datapath_flags_write_log(), [expected]);
                flags.fence_nfqueue().await.unwrap();
                flags.reopen_nfqueue().await.unwrap();
                assert_eq!(flags.snapshot(), restored);
                assert_eq!(
                    policy.read().await.datapath_flags_write_log(),
                    [expected; 3]
                );
                endpoints.capture_ready().unwrap();
                join_packet(endpoints, owner, drivers).await;
            }
        }
    })
    .await
    .expect("configured packet startup must initialize software flags before capture");
}

#[tokio::test]
async fn configured_packet_flag_failure_retains_cleanup_until_output_returns() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for backend in PACKET_BACKENDS {
            let budget = MemoryBudget::new(32 << 20);
            let (scope, scope_owner) = scope(&budget);
            let (plane, _health) = packet_plane(backend, "Direct", "block").await;
            let projection = plane.dns_controller.routing_projection();
            let stopped = Arc::clone(&plane.shutdown_requested);
            let policy = Arc::clone(&plane.ebpf);
            let mut held_backend = policy.write().await;
            held_backend.arm_datapath_flags_write_fault(1).unwrap();
            let mut opening = Box::pin(start_packet(plane, vec![(scope.clone(), scope_owner)], 1));
            assert!(futures::poll!(&mut opening).is_pending());
            scope
                .datagram_sender("198.51.100.1:53".parse().unwrap())
                .send_to(b"retained", "192.0.2.1:41000".parse().unwrap())
                .await
                .unwrap();
            let output = scope.next_output().await.unwrap();
            drop(held_backend);
            while !stopped.requested() {
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
            projection.shutdown(Duration::from_secs(1)).await;
            drop(projection);
            assert_eq!(budget.used(), 0);
        }
    })
    .await
    .expect("failed packet flags must retain joined cleanup");
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn cancelled_startup_never_activates_and_retains_exported_output() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for maintenance_waiting in [false, true] {
            let budget = MemoryBudget::new(32 << 20);
            let (scope, scope_owner) = scope(&budget);
            let (mut plane, _health) = local_plane().await;
            let projection = plane.dns_controller.routing_projection();
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
            let stopping = stopped.wait();
            tokio::pin!(stopping);
            assert!(futures::poll!(&mut stopping).is_pending());
            drop(opening);
            tokio::time::timeout(Duration::from_secs(1), &mut stopping)
                .await
                .expect("startup cancellation wakes capture before its blocked supervisor resumes");
            drop(config_guard);
            let _ = release.send(());
            assert!(native.core.activated_at(generation).is_none());
            assert!(output.packet().ends_with(b"retained"));
            output.release();
            assert!(scope.next_output().await.is_none());
            drop(scope);
            drop(native);
            projection.shutdown(Duration::from_secs(1)).await;
            drop(projection);
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
        endpoints
            .sender
            .send(Work::Tcp(flow, slot, None))
            .await
            .unwrap();
        let (_first_peer, _) = first.accept().await.unwrap();
        let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (flow, _) = established_tcp(&scope, second.local_addr().unwrap()).await;
        let id = flow.flow_id();
        let slot = Arc::clone(&endpoints.shared.tcp_slots)
            .acquire_owned()
            .await
            .unwrap();
        endpoints
            .sender
            .send(Work::Tcp(flow, slot, None))
            .await
            .unwrap();
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
        let projection = plane.dns_controller.routing_projection();
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
            .send(Work::Tcp(flow, permit, None))
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
        projection.shutdown(Duration::from_secs(1)).await;
        drop(projection);
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("ordinary close must abort packet state and join without further peer ingress");
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn configured_packet_running_waits_for_actual_capture_activation() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for backend in PACKET_BACKENDS {
            let budget = MemoryBudget::new(32 << 20);
            let (scope, scope_owner) = scope(&budget);
            let (mut plane, _health) = packet_plane(backend, "Rule", "block").await;
            *plane.ebpf.write().await = Box::new(crate::ebpf::userspace::UserspaceBackend::new(
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
                Arc::new(parking_lot::RwLock::new(
                    crate::ebpf::PnameSupport::Unavailable,
                )),
            ));
            plane.tc_kernel = None;
            let mut phase = plane.observe_phase();
            let (endpoints, owner, drivers) = start_packet(plane, vec![(scope, scope_owner)], 1)
                .await
                .unwrap();
            assert_eq!(*phase.borrow(), super::super::super::EnginePhase::Starting);
            assert!(!endpoints.shared.capture_ready.load(Ordering::Acquire));
            endpoints.capture_ready().unwrap();
            while *phase.borrow() != super::super::super::EnginePhase::Running {
                phase.changed().await.unwrap();
            }
            join_packet(endpoints, owner, drivers).await;
        }
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
                mark: None,
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
                    .queue_datagram(&scope, source, destination, 0, None, None, None, |budget| {
                        FundedDatagram::copy_from(b"cancelled", budget)
                    })
                    .unwrap();
                assert!(endpoints.retains(scope.scope(), source, destination, 17));
            };
            queue_initializer(source);
            endpoints
                .sender
                .try_send(Work::Tcp(flow, slot, None))
                .unwrap();
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
                        source_work: scope
                            .hold_udp_source("192.0.2.10:41003".parse().unwrap())
                            .unwrap(),
                        auxiliary: None,
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

#[tokio::test]
async fn driven_start_keeps_the_ordinary_pairing_and_budget_validation() {
    let budget = MemoryBudget::new(32 << 20);
    let (first, first_owner) = scope(&budget);
    let (_second, second_owner) = scope(&budget);
    let (plane, _health) = local_plane().await;
    let swapped = PacketEndpoints::start_driven(
        plane,
        vec![(first.clone(), second_owner)],
        1,
        None,
        ScopeId::HOST,
    )
    .await
    .err()
    .expect("a swapped owner must not receive a driver");
    assert!(format!("{swapped:#}").contains("owner mismatch"));
    let foreign = MemoryBudget::new(32 << 20);
    let (other, other_owner) = scope(&foreign);
    let (plane, _health) = local_plane().await;
    let mixed = PacketEndpoints::start_driven(
        plane,
        vec![(first, first_owner), (other, other_owner)],
        1,
        None,
        ScopeId::HOST,
    )
    .await
    .err()
    .expect("a foreign budget must not receive a driver");
    assert!(format!("{mixed:#}").contains("one memory ceiling"));
}

#[tokio::test]
async fn driven_startup_failure_keeps_drivers_serviceable_and_reports_abandonment() {
    use honk_datapath::buffer::TxClass;
    use std::task::{Context, Poll, Waker};

    tokio::time::timeout(Duration::from_secs(10), async {
        for abandon in [false, true] {
            let budget = MemoryBudget::new(32 << 20);
            let (scope, scope_owner) = scope(&budget);
            let (plane, _health) = local_plane().await;
            let (endpoints, mut owner, mut drivers) = PacketEndpoints::start_driven(
                plane,
                vec![(scope.clone(), scope_owner)],
                1,
                None,
                ScopeId::HOST,
            )
            .await
            .unwrap();
            let mut driver = drivers.pop();
            scope
                .datagram_sender("198.51.100.1:53".parse().unwrap())
                .send_to(b"retained", "192.0.2.1:41000".parse().unwrap())
                .await
                .unwrap();
            let mut outputs = [None];
            assert_eq!(
                driver.as_mut().unwrap().poll_outputs_class(
                    &mut Context::from_waker(Waker::noop()),
                    TxClass::Bulk,
                    &mut outputs
                ),
                Poll::Ready(Some(1))
            );
            let output = outputs[0].take().unwrap();
            // Closed before its supervisor's first poll: startup cannot commit readiness.
            endpoints.close();
            if abandon {
                driver.take();
            }
            for _ in 0..16 {
                let ready = std::future::poll_fn(|cx| {
                    if let Some(driver) = &mut driver {
                        driver.service(cx, Instant::now());
                    }
                    Poll::Ready(owner.poll_ready(cx))
                })
                .await;
                assert!(ready.is_pending(), "startup cleanup still owns the output");
                tokio::task::yield_now().await;
            }
            assert!(output.packet().ends_with(b"retained"));
            output.release();
            let error = std::future::poll_fn(|cx| {
                if let Some(driver) = &mut driver {
                    driver.service(cx, Instant::now());
                }
                owner.poll_ready(cx)
            })
            .await
            .expect_err("closed startup must not report readiness");
            let message = format!("{error:#}");
            if abandon {
                assert!(message.contains("abandoned"), "{message}");
            } else {
                assert!(message.contains("before admission"), "{message}");
            }
            drop((endpoints, owner, driver, scope));
            assert_eq!(budget.used(), 0);
        }
    })
    .await
    .expect("failed driven startup must retain cleanup and its abandonment outcome");
}

#[tokio::test]
async fn driven_task_admission_failure_keeps_unspawned_owner_until_output_returns() {
    use honk_datapath::buffer::TxClass;
    use std::task::{Context, Poll, Waker};

    tokio::time::timeout(Duration::from_secs(5), async {
        let budget = MemoryBudget::new(32 << 20);
        let (first, first_owner) = scope(&budget);
        let (second, second_owner) = scope(&budget);
        let (plane, _health) = local_plane().await;
        let stopped = plane.shutdown_intent();
        let projection = plane.dns_controller.routing_projection();
        let (endpoints, mut owner, mut drivers) = PacketEndpoints::start_driven(
            plane,
            vec![(first.clone(), first_owner), (second.clone(), second_owner)],
            1,
            None,
            ScopeId::HOST,
        )
        .await
        .unwrap();
        let mut held = Vec::new();
        for (index, scope) in [&first, &second].into_iter().enumerate() {
            scope
                .datagram_sender("198.51.100.1:53".parse().unwrap())
                .send_to(&[index as u8], "192.0.2.1:41000".parse().unwrap())
                .await
                .unwrap();
            let mut outputs = [None];
            assert_eq!(
                drivers[index].poll_outputs_class(
                    &mut Context::from_waker(Waker::noop()),
                    TxClass::Bulk,
                    &mut outputs,
                ),
                Poll::Ready(Some(1))
            );
            held.push(outputs[0].take().unwrap());
        }
        let pressure = budget.reserve(budget.limit() - budget.used()).unwrap();
        stopped.wait().await;
        while let Some(output) = held.pop() {
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(30),
                    std::future::poll_fn(|cx| {
                        for driver in &mut drivers {
                            driver.service(cx, Instant::now());
                        }
                        owner.poll_ready(cx)
                    })
                )
                .await
                .is_err(),
                "failed scope-task admission must still join every original output owner"
            );
            assert_eq!(output.packet().last(), Some(&(held.len() as u8)));
            output.release();
        }
        let result = std::future::poll_fn(|cx| {
            for driver in &mut drivers {
                driver.service(cx, Instant::now());
            }
            owner.poll_ready(cx)
        })
        .await;
        assert!(
            result.is_err(),
            "allocation failure remains a failed startup after cleanup"
        );
        drop(pressure);
        drop((drivers, owner, endpoints, first, second));
        projection.shutdown(Duration::from_secs(1)).await;
        drop(projection);
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("unfunded scope startup must keep and finish real ownership");
}

#[tokio::test]
async fn configured_packet_reload_authorizes_subscription_workers() {
    use crate::control::{ControlCommand, commands::ReloadOutcome};

    tokio::time::timeout(Duration::from_secs(10), async {
        for backend in PACKET_BACKENDS {
            let budget = MemoryBudget::new(32 << 20);
            let (scope, scope_owner) = scope(&budget);
            let (plane, _health) = packet_plane(backend, "Rule", "block").await;
            let config = plane.config_handle();
            let commands = plane.command_sender();
            let mut candidate = (**config.read().await).clone();
            let subscription = honk_config::subscription::Subscription {
                name: "packet-provider".into(),
                url: "http://127.0.0.1:9".into(),
                update_interval: 0,
                ..Default::default()
            };
            let id = subscription.id;
            candidate.subscriptions.push(subscription);
            let (endpoints, owner, drivers) = start_packet(plane, vec![(scope, scope_owner)], 1)
                .await
                .unwrap();
            let (result, reply) = tokio::sync::oneshot::channel();
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
            let reply = reply.await.unwrap();
            assert!(matches!(reply.outcome, ReloadOutcome::Committed { .. }));
            assert_eq!(reply.authorized.len(), 1);
            assert_eq!(reply.authorized[0].subscription.id, id);
            let revision = reply.authorized[0].revision;
            assert_eq!(config.read().await.subscriptions[0].id, id);
            for worker_revision in [revision.wrapping_sub(1), revision] {
                let (result, reply) = tokio::sync::oneshot::channel();
                commands
                    .send(ControlCommand::MergeSubscription {
                        subscription_id: id,
                        revision: worker_revision,
                        nodes: Vec::new(),
                        diagnostics: Vec::new(),
                        result,
                    })
                    .await
                    .unwrap();
                assert_eq!(
                    reply.await.unwrap().outcome.accepted(),
                    worker_revision == revision
                );
            }
            join_packet(endpoints, owner, drivers).await;
        }
    })
    .await
    .expect("configured packet commands must retain subscription authorization");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn tun_dual_capture_cold_start_fits_with_retained_producer_charge() {
    use crate::control::netstack::{CAPTURE_MEMORY, capture_scope_with_output};

    tokio::time::timeout(Duration::from_secs(10), async {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        // Retain the producer's declared fixture charge throughout startup and joined teardown.
        let producer_bytes = 32 << 20;
        let producer = budget.reserve(producer_bytes).unwrap();
        let caps = honk_netstack::TxCaps {
            tso4: true,
            tso6: true,
            ..honk_netstack::TxCaps::NONE
        };
        let plain =
            capture_scope_with_output(1500, 2, 128, u16::MAX as usize, caps, &budget).unwrap();
        let host =
            capture_scope_with_output(1500, 2, 128, u16::MAX as usize, caps, &budget).unwrap();
        host.0.prepare_host().unwrap();
        let dns_scope = plain.0.scope();
        let (plane, _health) = packet_plane(Backend::Tun, "Rule", "block").await;
        {
            let mut accepted = plane.config.write().await;
            let mut config = (**accepted).clone();
            config
                .datapath
                .as_mut()
                .unwrap()
                .tun
                .as_mut()
                .unwrap()
                .host_facts = true;
            *accepted = Arc::new(config);
        }
        let projection = plane.dns_controller.routing_projection();
        let capacity = plane.packet_udp_capacity();
        let (endpoints, mut owner, mut drivers) =
            PacketEndpoints::start_driven(plane, vec![plain, host], capacity, None, dns_scope)
                .await
                .unwrap();
        std::future::poll_fn(|cx| {
            for driver in &mut drivers {
                driver.service(cx, Instant::now());
            }
            owner.poll_ready(cx)
        })
        .await
        .unwrap();
        assert_eq!(drivers.len(), 2);
        assert!(budget.used() <= CAPTURE_MEMORY);
        join_packet(endpoints, owner, drivers).await;
        projection.shutdown(Duration::from_secs(1)).await;
        drop(projection);
        assert_eq!(budget.used(), producer_bytes);
        drop(producer);
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("real dual capture scopes and the shared supervisor must fit and join");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn xdp_sharded_startup_funds_required_owners_before_optional_output() {
    use crate::control::netstack::{CAPTURE_MEMORY, DirectRelayFence, capture_realm};

    tokio::time::timeout(Duration::from_secs(10), async {
        let mut required = None;
        for widened in [true, false] {
            let budget = MemoryBudget::new(CAPTURE_MEMORY);
            let pressure = required.map(|bytes| budget.reserve(CAPTURE_MEMORY - bytes).unwrap());
            let producer_bytes = pressure.as_ref().map_or(0, |grant| grant.bytes());
            let (realm, owners) = capture_realm(1500, 1, 256, 2, 1, &budget).unwrap();
            let admission = Arc::new(AtomicBool::new(false));
            realm
                .install_admission_fence(Arc::clone(&admission))
                .unwrap();
            let (plane, _health) = packet_plane(Backend::Xdp, "Rule", "block").await;
            let projection = plane.dns_controller.routing_projection();
            let capacity = plane.packet_udp_capacity();
            let (endpoints, mut owner, mut drivers) = PacketEndpoints::start_driven(
                plane,
                vec![(realm.clone(), owners)],
                capacity,
                None,
                ScopeId::HOST,
            )
            .await
            .unwrap();
            std::future::poll_fn(|cx| {
                for driver in &mut drivers {
                    driver.service(cx, Instant::now());
                }
                owner.poll_ready(cx)
            })
            .await
            .unwrap();
            let fences = [
                DirectRelayFence::new(&budget).unwrap(),
                DirectRelayFence::new(&budget).unwrap(),
            ];
            let before = budget.used();
            if widened {
                required = Some(before);
            } else {
                assert_eq!(before, CAPTURE_MEMORY);
            }
            assert_eq!(realm.widen_startup_output(256), widened);
            assert_eq!(budget.used() > before, widened);
            admission.store(true, Ordering::Release);
            endpoints.capture_ready().unwrap();
            join_packet(endpoints, owner, drivers).await;
            projection.shutdown(Duration::from_secs(1)).await;
            drop((projection, realm, fences));
            assert_eq!(budget.used(), producer_bytes);
            drop(pressure);
            assert_eq!(budget.used(), 0);
        }
    })
    .await
    .expect("two original scope owners and their funded supervisor must join");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn tun_driven_startup_enforces_configured_multiqueue_plain_realm() {
    use crate::control::netstack::{CAPTURE_MEMORY, capture_tun_realm};

    #[derive(Clone, Copy, Debug)]
    enum Layout {
        Plain,
        TwoPlainRealms,
        HostFacts,
        UnexpectedHost,
        WrongDns,
    }
    for (queues, owners, layout, accepts) in [
        (2, 2, Layout::Plain, true),
        (4, 4, Layout::Plain, true),
        (8, 8, Layout::Plain, true),
        (4, 1, Layout::Plain, false),
        (2, 1, Layout::TwoPlainRealms, false),
        (2, 1, Layout::HostFacts, false),
        (2, 2, Layout::HostFacts, false),
        (4, 4, Layout::UnexpectedHost, false),
        (4, 4, Layout::WrongDns, false),
    ] {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let (realm, realm_owners) =
            capture_tun_realm(1500, owners, honk_netstack::TxCaps::NONE, &budget).unwrap();
        let dns_scope = if matches!(layout, Layout::WrongDns) {
            ScopeId::HOST
        } else {
            realm.scope()
        };
        let mut plans = vec![PacketRealmPlan::from((realm, realm_owners))];
        match layout {
            Layout::TwoPlainRealms => plans.push(scope(&budget).into()),
            Layout::HostFacts | Layout::UnexpectedHost => {
                let host = scope(&budget);
                host.0.prepare_host().unwrap();
                plans.push(host.into());
            }
            Layout::Plain | Layout::WrongDns => {}
        }
        let (plane, _health) = packet_plane(Backend::Tun, "Rule", "block").await;
        {
            let mut config = plane.config.write().await;
            let tun = Arc::make_mut(&mut *config)
                .datapath
                .as_mut()
                .unwrap()
                .tun
                .as_mut()
                .unwrap();
            tun.queues = queues;
            tun.host_facts = matches!(layout, Layout::HostFacts);
        }
        let (endpoints, mut supervisor, mut drivers) =
            PacketEndpoints::start_driven(plane, plans, 1, None, dns_scope)
                .await
                .unwrap();
        let ready = std::future::poll_fn(|cx| {
            for driver in &mut drivers {
                driver.service(cx, Instant::now());
            }
            supervisor.poll_ready(cx)
        })
        .await;
        if accepts {
            ready.unwrap_or_else(|error| {
                panic!("{queues} configured queues, {owners} owners, {layout:?}: {error:#}")
            });
            join_packet(endpoints, supervisor, drivers).await;
        } else {
            let error = ready.expect_err("mismatched configured TUN realm reached readiness");
            assert!(
                format!("{error:#}")
                    .contains("TUN requires its plain scope and configured Host scope"),
                "{queues}/{owners} {layout:?}: {error:#}"
            );
            drop((endpoints, supervisor, drivers));
        }
        assert_eq!(
            budget.used(),
            0,
            "{queues}/{owners} {layout:?} leaked a reservation"
        );
    }
}

#[tokio::test]
async fn tun_driven_startup_requires_configured_host_and_plain_dns_identity() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for (host_facts, include_host, dns_identity, succeeds) in [
            (true, true, 0, true),
            (false, true, 0, false),
            (false, false, 2, false),
            (true, false, 0, false),
            (true, true, 1, false),
            (true, true, 2, false),
        ] {
            let budget = MemoryBudget::new(32 << 20);
            let (plain, plain_owner) = scope(&budget);
            let (host, host_owner) = scope(&budget);
            host.prepare_host().unwrap();
            let dns_scope = match dns_identity {
                0 => plain.scope(),
                1 => host.scope(),
                _ => ScopeId::HOST,
            };
            let (plane, _health) = packet_plane(Backend::Tun, "Rule", "block").await;
            {
                let mut accepted = plane.config.write().await;
                let mut config = (**accepted).clone();
                config
                    .datapath
                    .as_mut()
                    .unwrap()
                    .tun
                    .as_mut()
                    .unwrap()
                    .host_facts = host_facts;
                *accepted = Arc::new(config);
            }
            let mut scopes = vec![(plain, plain_owner)];
            if include_host {
                scopes.push((host, host_owner));
            } else {
                drop((host, host_owner));
            }
            let (endpoints, mut owner, mut drivers) =
                PacketEndpoints::start_driven(plane, scopes, 1, None, dns_scope)
                    .await
                    .unwrap();
            let ready = std::future::poll_fn(|cx| {
                for driver in &mut drivers {
                    driver.service(cx, Instant::now());
                }
                owner.poll_ready(cx)
            })
            .await;
            if succeeds {
                ready.unwrap();
                join_packet(endpoints, owner, drivers).await;
            } else {
                let error = ready.expect_err("invalid TUN scopes must reject startup");
                assert!(
                    format!("{error:#}")
                        .contains("TUN requires its plain scope and configured Host scope")
                );
            }
        }
    })
    .await
    .expect("TUN scope startup and teardown must finish");
}

#[tokio::test]
async fn tun_dns_bind_requires_preparation_before_startup() {
    let budget = MemoryBudget::new(32 << 20);
    let (scope, scope_owner) = scope(&budget);
    let (plane, _health) = packet_plane_with(Backend::Tun, "Rule", "block", |config| {
        config.dns.bind = "tcp+udp://localhost:0".into();
    })
    .await;
    let dns_scope = scope.scope();
    let (_endpoints, mut owner, mut drivers) =
        PacketEndpoints::start_driven(plane, vec![(scope, scope_owner)], 1, None, dns_scope)
            .await
            .unwrap();
    let error = std::future::poll_fn(|cx| {
        for driver in &mut drivers {
            driver.service(cx, Instant::now());
        }
        owner.poll_ready(cx)
    })
    .await
    .expect_err("TUN cannot resolve a bind endpoint after routing setup");
    assert_eq!(
        error.downcast_ref::<io::Error>().map(io::Error::kind),
        Some(io::ErrorKind::InvalidInput)
    );
}

#[cfg(all(target_os = "linux", feature = "packet-ebpf"))]
async fn configured_dns_startup(backend: Backend) {
    let reservation = super::super::super::dns_listener::BoundDnsListener::bind(
        &honk_config::dns::DnsBindEndpoint::parse("tcp+udp://127.0.0.1:0").unwrap(),
        None,
    )
    .unwrap();
    let address = reservation.local_addr();
    let hosts = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(hosts.path(), "full:packet.example.com 192.0.2.44\n").unwrap();
    let (plane, _health) = packet_plane_with(backend, "Rule", "block", |config| {
        config.dns.bind = format!("tcp+udp://{address}");
        config.dns.hosts = vec![hosts.path().to_str().unwrap().into()];
    })
    .await;
    let prepared = if backend == Backend::Tun {
        PacketEndpoints::prepare_dns_bind(plane.config.read().await.as_ref()).unwrap()
    } else {
        None
    };
    let budget = MemoryBudget::new(32 << 20);
    let (scope, scope_owner) = scope(&budget);
    let dns_scope = if backend == Backend::Tun {
        scope.scope()
    } else {
        ScopeId::HOST
    };
    drop(reservation);
    let (endpoints, mut owner, mut drivers) =
        PacketEndpoints::start_driven(plane, vec![(scope, scope_owner)], 1, prepared, dns_scope)
            .await
            .unwrap();
    let mut driver = drivers.pop().unwrap();
    std::future::poll_fn(|cx| {
        driver.service(cx, Instant::now());
        owner.poll_ready(cx)
    })
    .await
    .unwrap();
    let query = crate::dns::forwarder::build_dns_query("packet.example.com", 1);
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.send_to(&query, address).await.unwrap();
    let mut response = [0; 512];
    let length = udp.recv(&mut response).await.unwrap();
    assert!(response[..length].ends_with(&[192, 0, 2, 44]));
    let mut tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    crate::dns::transport::write_length_prefixed(&mut tcp, &query)
        .await
        .unwrap();
    let mut response = Vec::new();
    crate::dns::transport::read_length_prefixed_into(&mut tcp, &mut response, None)
        .await
        .unwrap();
    assert!(response.ends_with(&[192, 0, 2, 44]));
    drop(tcp);
    endpoints.close();
    let (_, result) = std::future::poll_fn(|cx| {
        driver.service(cx, Instant::now());
        owner.poll_join_plane(cx)
    })
    .await
    .unwrap();
    result.unwrap();
}

#[cfg(all(target_os = "linux", feature = "packet-ebpf"))]
#[test]
#[ignore = "requires the disposable kernel VM gate and SO_MARK privileges"]
fn tun_dns_bind_starts_with_prepared_addresses_and_marks_both_transports() {
    std::thread::spawn(|| {
        crate::test_support::netns::enter_with_loopback().unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                for backend in PACKET_BACKENDS {
                    tokio::time::timeout(Duration::from_secs(10), configured_dns_startup(backend))
                        .await
                        .expect("prepared configured packet DNS must start both transports");
                }
            });
    })
    .join()
    .unwrap();
}
