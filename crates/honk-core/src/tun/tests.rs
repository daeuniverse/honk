use super::*;
use crate::control::netstack::{PacketOwner, PacketScope, RuntimeLimits};
use std::os::unix::net::UnixDatagram;

#[tokio::test]
async fn stale_topology_readiness_rearms_before_the_next_notification() {
    let (reader, writer) = UnixDatagram::pair().unwrap();
    reader.set_nonblocking(true).unwrap();
    writer.set_nonblocking(true).unwrap();
    // SAFETY: the socket keeps its descriptor unchanged until deregistration.
    let mut reader = unsafe { AsyncFd::register(reader) }
        .map_err(io::Error::from)
        .unwrap();
    writer.send(b"stale").unwrap();
    drop(reader.readable().await.unwrap());
    assert_eq!(reader.get_ref().recv(&mut [0; 16]).unwrap(), 5);
    let (armed, waiting) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(async move {
        let mut armed = Some(armed);
        poll_fn(|cx| {
            match poll_topology(&mut reader, cx, |socket| match socket.recv(&mut [0; 16]) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
                Err(error) => Err(error),
            })
            .unwrap()
            {
                Poll::Pending => {
                    if let Some(armed) = armed.take() {
                        let _ = armed.send(());
                    }
                    Poll::Pending
                }
                Poll::Ready(changed) => {
                    assert!(changed, "cached readiness must clear and park, not spin");
                    Poll::Ready(())
                }
            }
        })
        .await;
    });
    waiting.await.unwrap();
    writer.send(b"changed").unwrap();
    tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .expect("the new topology event must wake the parked owner")
        .unwrap();
}

fn scope() -> (PacketScope, PacketOwner, Arc<MemoryBudget>) {
    let budget = MemoryBudget::new(8 << 20);
    let mut config = honk_netstack::Config::new([19; 32]);
    config.mode = honk_netstack::Mode::Transparent {
        exclude: Default::default(),
    };
    config.mtu = 1500;
    config.max_flows = 8;
    config.memory_limit = 2 << 20;
    let (scope, owner) = PacketScope::new(
        config,
        Arc::clone(&budget),
        RuntimeLimits {
            max_slots: 8,
            control_frames: 4,
            bulk_frames: 4,
            max_waiters: 4,
        },
        Instant::now(),
    )
    .unwrap();
    (scope, owner, budget)
}

async fn driven_endpoints() -> (
    PacketEndpoints,
    PacketEndpointOwner,
    PacketDriver,
    PacketScope,
    Arc<MemoryBudget>,
) {
    let (scope, scope_owner, budget) = scope();
    let mut config = Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.global.tcp_check_url.clear();
    config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
    config.global.preconnect_node_count = 0;
    config.global.udp_warm_node_count = 0;
    let plane = crate::control::tests::support::control_plane(config);
    let (endpoints, mut owner, mut drivers) =
        PacketEndpoints::start_driven(plane, vec![(scope.clone(), scope_owner)], 1, None).unwrap();
    let mut driver = drivers.pop().unwrap();
    poll_fn(|cx| {
        driver.service(cx, Instant::now());
        owner.poll_ready(cx)
    })
    .await
    .unwrap();
    (endpoints, owner, driver, scope, budget)
}

#[tokio::test]
async fn close_racing_udp_admission_preserves_the_joined_shutdown_outcome() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for port in [53, 443] {
            for abandon in [false, true] {
                let (endpoints, mut owner, driver, scope, budget) = driven_endpoints().await;
                let mut driver = Some(driver);
                let admission = AtomicBool::new(true);
                let source = "192.0.2.1:41000".parse().unwrap();
                let destination = std::net::SocketAddr::from(([198, 51, 100, 1], port));
                let mut packet = [0; 128];
                let length = honk_netstack::wire::udp::emit_packet(
                    &mut packet,
                    source,
                    destination,
                    b"close-race",
                )
                .unwrap();
                let mut received_source = false;
                std::thread::scope(|threads| {
                    let (close, requested) = std::sync::mpsc::sync_channel(0);
                    let closing = &endpoints;
                    threads.spawn(move || {
                        requested.recv().unwrap();
                        closing.close();
                    });
                    admit_packet(
                        &endpoints,
                        scope.scope(),
                        &packet[..length],
                        Instant::now(),
                        |_, _| {
                            let allowed =
                                admission.load(Ordering::Acquire) && !endpoints.is_closing();
                            assert!(allowed);
                            received_source = true;
                            close.send(()).unwrap();
                            // close publishes CLOSING before waiting for this scope mutex.
                            let deadline = Instant::now() + Duration::from_secs(5);
                            while !endpoints.is_closing() {
                                assert!(Instant::now() < deadline, "close did not publish");
                                std::thread::yield_now();
                            }
                            allowed
                        },
                    )
                    .expect("an admitted UDP racing endpoint close must not fail the TUN owner");
                });
                assert!(received_source);
                assert!(endpoints.is_closing());
                assert!(!endpoints.retains_source(scope.scope(), source.ip()));
                if abandon {
                    drop(driver.take());
                }
                let (plane, result) = poll_fn(|cx| {
                    if let Some(driver) = &mut driver {
                        driver.service(cx, Instant::now());
                    }
                    owner.poll_join_plane(cx)
                })
                .await
                .unwrap();
                if abandon {
                    result.expect_err("a close must preserve supervisor failure");
                } else {
                    result.expect("ordinary joined stop must preserve supervisor success");
                }
                drop((plane, endpoints, owner, driver, scope));
                assert_eq!(budget.used(), 0);
            }
        }
    })
    .await
    .expect("both normal stop and failed supervisor must join the original packet owners");
}

#[tokio::test]
async fn admission_errors_without_endpoint_close_remain_failures() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (endpoints, mut owner, mut driver, scope, budget) = driven_endpoints().await;
        let mut packet = [0; 128];
        let source = "192.0.2.1:41000".parse().unwrap();
        let length = honk_netstack::wire::udp::emit_packet(
            &mut packet,
            source,
            "198.51.100.1:53".parse().unwrap(),
            b"source-closed",
        )
        .unwrap();
        scope.shutdown(false);
        let error = admit_packet(
            &endpoints,
            scope.scope(),
            &packet[..length],
            Instant::now(),
            |_, _| true,
        )
        .expect_err("a closed UDP53 source hold alone is not a graceful endpoint stop");
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(!endpoints.is_closing());
        let error = admit_packet(
            &endpoints,
            honk_datapath::ScopeId::HOST,
            &packet[..length],
            Instant::now(),
            |_, _| true,
        )
        .expect_err("an unowned scope must remain an admission failure");
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::NotFound
        );
        endpoints.close();
        let (plane, result) = poll_fn(|cx| {
            driver.service(cx, Instant::now());
            owner.poll_join_plane(cx)
        })
        .await
        .unwrap();
        result.unwrap();
        drop((plane, endpoints, owner, driver, scope));
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("a genuine admission error must still permit joined cleanup");
}

async fn output(scope: &PacketScope) -> OutputLease {
    scope
        .datagram_sender("198.51.100.1:53".parse().unwrap())
        .send_to(b"unchanged-lease", "192.0.2.1:41000".parse().unwrap())
        .await
        .unwrap();
    scope.drive(Instant::now());
    scope.next_output().await.unwrap()
}

#[tokio::test]
async fn writable_readiness_retries_the_same_lease_without_new_input() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (scope, owner, budget) = scope();
        use honk_netstack::wire::tcp;
        let mut syn = [0; 128];
        let length = tcp::emit_packet(
            &mut syn,
            "192.0.2.1".parse().unwrap(),
            "198.51.100.1".parse().unwrap(),
            &tcp::Header {
                src_port: 41000,
                dst_port: 443,
                seq: 19,
                ack: 0,
                flags: tcp::SYN,
                window: 4096,
                urgent: 0,
                options: tcp::Options::default(),
            },
            [&[], &[]],
        )
        .unwrap();
        assert_eq!(
            scope.receive(&syn[..length], Instant::now()),
            honk_netstack::Rx::Consumed
        );
        let (syn, flow) = scope.poll_accept().unwrap();
        scope.drive(Instant::now());
        let lease = scope.next_output().await.unwrap();
        assert_eq!(lease.flow_id(), Some(syn.id));
        let original = lease.packet().to_vec();
        let pointer = lease.packet().as_ptr();
        let identity = (lease.scope(), lease.flow_id(), lease.class());
        let mut pending = std::array::from_fn(|_| None);
        pending[0] = Some(lease);
        let (writer, reader) = UnixDatagram::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        let filler = [7; 2048];
        loop {
            match writer.send(&filler) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("fill socket: {error}"),
            }
        }
        let mut attempts = 0;
        let mut bytes = 0;
        assert_eq!(
            flush_pending(
                &mut pending,
                &mut attempts,
                &mut bytes,
                Instant::now(),
                |packet| write_packet(writer.as_raw_fd(), packet)
            )
            .unwrap(),
            (true, false)
        );
        assert_eq!(attempts, 1);
        assert_eq!(bytes, 0);
        let retained = pending[0].as_ref().unwrap();
        assert_eq!(retained.packet().as_ptr(), pointer);
        assert_eq!(
            (retained.scope(), retained.flow_id(), retained.class()),
            identity
        );
        assert_eq!(retained.packet(), original);
        scope.shutdown(true);
        drop(flow);
        let joined = owner.run();
        tokio::pin!(joined);
        assert!(
            futures::poll!(&mut joined).is_pending(),
            "exported output still owns completion"
        );
        // SAFETY: the Unix socket keeps its descriptor unchanged while registered.
        let writer = unsafe { AsyncFd::register(writer) }
            .map_err(io::Error::from)
            .unwrap();
        let retry = poll_fn(|cx| {
            let mut attempts = 0;
            let mut bytes = 0;
            let runnable = poll_flush(
                &writer,
                cx,
                &mut pending,
                &mut attempts,
                &mut bytes,
                Instant::now(),
                || true,
            )
            .unwrap();
            if pending.iter().all(Option::is_none) {
                Poll::Ready(())
            } else {
                if runnable {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
        });
        tokio::pin!(retry);
        assert!(futures::poll!(&mut retry).is_pending());
        let mut received = [0; 4096];
        loop {
            match reader.recv(&mut received) {
                Ok(length) => assert_eq!(&received[..length], filler),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("drain filler: {error}"),
            }
        }
        retry.await;
        let length = reader.recv(&mut received).unwrap();
        assert_eq!(&received[..length], original);
        assert_eq!(
            reader.recv(&mut received).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        joined.await;
        drop(scope);
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("writable readiness alone must retry and release the original output");
}

#[tokio::test]
async fn closed_capture_does_not_write_a_pending_record() {
    let (scope, owner, budget) = scope();
    let lease = output(&scope).await;
    let pointer = lease.packet().as_ptr();
    let mut pending = std::array::from_fn(|_| None);
    pending[0] = Some(lease);
    let (writer, reader) = UnixDatagram::pair().unwrap();
    writer.set_nonblocking(true).unwrap();
    reader.set_nonblocking(true).unwrap();
    // SAFETY: this socket owns an unchanged descriptor until deregistration.
    let writer = unsafe { AsyncFd::register(writer) }
        .map_err(io::Error::from)
        .unwrap();
    let mut attempts = 0;
    let mut bytes = 0;
    assert!(
        poll_flush(
            &writer,
            &mut Context::from_waker(std::task::Waker::noop()),
            &mut pending,
            &mut attempts,
            &mut bytes,
            Instant::now(),
            || false
        )
        .unwrap()
    );
    assert_eq!((attempts, bytes), (0, 0));
    assert_eq!(pending[0].as_ref().unwrap().packet().as_ptr(), pointer);
    assert_eq!(
        reader.recv(&mut [0; 2048]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    scope.shutdown(true);
    let joined = owner.run();
    tokio::pin!(joined);
    assert!(futures::poll!(&mut joined).is_pending());
    drop(pending);
    joined.await;
    drop(scope);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn short_zero_and_fatal_writes_never_replay_or_release_as_success() {
    for outcome in [
        Ok(0),
        Ok(1),
        Err(io::ErrorKind::InvalidInput),
        Err(io::ErrorKind::BrokenPipe),
    ] {
        let (scope, owner, budget) = scope();
        let lease = output(&scope).await;
        let original = lease.packet().to_vec();
        let mut pending = std::array::from_fn(|_| None);
        pending[0] = Some(lease);
        let mut calls = 0;
        let mut attempts = 0;
        let mut bytes = 0;
        let error = flush_pending(
            &mut pending,
            &mut attempts,
            &mut bytes,
            Instant::now(),
            |packet| {
                calls += 1;
                assert_eq!(packet, original);
                outcome.map_err(io::Error::from)
            },
        )
        .unwrap_err();
        assert_eq!(
            calls, 1,
            "no whole-record or suffix retry after a boundary failure"
        );
        assert_eq!(bytes, 0);
        if outcome.is_ok() {
            assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        }
        assert_eq!(pending[0].as_ref().unwrap().packet(), original);
        scope.shutdown(true);
        let joined = owner.run();
        tokio::pin!(joined);
        assert!(futures::poll!(&mut joined).is_pending());
        drop(pending[0].take());
        joined.await;
        drop(scope);
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test]
async fn interrupted_writes_keep_one_lease_with_a_finite_syscall_budget() {
    let (scope, owner, budget) = scope();
    let lease = output(&scope).await;
    let pointer = lease.packet().as_ptr();
    let mut pending = std::array::from_fn(|_| None);
    pending[0] = Some(lease);
    let mut attempts = 0;
    let mut bytes = 0;
    let (blocked, runnable) = flush_pending(
        &mut pending,
        &mut attempts,
        &mut bytes,
        Instant::now(),
        |_| Err(io::ErrorKind::Interrupted.into()),
    )
    .unwrap();
    assert!(!blocked && runnable);
    assert!((1..=BATCH * 2).contains(&attempts));
    assert_eq!(bytes, 0);
    assert_eq!(pending[0].as_ref().unwrap().packet().as_ptr(), pointer);
    let mut attempts = 0;
    assert_eq!(
        flush_pending(
            &mut pending,
            &mut attempts,
            &mut bytes,
            Instant::now(),
            |packet| Ok(packet.len())
        )
        .unwrap(),
        (false, false)
    );
    assert_eq!(attempts, 1);
    assert!(pending.iter().all(Option::is_none));
    scope.shutdown(true);
    owner.run().await;
    drop(scope);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn accepted_prefix_is_not_rolled_back_when_the_next_record_blocks() {
    let (scope, owner, budget) = scope();
    let mut pending = std::array::from_fn(|_| None);
    pending[0] = Some(output(&scope).await);
    pending[1] = Some(output(&scope).await);
    let pointer = pending[1].as_ref().unwrap().packet().as_ptr();
    let length = pending[0].as_ref().unwrap().packet().len();
    let mut attempts = 0;
    let mut bytes = 0;
    let mut calls = 0;
    assert_eq!(
        flush_pending(
            &mut pending,
            &mut attempts,
            &mut bytes,
            Instant::now(),
            |packet| {
                calls += 1;
                if calls == 1 {
                    Ok(packet.len())
                } else {
                    Err(io::ErrorKind::WouldBlock.into())
                }
            }
        )
        .unwrap(),
        (true, false)
    );
    assert_eq!(attempts, 2);
    assert_eq!(bytes, length);
    assert!(pending[0].is_none());
    assert_eq!(pending[1].as_ref().unwrap().packet().as_ptr(), pointer);
    drop(pending);
    scope.shutdown(true);
    owner.run().await;
    drop(scope);
    assert_eq!(budget.used(), 0);
}

#[test]
fn fd_records_require_exact_ip_extent_and_bounded_turns() {
    let mut ipv4 = vec![0; 20];
    ipv4[0] = 0x45;
    ipv4[2..4].copy_from_slice(&20u16.to_be_bytes());
    let mut ipv6 = vec![0; 40];
    ipv6[0] = 0x60;
    for packet in [ipv4, ipv6] {
        assert!(exact_record(&packet));
        assert!(!exact_record(&packet[..packet.len() - 1]));
        let mut padded = packet;
        padded.push(0);
        assert!(!exact_record(&padded));
    }
    assert!(!exact_record(&[0; 40]));
    let now = Instant::now();
    assert!(turn_limit(BATCH, 0, now, BATCH));
    assert!(turn_limit(1, TURN_BYTES, now, BATCH));
    assert!(turn_limit(8, 0, now - TURN_TIME, BATCH));
    assert!(!turn_limit(0, 0, now - TURN_TIME, BATCH));
    assert!(!turn_limit(7, 0, now - TURN_TIME, BATCH));
}

#[test]
fn runtime_refuses_unavailable_tun_authority_without_restricting_dial_modes() {
    let base = honk_config::parser::parse_dae_config(
        r#"
        global { nfqueue_enable: false }
        datapath {
            backend: tun
            direct: endpoint
            tun {
                name: honk0
                address4: 198.18.0.1/32
                table: 202
                rule_priority: 10000
                capture { 0.0.0.0/0 }
            }
        }
        routing { fallback: direct }
    "#,
    )
    .unwrap();
    for mode in ["ip", "domain", "domain+", "domain++"] {
        let mut config = base.clone();
        config.global.dial_mode = mode.into();
        validate_runtime(&config, false).unwrap();
    }
    assert!(validate_runtime(&base, true).is_err());
    let mut config = base.clone();
    config.global.nfqueue_enable = true;
    assert!(validate_config(&config).is_err());
    let mut config = base.clone();
    config.global.lan_interface.push("lan0".into());
    assert!(validate_config(&config).is_err());
    let mut config = base.clone();
    config.global.wan_interface.push("wan0".into());
    assert!(validate_config(&config).is_err());
    let mut config = base.clone();
    config.routing.default_mark = 1;
    assert!(validate_config(&config).is_err());
    for predicate in [
        "pname(curl)",
        "!pname(curl)",
        "mac(02:00:00:00:00:01)",
        "!mac(02:00:00:00:00:01)",
    ] {
        let routing = honk_config::parser::parse_dae_config(&format!(
            "routing {{\n {predicate} -> direct\n fallback: direct\n }}"
        ))
        .unwrap()
        .routing;
        let mut config = base.clone();
        config.routing = routing;
        assert!(
            validate_config(&config).is_err(),
            "accepted unavailable {predicate}"
        );
    }
    validate_runtime(&Config::default(), true).unwrap();
}
