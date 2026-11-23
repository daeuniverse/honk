use super::*;

fn exported(
    driver: &mut PacketDriver,
    cx: &mut Context<'_>,
    class: TxClass,
) -> Option<OutputLease> {
    let mut outputs = [None];
    match driver.poll_outputs_class(cx, class, &mut outputs) {
        Poll::Ready(Some(1)) => outputs[0].take(),
        _ => None,
    }
}

struct DeviceWakes(AtomicUsize);

impl std::task::Wake for DeviceWakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn generated_turn_rescans_work_arriving_after_its_last_pull() {
    late_turn_output(false).await;
}

#[tokio::test]
async fn graceful_close_delivers_output_queued_after_the_last_pull() {
    late_turn_output(true).await;
}

async fn late_turn_output(graceful_close: bool) {
    let now = Instant::now();
    let (scope, owner) = PacketScope::new(
        config(),
        MemoryBudget::new(32 << 20),
        RuntimeLimits {
            bulk_frames: 2,
            ..limits()
        },
        now,
    )
    .unwrap();
    let mut driver = owner.hand_off();
    let wakes = Arc::new(DeviceWakes(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    let mut frame = [0; 1280];
    let client = "10.0.0.2:40000".parse().unwrap();
    let sender = scope.datagram_sender("203.0.113.9:53".parse().unwrap());
    sender.send_to(b"queued", client).await.unwrap();
    driver.finish_turn(&mut cx, now);
    driver.begin_turn(now);
    assert!(matches!(
        driver
            .materialize_into(now, TxClass::Control, &mut frame)
            .unwrap(),
        MaterializedOutput::Idle
    ));
    assert!(matches!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut frame)
            .unwrap(),
        MaterializedOutput::CpuQueuePending
    ));
    let prefix = exported(&mut driver, &mut cx, TxClass::Bulk).unwrap();
    assert!(prefix.packet().ends_with(b"queued"));
    assert!(matches!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut frame)
            .unwrap(),
        MaterializedOutput::Idle
    ));
    driver.finish_turn(&mut cx, now);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);

    sender.send_to(b"first wake", client).await.unwrap();
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    prefix.release();
    driver.begin_turn(now);
    assert!(matches!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut frame)
            .unwrap(),
        MaterializedOutput::CpuQueuePending
    ));
    let prefix = exported(&mut driver, &mut cx, TxClass::Bulk).unwrap();
    assert!(prefix.packet().ends_with(b"first wake"));
    prefix.release();
    assert!(matches!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut frame)
            .unwrap(),
        MaterializedOutput::Idle
    ));
    sender.send_to(b"late", client).await.unwrap();
    assert!(matches!(
        driver
            .materialize_into(now, TxClass::Control, &mut frame)
            .unwrap(),
        MaterializedOutput::Idle
    ));
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    if graceful_close {
        scope.shutdown(false);
    }
    driver.finish_turn(&mut cx, now);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 2);
    let output = exported(&mut driver, &mut cx, TxClass::Bulk).unwrap();
    assert!(output.packet().ends_with(b"late"));
    output.release();
    if graceful_close {
        driver.finish_turn(&mut cx, now);
        assert!(owner.reclaim().await);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn interrupted_generated_turn_rearms_before_close() {
    let now = Instant::now();
    let (scope, owner, _) = runtime(now);
    let mut driver = owner.hand_off();
    let wakes = Arc::new(DeviceWakes(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    driver.begin_turn(now);
    assert!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut [])
            .is_err()
    );
    driver.interrupt_turn(&cx);
    let resumed = wakes.0.load(Ordering::SeqCst);
    assert!(resumed > 0);
    scope.shutdown(false);
    assert!(wakes.0.load(Ordering::SeqCst) > resumed);
    driver.service_closing(&mut cx, now);
    assert!(owner.reclaim().await);
}

#[test]
fn unwinding_owner_aborts_an_unfinished_generated_turn() {
    let now = Instant::now();
    let (_scope, owner, _) = runtime(now);
    let mut driver = owner.hand_off();
    let wakes = Arc::new(DeviceWakes(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    driver.finish_turn(&mut cx, now);
    driver.begin_turn(now);
    let panic = catch_unwind(AssertUnwindSafe(move || {
        let _owner = owner;
        panic!("interrupted device owner");
    }))
    .unwrap_err();
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"interrupted device owner")
    );
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn tun_turn_preserves_expiry_after_the_last_output_pass() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for (source, destination) in [
            ("10.0.0.2:40000", "203.0.113.9:443"),
            ("[fd00::2]:40000", "[2001:db8::9]:443"),
        ] {
            let now = Instant::now();
            let (source, destination): (SocketAddr, SocketAddr) =
                (source.parse().unwrap(), destination.parse().unwrap());
            let mut cfg = config();
            cfg.fragment_limits.timeout = Duration::from_millis(20);
            let (scope, owner) =
                PacketScope::new(cfg, MemoryBudget::new(32 << 20), limits(), now).unwrap();
            let mut peer = Stack::new(config(), now);
            let mut first = [0; 1280];
            let length = peer
                .udp_send_from(source, destination, &[7; 4000], &mut first)
                .unwrap();
            assert_eq!(scope.receive(&first[..length], now), Rx::Consumed);
            let due = now + Duration::from_millis(20);
            let mut driver = owner.hand_off();
            let (writer, reader) = std::os::unix::net::UnixDatagram::pair().unwrap();
            writer.set_nonblocking(true).unwrap();
            reader.set_nonblocking(true).unwrap();
            let mut cx = context();
            let more = crate::tun::service_turn(std::slice::from_mut(&mut driver), &mut cx, now, |drivers, cx| {
                let driver = &mut drivers[0];
                for class in [TxClass::Control, TxClass::Bulk] {
                    assert!(exported(driver, cx, class).is_none());
                }
                assert_eq!(driver.deadline(), Some(due));
                // Expiry crosses after the last output poll, with no further ingress.
                std::thread::sleep(due.saturating_duration_since(Instant::now()));
                assert!(Instant::now() >= due);
                Ok(false)
            })
            .unwrap();
            assert!(!more, "the empty output pass supplied no continuation");
            assert_eq!(scope.0.inner.lock().queued, 0, "finalization must not strand an unexported ICMP packet");
            assert_eq!(driver.deadline(), Some(due), "overdue work must remain a next-turn trigger");
            let mut packet = [0; 1280];
            assert!(matches!(reader.recv(&mut packet), Err(error) if error.kind() == io::ErrorKind::WouldBlock));

            tokio::time::sleep_until(tokio::time::Instant::from_std(driver.deadline().unwrap())).await;
            let mut emitted = 0;
            crate::tun::service_turn(std::slice::from_mut(&mut driver), &mut cx, Instant::now(), |drivers, cx| {
                let driver = &mut drivers[0];
                for class in [TxClass::Control, TxClass::Bulk] {
                    if let Some(output) = exported(driver, cx, class) {
                        assert_eq!(writer.send(output.packet())?, output.packet().len());
                        output.release();
                        emitted += 1;
                    }
                }
                Ok(false)
            })
            .unwrap();
            assert_eq!(emitted, 1, "the deadline alone must deliver the expired fragment's reply");
            let length = reader.recv(&mut packet).unwrap();
            let ip = wire::parse_ip(&packet[..length]).unwrap();
            assert_eq!((ip.src, ip.dst), (destination.ip(), source.ip()));
            let message = &packet[ip.payload];
            assert_eq!((message[0], message[1]), (if source.is_ipv6() { 3 } else { 11 }, 1));
            assert_eq!(&message[8..], &first[..if source.is_ipv6() { 56 } else { 28 }]);
            assert!(matches!(reader.recv(&mut packet), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
            assert_eq!(driver.deadline(), None);
            scope.shutdown(true);
            driver.service(&mut cx, Instant::now());
            assert!(owner.reclaim().await);
            owner.run().await;
        }
    })
    .await
    .expect("expiry after the output pass must reach the next turn without fresh input");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn tun_dual_turn_services_timers_and_close_while_shared_output_is_blocked() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let now = Instant::now();
        let due = now + Duration::from_millis(20);
        let budget = MemoryBudget::new(32 << 20);
        let mut scopes = Vec::new();
        let mut owners = Vec::new();
        let mut drivers = Vec::new();
        for port in [40000, 40001] {
            let source = SocketAddr::from(([10, 0, 0, 2], port));
            let destination = "203.0.113.9:443".parse().unwrap();
            let mut cfg = config();
            cfg.fragment_limits.timeout = Duration::from_millis(20);
            let (scope, owner) = PacketScope::new(cfg, Arc::clone(&budget), limits(), now).unwrap();
            let mut peer = Stack::new(config(), now);
            let mut packet = [0; 1280];
            let length = peer
                .udp_send_from(source, destination, &[7; 4000], &mut packet)
                .unwrap();
            assert_eq!(scope.receive(&packet[..length], now), Rx::Consumed);
            scope
                .datagram_sender(destination)
                .send_to(b"pending", source)
                .await
                .unwrap();
            drivers.push(owner.hand_off());
            owners.push(owner);
            scopes.push(scope);
        }
        let (writer, reader) = std::os::unix::net::UnixDatagram::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        loop {
            match writer.send(&[0; 1280]) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("fill shared output: {error}"),
            }
        }
        let mut pending = Vec::new();
        crate::tun::service_turn(&mut drivers, &mut context(), now, |drivers, cx| {
            for driver in drivers {
                let output = exported(driver, cx, TxClass::Bulk).unwrap();
                assert_eq!(
                    writer.send(output.packet()).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                pending.push(output);
                assert_eq!(driver.deadline(), Some(due));
            }
            Ok(false)
        })
        .unwrap();
        crate::tun::service_turn(&mut drivers, &mut context(), due, |drivers, cx| {
            for driver in drivers {
                let output = exported(driver, cx, TxClass::Control)
                    .expect("each scope must expire its fragment behind blocked bulk output");
                assert_eq!(
                    writer.send(output.packet()).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                pending.push(output);
            }
            Ok(false)
        })
        .unwrap();
        assert_eq!(pending.len(), 4);
        for scope in &scopes {
            scope.shutdown(true);
        }
        crate::tun::service_turn(&mut drivers, &mut context(), due, |_, _| Ok(false)).unwrap();
        for scope in &scopes {
            assert!(
                !scope.0.inner.lock().finished,
                "blocked output retains its original scope"
            );
        }
        for output in pending {
            output.release();
        }
        crate::tun::service_turn(&mut drivers, &mut context(), due, |_, _| Ok(false)).unwrap();
        for owner in owners {
            assert!(owner.reclaim().await);
            owner.run().await;
        }
        drop((drivers, scopes));
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("both original scopes must finish without writable output or fresh ingress");
}

#[tokio::test]
async fn driven_scope_progresses_from_application_work_without_ingress() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let now = Instant::now();
        let (scope, owner, _) = runtime(now);
        let mut driver = owner.hand_off();
        let client: SocketAddr = "10.0.0.2:40000".parse().unwrap();
        assert_eq!(
            scope.receive(&segment(client, 100, 0, tcp::SYN, &[]), now),
            Rx::Consumed
        );
        let (_, mut io) = scope.poll_accept().unwrap();
        driver.service(&mut context(), now);
        let synack = exported(&mut driver, &mut context(), TxClass::Control).unwrap();
        let server_seq = decode(&synack).0.seq.wrapping_add(1);
        synack.release();
        assert_eq!(
            scope.receive(&segment(client, 101, server_seq, tcp::ACK, &[]), now),
            Rx::Consumed
        );
        driver.service(&mut context(), now);

        let (armed, waiting) = tokio::sync::oneshot::channel();
        let (outputs, mut received) = tokio::sync::mpsc::channel(2);
        let driven = tokio::spawn(async move {
            let mut armed = Some(armed);
            for _ in 0..2 {
                let output = std::future::poll_fn(|cx| {
                    // No protocol deadline advances in this application-only scenario.
                    driver.service(cx, now + Duration::from_millis(5));
                    for class in [TxClass::Control, TxClass::Bulk] {
                        if let Some(output) = exported(&mut driver, cx, class) {
                            return Poll::Ready(output);
                        }
                    }
                    if let Some(armed) = armed.take() {
                        let _ = armed.send(());
                    }
                    Poll::Pending
                })
                .await;
                outputs.send(output).await.unwrap();
            }
            driver
        });

        waiting.await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut io, b"app")
            .await
            .unwrap();
        let data = received.recv().await.unwrap();
        let (header, payload) = decode(&data);
        assert_eq!(header.seq, server_seq);
        assert_eq!(payload, b"app");
        data.release();
        drop(io);
        let fin = received.recv().await.unwrap();
        let header = decode(&fin).0;
        assert_ne!(header.flags & tcp::FIN, 0);
        assert_eq!(header.seq, server_seq.wrapping_add(3));
        fin.release();
        let mut driver = driven.await.unwrap();
        scope.shutdown(true);
        driver.service(&mut context(), now + Duration::from_millis(5));
        assert!(owner.reclaim().await);
        owner.run().await;
    })
    .await
    .expect("application work must deliver real output through the sleeping device task");
}

#[tokio::test]
async fn handback_is_authoritative_state_and_never_completion_proof() {
    let now = Instant::now();
    // Returned before the parked owner first polls: its state check observes it.
    let (scope, owner, _) = runtime(now);
    let mut driver = owner.hand_off();
    scope.shutdown(false);
    assert!(!driver.service(&mut context(), now));
    assert!(scope.0.inner.lock().finished);
    assert!(owner.reclaim().await);
    drop(driver);
    assert!(
        scope.0.inner.lock().rights == Rights::Task,
        "a returned driver's Drop cannot overwrite the reclaimed owner"
    );
    owner.run().await;

    // Abandoned while the owner is parked: it takes back the unfinished cleanup.
    let (scope, owner, _) = runtime(now);
    let driver = owner.hand_off();
    {
        let mut parked = std::pin::pin!(owner.reclaim());
        assert!(futures::poll!(&mut parked).is_pending());
        drop(driver);
        let reclaimed = tokio::time::timeout(Duration::from_secs(5), parked).await;
        assert!(!reclaimed.expect("driver Drop must wake the parked original owner"));
    }
    assert!(!scope.0.inner.lock().finished);
    scope.shutdown(true);
    owner.run().await;

    // A Returned flag on an unfinished scope is not a successful return.
    let (scope, owner, _) = runtime(now);
    let driver = owner.hand_off();
    scope.0.inner.lock().rights = Rights::Returned;
    assert!(!owner.reclaim().await);
    drop(driver);
    assert!(scope.0.inner.lock().rights == Rights::Task);
    scope.shutdown(true);
    owner.run().await;
}

#[tokio::test]
async fn held_output_blocks_driver_return_until_its_actual_release() {
    let now = Instant::now();
    let (scope, owner, _) = runtime(now);
    let mut driver = owner.hand_off();
    let mut cx = context();
    scope
        .datagram_sender("203.0.113.9:53".parse().unwrap())
        .send_to(b"held", "10.0.0.2:40000".parse().unwrap())
        .await
        .unwrap();
    let held = exported(&mut driver, &mut cx, TxClass::Bulk).unwrap();
    scope.shutdown(true);
    assert!(!driver.service(&mut cx, now));
    assert!(!scope.0.inner.lock().finished);
    assert!(scope.0.inner.lock().rights == Rights::Driven);
    held.release();
    assert!(!driver.service(&mut cx, now));
    assert!(scope.0.inner.lock().rights == Rights::Returned);
    assert!(owner.reclaim().await);
    owner.run().await;
}

#[tokio::test]
async fn driven_refund_fallback_stays_armed_until_serviced() {
    let now = Instant::now();
    let (scope, owner, _) = runtime(now);
    let mut driver = owner.hand_off();
    let mut cx = context();
    let sender = scope.datagram_sender("203.0.113.9:53".parse().unwrap());
    let client = "10.0.0.2:40000".parse().unwrap();
    sender.send_to(b"held", client).await.unwrap();
    let held = exported(&mut driver, &mut cx, TxClass::Bulk).unwrap();
    let mut blocked = std::pin::pin!(sender.send_to(b"next", client));
    assert!(blocked.as_mut().poll(&mut context()).is_pending());
    assert!(!driver.service(&mut cx, now));
    let armed = now + READINESS_FALLBACK;
    assert_eq!(driver.deadline(), Some(armed));
    assert!(!driver.service(&mut cx, now + READINESS_FALLBACK / 2));
    assert_eq!(
        driver.deadline(),
        Some(armed),
        "unrelated device polls must not postpone the refund check"
    );
    assert!(!driver.service(&mut cx, armed));
    assert_eq!(driver.deadline(), Some(armed + READINESS_FALLBACK));
    held.release();
    assert!(matches!(
        blocked.as_mut().poll(&mut context()),
        Poll::Ready(Ok(4))
    ));
    assert!(!driver.service(&mut cx, armed));
    assert_eq!(driver.deadline(), None, "no waiter, no fallback");
}

#[tokio::test]
async fn driven_shared_refund_resumes_a_sleeping_writer_without_ingress() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for direct in [false, true] {
            let now = Instant::now();
            let (scope, owner, budget) = runtime(now);
            let client = "10.0.0.2:40000".parse().unwrap();
            let (mut io, _) = handshake(&scope, now, client, 100);
            assert!(matches!(
                std::pin::Pin::new(&mut io).poll_write(&mut context(), &[7; 4096]),
                Poll::Ready(Ok(4096))
            ));
            let other_owner = budget.reserve(budget.limit() - budget.used()).unwrap();
            let mut driver = owner.hand_off();
            let (blocked, waiting) = tokio::sync::oneshot::channel();
            let writer = tokio::spawn(async move {
                let mut blocked = Some(blocked);
                let written = std::future::poll_fn(|cx| {
                    let result = std::pin::Pin::new(&mut io).poll_write(cx, &[9]);
                    if result.is_pending()
                        && let Some(blocked) = blocked.take()
                    {
                        let _ = blocked.send(());
                    }
                    result
                })
                .await
                .unwrap();
                (io, written)
            });
            waiting.await.unwrap();

            let (armed, asleep) = tokio::sync::oneshot::channel();
            let watched = scope.clone();
            let driven = tokio::spawn(async move {
                let timer: Option<tokio::time::Sleep> = None;
                tokio::pin!(timer);
                let mut armed = Some(armed);
                std::future::poll_fn(|cx| {
                    let now = Instant::now();
                    if direct {
                        driver.begin_turn(now);
                        driver.finish_turn(cx, now);
                    } else {
                        driver.service(cx, now);
                    }
                    if watched.0.inner.lock().finished {
                        return Poll::Ready(());
                    }
                    if let Some(deadline) = driver.deadline() {
                        let deadline = tokio::time::Instant::from_std(deadline);
                        if let Some(mut sleep) = timer.as_mut().as_pin_mut() {
                            sleep.as_mut().reset(deadline);
                        } else {
                            timer.set(Some(tokio::time::sleep_until(deadline)));
                        }
                        if timer.as_mut().as_pin_mut().unwrap().poll(cx).is_ready() {
                            cx.waker().wake_by_ref();
                        }
                    } else {
                        timer.set(None);
                    }
                    if let Some(armed) = armed.take() {
                        let _ = armed.send(());
                    }
                    Poll::Pending
                })
                .await;
                driver
            });
            asleep.await.unwrap();
            // A shared-budget reservation refund has no scope notification.
            drop(other_owner);
            let (io, written) = writer.await.unwrap();
            assert_eq!(written, 1);
            scope.shutdown(true);
            drop(io);
            let driver = driven.await.unwrap();
            assert!(owner.reclaim().await);
            owner.run().await;
            drop(driver);
        }
    })
    .await
    .expect("the conditional deadline must service a writer after an unnotified budget refund");
}

#[test]
fn direct_reservation_refusals_preserve_unsent_bytes_and_other_class_progress() {
    let now = Instant::now();
    let (scope, owner, budget) = runtime(now);
    let client = "10.0.0.2:40000".parse().unwrap();
    let (mut io, server_seq) = handshake(&scope, now, client, 100);
    let mut driver = owner.hand_off();
    let backing: Vec<_> = scope
        .0
        .inner
        .lock()
        .frames
        .iter()
        .map(|frame| frame.as_ref().unwrap().as_ptr() as usize)
        .collect();
    let mut packet = [0xa5; 1280];
    let before = scope.stats().unwrap().tx_packets;
    for class in [TxClass::Control, TxClass::Bulk] {
        for _ in 0..3 {
            assert!(matches!(
                driver.materialize_into(now, class, &mut packet).unwrap(),
                MaterializedOutput::Idle
            ));
            assert_eq!(packet, [0xa5; 1280]);
            let mut inner = scope.0.inner.lock();
            let lease = inner.ledger.reserve_tx(class).unwrap();
            inner.ledger.cancel_tx(lease).unwrap();
            assert!(inner.output_peers.iter().all(Option::is_none));
            assert_eq!(inner.queued, 0);
        }
    }
    let first = b"first-unsent";
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), first),
        Poll::Ready(Ok(n)) if n == first.len()
    ));
    let error = driver
        .materialize_into(now, TxClass::Bulk, &mut packet[..1279])
        .err()
        .expect("undersized capacity must fail before emission");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(scope.stats().unwrap().tx_packets, before);
    assert_eq!(packet, [0xa5; 1280]);
    let unavailable = scope
        .0
        .inner
        .lock()
        .ledger
        .reserve_tx(TxClass::Bulk)
        .unwrap();
    assert!(matches!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut packet)
            .unwrap(),
        MaterializedOutput::Idle
    ));
    assert_eq!(scope.stats().unwrap().tx_packets, before);
    assert_eq!(packet, [0xa5; 1280]);
    let stranger = "10.0.0.3:40001".parse().unwrap();
    scope.receive(&segment(stranger, 1, 700, tcp::ACK, &[]), now);
    driver.begin_turn(now);
    let control = materialized(&mut driver, now, TxClass::Control, &mut packet);
    assert_eq!(decode_packet(&packet[..control.len()]).0.flags, tcp::RST);
    drop(control);
    scope.0.inner.lock().ledger.cancel_tx(unavailable).unwrap();
    let held = materialized(&mut driver, now, TxClass::Bulk, &mut packet);
    let (header, payload) = decode_packet(&packet[..held.len()]);
    assert_eq!(
        (header.seq, payload.as_slice()),
        (server_seq, first.as_slice())
    );
    let original = packet;
    let next = b"next-unsent";
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), next),
        Poll::Ready(Ok(n)) if n == next.len()
    ));
    let before = scope.stats().unwrap().tx_packets;
    assert!(matches!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut packet)
            .unwrap(),
        MaterializedOutput::Idle
    ));
    assert_eq!(scope.stats().unwrap().tx_packets, before);
    assert_eq!(packet, original);
    {
        let inner = scope.0.inner.lock();
        assert_plain_frame_charge(&inner, &budget, 2 * 1280);
        assert_eq!(
            inner
                .frames
                .iter()
                .map(|frame| frame.as_ref().unwrap().as_ptr() as usize)
                .collect::<Vec<_>>(),
            backing
        );
    }
    drop(held);
    let sent = materialized(&mut driver, now, TxClass::Bulk, &mut packet);
    let (header, payload) = decode_packet(&packet[..sent.len()]);
    assert_eq!(header.seq, server_seq.wrapping_add(first.len() as u32));
    assert_eq!(payload, next);
    drop(sent);
    let pending = b"closed-unsent";
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), pending),
        Poll::Ready(Ok(n)) if n == pending.len()
    ));
    scope.0.inner.lock().ledger.close();
    let before = scope.stats().unwrap().tx_packets;
    let original = packet;
    assert!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut packet)
            .is_err()
    );
    assert_eq!(scope.stats().unwrap().tx_packets, before);
    assert_eq!(packet, original);
    let tx = scope
        .0
        .inner
        .lock()
        .stack
        .as_mut()
        .unwrap()
        .poll_transmit_with(now, &mut packet, TxCaps::NONE)
        .unwrap();
    assert_eq!(decode_packet(&packet[..tx.len]).1, pending);
    scope.shutdown(true);
    drop(io);
    assert!(matches!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut packet)
            .unwrap(),
        MaterializedOutput::Closed
    ));
    driver.finish_turn(&mut context(), now);
    assert!(scope.0.inner.lock().finished);
}

#[tokio::test]
async fn direct_udp_observes_atomic_cpu_fragment_prefix_for_both_families() {
    for (source, client) in [
        ("203.0.113.9:53", "10.0.0.2:40000"),
        ("[2001:db8::9]:53", "[fd00::2]:40000"),
    ] {
        let now = Instant::now();
        let (source, client): (SocketAddr, SocketAddr) =
            (source.parse().unwrap(), client.parse().unwrap());
        let (scope, owner) = PacketScope::new(
            config(),
            MemoryBudget::new(32 << 20),
            RuntimeLimits {
                bulk_frames: 2,
                ..limits()
            },
            now,
        )
        .unwrap();
        let mut driver = owner.hand_off();
        assert!(exported(&mut driver, &mut context(), TxClass::Bulk).is_none());
        let payload: Vec<_> = (0..4000).map(|n| (n % 251) as u8).collect();
        let sender = scope.datagram_sender(source);
        sender.send_to(&payload, client).await.unwrap();
        let before = scope.stats().unwrap().tx_packets;
        let mut packet = [0xa5; 1280];
        driver.begin_turn(now);
        assert!(matches!(
            driver
                .materialize_into(now, TxClass::Bulk, &mut packet)
                .unwrap(),
            MaterializedOutput::CpuQueuePending
        ));
        assert_eq!(scope.stats().unwrap().tx_packets, before);
        assert_eq!(scope.0.inner.lock().queued, 1);
        assert_eq!(packet, [0xa5; 1280]);
        {
            let mut inner = scope.0.inner.lock();
            let spare = inner.ledger.reserve_tx(TxClass::Bulk).unwrap();
            inner.ledger.cancel_tx(spare).unwrap();
        }
        let first = exported(&mut driver, &mut context(), TxClass::Bulk).unwrap();
        let first_bytes = first.packet().to_vec();
        let fragment_offset = |bytes: &[u8]| {
            let at = if client.is_ipv6() { 42 } else { 6 };
            let field = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
            if client.is_ipv6() {
                usize::from(field & 0xfff8)
            } else {
                usize::from(field & 0x1fff) * 8
            }
        };
        assert_eq!(fragment_offset(&first_bytes), 0);
        let head = if client.is_ipv6() { 48 } else { 20 };
        let mut offset = first_bytes.len() - head;
        let mut receiver = Stack::new(config(), now);
        assert_eq!(receiver.receive(now, &first_bytes), Rx::Consumed);
        first.release();
        let mut completed = false;
        for _ in 0..8 {
            let owner = materialized(&mut driver, now, TxClass::Bulk, &mut packet);
            let bytes = &packet[..owner.len()];
            assert_eq!(fragment_offset(bytes), offset);
            assert_eq!(
                wire::packet_addresses(bytes).unwrap(),
                (source.ip(), client.ip())
            );
            offset += bytes.len() - head;
            match receiver.receive(now, bytes) {
                Rx::Consumed => {}
                Rx::TransparentOwned {
                    src,
                    dst,
                    packet,
                    payload: range,
                    ..
                } => {
                    assert_eq!((src, dst), (source, client));
                    assert_eq!(&packet[range], payload);
                    completed = true;
                }
                other => panic!("direct fragments lost their original datagram: {other:?}"),
            }
            drop(owner);
            if completed {
                break;
            }
        }
        assert!(completed);
        assert_eq!(offset, payload.len() + 8);
        assert!(matches!(
            driver
                .materialize_into(now, TxClass::Bulk, &mut packet)
                .unwrap(),
            MaterializedOutput::Idle
        ));
        for payload in [b"".as_slice(), b"ordinary".as_slice()] {
            sender.send_to(payload, client).await.unwrap();
            assert!(matches!(
                driver
                    .materialize_into(now, TxClass::Bulk, &mut packet)
                    .unwrap(),
                MaterializedOutput::CpuQueuePending
            ));
            let cpu = exported(&mut driver, &mut context(), TxClass::Bulk).unwrap();
            let ip = wire::parse_ip(cpu.packet()).unwrap();
            assert_eq!(
                (ip.src, ip.dst, ip.proto),
                (source.ip(), client.ip(), wire::PROTO_UDP)
            );
            let udp = &cpu.packet()[ip.payload];
            assert!(wire::udp::verify_checksum(ip.src, ip.dst, udp));
            let (src, dst, range) = wire::udp::parse(udp).unwrap();
            assert_eq!(
                (src, dst, &udp[range]),
                (source.port(), client.port(), payload)
            );
            cpu.release();
        }
        driver.finish_turn(&mut context(), now);
        assert_eq!(scope.0.inner.lock().queued, 0);
    }
}

#[test]
fn direct_scope_unwind_cancels_only_unpublished_credit_without_relocking() {
    let now = Instant::now();
    let (scope, owner, budget) = runtime(now);
    let (mut io, _) = handshake(&scope, now, "10.0.0.2:40000".parse().unwrap(), 100);
    let retired = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&retired);
    let callback_scope = scope.clone();
    io.set_retirement_callback(move || {
        let unlocked = callback_scope.0.inner.try_lock().is_some();
        if unlocked {
            let _ = callback_scope.stats();
        }
        observed.fetch_add(if unlocked { 1 } else { 100 }, Ordering::SeqCst);
    })
    .unwrap();
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), b"guarded-original"),
        Poll::Ready(Ok(16))
    ));
    let mut driver = owner.hand_off();
    let before = scope.stats().unwrap().tx_packets;
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut inner = scope.0.inner.lock();
        let lease = inner.ledger.reserve_tx(TxClass::Bulk).unwrap();
        let _reservation = OutputReservation {
            inner: &mut inner,
            lease: Some(lease),
        };
        panic!("before the real emitter");
    }));
    assert!(unwind.is_err());
    assert_eq!(scope.stats().unwrap().tx_packets, before);
    let mut packet = [0; 1280];
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        driver.begin_turn(now);
        let _emitted = materialized(&mut driver, now, TxClass::Bulk, &mut packet);
        assert_eq!(
            decode_packet(&packet[.._emitted.len()]).1,
            b"guarded-original"
        );
        scope.shutdown(true);
        drop(io);
        assert_eq!(retired.load(Ordering::SeqCst), 0);
        panic!("after the real emitted owner, before device publication");
    }));
    assert!(unwind.is_err());
    assert_eq!(retired.load(Ordering::SeqCst), 1);
    {
        let mut inner = scope.0.inner.lock();
        assert!(inner.frames.iter().all(Option::is_some));
        assert_plain_frame_charge(&inner, &budget, 2 * 1280);
        assert_eq!(inner.ledger.outstanding_tx().count(), 0);
        assert!(inner.output_peers.iter().all(Option::is_none));
        assert!(inner.slots.iter().all(Option::is_none));
        for class in [TxClass::Control, TxClass::Bulk] {
            let lease = inner.ledger.reserve_tx(class).unwrap();
            inner.ledger.cancel_tx(lease).unwrap();
        }
    }
    driver.finish_turn(&mut context(), now);
    assert!(scope.0.inner.lock().finished);
    assert!(scope.0.inner.lock().rights == Rights::Returned);
}

#[test]
fn mixed_direct_cpu_return_finishes_panicking_callback_before_other_scope() {
    let now = Instant::now();
    let client = "10.0.0.2:40000".parse().unwrap();
    let mut runtimes = Vec::new();
    let mut outputs = Vec::new();
    for index in 0..2 {
        let (scope, owner, _) = runtime(now);
        let (mut io, _) = handshake(&scope, now, client, 100);
        let retired = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&retired);
        let callback_scope = scope.clone();
        io.set_retirement_callback(move || {
            assert!(callback_scope.0.inner.try_lock().is_some());
            let _ = callback_scope.stats();
            observed.fetch_add(1, Ordering::SeqCst);
            if index == 0 {
                panic!("retirement callback");
            }
        })
        .unwrap();
        assert!(matches!(
            std::pin::Pin::new(&mut io).poll_write(&mut context(), b"cpu-held"),
            Poll::Ready(Ok(8))
        ));
        scope.drive(now);
        let cpu = output(&scope).into_owner();
        let mut driver = owner.hand_off();
        io.abort();
        drop(io);
        driver.begin_turn(now);
        let mut packet = [0; 1280];
        let direct = materialized(&mut driver, now, TxClass::Control, &mut packet);
        assert_eq!(direct.flow_id(), cpu.flow_id());
        assert_ne!(decode_packet(&packet[..direct.len()]).0.flags & tcp::RST, 0);
        scope.shutdown(true);
        outputs.extend([cpu, direct]);
        runtimes.push((scope, owner, driver, retired));
    }
    let mut batch: [Option<&mut OutputOwner>; 4] = std::array::from_fn(|_| None);
    for (cell, output) in batch.iter_mut().zip(&mut outputs) {
        *cell = Some(output);
    }
    batch.swap(1, 2);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        OutputOwner::release_batch(&mut batch);
    }));
    assert!(unwind.is_err());
    assert!(batch[0].is_none() && batch[2].is_none());
    assert!(batch[1].is_some() && batch[3].is_some());
    assert_eq!(runtimes[0].3.load(Ordering::SeqCst), 1);
    assert_eq!(runtimes[1].3.load(Ordering::SeqCst), 0);
    assert!(
        runtimes[0]
            .0
            .0
            .inner
            .lock()
            .slots
            .iter()
            .all(Option::is_none)
    );
    assert_eq!(
        runtimes[1].0.0.inner.lock().ledger.outstanding_tx().count(),
        2
    );
    OutputOwner::release_batch(&mut batch);
    assert!(batch.iter().all(Option::is_none));
    drop(outputs);
    for (scope, _owner, mut driver, retired) in runtimes {
        assert_eq!(retired.load(Ordering::SeqCst), 1);
        let inner = scope.0.inner.lock();
        assert!(inner.frames.iter().all(Option::is_some));
        assert!(inner.slots.iter().all(Option::is_none));
        assert!(inner.output_peers.iter().all(Option::is_none));
        assert_eq!(inner.ledger.outstanding_tx().count(), 0);
        drop(inner);
        driver.finish_turn(&mut context(), now);
        assert!(scope.0.inner.lock().finished);
    }
}

#[test]
fn direct_ack_before_output_return_keeps_original_credit_and_retirement() {
    let now = Instant::now();
    let (scope, owner, _) = runtime(now);
    let client = "10.0.0.2:40000".parse().unwrap();
    let (mut io, server_seq) = handshake(&scope, now, client, 100);
    let id = io.flow_id();
    let retired = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&retired);
    io.set_retirement_callback(move || {
        observed.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap();
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), b"original"),
        Poll::Ready(Ok(8))
    ));
    let mut driver = owner.hand_off();
    let mut frame = [0; 1280];
    driver.begin_turn(now);
    let held = materialized(&mut driver, now, TxClass::Bulk, &mut frame);
    let original = frame;
    let length = held.len();
    assert_eq!(
        scope.receive(
            &segment(client, 101, server_seq.wrapping_add(8), tcp::ACK, &[]),
            now
        ),
        Rx::Consumed
    );
    assert_eq!(
        scope
            .0
            .inner
            .lock()
            .stack
            .as_ref()
            .unwrap()
            .tcp_stats(id)
            .unwrap()
            .outstanding_bytes,
        0
    );
    let mut scratch = [0xa5; 1280];
    assert!(matches!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut scratch)
            .unwrap(),
        MaterializedOutput::Idle
    ));
    assert_eq!(scope.0.inner.lock().ledger.outstanding_tx().count(), 1);
    io.abort();
    drop(io);
    driver.begin_turn(now);
    let reset = materialized(&mut driver, now, TxClass::Control, &mut scratch);
    assert_eq!(reset.flow_id(), Some(id));
    drop(reset);
    scope.shutdown(true);
    driver.finish_turn(&mut context(), now);
    assert!(!scope.0.inner.lock().finished);
    assert_eq!(retired.load(Ordering::SeqCst), 0);
    assert_eq!(frame, original);
    assert_eq!(decode_packet(&frame[..length]).1, b"original");
    assert!(scope.retains_source(client.ip()));
    drop(held);
    assert_eq!(retired.load(Ordering::SeqCst), 1);
    driver.finish_turn(&mut context(), now);
    assert!(scope.0.inner.lock().finished);
}

#[test]
fn direct_output_return_before_ack_preserves_original_retransmit_bytes() {
    let now = Instant::now();
    let (scope, owner, _) = runtime(now);
    let client = "10.0.0.2:40000".parse().unwrap();
    let (mut io, server_seq) = handshake(&scope, now, client, 100);
    let id = io.flow_id();
    let payload = b"independent-retransmit-storage";
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), payload),
        Poll::Ready(Ok(n)) if n == payload.len()
    ));
    let mut driver = owner.hand_off();
    let mut frame = [0; 1280];
    driver.begin_turn(now);
    let sent = materialized(&mut driver, now, TxClass::Bulk, &mut frame);
    assert_eq!(decode_packet(&frame[..sent.len()]).1, payload);
    drop(sent);
    frame.fill(0xcc);
    assert_eq!(scope.0.inner.lock().ledger.outstanding_tx().count(), 0);
    assert_eq!(
        scope
            .0
            .inner
            .lock()
            .stack
            .as_ref()
            .unwrap()
            .tcp_stats(id)
            .unwrap()
            .outstanding_bytes,
        payload.len() as u32
    );
    driver.finish_turn(&mut context(), now);
    let mut retransmitted = false;
    let mut time = now;
    for _ in 0..8 {
        time = driver
            .deadline()
            .expect("unACKed bytes retain a protocol deadline")
            .max(time);
        assert!(time <= now + Duration::from_secs(2));
        driver.begin_turn(time);
        if let MaterializedOutput::Packet(output) = driver
            .materialize_into(time, TxClass::Bulk, &mut frame)
            .unwrap()
        {
            let retransmit = output.owner;
            let (header, bytes) = decode_packet(&frame[..retransmit.len()]);
            assert_eq!(
                (header.seq, bytes.as_slice()),
                (server_seq, payload.as_slice())
            );
            assert_eq!(retransmit.flow_id(), Some(id));
            drop(retransmit);
            retransmitted = true;
        }
        driver.finish_turn(&mut context(), time);
        if retransmitted {
            break;
        }
    }
    assert!(retransmitted);
    assert_eq!(
        scope
            .0
            .inner
            .lock()
            .stack
            .as_ref()
            .unwrap()
            .tcp_stats(id)
            .unwrap()
            .outstanding_bytes,
        payload.len() as u32
    );
    assert_eq!(
        scope.receive(
            &segment(
                client,
                101,
                server_seq.wrapping_add(payload.len() as u32),
                tcp::ACK,
                &[]
            ),
            time
        ),
        Rx::Consumed
    );
    assert_eq!(
        scope
            .0
            .inner
            .lock()
            .stack
            .as_ref()
            .unwrap()
            .tcp_stats(id)
            .unwrap()
            .outstanding_bytes,
        0
    );
}

#[test]
fn direct_turn_refreshes_synack_app_ack_and_pending_close_before_last_disposal() {
    let now = Instant::now();
    let (scope, owner, _) = runtime(now);
    let mut driver = owner.hand_off();
    let client = "10.0.0.2:40000".parse().unwrap();
    let mut cx = context();
    let mut packet = [0; 1280];
    assert_eq!(
        scope.receive(&segment(client, 100, 0, tcp::SYN, &[]), now),
        Rx::Consumed
    );
    let (_, mut io) = scope.poll_accept().unwrap();
    driver.begin_turn(now);
    assert_eq!(scope.0.inner.lock().queued, 0);
    let synack = materialized(&mut driver, now, TxClass::Control, &mut packet);
    let syn = decode_packet(&packet[..synack.len()]).0;
    assert_eq!(syn.flags, tcp::SYN | tcp::ACK);
    driver.finish_turn(&mut cx, now);
    let due = driver
        .deadline()
        .expect("emission arms the SYNACK retransmit timer");
    assert!(due > now);
    drop(synack);
    let early = due - Duration::from_millis(1);
    driver.begin_turn(early);
    assert!(matches!(
        driver
            .materialize_into(early, TxClass::Control, &mut packet)
            .unwrap(),
        MaterializedOutput::Idle
    ));
    driver.finish_turn(&mut cx, early);
    assert_eq!(driver.deadline(), Some(due));
    driver.begin_turn(due);
    let retransmit = materialized(&mut driver, due, TxClass::Control, &mut packet);
    let retrans = decode_packet(&packet[..retransmit.len()]).0;
    assert_eq!(
        (retrans.seq, retrans.ack, retrans.flags),
        (syn.seq, syn.ack, syn.flags)
    );
    driver.finish_turn(&mut cx, due);
    assert_eq!(
        driver.deadline(),
        scope.0.inner.lock().stack.as_ref().unwrap().poll_timeout()
    );
    assert!(driver.deadline().unwrap() > due);
    drop(retransmit);
    let time = due + Duration::from_millis(1);
    let server_seq = syn.seq.wrapping_add(1);
    assert_eq!(
        scope.receive(&segment(client, 101, server_seq, tcp::ACK, &[]), time),
        Rx::Consumed
    );
    driver.begin_turn(time);
    driver.finish_turn(&mut cx, time);
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), b"app"),
        Poll::Ready(Ok(3))
    ));
    driver.begin_turn(time);
    assert_eq!(scope.0.inner.lock().queued, 0);
    let app = materialized(&mut driver, time, TxClass::Bulk, &mut packet);
    assert_eq!(decode_packet(&packet[..app.len()]).1, b"app");
    driver.finish_turn(&mut cx, time);
    assert_eq!(
        driver.deadline(),
        scope.0.inner.lock().stack.as_ref().unwrap().poll_timeout()
    );
    assert!(driver.deadline().is_some());
    drop(app);
    assert_eq!(
        scope.receive(
            &segment(client, 101, server_seq.wrapping_add(3), tcp::ACK, b"peer"),
            time
        ),
        Rx::Consumed
    );
    let ack_time = time + Duration::from_millis(50);
    driver.begin_turn(ack_time);
    let ack = materialized(&mut driver, ack_time, TxClass::Control, &mut packet);
    assert_eq!(decode_packet(&packet[..ack.len()]).0.ack, 105);
    drop(ack);
    let mut bytes = [0; 4];
    let mut read = tokio::io::ReadBuf::new(&mut bytes);
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_read(&mut context(), &mut read),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(read.filled(), b"peer");
    drop(io);
    assert_eq!(scope.0.inner.lock().pending_closes, 1);
    scope.shutdown(false);
    driver.begin_turn(ack_time);
    assert_eq!(scope.0.inner.lock().pending_closes, 0);
    assert_eq!(scope.0.inner.lock().queued, 0);
    let fin = materialized(&mut driver, ack_time, TxClass::Control, &mut packet);
    let (header, payload) = decode_packet(&packet[..fin.len()]);
    assert_eq!(
        (header.flags, header.seq, header.ack),
        (tcp::FIN | tcp::ACK, server_seq.wrapping_add(3), 105)
    );
    assert!(payload.is_empty());
    driver.finish_turn(&mut cx, ack_time);
    assert_eq!(
        driver.deadline(),
        scope.0.inner.lock().stack.as_ref().unwrap().poll_timeout()
    );
    scope.shutdown(true);
    driver.finish_turn(&mut cx, ack_time);
    assert!(!scope.0.inner.lock().finished);
    drop(fin);
    driver.finish_turn(&mut cx, ack_time);
    assert!(scope.0.inner.lock().finished);
    assert!(scope.0.inner.lock().rights == Rights::Returned);
    assert_eq!(driver.deadline(), None);
}

#[test]
fn direct_blocked_turn_keeps_the_shared_budget_deadline_until_serviced() {
    let now = Instant::now();
    let (scope, owner, budget) = runtime(now);
    let (mut io, _) = handshake(&scope, now, "10.0.0.2:40000".parse().unwrap(), 100);
    let (_other_scope, _other_owner) =
        PacketScope::new(config(), Arc::clone(&budget), limits(), now).unwrap();
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), &[7; 4096]),
        Poll::Ready(Ok(4096))
    ));
    let refund = budget.reserve(budget.limit() - budget.used()).unwrap();
    let mut writer_cx = context();
    assert!(
        std::pin::Pin::new(&mut io)
            .poll_write(&mut writer_cx, &[9])
            .is_pending()
    );
    let unavailable = scope
        .0
        .inner
        .lock()
        .ledger
        .reserve_tx(TxClass::Bulk)
        .unwrap();
    let mut driver = owner.hand_off();
    let mut cx = context();
    let mut packet = [0xa5; 1280];
    for time in [now, now + READINESS_FALLBACK / 2] {
        driver.begin_turn(time);
        for class in [TxClass::Control, TxClass::Bulk] {
            assert!(matches!(
                driver.materialize_into(time, class, &mut packet).unwrap(),
                MaterializedOutput::Idle
            ));
        }
        driver.finish_turn(&mut cx, time);
        assert_eq!(driver.deadline(), Some(now + READINESS_FALLBACK));
    }
    assert_eq!(packet, [0xa5; 1280]);
    let due = now + READINESS_FALLBACK;
    driver.begin_turn(due);
    for class in [TxClass::Control, TxClass::Bulk] {
        assert!(matches!(
            driver.materialize_into(due, class, &mut packet).unwrap(),
            MaterializedOutput::Idle
        ));
    }
    driver.finish_turn(&mut cx, due);
    assert_eq!(driver.deadline(), Some(due + READINESS_FALLBACK));
    drop(refund);
    let due = due + READINESS_FALLBACK;
    driver.begin_turn(due);
    assert!(matches!(
        driver
            .materialize_into(due, TxClass::Control, &mut packet)
            .unwrap(),
        MaterializedOutput::Idle
    ));
    driver.finish_turn(&mut cx, due);
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut writer_cx, &[9]),
        Poll::Ready(Ok(1))
    ));
    driver.finish_turn(&mut cx, due);
    assert_eq!(driver.deadline(), None);
    scope.0.inner.lock().ledger.cancel_tx(unavailable).unwrap();
}

#[test]
fn direct_paced_none_refreshes_deadline_without_consuming_the_next_payload() {
    let start = Instant::now();
    let (scope, owner, _) = runtime(start);
    let client = "10.0.0.2:40000".parse().unwrap();
    let mut driver = owner.hand_off();
    let mut packet = [0; 1280];
    scope.receive(&segment(client, 100, 0, tcp::SYN, &[]), start);
    let (_, mut io) = scope.poll_accept().unwrap();
    driver.begin_turn(start);
    let synack = materialized(&mut driver, start, TxClass::Control, &mut packet);
    let mut server_seq = decode_packet(&packet[..synack.len()]).0.seq.wrapping_add(1);
    drop(synack);
    let mut now = start + Duration::from_millis(10);
    scope.receive(&segment(client, 101, server_seq, tcp::ACK, &[]), now);
    // Passive handshake completion has no RTT sample; acknowledged data enables pacing.
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), b"r"),
        Poll::Ready(Ok(1))
    ));
    let warm = materialized(&mut driver, now, TxClass::Bulk, &mut packet);
    assert_eq!(decode_packet(&packet[..warm.len()]).1, b"r");
    server_seq = server_seq.wrapping_add(1);
    drop(warm);
    now += Duration::from_millis(10);
    scope.receive(&segment(client, 101, server_seq, tcp::ACK, &[]), now);
    let mut cx = context();
    driver.begin_turn(now);
    driver.finish_turn(&mut cx, now);
    let payload: Vec<_> = (0..8192).map(|n| (n % 251) as u8).collect();
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), &payload),
        Poll::Ready(Ok(n)) if n == payload.len()
    ));
    driver.begin_turn(now);
    let mut emitted = 0;
    for _ in 0..32 {
        let MaterializedOutput::Packet(output) = driver
            .materialize_into(now, TxClass::Bulk, &mut packet)
            .unwrap()
        else {
            break;
        };
        let owner = output.owner;
        let (header, bytes) = decode_packet(&packet[..owner.len()]);
        assert_eq!(header.seq, server_seq.wrapping_add(emitted as u32));
        assert_eq!(bytes, payload[emitted..emitted + bytes.len()]);
        emitted += bytes.len();
        drop(owner);
    }
    assert!(emitted > 0 && emitted < payload.len());
    assert!(matches!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut packet)
            .unwrap(),
        MaterializedOutput::Idle
    ));
    driver.finish_turn(&mut cx, now);
    let due = driver
        .deadline()
        .expect("paced None must expose its new deadline");
    assert!(due > now);
    assert_eq!(
        Some(due),
        scope.0.inner.lock().stack.as_ref().unwrap().poll_timeout()
    );
    driver.begin_turn(now);
    assert!(matches!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut packet)
            .unwrap(),
        MaterializedOutput::Idle
    ));
    driver.finish_turn(&mut cx, now);
    assert_eq!(driver.deadline(), Some(due));
    driver.begin_turn(due);
    let next = materialized(&mut driver, due, TxClass::Bulk, &mut packet);
    let (header, bytes) = decode_packet(&packet[..next.len()]);
    assert_eq!(header.seq, server_seq.wrapping_add(emitted as u32));
    assert_eq!(bytes, payload[emitted..emitted + bytes.len()]);
    assert_eq!(scope.0.inner.lock().queued, 0);
    drop(next);
    driver.finish_turn(&mut cx, due);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn auxiliary_old_retirement_guard_cannot_abort_reused_flow_id() {
    let root = MemoryBudget::new(4 << 20);
    let (scope, owner) = auxiliary_scope(1420, &root).unwrap();
    let mut driver = owner.hand_off();
    let client = "192.0.2.4:40000".parse().unwrap();
    driver.resume_auxiliary(1420, || true).unwrap();
    let (old_flow, _) = handshake(&scope, Instant::now(), client, 1);
    let guard = old_flow.retirement();
    let old_id = old_flow.flow_id();
    driver.begin_auxiliary_pause().unwrap();
    {
        let mut drain = pin!(driver.drain_auxiliary());
        assert!(futures::poll!(&mut drain).is_pending());
        drop(old_flow);
        drain.await.unwrap();
    }
    driver.resume_auxiliary(1500, || true).unwrap();
    let (new_flow, _) = handshake(&scope, Instant::now(), client, 2);
    assert_eq!(old_id, new_flow.flow_id());
    assert!(guard.on_retired(|| panic!("stale registration")).is_err());
    drop(guard);
    assert_eq!(
        scope
            .0
            .inner
            .lock()
            .stack
            .as_ref()
            .unwrap()
            .tcp_state(old_id),
        Some(honk_netstack::TcpState::Established)
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn auxiliary_rebind_waits_for_output_and_invalidates_retained_senders() {
    let root = MemoryBudget::new(8 << 20);
    let (scope, owner) = auxiliary_scope(1280, &root).unwrap();
    let record = scope
        .auxiliary_budget()
        .unwrap()
        .reserve(crate::tun::MAX_IP_BYTES + 11)
        .unwrap();
    let (other, other_owner) = auxiliary_scope(1500, &root).unwrap();
    assert_eq!(root.used(), 8 << 20);
    assert!(Arc::ptr_eq(&scope.budget(), &root));
    let mut driver = owner.hand_off();
    let mut other_driver = other_owner.hand_off();
    let realm = PacketRealm::singleton(scope.clone()).unwrap();
    let source = "203.0.113.9:443".parse().unwrap();
    let client = "192.0.2.1:43000".parse().unwrap();
    let offline = realm.datagram_sender(source);
    assert!(offline.send_to(b"offline", client).await.is_err());
    driver.resume_auxiliary(1280, || true).unwrap();
    other_driver.resume_auxiliary(1500, || true).unwrap();
    let old = realm.datagram_sender(source);
    let unaffected = other.datagram_sender(source);
    old.send_to(b"exported", client).await.unwrap();
    let exported = output(&scope);
    let waiting = loop {
        let mut send = Box::pin(old.send_to(b"waiting for credit", client));
        match futures::poll!(&mut send) {
            Poll::Ready(result) => {
                result.unwrap();
            }
            Poll::Pending => break send,
        }
    };
    let work = scope.auxiliary_work().unwrap().unwrap();
    driver.begin_auxiliary_pause().unwrap();
    work.cancelled().await;
    {
        let mut drain = pin!(driver.drain_auxiliary());
        assert!(futures::poll!(&mut drain).is_pending());
        unaffected.send_to(b"sibling", client).await.unwrap();
        assert!(output(&other).packet().ends_with(b"sibling"));
        assert!(exported.packet().ends_with(b"exported"));
        drop(exported);
        assert!(futures::poll!(&mut drain).is_pending());
        drop(work);
        assert!(futures::poll!(&mut drain).is_pending());
        let error = waiting.await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(error.get_ref().unwrap().is::<AuxiliaryBindingRetired>());
        drain.await.unwrap();
    }
    driver.resume_auxiliary(9000, || true).unwrap();
    assert!(offline.send_to(b"late", client).await.is_err());
    assert!(old.send_to(b"late", client).await.is_err());
    scope
        .datagram_sender(source)
        .send_to(b"replacement", client)
        .await
        .unwrap();
    assert!(output(&scope).packet().ends_with(b"replacement"));
    let last = scope.auxiliary_work().unwrap().unwrap();
    scope.shutdown(true);
    assert!(driver.resume_auxiliary(1500, || true).is_err());
    driver.service_closing(&mut context(), Instant::now());
    assert!(driver.is_returned());
    {
        let mut done = pin!(driver.wait_auxiliary_work());
        assert!(futures::poll!(&mut done).is_pending());
        drop(last);
        done.await.unwrap();
    }
    drop((
        driver,
        other_driver,
        old,
        offline,
        unaffected,
        realm,
        scope,
        other,
        owner,
        other_owner,
    ));
    assert_eq!(root.used(), 4 << 20);
    drop(record);
    assert_eq!(root.used(), 0);
}
