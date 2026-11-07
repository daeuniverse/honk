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
            assert!(
                driver
                    .materialize_into(now, class, &mut packet)
                    .unwrap()
                    .is_none()
            );
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
    assert!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut packet)
            .unwrap()
            .is_none()
    );
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
    assert!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut packet)
            .unwrap()
            .is_none()
    );
    assert_eq!(scope.stats().unwrap().tx_packets, before);
    assert_eq!(packet, original);
    {
        let inner = scope.0.inner.lock();
        assert_eq!(inner._storage.bytes(), 2 * 1280);
        assert!(budget.used() >= inner._storage.bytes());
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
    assert!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut packet)
            .unwrap()
            .is_none()
    );
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
        assert!(
            driver
                .materialize_into(now, TxClass::Bulk, &mut packet)
                .unwrap()
                .is_none()
        );
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
        assert!(
            driver
                .materialize_into(now, TxClass::Bulk, &mut packet)
                .unwrap()
                .is_none()
        );
        for payload in [b"".as_slice(), b"ordinary".as_slice()] {
            sender.send_to(payload, client).await.unwrap();
            assert!(
                driver
                    .materialize_into(now, TxClass::Bulk, &mut packet)
                    .unwrap()
                    .is_none()
            );
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
        assert_eq!(inner._storage.bytes(), 2 * 1280);
        assert!(budget.used() >= inner._storage.bytes());
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
    assert!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut scratch)
            .unwrap()
            .is_none()
    );
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
        if let Some(retransmit) = driver
            .materialize_into(time, TxClass::Bulk, &mut frame)
            .unwrap()
        {
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
    assert!(
        driver
            .materialize_into(early, TxClass::Control, &mut packet)
            .unwrap()
            .is_none()
    );
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
            assert!(
                driver
                    .materialize_into(time, class, &mut packet)
                    .unwrap()
                    .is_none()
            );
        }
        driver.finish_turn(&mut cx, time);
        assert_eq!(driver.deadline(), Some(now + READINESS_FALLBACK));
    }
    assert_eq!(packet, [0xa5; 1280]);
    let due = now + READINESS_FALLBACK;
    driver.begin_turn(due);
    for class in [TxClass::Control, TxClass::Bulk] {
        assert!(
            driver
                .materialize_into(due, class, &mut packet)
                .unwrap()
                .is_none()
        );
    }
    driver.finish_turn(&mut cx, due);
    assert_eq!(driver.deadline(), Some(due + READINESS_FALLBACK));
    drop(refund);
    let due = due + READINESS_FALLBACK;
    driver.begin_turn(due);
    assert!(
        driver
            .materialize_into(due, TxClass::Control, &mut packet)
            .unwrap()
            .is_none()
    );
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
        let Some(owner) = driver
            .materialize_into(now, TxClass::Bulk, &mut packet)
            .unwrap()
        else {
            break;
        };
        let (header, bytes) = decode_packet(&packet[..owner.len()]);
        assert_eq!(header.seq, server_seq.wrapping_add(emitted as u32));
        assert_eq!(bytes, payload[emitted..emitted + bytes.len()]);
        emitted += bytes.len();
        drop(owner);
    }
    assert!(emitted > 0 && emitted < payload.len());
    assert!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut packet)
            .unwrap()
            .is_none()
    );
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
    assert!(
        driver
            .materialize_into(now, TxClass::Bulk, &mut packet)
            .unwrap()
            .is_none()
    );
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
