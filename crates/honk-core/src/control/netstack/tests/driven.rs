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
                driver.service(cx, now);
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
    })
    .await
    .expect("the conditional deadline must service a writer after an unnotified budget refund");
}
