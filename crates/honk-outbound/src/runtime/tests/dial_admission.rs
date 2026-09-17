use super::*;
use std::sync::atomic::AtomicUsize;

#[test]
fn explicit_dial_limit_is_generation_owned() {
    let (registry, _) = OutboundRuntimeRegistry::build_reusing(&[], 7, None).unwrap();
    assert_eq!(registry.dial_limit(), 7);
    let (minimum, _) = OutboundRuntimeRegistry::build_reusing(&[], 0, None).unwrap();
    assert_eq!(minimum.dial_limit(), 1);
}

#[tokio::test]
async fn overlapping_generations_share_the_startup_dial_ceiling() {
    let (first, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 3, 4, 4, None).unwrap();
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(first.acquire_dial_permit().await);
    }

    let (second, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 4, 99, 99, Some(&first))
            .unwrap();
    assert_eq!(second.dial_limit(), 4);
    held.push(second.acquire_dial_permit().await);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), second.acquire_dial_permit())
            .await
            .is_err()
    );

    drop(held.pop());
    tokio::time::timeout(Duration::from_millis(100), second.acquire_dial_permit())
        .await
        .expect("released process capacity must admit the successor");
}

#[tokio::test]
async fn cold_replacement_retains_shared_scope_admission() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (registry, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 1, 1, 1, None).unwrap();
    let (successor, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 1, 1, 1, Some(&registry))
            .unwrap();
    let starts = Arc::new(AtomicUsize::new(0));
    let (scope, original) = registry
        .scope_dials_with_start(
            async {
                let stream = admit_physical_dial(tokio::net::TcpStream::connect(address))
                    .await
                    .unwrap();
                (capture_dial_scope(), stream)
            },
            {
                let starts = Arc::clone(&starts);
                move || {
                    starts.fetch_add(1, Ordering::SeqCst);
                }
            },
        )
        .await;
    drop(original);

    let mut competing = Box::pin(
        successor.scope_dials(admit_physical_dial(tokio::net::TcpStream::connect(address))),
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut competing)
            .await
            .is_err()
    );
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
    let replacement = tokio::spawn(scope.clone().scope(admit_replacement_dial(
        async move {
            let stream = tokio::net::TcpStream::connect(address).await?;
            started_tx.send(()).unwrap();
            finish_rx.await.unwrap();
            Ok::<_, std::io::Error>(stream)
        },
        true,
    )));
    tokio::time::timeout(Duration::from_secs(1), started_rx)
        .await
        .expect("a cold replacement must not reacquire its occupied permit")
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut competing)
            .await
            .is_err(),
        "the replacement must hold process admission throughout its connect"
    );
    finish_tx.send(()).unwrap();
    let stream = replacement.await.unwrap().unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut competing)
            .await
            .is_err(),
        "successful replacement admission must remain in the shared scope"
    );
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    drop((stream, scope));
    tokio::time::timeout(Duration::from_secs(1), competing)
        .await
        .expect("ending the shared scope must release process admission")
        .unwrap();
}

#[tokio::test]
async fn supplied_replacement_cannot_use_a_shared_siblings_permit() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (registry, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 2, 2, 2, None).unwrap();
    let occupied = registry.acquire_dial_permit().await;
    let (scope, sibling) = registry
        .scope_dials(async {
            let stream = admit_physical_dial(tokio::net::TcpStream::connect(address))
                .await
                .unwrap();
            (capture_dial_scope(), stream)
        })
        .await;
    let mut replacement = Box::pin(scope.clone().scope(admit_replacement_dial(
        tokio::net::TcpStream::connect(address),
        false,
    )));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut replacement)
            .await
            .is_err(),
        "supplied sockets cannot borrow a successful sibling's admission"
    );
    drop(occupied);
    let stream = tokio::time::timeout(Duration::from_secs(1), &mut replacement)
        .await
        .expect("released real capacity must admit the supplied replacement")
        .unwrap();
    drop(replacement);

    let mut competing = Box::pin(
        registry.scope_dials(admit_physical_dial(tokio::net::TcpStream::connect(address))),
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut competing)
            .await
            .is_err(),
        "the sibling and successful supplied replacement each occupy admission"
    );
    drop((stream, sibling, scope));
    tokio::time::timeout(Duration::from_secs(1), competing)
        .await
        .expect("ending the shared scope must release both permits")
        .unwrap();
}

#[tokio::test]
async fn replacement_failure_and_cancellation_release_transferred_admission() {
    for cancel in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (registry, _) =
            OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 1, 1, 1, None).unwrap();
        let scope = registry
            .scope_dials(async {
                let stream = admit_physical_dial(tokio::net::TcpStream::connect(address))
                    .await
                    .unwrap();
                drop(stream);
                capture_dial_scope()
            })
            .await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let replacement = tokio::spawn(scope.clone().scope(admit_replacement_dial(
            async move {
                let _stream = tokio::net::TcpStream::connect(address).await?;
                started_tx.send(()).unwrap();
                finish_rx.await.unwrap();
                Err::<(), _>(std::io::Error::other("replacement failed"))
            },
            true,
        )));
        tokio::time::timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("replacement must start before failure or cancellation")
            .unwrap();
        let mut competing = Box::pin(
            registry.scope_dials(admit_physical_dial(tokio::net::TcpStream::connect(address))),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut competing)
                .await
                .is_err()
        );
        if cancel {
            replacement.abort();
            assert!(replacement.await.unwrap_err().is_cancelled());
        } else {
            finish_tx.send(()).unwrap();
            assert!(replacement.await.unwrap().is_err());
        }
        tokio::time::timeout(Duration::from_secs(1), competing)
            .await
            .expect("failed or cancelled replacement must release admission before scope exit")
            .unwrap();
        drop(scope);
    }
}

#[tokio::test]
async fn cold_replacement_without_retained_credit_waits_for_admission() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (registry, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 1, 1, 1, None).unwrap();
    let occupied = registry.acquire_dial_permit().await;
    let scope = registry.scope_dials(async { capture_dial_scope() }).await;
    let mut replacement = Box::pin(scope.scope(admit_replacement_dial(
        tokio::net::TcpStream::connect(address),
        true,
    )));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut replacement)
            .await
            .is_err(),
        "cold provenance alone cannot bypass admission without a retained permit"
    );
    drop(occupied);
    tokio::time::timeout(Duration::from_secs(1), replacement)
        .await
        .expect("replacement without a retained credit must use released capacity")
        .unwrap();
}

#[tokio::test]
async fn one_dial_permit_serializes_real_tcp_fallbacks() {
    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    let first_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_addr = first_listener.local_addr().unwrap();
    let second_addr = second_listener.local_addr().unwrap();
    let addrs = [first_addr, second_addr];
    let release_first = Arc::new(tokio::sync::Notify::new());
    let first_started = Arc::new(tokio::sync::Notify::new());
    let second_started = Arc::new(tokio::sync::Notify::new());
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
            .unwrap()
            .0,
    );

    let dial = tokio::spawn({
        let release_first = Arc::clone(&release_first);
        let first_started = Arc::clone(&first_started);
        let second_started = Arc::clone(&second_started);
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        let generation = Arc::clone(&registry);
        async move {
            generation
                .scope_dials(async move {
                    crate::address_race::race_resolved_addrs_with_stagger(
                        &addrs,
                        Duration::ZERO,
                        move |addr| {
                            let release_first = Arc::clone(&release_first);
                            let first_started = Arc::clone(&first_started);
                            let second_started = Arc::clone(&second_started);
                            let active = Arc::clone(&active);
                            let peak = Arc::clone(&peak);
                            async move {
                                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                                peak.fetch_max(now, Ordering::SeqCst);
                                let _active = Active(active);
                                if addr == second_addr {
                                    second_started.notify_one();
                                }
                                let stream = tokio::net::TcpStream::connect(addr).await?;
                                if addr == first_addr {
                                    first_started.notify_one();
                                    release_first.notified().await;
                                    drop(stream);
                                    Err(std::io::Error::other("first address failed"))
                                } else {
                                    Ok(stream)
                                }
                            }
                        },
                    )
                    .await
                })
                .await
        }
    });

    first_started.notified().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), second_started.notified())
            .await
            .is_err(),
        "the fallback started without a second physical permit"
    );
    release_first.notify_one();
    let winner = dial.await.unwrap().unwrap().unwrap();
    assert_eq!(winner.peer_addr().unwrap(), second_addr);
    assert_eq!(peak.load(Ordering::SeqCst), 1);
    assert_eq!(active.load(Ordering::SeqCst), 0);

    let (mut first_server, _) = first_listener.accept().await.unwrap();
    let (second_server, _) = second_listener.accept().await.unwrap();
    use tokio::io::AsyncReadExt as _;
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_secs(1), first_server.read(&mut byte))
        .await
        .expect("failed TCP attempt stayed open")
        .unwrap();
    assert_eq!(read, 0);
    drop((winner, second_server));
}

#[tokio::test(start_paused = true)]
async fn overlapping_generations_bound_physical_address_attempts() {
    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    let (first, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 2, 2, 2, None).unwrap();
    let (second, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 2, 99, 99, Some(&first))
            .unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let run = |generation: Arc<OutboundRuntimeRegistry>| {
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        async move {
            let addrs = [
                "192.0.2.1:443".parse().unwrap(),
                "[2001:db8::1]:443".parse().unwrap(),
            ];
            generation
                .scope_dials(crate::address_race::race_resolved_addrs_with_stagger(
                    &addrs,
                    Duration::ZERO,
                    move |addr| {
                        let active = Arc::clone(&active);
                        let peak = Arc::clone(&peak);
                        async move {
                            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(now, Ordering::SeqCst);
                            let _active = Active(active);
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            Err::<(), _>(addr)
                        }
                    },
                ))
                .await
        }
    };

    let (old_result, new_result) = tokio::join!(run(Arc::new(first)), run(Arc::new(second)));
    assert!(matches!(old_result, Some(Err(_))));
    assert!(matches!(new_result, Some(Err(_))));
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    assert_eq!(active.load(Ordering::SeqCst), 0);
}
