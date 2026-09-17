use super::*;
use futures_util::FutureExt;
use std::cell::Cell;
use std::future::ready;
use std::sync::atomic::AtomicUsize;

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
    let (registry, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 1, 1, 1, None).unwrap();
    let (successor, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 1, 1, 1, Some(&registry))
            .unwrap();
    let starts = Arc::new(AtomicUsize::new(0));
    let scope = registry
        .scope_dials_with_start(
            async {
                admit_physical_dial(ready(Ok::<_, ()>(()))).await.unwrap();
                capture_dial_scope()
            },
            {
                let starts = Arc::clone(&starts);
                move || {
                    starts.fetch_add(1, Ordering::SeqCst);
                }
            },
        )
        .await;
    let mut competing = std::pin::pin!(successor.acquire_dial_permit());
    assert!(competing.as_mut().now_or_never().is_none());
    {
        let started = Cell::new(false);
        let mut replacement = std::pin::pin!(scope.clone().scope(admit_replacement_dial(
            async {
                started.set(true);
                tokio::task::yield_now().await;
                Ok::<_, ()>(())
            },
            true,
        )));
        assert!(replacement.as_mut().now_or_never().is_none());
        assert!(
            started.get(),
            "cold replacement must reuse occupied admission"
        );
        assert!(
            competing.as_mut().now_or_never().is_none(),
            "the replacement must hold process admission throughout its connect"
        );
        assert_eq!(replacement.as_mut().now_or_never(), Some(Ok(())));
    }
    assert!(
        competing.as_mut().now_or_never().is_none(),
        "successful replacement admission must remain in the shared scope"
    );
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    drop(scope);
    competing
        .now_or_never()
        .expect("ending the shared scope must release process admission");
}

#[tokio::test]
async fn replacement_failure_and_cancellation_release_transferred_admission() {
    for cancel in [false, true] {
        let (registry, _) =
            OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 1, 1, 1, None).unwrap();
        let scope = registry
            .scope_dials(async {
                admit_physical_dial(ready(Ok::<_, ()>(()))).await.unwrap();
                capture_dial_scope()
            })
            .await;
        let mut competing = std::pin::pin!(registry.acquire_dial_permit());
        {
            let started = Cell::new(false);
            let mut replacement = std::pin::pin!(scope.clone().scope(admit_replacement_dial(
                async {
                    started.set(true);
                    tokio::task::yield_now().await;
                    Err::<(), _>("replacement failed")
                },
                true,
            )));
            assert!(replacement.as_mut().now_or_never().is_none());
            assert!(started.get(), "replacement must start before terminating");
            assert!(competing.as_mut().now_or_never().is_none());
            if !cancel {
                assert_eq!(
                    replacement.as_mut().now_or_never(),
                    Some(Err("replacement failed"))
                );
            }
        }
        competing
            .now_or_never()
            .expect("failed or cancelled replacement must release admission before scope exit");
        drop(scope);
    }
}

#[tokio::test]
async fn cold_replacement_without_retained_credit_waits_for_admission() {
    let (registry, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 1, 1, 1, None).unwrap();
    let occupied = registry.acquire_dial_permit().await;
    let scope = registry.scope_dials(async { capture_dial_scope() }).await;
    let mut replacement =
        std::pin::pin!(scope.scope(admit_replacement_dial(ready(Ok::<_, ()>(())), true)));
    assert!(
        replacement.as_mut().now_or_never().is_none(),
        "cold provenance alone cannot bypass admission without a retained permit"
    );
    drop(occupied);
    replacement
        .now_or_never()
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
