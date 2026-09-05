use super::*;
#[tokio::test]
async fn successful_offer_releases_reusable_admission_permit() {
    let pool_a = Arc::new(pool(SessionPoolConfig::default()));
    let pool_b = Arc::new(pool(SessionPoolConfig::default()));
    let generation =
        crate::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 1, 1, None)
            .unwrap()
            .0;
    let admission = generation
        .scope_dials(async { crate::runtime::capture_dial_admission() })
        .await;
    pool_a.set_dial_admission(admission.clone());
    pool_b.set_dial_admission(admission);

    let offer_admission = pool_a
        .dial_admission
        .read()
        .clone()
        .expect("test pool admission bound");
    offer_admission
        .scope(pool_a.offer(|| async {
            crate::runtime::admit_physical_dial(async {
                Ok::<_, anyhow::Error>(TestSession::new())
            })
            .await
        }))
        .await
        .unwrap();

    tokio::time::timeout(
        Duration::from_millis(100),
        generation.scope_dials(crate::runtime::admit_physical_dial(async {
            Ok::<_, anyhow::Error>(())
        })),
    )
    .await
    .expect("completed pool offer retained its physical dial permit")
    .unwrap();
    assert!(!pool_b.is_retired());
}

#[tokio::test]
async fn late_janitor_start_uses_rebound_generation_limit() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pool = Arc::new(pool(SessionPoolConfig {
        max_sessions: 1,
        janitor_interval: Duration::from_millis(10),
        ..Default::default()
    }));
    let predecessor = crate::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
        .unwrap()
        .0;
    let successor = crate::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
        .unwrap()
        .0;
    predecessor
        .scope_dials(async {
            pool.set_dial_admission(crate::runtime::capture_dial_admission());
        })
        .await;
    successor
        .scope_dials(async {
            pool.set_dial_admission(crate::runtime::capture_dial_admission());
        })
        .await;
    let held = successor.acquire_dial_permit().await;
    let started = Arc::new(AtomicBool::new(false));
    let started_notify = Arc::new(tokio::sync::Notify::new());
    predecessor
        .scope_dials(async {
            pool.ensure_janitor(1, Duration::from_secs(60), {
                let started = Arc::clone(&started);
                let started_notify = Arc::clone(&started_notify);
                move || {
                    let started = Arc::clone(&started);
                    let started_notify = Arc::clone(&started_notify);
                    async move {
                        let stream =
                            crate::address_race::race_resolved_addrs(&[addr], move |addr| {
                                let started = Arc::clone(&started);
                                let started_notify = Arc::clone(&started_notify);
                                async move {
                                    started.store(true, Ordering::Release);
                                    started_notify.notify_one();
                                    tokio::net::TcpStream::connect(addr).await
                                }
                            })
                            .await
                            .expect("one address")?;
                        drop(stream);
                        Ok(TestSession::new())
                    }
                }
            });
        })
        .await;

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !started.load(Ordering::Acquire),
        "janitor replacement bypassed the physical dial limit"
    );
    drop(held);
    tokio::time::timeout(Duration::from_secs(1), started_notify.notified())
        .await
        .expect("admitted janitor replacement did not start");
    let (_server, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .expect("janitor replacement opened no TCP connection")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while pool.metrics().sessions == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("janitor did not publish its replacement session");
    pool.shutdown();
}
