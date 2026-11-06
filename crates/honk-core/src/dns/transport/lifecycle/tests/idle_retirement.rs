use super::*;

#[tokio::test]
async fn idle_retirement_leaves_borrowed_resource_ready() {
    let slot = Arc::new(LifecycleSlot::new());
    let resource = slot
        .acquire(|| async { Ok::<_, anyhow::Error>(5_u8) })
        .await
        .map(|(value, _)| value)
        .expect("resource");

    assert!(
        slot.retire_idle(|_| async { panic!("borrowed resource must not close") })
            .is_none()
    );

    let current = slot
        .acquire(|| async { panic!("borrowed resource must remain ready") })
        .await
        .map(|(value, _)| value)
        .expect("current resource");
    assert!(Arc::ptr_eq(&current, &resource));
    assert_eq!(slot.state(), LifecycleState::Ready);
    assert_eq!(slot.close_count(), 0);
}

#[tokio::test]
async fn idle_retirement_blocks_replacement_until_close_finishes() {
    let slot = Arc::new(LifecycleSlot::new());
    let resource = slot
        .acquire(|| async { Ok::<_, anyhow::Error>(1_u8) })
        .await
        .map(|(value, _)| value)
        .expect("resource");
    drop(resource);
    let closes = Arc::new(AtomicUsize::new(0));
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let first_closes = Arc::clone(&closes);
    let mut closing = Box::pin(
        slot.retire_idle(move |_| async move {
            release_rx.await.expect("release original cleanup");
            first_closes.fetch_add(1, Ordering::SeqCst);
        })
        .expect("idle resource"),
    );
    assert_eq!(slot.state(), LifecycleState::Closing);
    assert_eq!(closes.load(Ordering::SeqCst), 0);
    assert!(futures::poll!(closing.as_mut()).is_pending());

    let mut acquiring = Box::pin(slot.acquire(|| async { Ok::<_, anyhow::Error>(2_u8) }));
    assert!(futures::poll!(acquiring.as_mut()).is_pending());
    release_tx.send(()).expect("release original cleanup");
    tokio::time::timeout(Duration::from_secs(1), closing)
        .await
        .expect("idle retirement finishes");
    let replacement = tokio::time::timeout(Duration::from_secs(1), acquiring)
        .await
        .expect("replacement finishes")
        .map(|(value, _)| value)
        .expect("replacement");

    assert_eq!(*replacement, 2);
    assert_eq!(closes.load(Ordering::SeqCst), 1);
    assert_eq!(slot.close_count(), 1);
    assert_eq!(slot.state(), LifecycleState::Ready);
}

#[tokio::test]
async fn cancelled_idle_retirement_resumes_retained_close() {
    const NAME: &str = "dns::transport::lifecycle::tests::idle_retirement::cancelled_idle_retirement_resumes_retained_close";
    if crate::test_support::run_exact_in_child("HONK_DNS_TRANSPORT_PRESSURE_STATS_CHILD", NAME) {
        return;
    }
    let before = crate::stats::dns_snapshot();
    let slot = Arc::new(LifecycleSlot::new());
    let resource = slot
        .acquire(|| async { Ok::<_, anyhow::Error>(1_u8) })
        .await
        .map(|(value, _)| value)
        .expect("resource");
    drop(resource);
    let closes = Arc::new(AtomicUsize::new(0));
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let first_closes = Arc::clone(&closes);
    let first = slot
        .retire_idle(move |_| async move {
            release_rx.await.expect("release original cleanup");
            first_closes.fetch_add(1, Ordering::SeqCst);
        })
        .expect("idle resource");
    assert!(
        slot.retire_idle(|_| async { panic!("duplicate idle driver") })
            .is_none()
    );
    drop(first);
    assert_eq!(closes.load(Ordering::SeqCst), 0);

    let mut second = Box::pin(
        slot.retire_idle(|_| async {
            panic!("a second closer must not replace the original cleanup");
        })
        .expect("unpolled driver drop releases retirement"),
    );
    assert!(futures::poll!(second.as_mut()).is_pending());
    assert!(
        slot.retire_idle(|_| async { panic!("duplicate idle driver") })
            .is_none()
    );
    drop(second);

    let mut third = Box::pin(
        slot.retire_idle(|_| async {
            panic!("a second closer must not replace the original cleanup");
        })
        .expect("cancelled driver releases retirement"),
    );
    assert!(futures::poll!(third.as_mut()).is_pending());
    release_tx.send(()).expect("original cleanup retained");
    tokio::time::timeout(Duration::from_secs(1), third)
        .await
        .expect("later retirement resumes original cleanup");

    assert_eq!(closes.load(Ordering::SeqCst), 1);
    assert_eq!(slot.close_count(), 1);
    assert_eq!(slot.state(), LifecycleState::Closed);
    assert_eq!(
        crate::stats::dns_snapshot()
            .delta(before)
            .pressure_retired_transport,
        1
    );
}
