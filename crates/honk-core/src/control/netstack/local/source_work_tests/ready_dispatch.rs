use super::*;
use std::pin::pin;

struct Reenqueue(LocalFlow);

impl Wake for Reenqueue {
    fn wake(self: Arc<Self>) {
        let scope = self.0.0.scope.upgrade().unwrap();
        let shared = scope.local.get().unwrap();
        assert!(shared.ready.try_lock().is_some());
        self.0.mark_rx_admitted();
    }
}

#[tokio::test]
async fn ready_batch_services_outside_lock_and_preserves_reenqueue() {
    let (scope, owner, mut driver) = super::super::tests::physical();
    let shared = scope.0.local.get().unwrap();
    let authority = PeerAuthority::new(Arc::new(true.into()), &scope.0.budget).unwrap();
    let destination = "203.0.113.2:443".parse().unwrap();
    let now = Instant::now();
    let mut cx = Context::from_waker(Waker::noop());
    let [first, second] = [45001, 45002].map(|port| {
        let client = SocketAddr::from(([192, 0, 2, 1], port));
        let (flow, ack) = accept(&mut driver, &authority, client, destination, now);
        receive(
            &mut driver,
            &authority,
            &input(client, destination, 101, ack, tcp::ACK, b""),
            now,
        );
        driver.finish_turn(&mut cx, now);
        flow
    });
    let local = first.local().unwrap().clone();
    let wake = Waker::from(Arc::new(Reenqueue(local.clone())));
    let mut request = pin!(local.attach_remote(None));
    assert!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(&wake))
            .is_pending()
    );
    second.mark_rx_admitted();
    let local_owner = driver.local.as_mut().unwrap();
    assert!(local_owner.dispatch(&scope, now));
    let Poll::Ready(Ok(remote)) = request.as_mut().poll(&mut cx) else {
        panic!("first request serviced without waiting for another turn");
    };
    assert!(
        local_owner
            .inner
            .slot(second.flow_id())
            .unwrap()
            .rx_admitted
    );
    assert!(!local_owner.inner.slot(first.flow_id()).unwrap().rx_admitted);
    assert_eq!(shared.ready.lock().front(), Some(&first.flow_id()));
    assert!(shared.has_ready.load(Ordering::Acquire));
    assert!(!local_owner.dispatch(&scope, now));
    assert!(local_owner.inner.slot(first.flow_id()).unwrap().rx_admitted);
    assert!(!shared.has_ready.load(Ordering::Acquire));

    drop(remote);
    drop(first);
    drop(second);
    scope.shutdown(true);
    driver.service_closing(&mut cx, now);
    assert!(owner.reclaim().await);
    owner.run().await;
}

#[tokio::test]
async fn ready_batch_rearms_for_last_waiting_flow() {
    let budget = MemoryBudget::new(32 << 20);
    let (realm, mut owners) = capture_realm(1280, 32, 1, 1, 1, &budget).unwrap();
    let scope = realm.owners()[0].clone();
    let owner = owners.pop().unwrap();
    let mut driver = owner.hand_off();
    driver.make_local(1).unwrap();
    let shared = scope.0.local.get().unwrap();
    let authority = PeerAuthority::new(Arc::new(true.into()), &budget).unwrap();
    let destination = "203.0.113.2:443".parse().unwrap();
    let now = Instant::now();
    let mut cx = Context::from_waker(Waker::noop());
    let mut flows = Vec::with_capacity(BATCH + 1);
    for n in 0..=BATCH {
        let client = SocketAddr::from(([192, 0, 2, 1], 45_000 + n as u16));
        let (flow, ack) = accept(&mut driver, &authority, client, destination, now);
        receive(
            &mut driver,
            &authority,
            &input(client, destination, 101, ack, tcp::ACK, b""),
            now,
        );
        driver.finish_turn(&mut cx, now);
        flows.push(flow);
    }
    for flow in &flows {
        flow.mark_rx_admitted();
    }
    let last = flows.last().unwrap().flow_id();
    let wake = Arc::new(TurnWake::default());
    let waker = Waker::from(Arc::clone(&wake));
    let mut cx = Context::from_waker(&waker);
    driver.finish_turn(&mut cx, now);
    assert!(wake.0.load(Ordering::Relaxed));
    assert_eq!(shared.ready.lock().len(), 1);
    assert_eq!(shared.ready.lock().front(), Some(&last));
    assert!(
        !driver
            .local
            .as_mut()
            .unwrap()
            .inner
            .slot(last)
            .unwrap()
            .rx_admitted
    );
    driver.finish_turn(&mut cx, now);
    assert!(
        driver
            .local
            .as_mut()
            .unwrap()
            .inner
            .slot(last)
            .unwrap()
            .rx_admitted
    );
    assert!(!shared.has_ready.load(Ordering::Acquire));

    drop(flows);
    scope.shutdown(true);
    for _ in 0..2 {
        driver.service_closing(&mut cx, now);
    }
    assert!(scope.0.inner.lock().finished);
    assert!(owner.reclaim().await);
    owner.run().await;
}
