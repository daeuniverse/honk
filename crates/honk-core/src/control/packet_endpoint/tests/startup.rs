use super::*;

#[cfg(feature = "native-api")]
#[tokio::test]
async fn cancelled_startup_never_activates_and_retains_exported_output() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for maintenance_waiting in [false, true] {
            let budget = MemoryBudget::new(32 << 20);
            let (scope, scope_owner) = scope(&budget);
            let (mut plane, _health) = local_plane().await;
            let native =
                crate::native_api::observation::NativeObservation::attach(&mut plane).await;
            let generation = plane.diagnostics.read().generation;
            let stopped = Arc::clone(&plane.shutdown_requested);
            let config = Arc::clone(&plane.config);
            let config_guard = config.write().await;
            let mut opening = Box::pin(PacketEndpoints::new(
                plane,
                vec![(scope.clone(), scope_owner)],
                1,
            ));
            assert!(futures::poll!(&mut opening).is_pending());
            if maintenance_waiting {
                tokio::task::yield_now().await;
            }
            scope
                .datagram_sender("198.51.100.1:53".parse().unwrap())
                .send_to(b"retained", "192.0.2.1:41000".parse().unwrap())
                .await
                .unwrap();
            let output = scope.next_output().await.unwrap();
            drop(opening);
            drop(config_guard);
            while !stopped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            assert!(native.core.activated_at(generation).is_none());
            assert!(output.packet().ends_with(b"retained"));
            output.release();
            assert!(scope.next_output().await.is_none());
            drop(scope);
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
        endpoints.sender.send(Work::Tcp(flow, slot)).await.unwrap();
        let (_first_peer, _) = first.accept().await.unwrap();
        let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (flow, _) = established_tcp(&scope, second.local_addr().unwrap()).await;
        let id = flow.flow_id();
        let slot = Arc::clone(&endpoints.shared.tcp_slots)
            .acquire_owned()
            .await
            .unwrap();
        endpoints.sender.send(Work::Tcp(flow, slot)).await.unwrap();
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
