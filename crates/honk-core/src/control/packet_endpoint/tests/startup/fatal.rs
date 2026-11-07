use super::*;
use crate::control::{ControlCommand, EnginePhase, ReloadOutcome, client::SelectionRequest};
use crate::subscription::{AuthorizedSubscription, SubscriptionSupervisor};
use std::task::Poll;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn reload(
    config: honk_config::Config,
) -> (
    ControlCommand,
    tokio::sync::oneshot::Receiver<crate::control::ReloadReply>,
) {
    let (result, reply) = tokio::sync::oneshot::channel();
    (
        ControlCommand::ReloadConfig {
            request_id: 81,
            config: Box::new(config),
            diagnostics: Vec::new(),
            sources: None,
            expected_group_revision: None,
            result,
        },
        reply,
    )
}

#[tokio::test]
async fn fatal_selector_releases_real_config_and_subscription_shutdown_before_cq() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let budget = MemoryBudget::new(64 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (mut plane, _health) = xdp_plane_with("Rule", "block", |config| {
            config.groups[0].interrupt_connections = true;
            config.routing.default_outbound = "packet-control".into();
        }).await;
        let native = crate::native_api::observation::NativeObservation::attach(&mut plane).await;
        let mut phase = plane.observe_phase();
        let commands = plane.command_sender();
        let active_config = Arc::clone(&plane.config);
        let tracker = Arc::clone(&plane.connection_tracker);
        tracker.enable();
        let mut subscriptions = SubscriptionSupervisor::prepare(&mut honk_config::Config::default(), None, Vec::new()).await.unwrap();
        subscriptions.start(commands.clone());
        let subscription_handle = subscriptions.handle();
        let directory = tempfile::tempdir().unwrap();
        let entry = directory.path().join("main.dae");
        std::fs::write(&entry, "global {\n nfqueue_enable: false\n dial_mode: ip\n}\ndatapath {\n backend: xdp\n direct: endpoint\n interface { dut0: lan }\n}\nrouting { fallback: direct }\n").unwrap();
        let service = Arc::clone(&native.configuration);
        service.attach_phase(phase.clone());
        let coordinator = service.start(
            crate::native_api::store::SourceStore::File(entry.into()), None,
            directory.path().to_path_buf(), Arc::clone(&active_config), plane.log_files(),
            plane.startup_downgrades(),
            plane.diagnostics_handle(), commands.clone(), subscription_handle.clone(),
        ).await;
        let (endpoints, mut owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 4).await.unwrap();
        endpoints.capture_ready().unwrap();
        while *phase.borrow() != EnginePhase::Running { phase.changed().await.unwrap(); }

        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (flow, _) = established_tcp(&scope, upstream.local_addr().unwrap()).await;
        let permit = Arc::clone(&endpoints.shared.tcp_slots).acquire_owned().await.unwrap();
        endpoints.sender.send(Work::Tcp(flow, permit)).await.unwrap();
        let (mut server, _) = upstream.accept().await.unwrap();
        server.write_all(b"CQ-held selector reply").await.unwrap();
        let output = loop {
            let output = scope.next_output().await.unwrap();
            if output.packet().ends_with(b"CQ-held selector reply") { break output; }
            output.release();
        };
        assert_eq!(tracker.snapshot().len(), 1);
        let late_permit = commands.clone().reserve_owned().await.unwrap();
        let (result, selector_reply) = tokio::sync::oneshot::channel();
        commands.send(ControlCommand::SetSelector {
            request: SelectionRequest::Name { group: "packet-control".into(), member: "block".into() },
            reply: result,
        }).await.unwrap();
        assert_eq!(server.read(&mut [0; 1]).await.unwrap(), 0, "real selector cancellation closes the upstream before waiting for packet retirement");
        assert_eq!(tracker.snapshot().len(), 1, "CQ output keeps the actual interruption unfinished");
        let mut selector_reply = Box::pin(selector_reply);
        assert!(futures::poll!(&mut selector_reply).is_pending());

        service.request_sighup().unwrap();
        let provider = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        subscription_handle.reconcile(vec![AuthorizedSubscription {
            subscription: honk_config::subscription::Subscription {
                name: "fatal-publication".into(), url: format!("http://{}", provider.local_addr().unwrap()),
                download_detour: "direct".into(), update_interval: 0, ..Default::default()
            }, revision: 1,
        }]).await.unwrap();
        let (mut fetch, _) = provider.accept().await.unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") { headers.push(fetch.read_u8().await.unwrap()); }
        let body = "socks5://127.0.0.1:11088#fatal-publication";
        fetch.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        drop(fetch);
        while commands.capacity() > commands.max_capacity() - 3 { tokio::task::yield_now().await; }

        let mut warned = false;
        let mut failed = Box::pin(crate::xdp::join_endpoints(&mut owner,
            |_| Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "invalid CQ").into())),
            Instant::now(), &mut warned));
        assert!(futures::poll!(&mut failed).is_pending());
        commands.closed().await;
        assert!(selector_reply.await.is_err(), "fatal active result is indeterminate, not a fabricated success");
        coordinator.shutdown().await;
        assert_eq!(subscriptions.shutdown().await.unwrap(), 0);
        assert!(futures::poll!(&mut failed).is_pending(), "pre-close permit still owns a possible acknowledgement");
        let (late_command, late_reply) = reload((**active_config.read().await).clone());
        late_permit.send(late_command);
        assert!(late_reply.await.is_err());
        assert!(failed.await.is_err());
        assert!(!owner.task.as_ref().unwrap().is_finished(), "selector completion remains retained by actual CQ output");
        assert_eq!(tracker.snapshot().len(), 1);
        assert!(output.packet().ends_with(b"CQ-held selector reply"));
        assert!(budget.used() > 0);

        assert!(scope.next_output().await.is_none());
        output.release();
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
        assert!(tracker.snapshot().is_empty());
    }).await.expect("fatal acknowledgements and actual output release must complete independently");
}

#[tokio::test]
async fn normal_close_preserves_an_active_reload_result_but_fatal_close_is_indeterminate() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for fatal in [false, true] {
            let budget = MemoryBudget::new(32 << 20);
            let (scope, scope_owner) = scope(&budget);
            let (plane, _health) = xdp_plane("Rule", "block").await;
            let config = Arc::clone(&plane.config);
            let router = Arc::clone(&plane.router);
            let commands = plane.command_sender();
            let shutdown = plane.shutdown_intent();
            let mut candidate = (**config.read().await).clone();
            candidate.global.connect_timeout_ms += 1;
            let expected = candidate.global.connect_timeout_ms;
            let (endpoints, mut owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1).await.unwrap();
            scope.datagram_sender("198.51.100.1:53".parse().unwrap()).send_to(b"retained", "192.0.2.1:41000".parse().unwrap()).await.unwrap();
            let output = scope.next_output().await.unwrap();
            let held_router = router.write().await;
            let (command, reply) = reload(candidate);
            commands.send(command).await.unwrap();
            while commands.capacity() != commands.max_capacity() { tokio::task::yield_now().await; }
            let (queued, queued_reply) = reload((**config.read().await).clone());
            commands.send(queued).await.unwrap();
            let (merge_result, merge_reply) = tokio::sync::oneshot::channel();
            commands.send(ControlCommand::MergeSubscription {
                subscription_id: uuid::Uuid::new_v4(), revision: 1, nodes: Vec::new(),
                diagnostics: Vec::new(), result: merge_result,
            }).await.unwrap();
            if fatal {
                let mut warned = false;
                let mut failed = Box::pin(crate::xdp::join_endpoints(&mut owner,
                    |_| Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "invalid CQ").into())), Instant::now(), &mut warned));
                assert!(futures::poll!(&mut failed).is_pending());
                assert!(reply.await.is_err());
                assert!(queued_reply.await.is_err());
                assert!(merge_reply.await.is_err());
                assert!(failed.await.is_err());
                assert!(!owner.task.as_ref().unwrap().is_finished());
                drop(held_router);
            } else {
                let waiting = Arc::clone(&shutdown);
                let (armed, registered) = tokio::sync::oneshot::channel();
                let capture = tokio::spawn(async move {
                    let stopping = waiting.wait();
                    tokio::pin!(stopping);
                    assert!(futures::poll!(&mut stopping).is_pending());
                    armed.send(()).unwrap();
                    stopping.await;
                });
                registered.await.unwrap();
                endpoints.close();
                tokio::time::timeout(Duration::from_secs(1), capture)
                    .await.expect("direct close wakes the capture wait before the blocked reload can finish")
                    .unwrap();
                assert!(scope.next_output().await.is_none());
                assert!(!owner.task.as_ref().unwrap().is_finished());
                let mut reply = Box::pin(reply);
                assert!(futures::poll!(&mut reply).is_pending());
                drop(held_router);
                assert!(matches!(reply.await.unwrap().outcome, ReloadOutcome::Committed { .. }));
                assert_eq!(queued_reply.await.unwrap().outcome, ReloadOutcome::Rejected);
                assert_eq!(merge_reply.await.unwrap().outcome, ReloadOutcome::Rejected);
            }
            while config.read().await.global.connect_timeout_ms != expected { tokio::task::yield_now().await; }
            assert!(output.packet().ends_with(b"retained"));
            output.release();
            endpoints.shutdown().await.unwrap();
            owner.run().await.unwrap();
        }
    }).await.expect("fatal acknowledgement detachment must retain the real commit while normal close forwards it");
}

#[tokio::test]
async fn supervisor_panic_releases_command_waiters_without_claiming_clean_quiescence() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (plane, _health) = xdp_plane("Rule", "block").await;
        let commands = plane.command_sender();
        let mut candidate = (**plane.config.read().await).clone();
        candidate.global.connect_timeout_ms += 1;
        *plane.pre_dns_publication_hook.lock() = Some(Box::new(|_| panic!("command owner failure")));
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1).await.unwrap();
        scope.datagram_sender("198.51.100.1:53".parse().unwrap()).send_to(b"retained", "192.0.2.1:41000".parse().unwrap()).await.unwrap();
        let output = scope.next_output().await.unwrap();
        let (command, reply) = reload(candidate);
        commands.send(command).await.unwrap();
        assert!(reply.await.is_err());
        assert!(owner.fail_control().await.is_err());
        let error = owner.join_plane().await.err().expect("actual supervisor panic must reach the join");
        assert!(error.downcast_ref::<tokio::task::JoinError>().is_some_and(|error| error.is_panic()));
        assert!(output.packet().ends_with(b"retained"));
        output.release();
        drop(endpoints);
    }).await.expect("panic must fail the independent command completion guard rather than strand fatal shutdown");
}
