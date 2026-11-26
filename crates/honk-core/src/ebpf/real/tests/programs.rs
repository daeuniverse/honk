use super::*;

#[tokio::test]
#[ignore = "requires root; run via just test-netns"]
async fn deferred_verification_outlives_backend_and_consumers() {
    use crate::ebpf::interface::TcProgram;
    let pin_root =
        Path::new("/sys/fs/bpf").join(format!("honk-deferred-drop-test-{}", std::process::id()));
    let (_dae0, setup) = crate::daens::create_test_dae0_pair().expect("dae0 pair");
    let mut backend = RealEbpfBackend::load(
        crate::DEFAULT_BPF_OBJECT,
        &pin_root,
        12345,
        &setup,
        0,
        &[TcProgram::WanEgressL2],
    )
    .await
    .expect("backend load");
    let expected = [TcProgram::LanIngressL3, TcProgram::WanEgressL3];
    let prepare = backend
        .prepare_tc_programs(&expected)
        .expect("deferred job");
    backend
        .cleanup()
        .await
        .expect("cleanup before deferred verification");
    drop(backend);
    let batch = tokio::task::spawn_blocking(prepare)
        .await
        .expect("verifier joined");
    assert_eq!(batch.len(), expected.len());
    for ((program, prepared), expected) in batch.into_iter().zip(expected) {
        assert_eq!(program, expected);
        prepared.expect("original relocation FDs survive the backend and its consumers");
    }
    for name in [
        UDP_DECISION_SEQUENCE_MAP,
        routing::ROUTING_GENERATION_SEQUENCE_MAP,
    ] {
        std::fs::remove_file(pin_root.join(name)).expect("remove test allocator pin");
    }
    std::fs::remove_dir(&pin_root).expect("remove test pin root");
}

#[cfg(feature = "native-api")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires root; run via just test-netns"]
async fn receive_trace_preparation_does_not_wait_for_the_tc_verifier() {
    use crate::ebpf::interface::TcProgram;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::RwLock;

    let pin_root =
        Path::new("/sys/fs/bpf").join(format!("honk-trace-prepare-test-{}", std::process::id()));
    let (_dae0, setup) = crate::daens::create_test_dae0_pair().expect("dae0 pair");
    let backend = RealEbpfBackend::load(
        crate::DEFAULT_BPF_OBJECT,
        &pin_root,
        12345,
        &setup,
        0,
        &[TcProgram::WanEgressL2],
    )
    .await
    .expect("backend load");
    let loader = Arc::clone(backend.programs.as_ref().unwrap());
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(backend)));
    let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let holder = tokio::task::spawn_blocking(move || {
        let _object = loader.object();
        let _ = locked_tx.send(());
        release_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("release loader");
    });
    tokio::time::timeout(Duration::from_secs(2), locked_rx)
        .await
        .unwrap()
        .unwrap();
    let shared = Arc::clone(&backend);
    let mut preparation = tokio::spawn(async move {
        shared
            .read()
            .await
            .prepare_receive_trace()
            .expect("receive trace job")
    });
    let prepared = tokio::time::timeout(Duration::from_millis(200), &mut preparation).await;
    let readable = tokio::time::timeout(Duration::from_millis(200), backend.read())
        .await
        .is_ok();
    let writable = tokio::time::timeout(Duration::from_millis(200), backend.write())
        .await
        .is_ok();
    release_tx.send(()).expect("release verifier mutex");
    holder.await.expect("mutex holder joined");
    let preparation_was_ready = prepared.is_ok();
    let prepare = match prepared {
        Ok(joined) => joined.expect("preparation joined"),
        Err(_) => preparation.await.expect("delayed preparation joined"),
    };
    let trace = tokio::task::spawn_blocking(prepare)
        .await
        .expect("trace job joined");
    drop(trace);
    backend
        .write()
        .await
        .cleanup()
        .await
        .expect("backend cleanup");
    drop(backend);
    for name in [
        UDP_DECISION_SEQUENCE_MAP,
        routing::ROUTING_GENERATION_SEQUENCE_MAP,
    ] {
        std::fs::remove_file(pin_root.join(name)).expect("remove test allocator pin");
    }
    std::fs::remove_dir(&pin_root).expect("remove test pin root");
    assert!(
        preparation_was_ready,
        "preparation waited for the verifier mutex"
    );
    assert!(readable, "trace preparation blocked backend readers");
    assert!(writable, "trace preparation blocked backend writers");
}

/// Startup verifies only the initial variants. A variant first needed later
/// is loaded then and carries the active routing extension before it becomes
/// bindable; the next publication attaches to it as well.
#[tokio::test]
#[ignore = "requires root; run via just test-netns"]
async fn routing_target_loaded_on_first_use_gets_the_active_extension() {
    use crate::ebpf::interface::TcProgram;
    let pin_root =
        Path::new("/sys/fs/bpf").join(format!("honk-first-use-test-{}", std::process::id()));
    let (_dae0, setup) = crate::daens::create_test_dae0_pair().expect("dae0 pair");
    let mut backend = RealEbpfBackend::load(
        crate::DEFAULT_BPF_OBJECT,
        &pin_root,
        12345,
        &setup,
        0,
        &[TcProgram::WanEgressL2],
    )
    .await
    .expect("backend load");
    let loaded = |backend: &RealEbpfBackend| -> Vec<TcProgram> {
        TcProgram::ALL
            .into_iter()
            .filter(|program| {
                backend
                    .bpf()
                    .unwrap()
                    .program(program.name())
                    .unwrap()
                    .info()
                    .is_ok()
            })
            .collect()
    };
    assert_eq!(loaded(&backend), [TcProgram::WanEgressL2]);
    let router = crate::routing::Router::new(&[], "direct").unwrap();
    let routing = crate::control::routing_matcher::RoutingPushPlan::compile(
        &router,
        &std::collections::HashMap::from([("direct".into(), 0), ("block".into(), 1)]),
        honk_config::types::DialMode::Ip,
    )
    .unwrap();
    backend
        .publish_routing_plan(&routing, &[])
        .expect("publish routing");
    assert_eq!(held_tracing_link_count().unwrap(), 1);

    let prepare = backend
        .prepare_tc_programs(&[TcProgram::WanEgressL3])
        .unwrap();
    let previous_generation = backend.routing_policy_generation();
    for handle in [
        backend.log_flush_handle.take(),
        backend.event_flush_handle.take(),
    ]
    .into_iter()
    .flatten()
    {
        handle.abort();
        let _ = handle.await;
    }
    backend
        .publish_routing_plan(&routing, &[])
        .expect("publish while preparation is pending");
    assert!(backend.routing_policy_generation() > previous_generation);
    let prepared = tokio::task::spawn_blocking(prepare).await.unwrap();
    backend
        .commit_tc_programs(prepared)
        .expect("commit against current generation");
    assert_eq!(
        loaded(&backend),
        [TcProgram::WanEgressL2, TcProgram::WanEgressL3]
    );
    assert_eq!(held_tracing_link_count().unwrap(), 2);
    backend
        .publish_routing_plan(&routing, &[])
        .expect("republish routing");
    assert_eq!(held_tracing_link_count().unwrap(), 2);

    backend.detach_hooks().expect("detach hooks");
    backend.cleanup().await.expect("cleanup");
    for name in [
        UDP_DECISION_SEQUENCE_MAP,
        routing::ROUTING_GENERATION_SEQUENCE_MAP,
    ] {
        std::fs::remove_file(pin_root.join(name)).expect("remove test allocator pin");
    }
    std::fs::remove_dir(&pin_root).expect("remove test pin root");
}
