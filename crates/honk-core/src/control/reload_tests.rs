use super::reload::*;
use super::reload::{
    SelectorWarmResources, run_udp_warm_dispatches, selector_warm_candidates, udp_warm_candidates,
    warm_selector_candidate,
};
use super::*;

use crate::control::udp_endpoint::{EndpointReservation, UdpEndpoint};
use crate::dns;
use crate::ebpf::mock::MockEbpfBackend;
use crate::ebpf::{DatapathFlagsWriteOrigin, RoutingPushPhase};
use crate::stats::StatsManager;
fn restart_required_changes(current: &Config, candidate: &Config) -> Vec<&'static str> {
    let current_log_file = crate::resolved_log_file_path(current, None);
    let candidate_log_file = crate::resolved_log_file_path(candidate, None);
    super::reload::restart_required_changes(
        current,
        candidate,
        current_log_file.as_deref(),
        candidate_log_file.as_deref(),
    )
}

#[test]
fn subscription_store_toggle_requires_restart() {
    let current = Config::default();
    let mut replacement = current.clone();
    replacement.global.store_subscribe = !current.global.store_subscribe;

    assert_eq!(
        restart_required_changes(&current, &replacement),
        vec!["global.store_subscribe"]
    );
}

#[test]
fn udp_nfqueue_toggle_requires_restart() {
    let current = Config::default();
    let mut replacement = current.clone();
    replacement.global.nfqueue_enable = !current.global.nfqueue_enable;

    assert_eq!(
        restart_required_changes(&current, &replacement),
        vec!["global.nfqueue_enable"]
    );
}

#[test]
fn semantically_equivalent_dns_bind_does_not_require_restart() {
    let mut current = Config::default();
    current.dns.bind = "127.0.0.1:53".into();
    let mut replacement = current.clone();
    replacement.dns.bind = "udp://127.0.0.1:53".into();

    assert!(restart_required_changes(&current, &replacement).is_empty());
}

#[test]
fn dns_bind_transport_change_requires_restart() {
    let mut current = Config::default();
    current.dns.bind = "udp://127.0.0.1:53".into();
    let mut replacement = current.clone();
    replacement.dns.bind = "tcp+udp://127.0.0.1:53".into();

    assert_eq!(
        restart_required_changes(&current, &replacement),
        vec!["dns.bind"]
    );
}

#[test]
fn enabling_dns_bind_requires_restart() {
    let current = Config::default();
    let mut replacement = current.clone();
    replacement.dns.bind = "tcp://127.0.0.1:0".into();

    assert_eq!(
        restart_required_changes(&current, &replacement),
        vec!["dns.bind"]
    );
}

#[test]
fn data_directory_change_requires_restart() {
    let current = Config::default();
    let mut replacement = current.clone();
    replacement.global.data_dir = "/srv/honk".into();

    assert_eq!(
        restart_required_changes(&current, &replacement),
        vec!["global.data_dir"]
    );
}

#[test]
fn external_ui_download_settings_require_restart() {
    let current = Config::default();
    let mut replacement = current.clone();
    replacement.experimental.clash_api.external_ui_download_url =
        "https://example.com/ui.zip".into();
    replacement
        .experimental
        .clash_api
        .external_ui_download_detour = "proxy".into();

    assert_eq!(
        restart_required_changes(&current, &replacement),
        vec![
            "experimental.clash_api.external_ui_download_url",
            "experimental.clash_api.external_ui_download_detour"
        ]
    );
}

#[test]
fn log_file_change_requires_restart() {
    let current = Config::default();
    let mut replacement = current.clone();
    replacement.global.log_file = "/var/log/honk/honk.log".into();

    assert_eq!(
        restart_required_changes(&current, &replacement),
        vec!["global.log_file"]
    );
}

#[test]
fn cli_log_override_shadows_configured_log_file_change() {
    let mut current = Config::default();
    current.global.log_file = "old.log".into();
    let mut replacement = current.clone();
    replacement.global.log_file = "new.log".into();
    let cli_override = std::path::Path::new("cli.log");
    let current_log_file = crate::resolved_log_file_path(&current, Some(cli_override));
    let candidate_log_file = crate::resolved_log_file_path(&replacement, Some(cli_override));

    assert!(
        super::reload::restart_required_changes(
            &current,
            &replacement,
            current_log_file.as_deref(),
            candidate_log_file.as_deref(),
        )
        .is_empty()
    );
}

#[test]
fn equivalent_resolved_log_file_path_does_not_require_restart() {
    let mut current = Config::default();
    current.global.log_file = "honk.log".into();
    let mut replacement = current.clone();
    replacement.global.log_file = honk_config::paths::data_dir()
        .join("honk.log")
        .to_string_lossy()
        .into_owned();

    assert!(restart_required_changes(&current, &replacement).is_empty());
}

fn test_dns_forwarder() -> std::sync::Arc<dns::forwarder::DnsForwarder> {
    let cache = Arc::new(tokio::sync::Mutex::new(dns::cache::DnsCache::new(100)));
    let router = Arc::new(
        dns::routing::DnsRouter::new(&honk_config::dns::DnsRouting {
            rules: vec![],
            fallback: "default".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    let upstream_pool = Arc::new(
        dns::upstream_pool::UpstreamPool::new(
            &[honk_config::dns::DnsUpstream {
                name: "default".into(),
                address: "8.8.8.8:53".into(),
                protocol: honk_config::types::DnsProtocol::Udp,
                tls_server_name: None,
                outbound: None,
            }],
            router.clone(),
        )
        .unwrap(),
    );
    dns::forwarder::DnsForwarder::new(upstream_pool, cache, router)
        .with_cache_enabled(false)
        .into()
}
#[test]
fn single_leaf_tcp_connectivity_stays_open_for_recovery() {
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "only".into(),
        ..Default::default()
    };
    let config = Config {
        nodes: vec![node.clone()],
        groups: vec![Group {
            name: "single".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![node.id],
            ..Default::default()
        }],
        ..Default::default()
    };
    let alive = Arc::new(crate::outbound::AliveDialerSet::new());
    alive.report_unavailable_forced(node.id, ProbeDomain::Tcp, IpVersion::V4);
    alive.report_unavailable_forced(node.id, ProbeDomain::DataUdp, IpVersion::V4);
    let manager =
        GroupManager::with_alive_set(&config.groups, &config.nodes, Some(Arc::clone(&alive)));
    let snapshot = group_connectivity_snapshot(&config, &manager, &alive);

    assert!(snapshot.contains(&(OutboundIndex::UserBase as u8, 0, 0, true)));
    assert!(snapshot.contains(&(OutboundIndex::UserBase as u8, 2, 0, false)));
}

#[test]
fn group_connectivity_follows_reordered_outbound_ids() {
    let a = Node {
        id: uuid::Uuid::new_v4(),
        name: "a".into(),
        ..Default::default()
    };
    let b = Node {
        id: uuid::Uuid::new_v4(),
        name: "b".into(),
        ..Default::default()
    };
    let group = |name: &str, node: &Node| Group {
        name: name.into(),
        policy: GroupPolicy::Selector,
        nodes: vec![node.id],
        ..Default::default()
    };
    let mut config = Config {
        nodes: vec![a.clone(), b.clone()],
        groups: vec![group("ga", &a), group("gb", &b)],
        ..Default::default()
    };
    let alive = Arc::new(crate::outbound::AliveDialerSet::new());
    alive.report_unavailable_forced(a.id, ProbeDomain::DataUdp, IpVersion::V4);

    let original_manager =
        GroupManager::with_alive_set(&config.groups, &config.nodes, Some(Arc::clone(&alive)));
    let original = group_connectivity_snapshot(&config, &original_manager, &alive);
    assert!(original.contains(&(OutboundIndex::UserBase as u8, 2, 0, false)));
    assert!(original.contains(&(OutboundIndex::UserBase as u8 + 1, 2, 0, true)));

    config.groups.swap(0, 1);
    let reordered_manager =
        GroupManager::with_alive_set(&config.groups, &config.nodes, Some(Arc::clone(&alive)));
    let reordered = group_connectivity_snapshot(&config, &reordered_manager, &alive);
    assert!(reordered.contains(&(OutboundIndex::UserBase as u8, 2, 0, true)));
    assert!(reordered.contains(&(OutboundIndex::UserBase as u8 + 1, 2, 0, false)));

    let mut backend = MockEbpfBackend::new();
    publish_group_connectivity(&mut backend, &original).unwrap();
    open_group_connectivity(&mut backend, 2).unwrap();
    assert!(
        backend
            .get_outbound_alive(OutboundIndex::UserBase as u8 + 1, 2, 0)
            .unwrap()
    );
    publish_group_connectivity(&mut backend, &reordered).unwrap();
    assert!(
        !backend
            .get_outbound_alive(OutboundIndex::UserBase as u8 + 1, 2, 0)
            .unwrap()
    );
}

async fn test_cp() -> ControlPlane {
    let mut control_plane = ControlPlane::new(
        Config::default(),
        Box::new(MockEbpfBackend::new()),
        Router::new(&[], "direct").unwrap(),
        std::sync::Arc::new(ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        test_dns_forwarder(),
    )
    .unwrap();
    let initial_plan = control_plane.active_routing_plan.read().clone();
    routing_matcher::RoutingMatcherBuilder::push_plan(
        &mut **control_plane.ebpf.write().await,
        &initial_plan,
    )
    .unwrap();
    routing_matcher::RoutingMatcherBuilder::activate_projection(&initial_plan);
    control_plane
        .routing_publication_dirty
        .store(false, std::sync::atomic::Ordering::Release);
    control_plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("Rule", "Proxy"),
    )));
    control_plane.start_datapath_flags_coordinator().unwrap();
    control_plane
        .initialize_datapath_flags(false, false)
        .await
        .unwrap();
    control_plane
}

fn changed_routing_config() -> Config {
    let mut config = Config::default();
    config
        .routing
        .rules
        .push(honk_config::routing::RoutingRule {
            name: "reload-change".into(),
            condition: honk_config::routing::RoutingCondition {
                domain: vec!["reload.example".into()],
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: false,
            mark: 0,
        });
    config
}

fn score_reload_config(interval: u64) -> Config {
    let nodes = ["score-a", "score-b"].map(|name| Node {
        id: uuid::Uuid::new_v5(&honk_config::node::NODE_ID_NAMESPACE, name.as_bytes()),
        name: name.into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    });
    let mut config = Config::default();
    config.global.check_interval_secs = interval;
    config.nodes = nodes.to_vec();
    config.groups = vec![Group {
        name: "score".into(),
        policy: GroupPolicy::Score,
        nodes: nodes.iter().map(|node| node.id).collect(),
        ..Default::default()
    }];
    config
}

fn score_reload_context() -> honk_outbound::group::ScoreSelectionContext {
    honk_outbound::group::ScoreSelectionContext {
        network: honk_outbound::group::SelectionNetwork::Tcp,
        probe_domain: ProbeDomain::Tcp,
        target_family: Some(IpVersion::V4),
        health_family: IpVersion::V4,
        target: Some(honk_outbound::group::ScoreTarget::domain(
            "reload.example",
            443,
        )),
    }
}

#[tokio::test]
async fn reload_publishes_score_authority_before_dns_snapshot_is_reachable() {
    let cp = Arc::new(test_cp().await);
    let first_interval = Config::default().global.check_interval_secs + 1;
    assert!(
        cp.apply_runtime_config(score_reload_config(first_interval), &DrainTracker::new(),)
            .await
    );
    let provider = cp.dns_controller.runtime_provider();
    let before_dns = provider.current_generation();
    let old_manager = cp.group_manager.read().clone();
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed_at_hook = Arc::clone(&observed);
    let lock_at_hook = Arc::clone(&cp);
    let _hook_guard = cp.set_pre_dns_publication_hook(move |new_manager| {
        assert!(lock_at_hook.reload_lock.try_lock().is_err());
        let first = new_manager.selection_plan_for_target("score", &score_reload_context());
        let first_id = first.entries[0].node.id;
        let reporter = first.entries[0].feedback.as_ref().unwrap().start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(honk_outbound::group::ScoreOutcome::Success);
        assert_ne!(
            new_manager
                .selection_plan_for_target("score", &score_reload_context())
                .entries[0]
                .node
                .id,
            first_id,
            "the published replacement authority must accept Score writes"
        );
        assert!(
            old_manager
                .selection_plan_for_target("score", &score_reload_context())
                .entries[0]
                .feedback
                .is_none()
        );
        observed_at_hook.store(true, std::sync::atomic::Ordering::Release);
        println!("replacement Score authority accepted writes before DNS publication");
    });

    let result = cp
        .apply_runtime_config(
            score_reload_config(first_interval + 1),
            &DrainTracker::new(),
        )
        .await;

    assert!(result);
    assert!(observed.load(std::sync::atomic::Ordering::Acquire));
    assert_ne!(provider.current_generation(), before_dns);
    assert!(
        cp.group_manager
            .read()
            .selection_plan_for_target("score", &score_reload_context())
            .entries[0]
            .feedback
            .is_some()
    );
}

#[tokio::test]
async fn failed_reload_keeps_old_score_authority() {
    let cp = test_cp().await;
    let interval = Config::default().global.check_interval_secs + 1;
    assert!(
        cp.apply_runtime_config(score_reload_config(interval), &DrainTracker::new())
            .await
    );
    let provider = cp.dns_controller.runtime_provider();
    let before_dns = provider.current_generation();
    let before_manager = cp.group_manager.read().clone();
    let mut invalid = score_reload_config(interval + 1);
    invalid.dns.upstream[0].address = "://invalid".into();

    assert!(!cp.apply_runtime_config(invalid, &DrainTracker::new()).await);

    assert_eq!(provider.current_generation(), before_dns);
    assert!(Arc::ptr_eq(&cp.group_manager.read(), &before_manager));
    assert_eq!(cp.config.read().await.global.check_interval_secs, interval);
    let feedback = before_manager
        .selection_plan_for_target("score", &score_reload_context())
        .entries[0]
        .feedback
        .clone();
    assert!(feedback.is_some());
    println!("rejected reload preserved DNS generation and old Score authority");
    feedback
        .unwrap()
        .start()
        .setup_failed(honk_outbound::group::ScoreOutcome::Timeout);
}

#[tokio::test]
async fn post_publication_datapath_failure_is_committed_degraded() {
    for failed_ordinal in [2, 3] {
        let cp = test_cp().await;
        assert!(cp.datapath_flags.is_some());
        let first_interval = Config::default().global.check_interval_secs + 1;
        assert!(
            cp.apply_runtime_config(score_reload_config(first_interval), &DrainTracker::new(),)
                .await
        );
        let provider = cp.dns_controller.runtime_provider();
        let before_dns = provider.current_generation();
        let before_manager = cp.group_manager.read().clone();
        let expected_flags;
        {
            let mut ebpf = cp.ebpf.write().await;
            expected_flags = *ebpf.datapath_flags_write_log().last().unwrap();
            ebpf.clear_datapath_flags_write_log();
            ebpf.arm_datapath_flags_write_fault(failed_ordinal).unwrap();
            assert!(ebpf.datapath_flags_write_log().is_empty());
        }
        let interval = first_interval + failed_ordinal as u64;
        let drain = DrainTracker::new();
        let expected_new_flags =
            expected_flags & !honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_NO_DOMAIN_RULES;
        assert_ne!(expected_new_flags, expected_flags);
        let mut replacement = score_reload_config(interval);
        replacement
            .routing
            .rules
            .push(honk_config::routing::RoutingRule {
                name: "distinct-static-flags".into(),
                condition: honk_config::routing::RoutingCondition {
                    domain: vec!["static-flags.example".into()],
                    ..Default::default()
                },
                outbound: honk_config::routing::RoutingOutbound::Simple("direct".into()),
                priority: 0,
                must: false,
                mark: 0,
            });

        let result = cp.apply_runtime_config(replacement, &drain).await;
        let ebpf = cp.ebpf.read().await;
        let writes = ebpf.datapath_flags_write_log();
        let trace = ebpf.datapath_flags_write_trace();
        drop(ebpf);

        let expected_writes = if failed_ordinal == 2 {
            vec![expected_flags, expected_new_flags]
        } else {
            vec![expected_flags, expected_new_flags, expected_new_flags]
        };
        assert_eq!(writes, expected_writes);
        assert_eq!(trace.len(), failed_ordinal);
        let expected_origins = if failed_ordinal == 2 {
            vec![
                DatapathFlagsWriteOrigin::FenceNfqueue,
                DatapathFlagsWriteOrigin::SetStatic,
            ]
        } else {
            vec![
                DatapathFlagsWriteOrigin::FenceNfqueue,
                DatapathFlagsWriteOrigin::SetStatic,
                DatapathFlagsWriteOrigin::ReopenNfqueue,
            ]
        };
        for (index, write) in trace.iter().enumerate() {
            assert_eq!(write.ordinal, index + 1);
            assert_eq!(write.flags, expected_writes[index]);
            assert_eq!(write.origin, expected_origins[index]);
            assert_eq!(write.failed, index + 1 == failed_ordinal);
        }
        let labelled_trace: Vec<_> = trace
            .iter()
            .map(|write| (write.origin, write.flags, write.failed))
            .collect();
        assert!(labelled_trace.last().unwrap().2);
        println!("failed_ordinal={failed_ordinal} stage_trace={labelled_trace:?}");
        assert!(
            result,
            "post-publication failure {failed_ordinal} is committed"
        );
        assert_ne!(provider.current_generation(), before_dns);
        assert_eq!(cp.config.read().await.global.check_interval_secs, interval);
        assert!(!Arc::ptr_eq(&cp.group_manager.read(), &before_manager));
        assert!(!cp.is_datapath_healthy());
        assert!(drain.should_reject());
        assert!(cp.drain_tracker.should_reject());
        assert!(
            before_manager
                .selection_plan_for_target("score", &score_reload_context())
                .entries[0]
                .feedback
                .is_none()
        );
        assert!(
            cp.group_manager
                .read()
                .selection_plan_for_target("score", &score_reload_context())
                .entries[0]
                .feedback
                .is_some()
        );
    }
}

#[tokio::test]
async fn empty_subscription_merge_does_not_publish_runtime() {
    let cp = test_cp().await;
    let provider = cp.dns_controller.runtime_provider();
    let before_generation = provider.current_generation();
    let before_retired = provider.retired_count();

    cp.merge_subscription_nodes(uuid::Uuid::new_v4(), Vec::new())
        .await;

    assert_eq!(provider.current_generation(), before_generation);
    assert_eq!(provider.retired_count(), before_retired);
}

#[tokio::test]
async fn reload_clamps_dials_to_startup_descriptor_reservation() {
    let cp = test_cp().await;
    let ceiling = cp.resource_budget.transient_dials;
    let mut config = cp.config_handle().read().await.as_ref().clone();
    config.global.max_concurrent_dials = usize::MAX;

    assert!(cp.apply_runtime_config(config, &DrainTracker::new()).await);
    assert_eq!(cp.runtime_registry.read().dial_limit(), ceiling);
}

/// A reload whose build phase fails (invalid upstream address) must abort
/// without touching the live config — the atomicity guarantee of the
/// two-phase apply.
#[tokio::test]
async fn build_failure_leaves_live_config_untouched() {
    let cp = test_cp().await;
    let before = cp.config_handle().read().await.global.check_interval_secs;

    // An upstream with an empty address fails DnsEndpoint::parse during
    // build_dns_forwarder — the reload must abort before commit.
    let mut bad = Config::default();
    bad.global.check_interval_secs += 1;
    bad.dns.upstream = vec![honk_config::dns::DnsUpstream {
        name: "broken".into(),
        address: String::new(),
        protocol: honk_config::types::DnsProtocol::Udp,
        tls_server_name: None,
        outbound: None,
    }];

    let drain = DrainTracker::new();
    cp.apply_runtime_config(bad, &drain).await;

    let after = cp.config_handle().read().await.global.check_interval_secs;
    assert_eq!(before, after, "failed build must not swap the live config");
}

#[tokio::test]
async fn reload_cancels_initializing_generation_before_swap_and_keeps_ready_endpoint() {
    use honk_outbound::proxy::PacketTransport;
    use std::io;
    use std::sync::Mutex;
    use tokio::sync::Notify;

    /// Minimal scripted transport local to this reload test so we can
    /// prove a real driver survives production cancel/reload.
    #[derive(Debug)]
    struct ReloadTestTransport {
        relay: std::net::SocketAddr,
        sent: Mutex<Vec<Vec<u8>>>,
        progress: Notify,
    }

    #[async_trait::async_trait]
    impl PacketTransport for ReloadTestTransport {
        fn relay_addr(&self) -> std::net::SocketAddr {
            self.relay
        }

        async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
            self.sent.lock().unwrap().push(data.to_vec());
            self.progress.notify_waiters();
            Ok(())
        }

        async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
            // Leave receive pending for the life of the driver.
            std::future::pending().await
        }
    }

    impl ReloadTestTransport {
        async fn wait_for_send_count(&self, count: usize) {
            loop {
                if self.sent.lock().unwrap().len() >= count {
                    return;
                }
                self.progress.notified().await;
            }
        }

        fn sent_packets(&self) -> Vec<Vec<u8>> {
            self.sent.lock().unwrap().clone()
        }
    }

    let cp = test_cp().await;
    let pool = cp.udp_pool.clone();
    let stats = Arc::new(StatsManager::new());
    let ready_client: std::net::SocketAddr = "10.0.0.1:53000".parse().unwrap();
    let initializing_client: std::net::SocketAddr = "10.0.0.2:53000".parse().unwrap();
    let dst: std::net::SocketAddr = "203.0.113.2:443".parse().unwrap();
    let relay: std::net::SocketAddr = "192.0.2.10:1080".parse().unwrap();

    let ready_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let mut ready_lease =
        match pool.reserve_or_enqueue(ready_client, dst, b"ready-first", ready_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("ready fixture must reserve an initializing entry"),
        };
    let transport = Arc::new(ReloadTestTransport {
        relay,
        sent: Mutex::new(Vec::new()),
        progress: Notify::new(),
    });
    let ready_endpoint = Arc::new(UdpEndpoint::new(
        transport.clone() as Arc<dyn PacketTransport>,
        relay,
        uuid::Uuid::from_u128(0x1ead9),
    ));
    let queue_rx = ready_lease.take_queue_receiver().unwrap();
    let reply_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let mut driver = pool.spawn_driver(
        ready_client,
        dst,
        ready_lease.generation(),
        ready_lease.decision_token(),
        Arc::clone(&ready_endpoint),
        queue_rx,
        reply_socket,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        "ready-node".into(),
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), driver.wait_ready())
        .await
        .expect("driver must become ready")
        .unwrap();
    assert!(ready_lease.commit_ready(Arc::clone(&ready_endpoint)));
    driver
        .start(ready_lease.take_first().unwrap())
        .expect("driver start");
    tokio::time::timeout(std::time::Duration::from_secs(1), driver.wait_first_ack())
        .await
        .expect("driver must send the first packet")
        .unwrap();
    // Production drops a committed lease after the first-send ack; only
    // the Ready driver, not an initializer guard, survives into reload.
    drop(ready_lease);

    let init_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let initializing_lease = match pool.reserve_or_enqueue(
        initializing_client,
        dst,
        b"initializing",
        init_permit,
        &stats,
    ) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("reload fixture must reserve an initializing entry"),
    };
    let mut cancellation = initializing_lease.cancellation();
    let initializer = tokio::spawn(async move {
        cancellation
            .changed()
            .await
            .expect("reload must broadcast initializer cancellation");
        drop(initializing_lease);
    });

    let mut new_config = Config::default();
    new_config.global.check_interval_secs += 1;
    let drain = DrainTracker::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        cp.apply_runtime_config(new_config, &drain),
    )
    .await
    .expect("reload must complete");
    initializer.await.unwrap();
    assert!(pool.get(initializing_client, dst).is_none());
    assert!(
        Arc::ptr_eq(&pool.get(ready_client, dst).unwrap(), &ready_endpoint),
        "ordinary reload must not retire Ready endpoint drivers"
    );

    // After production reload cancellation the Ready driver must still
    // accept and deliver a steady packet (or at least enqueue+transport).
    let follower_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    assert!(matches!(
        pool.reserve_or_enqueue(ready_client, dst, b"after-reload", follower_permit, &stats,),
        EndpointReservation::Enqueued
    ));
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        transport.wait_for_send_count(2),
    )
    .await
    .expect("Ready endpoint driver must survive reload");
    assert_eq!(
        transport.sent_packets(),
        vec![b"ready-first".to_vec(), b"after-reload".to_vec()]
    );

    let replacement_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    assert!(matches!(
        pool.reserve_or_enqueue(
            initializing_client,
            dst,
            b"next-generation",
            replacement_permit,
            &stats,
        ),
        EndpointReservation::Initializing(_)
    ));
    assert_eq!(
        cp.config_handle().read().await.global.check_interval_secs,
        Config::default().global.check_interval_secs + 1
    );
    pool.remove(ready_client, dst);
    pool.remove(initializing_client, dst);
}

#[tokio::test(start_paused = true)]
async fn reload_timeout_keeps_runtime_and_restores_admission() {
    let cp = Arc::new(test_cp().await);
    let pool = cp.udp_pool.clone();
    let stats = Arc::new(StatsManager::new());
    let client: std::net::SocketAddr = "10.0.0.9:53000".parse().unwrap();
    let dst: std::net::SocketAddr = "203.0.113.9:443".parse().unwrap();
    let slow_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let lease = match pool.reserve_or_enqueue(client, dst, b"held", slow_permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("timeout fixture must hold a real initializer lease"),
    };
    let mut cancellation = lease.cancellation();
    let before = cp.config_handle().read().await.global.check_interval_secs;
    let mut next = Config::default();
    next.global.check_interval_secs += 1;
    let drain = Arc::new(DrainTracker::new());
    let reloading_cp = Arc::clone(&cp);
    let reloading_drain = Arc::clone(&drain);
    let reloader = tokio::spawn(async move {
        reloading_cp
            .apply_runtime_config(next, reloading_drain.as_ref())
            .await;
    });

    cancellation
        .changed()
        .await
        .expect("reload must cancel the held initializer before waiting");
    assert!(
        drain.should_reject(),
        "reload must fail closed while it waits"
    );
    tokio::time::advance(Duration::from_secs(5) + Duration::from_millis(1)).await;
    reloader.await.unwrap();

    assert_eq!(
        cp.config_handle().read().await.global.check_interval_secs,
        before,
        "a timed-out initializer must prevent the runtime/config swap"
    );
    assert!(
        !drain.should_reject(),
        "an aborted reload must restore admission after its timeout"
    );
    assert_eq!(
        pool.len(),
        1,
        "the real initializer remains held until its owner drops it"
    );
    drop(lease);
    assert!(pool.is_empty());
}

/// A non-routing reload publishes a fresh DNS generation without rewriting
/// the static routing bank or retaining its generation-owned upstream pool.
#[tokio::test]
async fn valid_reload_commits() {
    let expected_interval = Config::default().global.check_interval_secs + 1;
    let cp = test_cp().await;
    let before_routing_generation = cp.ebpf.read().await.active_routing_generation().unwrap();
    let before_runtime = cp.dns_controller.runtime_provider().acquire();
    let cache = before_runtime.runtime().cache();
    let before_forwarder = Arc::clone(before_runtime.runtime().forwarder());
    let before_dns_router = before_forwarder.routing_snapshot();
    let before_upstream_pool = Arc::clone(&before_forwarder.upstream_pool);
    assert_eq!(
        before_runtime.runtime().routing_projection().generation(),
        0
    );
    drop(before_runtime);

    let mut good = Config::default();
    good.global.check_interval_secs = expected_interval;
    assert!(cp.apply_runtime_config(good, &DrainTracker::new()).await);

    assert_eq!(
        cp.config_handle().read().await.global.check_interval_secs,
        expected_interval,
        "valid reload should swap the live config"
    );
    assert_eq!(
        cp.ebpf.read().await.active_routing_generation().unwrap(),
        before_routing_generation,
    );
    let after_runtime = cp.dns_controller.runtime_provider().acquire();
    let after_forwarder = Arc::clone(after_runtime.runtime().forwarder());
    assert!(Arc::ptr_eq(&after_runtime.runtime().cache(), &cache));
    assert_eq!(after_runtime.runtime().routing_projection().generation(), 1);
    assert!(!Arc::ptr_eq(&before_forwarder, &after_forwarder));
    assert!(Arc::ptr_eq(
        &before_dns_router,
        &after_forwarder.routing_snapshot()
    ));
    assert!(!Arc::ptr_eq(
        &before_upstream_pool,
        &after_forwarder.upstream_pool
    ));
}

#[tokio::test]
async fn identical_effective_reload_retains_runtime_identity_and_writes_nothing() {
    let cp = test_cp().await;
    assert!(
        cp.apply_runtime_config(Config::default(), &DrainTracker::new())
            .await
    );
    let config = cp.config_handle().read().await.as_ref().clone();
    let dns_generation = cp
        .dns_controller
        .runtime_provider()
        .current_generation()
        .get();
    let routing_generation = cp.ebpf.read().await.active_routing_generation().unwrap();
    let forwarder = cp.dns_controller.forwarder();
    let cache = forwarder.cache();
    let group_manager = cp.group_manager.read().clone();
    let runtime_registry = cp.runtime_registry.read().clone();
    let routing_plan = cp.active_routing_plan.read().clone();
    cp.ebpf.write().await.clear_datapath_flags_write_log();
    let drain = DrainTracker::new();

    assert!(cp.apply_runtime_config(config, &drain).await);

    assert_eq!(
        cp.dns_controller
            .runtime_provider()
            .current_generation()
            .get(),
        dns_generation
    );
    assert_eq!(
        cp.ebpf.read().await.active_routing_generation().unwrap(),
        routing_generation
    );
    assert!(cp.ebpf.read().await.datapath_flags_write_log().is_empty());
    assert!(Arc::ptr_eq(&cp.dns_controller.forwarder(), &forwarder));
    assert!(Arc::ptr_eq(&cp.dns_controller.forwarder().cache(), &cache));
    assert!(Arc::ptr_eq(&cp.group_manager.read(), &group_manager));
    assert!(Arc::ptr_eq(&cp.runtime_registry.read(), &runtime_registry));
    assert!(Arc::ptr_eq(&cp.active_routing_plan.read(), &routing_plan));
    assert!(!drain.should_reject());
}

#[tokio::test]
async fn router_only_semantic_reload_fences_sniffed_bitmap_writers() {
    let cp = test_cp().await;
    let mut first = changed_routing_config();
    first.routing.rules[0].condition.domain = vec!["first.example".into()];
    assert!(
        cp.apply_runtime_config(first.clone(), &DrainTracker::new())
            .await
    );
    let ebpf_generation = cp.ebpf.read().await.active_routing_generation().unwrap();
    let bitmap_generation =
        routing_matcher::DOMAIN_BITMAPS_GENERATION.load(std::sync::atomic::Ordering::Acquire);

    first.routing.rules[0].condition.domain = vec!["second.example".into()];
    assert!(cp.apply_runtime_config(first, &DrainTracker::new()).await);

    assert_eq!(
        cp.ebpf.read().await.active_routing_generation().unwrap(),
        ebpf_generation,
        "equal eBPF plan bytes should not flip the map bank"
    );
    assert!(
        routing_matcher::DOMAIN_BITMAPS_GENERATION.load(std::sync::atomic::Ordering::Acquire)
            > bitmap_generation,
        "replacing the userspace Router must fence stale bitmap writers"
    );
}
#[tokio::test]
async fn identical_subscription_merge_skips_runtime_generation() {
    let subscription_id = uuid::Uuid::new_v4();
    let mut node = Node {
        name: "subscription-node".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: "127.0.0.1:1080".into(),
        subscription_id: Some(subscription_id),
        ..Default::default()
    };
    node.id = node.derive_id();

    let cp = test_cp().await;
    let mut initial = Config::default();
    initial.nodes.push(node.clone());
    assert!(cp.apply_runtime_config(initial, &DrainTracker::new()).await);
    let before = cp
        .dns_controller
        .runtime_provider()
        .current_generation()
        .get();

    let mut fetched = node;
    fetched.created_at += chrono::Duration::seconds(1);
    fetched.updated_at += chrono::Duration::seconds(1);
    cp.merge_subscription_nodes(subscription_id, vec![fetched])
        .await;

    assert_eq!(
        cp.dns_controller
            .runtime_provider()
            .current_generation()
            .get(),
        before,
        "identical effective subscription data must not publish a generation"
    );
}

#[tokio::test]
async fn unchanged_reload_retries_dirty_startup_routing() {
    let cp = test_cp().await;
    let before = cp.ebpf.read().await.active_routing_generation().unwrap();
    cp.routing_publication_dirty
        .store(true, std::sync::atomic::Ordering::Release);

    assert!(
        cp.apply_runtime_config(Config::default(), &DrainTracker::new())
            .await
    );
    assert_ne!(
        cp.ebpf.read().await.active_routing_generation().unwrap(),
        before
    );
    assert!(
        !cp.routing_publication_dirty
            .load(std::sync::atomic::Ordering::Acquire)
    );
}

#[tokio::test]
async fn changed_hosts_file_rebuilds_reload_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("hosts.rules");
    std::fs::write(&path, "full:reload.invalid 192.0.2.1\n").unwrap();
    let cp = test_cp().await;
    let mut config = Config::default();
    config.dns.hosts = vec![path.to_string_lossy().into_owned()];

    assert!(
        cp.apply_runtime_config(config.clone(), &DrainTracker::new())
            .await
    );
    let first_forwarder = cp.dns_controller.forwarder();
    let first = first_forwarder.hosts_snapshot();
    let first_hosts = first.hosts().unwrap();
    let first_policy = first_forwarder.policy_id().unwrap();
    let cache = first_forwarder.cache();

    std::fs::write(&path, "full:reload.invalid 192.0.2.2\n").unwrap();
    assert!(cp.apply_runtime_config(config, &DrainTracker::new()).await);
    let second_forwarder = cp.dns_controller.forwarder();
    let second = second_forwarder.hosts_snapshot();

    assert_ne!(first.fingerprint(), second.fingerprint());
    assert!(!Arc::ptr_eq(&first_hosts, &second.hosts().unwrap()));
    assert_ne!(first_policy, second_forwarder.policy_id().unwrap());
    assert!(Arc::ptr_eq(&cache, &second_forwarder.cache()));
}

#[tokio::test]
async fn client_subnet_reload_injects_upstream_query() {
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cp = test_cp().await;
    let mut replacement = Config::default();
    replacement.dns.client_subnet = "198.51.100.9/24".into();
    replacement.dns.cache.enabled = false;
    replacement.dns.upstream[0].address = upstream.local_addr().unwrap().to_string();

    assert!(
        cp.apply_runtime_config(replacement, &DrainTracker::new())
            .await
    );
    let config = cp.config_handle().read().await.clone();
    assert_eq!(
        config.dns.effective_client_subnet().unwrap(),
        Some("198.51.100.0/24".parse().unwrap())
    );
    let expected_policy = crate::dns::policy::PolicyId::from_config(&config.dns).unwrap();
    let runtime = cp.dns_controller.runtime_provider().acquire();
    assert_eq!(
        runtime
            .runtime()
            .forwarder()
            .policy_id
            .as_ref()
            .unwrap()
            .canonical_bytes(),
        expected_policy.canonical_bytes()
    );
    let forwarder = Arc::clone(runtime.runtime().forwarder());
    drop(runtime);

    let query = crate::dns::forwarder::build_dns_query("example.com", 1);
    let resolve = tokio::spawn(async move { forwarder.resolve(&query).await });
    let mut wire = [0_u8; 512];
    let (length, peer) =
        tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut wire))
            .await
            .expect("reloaded upstream did not receive query")
            .unwrap();
    assert_eq!(
        &wire[length - 11..length],
        &[0, 8, 0, 7, 0, 1, 24, 0, 198, 51, 100]
    );

    let mut response = wire[..length].to_vec();
    response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    upstream.send_to(&response, peer).await.unwrap();
    let response = resolve.await.unwrap().unwrap();
    assert_eq!(&response[10..12], &[0, 0]);
}

#[tokio::test]
async fn routing_push_failure_replays_old_plan_and_keeps_userspace_generation() {
    let cp = test_cp().await;
    cp.ebpf
        .write()
        .await
        .inject_routing_fault(RoutingPushPhase::Meta, 1)
        .unwrap();
    let mut replacement = changed_routing_config();
    replacement.global.check_interval_secs += 1;

    cp.apply_runtime_config(replacement, &DrainTracker::new())
        .await;

    assert_eq!(
        cp.config_handle().read().await.global.check_interval_secs,
        Config::default().global.check_interval_secs,
    );
    assert!(cp.is_datapath_healthy());
    assert!(!cp.drain_tracker.should_reject());
}

#[tokio::test]
async fn domain_route_staging_failure_keeps_the_active_generation() {
    let cp = test_cp().await;
    let before = cp.ebpf.read().await.active_routing_generation().unwrap();
    cp.ebpf
        .write()
        .await
        .inject_routing_fault(RoutingPushPhase::DomainRouting, 1)
        .unwrap();
    let mut replacement = changed_routing_config();
    replacement.global.check_interval_secs += 1;

    cp.apply_runtime_config(replacement, &DrainTracker::new())
        .await;
    assert_eq!(
        cp.ebpf.read().await.active_routing_generation().unwrap(),
        before
    );
    assert_eq!(
        cp.config_handle().read().await.global.check_interval_secs,
        Config::default().global.check_interval_secs,
    );
    assert!(cp.is_datapath_healthy());
    assert!(!cp.drain_tracker.should_reject());
}

#[tokio::test]
async fn replay_failure_marks_unhealthy_and_rejects_connections() {
    let cp = test_cp().await;
    cp.ebpf
        .write()
        .await
        .inject_routing_fault(RoutingPushPhase::Meta, 2)
        .unwrap();

    cp.apply_runtime_config(changed_routing_config(), &DrainTracker::new())
        .await;

    assert!(!cp.is_datapath_healthy());
    assert!(cp.drain_tracker.should_reject());

    let mut invalid = Config::default();
    invalid.dns.upstream[0].address.clear();
    cp.apply_runtime_config(invalid, &DrainTracker::new()).await;
    cp.apply_runtime_config(Config::default(), &DrainTracker::new())
        .await;

    assert!(!cp.is_datapath_healthy());
    assert!(cp.drain_tracker.should_reject());
}

#[tokio::test]
async fn default_udp_warm_is_disabled_without_a_task_or_metrics() {
    let cp = test_cp().await;
    let generation = cp.runtime_registry.read().clone();

    cp.start_udp_warm_coordinator(generation).await;

    assert!(
        cp.udp_warm_task.lock().await.is_none(),
        "the default zero count must not spawn udp_warm_task"
    );
    let snapshot = cp.stats.udp_snapshot();
    assert_eq!(
        (
            snapshot.warm_attempts,
            snapshot.warm_successes,
            snapshot.warm_failures
        ),
        (0, 0, 0),
        "the strict no-op must not touch warm metrics"
    );
}

#[test]
fn selector_warm_candidates_follow_configured_leaves_and_deduplicate() {
    let node = |name: &str, protocol| Node {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        address: "127.0.0.1:9".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(protocol),
        ..Default::default()
    };
    let anytls = node("selector-anytls", NodeProtocol::AnyTLS);
    let socks = node("selector-socks", NodeProtocol::Socks5);
    let direct = node("selector-direct", NodeProtocol::Direct);
    let groups = vec![
        Group {
            name: "first".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![anytls.id, direct.id],
            ..Default::default()
        },
        Group {
            name: "shared".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![anytls.id],
            ..Default::default()
        },
        Group {
            name: "child".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![socks.id],
            ..Default::default()
        },
        Group {
            name: "parent".into(),
            policy: GroupPolicy::Selector,
            groups: vec!["child".into()],
            ..Default::default()
        },
    ];
    let config = Config {
        nodes: vec![anytls.clone(), socks.clone(), direct],
        groups,
        ..Default::default()
    };
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let generation = honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap();

    assert_eq!(
        selector_warm_candidates(&config, &manager, &generation)
            .into_iter()
            .map(|node| node.id)
            .collect::<Vec<_>>(),
        vec![anytls.id, socks.id]
    );
}

#[tokio::test]
async fn selector_choice_switch_replaces_bare_tcp_pin_immediately() {
    let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_socket = first_listener.local_addr().unwrap();
    let second_socket = second_listener.local_addr().unwrap();
    let first_addr = first_socket.to_string();
    let second_addr = second_socket.to_string();
    let first = Node {
        id: uuid::Uuid::new_v4(),
        name: "selector-first".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: first_addr.clone(),
        host: first_socket.ip().to_string(),
        port: first_socket.port(),
        ..Default::default()
    };
    let second = Node {
        id: uuid::Uuid::new_v4(),
        name: "selector-second".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: second_addr.clone(),
        host: second_socket.ip().to_string(),
        port: second_socket.port(),
        ..Default::default()
    };
    let config = Config {
        nodes: vec![first.clone(), second.clone()],
        groups: vec![Group {
            name: "manual".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![first.id, second.id],
            ..Default::default()
        }],
        ..Default::default()
    };
    let manager = Arc::new(GroupManager::new(&config.groups, &config.nodes));
    let generation =
        Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap());
    assert_eq!(
        selector_warm_candidates(&config, &manager, &generation)
            .into_iter()
            .map(|node| node.id)
            .collect::<Vec<_>>(),
        vec![first.id]
    );
    let cp = test_cp().await;
    *cp.config.write().await = Arc::new(config);
    *cp.group_manager.write() = Arc::clone(&manager);
    *cp.runtime_registry.write() = Arc::clone(&generation);
    install_selector_warm_callback(&manager, &cp.selector_warm_notify);

    cp.start_selector_warm_coordinator(Arc::clone(&generation))
        .await;
    let (first_server, _) = tokio::time::timeout(Duration::from_secs(1), first_listener.accept())
        .await
        .expect("first selector must preconnect")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !cp.connection_pool.has_live_bare_entry(&first_addr) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    manager.set_selector_choice("manual", "selector-second");
    let (second_server, _) = tokio::time::timeout(Duration::from_secs(1), second_listener.accept())
        .await
        .expect("choice change must preconnect immediately")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while cp.connection_pool.has_live_bare_entry(&first_addr)
            || !cp.connection_pool.has_live_bare_entry(&second_addr)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("choice change must replace the old pin");

    drop((first_server, second_server));
    cp.stop_selector_warm_coordinator().await;
    generation.shutdown().await;
}

#[tokio::test]
async fn changed_selector_bare_endpoint_is_purged_before_failed_replacement() {
    let old_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let old_socket = old_listener.local_addr().unwrap();
    let old_addr = old_socket.to_string();
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "selector-moved".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: old_addr.clone(),
        host: old_socket.ip().to_string(),
        port: old_socket.port(),
        ..Default::default()
    };
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
            .unwrap(),
    );
    let cp = test_cp().await;
    let resources = SelectorWarmResources {
        generation: Arc::clone(&generation),
        proxy_registry: cp.proxy_registry.clone(),
        group_manager: cp.group_manager.clone(),
        connection_pool: cp.connection_pool.clone(),
        stats: cp.stats.clone(),
        selected_ids: cp.selector_warm_ids.clone(),
        bare_warm: cp.selector_bare_warm.clone(),
    };

    warm_selector_candidate(node.clone(), resources.clone(), Duration::from_secs(1)).await;
    let (old_server, _) = tokio::time::timeout(Duration::from_secs(1), old_listener.accept())
        .await
        .expect("initial selector must preconnect")
        .unwrap();
    assert!(cp.connection_pool.has_live_bare_entry(&old_addr));
    assert_eq!(cp.selector_bare_warm.lock().get(&node.id), Some(&old_addr));

    let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_socket = unavailable.local_addr().unwrap();
    drop(unavailable);
    let mut moved = node.clone();
    moved.address = unavailable_socket.to_string();
    moved.host = unavailable_socket.ip().to_string();
    moved.port = unavailable_socket.port();
    warm_selector_candidate(moved, resources, Duration::from_millis(100)).await;

    assert!(!cp.connection_pool.has_live_bare_entry(&old_addr));
    assert!(!cp.selector_bare_warm.lock().contains_key(&node.id));
    assert_eq!(
        cp.stats
            .warm_snapshot(&generation, &cp.connection_pool)
            .selector_nodes,
        0
    );

    drop(old_server);
    generation.shutdown().await;
}

#[test]
fn udp_warm_candidates_only_use_authoritative_group_leaves() {
    let node = |name: &str, protocol| Node {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        address: "127.0.0.1:9".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(protocol),
        ..Default::default()
    };
    let anytls = node("anytls", honk_config::types::NodeProtocol::AnyTLS);
    let nested_warmable = node("socks", honk_config::types::NodeProtocol::AnyTLS);
    let cold = node("cold", honk_config::types::NodeProtocol::VMess);
    let standalone = node("standalone", honk_config::types::NodeProtocol::VMess);
    let groups = vec![
        Group {
            name: "first".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![anytls.id],
            ..Default::default()
        },
        Group {
            name: "nested".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![nested_warmable.id],
            ..Default::default()
        },
        Group {
            name: "parent".into(),
            policy: GroupPolicy::Selector,
            groups: vec!["nested".into()],
            ..Default::default()
        },
        Group {
            name: "via-final".into(),
            policy: GroupPolicy::Selector,
            final_outbound: Some("parent".into()),
            ..Default::default()
        },
        Group {
            name: "cold-urltest".into(),
            policy: GroupPolicy::URLTest,
            nodes: vec![cold.id],
            ..Default::default()
        },
        Group {
            name: "direct-final".into(),
            policy: GroupPolicy::Selector,
            final_outbound: Some("direct".into()),
            ..Default::default()
        },
    ];
    let mut config = Config::default();
    config.routing.default_outbound = "direct".into();
    config.nodes = vec![anytls.clone(), nested_warmable.clone(), cold, standalone];
    config.groups = groups;
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let runtime = honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap();

    assert_eq!(
        udp_warm_candidates(&config, &manager, &runtime, 8),
        vec![anytls.id, nested_warmable.id],
        "V4/V6 and final/nested paths deduplicate UUIDs; cold/standalone stay out, \
             direct-final contributes nothing"
    );
    assert_eq!(
        udp_warm_candidates(&config, &manager, &runtime, 1),
        vec![anytls.id, nested_warmable.id],
        "the count is a per-group cap; the process-wide cap (4x) does not bind here"
    );
    assert!(udp_warm_candidates(&config, &manager, &runtime, 0).is_empty());
}

#[test]
fn udp_warm_candidates_bound_capacity_and_exclude_explicitly_dead_udp_leaves() {
    let node = |name: &str| Node {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::AnyTLS,
        ),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    };
    let dead = node("dead-udp");
    let selected = node("selected");
    let second = node("second");
    let config = Config {
        nodes: vec![dead.clone(), selected.clone(), second.clone()],
        groups: vec![
            Group {
                name: "first".into(),
                policy: GroupPolicy::Selector,
                nodes: vec![dead.id, selected.id],
                ..Default::default()
            },
            Group {
                name: "second".into(),
                policy: GroupPolicy::Selector,
                nodes: vec![second.id],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let alive = Arc::new(crate::outbound::AliveDialerSet::new());
    for ipver in [IpVersion::V4, IpVersion::V6] {
        alive.report_unavailable_forced(dead.id, ProbeDomain::DataUdp, ipver);
        alive.report_unavailable_forced(dead.id, ProbeDomain::DnsUdp, ipver);
    }
    let manager =
        GroupManager::with_alive_set(&config.groups, &config.nodes, Some(Arc::clone(&alive)));
    let runtime = honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap();

    assert_eq!(
        udp_warm_candidates(&config, &manager, &runtime, usize::MAX),
        vec![selected.id, second.id],
        "an unbounded configured count only returns selectable leaves once across V4/V6"
    );
    assert_eq!(
        udp_warm_candidates(&config, &manager, &runtime, 1),
        vec![selected.id, second.id],
        "a per-group cap of one keeps the best live leaf of every group"
    );
}

#[test]
fn udp_warm_candidates_enforce_a_process_wide_latency_ordered_cap() {
    // Six groups of two leaves: the per-group top-2 alone would retain
    // twelve transports; the process-wide cap (4 x count = 8) keeps only
    // the globally fastest.
    let mut nodes = Vec::new();
    let mut groups = Vec::new();
    for g in 0..6 {
        let mut ids = Vec::new();
        for i in 0..2 {
            let node = Node {
                id: uuid::Uuid::new_v4(),
                name: format!("n{g}-{i}"),
                outbound: honk_config::node::OutboundConfig::from_protocol(
                    honk_config::types::NodeProtocol::AnyTLS,
                ),
                address: "127.0.0.1:9".into(),
                ..Default::default()
            };
            ids.push(node.id);
            nodes.push(node);
        }
        groups.push(Group {
            name: format!("g{g}"),
            policy: GroupPolicy::Selector,
            nodes: ids,
            ..Default::default()
        });
    }
    // Global latency order: n0-0 fastest (1ms) ... n5-1 slowest (12ms).
    let alive = Arc::new(crate::outbound::AliveDialerSet::new());
    for (index, node) in nodes.iter().enumerate() {
        alive.record_probe_latency(
            node.id,
            ProbeDomain::DataUdp,
            IpVersion::V4,
            Duration::from_millis(index as u64 + 1),
        );
    }
    let config = Config {
        nodes,
        groups,
        ..Default::default()
    };
    let manager =
        GroupManager::with_alive_set(&config.groups, &config.nodes, Some(Arc::clone(&alive)));
    let runtime = honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap();

    let candidates = udp_warm_candidates(&config, &manager, &runtime, 2);
    let expected: Vec<_> = config.nodes.iter().take(8).map(|n| n.id).collect();
    assert_eq!(candidates, expected);
}

#[test]
fn udp_warm_candidates_do_not_mutate_group_selection_state() {
    let node = |name: &str| Node {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::AnyTLS,
        ),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    };
    let (lb_a, lb_b, lb_c) = (node("lb-a"), node("lb-b"), node("lb-c"));
    let (fallback_a, fallback_b, cold) = (node("fallback-a"), node("fallback-b"), node("cold"));
    let fallback = Group {
        name: "fallback".into(),
        policy: GroupPolicy::Fallback,
        nodes: vec![fallback_a.id, fallback_b.id],
        interrupt_connections: true,
        ..Default::default()
    };
    let config = Config {
        nodes: vec![
            lb_a.clone(),
            lb_b.clone(),
            lb_c.clone(),
            fallback_a.clone(),
            fallback_b.clone(),
            cold.clone(),
        ],
        groups: vec![
            Group {
                name: "load-balance".into(),
                policy: GroupPolicy::LoadBalance,
                nodes: vec![lb_a.id, lb_b.id, lb_c.id],
                ..Default::default()
            },
            Group {
                name: "cold-urltest".into(),
                policy: GroupPolicy::URLTest,
                nodes: vec![cold.id],
                ..Default::default()
            },
            fallback,
        ],
        ..Default::default()
    };
    let alive = Arc::new(crate::outbound::AliveDialerSet::new());
    alive.register_urltest_group(
        "cold-urltest",
        std::slice::from_ref(&cold.id),
        Some(Duration::from_secs(60)),
    );
    let manager =
        GroupManager::with_alive_set(&config.groups, &config.nodes, Some(Arc::clone(&alive)));
    // Advance LB once and set the fallback pin before observing warm-up.
    assert_eq!(
        manager
            .selection_plan_for_domain("load-balance", ProbeDomain::DataUdp, IpVersion::V4)
            .nodes[0]
            .id,
        lb_a.id
    );
    assert_eq!(
        manager
            .selection_plan_for_domain("fallback", ProbeDomain::DataUdp, IpVersion::V4)
            .nodes[0]
            .id,
        fallback_a.id
    );
    let interrupts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback_interrupts = Arc::clone(&interrupts);
    manager.set_interrupt_callback(Some(Arc::new(move |_| {
        callback_interrupts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    })));
    for ipver in [IpVersion::V4, IpVersion::V6] {
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            alive.report_unavailable_forced(fallback_a.id, domain, ipver);
        }
    }
    assert!(alive.is_urltest_group_idle("cold-urltest"));
    let runtime = honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap();

    assert_eq!(
        udp_warm_candidates(&config, &manager, &runtime, 4),
        vec![lb_a.id, lb_b.id, lb_c.id, cold.id, fallback_b.id],
        "per-group top-three plus cold URLTest and the live fallback leaf,              UUID-deduplicated across V4/V6"
    );
    assert!(alive.is_urltest_group_idle("cold-urltest"));
    assert_eq!(
        manager
            .get_fallback_selection_for_network("fallback", crate::group::SelectionNetwork::Udp,),
        Some("fallback-a".into())
    );
    assert_eq!(interrupts.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        manager
            .selection_plan_for_domain("load-balance", ProbeDomain::DataUdp, IpVersion::V4)
            .nodes[0]
            .id,
        lb_b.id,
        "warm discovery must not consume the next real round-robin pick"
    );
}

#[tokio::test]
async fn udp_warm_coordinator_limits_concurrency_and_keeps_shutdown_errors_neutral() {
    let nodes: Vec<Node> = (0..5)
        .map(|n| Node {
            id: uuid::Uuid::new_v4(),
            name: format!("node-{n}"),
            outbound: honk_config::node::OutboundConfig::from_protocol(
                honk_config::types::NodeProtocol::Socks5,
            ),
            address: "127.0.0.1:9".into(),
            ..Default::default()
        })
        .collect();
    let ids = nodes.iter().map(|node| node.id).collect::<Vec<_>>();
    let generation =
        Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(&nodes).unwrap());
    let stats = Arc::new(StatsManager::new());
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dispatch = {
        let active = active.clone();
        let peak = peak.clone();
        Arc::new(move |_generation, _id| {
            let active = active.clone();
            let peak = peak.clone();
            async move {
                let now = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                Ok(honk_outbound::proxy::WarmOutcome::Ready)
            }
        })
    };
    run_udp_warm_dispatches(ids, Arc::clone(&generation), stats.clone(), dispatch).await;
    assert_eq!(peak.load(std::sync::atomic::Ordering::SeqCst), 4);
    let snapshot = stats.udp_snapshot();
    assert_eq!(
        (
            snapshot.warm_attempts,
            snapshot.warm_successes,
            snapshot.warm_failures
        ),
        (5, 5, 0)
    );

    generation.shutdown().await;
    let neutral_stats = Arc::new(StatsManager::new());
    let neutral_dispatch =
        Arc::new(|_generation, _id| async { Err(anyhow::anyhow!("old generation was shut down")) });
    run_udp_warm_dispatches(
        vec![nodes[0].id],
        generation,
        neutral_stats.clone(),
        neutral_dispatch,
    )
    .await;
    let neutral = neutral_stats.udp_snapshot();
    assert_eq!(
        (
            neutral.warm_attempts,
            neutral.warm_successes,
            neutral.warm_failures
        ),
        (1, 0, 0)
    );
}

#[tokio::test]
async fn udp_warm_dispatch_metrics_distinguish_live_and_terminal_errors_and_panics() {
    #[derive(Clone, Copy)]
    enum Outcome {
        Ready,
        NotApplicable,
        LiveError,
        TerminalError,
        LivePanic,
        TerminalPanic,
    }

    let cases = [
        ("ready", Outcome::Ready, 1, 0),
        ("not-applicable", Outcome::NotApplicable, 0, 0),
        ("live-error", Outcome::LiveError, 0, 1),
        ("terminal-error", Outcome::TerminalError, 0, 0),
        ("live-panic", Outcome::LivePanic, 0, 1),
        ("terminal-panic", Outcome::TerminalPanic, 0, 0),
    ];
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "warm-node".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::Socks5,
        ),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    };

    for (name, outcome, expected_successes, expected_failures) in cases {
        let generation = Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
                .unwrap(),
        );
        let stats = Arc::new(StatsManager::new());
        let dispatch = Arc::new(
            move |generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
                  _node_id: uuid::Uuid| async move {
                match outcome {
                    Outcome::Ready => Ok(honk_outbound::proxy::WarmOutcome::Ready),
                    Outcome::NotApplicable => Ok(honk_outbound::proxy::WarmOutcome::NotApplicable),
                    Outcome::LiveError => Err(anyhow::anyhow!("live warm error")),
                    Outcome::TerminalError => {
                        generation.shutdown().await;
                        Err(anyhow::anyhow!("terminal warm error"))
                    }
                    Outcome::LivePanic => panic!("live warm panic"),
                    Outcome::TerminalPanic => {
                        generation.shutdown().await;
                        panic!("terminal warm panic")
                    }
                }
            },
        );

        run_udp_warm_dispatches(vec![node.id], generation, Arc::clone(&stats), dispatch).await;
        let snapshot = stats.udp_snapshot();
        assert_eq!(
            (
                snapshot.warm_attempts,
                snapshot.warm_successes,
                snapshot.warm_failures,
            ),
            (1, expected_successes, expected_failures),
            "{name} outcome must update only its fixed aggregate metric"
        );
    }
}

#[tokio::test]
async fn reload_retires_only_the_old_warm_generation_and_starts_the_new_one() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct WarmCancellation(Arc<AtomicUsize>);

    impl Drop for WarmCancellation {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Debug)]
    struct BlockingWarmHandler {
        started: tokio::sync::mpsc::UnboundedSender<Arc<honk_outbound::runtime::NodeRuntime>>,
        cancelled: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl honk_outbound::proxy::TcpOutbound for BlockingWarmHandler {
        async fn dial(
            &self,
            _node: &Node,
            _target: std::net::SocketAddr,
            _target_domain: Option<&str>,
            _connect_timeout: Duration,
        ) -> anyhow::Result<honk_outbound::proxy::ProxyStream> {
            anyhow::bail!("not used by the warm coordinator")
        }
    }

    #[async_trait::async_trait]
    impl honk_outbound::proxy::WarmableOutbound for BlockingWarmHandler {
        async fn warm(
            &self,
            runtime: Arc<honk_outbound::runtime::NodeRuntime>,
            _connect_timeout: Duration,
            _requirement: honk_outbound::proxy::WarmRequirement,
        ) -> anyhow::Result<()> {
            self.started
                .send(runtime)
                .expect("warm coordinator receiver must stay open");
            let _cancel = WarmCancellation(self.cancelled.clone());
            std::future::pending::<()>().await;
            unreachable!("pending warm dispatch was unexpectedly completed")
        }
    }

    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "warm-node".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::AnyTLS,
        ),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    };
    let mut config = Config::default();
    config.global.udp_warm_node_count = 1;
    config.routing.default_outbound = "warm-group".into();
    config.nodes = vec![node.clone()];
    config.groups = vec![Group {
        name: "warm-group".into(),
        policy: GroupPolicy::Selector,
        nodes: vec![node.id],
        ..Default::default()
    }];
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let cancelled = Arc::new(AtomicUsize::new(0));
    let mut proxy_registry = ProxyRegistry::new();
    let warm_handler = Arc::new(BlockingWarmHandler {
        started: started_tx,
        cancelled: cancelled.clone(),
    });
    proxy_registry.register(
        honk_outbound::proxy::ProtocolEntry::new(
            honk_config::types::NodeProtocol::AnyTLS,
            warm_handler.clone(),
        )
        .with_warmable(warm_handler),
    );
    let mut cp = ControlPlane::new(
        config.clone(),
        Box::new(MockEbpfBackend::new()),
        router,
        Arc::new(proxy_registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        test_dns_forwarder(),
    )
    .unwrap();
    cp.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("Rule", "Proxy"),
    )));
    cp.start_datapath_flags_coordinator().unwrap();
    cp.initialize_datapath_flags(false, false).await.unwrap();

    let old_generation = cp.runtime_registry.read().clone();
    assert_eq!(
        udp_warm_candidates(
            &config,
            &cp.group_manager.read(),
            &old_generation,
            config.global.udp_warm_node_count,
        ),
        vec![node.id]
    );
    cp.start_udp_warm_coordinator(Arc::clone(&old_generation))
        .await;
    let old_runtime = tokio::time::timeout(Duration::from_secs(1), started_rx.recv())
        .await
        .expect("old warm must start")
        .expect("old runtime");
    assert!(Arc::ptr_eq(
        &old_runtime,
        &old_generation.get(&node.id).unwrap()
    ));

    // A failed build must not retire the old task or its generation.
    let mut bad = config.clone();
    bad.dns.upstream = vec![honk_config::dns::DnsUpstream {
        name: "invalid".into(),
        address: String::new(),
        protocol: honk_config::types::DnsProtocol::Udp,
        tls_server_name: None,
        outbound: None,
    }];
    cp.apply_runtime_config(bad, &DrainTracker::new()).await;
    assert!(!old_generation.is_shutdown());
    assert_eq!(cancelled.load(Ordering::SeqCst), 0);

    cp.apply_runtime_config(config, &DrainTracker::new()).await;
    let new_runtime = tokio::time::timeout(Duration::from_secs(1), started_rx.recv())
        .await
        .expect("new warm must start after reload")
        .expect("new runtime");
    let new_generation = cp.runtime_registry.read().clone();
    assert!(old_generation.is_shutdown());
    assert!(
        cancelled.load(Ordering::SeqCst) >= 1,
        "old warm must exit after its generation becomes terminal"
    );
    assert!(
        Arc::ptr_eq(&old_runtime, &new_runtime),
        "an unchanged node reuses the old generation's NodeRuntime"
    );
    assert!(Arc::ptr_eq(
        &new_runtime,
        &new_generation.get(&node.id).unwrap()
    ));

    cp.stop_udp_warm_coordinator().await;
    new_generation.shutdown().await;
}
