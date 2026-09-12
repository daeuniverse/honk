use super::*;
use crate::config_diagnostics::{DiagnosticBuckets, DiagnosticSnapshot};
use crate::control::c20_tests::{canonical_socks5, control_plane};
use crate::subscription::{SubscriptionAuthorizations, SubscriptionSupervisor};
use honk_config::diagnostic::{DetailedDiagnostic, DiagnosticSources, SafeValue, SettingPath};
use honk_config::subscription::Subscription;

fn warning(code: &'static str, line: usize) -> Vec<DetailedDiagnostic> {
    let mut diagnostic = DetailedDiagnostic::warning(
        code,
        DiagnosticSources::new(Some("/private/config.dae".into())).root(),
        SettingPath::new("global").field("check_tolerance"),
        SafeValue::Redacted,
        "invalid duration; keeping the default",
    );
    diagnostic.line = Some(line);
    vec![diagnostic]
}

async fn snapshot(cp: &ControlPlane) -> DiagnosticSnapshot {
    let config = cp.config.read().await;
    cp.diagnostics.read().snapshot(&config.subscriptions)
}

async fn fixture(config: Config, buckets: DiagnosticBuckets) -> ControlPlane {
    let mut cp = control_plane(config).await;
    cp.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("Rule", ""),
    )));
    cp.start_datapath_flags_coordinator().unwrap();
    cp.initialize_datapath_flags(false, false).await.unwrap();
    cp.install_startup_diagnostics(buckets).await;
    cp
}

async fn reload(cp: &ControlPlane, config: Config, diagnostics: Vec<DetailedDiagnostic>) -> bool {
    let current = cp.config.read().await;
    let mut authorizations = SubscriptionAuthorizations::new(&current.subscriptions).unwrap();
    drop(current);
    cp.apply_sighup_config(
        config,
        diagnostics,
        &DrainTracker::new(),
        &mut authorizations,
    )
    .await
    .unwrap()
}

fn provider_config() -> (Config, DiagnosticBuckets) {
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    let mut buckets = DiagnosticBuckets {
        static_diagnostics: warning("static", 1),
        ..Default::default()
    };
    for (index, code) in ["first", "second"].into_iter().enumerate() {
        let provider = Subscription {
            name: code.into(),
            url: format!("http://127.0.0.1:{}/", 1080 + index),
            update_interval: 0,
            ..Default::default()
        };
        config.nodes.push(canonical_socks5(
            code,
            "127.0.0.1",
            1080 + index as u16,
            Some(provider.id),
        ));
        buckets.replace_provider(provider.id, warning(code, 1));
        config.subscriptions.push(provider);
    }
    (config, buckets)
}

async fn refresh(
    cp: &ControlPlane,
    provider: &Subscription,
    nodes: Vec<Node>,
    diagnostics: Vec<DetailedDiagnostic>,
    stale: bool,
) -> Result<bool, honk_config::error::DetailedConfigError> {
    let config = cp.config.read().await;
    let authorizations = SubscriptionAuthorizations::new(&config.subscriptions).unwrap();
    let revision = authorizations.revision(provider.id).unwrap() - u64::from(stale);
    drop(config);
    cp.merge_authorized_subscription_nodes_with_drain(
        provider.id,
        revision,
        &authorizations,
        nodes,
        diagnostics,
        &DrainTracker::new(),
    )
    .await
}

#[tokio::test]
async fn c14_startup_snapshot_follows_body_and_collection_admission() {
    use tokio::io::AsyncWriteExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider = Subscription {
        name: "private-provider".into(),
        url: format!("http://{}/", listener.local_addr().unwrap()),
        update_interval: 0,
        ..Default::default()
    };
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let body = "socks5://127.0.0.1:1080#accepted\nprivate-invalid-line";
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.subscriptions.push(provider);
    let mut supervisor = SubscriptionSupervisor::prepare(&mut config, None, warning("static", 1))
        .await
        .unwrap();
    config.validate_assembled().unwrap();
    let cp = fixture(config, supervisor.take_startup_diagnostics()).await;
    let active = snapshot(&cp).await;
    assert_eq!(active.generation, 0);
    assert_eq!(active.diagnostics.len(), 2);
    assert_eq!(active.diagnostics[0].code, "static");
    assert_eq!(active.diagnostics[1].source, 1);
    assert_eq!(cp.config.read().await.nodes.len(), 1);
    server.await.unwrap();
    supervisor.shutdown().await;
}

#[tokio::test]
async fn c14_reload_replaces_snapshot_at_commit() {
    let cp = fixture(
        Config::default(),
        DiagnosticBuckets {
            static_diagnostics: warning("old", 1),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(snapshot(&cp).await.diagnostics[0].code, "old");
    let config = changed_routing_config();
    assert!(reload(&cp, config, warning("new", 2)).await);
    let active = snapshot(&cp).await;
    assert_eq!(
        active.generation,
        cp.dns_controller
            .runtime_provider()
            .current_generation()
            .get()
    );
    assert_eq!(active.generation, 1);
    assert_eq!(active.diagnostics[0].code, "new");
    assert_eq!(
        cp.config.read().await.routing.rules[0].condition.domain,
        ["reload.example"]
    );
}

#[tokio::test]
async fn c14_public_reload_replaces_full_candidate_provenance() {
    let (config, buckets) = provider_config();
    let cp = fixture(config.clone(), buckets).await;
    let mut candidate = config;
    candidate.global.check_tolerance_ms += 1;

    assert!(
        cp.reload_runtime_config(
            candidate.clone(),
            DiagnosticBuckets {
                static_diagnostics: warning("replacement", 2),
                ..Default::default()
            },
        )
        .await
    );

    assert_eq!(cp.config.read().await.as_ref(), &candidate);
    assert_eq!(
        snapshot(&cp)
            .await
            .diagnostics
            .iter()
            .map(|row| row.code)
            .collect::<Vec<_>>(),
        ["replacement"]
    );
}

#[tokio::test]
async fn c14_full_reload_preserves_provider_ownership_for_clean_refresh() {
    let (mut config, _) = provider_config();
    let provider = config.subscriptions[0].clone();
    let node = config.nodes[0].clone();
    let cp = fixture(config.clone(), DiagnosticBuckets::default()).await;
    config.global.check_tolerance_ms += 1;

    assert!(
        cp.reload_runtime_config(
            config,
            DiagnosticBuckets {
                providers: vec![(provider.id, warning("provider-warning", 2))],
                ..Default::default()
            },
        )
        .await
    );
    assert_eq!(snapshot(&cp).await.diagnostics[0].code, "provider-warning");

    cp.merge_subscription_nodes(provider.id, vec![node], Vec::new())
        .await;
    assert!(snapshot(&cp).await.diagnostics.is_empty());
}

#[tokio::test]
async fn c14_duplicate_provider_buckets_reject_even_an_unchanged_config() {
    let (config, buckets) = provider_config();
    let provider = config.subscriptions[0].id;
    let cp = fixture(config.clone(), buckets).await;
    let before = snapshot(&cp).await;
    let duplicate = DiagnosticBuckets {
        providers: vec![
            (provider, warning("duplicate-first", 2)),
            (provider, warning("duplicate-second", 3)),
        ],
        ..Default::default()
    };
    assert!(!cp.reload_runtime_config(config.clone(), duplicate).await);
    assert_eq!(snapshot(&cp).await, before);
    assert_eq!(cp.config.read().await.as_ref(), &config);
}

#[tokio::test]
async fn c14_public_merge_projects_unconfigured_provider_provenance() {
    let cp = fixture(Config::default(), DiagnosticBuckets::default()).await;
    let provider = Subscription::default();
    let mut diagnostics = Vec::new();
    let nodes = crate::subscription::parse_subscription_content_with_diagnostics(
        &provider,
        "socks5://127.0.0.1:1080#accepted\nREMARKS=private-provider-marker",
        &mut diagnostics,
    )
    .unwrap();

    cp.merge_subscription_nodes(provider.id, nodes, diagnostics)
        .await;

    assert!(
        cp.config
            .read()
            .await
            .nodes
            .iter()
            .any(|node| { node.name == "accepted" && node.subscription_id == Some(provider.id) })
    );
    let active = snapshot(&cp).await;
    assert_eq!(active.diagnostics.len(), 1);
    assert_eq!(active.sources.len(), 1);
    let diagnostic = &active.diagnostics[0];
    assert_eq!(diagnostic.code, "subscription-profile-entry");
    assert_eq!(diagnostic.setting, "entries[2]");
    assert_eq!(diagnostic.line, Some(2));
    assert_eq!(diagnostic.source, active.sources[0].id);
}

#[tokio::test]
async fn c14_sighup_retains_rebased_provider_provenance() {
    let (config, buckets) = provider_config();
    let retained_nodes = config.nodes.clone();
    let cp = fixture(config.clone(), buckets).await;
    let mut candidate = config;
    candidate.nodes.clear();
    candidate.global.check_tolerance_ms += 1;

    assert!(reload(&cp, candidate, warning("replacement", 2)).await);

    assert_eq!(cp.config.read().await.nodes, retained_nodes);
    assert_eq!(
        snapshot(&cp)
            .await
            .diagnostics
            .iter()
            .map(|row| row.code)
            .collect::<Vec<_>>(),
        ["replacement", "first", "second"]
    );
}

#[tokio::test]
async fn c14_network_refresh_preserves_active_provenance() {
    let mut config = changed_routing_config();
    config.global.lan_interface = vec!["c14-missing-lan".into()];
    config.global.wan_interface = vec!["c14-missing-wan".into()];
    config.routing.rules[0].name = "__local_direct_stale".into();
    let mut cp = fixture(
        config,
        DiagnosticBuckets {
            static_diagnostics: warning("active", 1),
            ..Default::default()
        },
    )
    .await;
    let before = snapshot(&cp).await;
    let mut authorizations = SubscriptionAuthorizations::new(&[]).unwrap();

    assert!(
        cp.dispatch_control_command(
            ControlCommand::NetworkChanged,
            &DrainTracker::new(),
            &mut authorizations,
        )
        .await
    );

    let after = snapshot(&cp).await;
    assert_eq!(after.diagnostics, before.diagnostics);
    assert_eq!(after.sources, before.sources);
    assert!(after.generation > before.generation);
}

#[tokio::test]
async fn c14_failed_reload_keeps_active_snapshot() {
    let cp = fixture(
        Config::default(),
        DiagnosticBuckets {
            static_diagnostics: warning("active", 1),
            ..Default::default()
        },
    )
    .await;
    let before = snapshot(&cp).await;
    assert_eq!(before.diagnostics[0].code, "active");
    let original = cp.config.read().await.clone();
    let mut config = original.as_ref().clone();
    config.global.log_level = "debug".into();
    assert!(
        !cp.reload_runtime_config(
            config,
            DiagnosticBuckets {
                static_diagnostics: warning("rejected", 2),
                ..Default::default()
            },
        )
        .await
    );
    assert_eq!(snapshot(&cp).await, before);
    assert_eq!(*cp.config.read().await, original);
}

#[tokio::test]
async fn c14_equal_reload_replaces_provenance_without_new_generation() {
    let cp = fixture(Config::default(), DiagnosticBuckets::default()).await;
    assert!(
        cp.reload_runtime_config(
            Config::default(),
            DiagnosticBuckets {
                static_diagnostics: warning("active", 1),
                ..Default::default()
            },
        )
        .await
    );
    let before = snapshot(&cp).await;
    let config = cp.config.read().await.as_ref().clone();
    assert!(
        cp.reload_runtime_config(
            config,
            DiagnosticBuckets {
                static_diagnostics: warning("active", 9),
                ..Default::default()
            },
        )
        .await
    );
    let after = snapshot(&cp).await;
    assert_eq!(after.generation, before.generation);
    assert_eq!(before.diagnostics[0].line, Some(1));
    assert_eq!(after.diagnostics[0].line, Some(9));
}

#[tokio::test]
async fn c14_provider_refresh_replaces_only_its_bucket() {
    let (config, buckets) = provider_config();
    let provider = config.subscriptions[0].clone();
    let cp = fixture(config, buckets).await;
    let before = snapshot(&cp).await;
    let node = canonical_socks5("new", "127.0.0.1", 1082, Some(provider.id));
    cp.merge_subscription_nodes(provider.id, vec![node.clone()], warning("replacement", 3))
        .await;
    let after = snapshot(&cp).await;
    assert_eq!(
        after
            .diagnostics
            .iter()
            .map(|row| row.code)
            .collect::<Vec<_>>(),
        ["static", "replacement", "second"]
    );
    assert_eq!(after.diagnostics[0], before.diagnostics[0]);
    assert_eq!(after.diagnostics[2], before.diagnostics[2]);
    assert!(
        cp.config
            .read()
            .await
            .nodes
            .iter()
            .any(|active| active.id == node.id)
    );
}

#[tokio::test]
async fn c14_unchanged_authorized_refresh_replaces_provenance() {
    let (config, buckets) = provider_config();
    let provider = config.subscriptions[0].clone();
    let node = config.nodes[0].clone();
    let cp = fixture(config, buckets).await;
    let before = snapshot(&cp).await;
    assert_eq!(before.diagnostics[1].line, Some(1));
    assert!(
        refresh(&cp, &provider, vec![node], warning("first", 9), false)
            .await
            .unwrap()
    );
    let after = snapshot(&cp).await;
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.diagnostics[1].line, Some(9));
    assert_eq!(after.diagnostics[0], before.diagnostics[0]);
    assert_eq!(after.diagnostics[2], before.diagnostics[2]);
}

#[tokio::test]
async fn c14_rejected_refresh_keeps_nodes_and_diagnostics() {
    let (config, buckets) = provider_config();
    let provider = config.subscriptions[0].clone();
    let mut collision = config.nodes[1].clone();
    collision.subscription_id = Some(provider.id);
    let cp = fixture(config.clone(), buckets).await;
    let before = snapshot(&cp).await;
    assert_eq!(before.diagnostics[1].code, "first");
    assert!(
        refresh(
            &cp,
            &provider,
            vec![collision],
            warning("rejected", 4),
            false
        )
        .await
        .is_err()
    );
    assert_eq!(snapshot(&cp).await, before);
    assert_eq!(cp.config.read().await.as_ref(), &config);
}

#[tokio::test]
async fn c14_stale_equal_refresh_keeps_nodes_and_diagnostics() {
    let (config, buckets) = provider_config();
    let provider = config.subscriptions[0].clone();
    let cp = fixture(config.clone(), buckets).await;
    let before = snapshot(&cp).await;
    assert_eq!(before.diagnostics[1].code, "first");
    assert!(
        !refresh(
            &cp,
            &provider,
            vec![config.nodes[0].clone()],
            warning("stale", 4),
            true
        )
        .await
        .unwrap()
    );
    assert_eq!(snapshot(&cp).await, before);
    assert_eq!(cp.config.read().await.as_ref(), &config);
}

#[tokio::test]
async fn c14_empty_refresh_has_no_body_snapshot() {
    let (config, buckets) = provider_config();
    let provider = config.subscriptions[0].clone();
    let cp = fixture(config.clone(), buckets).await;
    let before = snapshot(&cp).await;
    assert_eq!(before.diagnostics[1].code, "first");
    assert!(
        refresh(&cp, &provider, Vec::new(), warning("empty", 4), false)
            .await
            .unwrap()
    );
    cp.merge_subscription_nodes(provider.id, Vec::new(), Vec::new())
        .await;
    assert_eq!(snapshot(&cp).await, before);
    assert_eq!(cp.config.read().await.as_ref(), &config);
}

#[cfg(feature = "clash-api")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c14_get_waits_for_a_consistent_reload_commit() {
    use futures::FutureExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    let cp = Arc::new(
        fixture(
            Config::default(),
            DiagnosticBuckets {
                static_diagnostics: warning("old", 1),
                ..Default::default()
            },
        )
        .await,
    );
    let state = Arc::new(crate::clash_api::ClashState {
        config: cp.config_handle(),
        diagnostics: cp.diagnostics_handle(),
        stats: cp.stats_handle(),
        alive_set: cp.alive_set(),
        group_manager: cp.group_manager(),
        cache_db: None,
        connection_tracker: cp.connection_tracker(),
        proxy_registry: cp.proxy_registry(),
        runtime_registry: cp.runtime_registry(),
        mode_state: cp.mode_state.clone().unwrap(),
        datapath_flags: cp.datapath_flags_handle().unwrap(),
        secret: String::new(),
        connection_pool: cp.connection_pool(),
        external_ui: String::new(),
        router: cp.traffic_router(),
        log_handle: crate::clash_api::logs::layer::<tracing_subscriber::Registry>().1,
        dns_service: cp.dns_service(),
        stream_samplers: Arc::new(crate::clash_api::StreamSamplers::new()),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let request_polled = Arc::new(tokio::sync::Notify::new());
    let request_pending = Arc::new(AtomicBool::new(false));
    let polled = request_polled.clone();
    let pending = request_pending.clone();
    let app = crate::clash_api::router(state).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let polled = polled.clone();
            let pending = pending.clone();
            async move {
                let response = next.run(request);
                tokio::pin!(response);
                let first_poll = response.as_mut().now_or_never();
                pending.store(first_poll.is_none(), Ordering::SeqCst);
                polled.notify_one();
                match first_poll {
                    Some(response) => response,
                    None => response.await,
                }
            }
        },
    ));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let entered = Arc::new(tokio::sync::Notify::new());
    let (release, blocked) = std::sync::mpsc::channel();
    let notice = entered.clone();
    let _hook = cp.set_pre_dns_publication_hook(move |_| {
        notice.notify_one();
        blocked.recv_timeout(Duration::from_secs(5)).unwrap();
    });
    let reloader = cp.clone();
    let committing = tokio::spawn(async move {
        reload(&reloader, changed_routing_config(), warning("new", 2)).await
    });
    entered.notified().await;
    let response = tokio::spawn(async move {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{address}/configs"))
            .send()
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), request_polled.notified())
        .await
        .unwrap();
    release.send(()).unwrap();
    assert!(committing.await.unwrap());
    assert!(request_pending.load(Ordering::SeqCst));
    let body: serde_json::Value = response.await.unwrap().json().await.unwrap();
    assert_eq!(body["log-level"], "info");
    assert_eq!(body["honk-diagnostics"]["generation"], 1);
    assert_eq!(body["honk-diagnostics"]["diagnostics"][0]["code"], "new");
    server.abort();
}
