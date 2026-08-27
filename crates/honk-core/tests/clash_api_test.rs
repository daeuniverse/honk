//! Integration tests for the Clash-compatible REST API (Phase 5).
//!
//! Boots the real axum router on 127.0.0.1:0 with a lightweight ClashState
//! (no eBPF involved) and exercises auth, proxies, mode persistence,
//! connections, delay, and cache-flush endpoints over HTTP.

#![cfg(feature = "clash-api")]

use honk_config::Config;
use honk_config::dns::{DnsConfig, DnsRouting};
use honk_config::experimental::CacheFileConfig;
use honk_config::node::{Group, Node};
use honk_config::types::NodeProtocol;
use honk_core::cachedb::CacheDb;
use honk_core::clash_api::{self, ClashState};
use honk_core::connection_tracker::{ConnectionEntry, ConnectionTracker};
use honk_core::dns::cache::DnsCache;
use honk_core::dns::forwarder::{DnsForwarder, DnsUpstreamPool, build_dns_query};
use honk_core::dns::routing::DnsRouter;
use honk_core::mode::{DatapathFlagsHandle, ModeState};
use honk_core::stats::StatsManager;
use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
use honk_outbound::group::GroupManager;
use honk_outbound::proxy::ProxyRegistry;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};
use tracing_subscriber::prelude::*;

fn make_node(name: &str) -> Node {
    Node {
        id: uuid::Uuid::new_v5(&honk_config::node::NODE_ID_NAMESPACE, name.as_bytes()),
        name: name.into(),
        protocol: NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 1,
        ..Default::default()
    }
}

/// Minimal config: one Selector group "proxy" with nodes node-a / node-b.
fn test_config() -> Config {
    let (a, b) = (make_node("node-a"), make_node("node-b"));
    let group = Group {
        name: "proxy".into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![a.id, b.id],
        ..Default::default()
    };
    Config {
        nodes: vec![a, b],
        groups: vec![group],
        ..Default::default()
    }
}

struct TestApp {
    addr: SocketAddr,
    state: Arc<ClashState>,
    log_dispatch: tracing::Dispatch,
    db_path: std::path::PathBuf,
    /// Every `set_datapath_flags` value the mock backend received.
    ebpf_datapath_flags_writes: std::sync::Arc<std::sync::Mutex<Vec<u32>>>,
    _tmp: tempfile::TempDir,
}

impl TestApp {
    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

/// Mock DNS upstream pool returning one canned wire response.
struct StaticUpstream(Vec<u8>);

#[async_trait::async_trait]
impl DnsUpstreamPool for StaticUpstream {
    async fn query(&self, _upstream: &str, _raw: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}

/// A-record response for example.com → `ip` with the given TTL.
fn a_record_response(ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let ttl = ttl.to_be_bytes();
    vec![
        0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // header
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // qname
        0x00, 0x01, 0x00, 0x01, // qtype A, qclass IN
        0xc0, 0x0c, // answer name (pointer to qname)
        0x00, 0x01, 0x00, 0x01, // type A, class IN
        ttl[0], ttl[1], ttl[2], ttl[3], // TTL
        0x00, 0x04, ip[0], ip[1], ip[2], ip[3], // rdlength + rdata
    ]
}

/// NXDOMAIN response for nx.example.com (ANCOUNT = 0, RCODE = 3).
fn nxdomain_response() -> Vec<u8> {
    vec![
        0x00, 0x00, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header
        0x02, b'n', b'x', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
        0x00, // qname
        0x00, 0x01, 0x00, 0x01, // qtype A, qclass IN
    ]
}

fn test_dns_forwarder(cache: Arc<tokio::sync::Mutex<DnsCache>>, response: Vec<u8>) -> DnsForwarder {
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            rules: vec![],
            fallback: "default".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    DnsForwarder::new(Arc::new(StaticUpstream(response)), cache, router)
}

async fn spawn_app(secret: &str, external_ui: &str) -> TestApp {
    spawn_app_with_config(test_config(), secret, external_ui).await
}

async fn spawn_app_with_config(config: Config, secret: &str, external_ui: &str) -> TestApp {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("cache.db");
    let cache_cfg = CacheFileConfig {
        enabled: true,
        path: db_path.to_str().unwrap().to_string(),
        ..Default::default()
    };
    let db = Arc::new(CacheDb::open(&cache_cfg).expect("cache.db opens"));

    let alive_set = Arc::new(AliveDialerSet::new());
    let group_manager =
        GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive_set.clone()));
    // Wire the same persistence the control plane installs in production.
    {
        let db_cb = db.clone();
        group_manager.set_persist_callback(Some(Arc::new(move |group, node| {
            db_cb.save_selector_choice(group, node);
        })));
    }
    let group_manager = group_manager.into_shared();

    let (log_layer, log_handle) = clash_api::logs::layer();
    let log_dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(log_layer));
    let dns_cache = Arc::new(tokio::sync::Mutex::new(DnsCache::new(16)));
    let dns_service = honk_core::dns::DnsService::with_forwarder(Arc::new(test_dns_forwarder(
        dns_cache,
        a_record_response([93, 184, 216, 34], 300),
    )));
    let stats = Arc::new(StatsManager::new());
    let connection_tracker = Arc::new(ConnectionTracker::new());
    let runtime_registry = honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes)
        .unwrap()
        .into_shared();
    let traffic_router =
        honk_core::routing::Router::new(&config.routing.rules, &config.routing.default_outbound)
            .unwrap();
    let ebpf_datapath_flags_writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut mock_ebpf = honk_core::ebpf::mock::MockEbpfBackend::new();
    mock_ebpf.datapath_flags_writes = ebpf_datapath_flags_writes.clone();
    let mode_state = Arc::new(parking_lot::RwLock::new(ModeState::new("Rule", "proxy")));
    let ebpf: Arc<tokio::sync::RwLock<Box<dyn honk_core::ebpf::EbpfBackend>>> =
        Arc::new(tokio::sync::RwLock::new(Box::new(mock_ebpf)));
    let datapath_flags =
        DatapathFlagsHandle::new(ebpf, Arc::clone(&mode_state), Some(Arc::clone(&db)));
    datapath_flags.initialize(0, false, false).await.unwrap();
    let state = Arc::new(ClashState {
        config: Arc::new(tokio::sync::RwLock::new(Arc::new(config))),
        stats: stats.clone(),
        alive_set,
        group_manager,
        cache_db: Some(db),
        connection_tracker: connection_tracker.clone(),
        proxy_registry: Arc::new(ProxyRegistry::default_resolver().unwrap()),
        runtime_registry,
        mode_state,
        datapath_flags,
        secret: secret.to_string(),
        external_ui: external_ui.to_string(),
        router: Arc::new(tokio::sync::RwLock::new(traffic_router)),
        log_handle,
        dns_service,
        connection_pool: Arc::new(honk_core::pool::ConnectionPool::new()),
        stream_samplers: Arc::new(clash_api::StreamSamplers::new()),
    });

    let app = clash_api::router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("axum serve error: {e:#}");
        }
    });
    // Give the server a tick to bind.
    tokio::task::yield_now().await;

    TestApp {
        addr,
        state,
        log_dispatch,
        db_path,
        ebpf_datapath_flags_writes,
        _tmp: tmp,
    }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap()
}

const SCORE_STATS_FIXTURE_LINES: &[&str] = &[
    "global {",
    "wan_interface: lo",
    "lan_interface: lo",
    "log_level: info",
    "auto_config_kernel_parameter: false",
    "nfqueue_enable: false",
    "data_dir: '__HONK_SCORE_QA_DATA_DIR__'",
    "}",
    "node {",
    "private-node-alpha: 'socks5://private-user:private-pass@private-node-alpha.invalid:16543'",
    "private-node-beta: 'socks5://private-user-2:private-pass-2@203.0.113.88:26543'",
    "}",
    "group {",
    "z-score {",
    "filter: name('private-node-alpha','private-node-beta')",
    "policy: score",
    "}",
    "a-score {",
    "filter: name('private-node-alpha','private-node-beta')",
    "policy: score",
    "}",
    "}",
    "routing {",
    "fallback: direct",
    "}",
    "experimental {",
    "clash_api {",
    "external_controller: '127.0.0.1:19090'",
    "secret: 'score-review-secret'",
    "}",
    "}",
];

fn normalized_fixture_lines(source: &str) -> Vec<&str> {
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

fn score_stats_fixture_matches(source: &str) -> bool {
    normalized_fixture_lines(source) == SCORE_STATS_FIXTURE_LINES
}

#[tokio::test]
async fn test_auth_open_when_no_secret() {
    let app = spawn_app("", "").await;
    let resp = http_client().get(app.url("/proxies")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_auth_secret_enforced() {
    let app = spawn_app("topsecret", "").await;
    let client = http_client();

    // No header → 401 with the clash error shape.
    let resp = client.get(app.url("/proxies")).send().await.unwrap();
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "Unauthorized");

    // Wrong token → 401.
    let resp = client
        .get(app.url("/proxies"))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Correct Bearer token → 200.
    let resp = client
        .get(app.url("/proxies"))
        .bearer_auth("topsecret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Non-Bearer scheme → 401.
    let resp = client
        .get(app.url("/proxies"))
        .header("Authorization", "Basic topsecret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_rules_aggregate_simple_and_preserve_complex() {
    let config = honk_config::parser::parse_dae_config(
        r#"
routing {
    sip(10.10.10.24/32,
        10.10.10.25/32
    ) -> direct
    pname(curl, wget) && l4proto(tcp) -> proxy
    dport(80, 443) -> proxy
    domain(suffix: example.com, keyword: tracker) -> proxy
    !dport(53) -> block
    dip(geoip: private) -> direct(must)
    fallback: direct
}
"#,
    )
    .unwrap();
    let app = spawn_app_with_config(config, "", "").await;

    let body: serde_json::Value = http_client()
        .get(app.url("/rules"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(
        body["rules"],
        serde_json::json!([
            {
                "type": "src-ip-cidr",
                "payload": "10.10.10.24/32,10.10.10.25/32",
                "proxy": "direct"
            },
            {
                "type": "complex",
                "payload": "pname(curl, wget) && l4proto(tcp) -> proxy",
                "proxy": "proxy"
            },
            {
                "type": "dst-port",
                "payload": "80,443",
                "proxy": "proxy"
            },
            {
                "type": "complex",
                "payload": "domain(suffix: example.com, keyword: tracker) -> proxy",
                "proxy": "proxy"
            },
            {
                "type": "complex",
                "payload": "!dport(53) -> block",
                "proxy": "block"
            },
            {
                "type": "complex",
                "payload": "dip(geoip: private) -> direct(must)",
                "proxy": "direct"
            }
        ])
    );
}

#[tokio::test]
async fn test_proxies_structure_and_selector_switch() {
    let app = spawn_app("", "").await;
    let client = http_client();
    app.state.mode_state.write().global_selection = "Proxy".to_string();

    let body: serde_json::Value = client
        .get(app.url("/proxies"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let proxies = &body["proxies"];

    // The Selector group is present with both members.
    assert_eq!(proxies["proxy"]["type"], "selector");
    assert_eq!(
        proxies["proxy"]["all"],
        serde_json::json!(["node-a", "node-b"])
    );
    // Default selection falls back to the first member.
    assert_eq!(proxies["proxy"]["now"], "node-a");
    // Group members are ALSO listed as top-level entries (clash semantics):
    // dashboards resolve member names/delays through them.
    assert_eq!(proxies["node-a"]["name"], "node-a");
    assert_eq!(proxies["node-b"]["name"], "node-b");
    assert!(proxies["node-a"]["type"].is_string());
    assert!(proxies["node-a"]["history"].is_array());
    // GLOBAL synthetic group exists with the mode-state selection.
    assert_eq!(proxies["GLOBAL"]["type"], "selector");
    assert_eq!(proxies["GLOBAL"]["now"], "proxy");
    // Every GLOBAL member is concrete, unique, and resolves to a top-level
    // proxy document; stale virtual selections fall back to the first member.
    let global_all = proxies["GLOBAL"]["all"].as_array().unwrap();
    let unique: std::collections::HashSet<_> = global_all.iter().collect();
    assert_eq!(global_all.len(), unique.len());
    assert!(!global_all.iter().any(|name| name == "Proxy"));
    for member in global_all {
        assert!(proxies.get(member.as_str().unwrap()).is_some());
    }

    // Switch the selector to node-b.
    let resp = client
        .put(app.url("/proxies/proxy"))
        .json(&serde_json::json!({"name": "node-b"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let body: serde_json::Value = client
        .get(app.url("/proxies"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["proxies"]["proxy"]["now"], "node-b");

    // The persist callback must have written cache.db.
    let db = app.state.cache_db.as_ref().unwrap();
    assert_eq!(db.load_selector_choice("proxy").as_deref(), Some("node-b"));

    // Unknown member → 400.
    let resp = client
        .put(app.url("/proxies/proxy"))
        .json(&serde_json::json!({"name": "node-x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_score_proxy_contract_and_put_rejection() {
    use honk_outbound::group::{
        ScoreOutcome, ScoreSelectionContext, ScoreTarget, SelectionNetwork,
    };

    let (a, b) = (make_node("node-a"), make_node("node-b"));
    let group = Group {
        name: "auto".into(),
        policy: honk_config::group::GroupPolicy::Score,
        nodes: vec![a.id, b.id],
        ..Default::default()
    };
    let app = spawn_app_with_config(
        Config {
            nodes: vec![a.clone(), b.clone()],
            groups: vec![group],
            ..Default::default()
        },
        "",
        "",
    )
    .await;
    let context = ScoreSelectionContext {
        network: SelectionNetwork::Tcp,
        probe_domain: ProbeDomain::Tcp,
        target_family: Some(IpVersion::V4),
        health_family: IpVersion::V4,
        target: Some(ScoreTarget::domain("seed.example", 443)),
    };
    let manager = app.state.group_manager.read().clone();
    let first = manager.selection_plan_for_target("auto", &context);
    assert_eq!(first.entries[0].node.id, a.id);
    first.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .start()
        .setup_failed(ScoreOutcome::Timeout);
    let second = manager.selection_plan_for_target("auto", &context);
    assert_eq!(second.entries[0].node.id, b.id);
    let reporter = second.entries[0].feedback.as_ref().unwrap().start();
    reporter.setup_succeeded();
    reporter.tx(1);
    reporter.rx(1);
    reporter.finish(ScoreOutcome::Success);

    let client = http_client();
    let body: serde_json::Value = client
        .get(app.url("/proxies"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["proxies"]["auto"]["type"], "url_test");
    assert_eq!(
        body["proxies"]["auto"]["all"],
        serde_json::json!(["node-a", "node-b"])
    );
    assert_eq!(body["proxies"]["auto"]["now"], "node-b");

    let response = client
        .put(app.url("/proxies/auto"))
        .json(&serde_json::json!({"name": "node-a"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert_eq!(
        app.state
            .cache_db
            .as_ref()
            .unwrap()
            .load_selector_choice("auto"),
        None
    );
    let body: serde_json::Value = client
        .get(app.url("/proxies/auto"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["now"], "node-b");
}

#[tokio::test]
async fn score_stats_are_authenticated_deterministic_and_private() {
    use honk_config::group::GroupPolicy;
    use honk_outbound::group::{ScoreSelectionContext, ScoreTarget, SelectionNetwork};

    let fixture = include_str!("fixtures/score_stats_manual.dae");
    assert!(score_stats_fixture_matches(fixture));
    let missing_default = fixture.replacen("    log_level: info\n", "", 1);
    assert!(!score_stats_fixture_matches(&missing_default));

    let config = honk_config::parser::parse_dae_config(fixture).unwrap();
    assert_eq!(
        config.experimental.clash_api.external_controller,
        "127.0.0.1:19090"
    );
    assert_eq!(config.experimental.clash_api.secret, "score-review-secret");
    assert_eq!(config.global.lan_interface, ["lo"]);
    assert_eq!(config.global.wan_interface, ["lo"]);
    assert_eq!(config.global.log_level, "info");
    assert!(!config.global.auto_config_kernel_parameter);
    assert!(!config.global.nfqueue_enable);
    assert_eq!(config.global.data_dir, "__HONK_SCORE_QA_DATA_DIR__");
    assert_eq!(config.routing.default_outbound, "direct");
    assert_eq!(
        config
            .groups
            .iter()
            .map(|group| group.name.as_str())
            .collect::<Vec<_>>(),
        ["z-score", "a-score"]
    );
    assert!(
        config
            .groups
            .iter()
            .all(|group| group.policy == GroupPolicy::Score)
    );
    assert_eq!(
        config
            .nodes
            .iter()
            .map(|node| (
                node.name.as_str(),
                node.protocol,
                node.address.as_str(),
                node.port,
                node.username.as_deref(),
                node.password.as_deref(),
            ))
            .collect::<Vec<_>>(),
        [
            (
                "private-node-alpha",
                NodeProtocol::Socks5,
                "private-node-alpha.invalid:16543",
                16543,
                Some("private-user"),
                Some("private-pass"),
            ),
            (
                "private-node-beta",
                NodeProtocol::Socks5,
                "203.0.113.88:26543",
                26543,
                Some("private-user-2"),
                Some("private-pass-2"),
            ),
        ]
    );
    let expected_members: std::collections::HashSet<_> =
        config.nodes.iter().map(|node| node.id).collect();
    for group in &config.groups {
        assert_eq!(
            group
                .nodes
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>(),
            expected_members,
            "{} must resolve exactly the two fixture nodes",
            group.name
        );
    }

    let selector = spawn_app("", "").await;
    let selector_stats: serde_json::Value = http_client()
        .get(selector.url("/stats"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(selector_stats["score"]["groups"], serde_json::json!([]));

    let app = spawn_app_with_config(config.clone(), "score-review-secret", "").await;
    let client = http_client();
    let no_auth_status = client.get(app.url("/stats")).send().await.unwrap().status();
    assert_eq!(no_auth_status, 401);
    let wrong_auth_status = client
        .get(app.url("/stats"))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(wrong_auth_status, 401);

    let context = ScoreSelectionContext {
        network: SelectionNetwork::Tcp,
        probe_domain: ProbeDomain::Tcp,
        target_family: Some(IpVersion::V4),
        health_family: IpVersion::V4,
        target: Some(ScoreTarget::domain("private-target.example", 443)),
    };
    let manager = app.state.group_manager.read().clone();
    for group in ["z-score", "a-score"] {
        assert!(
            !manager
                .selection_plan_for_target(group, &context)
                .entries
                .is_empty()
        );
    }

    let first_response = client
        .get(app.url("/stats"))
        .bearer_auth("score-review-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(first_response.status(), 200);
    let first: serde_json::Value = first_response.json().await.unwrap();
    let score = first["score"].clone();
    let expected_score = serde_json::json!({
        "groups": [
            {
                "name": "a-score",
                "tcp": {
                    "coldExplore": 1,
                    "periodicExplore": 0,
                    "reliabilityWinner": 0,
                    "performanceWinner": 0,
                    "incumbentHeld": 0,
                    "freshFailureBypass": 0,
                    "deadFiltered": 0,
                    "switchFlap": 0,
                },
                "udp": {
                    "coldExplore": 0,
                    "periodicExplore": 0,
                    "reliabilityWinner": 0,
                    "performanceWinner": 0,
                    "incumbentHeld": 0,
                    "freshFailureBypass": 0,
                    "deadFiltered": 0,
                    "switchFlap": 0,
                },
            },
            {
                "name": "z-score",
                "tcp": {
                    "coldExplore": 1,
                    "periodicExplore": 0,
                    "reliabilityWinner": 0,
                    "performanceWinner": 0,
                    "incumbentHeld": 0,
                    "freshFailureBypass": 0,
                    "deadFiltered": 0,
                    "switchFlap": 0,
                },
                "udp": {
                    "coldExplore": 0,
                    "periodicExplore": 0,
                    "reliabilityWinner": 0,
                    "performanceWinner": 0,
                    "incumbentHeld": 0,
                    "freshFailureBypass": 0,
                    "deadFiltered": 0,
                    "switchFlap": 0,
                },
            },
        ],
    });
    assert_eq!(score, expected_score);
    let mut unexpected_counter = expected_score.clone();
    unexpected_counter["groups"][0]["udp"]["periodicExplore"] = serde_json::json!(1);
    assert_ne!(score, unexpected_counter);
    assert!(first["outbounds"].is_array());
    let connections = client
        .get(app.url("/connections"))
        .bearer_auth("score-review-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(connections.status(), 200);

    let mut private_values: Vec<String> = [
        "private-target.example",
        "443",
        "private-node-alpha",
        "private-node-beta",
        "private-user",
        "private-pass",
        "private-user-2",
        "private-pass-2",
        "private-node-alpha.invalid",
        "203.0.113.88",
        "16543",
        "26543",
        "score-review-secret",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    private_values.extend(config.nodes.iter().map(|node| node.id.to_string()));
    let encoded_score = score.to_string();
    assert!(
        private_values
            .iter()
            .all(|value| !encoded_score.contains(value))
    );

    let proxies = client
        .get(app.url("/proxies"))
        .bearer_auth("score-review-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(proxies.status(), 200);
    let second: serde_json::Value = client
        .get(app.url("/stats"))
        .bearer_auth("score-review-secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(second["score"], score);
    println!(
        "score_stats status=no_auth:{no_auth_status} wrong_auth:{wrong_auth_status} correct:200 schema={score}"
    );
}

/// Dashboards (metacubexd/zashboard) send PUT/PATCH without a JSON
/// Content-Type; the API must still accept them (mihomo parity).
#[tokio::test]
async fn test_put_and_patch_without_content_type() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let resp = client
        .put(app.url("/proxies/proxy"))
        .body(r#"{"name":"node-b"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let db = app.state.cache_db.as_ref().unwrap();
    assert_eq!(db.load_selector_choice("proxy").as_deref(), Some("node-b"));

    let resp = client
        .patch(app.url("/configs"))
        .body(r#"{"mode":"global"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let body: serde_json::Value = client
        .get(app.url("/configs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["mode"], "Global");
}

/// Parent selector containing a sub-group: the sub-group tag appears in
/// `all`, is a valid PUT target (persisted + restored on "restart"), and
/// the selection chain resolves through it to the leaf.
#[tokio::test]
async fn test_nested_group_selector_via_api() {
    let (a, b, c) = (
        make_node("node-a"),
        make_node("node-b"),
        make_node("node-c"),
    );
    let sub = Group {
        name: "sub".into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![b.id, c.id],
        ..Default::default()
    };
    let parent = Group {
        name: "parent".into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![a.id],
        groups: vec!["sub".into()],
        ..Default::default()
    };
    let config = Config {
        nodes: vec![a, b, c],
        groups: vec![parent, sub],
        ..Default::default()
    };
    let app = spawn_app_with_config(config.clone(), "", "").await;
    let client = http_client();

    // `all` lists member tags: the direct node and the sub-group tag.
    let body: serde_json::Value = client
        .get(app.url("/proxies/parent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["all"], serde_json::json!(["node-a", "sub"]));
    assert_eq!(body["now"], "node-a");

    // Select the sub-group tag.
    let resp = client
        .put(app.url("/proxies/parent"))
        .json(&serde_json::json!({"name": "sub"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let body: serde_json::Value = client
        .get(app.url("/proxies/parent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["now"], "sub");
    // The chain resolves through the sub-group to its own selection.
    assert_eq!(
        app.state.group_manager.read().selection_chain("parent"),
        vec!["parent", "sub", "node-b"]
    );

    // A leaf inside the sub-group is NOT a direct member: sing-box drills
    // down layer by layer, so this must be rejected.
    let resp = client
        .put(app.url("/proxies/parent"))
        .json(&serde_json::json!({"name": "node-b"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // The persist callback wrote the sub-group tag to cache.db.
    let db = app.state.cache_db.as_ref().unwrap();
    assert_eq!(db.load_selector_choice("parent").as_deref(), Some("sub"));

    // "Restart": rebuild the manager from the same config and restore the
    // persisted choices exactly like ControlPlane::init_cache_db does.
    let restored = GroupManager::with_alive_set(
        &config.groups,
        &config.nodes,
        Some(app.state.alive_set.clone()),
    );
    for group in &config.groups {
        if group.policy == honk_config::group::GroupPolicy::Selector
            && let Some(choice) = db.load_selector_choice(&group.name)
        {
            restored.set_selector_choice(&group.name, &choice);
        }
    }
    assert_eq!(
        restored.get_selector_choice("parent").as_deref(),
        Some("sub")
    );
    // The restored choice drives selection: parent → sub → sub's leaf.
    assert_eq!(restored.select_node("parent").unwrap().name, "node-b");
    assert_eq!(
        restored.selection_chain("parent"),
        vec!["parent", "sub", "node-b"]
    );
}

#[tokio::test]
async fn test_global_selection_and_mode_persisted() {
    let app = spawn_app("", "").await;
    let client = http_client();

    // Select a group as the GLOBAL target.
    let resp = client
        .put(app.url("/proxies/GLOBAL"))
        .json(&serde_json::json!({"name": "proxy"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(app.state.mode_state.read().global_selection, "proxy");

    // Virtual and unknown GLOBAL targets do not resolve.
    for invalid in ["Proxy", "nope"] {
        let resp = client
            .put(app.url("/proxies/GLOBAL"))
            .json(&serde_json::json!({"name": invalid}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    // Switch mode to Global (case-insensitive).
    let resp = client
        .patch(app.url("/configs"))
        .json(&serde_json::json!({"mode": "global"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(app.state.mode_state.read().mode, "Global");

    // GET /configs reflects the new mode; GET /proxies reflects GLOBAL.now.
    let body: serde_json::Value = client
        .get(app.url("/configs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["mode"], "Global");
    let body: serde_json::Value = client
        .get(app.url("/proxies"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["proxies"]["GLOBAL"]["now"], "proxy");

    // Invalid mode → 400.
    let resp = client
        .patch(app.url("/configs"))
        .json(&serde_json::json!({"mode": "bogus"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Point writes are acknowledged from the in-memory pending map and become
    // crash-durable on the bounded background flush.
    let cache_cfg = CacheFileConfig {
        enabled: true,
        path: app.db_path.to_str().unwrap().to_string(),
        ..Default::default()
    };
    let reopened = CacheDb::open(&cache_cfg).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        if reopened.load_clash_mode().as_deref() == Some("Global")
            && reopened.load_selector_choice("GLOBAL").as_deref() == Some("proxy")
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "cache.db point-write durability bound exceeded"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A mode switch over PATCH /configs rewrites the datapath offload flags:
/// Rule offloads direct-routed flows, Direct offloads every
/// non-must/non-block flow, Global keeps only must-direct offload.  The
/// static NO_DOMAIN_RULES bit rides along unchanged.
#[tokio::test]
async fn test_mode_switch_updates_datapath_flags() {
    let app = spawn_app("", "").await;
    let client = http_client();

    use honk_ebpf_common::{
        DATAPATH_FLAG_OFFLOAD_ALL as OFFLOAD_ALL, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as OFFLOAD_RULE,
    };

    let writes = || app.ebpf_datapath_flags_writes.lock().unwrap().clone();
    assert_eq!(writes(), vec![OFFLOAD_RULE]);

    for (mode, expect_flags) in [
        ("global", 0),
        ("direct", OFFLOAD_ALL),
        ("rule", OFFLOAD_RULE),
    ] {
        let resp = client
            .patch(app.url("/configs"))
            .json(&serde_json::json!({"mode": mode}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);
        assert_eq!(writes().last().copied(), Some(expect_flags));
    }
    assert_eq!(writes(), vec![OFFLOAD_RULE, 0, OFFLOAD_ALL, OFFLOAD_RULE]);

    // An invalid mode must not touch the datapath flags.
    let resp = client
        .patch(app.url("/configs"))
        .json(&serde_json::json!({"mode": "bogus"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert_eq!(writes(), vec![OFFLOAD_RULE, 0, OFFLOAD_ALL, OFFLOAD_RULE]);
}

#[tokio::test]
async fn test_connections_snapshot_and_delete() {
    let app = spawn_app("", "").await;
    let client = http_client();

    // Inject one tracked connection with process attribution (as the eBPF
    // handoff provides for locally-originated flows).
    let id = app.state.connection_tracker.register(ConnectionEntry {
        id: "conn-1".into(),
        source: "10.0.0.2:12345".into(),
        destination: "142.250.72.14:443".into(),
        proxy: "proxy".into(),
        rule: "suffix".into(),
        rule_payload: "example.com".into(),
        chains: vec!["node-a".into(), "hk".into(), "proxy".into()],
        upload: std::sync::Arc::new(AtomicU64::new(100)),
        download: std::sync::Arc::new(AtomicU64::new(200)),
        start_time: Instant::now(),
        domain: Some("example.com".into()),
        network: "tcp".into(),
        process: Some("curl".into()),
        process_path: Some("/usr/bin/curl".into()),
    });
    // A LAN-forwarded flow carries no process attribution.
    app.state.connection_tracker.register(ConnectionEntry {
        id: "conn-2".into(),
        source: "[2001:db8::10]:4321".into(),
        destination: "[2001:db8::20]:443".into(),
        proxy: "proxy".into(),
        rule: "Match".into(),
        rule_payload: String::new(),
        chains: vec!["node-a".into(), "proxy".into()],
        upload: std::sync::Arc::new(AtomicU64::new(0)),
        download: std::sync::Arc::new(AtomicU64::new(0)),
        start_time: Instant::now(),
        domain: None,
        network: "udp".into(),
        process: None,
        process_path: None,
    });

    let body: serde_json::Value = client
        .get(app.url("/connections"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let conns = body["connections"].as_array().unwrap();
    assert_eq!(conns.len(), 2);
    let c = conns.iter().find(|c| c["id"] == id).unwrap();
    assert_eq!(c["metadata"]["sourceIP"], "10.0.0.2");
    assert_eq!(c["metadata"]["destinationIP"], "142.250.72.14");
    assert_eq!(c["metadata"]["sourcePort"], "12345");
    assert_eq!(c["metadata"]["host"], "example.com");
    assert_eq!(c["metadata"]["process"], "curl");
    assert_eq!(c["metadata"]["processPath"], "/usr/bin/curl");
    assert_eq!(c["upload"], 100);
    assert_eq!(c["download"], 200);
    assert_eq!(c["rule"], "suffix");
    assert_eq!(c["rulePayload"], "example.com");
    assert_eq!(
        c["chains"],
        serde_json::json!(["node-a", "hk", "proxy"]),
        "chains must be the selection path, leaf-first"
    );
    // RFC3339 start timestamp.
    let start = c["start"].as_str().unwrap();
    assert!(chrono::DateTime::parse_from_rfc3339(start).is_ok());
    // A flow without process attribution emits both keys with empty values
    // (mihomo semantics; zashboard reads processPath unguarded).
    let c2 = conns.iter().find(|c| c["id"] == "conn-2").unwrap();
    assert_eq!(c2["metadata"]["process"], "");
    assert_eq!(c2["metadata"]["processPath"], "");
    assert_eq!(c2["metadata"]["sourceIP"], "2001:db8::10");
    assert_eq!(c2["metadata"]["destinationIP"], "2001:db8::20");
    assert_eq!(c2["metadata"]["sourcePort"], "4321");
    assert_eq!(c2["metadata"]["destinationPort"], "443");
    assert_eq!(body["uploadTotal"], 100);
    assert_eq!(body["downloadTotal"], 200);

    // DELETE the single connection.
    let resp = client
        .delete(app.url(&format!("/connections/{}", id)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let body: serde_json::Value = client
        .get(app.url("/connections"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let remaining = body["connections"].as_array().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0]["id"], "conn-2");
}

/// Plaintext HTTP server answering 204 to everything.
async fn spawn_mock_http_server() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn test_group_delay_omits_failed_members() {
    let app = spawn_app("", "").await;
    let client = http_client();
    let http_addr = spawn_mock_http_server().await;

    // A lone transient failure must preserve the existing latency history.
    app.state.alive_set.record_probe_latency(
        make_node("node-a").id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(123),
    );

    // The URL is https but the server speaks plaintext HTTP: the TLS
    // handshake fails, so both members are omitted from the result.
    let url = format!("https://{}/", http_addr);
    let resp = client
        .get(app.url(&format!("/group/proxy/delay?url={}&timeout=3000", url)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let map = body.as_object().unwrap();
    assert!(
        !map.contains_key("node-a") && !map.contains_key("node-b"),
        "failed members must be omitted, got: {map:?}"
    );

    assert_eq!(
        app.state.alive_set.get_last_latency(
            make_node("node-a").id,
            ProbeDomain::Tcp,
            IpVersion::V4
        ),
        Some(Duration::from_millis(123))
    );

    // Unknown group → 404.
    let resp = client
        .get(app.url("/group/nope/delay"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_score_group_delay_returns_current_winner_latency() {
    use honk_outbound::group::{ScoreOutcome, ScoreSelectionContext, SelectionNetwork};

    let direct = Config::builtin_direct_node();
    let unreachable = make_node("unreachable");
    let group = Group {
        name: "auto-delay".into(),
        policy: honk_config::group::GroupPolicy::Score,
        nodes: vec![unreachable.id, direct.id],
        ..Default::default()
    };
    let app = spawn_app_with_config(
        Config {
            nodes: vec![unreachable.clone(), direct.clone()],
            groups: vec![group],
            ..Default::default()
        },
        "",
        "",
    )
    .await;
    let manager = app.state.group_manager.read().clone();
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    manager
        .feedback_for_group_node("auto-delay", unreachable.id, aggregate.clone())
        .unwrap()
        .start()
        .setup_failed(ScoreOutcome::Timeout);
    let reporter = manager
        .feedback_for_group_node("auto-delay", direct.id, aggregate)
        .unwrap()
        .start();
    reporter.setup_succeeded();
    reporter.tx(1);
    reporter.rx(1);
    reporter.finish(ScoreOutcome::Success);
    assert_eq!(
        manager.get_score_selection_for_network("auto-delay", SelectionNetwork::Tcp),
        Some(Config::BUILTIN_DIRECT_NODE.into())
    );

    let http_addr = spawn_mock_http_server().await;
    let response = http_client()
        .get(app.url(&format!(
            "/proxies/auto-delay/delay?url=http://{http_addr}/&timeout=1000"
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let delay = response.json::<serde_json::Value>().await.unwrap()["delay"]
        .as_u64()
        .unwrap();
    assert!(delay < 1000);
}

#[tokio::test]
async fn test_group_delay_returns_member_results_for_zashboard_core_mode() {
    let direct = Config::builtin_direct_node();
    let group = Group {
        name: "proxy".into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![direct.id],
        ..Default::default()
    };
    let app = spawn_app_with_config(
        Config {
            nodes: vec![direct],
            groups: vec![group],
            ..Default::default()
        },
        "",
        "",
    )
    .await;
    let http_addr = spawn_mock_http_server().await;

    let response = http_client()
        .get(app.url(&format!(
            "/group/proxy/delay?url=http://{http_addr}/&timeout=1000"
        )))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body[Config::BUILTIN_DIRECT_NODE].as_u64().is_some());

    let proxies: serde_json::Value = http_client()
        .get(app.url("/proxies"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        proxies["proxies"][Config::BUILTIN_DIRECT_NODE]["history"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn test_node_delay_failure_is_503() {
    let app = spawn_app("", "").await;
    let client = http_client();

    // Nothing listens on 127.0.0.1:1 → measurement fails → 503 message body.
    let resp = client
        .get(app.url("/proxies/node-a/delay?url=https://127.0.0.1:1/&timeout=1000"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["message"].as_str().unwrap().contains("delay test"));

    // Unknown proxy → 404.
    let resp = client
        .get(app.url("/proxies/nope/delay"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// Nested groups on the delay endpoints: `/group/{name}/delay` flattens
/// sub-group members to their representative leaves, consecutive failures
/// replace the leaf's display history, and `/proxies/{subgroup-tag}/delay`
/// works through the group branch.
#[tokio::test]
async fn test_nested_group_delay_endpoints() {
    let (a, b) = (make_node("node-a"), make_node("node-b"));
    let sub = Group {
        name: "sub".into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![b.id],
        ..Default::default()
    };
    let parent = Group {
        name: "parent".into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![a.id],
        groups: vec!["sub".into()],
        ..Default::default()
    };
    let config = Config {
        nodes: vec![a, b],
        groups: vec![parent, sub],
        ..Default::default()
    };
    let app = spawn_app_with_config(config, "", "").await;
    let client = http_client();

    // Seed the sub-group leaf: the parent failure is transient, while the
    // follow-up sub-group failure supplies the strike.
    app.state.alive_set.record_probe_latency(
        make_node("node-b").id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(55),
    );

    let resp = client
        .get(app.url("/group/parent/delay?url=https://127.0.0.1:1/&timeout=1000"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let map = body.as_object().unwrap();
    assert!(
        !map.contains_key("node-a") && !map.contains_key("sub"),
        "failed members must be omitted, got: {map:?}"
    );
    assert_eq!(
        app.state.alive_set.get_last_latency(
            make_node("node-b").id,
            ProbeDomain::Tcp,
            IpVersion::V4
        ),
        Some(Duration::from_millis(55)),
        "one transient failure must preserve the leaf's latency"
    );

    // The sub-group tag itself is a valid delay target (group branch):
    // its member fails the measurement → 503, not 404.
    let resp = client
        .get(app.url("/proxies/sub/delay?url=https://127.0.0.1:1/&timeout=1000"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
    assert_eq!(
        app.state.alive_set.get_last_latency(
            make_node("node-b").id,
            ProbeDomain::Tcp,
            IpVersion::V4
        ),
        Some(Duration::from_secs(10)),
        "the consecutive failure must append the penalty sample"
    );
}

#[tokio::test]
async fn test_cache_flush_endpoints() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let db = app.state.cache_db.as_ref().unwrap();
    db.set("fakeip:198.18.0.1", "example.com");
    assert!(db.get("fakeip:198.18.0.1").is_some());

    let resp = client
        .post(app.url("/cache/fakeip/flush"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert!(db.get("fakeip:198.18.0.1").is_none());
    // Unrelated keys survive the prefix flush.
    db.save_selector_choice("proxy", "node-a");
    assert!(db.load_selector_choice("proxy").is_some());

    // DNS cache flush clears both the in-memory cache and persisted answers.
    let now = honk_core::dns::persist::unix_now();
    db.save_dns_answer("example.com", 1, r#"{"r":"QUJD"}"#, now + 300);
    app.state
        .dns_service
        .cache()
        .lock()
        .await
        .put("example.com:1".into(), vec![1, 2, 3], 300);
    assert!(
        app.state
            .dns_service
            .cache()
            .lock()
            .await
            .get("example.com:1")
            .is_some()
    );
    assert_eq!(db.load_dns_answers(now).len(), 1);

    let resp = client
        .post(app.url("/cache/dns/flush"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert!(
        app.state
            .dns_service
            .cache()
            .lock()
            .await
            .get("example.com:1")
            .is_none()
    );
    assert!(db.load_dns_answers(now).is_empty());
    // The selector choice is untouched by the DNS flush.
    assert!(db.load_selector_choice("proxy").is_some());
}

#[tokio::test]
async fn test_external_ui_static_hosting() {
    let ui_tmp = tempfile::tempdir().unwrap();
    std::fs::write(ui_tmp.path().join("index.html"), "<html>honk-ui</html>").unwrap();

    let app = spawn_app("", ui_tmp.path().to_str().unwrap()).await;
    let client = http_client();

    // /ui → 301 to /ui/.
    let resp = client.get(app.url("/ui")).send().await.unwrap();
    assert_eq!(resp.status(), 301);
    assert_eq!(resp.headers()["location"], "/ui/");

    // /ui/ serves index.html.
    let resp = client.get(app.url("/ui/")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("honk-ui"));

    // Missing file → 404 (no panic).
    let resp = client.get(app.url("/ui/nope.txt")).send().await.unwrap();
    assert_eq!(resp.status(), 404);

    // Browser-style GET / redirects to the UI; JSON clients get hello.
    let resp = client.get(app.url("/")).send().await.unwrap();
    assert_eq!(resp.status(), 302);
    let resp = client
        .get(app.url("/"))
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["hello"], "clash");
}

/// /traffic pushes per-second deltas; WS auth accepts `?token=<secret>`.
#[tokio::test]
async fn test_traffic_ws_with_token_auth() {
    let app = spawn_app("topsecret", "").await;

    let ws_url = format!("ws://{}/traffic?token=topsecret", app.addr);
    let (mut ws, resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
    assert_eq!(resp.status().as_u16(), 101);

    // Let the WS task take its baseline, then add traffic: the next
    // per-second frame must report exactly this delta.
    tokio::time::sleep(Duration::from_millis(200)).await;
    {
        let stats = &app.state.stats;
        stats.record_bytes("proxy", 500, 1500);
    }

    use futures::StreamExt;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let msg = tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("traffic frame within 5s")
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&msg.into_text().unwrap()).unwrap();
        if v["up"] == 500 && v["down"] == 1500 {
            break;
        }
        // Ticks before the record landed report 0/0 — keep waiting.
    }

    // WS with a wrong token → 401 during the handshake.
    let bad_url = format!("ws://{}/traffic?token=nope", app.addr);
    let err = tokio_tungstenite::connect_async(bad_url).await;
    assert!(err.is_err());
}

/// /memory streams per-second inuse/oslimit frames (chunked HTTP here).
#[tokio::test]
async fn test_memory_chunked_reports_rss() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let mut resp = client.get(app.url("/memory")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["transfer-encoding"], "chunked");

    let chunk = tokio::time::timeout(Duration::from_secs(5), resp.chunk())
        .await
        .expect("memory frame within 5s")
        .unwrap()
        .expect("non-empty first chunk");
    let text = String::from_utf8(chunk.to_vec()).unwrap();
    let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert!(v["inuse"].as_u64().unwrap() > 0);
    assert_eq!(v["oslimit"], 0);
}

/// WS auth percent-decodes `?token=` before comparing to the secret, so
/// secrets containing reserved characters (`+`, `=`) authenticate both in
/// their percent-encoded form (what WS clients should send) and raw form.
#[tokio::test]
async fn test_ws_token_percent_decoded() {
    let secret = "s3+cr=t";
    let app = spawn_app(secret, "").await;

    // Percent-encoded form: %2B = '+', %3D = '='.
    let (mut ws, resp) =
        tokio_tungstenite::connect_async(format!("ws://{}/traffic?token=s3%2Bcr%3Dt", app.addr))
            .await
            .unwrap();
    assert_eq!(resp.status().as_u16(), 101);
    // The stream is live: a per-second traffic frame arrives.
    use futures::StreamExt;
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("traffic frame within 5s")
        .unwrap();
    assert!(msg.is_ok());
    drop(ws);

    // Raw form: '+' and '=' need no encoding inside a query value.
    let (_, resp) =
        tokio_tungstenite::connect_async(format!("ws://{}/traffic?token=s3+cr=t", app.addr))
            .await
            .unwrap();
    assert_eq!(resp.status().as_u16(), 101);

    // A token decoding to a different value is still rejected.
    let err =
        tokio_tungstenite::connect_async(format!("ws://{}/traffic?token=s3%2Bcr%3Du", app.addr))
            .await;
    assert!(err.is_err());
}

/// /connections streams the same JSON shape as plain GET.
#[tokio::test]
async fn test_connections_ws_stream() {
    let app = spawn_app("", "").await;
    app.state.connection_tracker.register(ConnectionEntry {
        id: "ws-conn".into(),
        source: "10.0.0.3:5555".into(),
        destination: "1.1.1.1:443".into(),
        proxy: "proxy".into(),
        rule: "Match".into(),
        rule_payload: String::new(),
        chains: vec!["node-a".into(), "proxy".into()],
        upload: std::sync::Arc::new(AtomicU64::new(1)),
        download: std::sync::Arc::new(AtomicU64::new(2)),
        start_time: Instant::now(),
        domain: None,
        network: "tcp".into(),
        process: None,
        process_path: None,
    });

    let ws_url = format!("ws://{}/connections?interval=200", app.addr);
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    use futures::StreamExt;
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("connections frame within 5s")
        .unwrap()
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&msg.into_text().unwrap()).unwrap();
    let conns = v["connections"].as_array().unwrap();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0]["id"], "ws-conn");
}

/// Plain GET /traffic returns a chunked JSON stream with per-second frames.
#[tokio::test]
async fn test_traffic_chunked_fallback() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let mut resp = client.get(app.url("/traffic")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "application/json");
    // Streaming bodies have no known length → chunked transfer encoding.
    assert_eq!(resp.headers()["transfer-encoding"], "chunked");

    // The first frame arrives after the first 1s tick.
    let chunk = tokio::time::timeout(Duration::from_secs(5), resp.chunk())
        .await
        .expect("traffic frame within 5s")
        .unwrap()
        .expect("non-empty first chunk");
    let text = String::from_utf8(chunk.to_vec()).unwrap();
    let first_line = text.lines().next().unwrap();
    let v: serde_json::Value = serde_json::from_str(first_line).unwrap();
    assert!(v.get("up").is_some() && v.get("down").is_some());
}

/// Plain GET /logs streams one JSON document per log event.
#[tokio::test]
async fn test_logs_chunked_fallback() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let mut resp = client.get(app.url("/logs")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "application/json");

    tracing::dispatcher::with_default(&app.log_dispatch, || {
        tracing::info!("chunked-log-line");
    });

    let chunk = tokio::time::timeout(Duration::from_secs(5), resp.chunk())
        .await
        .expect("log line within 5s")
        .unwrap()
        .expect("non-empty first chunk");
    let text = String::from_utf8(chunk.to_vec()).unwrap();
    let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(v["type"], "info");
    assert_eq!(v["payload"], "chunked-log-line");
}

#[tokio::test]
async fn test_dns_query_from_cache() {
    let app = spawn_app("", "").await;
    let client = http_client();

    // Pre-seed the shared DNS cache so the forwarder answers from cache.
    app.state.dns_service.cache().lock().await.put(
        "example.com:1".into(),
        a_record_response([93, 184, 216, 34], 300),
        300,
    );

    let body: serde_json::Value = client
        .get(app.url("/dns/query?name=example.com&type=A"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["Status"], 0);
    assert_eq!(body["Question"][0]["name"], "example.com");
    assert_eq!(body["Question"][0]["type"], 1);
    assert_eq!(body["Answer"][0]["name"], "example.com");
    assert_eq!(body["Answer"][0]["type"], 1);
    assert_eq!(body["Answer"][0]["TTL"], 300);
    assert_eq!(body["Answer"][0]["data"], "93.184.216.34");
}

#[tokio::test]
async fn test_dns_query_upstream_and_nxdomain() {
    let app = spawn_app("", "").await;
    let client = http_client();

    // Cache miss → the mock upstream answers with the canned A response.
    let body: serde_json::Value = client
        .get(app.url("/dns/query?name=example.com"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["Status"], 0);
    assert_eq!(body["Answer"][0]["data"], "93.184.216.34");

    // NXDOMAIN: swap in a forwarder whose upstream returns RCODE 3.
    let nx_service = honk_core::dns::DnsService::with_forwarder(Arc::new(test_dns_forwarder(
        app.state.dns_service.cache(),
        nxdomain_response(),
    )));
    let state = Arc::new(ClashState {
        config: app.state.config.clone(),
        stats: app.state.stats.clone(),
        alive_set: app.state.alive_set.clone(),
        group_manager: app.state.group_manager.clone(),
        cache_db: app.state.cache_db.clone(),
        connection_tracker: app.state.connection_tracker.clone(),
        proxy_registry: app.state.proxy_registry.clone(),
        runtime_registry: app.state.runtime_registry.clone(),
        mode_state: app.state.mode_state.clone(),
        datapath_flags: app.state.datapath_flags.clone(),
        secret: String::new(),
        external_ui: String::new(),
        router: app.state.router.clone(),
        log_handle: app.state.log_handle.clone(),
        dns_service: nx_service,
        connection_pool: app.state.connection_pool.clone(),
        stream_samplers: app.state.stream_samplers.clone(),
    });
    let nx_app = clash_api::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, nx_app).await;
    });

    // Fresh name so the negative cache from earlier queries does not apply.
    let body: serde_json::Value = client
        .get(format!("http://{}/dns/query?name=nx.example.com", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["Status"], 3, "NXDOMAIN maps to Status 3");
    assert_eq!(body["Answer"].as_array().unwrap().len(), 0);

    // The NXDOMAIN is now in the negative cache; the same query again is
    // answered from it with the same proper NXDOMAIN Status 3 (a negative
    // hit must not degrade into SERVFAIL).
    let body: serde_json::Value = client
        .get(format!("http://{}/dns/query?name=nx.example.com", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["Status"], 3);
    assert_eq!(body["Answer"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_dns_query_missing_name_is_400() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let resp = client.get(app.url("/dns/query")).send().await.unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["message"].as_str().unwrap().contains("name"));

    let resp = client
        .get(app.url("/dns/query?name=&type=A"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let resp = client
        .get(app.url("/dns/query?name=example.com&type=bogus"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_proxy_providers_structure() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let body: serde_json::Value = client
        .get(app.url("/providers/proxies"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let provider = &body["providers"]["proxy"];
    assert_eq!(provider["name"], "proxy");
    assert_eq!(provider["type"], "Proxy");
    assert_eq!(provider["vehicleType"], "Compatible");
    assert!(provider["updatedAt"].is_null());

    let proxies = provider["proxies"].as_array().unwrap();
    assert_eq!(proxies.len(), 2);
    assert_eq!(proxies[0]["name"], "node-a");
    assert_eq!(proxies[0]["type"], "Socks5");
    assert_eq!(proxies[0]["udp"], true);
    assert_eq!(proxies[1]["name"], "node-b");

    // Rule providers stay an empty list.
    let body: serde_json::Value = client
        .get(app.url("/providers/rules"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["providers"], serde_json::json!([]));
}

#[tokio::test]
async fn test_store_dns_persister_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("cache.db");
    let cache_cfg = CacheFileConfig {
        enabled: true,
        path: db_path.to_str().unwrap().to_string(),
        store_dns: true,
        ..Default::default()
    };
    let db = Arc::new(CacheDb::open(&cache_cfg).unwrap());

    let dns_cache = Arc::new(tokio::sync::Mutex::new(DnsCache::new(16)));
    let dns_config = DnsConfig::default();
    let policy = honk_core::dns::policy::PolicyId::from_config(&dns_config).unwrap();
    let persister = honk_core::dns::persist::DnsCachePersister::spawn(db.clone());
    assert_eq!(
        persister
            .restore_cache(&dns_cache, Some(policy.clone()))
            .await
            .expect("initial restore"),
        0
    );
    dns_cache
        .lock()
        .await
        .set_persister(Some(persister.clone()));
    let forwarder = test_dns_forwarder(dns_cache.clone(), a_record_response([1, 2, 3, 4], 300))
        .with_policy_from_config(&dns_config)
        .unwrap();
    let response = forwarder
        .resolve(&build_dns_query("example.com", 1))
        .await
        .expect("initial resolve");
    assert_eq!(response, a_record_response([1, 2, 3, 4], 300));
    persister.shutdown().await.expect("persistence shutdown");
    assert_eq!(persister.counters().written, 1);

    let now = honk_core::dns::persist::unix_now();
    db.save_dns_answer("legacy.example", 1, r#"{"r":"TEVHQUNZ"}"#, now + 300);
    let fresh_cache = Arc::new(tokio::sync::Mutex::new(DnsCache::new(16)));
    let restart = honk_core::dns::persist::DnsCachePersister::spawn(db.clone());
    assert_eq!(
        restart
            .restore_cache(&fresh_cache, Some(policy))
            .await
            .expect("restart restore"),
        1
    );

    let forwarder = test_dns_forwarder(fresh_cache, nxdomain_response())
        .with_policy_from_config(&dns_config)
        .unwrap();
    let resp = forwarder
        .resolve(&build_dns_query("example.com", 1))
        .await
        .unwrap();
    assert_eq!(resp, a_record_response([1, 2, 3, 4], 300));
    restart.shutdown().await.expect("restart shutdown");
    assert_eq!(
        db.load_dns_answers(now).len(),
        1,
        "v2 restart must leave rollback-compatible legacy rows untouched"
    );
}

#[tokio::test]
async fn stats_exposes_udp_metrics() {
    let app = spawn_app("", "").await;
    app.state.stats.record_udp_endpoint_hit();
    app.state.stats.record_udp_slow_permit_accepted();
    app.state.stats.record_udp_nfqueue_received();
    app.state.stats.increment_udp_nfqueue_active_flows();
    app.state
        .stats
        .record_udp_nfqueue_direct_accepted(Duration::from_millis(1));
    app.state.stats.record_udp_nfqueue_proxy_copied();
    app.state
        .stats
        .record_udp_nfqueue_proxy_dropped(Duration::from_millis(2));
    app.state
        .stats
        .record_udp_nfqueue_block(Duration::from_millis(3));
    app.state
        .stats
        .record_udp_nfqueue_cancel(Duration::from_millis(4));
    app.state
        .stats
        .record_udp_nfqueue_drop(Duration::from_millis(5));
    app.state.stats.record_udp_nfqueue_token_mismatch();
    app.state.stats.record_udp_nfqueue_token_exhaustion();
    app.state.stats.record_udp_nfqueue_token_rollover();
    app.state.stats.record_udp_nfqueue_verdict_error();

    let body: serde_json::Value = http_client()
        .get(app.url("/stats"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // UDP is additive: existing dashboard keys retain their shapes.
    assert!(body["outbounds"].is_array());
    assert!(body["pool"].is_object());

    let tcp = &body["tcp"];
    assert!(tcp["activeFlows"].is_u64());
    assert!(tcp["limit"].is_u64());
    assert_eq!(tcp["capacity"]["rejected"], 0);

    let udp = &body["udp"];
    assert_eq!(udp["endpoint"]["hits"], 1);
    assert_eq!(udp["endpoint"]["misses"], 0);
    assert_eq!(udp["slowPermit"]["accepted"], 1);
    assert_eq!(udp["slowPermit"]["rejected"], 0);
    assert_eq!(udp["slowPermit"]["closed"], 0);
    // Endpoint-driver queue metrics are defined now but are Task 3-owned.
    assert_eq!(udp["queue"]["accepted"], 0);
    assert_eq!(udp["queue"]["full"], 0);
    assert_eq!(udp["queue"]["closed"], 0);
    assert_eq!(udp["capacity"]["rejected"], 0);
    assert_eq!(udp["firstSend"]["failures"], 0);
    assert_eq!(udp["latency"]["route"]["count"], 0);
    assert_eq!(udp["latency"]["dial"]["count"], 0);
    assert_eq!(udp["latency"]["replyReady"]["count"], 0);
    assert_eq!(udp["latency"]["firstSend"]["count"], 0);
    assert_eq!(udp["latency"]["firstReply"]["count"], 0);
    assert_eq!(udp["stagger"]["attempts"], 0);
    assert_eq!(udp["stagger"]["winners"], 0);
    assert_eq!(udp["stagger"]["cancellations"], 0);
    assert_eq!(udp["warm"]["attempts"], 0);
    assert_eq!(udp["warm"]["successes"], 0);
    assert_eq!(udp["warm"]["failures"], 0);

    let nfqueue = &udp["nfqueue"];
    assert_eq!(nfqueue["received"], 1);
    assert_eq!(nfqueue["activeFlows"], 1);
    assert_eq!(nfqueue["kernelQueueDepth"], 0);
    assert_eq!(nfqueue["kernelStatsAvailable"], false);
    assert_eq!(nfqueue["kernelStatsReadErrors"], 0);
    assert_eq!(nfqueue["kernelDropped"], 0);
    assert_eq!(nfqueue["kernelUserDropped"], 0);
    assert_eq!(nfqueue["heldPackets"], 0);
    assert_eq!(nfqueue["heldPeak"], 0);
    assert_eq!(nfqueue["socketReceiveBufferBytes"], 0);
    assert_eq!(nfqueue["actorQueueFull"], 0);
    assert_eq!(nfqueue["correlatorFull"], 0);
    assert_eq!(nfqueue["actorQueueDepth"], 0);
    assert_eq!(nfqueue["actorQueuedBytes"], 0);
    assert_eq!(nfqueue["actorOldestAgeNanos"], 0);
    assert_eq!(nfqueue["directAccepted"], 1);
    assert_eq!(nfqueue["proxyCopied"], 1);
    assert_eq!(nfqueue["proxyDropped"], 1);
    assert_eq!(nfqueue["block"], 1);
    assert_eq!(nfqueue["cancel"], 1);
    assert_eq!(nfqueue["drop"], 1);
    assert_eq!(nfqueue["tokenMismatch"], 1);
    assert_eq!(nfqueue["tokenExhaustion"], 1);
    assert_eq!(nfqueue["tokenRollovers"], 1);
    assert_eq!(nfqueue["verdictErrors"], 1);
    assert_eq!(nfqueue["receiptToVerdict"]["count"], 5);

    // Top-level warm gauges: nodes by reason and per-protocol retained
    // sessions/clients, all zero before any warm-up runs.
    let warm = &body["warm"];
    assert_eq!(warm["nodes"]["preconnect"], 0);
    assert_eq!(warm["nodes"]["health"], 0);
    assert_eq!(warm["nodes"]["udp"], 0);
    assert_eq!(warm["nodes"]["selector"], 0);
    assert_eq!(warm["nodes"]["traffic"], 0);
    assert_eq!(warm["sessions"]["anytls"], 0);
    assert_eq!(warm["sessions"]["vless"], 0);
    assert_eq!(warm["sessions"]["tuic"], 0);
    assert_eq!(warm["sessions"]["juicity"], 0);
    assert_eq!(warm["sessions"]["hysteria2"], 0);
}
