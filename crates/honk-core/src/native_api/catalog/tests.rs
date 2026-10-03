use super::*;
use crate::native_api::pages::{MAX_SNAPSHOTS, SNAPSHOT_TTL};
use crate::observe::catalog::{Catalog, tests::fixture};
use honk_config::group::GroupPolicy;
use honk_outbound::alive::IpVersion;
use std::sync::Arc;
use std::time::{Duration, Instant};

async fn body(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), MAX_SNAPSHOT_BYTES + 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn capture(config: &Config, catalog: &Catalog, filter: Option<&str>) -> NodeSnapshot {
    node_snapshot(
        config,
        &GroupManager::new(&config.groups, &config.nodes),
        &catalog.snapshot(),
        &AliveDialerSet::new(),
        filter,
        &RequestId("request".into()),
        &ListenerSecrets::from_config(config),
    )
    .unwrap()
}

fn resume(
    pages: &NodePages,
    cursor: &str,
    group_id: Option<&str>,
    limit: usize,
    request: &RequestId,
) -> Result<Response, ApiError> {
    pages.resume(
        cursor,
        limit,
        |snapshot| snapshot.group_id.as_deref() == group_id,
        request,
    )
}

#[tokio::test]
async fn pages_freeze_rows_and_bind_instance_and_direct_group_filter() {
    let mut config = fixture();
    config.nodes[1].name = config.nodes[0].name.clone();
    let catalog = Catalog::new(&config);
    let pages = NodePages::default();
    let identity = catalog.snapshot();
    let request = RequestId("request".into());
    let parent = &identity.groups["parent"];
    let parent_page = body(
        pages
            .first(capture(&config, &catalog, Some(parent)), 100, &request)
            .unwrap(),
    )
    .await;
    assert_eq!(
        parent_page["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|node| node["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![config.nodes[0].id.to_string()]
    );

    let child = &identity.groups["child"];
    let first = body(
        pages
            .first(capture(&config, &catalog, Some(child)), 1, &request)
            .unwrap(),
    )
    .await;
    let cursor = first["next_cursor"].as_str().unwrap();
    assert!(resume(&NodePages::default(), cursor, Some(child), 1, &request).is_err());
    assert!(resume(&pages, cursor, Some(parent), 1, &request).is_err());
    assert!(resume(&pages, cursor, None, 1, &request).is_err());
    config.nodes[2].name = "new-name".into();
    config.groups.clear();
    catalog.install(&config);
    let status = |result: Result<Response, ApiError>| result.unwrap_err().into_response().status();
    assert_eq!(
        status(resume(&pages, cursor, Some(child), 100, &request)),
        StatusCode::BAD_REQUEST
    );
    let second = body(resume(&pages, cursor, Some(child), 1, &request).unwrap()).await;
    assert_eq!(second["observed_at"], first["observed_at"]);
    assert_eq!(second["nodes"][0]["name"], "node-3");
    assert_eq!(second["nodes"][0]["group_ids"], json!([child]));
    assert_eq!(second["next_cursor"], Value::Null);
    pages.0.lock()[0].created = Instant::now() - SNAPSHOT_TTL;
    let error = resume(&pages, cursor, Some(child), 1, &request)
        .unwrap_err()
        .into_response();
    assert_eq!(error.status(), StatusCode::GONE);
}

#[tokio::test]
async fn snapshot_count_and_byte_caps_evict_old_cursors_and_reject_oversized_rows() {
    let mut config = fixture();
    let catalog = Catalog::new(&config);
    let pages = NodePages::default();
    let request = RequestId("request".into());
    let first = body(
        pages
            .first(capture(&config, &catalog, None), 1, &request)
            .unwrap(),
    )
    .await;
    for _ in 0..MAX_SNAPSHOTS {
        pages
            .first(capture(&config, &catalog, None), 1, &request)
            .unwrap();
    }
    assert_eq!(pages.0.lock().len(), MAX_SNAPSHOTS);
    assert!(
        resume(
            &pages,
            first["next_cursor"].as_str().unwrap(),
            None,
            1,
            &request
        )
        .is_err()
    );

    config.nodes[0].name = "x".repeat(MAX_SNAPSHOT_BYTES / 2);
    let first_large = body(
        pages
            .first(capture(&config, &catalog, None), 1, &request)
            .unwrap(),
    )
    .await;
    pages
        .first(capture(&config, &catalog, None), 1, &request)
        .unwrap();
    assert!(
        pages
            .0
            .lock()
            .iter()
            .map(|snapshot| snapshot.bytes)
            .sum::<usize>()
            <= MAX_SNAPSHOT_BYTES
    );
    assert!(
        resume(
            &pages,
            first_large["next_cursor"].as_str().unwrap(),
            None,
            1,
            &request
        )
        .is_err()
    );

    config.nodes[0].name = "x".repeat(MAX_SNAPSHOT_BYTES);
    let response = node_snapshot(
        &config,
        &GroupManager::new(&config.groups, &config.nodes),
        &catalog.snapshot(),
        &AliveDialerSet::new(),
        None,
        &request,
        &ListenerSecrets::from_config(&config),
    )
    .err()
    .unwrap()
    .into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body(response).await["error"]["code"],
        "snapshot_unavailable"
    );
}

#[test]
fn projections_keep_duplicate_names_and_nested_member_identity_separate() {
    let mut config = fixture();
    config.nodes[0].name = "same".into();
    config.nodes[1].name = "same".into();
    config.groups[0].nodes.push(config.nodes[1].id);
    config.groups[0].default = Some("child".into());
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let identity = Catalog::new(&config).snapshot();
    let value = group_value(
        &manager,
        manager.group("parent").unwrap(),
        &identity,
        &AliveDialerSet::new(),
        true,
    );
    assert_eq!(
        value["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|member| member["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            config.nodes[0].id.to_string(),
            config.nodes[1].id.to_string(),
            identity.groups["child"].clone()
        ]
    );
    assert_eq!(
        value["runtime"]["selection"]["tcp"]["member_id"],
        identity.groups["child"]
    );
    assert_eq!(
        value["runtime"]["selection"]["tcp"]["resolved_leaf_node_id"],
        config.nodes[1].id.to_string()
    );
    assert_eq!(
        value["config"]["default_member_id"],
        identity.groups["child"]
    );

    config.groups[0].policy = GroupPolicy::Fallback;
    let manager = GroupManager::new(&config.groups, &config.nodes);
    assert_eq!(
        manager.select_node("parent").unwrap().id,
        config.nodes[0].id
    );
    assert!(
        manager
            .peek_selection("parent", SelectionNetwork::Tcp)
            .is_none()
    );
}

#[test]
fn native_reads_do_not_rotate_load_balance_wake_urltest_or_train_score() {
    let mut config = fixture();
    config.groups = [
        GroupPolicy::LoadBalance,
        GroupPolicy::URLTest,
        GroupPolicy::Score,
    ]
    .into_iter()
    .map(|policy_kind| Group {
        name: policy_kind.as_str().into(),
        policy: policy_kind,
        nodes: config.nodes.iter().map(|node| node.id).collect(),
        ..Default::default()
    })
    .collect();
    let alive = Arc::new(AliveDialerSet::new());
    alive.register_urltest_group(
        "urltest",
        &config.groups[1].nodes,
        Some(Duration::from_secs(60)),
    );
    let manager = GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive.clone()));
    let untouched = GroupManager::with_alive_set(
        &config.groups,
        &config.nodes,
        Some(Arc::new(AliveDialerSet::new())),
    );
    let identity = Catalog::new(&config).snapshot();
    let counters = manager.score_reason_snapshot();
    let cache = manager.score_cache_snapshot();
    for _ in 0..20 {
        for group in &config.groups {
            group_value(&manager, group, &identity, &alive, true);
        }
    }
    assert!(alive.is_urltest_group_idle("urltest"));
    assert!(
        manager
            .peek_selection("urltest", SelectionNetwork::Tcp)
            .is_none()
    );
    assert_eq!(manager.score_reason_snapshot(), counters);
    assert_eq!(manager.score_cache_snapshot(), cache);
    for _ in 0..8 {
        for group in ["loadbalance", "score"] {
            assert_eq!(
                manager.select_node(group).unwrap().id,
                untouched.select_node(group).unwrap().id
            );
        }
    }
}

#[test]
fn group_health_falls_back_by_member_and_full_measurement_key() {
    use honk_outbound::alive::{
        GroupProbeContext, HealthMeasurement, HealthPurpose, HealthState, HealthTransport,
        HealthWarmth, ProbeDomain,
    };

    let mut config = fixture();
    let node = &config.nodes[0];
    for (name, check_url) in [
        ("other", None),
        ("custom", Some("https://example.test/".into())),
    ] {
        config.groups.push(Group {
            name: name.into(),
            nodes: vec![node.id],
            check_url,
            ..Default::default()
        });
    }
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let identity = Catalog::new(&config).snapshot();
    let alive = AliveDialerSet::new();
    alive.enable_health_history();
    alive.register_node(node.id, node.name.clone(), "127.0.0.1:1".into());
    let ticket = alive.probe_ticket(node.id);
    let tcp = HealthObservation::probe(
        ProbeDomain::Tcp,
        HealthMeasurement::TcpConnect,
        IpVersion::V4,
        Some(Duration::from_millis(12)),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
    );
    let http = HealthObservation {
        measurement: HealthMeasurement::HttpHeaders,
        ..tcp
    };
    let dns = HealthObservation {
        measurement: HealthMeasurement::DnsRoundTrip,
        purpose: HealthPurpose::Dns,
        ..tcp
    };
    let udp_dns = HealthObservation {
        transport: HealthTransport::Udp,
        ..dns
    };
    let global = [
        tcp,
        http,
        HealthObservation {
            warmth: HealthWarmth::Warm,
            ..http
        },
        HealthObservation {
            ip_version: IpVersion::V6,
            ..http
        },
        dns,
        udp_dns,
        HealthObservation {
            purpose: HealthPurpose::Data,
            ..udp_dns
        },
    ];
    for sample in global {
        assert!(alive.complete_probe(&ticket, None, sample));
    }
    for sample in [http, udp_dns] {
        assert!(alive.complete_probe(
            &ticket,
            Some(GroupProbeContext {
                group_id: identity.groups["parent"].parse().unwrap(),
                member_id: node.id,
            }),
            HealthObservation {
                state: HealthState::Unavailable,
                latency: None,
                error: Some("probe_failed"),
                ..sample
            },
        ));
    }
    let rows = group_health(
        &manager,
        manager.group("parent").unwrap(),
        &identity,
        &alive,
    );
    assert_eq!(rows.len(), global.len());
    for row in &rows {
        assert_eq!(row["member_id"], node.id.to_string());
        assert_eq!(row["resolved_leaf_node_id"], node.id.to_string());
        let scoped = row["ip_version"] == "ipv4"
            && row["warmth"] == "cold"
            && (row["measurement"] == "http_headers"
                || row["transport"] == "udp" && row["purpose"] == "dns");
        assert_eq!(row["state"], if scoped { "unavailable" } else { "healthy" });
        assert_eq!(
            row["latency_ms"],
            if scoped { Value::Null } else { json!(12.0) }
        );
        for field in ["moving_avg_ms", "avg10_ms"] {
            assert_eq!(row[field], row["latency_ms"], "{field}");
        }
    }
    for sample in global {
        assert!(rows.iter().any(|row| {
            row["transport"] == json!(sample.transport)
                && row["purpose"] == json!(sample.purpose)
                && row["measurement"] == json!(sample.measurement)
                && row["ip_version"]
                    == if sample.ip_version == IpVersion::V4 {
                        "ipv4"
                    } else {
                        "ipv6"
                    }
                && row["warmth"] == json!(sample.warmth)
        }));
    }
    let other = group_health(&manager, manager.group("other").unwrap(), &identity, &alive);
    assert_eq!(other.len(), global.len());
    assert!(
        other
            .iter()
            .all(|row| row["state"] == "healthy" && row["latency_ms"] == json!(12.0))
    );
    assert!(
        group_health(
            &manager,
            manager.group("custom").unwrap(),
            &identity,
            &alive
        )
        .is_empty()
    );
    assert_eq!(alive.health_observations(node.id), global);
}
