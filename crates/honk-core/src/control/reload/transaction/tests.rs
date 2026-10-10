use super::*;

fn subscription(id: u128, name: &str, ua: Option<&str>) -> honk_config::subscription::Subscription {
    honk_config::subscription::Subscription {
        id: uuid::Uuid::from_u128(id),
        name: name.into(),
        url: "http://same-url".into(),
        user_agent: ua.map(str::to_string),
        ..Default::default()
    }
}

fn with_header(
    mut sub: honk_config::subscription::Subscription,
    value: &str,
) -> honk_config::subscription::Subscription {
    sub.headers = vec![honk_config::subscription::SubscriptionHeader {
        key: "X-Token".into(),
        value: value.into(),
    }];
    sub
}

fn subscription_node(name: &str, subscription_id: u128) -> honk_config::node::Node {
    honk_config::node::Node {
        name: name.into(),
        subscription_id: Some(uuid::Uuid::from_u128(subscription_id)),
        ..Default::default()
    }
}

#[test]
fn rebase_matches_subscription_identity_beyond_url() {
    let current = Config {
        subscriptions: vec![
            subscription(1, "a", Some("ua-a")),
            subscription(2, "b", Some("ua-b")),
        ],
        nodes: vec![
            subscription_node("node-a", 1),
            subscription_node("node-b", 2),
        ],
        ..Default::default()
    };

    // Same file with the subscription order swapped; a fresh parse assigns
    // fresh IDs.
    let mut candidate = Config {
        subscriptions: vec![
            subscription(3, "b", Some("ua-b")),
            subscription(4, "a", Some("ua-a")),
        ],
        ..Default::default()
    };

    rebase_subscription_nodes(&current, &mut candidate);

    assert_eq!(candidate.subscriptions[0].id, uuid::Uuid::from_u128(2));
    assert_eq!(candidate.subscriptions[1].id, uuid::Uuid::from_u128(1));
    let mut node_names: Vec<&str> = candidate
        .nodes
        .iter()
        .map(|node| node.name.as_str())
        .collect();
    node_names.sort_unstable();
    assert_eq!(node_names, ["node-a", "node-b"]);
    for node in &candidate.nodes {
        let expected = if node.name == "node-a" { 1 } else { 2 };
        assert_eq!(node.subscription_id, Some(uuid::Uuid::from_u128(expected)));
    }
}

#[test]
fn rebase_treats_changed_headers_as_a_new_subscription() {
    let current = Config {
        subscriptions: vec![with_header(subscription(1, "a", None), "old")],
        nodes: vec![subscription_node("node-a", 1)],
        ..Default::default()
    };
    let mut candidate = Config {
        subscriptions: vec![with_header(subscription(2, "a", None), "new")],
        ..Default::default()
    };

    rebase_subscription_nodes(&current, &mut candidate);

    assert_eq!(candidate.subscriptions[0].id, uuid::Uuid::from_u128(2));
    assert!(candidate.nodes.is_empty());
}

#[tokio::test]
async fn build_dns_forwarder_propagates_missing_external_ech_config() {
    use honk_config::node::{Node, OutboundConfig};
    use honk_config::types::NodeProtocol;

    let temp = tempfile::tempdir().unwrap();
    let ech_path = temp.path().join("ech-config");
    std::fs::write(&ech_path, "AA==").unwrap();

    let mut node = Node {
        name: "ech-node".into(),
        address: "127.0.0.1".into(),
        port: 443,
        outbound: OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
        ..Default::default()
    };
    let anytls = node.anytls_mut().unwrap();
    anytls.password = Some("password".into());
    anytls.tls.enabled = true;
    anytls.tls.ech_config_path = Some(ech_path.to_string_lossy().into_owned());
    node.id = node.derive_id();

    let config = Config {
        nodes: vec![node],
        ..Default::default()
    };

    let dns_router =
        Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(&config.dns).unwrap());
    let initial_pool = Arc::new(
        crate::dns::upstream_pool::UpstreamPool::new(&config.dns.upstream, Arc::clone(&dns_router))
            .unwrap(),
    );
    let initial_forwarder = Arc::new(crate::dns::forwarder::DnsForwarder::new(
        initial_pool,
        Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
            100,
        ))),
        Arc::clone(&dns_router),
    ));
    let traffic_router =
        Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let control_plane = crate::control::ControlPlane::new(
        config.clone(),
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        traffic_router.clone(),
        Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
        crate::dns::DnsResolver::new(&config.dns).unwrap(),
        initial_forwarder,
    )
    .unwrap();

    let source_registry =
        Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap());
    let group_manager = Arc::new(GroupManager::new(&config.groups, &config.nodes));
    let hosts_snapshot = crate::dns::forwarder::HostsSourceSet::load(&config.dns)
        .unwrap()
        .parse()
        .unwrap();
    let dns_policy = crate::dns::policy::PolicyId::from_config_with_artifacts(
        &config.dns,
        &hosts_snapshot.fingerprint(),
        &dns_router.geo_fingerprint(),
    )
    .unwrap();

    std::fs::remove_file(&ech_path).unwrap();
    let result = control_plane
        .build_dns_forwarder(
            &config,
            Arc::new(traffic_router),
            group_manager,
            source_registry,
            dns_policy,
            dns_router,
            hosts_snapshot,
        )
        .await;

    let error = result
        .err()
        .expect("missing ECH file must reject preparation");
    let source = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .expect("preparation must preserve the file I/O error");
    assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn supplied_geo_bytes_drive_reload_and_rejection_retains_live_metadata() {
    use crate::configuration::SourceUpdate;
    use crate::dns::routing::DnsRequestDecision;
    use crate::routing::{GeoAssetSnapshot, GeoRequirements, GeoSourceSet};

    let mut cp = crate::control::tests::support::control_plane(Config::default());
    cp.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("Rule", ""),
    )));
    cp.start_datapath_flags_coordinator().unwrap();
    cp.initialize_datapath_flags(false, false).await.unwrap();
    let mut config = honk_config::parser::parse_dae_config(
        "routing {\n domain(geosite:lab) -> block\n fallback: direct\n }\n\
         dns { routing { request {\n qname(geosite:lab) -> reject\n fallback: asis\n } } }",
    )
    .unwrap();
    config.ensure_builtin_nodes();
    let requirements = GeoRequirements::for_traffic(&config.routing.rules).union(
        &crate::dns::routing::DnsRouter::geo_requirements(&config.dns),
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("geosite.dat");
    let old = b"\x0a\x13\x0a\x03lab\x12\x0c\x08\x02\x12\x08old.test";
    let new = b"\x0a\x13\x0a\x03lab\x12\x0c\x08\x02\x12\x08new.test";
    let update = |bytes: &[u8]| SourceUpdate {
        sources: Vec::new(),
        dependencies: Vec::new(),
        geo_sources: Some(
            GeoSourceSet::from_assets(
                &requirements,
                vec![(
                    GeoAssetSnapshot {
                        kind: "geosite",
                        path: Some(path.clone()),
                        sha256: crate::configuration::digest(bytes),
                        size_bytes: bytes.len() as u64,
                        modified_at: None,
                    },
                    Arc::from(bytes),
                )],
            )
            .unwrap(),
        ),
    };
    let initial = update(old);
    let replacement = update(new);
    std::fs::write(&path, b"changed after capture").unwrap();
    let mut authorizations = crate::subscription::SubscriptionAuthorizations::new(&[]).unwrap();
    let drain = DrainTracker::new();
    let applied = cp
        .apply_sighup_config(
            config.clone(),
            Vec::new(),
            &drain,
            &mut authorizations,
            Some(&initial),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(applied, ReloadOutcome::Committed { .. }));
    let generation = applied.generation().unwrap();
    assert_eq!(
        cp.dns_controller
            .forwarder()
            .routing_snapshot()
            .select_request("old.test", 1),
        DnsRequestDecision::Reject,
    );
    assert_eq!(
        cp.apply_sighup_config(
            config.clone(),
            Vec::new(),
            &drain,
            &mut authorizations,
            Some(&initial),
            None,
        )
        .await
        .unwrap(),
        ReloadOutcome::Noop { generation },
    );
    assert!(matches!(
        cp.apply_sighup_config(
            config.clone(),
            Vec::new(),
            &drain,
            &mut authorizations,
            Some(&replacement),
            None,
        )
        .await
        .unwrap(),
        ReloadOutcome::Committed { .. },
    ));
    let live_assets = cp.router.read().await.geo_assets().to_vec();
    assert_eq!(live_assets[0].sha256, crate::configuration::digest(new));
    let service = crate::dns::DnsService::with_provider(cp.dns_controller.runtime_provider());
    assert_eq!(service.geo_assets(), live_assets);
    let dns_router = service.forwarder().routing_snapshot();
    assert_eq!(
        dns_router.select_request("new.test", 1),
        DnsRequestDecision::Reject
    );
    assert_eq!(
        dns_router.select_request("old.test", 1),
        DnsRequestDecision::AsIs
    );

    config.global.tproxy_port += 1;
    assert_eq!(
        cp.apply_sighup_config(
            config,
            Vec::new(),
            &drain,
            &mut authorizations,
            Some(&initial),
            None,
        )
        .await
        .unwrap(),
        ReloadOutcome::Rejected,
    );
    assert_eq!(cp.router.read().await.geo_assets(), live_assets);
    assert_eq!(service.geo_assets(), live_assets);
    let provider = cp.dns_controller.runtime_provider();
    provider.begin_pause();
    provider.finish_pause().await.unwrap();
    assert_eq!(service.geo_assets(), live_assets);
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn shared_geoip_matchers_follow_reload_ownership() {
    use crate::configuration::SourceUpdate;
    use crate::dns::routing::{DnsResponseDecision, DnsRouter};
    use crate::routing::{
        BinaryLpmTrie, CompiledPredicate, GeoAssetSnapshot, GeoRequirements, GeoSourceSet,
    };

    let mut cp = crate::control::tests::support::control_plane(Config::default());
    cp.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("Rule", ""),
    )));
    cp.start_datapath_flags_coordinator().unwrap();
    cp.initialize_datapath_flags(false, false).await.unwrap();
    let mut config = honk_config::parser::parse_dae_config(
        "routing {\n dip(geoip:lab) -> block\n fallback: direct\n }\n\
         dns { routing { response {\n ip(geoip:lab) -> reject\n fallback: accept\n } } }",
    )
    .unwrap();
    config.ensure_builtin_nodes();
    let requirements = GeoRequirements::for_traffic(&config.routing.rules)
        .union(&DnsRouter::geo_requirements(&config.dns));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("geoip.dat");
    // `lab` holds 198.51.100.0/24, then 203.0.113.0/24.
    let old = b"\x0a\x0f\x0a\x03lab\x12\x08\x0a\x04\xc6\x33\x64\x00\x10\x18";
    let new = b"\x0a\x0f\x0a\x03lab\x12\x08\x0a\x04\xcb\x00\x71\x00\x10\x18";
    let update = |bytes: &[u8]| SourceUpdate {
        sources: Vec::new(),
        dependencies: Vec::new(),
        geo_sources: Some(
            GeoSourceSet::from_assets(
                &requirements,
                vec![(
                    GeoAssetSnapshot {
                        kind: "geoip",
                        path: Some(path.clone()),
                        sha256: crate::configuration::digest(bytes),
                        size_bytes: bytes.len() as u64,
                        modified_at: None,
                    },
                    Arc::from(bytes),
                )],
            )
            .unwrap(),
        ),
    };
    let (initial, replacement) = (update(old), update(new));
    let mut authorizations = crate::subscription::SubscriptionAuthorizations::new(&[]).unwrap();
    let drain = DrainTracker::new();
    let mut apply = async |config: &Config, update: &SourceUpdate| {
        cp.apply_sighup_config(
            config.clone(),
            Vec::new(),
            &drain,
            &mut authorizations,
            Some(update),
            None,
        )
        .await
        .unwrap()
    };
    let live = async |cp: &ControlPlane| {
        let router = cp.router.read().await.clone();
        let dns = cp.dns_controller.forwarder().routing_snapshot();
        let routed = router.compiled_routes()[0].conditions[0].predicate.clone();
        let CompiledPredicate::DestinationIp(routed) = routed else {
            panic!("expected a destination IP condition");
        };
        // Each matcher owns one trie, so trie identity is matcher identity.
        let routed = Arc::clone(routed.trie());
        let answered = Arc::clone(dns.answer_ip_tries()[0]);
        (router, dns, routed, answered)
    };
    let blocks = |router: &Router, ip: &str| {
        router.route(&crate::routing::ConnectionInfo {
            domain: None,
            dst_ip: ip.parse().unwrap(),
            dst_port: 443,
            src_ip: "192.0.2.1".parse().unwrap(),
            src_port: 12345,
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        }) == "block"
    };
    let rejects = |dns: &DnsRouter, ip: &str| {
        dns.select_response("lab.test", 1, &[ip.parse().unwrap()], "")
            == DnsResponseDecision::Reject
    };
    let shared = |a: &Arc<BinaryLpmTrie>, b: &Arc<BinaryLpmTrie>| Arc::ptr_eq(a, b);

    assert!(matches!(
        apply(&config, &initial).await,
        ReloadOutcome::Committed { .. }
    ));
    let (old_router, old_dns, old_routed, answered) = live(&cp).await;
    assert!(shared(&old_routed, &answered));

    // Same path, changed bytes: the new build shares its own matcher while
    // readers of the old generation keep deciding with the old one.
    assert!(matches!(
        apply(&config, &replacement).await,
        ReloadOutcome::Committed { .. }
    ));
    let (router, dns, routed, answered) = live(&cp).await;
    assert!(shared(&routed, &answered));
    assert!(!shared(&routed, &old_routed));
    assert!(blocks(&router, "203.0.113.1") && !blocks(&router, "198.51.100.1"));
    assert!(rejects(&dns, "203.0.113.1") && !rejects(&dns, "198.51.100.1"));
    assert!(blocks(&old_router, "198.51.100.1") && !blocks(&old_router, "203.0.113.1"));
    assert!(rejects(&old_dns, "198.51.100.1") && !rejects(&old_dns, "203.0.113.1"));
    drop((old_router, old_dns));

    // A DNS build failure after the traffic router was rebuilt keeps both
    // live routers and their shared matcher.
    let mut failing = config.clone();
    failing.routing.rules.push(failing.routing.rules[0].clone());
    failing
        .dns
        .routing
        .response
        .rules
        .push(honk_config::dns::DnsResponseRule {
            conditions: vec![honk_config::dns::DnsCond::Sip {
                not: false,
                cidrs: vec!["192.0.2.0/24".into()],
            }],
            action: honk_config::dns::DnsResponseAction::Reject,
        });
    assert_eq!(apply(&failing, &replacement).await, ReloadOutcome::Rejected);
    let (_, _, live_routed, live_answered) = live(&cp).await;
    assert!(shared(&live_routed, &routed) && shared(&live_answered, &routed));

    // Only DNS rebuilds: its unchanged network list keeps the reused traffic
    // router's matcher instead of building a second copy.
    let mut dns_only = config.clone();
    dns_only
        .dns
        .routing
        .response
        .rules
        .push(dns_only.dns.routing.response.rules[0].clone());
    assert!(matches!(
        apply(&dns_only, &replacement).await,
        ReloadOutcome::Committed { .. }
    ));
    let (router, dns, live_routed, live_answered) = live(&cp).await;
    assert!(shared(&live_routed, &routed));
    assert!(shared(&live_answered, &routed));
    assert!(blocks(&router, "203.0.113.1") && rejects(&dns, "203.0.113.1"));
    assert!(!rejects(&dns, "198.51.100.1"));
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn shared_geosite_matchers_follow_reload_ownership() {
    use crate::configuration::SourceUpdate;
    use crate::dns::routing::{DnsResponseDecision, DnsRouter};
    use crate::routing::{GeoAssetSnapshot, GeoRequirements, GeoSourceSet, GeositeMatcher};

    let mut cp = crate::control::tests::support::control_plane(Config::default());
    cp.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("Rule", ""),
    )));
    cp.start_datapath_flags_coordinator().unwrap();
    cp.initialize_datapath_flags(false, false).await.unwrap();
    let mut config = honk_config::parser::parse_dae_config(
        "routing {\n domain(geosite:lab) -> block\n fallback: direct\n }\n\
         dns { routing { response {\n qname(geosite:lab) -> reject\n fallback: accept\n } } }",
    )
    .unwrap();
    config.ensure_builtin_nodes();
    let requirements = GeoRequirements::for_traffic(&config.routing.rules)
        .union(&DnsRouter::geo_requirements(&config.dns));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("geosite.dat");
    // `lab` holds the domain `old.test`, then `new.test`.
    let old = b"\x0a\x13\x0a\x03lab\x12\x0c\x08\x02\x12\x08old.test";
    let new = b"\x0a\x13\x0a\x03lab\x12\x0c\x08\x02\x12\x08new.test";
    let update = |bytes: &[u8]| SourceUpdate {
        sources: Vec::new(),
        dependencies: Vec::new(),
        geo_sources: Some(
            GeoSourceSet::from_assets(
                &requirements,
                vec![(
                    GeoAssetSnapshot {
                        kind: "geosite",
                        path: Some(path.clone()),
                        sha256: crate::configuration::digest(bytes),
                        size_bytes: bytes.len() as u64,
                        modified_at: None,
                    },
                    Arc::from(bytes),
                )],
            )
            .unwrap(),
        ),
    };
    let (initial, replacement) = (update(old), update(new));
    let mut authorizations = crate::subscription::SubscriptionAuthorizations::new(&[]).unwrap();
    let drain = DrainTracker::new();
    let mut apply = async |config: &Config, update: &SourceUpdate| {
        cp.apply_sighup_config(
            config.clone(),
            Vec::new(),
            &drain,
            &mut authorizations,
            Some(update),
            None,
        )
        .await
        .unwrap()
    };
    let live = async |cp: &ControlPlane| {
        let router = cp.router.read().await.clone();
        let dns = cp.dns_controller.forwarder().routing_snapshot();
        let routed = Arc::clone(router.geosite_matchers()[0]);
        let answered = Arc::clone(dns.geosite_matchers()[0]);
        (router, dns, routed, answered)
    };
    let blocks = |router: &Router, domain: &str| {
        router.route(&crate::routing::ConnectionInfo {
            domain: Some(domain.into()),
            dst_ip: "192.0.2.2".parse().unwrap(),
            dst_port: 443,
            src_ip: "192.0.2.1".parse().unwrap(),
            src_port: 12345,
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        }) == "block"
    };
    let rejects = |dns: &DnsRouter, domain: &str| {
        dns.select_response(domain, 1, &[], "") == DnsResponseDecision::Reject
    };
    let shared = |a: &Arc<GeositeMatcher>, b: &Arc<GeositeMatcher>| Arc::ptr_eq(a, b);

    assert!(matches!(
        apply(&config, &initial).await,
        ReloadOutcome::Committed { .. }
    ));
    let (old_router, old_dns, old_routed, answered) = live(&cp).await;
    assert!(shared(&old_routed, &answered));

    // Same path, changed bytes: the new build shares its own matcher while
    // readers of the old generation keep deciding with the old one.
    assert!(matches!(
        apply(&config, &replacement).await,
        ReloadOutcome::Committed { .. }
    ));
    let (router, dns, routed, answered) = live(&cp).await;
    assert!(shared(&routed, &answered));
    assert!(!shared(&routed, &old_routed));
    assert!(blocks(&router, "new.test") && !blocks(&router, "old.test"));
    assert!(rejects(&dns, "new.test") && !rejects(&dns, "old.test"));
    assert!(blocks(&old_router, "old.test") && !blocks(&old_router, "new.test"));
    assert!(rejects(&old_dns, "old.test") && !rejects(&old_dns, "new.test"));
    drop((old_router, old_dns));

    // A DNS build failure after the traffic router was rebuilt keeps both
    // live routers and their shared matcher.
    let mut failing = config.clone();
    failing.routing.rules.push(failing.routing.rules[0].clone());
    failing
        .dns
        .routing
        .response
        .rules
        .push(honk_config::dns::DnsResponseRule {
            conditions: vec![honk_config::dns::DnsCond::Sip {
                not: false,
                cidrs: vec!["192.0.2.0/24".into()],
            }],
            action: honk_config::dns::DnsResponseAction::Reject,
        });
    assert_eq!(apply(&failing, &replacement).await, ReloadOutcome::Rejected);
    let (_, _, live_routed, live_answered) = live(&cp).await;
    assert!(shared(&live_routed, &routed) && shared(&live_answered, &routed));

    // Only DNS rebuilds: the reused traffic router does not seed the build,
    // so this generation decides correctly without cross-router sharing.
    let mut dns_only = config.clone();
    dns_only
        .dns
        .routing
        .response
        .rules
        .push(dns_only.dns.routing.response.rules[0].clone());
    assert!(matches!(
        apply(&dns_only, &replacement).await,
        ReloadOutcome::Committed { .. }
    ));
    let (router, dns, live_routed, live_answered) = live(&cp).await;
    assert!(shared(&live_routed, &routed));
    assert!(!shared(&live_answered, &routed));
    assert!(blocks(&router, "new.test") && rejects(&dns, "new.test"));
    assert!(!rejects(&dns, "old.test"));
}
