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
