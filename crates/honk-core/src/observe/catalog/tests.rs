use super::*;
use honk_config::node::Node;

pub(crate) fn fixture() -> Config {
    let mut config = Config::default();
    config.nodes = (1..=3)
        .map(|number| Node {
            id: Uuid::from_u128(number),
            name: format!("node-{number}"),
            ..Default::default()
        })
        .collect();
    config.groups = vec![
        Group {
            name: "parent".into(),
            nodes: vec![config.nodes[0].id],
            groups: vec!["child".into()],
            ..Default::default()
        },
        Group {
            name: "child".into(),
            nodes: vec![config.nodes[1].id, config.nodes[2].id],
            ..Default::default()
        },
    ];
    config
}

#[test]
fn identities_survive_reordering_but_not_removal_or_restart() {
    let mut config = fixture();
    let catalog = Catalog::new(&config);
    let original = catalog.snapshot();
    config.groups.reverse();
    for group in &mut config.groups {
        group.id = Uuid::new_v4();
    }
    config.experimental.native_api.secret = "not part of a group revision".into();
    catalog.install(&config);
    assert_eq!(catalog.snapshot().revision, original.revision);
    assert_eq!(catalog.snapshot().groups, original.groups);

    // Only URLTest reports a tolerance, so it is not part of this group's revision.
    config.groups[0].tolerance += 1;
    catalog.install(&config);
    assert_eq!(catalog.snapshot().revision, original.revision);
    config.groups[0].own.interrupt_connections = true;
    catalog.install(&config);
    assert_ne!(catalog.snapshot().revision, original.revision);
    assert_eq!(catalog.snapshot().groups, original.groups);

    let removed = config.groups.remove(0);
    catalog.install(&config);
    assert!(!catalog.snapshot().groups.contains_key(&removed.name));
    config.groups.push(removed);
    catalog.install(&config);
    assert_ne!(catalog.snapshot().groups["child"], original.groups["child"]);
    assert_eq!(
        catalog.snapshot().groups["parent"],
        original.groups["parent"]
    );
    assert_ne!(
        Catalog::new(&config).snapshot().groups["parent"],
        original.groups["parent"]
    );
}

#[test]
fn revision_and_members_follow_effective_duplicate_and_cycle_rules() {
    let mut config = fixture();
    let mut shadow = config.groups[0].clone();
    shadow.nodes.clear();
    config.groups.insert(0, shadow);
    config.groups[2].groups.push("parent".into());
    let catalog = Catalog::new(&config);
    let original = catalog.snapshot();
    config.groups[0].interrupt_connections ^= true;
    catalog.install(&config);
    assert_eq!(catalog.snapshot().revision, original.revision);
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let effective = GroupManager::effective_groups(&config.groups);
    for (name, group) in &effective {
        assert_eq!(manager.group(name).unwrap(), group);
    }
    let before = catalog.snapshot().revision.clone();
    config.groups[1].nodes.push(config.nodes[2].id);
    catalog.install(&config);
    assert_ne!(catalog.snapshot().revision, before);
}

#[test]
fn cold_nested_selection_keeps_member_without_inventing_leaf() {
    let mut config = fixture();
    config.groups[0].default = Some("child".into());
    config.groups[1].policy = GroupPolicy::URLTest;
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let identity = Catalog::new(&config).snapshot();
    let value = selection(
        &manager,
        manager.group("parent").unwrap(),
        SelectionNetwork::Tcp,
        &identity,
    );
    assert_eq!(value["member_id"], identity.groups["child"]);
    assert_eq!(value["resolved_leaf_node_id"], Value::Null);
}

#[test]
fn check_urls_remove_userinfo_and_fragments_without_rewriting_request_target() {
    let group = Group {
        check_url: Some("https://user:password@example.com:8443/a/../probe?round=1#private".into()),
        ..Default::default()
    };
    assert_eq!(
        check_url(&group).as_deref(),
        Some("https://example.com:8443/a/../probe?round=1")
    );
    assert_eq!(
        check_url(&Group {
            check_url: Some("file:///private/path".into()),
            ..Default::default()
        }),
        None
    );
}

#[test]
fn check_url_reports_the_probed_url_without_fallback_entries() {
    let configured = "http://example.test/probe,192.0.2.1,http://other.test/";
    let group = Group {
        check_url: Some(configured.into()),
        ..Default::default()
    };
    let probed = honk_outbound::urltest::health_http_probe_request(configured, "")
        .unwrap()
        .uri()
        .to_string();
    assert_eq!(probed, "http://example.test/probe");
    assert_eq!(check_url(&group), Some(probed));
}

#[test]
fn native_probe_context_keeps_exact_members_without_expanding_probe_set() {
    let mut config = fixture();
    config.nodes[0].name = "child".into();
    config.nodes[1].name = "child".into();
    config.groups[0].nodes.push(config.nodes[1].id);
    config.groups[1].default = Some("node-3".into());
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let identity = Catalog::new(&config).snapshot();
    let probes = manager.delay_test_targets("parent");
    assert_eq!(
        probes
            .iter()
            .map(|(member, _)| member_id(*member, &identity).unwrap())
            .collect::<Vec<_>>(),
        vec![
            config.nodes[0].id.to_string(),
            config.nodes[1].id.to_string(),
            identity.groups["child"].clone()
        ]
    );
    assert_eq!(
        probes.iter().map(|(_, leaf)| leaf.id).collect::<Vec<_>>(),
        vec![config.nodes[0].id, config.nodes[1].id, config.nodes[2].id]
    );
    assert_eq!(
        probes.iter().map(|(_, leaf)| leaf.id).collect::<Vec<_>>(),
        manager
            .delay_test_members("parent")
            .iter()
            .map(|(_, leaf)| leaf.id)
            .collect::<Vec<_>>()
    );
    manager
        .set_selector_choice(
            "child",
            "child",
            honk_outbound::group::SelectorNetworks::Both,
        )
        .unwrap();
    let probes = manager.delay_test_targets("parent");
    assert_eq!(
        probes
            .iter()
            .map(|(member, _)| member_id(*member, &identity).unwrap())
            .collect::<Vec<_>>(),
        vec![
            config.nodes[0].id.to_string(),
            config.nodes[1].id.to_string()
        ]
    );
    assert_eq!(probes.len(), manager.delay_test_members("parent").len());
}

#[test]
fn manual_selector_reports_runtime_selection_source() {
    let config = fixture();
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let identity = Catalog::new(&config).snapshot();
    let value = selection(
        &manager,
        manager.group("child").unwrap(),
        SelectionNetwork::Tcp,
        &identity,
    );
    assert_eq!(value["member_id"], config.nodes[1].id.to_string());
    assert_eq!(value["source"], "runtime");
}
