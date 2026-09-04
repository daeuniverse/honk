use super::*;

#[test]
fn direct_selector_fast_path_preserves_first_member_selection() {
    let a = make_node(nid("a"), "a");
    let b = make_node(nid("b"), "b");
    let group = make_group("selector", GroupPolicy::Selector, vec![a.id, b.id]);
    let manager = GroupManager::new(&[group], &[a, b]);
    assert_eq!(
        manager
            .select_node_for_domain("selector", ProbeDomain::Tcp, IpVersion::V4)
            .expect("direct selector must choose first member")
            .name,
        "a"
    );
}

#[test]
fn direct_selector_plan_fast_path_preserves_choice_default_and_health() {
    let a = make_node(nid("plan-a"), "plan-a");
    let b = make_node(nid("plan-b"), "plan-b");
    let mut group = make_group("plan-selector", GroupPolicy::Selector, vec![a.id, b.id]);
    group.default = Some(b.name.clone());
    let alive = Arc::new(AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(&[group], &[a, b], Some(Arc::clone(&alive)));

    assert_eq!(
        manager
            .selection_plan_for_domain("plan-selector", ProbeDomain::Tcp, IpVersion::V4)
            .nodes[0]
            .name,
        "plan-b"
    );
    manager.set_selector_choice("plan-selector", "plan-a");
    assert_eq!(
        manager
            .selection_plan_for_domain("plan-selector", ProbeDomain::Tcp, IpVersion::V4)
            .nodes[0]
            .name,
        "plan-a"
    );
    alive.report_unavailable_forced(nid("plan-a"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(
        manager
            .selection_plan_for_domain("plan-selector", ProbeDomain::Tcp, IpVersion::V4)
            .nodes[0]
            .name,
        "plan-b"
    );
}

#[test]
fn dead_single_leaf_remains_a_tcp_last_resort_only() {
    let node = make_node(nid("last-resort"), "last-resort");
    let single = make_group("single", GroupPolicy::Selector, vec![node.id]);
    let child = make_group("child", GroupPolicy::Selector, vec![node.id]);
    let parent = make_subgroup("parent", GroupPolicy::Selector, &["child"]);
    let alive = Arc::new(AliveDialerSet::new());
    alive.report_unavailable_forced(node.id, ProbeDomain::Tcp, IpVersion::V4);
    let manager = GroupManager::with_alive_set(
        &[single.clone(), child.clone(), parent.clone()],
        std::slice::from_ref(&node),
        Some(Arc::clone(&alive)),
    );

    for group in ["single", "parent"] {
        assert_eq!(
            manager
                .selection_plan_for_domain(group, ProbeDomain::Tcp, IpVersion::V4)
                .nodes
                .first()
                .map(|node| node.name.as_str()),
            Some("last-resort")
        );
        assert_eq!(
            manager
                .select_node_for_domain(group, ProbeDomain::Tcp, IpVersion::V4)
                .map(|node| node.name.as_str()),
            Some("last-resort")
        );
    }

    for domain in [ProbeDomain::DnsUdp, ProbeDomain::DataUdp] {
        alive.report_unavailable_forced(node.id, domain, IpVersion::V4);
    }
    assert!(
        manager
            .selection_plan_for_domain("single", ProbeDomain::DataUdp, IpVersion::V4)
            .nodes
            .is_empty()
    );

    let mut with_final = single;
    with_final.final_outbound = Some("block".into());
    let manager =
        GroupManager::with_alive_set(&[with_final], std::slice::from_ref(&node), Some(alive));
    assert!(
        manager
            .selection_plan_for_domain("single", ProbeDomain::Tcp, IpVersion::V4)
            .nodes
            .is_empty()
    );
}
use chrono::Utc;

fn nid(name: &str) -> uuid::Uuid {
    uuid::Uuid::new_v5(&honk_config::node::NODE_ID_NAMESPACE, name.as_bytes())
}

fn make_node(id: uuid::Uuid, name: &str) -> Node {
    Node {
        id,
        name: name.into(),
        ..Default::default()
    }
}

fn make_group(name: &str, policy: GroupPolicy, ids: Vec<uuid::Uuid>) -> Group {
    Group {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        policy,
        nodes: ids,
        filters: vec![],
        groups: vec![],
        default: None,
        final_outbound: None,
        check_url: None,
        check_interval: None,
        tolerance: 50,
        idle_timeout: None,
        interrupt_connections: false,
        created_at: Utc::now(),
    }
}

fn make_subgroup(name: &str, policy: GroupPolicy, sub_tags: &[&str]) -> Group {
    let mut g = make_group(name, policy, vec![]);
    g.groups = sub_tags.iter().map(|s| s.to_string()).collect();
    g
}

#[test]
fn test_selector_default_first_alive() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let m = GroupManager::new(
        &[make_group("g", GroupPolicy::Selector, vec![n1, n2])],
        &nodes,
    );
    // Without alive_set, all nodes are considered alive.
    let selected = m.select_node("g").unwrap();
    assert_eq!(selected.id, n1);
}

#[test]
fn test_selector_with_default_name() {
    let (n1, n2) = (nid("alpha"), nid("beta"));
    let nodes = vec![make_node(n1, "alpha"), make_node(n2, "beta")];
    let mut group = make_group("g", GroupPolicy::Selector, vec![n1, n2]);
    group.default = Some("beta".into());
    let m = GroupManager::new(&[group], &nodes);
    let selected = m.select_node("g").unwrap();
    assert_eq!(selected.name, "beta");
}

#[test]
fn test_selector_runtime_choice_overrides_default() {
    let (n1, n2, n3) = (nid("a"), nid("b"), nid("c"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b"), make_node(n3, "c")];
    let mut group = make_group("g", GroupPolicy::Selector, vec![n1, n2, n3]);
    group.default = Some("b".into());
    let m = GroupManager::new(&[group], &nodes);
    m.set_selector_choice("g", "c");
    let selected = m.select_node("g").unwrap();
    assert_eq!(selected.name, "c");
}

#[test]
fn selector_choice_filtered_by_health_falls_back_without_rewriting_choice() {
    let (a, b) = (nid("sel-a"), nid("sel-b"));
    let nodes = vec![make_node(a, "sel-a"), make_node(b, "sel-b")];
    let group = make_group("g", GroupPolicy::Selector, vec![a, b]);
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(&[group], &nodes, Some(alive.clone()));
    m.set_selector_choice("g", "sel-a");
    alive.report_unavailable_forced(a, ProbeDomain::Tcp, IpVersion::V4);

    let selected = m
        .select_node_for_domain("g", ProbeDomain::Tcp, IpVersion::V4)
        .unwrap();
    assert_eq!(
        selected.name, "sel-b",
        "a health-filtered choice falls back to the first alive member"
    );
    assert_eq!(
        m.get_selector_choice("g").as_deref(),
        Some("sel-a"),
        "the stored choice is preserved so recovery restores it"
    );

    // The fallback is rate-limit logged once per (group, network); a second
    // pick inside the cooldown leaves the timestamp untouched.
    let key = ("g".to_string(), SelectionNetwork::Tcp);
    let first_at = m.selector_fallback_log.read().get(&key).copied();
    assert!(first_at.is_some(), "a filtered-choice fallback is logged");
    m.select_node_for_domain("g", ProbeDomain::Tcp, IpVersion::V4)
        .unwrap();
    let second_at = m.selector_fallback_log.read().get(&key).copied();
    assert_eq!(first_at, second_at, "the warn is rate-limited");
}

#[test]
fn selector_default_filtered_by_health_falls_back_with_log() {
    let (a, b) = (nid("def-a"), nid("def-b"));
    let nodes = vec![make_node(a, "def-a"), make_node(b, "def-b")];
    let mut group = make_group("gd", GroupPolicy::Selector, vec![a, b]);
    group.default = Some("def-a".into());
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(&[group], &nodes, Some(alive.clone()));
    alive.report_unavailable_forced(a, ProbeDomain::Tcp, IpVersion::V4);

    let selected = m
        .select_node_for_domain("gd", ProbeDomain::Tcp, IpVersion::V4)
        .unwrap();
    assert_eq!(selected.name, "def-b");
    assert!(
        m.selector_fallback_log
            .read()
            .contains_key(&("gd".to_string(), SelectionNetwork::Tcp)),
        "a health-filtered default is as invisible as a filtered choice"
    );
}

#[test]
fn selector_all_filtered_serves_last_resort_leaf_with_log() {
    let a = nid("lr-a");
    let nodes = vec![make_node(a, "lr-a")];
    let group = make_group("lr", GroupPolicy::Selector, vec![a]);
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(&[group], &nodes, Some(alive.clone()));
    alive.report_unavailable_forced(a, ProbeDomain::Tcp, IpVersion::V4);

    let selected = m
        .select_node_for_domain("lr", ProbeDomain::Tcp, IpVersion::V4)
        .unwrap();
    assert_eq!(selected.name, "lr-a", "the sole leaf stays dialable");
    assert!(
        m.selector_fallback_log
            .read()
            .contains_key(&("lr".to_string(), SelectionNetwork::Tcp)),
        "the last-resort serve is logged"
    );
}

#[test]
fn selector_warm_node_keeps_configured_dead_leaf_and_resolves_nested_choice() {
    let (a, b) = (nid("warm-a"), nid("warm-b"));
    let nodes = vec![make_node(a, "warm-a"), make_node(b, "warm-b")];
    let mut child = make_group("warm-child", GroupPolicy::Selector, vec![a, b]);
    child.default = Some("warm-b".into());
    let parent = make_subgroup("warm-parent", GroupPolicy::Selector, &["warm-child"]);
    let alive = Arc::new(AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(&[child, parent], &nodes, Some(alive.clone()));

    manager.set_selector_choice("warm-child", "warm-a");
    alive.report_unavailable_forced(a, ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(
        manager
            .selector_warm_node("warm-parent")
            .map(|node| node.id),
        Some(a),
        "warm ownership follows the configured choice instead of liveness fallback"
    );
}

#[test]
fn test_not_found() {
    let n = make_node(nid("x"), "x");
    let m = GroupManager::new(&[make_group("g", GroupPolicy::Selector, vec![n.id])], &[n]);
    assert!(m.select_node("nope").is_none());
    assert!(m.get_group_policy("nope").is_none());
}

#[test]
fn test_selector_choice_get_set() {
    let m = GroupManager::new(&[], &[]);
    assert!(m.get_selector_choice("g").is_none());
    m.set_selector_choice("g", "node1");
    assert_eq!(m.get_selector_choice("g"), Some("node1".into()));
}

#[test]
fn test_urltest_selection() {
    let n = nid("a");
    let nodes = vec![make_node(n, "a")];
    let m = GroupManager::new(&[make_group("g", GroupPolicy::URLTest, vec![n])], &nodes);
    let selected = m.select_node("g").unwrap();
    assert_eq!(selected.id, n);
    assert_eq!(m.get_urltest_selection("g"), Some("a".into()));
}

#[test]
fn test_group_policy() {
    let n = nid("a");
    let nodes = vec![make_node(n, "a")];
    let m = GroupManager::new(
        &[
            make_group("sel", GroupPolicy::Selector, vec![n]),
            make_group("url", GroupPolicy::URLTest, vec![n]),
        ],
        &nodes,
    );
    assert_eq!(m.get_group_policy("sel"), Some(GroupPolicy::Selector));
    assert_eq!(m.get_group_policy("url"), Some(GroupPolicy::URLTest));
}

#[test]
fn test_node_names_in_group() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let m = GroupManager::new(
        &[make_group("g", GroupPolicy::Selector, vec![n1, n2])],
        &nodes,
    );
    let names = m.node_names_in_group("g");
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"a".to_string()));
    assert!(names.contains(&"b".to_string()));
}

#[test]
fn test_idle_default() {
    let n = nid("a");
    let nodes = vec![make_node(n, "a")];
    // No idle_timeout → never idle
    let m = GroupManager::new(&[make_group("g", GroupPolicy::Selector, vec![n])], &nodes);
    assert!(!m.is_group_idle("g"));
}

#[test]
fn test_idle_with_timeout() {
    let n = nid("a");
    let nodes = vec![make_node(n, "a")];
    let mut group = make_group("g", GroupPolicy::Selector, vec![n]);
    group.idle_timeout = Some(1);
    let m = GroupManager::new(&[group], &nodes);
    // Never used → idle.
    assert!(m.is_group_idle("g"));
    m.select_node("g");
    assert!(!m.is_group_idle("g"));
    std::thread::sleep(Duration::from_secs(1));
    assert!(m.is_group_idle("g"));
}

#[test]
fn test_final_outbound() {
    let n = nid("a");
    let nodes = vec![make_node(n, "a")];
    let mut group = make_group("g", GroupPolicy::Selector, vec![n]);
    group.final_outbound = Some("direct".into());
    let m = GroupManager::new(&[group], &nodes);
    assert_eq!(m.get_final_outbound("g"), Some("direct".into()));
    assert_eq!(m.get_final_outbound("nope"), None);
}

#[test]
fn test_persist_callback_on_selector_change() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let m = GroupManager::new(
        &[make_group("g", GroupPolicy::Selector, vec![n1, n2])],
        &nodes,
    );
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls2 = calls.clone();
    m.set_persist_callback(Some(Arc::new(move |g, n| {
        calls2.lock().unwrap().push((g.to_string(), n.to_string()));
    })));

    m.set_selector_choice("g", "a");
    m.set_selector_choice("g", "a"); // unchanged → no extra call
    m.set_selector_choice("g", "b");
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[
            ("g".to_string(), "a".to_string()),
            ("g".to_string(), "b".to_string())
        ]
    );

    // Removing the callback stops persistence.
    m.set_persist_callback(None);
    m.set_selector_choice("g", "a");
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[test]
fn selector_change_callback_fires_only_for_effective_choice_changes() {
    let node = make_node(nid("warm-callback"), "warm-callback");
    let manager = GroupManager::new(
        &[make_group(
            "warm-callback-group",
            GroupPolicy::Selector,
            vec![node.id],
        )],
        &[node],
    );
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback_calls = Arc::clone(&calls);
    manager.set_selector_change_callback(Some(Arc::new(move || {
        callback_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    })));

    manager.set_selector_choice("warm-callback-group", "warm-callback");
    manager.set_selector_choice("warm-callback-group", "warm-callback");
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[test]
fn test_interrupt_callback_selector() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let mut g_on = make_group("on", GroupPolicy::Selector, vec![n1, n2]);
    g_on.interrupt_connections = true;
    let g_off = make_group("off", GroupPolicy::Selector, vec![n1, n2]);
    let m = GroupManager::new(&[g_on, g_off], &nodes);

    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls2 = calls.clone();
    m.set_interrupt_callback(Some(Arc::new(move |g| {
        calls2.lock().unwrap().push(g.to_string());
    })));

    // interrupt_connections = false → never fires.
    m.set_selector_choice("off", "b");
    assert!(calls.lock().unwrap().is_empty());

    // interrupt_connections = true → fires on actual changes only.
    m.set_selector_choice("on", "a");
    m.set_selector_choice("on", "a"); // unchanged → no interrupt
    m.set_selector_choice("on", "b");
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &["on".to_string(), "on".to_string()]
    );
}

#[test]
fn test_interrupt_callback_urltest_switch() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let mut group = make_group("g", GroupPolicy::URLTest, vec![n1, n2]);
    group.interrupt_connections = true;
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(&[group], &nodes, Some(alive.clone()));

    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls2 = calls.clone();
    m.set_interrupt_callback(Some(Arc::new(move |g| {
        calls2.lock().unwrap().push(g.to_string());
    })));

    // 'a' has the lower latency → selected first. First selection is
    // not a change, so no interrupt fires.
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    let sel = m.select_node("g").unwrap();
    assert_eq!(sel.name, "a");
    assert!(calls.lock().unwrap().is_empty());

    // Kill 'a' → next selection switches to 'b' → interrupt fires once.
    alive.report_unavailable_forced(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
    let sel = m.select_node("g").unwrap();
    assert_eq!(sel.name, "b");
    assert_eq!(calls.lock().unwrap().as_slice(), &["g".to_string()]);

    m.select_node("g");
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn test_select_marks_group_active() {
    let n = nid("a");
    let nodes = vec![make_node(n, "a")];
    let alive = Arc::new(AliveDialerSet::new());
    alive.register_urltest_group("g", &[nid("a")], Some(Duration::from_secs(3600)));
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::URLTest, vec![n])],
        &nodes,
        Some(alive.clone()),
    );

    // Lazy start: idle before first use, active after selection.
    assert!(alive.is_urltest_group_idle("g"));
    m.select_node("g");
    assert!(!alive.is_urltest_group_idle("g"));

    // The parallel-dial path also counts as activity.
    alive.register_urltest_group("g2", &[nid("a")], Some(Duration::from_millis(50)));
    let m2 = GroupManager::with_alive_set(
        &[make_group("g2", GroupPolicy::URLTest, vec![n])],
        &nodes,
        Some(alive.clone()),
    );
    assert!(alive.is_urltest_group_idle("g2"));
    m2.select_nodes_in_order_for_domain("g2", ProbeDomain::Tcp, IpVersion::V4);
    assert!(!alive.is_urltest_group_idle("g2"));
}

/// Authoritative selection (sing-box semantics): the dial path returns
/// exactly the policy pick, not a latency-sorted race list.
#[test]
fn test_selector_dial_list_is_the_chosen_node_only() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::Selector, vec![n1, n2])],
        &nodes,
        Some(alive.clone()),
    );
    // "a" has the better latency, but the manual choice "b" must win.
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(50),
    );
    m.set_selector_choice("g", "b");

    let picked = m.select_nodes_in_order_for_domain("g", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(picked.len(), 1);
    assert_eq!(picked[0].name, "b");
}

/// URLTest: with measurement data the dial list is the single selected
/// node; without any data (cold start) all alive candidates race.
#[test]
fn test_urltest_dial_list_single_when_data_exists_race_when_cold() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::URLTest, vec![n1, n2])],
        &nodes,
        Some(alive.clone()),
    );

    // Cold start: no latency data — all candidates race.
    let cold = m.select_nodes_in_order_for_domain("g", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(cold.len(), 2);

    // With measurements, only the best node is dialed.
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(50),
    );
    let warm = m.select_nodes_in_order_for_domain("g", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(warm.len(), 1);
    assert_eq!(warm[0].name, "a");
}

#[test]
fn urltest_retry_candidates_deduplicate_shared_nested_leaves_before_cap() {
    let (a, b) = (nid("retry-a"), nid("retry-b"));
    let nodes = vec![make_node(a, "retry-a"), make_node(b, "retry-b")];
    let groups = vec![
        make_group("a-1", GroupPolicy::Selector, vec![a]),
        make_group("a-2", GroupPolicy::Selector, vec![a]),
        make_group("a-3", GroupPolicy::Selector, vec![a]),
        make_group("b-1", GroupPolicy::Selector, vec![b]),
        make_subgroup("retry", GroupPolicy::URLTest, &["a-1", "a-2", "a-3", "b-1"]),
    ];
    let alive = Arc::new(AliveDialerSet::new());
    alive.record_probe_latency(
        a,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        b,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(20),
    );
    let manager = GroupManager::with_alive_set(&groups, &nodes, Some(alive));

    let retry_ids: Vec<_> = manager
        .urltest_retry_candidates("retry", ProbeDomain::Tcp, IpVersion::V4)
        .into_iter()
        .map(|node| node.id)
        .collect();
    assert_eq!(retry_ids, vec![a, b]);
}

#[test]
fn selection_plan_preserves_authoritative_and_cold_urltest_provenance() {
    let (a, b) = (nid("a"), nid("b"));
    let nodes = vec![make_node(a, "a"), make_node(b, "b")];
    let groups = vec![
        make_group("selector", GroupPolicy::Selector, vec![a, b]),
        make_group("load-balance", GroupPolicy::LoadBalance, vec![a, b]),
        make_group("fallback", GroupPolicy::Fallback, vec![a, b]),
    ];
    let manager = GroupManager::new(&groups, &nodes);
    for group_name in ["selector", "load-balance", "fallback"] {
        let plan =
            manager.selection_plan_for_domain(group_name, ProbeDomain::DataUdp, IpVersion::V4);
        assert_eq!(plan.mode, SelectionPlanMode::Authoritative, "{group_name}");
        assert_eq!(plan.nodes.len(), 1, "{group_name}");
    }

    let alive = Arc::new(AliveDialerSet::new());
    let warm = GroupManager::with_alive_set(
        &[make_group("warm", GroupPolicy::URLTest, vec![a, b])],
        &nodes,
        Some(alive.clone()),
    );
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    let plan = warm.selection_plan_for_domain("warm", ProbeDomain::DataUdp, IpVersion::V4);
    assert_eq!(plan.mode, SelectionPlanMode::Authoritative);
    assert_eq!(plan.nodes[0].name, "a");

    // A selected cold child contributes its one current leaf. Its cold state
    // must never turn an authoritative parent into a transport race.
    let child = make_group("child", GroupPolicy::URLTest, vec![a, b]);
    let parent = make_subgroup("parent", GroupPolicy::Selector, &["child"]);
    let nested = GroupManager::new(&[child, parent], &nodes);
    let plan = nested.selection_plan_for_domain("parent", ProbeDomain::DataUdp, IpVersion::V4);
    assert_eq!(plan.mode, SelectionPlanMode::Authoritative);
    assert_eq!(
        plan.nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["a"]
    );
}

#[test]
fn selection_plan_cold_urltest_keeps_mode_with_one_udp_eligible_leaf() {
    let (a, b) = (nid("udp-dead"), nid("udp-live"));
    let nodes = vec![make_node(a, "udp-dead"), make_node(b, "udp-live")];
    let alive = Arc::new(AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(
        &[make_group("cold", GroupPolicy::URLTest, vec![a, b])],
        &nodes,
        Some(alive.clone()),
    );
    alive.report_unavailable_forced(nid("udp-dead"), ProbeDomain::DataUdp, IpVersion::V4);
    alive.report_unavailable_forced(nid("udp-dead"), ProbeDomain::DnsUdp, IpVersion::V4);

    let plan = manager.selection_plan_for_domain("cold", ProbeDomain::DataUdp, IpVersion::V4);
    assert_eq!(plan.mode, SelectionPlanMode::ColdUrlTest);
    assert_eq!(
        plan.nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["udp-live"]
    );
}

#[test]
fn selection_plan_ignores_udp_measurement_from_dead_candidate() {
    let (a, b, c) = (
        nid("measured-dead"),
        nid("unmeasured-live-b"),
        nid("unmeasured-live-c"),
    );
    let nodes = vec![
        make_node(a, "measured-dead"),
        make_node(b, "unmeasured-live-b"),
        make_node(c, "unmeasured-live-c"),
    ];
    let alive = Arc::new(AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(
        &[make_group(
            "cold-after-filter",
            GroupPolicy::URLTest,
            vec![a, b, c],
        )],
        &nodes,
        Some(alive.clone()),
    );
    alive.record_probe_latency(
        nid("measured-dead"),
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_unavailable_forced(nid("measured-dead"), domain, IpVersion::V4);
    }

    let plan =
        manager.selection_plan_for_domain("cold-after-filter", ProbeDomain::DataUdp, IpVersion::V4);
    assert_eq!(plan.mode, SelectionPlanMode::ColdUrlTest);
    assert_eq!(
        plan.nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["unmeasured-live-b", "unmeasured-live-c"]
    );
    assert_eq!(
        manager
            .select_nodes_in_order_for_domain(
                "cold-after-filter",
                ProbeDomain::DataUdp,
                IpVersion::V4,
            )
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["unmeasured-live-b", "unmeasured-live-c"]
    );
}

#[test]
fn test_migrate_selector_choices_from() {
    let (n1, n2, n3) = (nid("a"), nid("b"), nid("c"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b"), make_node(n3, "c")];

    // Old manager: three selector groups with runtime choices.
    let old = GroupManager::new(
        &[
            make_group("keep", GroupPolicy::Selector, vec![n1, n2]),
            make_group("shrunk", GroupPolicy::Selector, vec![n1, n2]),
            make_group("gone", GroupPolicy::Selector, vec![n1, n3]),
        ],
        &nodes,
    );
    old.set_selector_choice("keep", "b");
    old.set_selector_choice("shrunk", "b");
    old.set_selector_choice("gone", "a");

    // New config: "keep" unchanged, "shrunk" lost node "b", "gone" removed.
    let new = GroupManager::new(
        &[
            make_group("keep", GroupPolicy::Selector, vec![n1, n2]),
            make_group("shrunk", GroupPolicy::Selector, vec![n1]),
        ],
        &nodes,
    );
    new.migrate_selector_choices_from(&old);

    // Surviving choice migrated and drives selection.
    assert_eq!(new.get_selector_choice("keep"), Some("b".into()));
    assert_eq!(new.select_node("keep").unwrap().name, "b");
    // Choice whose node left the group is dropped.
    assert_eq!(new.get_selector_choice("shrunk"), None);
    // Choice for a removed group is dropped.
    assert_eq!(new.get_selector_choice("gone"), None);
}

#[test]
fn test_loadbalance_round_robin_independent_per_group() {
    let (n1, n2, n3) = (nid("a"), nid("b"), nid("c"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b"), make_node(n3, "c")];
    let m = GroupManager::new(
        &[
            make_group("g1", GroupPolicy::LoadBalance, vec![n1, n2, n3]),
            make_group("g2", GroupPolicy::LoadBalance, vec![n1, n2, n3]),
        ],
        &nodes,
    );
    // g1 rotates through the members in declaration order.
    let seq: Vec<String> = (0..4)
        .map(|_| m.select_node("g1").unwrap().name.clone())
        .collect();
    assert_eq!(seq, vec!["a", "b", "c", "a"]);
    // g2's counter is independent — it starts from "a" even though g1
    // already rotated (regression: a shared cross-group counter made
    // g1's rotation skew g2's picks).
    let seq2: Vec<String> = (0..3)
        .map(|_| m.select_node("g2").unwrap().name.clone())
        .collect();
    assert_eq!(seq2, vec!["a", "b", "c"]);
}

#[test]
fn loadbalance_tcp_and_udp_cursors_are_independent() {
    let (a, b) = (nid("a"), nid("b"));
    let nodes = vec![make_node(a, "a"), make_node(b, "b")];
    let manager = GroupManager::new(
        &[make_group("lb", GroupPolicy::LoadBalance, vec![a, b])],
        &nodes,
    );

    assert_eq!(
        manager
            .select_node_for_domain("lb", ProbeDomain::Tcp, IpVersion::V4)
            .unwrap()
            .name,
        "a"
    );
    assert_eq!(
        manager
            .select_node_for_domain("lb", ProbeDomain::DataUdp, IpVersion::V4)
            .unwrap()
            .name,
        "a"
    );
    assert_eq!(
        manager
            .select_node_for_domain("lb", ProbeDomain::Tcp, IpVersion::V4)
            .unwrap()
            .name,
        "b"
    );
    assert_eq!(
        manager
            .select_node_for_domain("lb", ProbeDomain::DataUdp, IpVersion::V4)
            .unwrap()
            .name,
        "b"
    );
}

#[test]
fn test_loadbalance_skips_dead_nodes() {
    let (n1, n2, n3) = (nid("a"), nid("b"), nid("c"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b"), make_node(n3, "c")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("lb", GroupPolicy::LoadBalance, vec![n1, n2, n3])],
        &nodes,
        Some(alive.clone()),
    );
    alive.report_unavailable_forced(nid("b"), ProbeDomain::Tcp, IpVersion::V4);
    let seq: Vec<String> = (0..4)
        .map(|_| m.select_node("lb").unwrap().name.clone())
        .collect();
    // "b" is dead → rotation runs over [a, c] only.
    assert_eq!(seq, vec!["a", "c", "a", "c"]);
}

#[test]
fn test_loadbalance_order_for_parallel_dial() {
    let (n1, n2, n3) = (nid("a"), nid("b"), nid("c"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b"), make_node(n3, "c")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("lb", GroupPolicy::LoadBalance, vec![n1, n2, n3])],
        &nodes,
        Some(alive.clone()),
    );
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("c"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(50),
    );

    let names = |v: Vec<&Node>| v.iter().map(|n| n.name.clone()).collect::<Vec<_>>();
    // Authoritative selection: only the rotated pick is returned —
    // racing the tail would defeat round-robin balancing.
    let first = names(m.select_nodes_in_order_for_domain("lb", ProbeDomain::Tcp, IpVersion::V4));
    assert_eq!(first, vec!["a"]);
    let second = names(m.select_nodes_in_order_for_domain("lb", ProbeDomain::Tcp, IpVersion::V4));
    assert_eq!(second, vec!["b"]);
    let third = names(m.select_nodes_in_order_for_domain("lb", ProbeDomain::Tcp, IpVersion::V4));
    assert_eq!(third, vec!["c"]);
}

#[test]
fn test_loadbalance_no_interrupt_on_rotation() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let mut group = make_group("lb", GroupPolicy::LoadBalance, vec![n1, n2]);
    group.interrupt_connections = true;
    let m = GroupManager::new(&[group], &nodes);

    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls2 = calls.clone();
    m.set_interrupt_callback(Some(Arc::new(move |g| {
        calls2.lock().unwrap().push(g.to_string());
    })));

    // The pick changes on every rotation, but per-connection rotation
    // is the point of load balancing — it must never interrupt.
    for _ in 0..4 {
        m.select_node("lb");
    }
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn test_fallback_first_alive_switch_and_no_flap_back() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("fb", GroupPolicy::Fallback, vec![n1, n2])],
        &nodes,
        Some(alive.clone()),
    );
    // "b" is faster, but Fallback follows declaration order.
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    assert_eq!(m.select_node("fb").unwrap().name, "a");
    assert_eq!(m.get_fallback_selection("fb"), Some("a".into()));

    alive.report_unavailable_forced(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(m.select_node("fb").unwrap().name, "b");
    assert_eq!(m.get_fallback_selection("fb"), Some("b".into()));

    // Preferred node recovers → NO immediate failback (hysteresis).
    alive.report_available_traffic(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(m.select_node("fb").unwrap().name, "b");

    // Current pin dies again → re-evaluate declaration order → "a".
    alive.report_unavailable_forced(nid("b"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(m.select_node("fb").unwrap().name, "a");
}

#[test]
fn fallback_tcp_and_udp_pins_are_independent() {
    let (a, b) = (nid("a"), nid("b"));
    let nodes = vec![make_node(a, "a"), make_node(b, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(
        &[make_group("fb", GroupPolicy::Fallback, vec![a, b])],
        &nodes,
        Some(alive.clone()),
    );

    assert_eq!(manager.select_node("fb").unwrap().name, "a");
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_unavailable_forced(nid("a"), domain, IpVersion::V4);
    }
    assert_eq!(
        manager
            .select_node_for_domain("fb", ProbeDomain::DataUdp, IpVersion::V4)
            .unwrap()
            .name,
        "b"
    );
    assert_eq!(manager.select_node("fb").unwrap().name, "a");
    assert_eq!(manager.get_fallback_selection("fb"), Some("a".into()));
}

#[test]
fn test_fallback_interrupt_on_switch() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let mut group = make_group("fb", GroupPolicy::Fallback, vec![n1, n2]);
    group.interrupt_connections = true;
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(&[group], &nodes, Some(alive.clone()));

    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls2 = calls.clone();
    m.set_interrupt_callback(Some(Arc::new(move |g| {
        calls2.lock().unwrap().push(g.to_string());
    })));

    // First-ever pin is not a change → no interrupt.
    assert_eq!(m.select_node("fb").unwrap().name, "a");
    assert!(calls.lock().unwrap().is_empty());

    alive.report_unavailable_forced(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(m.select_node("fb").unwrap().name, "b");
    assert_eq!(calls.lock().unwrap().as_slice(), &["fb".to_string()]);

    m.select_node("fb");
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn test_urltest_tcp_udp_separate_selections() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::URLTest, vec![n1, n2])],
        &nodes,
        Some(alive.clone()),
    );
    // "a" wins on TCP, "b" wins on UDP (DataUdp).
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(10),
    );

    let tcp = m.select_node_for_domain("g", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(tcp.unwrap().name, "a");
    let udp = m.select_node_for_domain("g", ProbeDomain::DataUdp, IpVersion::V4);
    assert_eq!(udp.unwrap().name, "b");

    // The two selections are tracked independently.
    assert_eq!(m.get_urltest_selection("g"), Some("a".into())); // TCP view
    assert_eq!(
        m.get_urltest_selection_for_network("g", SelectionNetwork::Tcp),
        Some("a".into())
    );
    assert_eq!(
        m.get_urltest_selection_for_network("g", SelectionNetwork::Udp),
        Some("b".into())
    );
    assert_eq!(
        m.selection_chain_for_network("g", SelectionNetwork::Tcp),
        vec!["g", "a"]
    );
    assert_eq!(
        m.selection_chain_for_network("g", SelectionNetwork::Udp),
        vec!["g", "b"]
    );
}

#[test]
fn test_urltest_udp_falls_back_to_tcp_selection() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::URLTest, vec![n1, n2])],
        &nodes,
        Some(alive.clone()),
    );
    // Only TCP measurements exist.
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );

    assert_eq!(m.select_node("g").unwrap().name, "a"); // establishes TCP selection
    // No UDP data → UDP selection mirrors the TCP one (sing-box Now()).
    let udp = m.select_node_for_domain("g", ProbeDomain::DataUdp, IpVersion::V4);
    assert_eq!(udp.unwrap().name, "a");
    assert_eq!(
        m.get_urltest_selection_for_network("g", SelectionNetwork::Udp),
        Some("a".into())
    );
}

#[test]
fn test_urltest_udp_uses_dns_udp_latency_when_no_data_udp() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::URLTest, vec![n1, n2])],
        &nodes,
        Some(alive.clone()),
    );
    // TCP says "a"; only DNS-UDP measurements exist and they say "b".
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::DnsUdp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::DnsUdp,
        IpVersion::V4,
        Duration::from_millis(10),
    );

    assert_eq!(m.select_node("g").unwrap().name, "a");
    // DnsUdp latency counts as UDP-specific data → no TCP mirroring.
    let udp = m.select_node_for_domain("g", ProbeDomain::DataUdp, IpVersion::V4);
    assert_eq!(udp.unwrap().name, "b");
}

/// A node whose DataUDP AND DnsUDP domains are both explicitly dead is
/// excluded from UDP selection even though its TCP is alive (the
/// AnyTLS-without-UoT scenario). TCP selection is unaffected.
#[test]
fn test_udp_both_dead_excluded_despite_tcp_alive() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::Selector, vec![n1, n2])],
        &nodes,
        Some(alive.clone()),
    );

    // "a" UDP-dead on both domains, TCP still alive → "b" wins UDP.
    alive.report_unavailable_forced(nid("a"), ProbeDomain::DataUdp, IpVersion::V4);
    alive.report_unavailable_forced(nid("a"), ProbeDomain::DnsUdp, IpVersion::V4);
    let udp = m.select_node_for_domain("g", ProbeDomain::DataUdp, IpVersion::V4);
    assert_eq!(udp.unwrap().name, "b");

    // With "b" UDP-dead too, NOTHING is selectable for UDP — no TCP
    // fallback for explicitly UDP-dead nodes.
    alive.report_unavailable_forced(nid("b"), ProbeDomain::DataUdp, IpVersion::V4);
    alive.report_unavailable_forced(nid("b"), ProbeDomain::DnsUdp, IpVersion::V4);
    assert!(
        m.select_node_for_domain("g", ProbeDomain::DataUdp, IpVersion::V4)
            .is_none()
    );
    assert!(
        m.select_nodes_in_order_for_domain("g", ProbeDomain::DataUdp, IpVersion::V4)
            .is_empty()
    );

    // TCP selection is unaffected by the UDP deaths.
    assert_eq!(m.select_node("g").unwrap().name, "a");
}

/// Either UDP domain alive is enough: DataUDP-dead but DnsUDP-alive
/// stays selectable for UDP.
#[test]
fn test_udp_single_domain_alive_selectable() {
    let n1 = nid("a");
    let nodes = vec![make_node(n1, "a")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::Selector, vec![n1])],
        &nodes,
        Some(alive.clone()),
    );

    alive.report_unavailable_forced(nid("a"), ProbeDomain::DataUdp, IpVersion::V4);
    assert!(alive.has_udp_state(nid("a")));
    let udp = m.select_node_for_domain("g", ProbeDomain::DataUdp, IpVersion::V4);
    assert_eq!(udp.unwrap().name, "a");
}

/// Nodes never probed for UDP inherit TCP liveness (the legacy
/// fallback): alive TCP → selectable; dead TCP → not.
#[test]
fn test_udp_unprobed_node_inherits_tcp_liveness() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::Selector, vec![n1, n2])],
        &nodes,
        Some(alive.clone()),
    );

    // No UDP state anywhere: both nodes selectable for UDP.
    assert!(!alive.has_udp_state(nid("a")));
    assert_eq!(
        m.select_node_for_domain("g", ProbeDomain::DataUdp, IpVersion::V4)
            .unwrap()
            .name,
        "a"
    );

    // A TCP-dead unprobed node is excluded: its UDP health is unknown
    // and there is no healthy TCP to inherit.
    alive.report_unavailable_forced(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
    assert!(!alive.has_udp_state(nid("a")));
    assert_eq!(
        m.select_node_for_domain("g", ProbeDomain::DataUdp, IpVersion::V4)
            .unwrap()
            .name,
        "b"
    );

    // With every unprobed node TCP-dead, UDP selection is empty.
    alive.report_unavailable_forced(nid("b"), ProbeDomain::Tcp, IpVersion::V4);
    assert!(
        m.select_node_for_domain("g", ProbeDomain::DataUdp, IpVersion::V4)
            .is_none()
    );
}

/// The original bug: a URLTest group picked the TCP-fastest node for
/// UDP even when its UDP path was dead. Explicit UDP deaths must make
/// the UDP selection skip it (TCP selection still honours latency).
#[test]
fn test_urltest_udp_selection_skips_udp_dead_node() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::URLTest, vec![n1, n2])],
        &nodes,
        Some(alive.clone()),
    );
    // "a" is TCP-fastest but its UDP path is dead; "b" is slower but
    // fully healthy.
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    alive.report_unavailable_forced(nid("a"), ProbeDomain::DataUdp, IpVersion::V4);
    alive.report_unavailable_forced(nid("a"), ProbeDomain::DnsUdp, IpVersion::V4);
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(50),
    );

    assert_eq!(m.select_node("g").unwrap().name, "a"); // TCP still picks "a"
    let udp = m.select_node_for_domain("g", ProbeDomain::DataUdp, IpVersion::V4);
    assert_eq!(udp.unwrap().name, "b"); // UDP skips UDP-dead "a"
}

/// A → B → A cycle must not panic or hang: construction cuts the
/// cycle-closing edge (with a warning) and both groups stay usable.
#[test]
fn test_cycle_detection_breaks_cycle_edge() {
    let n = nid("a");
    let nodes = vec![make_node(n, "a")];
    let mut ga = make_group("A", GroupPolicy::Selector, vec![n]);
    ga.groups = vec!["B".into()];
    let mut gb = make_group("B", GroupPolicy::Selector, vec![n]);
    gb.groups = vec!["A".into()];
    let m = GroupManager::new(&[ga, gb], &nodes);

    // Deterministic DFS (sorted start at "A"): A → B unvisited → B's
    // edge back to A is the back edge and gets cut.
    assert_eq!(m.node_names_in_group("A"), vec!["a", "B"]);
    assert_eq!(m.node_names_in_group("B"), vec!["a"]);

    // Both groups still resolve to the leaf without hanging.
    assert_eq!(m.select_node("A").unwrap().name, "a");
    assert_eq!(m.select_node("B").unwrap().name, "a");
    assert_eq!(m.leaf_node_names_in_group("A"), vec!["a"]);
    assert_eq!(m.selection_chain("A"), vec!["A", "a"]);

    // A self-loop is a cycle too.
    let mut gs = make_group("S", GroupPolicy::Selector, vec![n]);
    gs.groups = vec!["S".into()];
    let m2 = GroupManager::new(&[gs], &nodes);
    assert_eq!(m2.node_names_in_group("S"), vec!["a"]);
    assert_eq!(m2.select_node("S").unwrap().name, "a");
}

/// Three-level nesting: top → mid (sub-group) → leaf-g (sub-group) →
/// leaf. Each Selector choice names a member tag; the dial path
/// resolves the chain to the single leaf. Choices survive a manager
/// rebuild via `migrate_selector_choices_from` (the reload path).
#[test]
fn test_nested_selector_three_levels() {
    let (l1, l2, l3) = (nid("l1"), nid("l2"), nid("l3"));
    let nodes = vec![
        make_node(l1, "l1"),
        make_node(l2, "l2"),
        make_node(l3, "l3"),
    ];
    let leaf_g = make_group("leaf-g", GroupPolicy::Selector, vec![l1, l2]);
    let mut mid = make_subgroup("mid", GroupPolicy::Selector, &["leaf-g"]);
    mid.nodes = vec![l3];
    let mut top = make_subgroup("top", GroupPolicy::Selector, &["mid"]);
    top.nodes = vec![l1];
    let groups = vec![leaf_g, mid, top];

    let m = GroupManager::new(&groups, &nodes);
    // Member tags mix node names and sub-group tags.
    assert_eq!(m.node_names_in_group("top"), vec!["l1", "mid"]);
    assert_eq!(m.node_names_in_group("mid"), vec!["l3", "leaf-g"]);
    assert_eq!(m.leaf_node_names_in_group("top"), vec!["l1", "l3", "l2"]);

    m.set_selector_choice("leaf-g", "l2");
    m.set_selector_choice("mid", "leaf-g");
    m.set_selector_choice("top", "mid");

    // The authoritative pick is the chain's leaf.
    let picked = m.select_nodes_in_order_for_domain("top", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(picked.len(), 1);
    assert_eq!(picked[0].name, "l2");
    assert_eq!(m.select_node("top").unwrap().name, "l2");
    assert_eq!(m.selection_chain("top"), vec!["top", "mid", "leaf-g", "l2"]);

    // A sub-group choice pointing at a non-member is ignored
    // (falls back to the first member) instead of breaking.
    m.set_selector_choice("mid", "nope");
    assert_eq!(m.select_node("mid").unwrap().name, "l3");
    m.set_selector_choice("mid", "leaf-g");

    // Rebuild (config reload): every choice — node-targeted and
    // sub-group-targeted alike — migrates while the members exist.
    let m2 = GroupManager::new(&groups, &nodes);
    m2.migrate_selector_choices_from(&m);
    assert_eq!(m2.get_selector_choice("top"), Some("mid".into()));
    assert_eq!(m2.get_selector_choice("mid"), Some("leaf-g".into()));
    assert_eq!(m2.select_node("top").unwrap().name, "l2");

    // A rebuilt manager without the sub-group drops the stale choice.
    let mut top_only = make_subgroup("top", GroupPolicy::Selector, &["mid"]);
    top_only.nodes = vec![l1];
    let m3 = GroupManager::new(&[top_only], &nodes);
    m3.migrate_selector_choices_from(&m);
    assert_eq!(m3.get_selector_choice("top"), None);
}

/// URLTest parent over a URLTest sub-group: the sub-group contributes
/// its own selected leaf, ranks by that leaf's latency, and the
/// parent's `now`/chain report the sub-group's tag.
#[test]
fn test_urltest_parent_with_urltest_subgroup() {
    let (l1, l2, d) = (nid("l1"), nid("l2"), nid("d"));
    let nodes = vec![make_node(l1, "l1"), make_node(l2, "l2"), make_node(d, "d")];
    let sub = make_group("sub", GroupPolicy::URLTest, vec![l1, l2]);
    let mut parent = make_subgroup("parent", GroupPolicy::URLTest, &["sub"]);
    parent.nodes = vec![d];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(&[sub, parent], &nodes, Some(alive.clone()));

    alive.record_probe_latency(
        nid("l1"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("l2"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(20),
    );
    alive.record_probe_latency(
        nid("d"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(5),
    );

    // The direct member is fastest → picked under its own node name.
    assert_eq!(m.select_node("parent").unwrap().name, "d");
    assert_eq!(m.get_urltest_selection("parent"), Some("d".into()));
    // Flattening formed the sub-group's own selection as a side effect.
    assert_eq!(m.get_urltest_selection("sub"), Some("l1".into()));
    assert_eq!(m.selection_chain("parent"), vec!["parent", "d"]);

    // Kill the direct member → the sub-group's representative leaf wins.
    alive.report_unavailable_forced(nid("d"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(m.select_node("parent").unwrap().name, "l1");
    // `now` displays the sub-group tag, the chain resolves to the leaf.
    assert_eq!(m.get_urltest_selection("parent"), Some("sub".into()));
    assert_eq!(m.selection_chain("parent"), vec!["parent", "sub", "l1"]);

    // Cold start with no data anywhere: every flattened leaf races.
    let m_cold = GroupManager::with_alive_set(
        &[
            make_group("sub", GroupPolicy::URLTest, vec![l1, l2]),
            make_subgroup("parent", GroupPolicy::URLTest, &["sub"]),
        ],
        &nodes,
        None,
    );
    let race = m_cold.select_nodes_in_order_for_domain("parent", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(race.len(), 1, "sub-group contributes exactly its own pick");
    assert_eq!(race[0].name, "l1");
}

/// The user's sing-box-style layout: selector/urltest groups with
/// emoji tags nesting country urltest groups. Verifies candidate
/// flattening, direct-node reachability through a nested selector, and
/// selection chains through two levels of sub-groups.
#[test]
fn test_user_style_nested_layout() {
    // Leaf nodes (direct-out uses the HTTP protocol convention for the
    // direct handler; the rest stand in for subscription nodes).
    let node_names = [
        "direct-out",
        "singal-1",
        "singal-2",
        "tw-1",
        "tw-2",
        "hk-1",
        "hk-2",
        "jp-1",
        "sg-1",
        "us-1",
        "misc-1",
    ];
    let nodes: Vec<Node> = node_names
        .iter()
        .map(|n| make_node(uuid::Uuid::new_v4(), n))
        .collect();
    let id = |name: &str| nodes.iter().find(|n| n.name == name).unwrap().id;
    let ids = |names: &[&str]| names.iter().map(|n| id(n)).collect::<Vec<_>>();

    let groups = vec![
        make_group("🇨🇳 taiwan", GroupPolicy::URLTest, ids(&["tw-1", "tw-2"])),
        make_group("🇭🇰 hongkong", GroupPolicy::URLTest, ids(&["hk-1", "hk-2"])),
        make_group("🇯🇵 japan", GroupPolicy::URLTest, ids(&["jp-1"])),
        make_group("🇸🇬 sgp", GroupPolicy::URLTest, ids(&["sg-1"])),
        make_group("🇺🇸 america", GroupPolicy::URLTest, ids(&["us-1"])),
        make_group("🍡 other_contry", GroupPolicy::URLTest, ids(&["misc-1"])),
        make_group(
            "🥤 singal",
            GroupPolicy::Selector,
            ids(&["singal-1", "singal-2"]),
        ),
        make_subgroup(
            "🍃 wind",
            GroupPolicy::URLTest,
            &["🇭🇰 hongkong", "🇨🇳 taiwan", "🇯🇵 japan"],
        ),
        make_subgroup(
            "🍪 country",
            GroupPolicy::Selector,
            &[
                "🇨🇳 taiwan",
                "🇭🇰 hongkong",
                "🇯🇵 japan",
                "🇸🇬 sgp",
                "🇺🇸 america",
                "🍡 other_contry",
            ],
        ),
        {
            let mut g = make_subgroup(
                "🥗 proxy",
                GroupPolicy::Selector,
                &["🍃 wind", "🍪 country", "🥤 singal"],
            );
            g.nodes = ids(&["direct-out"]);
            g
        },
        {
            let mut g = make_subgroup("🍥 final", GroupPolicy::Selector, &["🥗 proxy"]);
            g.nodes = ids(&["direct-out"]);
            g
        },
        {
            let mut g = make_subgroup(
                "👾 game",
                GroupPolicy::Selector,
                &["🥗 proxy", "🍪 country", "🥤 singal"],
            );
            g.nodes = ids(&["direct-out"]);
            g
        },
    ];
    let m = GroupManager::new(&groups, &nodes);

    // 🥗 proxy flattens to exactly one candidate per member:
    // [direct-out, 🍃 wind's leaf, 🍪 country's leaf, 🥤 singal's leaf].
    let members = m.delay_test_members("🥗 proxy");
    let tags: Vec<&str> = members.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(
        tags,
        vec!["direct-out", "🍃 wind", "🍪 country", "🥤 singal"]
    );
    // Each member resolves to a concrete leaf node.
    assert!(
        members
            .iter()
            .all(|(_, leaf)| node_names.contains(&leaf.name.as_str()))
    );

    // 🍥 final selecting direct-out dials the direct node itself.
    m.set_selector_choice("🍥 final", "direct-out");
    let picked = m.select_nodes_in_order_for_domain("🍥 final", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(picked.len(), 1);
    assert_eq!(picked[0].name, "direct-out");
    assert_eq!(
        m.selection_chain("🍥 final"),
        vec!["🍥 final", "direct-out"]
    );

    // 👾 game → 🍪 country → first country sub-group → its first leaf.
    m.set_selector_choice("👾 game", "🍪 country");
    let picked = m.select_nodes_in_order_for_domain("👾 game", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(picked.len(), 1);
    assert_eq!(picked[0].name, "tw-1");
    assert_eq!(
        m.selection_chain("👾 game"),
        vec!["👾 game", "🍪 country", "🇨🇳 taiwan", "tw-1"]
    );

    // 🍃 wind (urltest over three country groups) flattens to each
    // country's representative leaf; cold start (no latency data)
    // races all of them in member order.
    let picked = m.select_nodes_in_order_for_domain("🍃 wind", ProbeDomain::Tcp, IpVersion::V4);
    let names: Vec<&str> = picked.iter().map(|n| n.name.as_str()).collect();
    assert_eq!(names, vec!["hk-1", "tw-1", "jp-1"]);
    // `now` caches the member (sub-group) tag once wind is reached as a
    // Selector's chosen sub-group with applied effects.
    m.set_selector_choice("🥗 proxy", "🍃 wind");
    let _ = m.select_nodes_in_order_for_domain("🥗 proxy", ProbeDomain::Tcp, IpVersion::V4);
    let wind_now = m.get_urltest_selection("🍃 wind").unwrap();
    assert!(["🇭🇰 hongkong", "🇨🇳 taiwan", "🇯🇵 japan"].contains(&wind_now.as_str()));

    // LoadBalance and Fallback flatten the same way.
    let lb = make_subgroup("lb", GroupPolicy::LoadBalance, &["🥤 singal", "🇯🇵 japan"]);
    let fb = make_subgroup("fb", GroupPolicy::Fallback, &["🥤 singal"]);
    let m2 = GroupManager::new(
        &[
            make_group(
                "🥤 singal",
                GroupPolicy::Selector,
                ids(&["singal-1", "singal-2"]),
            ),
            make_group("🇯🇵 japan", GroupPolicy::URLTest, ids(&["jp-1"])),
            lb,
            fb,
        ],
        &nodes,
    );
    // Round-robin rotates over the flattened sub-group picks.
    let seq: Vec<String> = (0..3)
        .map(|_| m2.select_node("lb").unwrap().name.clone())
        .collect();
    assert_eq!(seq, vec!["singal-1", "jp-1", "singal-1"]);
    // Fallback pins the sub-group's leaf and reports the tag.
    assert_eq!(m2.select_node("fb").unwrap().name, "singal-1");
    assert_eq!(m2.get_fallback_selection("fb"), Some("🥤 singal".into()));
    assert_eq!(
        m2.selection_chain("fb"),
        vec!["fb", "🥤 singal", "singal-1"]
    );
}

/// URLTest hysteresis baseline is the incumbent's *current* measured
/// latency (sing-box `Select()` parity), not the latency recorded when it
/// was selected: a degraded incumbent must be displaced once a challenger
/// beats its current latency by ≥ tolerance.
#[test]
fn test_urltest_switches_when_incumbent_degrades() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::URLTest, vec![n1, n2])],
        &nodes,
        Some(alive.clone()),
    );
    // 'a' wins the first selection at 10ms (moving average starts at 10).
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    assert_eq!(m.select_node("g").unwrap().name, "a");

    // 'a' degrades: a 400ms sample moves its average to (10+400)/2 = 205ms.
    // 'b' (100ms) now beats a's *current* latency by > tolerance (50ms) and
    // must take over — the stale 10ms baseline would have kept 'a' forever.
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(400),
    );
    assert_eq!(m.select_node("g").unwrap().name, "b");
}

/// Within tolerance of the incumbent's current latency, the selection is
/// stable (no flapping).
#[test]
fn test_urltest_keeps_incumbent_within_tolerance_of_current_latency() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::URLTest, vec![n1, n2])],
        &nodes,
        Some(alive.clone()),
    );
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(80),
    );
    assert_eq!(m.select_node("g").unwrap().name, "a");

    // 'a' drifts to (10+190)/2 = 100ms; 'b' at 80ms is faster but within
    // the 50ms tolerance of a's current latency → keep 'a'.
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(190),
    );
    assert_eq!(m.select_node("g").unwrap().name, "a");
}

/// Lab scenario S3: a flaky node (fast when it works, but failing real dials)
/// must not be re-adopted while the incumbent is healthy. Probe failures own
/// liveness without creating ranking strikes; a dial failure demotes the node
/// while retaining its real moving average, and tolerance then guards the
/// incumbent against the flaky node's lower average.
#[test]
fn urltest_flaky_node_stays_demoted_after_dial_failure() {
    let (na, nb, nc) = (nid("a"), nid("b"), nid("c"));
    let nodes = vec![make_node(na, "a"), make_node(nb, "b"), make_node(nc, "c")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::URLTest, vec![na, nb, nc])],
        &nodes,
        Some(alive.clone()),
    );
    let probe_ok = |n: uuid::Uuid, ms: u64| {
        alive.record_probe_latency(
            n,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_millis(ms),
        );
    };
    probe_ok(nid("a"), 7);
    probe_ok(nid("b"), 21);
    probe_ok(nid("c"), 42);
    assert_eq!(m.select_node("g").unwrap().name, "a");

    // One probe failure keeps 'a' alive and does not bypass tolerance.
    alive.mark_dead(nid("a"));
    assert!(alive.is_alive_for(nid("a"), ProbeDomain::Tcp, IpVersion::V4));
    assert_eq!(m.select_node("g").unwrap().name, "a");

    // One transient dial failure leaves no strike — 'a' keeps the seat.
    alive.record_dial_failure(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(m.select_node("g").unwrap().name, "a");
    // The second consecutive failure supplies the ranking strike and moves
    // to 'b'.
    alive.record_dial_failure(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(m.select_node("g").unwrap().name, "b");

    // 'a' recovers after two good probes; 7ms beats b's 21ms but stays
    // within the 50ms tolerance → hysteresis keeps 'b'.
    probe_ok(nid("a"), 7);
    probe_ok(nid("a"), 7);
    assert_eq!(m.select_node("g").unwrap().name, "b");

    // Now the flaky loop: a user dial through 'a' fails → strike, an
    // emergency re-probe succeeds (the node works 60% of the time).
    for round in 0..6 {
        alive.report_unavailable_traffic(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
        alive.record_dial_failure(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
        probe_ok(nid("a"), 7);
        assert_eq!(
            m.select_node("g").unwrap().name,
            "b",
            "round {round}: flaky node 'a' must not displace the incumbent"
        );
    }

    // When the incumbent itself fails dials, the strike (second consecutive
    // failure) skips hysteresis and the group moves; one lucky re-probe
    // does not let it reclaim the rank against the new incumbent.
    let alive2 = Arc::new(AliveDialerSet::new());
    let m2 = GroupManager::with_alive_set(
        &[make_group("g2", GroupPolicy::URLTest, vec![na, nb])],
        &nodes,
        Some(alive2.clone()),
    );
    probe_ok2(&alive2, nid("a"), 7);
    probe_ok2(&alive2, nid("b"), 21);
    assert_eq!(m2.select_node("g2").unwrap().name, "a");
    alive2.record_dial_failure(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(
        m2.select_node("g2").unwrap().name,
        "a",
        "one transient failure keeps the incumbent"
    );
    alive2.record_dial_failure(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(m2.select_node("g2").unwrap().name, "b");
    probe_ok2(&alive2, nid("a"), 7);
    assert_eq!(m2.select_node("g2").unwrap().name, "b");
}

fn probe_ok2(alive: &AliveDialerSet, n: uuid::Uuid, ms: u64) {
    alive.record_probe_latency(
        n,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(ms),
    );
}

/// Strike stickiness at ranking level: one lucky probe success after a dial
/// failure does NOT clear the demotion — even when the challenger's latency
/// would win by far. Two consecutive successes clear it, and then the
/// challenger wins only because the gap exceeds tolerance.
#[test]
fn urltest_strike_demotion_needs_two_consecutive_successes() {
    let (na, nb) = (nid("a"), nid("b"));
    let nodes = vec![make_node(na, "a"), make_node(nb, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::URLTest, vec![na, nb])],
        &nodes,
        Some(alive.clone()),
    );
    probe_ok2(&alive, nid("a"), 7);
    probe_ok2(&alive, nid("b"), 21);
    assert_eq!(m.select_node("g").unwrap().name, "a");

    // Two consecutive dial failures strike the incumbent; a lone one does
    // not.
    alive.record_dial_failure(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(m.select_node("g").unwrap().name, "a");
    alive.record_dial_failure(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(m.select_node("g").unwrap().name, "b");

    // One lucky success: the strike is still pending — 'a' stays demoted
    // even though 7ms vs 200ms is far beyond tolerance.
    probe_ok2(&alive, nid("a"), 7);
    probe_ok2(&alive, nid("b"), 200);
    assert_eq!(m.select_node("g").unwrap().name, "b");

    // The second consecutive success clears the strike; with the gap beyond
    // tolerance 'a' wins immediately.
    probe_ok2(&alive, nid("a"), 7);
    assert_eq!(m.select_node("g").unwrap().name, "a");
}

/// A URLTest group with a custom check_url ranks and filters by the
/// per-(node, url) probe state, not the global one (sing-box urltest
/// `url` option): a node globally healthy but dead for the group's URL
/// is excluded; ranking uses per-URL latency.
#[test]
fn test_urltest_group_custom_check_url_selection() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let url = "http://chatgpt.example/trace";
    let mut group = make_group("g", GroupPolicy::URLTest, vec![n1, n2]);
    group.check_url = Some(url.to_string());
    let alive = Arc::new(AliveDialerSet::new());
    alive.sync_group_check_urls(&[("g".into(), url.into())]);
    let m = GroupManager::with_alive_set(&[group], &nodes, Some(alive.clone()));

    // Global: a is faster. Per-URL: b is faster → b wins.
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(500),
    );
    alive.record_url_probe_success("a", url, Duration::from_millis(200));
    alive.record_url_probe_success("b", url, Duration::from_millis(100));
    assert_eq!(m.select_node("g").unwrap().name, "b");

    // b dies for the group's URL (but stays globally alive) → a wins.
    for _ in 0..3 {
        alive.record_url_probe_failure("b", url);
    }
    assert!(alive.is_alive_for(nid("b"), ProbeDomain::Tcp, IpVersion::V4));
    assert_eq!(m.select_node("g").unwrap().name, "a");
}

/// Groups without check_url keep the global behaviour (regression).
#[test]
fn test_urltest_group_without_check_url_uses_global_state() {
    let (n1, n2) = (nid("a"), nid("b"));
    let nodes = vec![make_node(n1, "a"), make_node(n2, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::URLTest, vec![n1, n2])],
        &nodes,
        Some(alive.clone()),
    );
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    assert_eq!(m.select_node("g").unwrap().name, "a");
    // Stray per-URL failures for 'a' must not leak into this group.
    for _ in 0..3 {
        alive.record_url_probe_failure("a", "http://unrelated.example");
    }
    assert_eq!(m.select_node("g").unwrap().name, "a");
}

/// Nested group with a custom check_url: the parent's per-URL state is
/// keyed by the SUB-GROUP TAG (sing-box RealTag semantics) — the parent
/// ranks sub-groups as units, independent of which leaf each sub-group
/// currently picks.
#[test]
fn test_nested_group_check_url_ranks_subgroups_by_tag() {
    let (n1, n2) = (nid("hk-1"), nid("us-1"));
    let nodes = vec![make_node(n1, "hk-1"), make_node(n2, "us-1")];
    let url = "http://chatgpt.example/trace";
    let hk = make_subgroup("hk", GroupPolicy::URLTest, &[]);
    let us = make_subgroup("us", GroupPolicy::URLTest, &[]);
    let mut hk = hk;
    hk.nodes = vec![n1];
    let mut us = us;
    us.nodes = vec![n2];
    let mut parent = make_group("ai", GroupPolicy::URLTest, vec![]);
    parent.groups = vec!["hk".into(), "us".into()];
    parent.check_url = Some(url.to_string());

    let alive = Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(&[parent, hk, us], &nodes, Some(alive.clone()));

    // Per-URL probe results recorded under the sub-group tags: hk faster.
    alive.record_url_probe_success("hk", url, Duration::from_millis(120));
    alive.record_url_probe_success("us", url, Duration::from_millis(300));
    let sel = m.select_node("ai").unwrap();
    assert_eq!(sel.name, "hk-1");
    assert_eq!(m.selection_chain("ai"), vec!["ai", "hk", "hk-1"]);

    // hk dies FOR THE PARENT'S URL (its own/global state untouched) →
    // the parent switches to us even though hk-1 is globally healthy.
    for _ in 0..3 {
        alive.record_url_probe_failure("hk", url);
    }
    assert!(alive.is_alive_for(nid("hk-1"), ProbeDomain::Tcp, IpVersion::V4));
    let sel = m.select_node("ai").unwrap();
    assert_eq!(sel.name, "us-1");
}

#[test]
fn peek_selection_plan_keeps_cold_urltest_idle_and_cache_empty() {
    let node_id = nid("cold");
    let nodes = vec![make_node(node_id, "cold")];
    let group = make_group("cold", GroupPolicy::URLTest, vec![node_id]);
    let alive = Arc::new(AliveDialerSet::new());
    alive.register_urltest_group("cold", &[nid("cold")], Some(Duration::from_secs(60)));
    let manager = GroupManager::with_alive_set(&[group], &nodes, Some(Arc::clone(&alive)));

    assert!(alive.is_urltest_group_idle("cold"));
    let plan = manager.peek_selection_plan_for_domain("cold", ProbeDomain::DataUdp, IpVersion::V4);

    assert_eq!(plan.mode, SelectionPlanMode::ColdUrlTest);
    assert_eq!(plan.nodes[0].name, "cold");
    assert!(alive.is_urltest_group_idle("cold"));
    assert_eq!(manager.get_urltest_selection("cold"), None);
}

#[test]
fn peek_selection_plan_load_balance_does_not_advance_cursor() {
    let (a, b) = (nid("a"), nid("b"));
    let nodes = vec![make_node(a, "a"), make_node(b, "b")];
    let manager = GroupManager::new(
        &[make_group("lb", GroupPolicy::LoadBalance, vec![a, b])],
        &nodes,
    );

    for _ in 0..2 {
        let plan =
            manager.peek_selection_plan_for_domain("lb", ProbeDomain::DataUdp, IpVersion::V4);
        assert_eq!(plan.nodes[0].name, "a");
    }
    assert_eq!(
        manager
            .selection_plan_for_domain("lb", ProbeDomain::DataUdp, IpVersion::V4)
            .nodes[0]
            .name,
        "a"
    );
    assert_eq!(
        manager
            .selection_plan_for_domain("lb", ProbeDomain::DataUdp, IpVersion::V4)
            .nodes[0]
            .name,
        "b"
    );
}

#[test]
fn peek_selection_plan_does_not_update_urltest_or_fallback_after_death() {
    let (a, b) = (nid("a"), nid("b"));
    let nodes = vec![make_node(a, "a"), make_node(b, "b")];
    let mut urltest = make_group("url", GroupPolicy::URLTest, vec![a, b]);
    let mut fallback = make_group("fallback", GroupPolicy::Fallback, vec![a, b]);
    urltest.interrupt_connections = true;
    fallback.interrupt_connections = true;
    let alive = Arc::new(AliveDialerSet::new());
    let manager =
        GroupManager::with_alive_set(&[urltest, fallback], &nodes, Some(Arc::clone(&alive)));
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    assert_eq!(
        manager
            .selection_plan_for_domain("url", ProbeDomain::DataUdp, IpVersion::V4)
            .nodes[0]
            .name,
        "a"
    );
    assert_eq!(
        manager
            .selection_plan_for_domain("fallback", ProbeDomain::DataUdp, IpVersion::V4)
            .nodes[0]
            .name,
        "a"
    );
    let interrupts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback_interrupts = Arc::clone(&interrupts);
    manager.set_interrupt_callback(Some(Arc::new(move |_| {
        callback_interrupts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    })));
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_unavailable_forced(nid("a"), domain, IpVersion::V4);
    }

    for group in ["url", "fallback"] {
        let plan =
            manager.peek_selection_plan_for_domain(group, ProbeDomain::DataUdp, IpVersion::V4);
        assert_eq!(
            plan.nodes[0].name, "b",
            "{group} must observe the live leaf"
        );
    }
    assert_eq!(
        manager.get_urltest_selection_for_network("url", SelectionNetwork::Udp),
        Some("a".into())
    );
    assert_eq!(
        manager.get_fallback_selection_for_network("fallback", SelectionNetwork::Udp),
        Some("a".into())
    );
    assert_eq!(interrupts.load(std::sync::atomic::Ordering::SeqCst), 0);

    for group in ["url", "fallback"] {
        assert_eq!(
            manager
                .selection_plan_for_domain(group, ProbeDomain::DataUdp, IpVersion::V4)
                .nodes[0]
                .name,
            "b"
        );
    }
    assert_eq!(
        manager.get_urltest_selection_for_network("url", SelectionNetwork::Udp),
        Some("b".into())
    );
    assert_eq!(
        manager.get_fallback_selection_for_network("fallback", SelectionNetwork::Udp),
        Some("b".into())
    );
    assert_eq!(interrupts.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn peek_selection_plan_keeps_nested_child_idle_and_only_reads_tcp_mirror() {
    let (a, b) = (nid("a"), nid("b"));
    let nodes = vec![make_node(a, "a"), make_node(b, "b")];
    let child = make_group("child", GroupPolicy::URLTest, vec![a, b]);
    let parent = make_subgroup("parent", GroupPolicy::Selector, &["child"]);
    let alive = Arc::new(AliveDialerSet::new());
    for group in ["child", "parent"] {
        alive.register_urltest_group(group, &[nid("a"), nid("b")], Some(Duration::from_secs(60)));
    }
    let manager = GroupManager::with_alive_set(&[child, parent], &nodes, Some(Arc::clone(&alive)));
    alive.record_probe_latency(
        nid("a"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nid("b"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );

    // A nested cold pick observes both groups but activates neither one.
    let plan =
        manager.peek_selection_plan_for_domain("parent", ProbeDomain::DataUdp, IpVersion::V4);
    assert_eq!(plan.nodes[0].name, "a");
    assert!(alive.is_urltest_group_idle("parent"));
    assert!(alive.is_urltest_group_idle("child"));
    assert_eq!(
        manager.get_urltest_selection_for_network("child", SelectionNetwork::Udp),
        None
    );

    // Once TCP selected the child for real, a UDP peek may read that mirror
    // but cannot create the independent UDP cache entry.
    assert_eq!(manager.select_node("child").unwrap().name, "a");
    let plan =
        manager.peek_selection_plan_for_domain("parent", ProbeDomain::DataUdp, IpVersion::V4);
    assert_eq!(plan.nodes[0].name, "a");
    assert!(alive.is_urltest_group_idle("parent"));
    assert_eq!(
        manager.get_urltest_selection_for_network("child", SelectionNetwork::Udp),
        None
    );
}

/// The warm coordinator's per-group top-N source: latency-ordered, alive
/// filtered, capped, and never mutating selection state.
#[test]
fn ranked_udp_leaves_orders_caps_and_filters() {
    let (na, nb, nc) = (nid("a"), nid("b"), nid("c"));
    let nodes = vec![make_node(na, "a"), make_node(nb, "b"), make_node(nc, "c")];
    let alive = Arc::new(AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(
        &[make_group("g", GroupPolicy::URLTest, vec![na, nb, nc])],
        &nodes,
        Some(alive.clone()),
    );
    for (node, ms) in [(nb, 10u64), (na, 30), (nc, 20)] {
        alive.record_probe_latency(
            node,
            ProbeDomain::DataUdp,
            IpVersion::V4,
            Duration::from_millis(ms),
        );
    }
    let names = |limit| {
        manager
            .ranked_udp_leaves("g", IpVersion::V4, limit)
            .iter()
            .map(|n| n.name.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(names(3), vec!["b", "c", "a"]);
    assert_eq!(names(2), vec!["b", "c"]);
    assert_eq!(names(1), vec!["b"]);
    assert!(names(0).is_empty());

    // Both UDP domains dead on the leader -> it drops out of the ranking.
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_unavailable_forced(nid("b"), domain, IpVersion::V4);
    }
    assert_eq!(names(2), vec!["c", "a"]);

    // Peek semantics: no urltest cache write, no cursor advance.
    assert!(
        manager
            .get_urltest_selection_for_network("g", SelectionNetwork::Udp)
            .is_none()
    );
}
