use super::*;

const DATA: ProbeDomain = ProbeDomain::DataUdp;
const DNS: ProbeDomain = ProbeDomain::DnsUdp;

fn udp_nodes() -> Vec<Node> {
    let mut nodes = nodes();
    nodes[2] = Node::from_share_link("trojan://pass@127.0.0.1:2443#exit").unwrap();
    nodes
}

fn udp_pick(
    gm: &GroupManager,
    root: &str,
    domain: ProbeDomain,
    family: IpVersion,
) -> Option<UdpRouteAdmission> {
    let context = ScoreSelectionContext::aggregate(SelectionNetwork::Udp, domain, family);
    let (plan, revision) = gm.dial_plan_for_target(root, &context, None);
    let entry = plan.entries.into_iter().next()?;
    let mut target = gm.own_target(Target {
        node: entry.node,
        route: entry.route,
    });
    target.collapse = entry.collapse;
    gm.capture_udp_route(
        &target,
        &entry.selection_chain,
        &entry.final_owners,
        revision,
        domain,
        plan.health_family,
    )
}

#[test]
fn udp_prefix_uses_fifty_distinct_flows_and_only_its_own_reply() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = udp_nodes();
    let gm = manager(
        &alive,
        &[group("A", &nodes[0]), group("B", &nodes[1])],
        &nodes,
    );
    gm.publish_route_health();
    let a = || udp_pick(&gm, "A", DATA, V4).unwrap();
    let initial = a();
    let pending = a();
    let sibling = udp_pick(&gm, "B", DATA, V4).unwrap();
    let other_family = udp_pick(&gm, "A", DATA, V6).unwrap();
    let dns = udp_pick(&gm, "A", DNS, V4).unwrap();
    let bad = crate::proxy::test_prefix_refusal(1);
    let shared = SharedError::fanout(crate::proxy::test_prefix_refusal(1));
    assert!(gm.report_udp_route_failure(&initial, &shared));
    assert!(!gm.report_udp_route_failure(&initial, bad.as_ref()));
    assert!(!gm.report_udp_route_failure(&a(), &shared));
    assert!(gm.report_udp_route_failure(&other_family, &shared));
    assert!(gm.report_udp_route_failure(&dns, &shared));
    assert!(gm.report_route_failure(
        "A",
        &pick(&gm, "A"),
        V4,
        gm.route_health_revision("A").admit(),
        &shared
    ));
    for _ in 1..49 {
        assert!(gm.report_udp_route_failure(&a(), bad.as_ref()));
    }
    gm.report_udp_route_reply(&a());
    assert!(!gm.report_udp_route_failure(&pending, bad.as_ref()));
    for _ in 0..49 {
        assert!(gm.report_udp_route_failure(&a(), bad.as_ref()));
    }
    let last = a();
    for neutral in [
        PacketRejection::Policy,
        PacketRejection::Capacity,
        PacketRejection::Cancelled,
    ] {
        assert!(!gm.report_udp_route_failure(&last, &neutral));
    }
    assert!(!gm.report_udp_route_failure(
        &last,
        &std::io::Error::from(std::io::ErrorKind::UnexpectedEof)
    ));
    assert!(gm.udp_route_current(&last));
    assert!(gm.report_udp_route_failure(&last, bad.as_ref()));
    assert!(!gm.udp_route_current(&last));
    assert!(gm.udp_route_current(&sibling));
    assert!(gm.udp_route_current(&other_family));
    assert!(gm.udp_route_current(&dns));
    assert!(alive.is_alive_for(nodes[2].id, DATA, V4));
    let tcp = pick(&gm, "A");
    gm.report_route_response(
        "A",
        tcp.key(),
        V4,
        gm.route_health_revision("A").admit(),
        None,
    );
    gm.report_udp_route_reply(&sibling);
    assert!(!gm.udp_route_current(&last));
    assert!(alive.take_route_probe().is_none());
}

#[test]
fn named_udp_chain_charges_physical_hop_and_rejects_default_probe_recovery() {
    let alive = Arc::new(AliveDialerSet::new());
    let mut nodes = udp_nodes();
    nodes.push(Node::chain("direct-chain", vec!["a".into(), "exit".into()]));
    let nodes = honk_config::Config {
        nodes,
        ..Default::default()
    }
    .assemble(|_, _, _| {})
    .unwrap()
    .nodes;
    let chain = nodes.iter().find(|n| n.name == "direct-chain").unwrap();
    let exit = nodes.iter().find(|n| n.name == "exit").unwrap().id;
    let target = OwnedTarget::node(chain.clone());
    assert_eq!(target.key(), DialKey::Node(chain.id));
    let gm = manager(&alive, &[], &nodes);
    gm.publish_route_health();
    let names = [chain.name.clone()];
    let capture = || {
        gm.capture_udp_route(&target, &names, &[], gm.udp_node_revision(chain), DATA, V4)
            .unwrap()
    };
    let fault = ChainHopFailure {
        hop: 1,
        node: exit,
        error: NodeFailure(anyhow::anyhow!("invalid proxy record")).into(),
    };
    let old_bare = gm.capture_udp_bare_reply(exit, V4).unwrap();
    let token = capture();
    assert!(token.depends_on(exit, DATA, V4, UdpHopRole::Framing));
    for _ in 0..50 {
        assert!(gm.report_udp_route_failure(&capture(), &fault));
    }
    assert!(!gm.udp_route_current(&token));
    assert!(!alive.is_alive_for(exit, DATA, V4));
    assert!(alive.is_alive_for(chain.id, DATA, V4));
    assert!(alive.is_alive_for(exit, DATA, V6));
    alive.record_probe_latency(exit, DATA, V4, Duration::from_millis(2));
    alive.report_available_traffic(exit, TCP, V4);
    gm.report_udp_bare_reply(&old_bare);
    assert!(!alive.is_alive_for(exit, DATA, V4));
    gm.report_udp_bare_reply(&gm.capture_udp_bare_reply(exit, V4).unwrap());
    assert!(alive.is_alive_for(exit, DATA, V4));
    assert!(gm.udp_route_current(&token));
    let successor = manager(&alive, &[], &nodes);
    successor.publish_route_health();
    assert!(!gm.with_udp_score_authority(&token, |current| current));
    assert!(!successor.report_udp_route_failure(&token, &fault));
}

#[test]
fn nested_udp_selector_rejects_fabricated_path_and_old_revision() {
    let nodes = udp_nodes();
    let mut subgroup = group("inner", &nodes[0]);
    subgroup.nodes.push(nodes[1].id);
    subgroup.policy = GroupPolicy::Selector;
    let outer = Group {
        name: "outer".into(),
        groups: vec!["inner".into()],
        ..Default::default()
    };
    let alive = Arc::new(AliveDialerSet::new());
    let gm = manager(&alive, &[subgroup, outer], &nodes);
    gm.publish_route_health();
    let chosen = udp_pick(&gm, "outer", DATA, V4).unwrap();
    gm.set_selector_choice("inner", "b", crate::group::SelectorNetworks::Udp)
        .unwrap();
    assert!(!gm.udp_route_current(&chosen));
    assert!(!gm.report_udp_route_failure(&chosen, crate::proxy::test_prefix_refusal(1).as_ref()));
    let tcp_pick = pick(&gm, "outer");
    assert_eq!(tcp_pick.node.id, nodes[0].id);
    let (_, revision) = gm.dial_plan_for_target(
        "outer",
        &ScoreSelectionContext::aggregate(SelectionNetwork::Udp, DATA, V4),
        None,
    );
    assert!(
        gm.capture_udp_route(
            &tcp_pick,
            &["outer".into(), "inner".into(), "a".into()],
            &[],
            revision,
            DATA,
            V4
        )
        .is_none()
    );
    assert!(udp_pick(&gm, "outer", DATA, V4).is_some());
}

#[test]
fn no_exit_group_captures_bound_chain_under_its_udp_selector() {
    let alive = Arc::new(AliveDialerSet::new());
    let mut nodes = udp_nodes();
    nodes.push(Node::chain("chain", vec!["a".into(), "exit".into()]));
    let nodes = honk_config::Config {
        nodes,
        ..Default::default()
    }
    .assemble(|_, _, _| {})
    .unwrap()
    .nodes;
    let chain = nodes.iter().find(|node| node.name == "chain").unwrap();
    let bare = nodes.iter().find(|node| node.name == "b").unwrap();
    let inner = Group {
        name: "inner".into(),
        nodes: vec![chain.id, bare.id],
        policy: GroupPolicy::Selector,
        ..Default::default()
    };
    let root = Group {
        name: "root".into(),
        groups: vec!["inner".into()],
        policy: GroupPolicy::Selector,
        ..Default::default()
    };
    let gm = manager(&alive, &[inner, root], &nodes);
    assert!(!gm.has_exits());
    assert!(gm.group_has_udp_chain("root"));
    gm.publish_route_health();
    let selected = udp_pick(&gm, "root", DATA, V4).unwrap();
    let named = gm
        .capture_udp_route(
            &OwnedTarget::node(chain.clone()),
            std::slice::from_ref(&chain.name),
            &[],
            gm.udp_node_revision(chain),
            DATA,
            V4,
        )
        .unwrap();
    gm.set_selector_choice("inner", &bare.name, crate::group::SelectorNetworks::Udp)
        .unwrap();
    assert!(!gm.udp_route_current(&selected));
    assert!(gm.udp_route_current(&named));
    assert!(gm.report_udp_route_failure(&named, crate::proxy::test_prefix_refusal(1).as_ref()));
    assert!(!gm.report_udp_route_failure(&selected, crate::proxy::test_prefix_refusal(1).as_ref()));
    assert!(named.depends_on(
        *chain.resolved_chain_hops().unwrap().last().unwrap(),
        DATA,
        V4,
        UdpHopRole::Framing
    ));
}

fn complete_udp(ticket: &RouteProbeTicket) {
    ticket
        .settle_udp(
            true,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &crate::alive::ProbeCancellation::default(),
        )
        .notify();
}

#[tokio::test]
async fn udp_dns_witness_requires_explicit_target_matching_family_and_current_pin() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = udp_nodes();
    let mut root = group("root", &nodes[0]);
    root.nodes.push(nodes[1].id);
    root.policy = GroupPolicy::Selector;
    let gm = manager(&alive, &[root], &nodes);
    gm.publish_route_health();
    let initial = udp_pick(&gm, "root", DATA, V4).unwrap();
    let failure = crate::proxy::test_prefix_refusal(1);
    for _ in 0..50 {
        let packet = udp_pick(&gm, "root", DATA, V4).unwrap();
        assert!(gm.report_udp_route_failure(&packet, failure.as_ref()));
    }
    assert!(!gm.udp_route_current(&initial));
    assert!(alive.take_route_probe().is_none());

    let explicit = [
        "[::1]:5301".to_owned(),
        "[::ffff:127.0.0.1]:5302".to_owned(),
    ];
    gm.publish_route_health_with_udp(Some(&explicit));
    let ticket = alive.take_route_probe().unwrap();
    assert_eq!((ticket.domain(), ticket.family()), (DATA, V4));
    assert_eq!(ticket.udp_check_dns(), Some(explicit.as_slice()));
    assert_eq!(
        alive
            .route_udp_probe_addr(&ticket, |_| true, None)
            .await
            .unwrap(),
        Some("127.0.0.1:5302".parse().unwrap())
    );
    assert!(alive.take_route_probe().is_none());
    gm.set_selector_choice("root", "b", crate::group::SelectorNetworks::Udp)
        .unwrap();
    assert!(!ticket.is_current());
    assert_eq!(
        alive
            .route_udp_probe_addr(&ticket, |_| true, None)
            .await
            .unwrap(),
        None
    );
    complete_udp(&ticket);
    drop(ticket);
    assert!(alive.take_route_probe().is_none());
    assert!(udp_pick(&gm, "root", DATA, V4).is_some());
    gm.set_selector_choice("root", "a", crate::group::SelectorNetworks::Udp)
        .unwrap();
    assert!(udp_pick(&gm, "root", DATA, V4).is_none());
    for row in alive.route_health.write().rows.values_mut() {
        row.due = Instant::now();
    }
    complete_udp(&alive.take_route_probe().unwrap());
    assert!(udp_pick(&gm, "root", DATA, V4).is_some());
}

#[test]
fn physical_udp_retirement_uses_exact_domain_family_and_no_prefix_sweep() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = udp_nodes();
    let gm = manager(&alive, &[group("A", &nodes[0])], &nodes);
    gm.publish_route_health_with_udp(Some(&["127.0.0.1:5300".into()]));
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    alive.set_routed_udp_death_callback(Some(Box::new({
        let calls = Arc::clone(&calls);
        move |id, domain, family, role| calls.lock().unwrap().push((id, domain, family, role))
    })));
    let exit = nodes[2].id;
    let fault = ChainHopFailure {
        hop: 1,
        node: exit,
        error: NodeFailure(anyhow::anyhow!("bad terminal record")).into(),
    };
    let last = udp_pick(&gm, "A", DATA, V4).unwrap();
    let other = udp_pick(&gm, "A", DATA, V6).unwrap();
    assert!(last.depends_on(exit, DATA, V4, UdpHopRole::Framing));
    assert!(!last.depends_on(exit, DATA, V4, UdpHopRole::Carrier));
    assert!(!other.depends_on(exit, DATA, V4, UdpHopRole::Framing));
    assert!(!last.depends_on(exit, DNS, V4, UdpHopRole::Framing));
    let prefix = crate::proxy::test_prefix_refusal(1);
    for _ in 0..49 {
        let flow = udp_pick(&gm, "A", DATA, V4).unwrap();
        assert!(gm.report_udp_route_failure(&flow, &fault));
        let refusal = udp_pick(&gm, "A", DATA, V4).unwrap();
        assert!(gm.report_udp_route_failure(&refusal, prefix.as_ref()));
    }
    let tail = udp_pick(&gm, "A", DATA, V4).unwrap();
    assert!(gm.report_udp_route_failure(&tail, prefix.as_ref()));
    assert!(calls.lock().unwrap().is_empty());
    assert!(gm.report_udp_route_failure(&last, &fault));
    assert_eq!(
        *calls.lock().unwrap(),
        [(exit, DATA, V4, UdpHopRole::Framing)]
    );
    assert!(gm.udp_route_current(&other));
    let ticket = alive.take_route_probe().unwrap();
    assert_eq!(ticket.target(), pick(&gm, "A").key());
    complete_udp(&ticket);
    assert!(
        !gm.udp_route_current(&last),
        "the other failed scope still owns a claim"
    );
    drop(ticket);
    complete_udp(&alive.take_route_probe().unwrap());
    assert!(gm.udp_route_current(&last));
    assert!(alive.is_alive_for(exit, DATA, V4));
}

#[tokio::test]
async fn udp_recovery_never_bootstraps_or_resolves_past_local_refusal() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = udp_nodes();
    let gm = manager(&alive, &[group("A", &nodes[0])], &nodes);
    gm.publish_route_health_with_udp(Some(&[
        "denied.test:5300".into(),
        "sibling.test:5301".into(),
    ]));
    for _ in 0..50 {
        let flow = udp_pick(&gm, "A", DATA, V4).unwrap();
        assert!(gm.report_udp_route_failure(&flow, crate::proxy::test_prefix_refusal(1).as_ref()));
    }
    let ticket = alive.take_route_probe().unwrap();
    assert_eq!(
        alive
            .route_udp_probe_addr(&ticket, |_| true, None)
            .await
            .unwrap(),
        None
    );
    let never_resolve: crate::alive::ResolveHook =
        Arc::new(|_, _| panic!("denied port reached DNS"));
    assert!(crate::proxy::is_packet_rejection(
        &alive
            .route_udp_probe_addr(&ticket, |port| port != 5300, Some(&never_resolve))
            .await
            .unwrap_err()
    ));
    let resolve: crate::alive::ResolveHook = Arc::new(|host, port| {
        assert_eq!((host.as_str(), port), ("denied.test", 5300));
        Box::pin(async { Err(PacketRejection::Policy.into()) })
    });
    assert!(crate::proxy::is_packet_rejection(
        &alive
            .route_udp_probe_addr(&ticket, |_| true, Some(&resolve))
            .await
            .unwrap_err()
    ));
    let successor = manager(&alive, &[group("A", &nodes[0])], &nodes);
    successor.publish_route_health_with_udp(Some(&["127.0.0.1:5302".into()]));
    assert_eq!(
        alive
            .route_udp_probe_addr(&ticket, |_| true, Some(&never_resolve))
            .await
            .unwrap(),
        None
    );
    complete_udp(&ticket);
    assert!(udp_pick(&successor, "A", DATA, V4).is_none());
}

#[test]
fn udp_recovery_timeout_backs_off_once_per_current_claim() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = udp_nodes();
    let groups = [group("A", &nodes[0])];
    let gm = manager(&alive, &groups, &nodes);
    gm.publish_route_health_with_udp(Some(&["127.0.0.1:5300".into()]));
    for _ in 0..50 {
        let flow = udp_pick(&gm, "A", DATA, V4).unwrap();
        assert!(gm.report_udp_route_failure(&flow, crate::proxy::test_prefix_refusal(1).as_ref()));
    }
    let expired = tokio::time::Instant::now();
    let cancel = crate::alive::ProbeCancellation::default();
    for misses in 1..=2 {
        let ticket = alive.take_route_probe().unwrap();
        let claim = ticket.key;
        let before = Instant::now();
        ticket.settle_udp(true, expired, &cancel).notify();
        assert!(ticket.is_current());
        ticket.settle_udp(false, expired, &cancel).notify();
        ticket.settle_udp(false, expired, &cancel).notify();
        let mut state = alive.route_health.write();
        let row = state.rows.get_mut(&claim).unwrap();
        assert_eq!(row.misses, misses);
        assert!(row.due >= before + probe_backoff(alive.base_cooldown, alive.max_cooldown, misses));
        row.due = Instant::now();
    }
    let stale = alive.take_route_probe().unwrap();
    let successor = manager(&alive, &groups, &nodes);
    successor.republish_route_health();
    stale.settle_udp(false, expired, &cancel).notify();
    assert_eq!(alive.route_health.read().rows[&stale.key].misses, 2);
    drop(stale);
    assert!(udp_pick(&successor, "A", DATA, V4).is_none());
    successor.publish_route_health_with_udp(Some(&[]));
    assert!(alive.admitted_udp_check_dns().unwrap().is_empty());
    successor.republish_route_health();
    assert!(alive.admitted_udp_check_dns().unwrap().is_empty());
    assert!(alive.take_route_probe().is_none());
    successor.publish_route_health_with_udp(None);
    assert!(alive.admitted_udp_check_dns().is_none());
}

#[test]
fn udp_final_cannot_probe_past_a_nested_selected_block() {
    let alive = Arc::new(AliveDialerSet::new());
    let mut nodes = udp_nodes();
    let block = honk_config::Config::builtin_block_node();
    let child = Group {
        name: "child".into(),
        nodes: vec![block.id],
        policy: GroupPolicy::Selector,
        ..Default::default()
    };
    nodes.push(block);
    let mut root = group("root", &nodes[1]);
    alive.report_unavailable_forced(nodes[1].id, TCP, V4);
    root.policy = GroupPolicy::Selector;
    root.groups.push(child.name.clone());
    root.final_outbound = Some(nodes[0].name.clone());
    let gm = manager(&alive, &[root, child], &nodes);
    gm.publish_route_health_with_udp(Some(&["127.0.0.1:5300".into()]));
    let refusal = crate::proxy::test_prefix_refusal(1);
    let context = ScoreSelectionContext::aggregate(SelectionNetwork::Udp, DATA, V4);
    assert_eq!(
        gm.dial_plan_for_target("root", &context, None).0.entries[0].final_owners,
        ["root"]
    );
    for _ in 0..50 {
        let attempt = udp_pick(&gm, "root", DATA, V4).unwrap();
        assert!(gm.report_udp_route_failure(&attempt, refusal.as_ref()));
    }
    gm.set_selector_choice("root", "child", crate::group::SelectorNetworks::Udp)
        .unwrap();
    assert_eq!(
        gm.dial_plan_for_target("root", &context, None).0.entries[0]
            .node
            .id,
        honk_config::config::BLOCK_NODE_ID
    );
    assert!(alive.take_route_probe().is_none());
    gm.set_selector_choice("root", "b", crate::group::SelectorNetworks::Udp)
        .unwrap();
    assert!(alive.take_route_probe().is_some());
}

#[test]
fn removing_the_original_path_drops_its_active_framing_witness() {
    let alive = Arc::new(AliveDialerSet::new());
    let mut nodes = udp_nodes();
    nodes[3] = Node::from_share_link("trojan://pass@127.0.0.1:2444#far").unwrap();
    let e = nodes[2].id;
    let mut carrier = group("carrier", &nodes[2]);
    carrier.exit = Some("far".into());
    let gm = manager(&alive, &[group("A", &nodes[0]), carrier.clone()], &nodes);
    gm.publish_route_health_with_udp(Some(&["127.0.0.1:5300".into()]));
    let fault = ChainHopFailure {
        hop: 1,
        node: e,
        error: NodeFailure(anyhow::anyhow!("invalid terminal record")).into(),
    };
    for _ in 0..50 {
        assert!(gm.report_udp_route_failure(&udp_pick(&gm, "A", DATA, V4).unwrap(), &fault));
    }
    // Independent native framing evidence and a later carrier reply on E -> far.
    alive.report_unavailable_traffic(e, DATA, V4);
    gm.report_udp_route_reply(&udp_pick(&gm, "carrier", DATA, V4).unwrap());
    assert_eq!(
        alive.read_state(e, alive_index(DATA, V4)).traffic_failures,
        1
    );
    assert!(!alive.routed_udp_node_available(e, DATA, V4));
    assert!(alive.udp_carrier_available(e, DATA, V4));
    let other_role = manager(&alive, std::slice::from_ref(&carrier), &nodes);
    other_role.republish_route_health();
    assert!(alive.take_route_probe().is_none());
    let rebound = manager(&alive, &[carrier, group("B", &nodes[1])], &nodes);
    rebound.republish_route_health();
    assert!(udp_pick(&rebound, "B", DATA, V4).is_none());
    assert!(
        alive.take_route_probe().is_none(),
        "a different front cannot authorize new active UDP traffic"
    );
    let restored = manager(
        &alive,
        &[group("A", &nodes[0]), group("B", &nodes[1])],
        &nodes,
    );
    restored.republish_route_health();
    assert!(
        alive.take_route_probe().is_none(),
        "readding a path cannot resurrect a dropped witness"
    );
    assert!(!alive.routed_udp_node_available(e, DATA, V4));
    let bare = restored.capture_udp_bare_reply(e, V4).unwrap();
    restored.report_udp_bare_reply(&bare);
    assert!(udp_pick(&restored, "B", DATA, V4).is_some());
}

#[test]
fn later_datagrams_cannot_refresh_the_first_reply_watermark() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = udp_nodes();
    let gm = manager(&alive, &[group("A", &nodes[0])], &nodes);
    gm.publish_route_health();
    let live = udp_pick(&gm, "A", DATA, V4).unwrap();
    gm.report_udp_route_reply(&live);
    let newer = udp_pick(&gm, "A", DATA, V4).unwrap();
    gm.report_udp_route_reply(&live);
    let refused = crate::proxy::test_prefix_refusal(1);
    assert!(gm.report_udp_route_failure(&newer, refused.as_ref()));
    assert!(gm.report_udp_route_failure(&live, refused.as_ref()));
}

#[test]
fn a_framing_reply_cannot_recover_a_carrier_fault_on_the_same_udp_uuid() {
    let alive = Arc::new(AliveDialerSet::new());
    let mut nodes = udp_nodes();
    nodes[3] = Node::from_share_link("trojan://pass@127.0.0.1:2444#far").unwrap();
    let e = nodes[2].id;
    let mut carrier = group("carrier", &nodes[2]);
    carrier.exit = Some("far".into());
    let gm = manager(&alive, &[carrier, group("framer", &nodes[1])], &nodes);
    gm.publish_route_health();
    let cause = SharedError::fanout(NodeFailure(anyhow::anyhow!("carrier fault")).into());
    let fail = |hop| ChainHopFailure {
        hop,
        node: e,
        error: cause.clone().into(),
    };
    let framer = udp_pick(&gm, "framer", DATA, V4).unwrap();
    let carrier = udp_pick(&gm, "carrier", DATA, V4).unwrap();
    assert!(gm.report_udp_route_failure(&carrier, &fail(0)));
    assert!(gm.report_udp_route_failure(&framer, &fail(1)));
    for _ in 1..50 {
        let attempt = udp_pick(&gm, "carrier", DATA, V4).unwrap();
        let error = ChainHopFailure {
            hop: 0,
            node: e,
            error: NodeFailure(anyhow::anyhow!("carrier fault")).into(),
        };
        assert!(gm.report_udp_route_failure(&attempt, &error));
    }
    let framer = udp_pick(&gm, "framer", DATA, V4).unwrap();
    gm.report_udp_route_reply(&framer);
    assert!(alive.is_alive_for(e, DATA, V4));
    assert!(!gm.udp_route_current(&carrier));
    assert!(gm.udp_route_current(&framer));
}

#[test]
fn shared_udp_prefix_does_not_transfer_active_checks_to_another_suffix_or_root() {
    let alive = Arc::new(AliveDialerSet::new());
    let mut nodes = udp_nodes();
    nodes[3] = Node::from_share_link("trojan://pass@127.0.0.1:2444#far").unwrap();
    let inner = group("inner", &nodes[0]);
    let outer = Group {
        name: "outer".into(),
        groups: vec!["inner".into()],
        exit: Some("far".into()),
        ..Default::default()
    };
    let gm = manager(&alive, &[inner.clone(), outer.clone()], &nodes);
    gm.publish_route_health_with_udp(Some(&["127.0.0.1:5300".into()]));
    for _ in 0..50 {
        let flow = udp_pick(&gm, "outer", DATA, V4).unwrap();
        assert!(gm.report_udp_route_failure(&flow, crate::proxy::test_prefix_refusal(1).as_ref()));
    }
    let ticket = alive.take_route_probe().unwrap();
    assert_eq!(ticket.target(), pick(&gm, "outer").key());
    drop(ticket);
    let renamed = Group {
        name: "replacement".into(),
        ..inner.clone()
    };
    let replaced_edge = Group {
        groups: vec![renamed.name.clone()],
        ..outer.clone()
    };
    let successor = manager(&alive, &[inner.clone(), renamed, replaced_edge], &nodes);
    successor.republish_route_health();
    // Keep the A -> exit prefix down without transferring outer's probe to inner.
    assert!(udp_pick(&successor, "inner", DATA, V4).is_none());
    for row in alive.route_health.write().rows.values_mut() {
        row.due = Instant::now();
    }
    assert!(alive.take_route_probe().is_none());
    let restored = manager(&alive, &[inner, outer], &nodes);
    restored.republish_route_health();
    assert!(alive.take_route_probe().is_none());
}

#[test]
fn removing_the_last_udp_route_keeps_only_the_surviving_bare_framing_fault() {
    for (was_registered, strikes) in [(false, 49), (true, 49), (false, 50), (true, 50)] {
        let alive = Arc::new(AliveDialerSet::new());
        let nodes = udp_nodes();
        let exit = nodes[2].id;
        let original = manager(&alive, &[group("routed", &nodes[0])], &nodes);
        original.publish_route_health_with_udp(Some(&["127.0.0.1:5300".into()]));
        let fault = ChainHopFailure {
            hop: 1,
            node: exit,
            error: NodeFailure(anyhow::anyhow!("invalid terminal record")).into(),
        };
        for _ in 0..strikes {
            let admitted = udp_pick(&original, "routed", DATA, V4).unwrap();
            assert!(original.report_udp_route_failure(&admitted, &fault));
        }
        let wrong_family = original.capture_udp_bare_reply(exit, V6).unwrap();
        original.report_udp_bare_reply(&wrong_family);
        if was_registered {
            alive.register_node(exit, nodes[2].name.clone(), None);
        }
        let stale = original.capture_udp_bare_reply(exit, V4).unwrap();
        let plain = manager(&alive, &[], &nodes);
        assert!(!plain.retains_udp_route_health_node(exit));
        alive.sync_registrations_retaining_routes(Default::default(), |_| true, |_| false);
        plain.republish_route_health();
        assert!(alive.take_route_probe().is_none());
        assert_eq!(
            plain.is_node_selectable_for_domain(exit, DATA, V4),
            strikes < 50
        );
        assert!(plain.is_node_selectable_for_domain(exit, DATA, V6));
        assert!(plain.is_node_selectable_for_domain(exit, DNS, V4));
        assert!(plain.is_node_selectable_for_domain(nodes[0].id, DATA, V4));
        assert!(plain.capture_udp_bare_reply(nodes[0].id, V4).is_none());
        assert!(plain.capture_udp_bare_reply(exit, V6).is_none());
        plain.report_udp_bare_reply(&stale);
        assert_eq!(
            plain.is_node_selectable_for_domain(exit, DATA, V4),
            strikes < 50
        );
        if strikes == 50 {
            let removed = manager(&alive, &[], &nodes[..2]);
            alive.sync_registrations_retaining_routes(Default::default(), |_| true, |_| false);
            removed.republish_route_health();
            let readded = manager(&alive, &[], &nodes);
            readded.republish_route_health();
            assert!(readded.is_node_selectable_for_domain(exit, DATA, V4));
            assert!(readded.capture_udp_bare_reply(exit, V4).is_none());
            continue;
        }
        // This family is still selectable at 49; a later bare flow can supply a real receipt.

        let matching = plain.capture_udp_bare_reply(exit, V4).unwrap();
        plain.report_udp_bare_reply(&matching);
        assert!(plain.is_node_selectable_for_domain(exit, DATA, V4));
        assert!(plain.capture_udp_bare_reply(exit, V4).is_none());
    }
}

#[test]
fn removing_an_exit_discards_its_collapsed_udp_witness_even_if_the_dial_key_survives() {
    for duplicate_exit in [false, true] {
        let alive = Arc::new(AliveDialerSet::new());
        let nodes = udp_nodes();
        let exit = nodes[2].id;
        let mut inner = group("inner", &nodes[2]);
        let outer = Group {
            name: "outer".into(),
            groups: vec![inner.name.clone()],
            exit: duplicate_exit.then(|| "exit".into()),
            ..Default::default()
        };
        let original = manager(&alive, &[inner.clone(), outer.clone()], &nodes);
        original.publish_route_health_with_udp(Some(&["127.0.0.1:5300".into()]));
        let fault = ChainHopFailure {
            hop: 0,
            node: exit,
            error: NodeFailure(anyhow::anyhow!("invalid terminal record")).into(),
        };
        for _ in 0..50 {
            let admission = udp_pick(&original, "outer", DATA, V4).unwrap();
            assert_eq!(admission.key(), DialKey::Node(exit));
            assert!(original.report_udp_route_failure(&admission, &fault));
        }
        let unchanged = manager(&alive, &[inner.clone(), outer.clone()], &nodes);
        unchanged.republish_route_health();
        let ticket = alive
            .take_route_probe()
            .expect("original collapse is authorized");
        assert_eq!(
            (ticket.target(), ticket.family()),
            (DialKey::Node(exit), V4)
        );
        drop(ticket);

        inner.exit = None;
        let successor = manager(&alive, &[inner, outer], &nodes);
        successor.republish_route_health();
        let context = ScoreSelectionContext::aggregate(SelectionNetwork::Udp, DATA, V6);
        let (plan, _) = successor.dial_plan_for_target("outer", &context, None);
        assert_eq!(plan.entries[0].node.id, exit);
        assert!(plan.entries[0].route.is_none());
        assert_eq!(
            plan.entries[0].collapse != crate::group::ExitCollapse::None,
            duplicate_exit,
        );
        for row in alive.route_health.write().rows.values_mut() {
            row.due = Instant::now();
        }
        assert!(alive.take_route_probe().is_none());
        assert!(successor.udp_hop_down(exit, DATA, V4, UdpHopRole::Framing));
        assert!(!successor.udp_hop_down(exit, DATA, V4, UdpHopRole::Carrier));
        assert!(successor.is_node_selectable_for_domain(exit, DATA, V6));
        assert!(successor.is_node_selectable_for_domain(exit, DNS, V4));

        let receipt = successor.capture_udp_bare_reply(exit, V4).unwrap();
        successor.report_udp_bare_reply(&receipt);
        assert!(successor.is_node_selectable_for_domain(exit, DATA, V4));
        assert!(alive.take_route_probe().is_none());
    }
}
