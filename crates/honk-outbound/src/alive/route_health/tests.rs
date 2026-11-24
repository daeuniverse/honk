use super::*;
use crate::group::{OwnedTarget, ScoreSelectionContext, SelectionNetwork, Target};
use crate::proxy::{ChainHopFailure, NodeFailure, PacketRejection, TargetFailure};
use honk_config::group::{Group, GroupPolicy};
use honk_config::node::Node;

const V4: IpVersion = IpVersion::V4;
const V6: IpVersion = IpVersion::V6;
const URL: &str = "http://check.example/ready";

fn nodes() -> Vec<Node> {
    ["a", "b", "exit", "far"]
        .into_iter()
        .enumerate()
        .map(|(i, name)| {
            Node::from_share_link(&format!("socks5://127.0.0.1:{}#{name}", 2000 + i)).unwrap()
        })
        .collect()
}

fn group(name: &str, node: &Node) -> Group {
    Group {
        name: name.into(),
        nodes: vec![node.id],
        exit: Some("exit".into()),
        check_url: Some(URL.into()),
        policy: GroupPolicy::Fallback,
        ..Default::default()
    }
}

fn manager(alive: &Arc<AliveDialerSet>, groups: &[Group], nodes: &[Node]) -> Arc<GroupManager> {
    Arc::new(GroupManager::with_alive_set(
        groups,
        nodes,
        Some(Arc::clone(alive)),
    ))
}

fn pick(manager: &GroupManager, root: &str) -> OwnedTarget {
    let context = ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, TCP, V4);
    let (plan, _) = manager.dial_plan_for_target(root, &context, None);
    let entry = plan.entries.into_iter().next().unwrap();
    let mut target = manager.own_target(Target {
        node: entry.node,
        route: entry.route,
    });
    target.collapse = entry.collapse;
    target
}

fn refuse(
    manager: &GroupManager,
    root: &str,
    target: &OwnedTarget,
    family: IpVersion,
    error: &(dyn std::error::Error + 'static),
) -> bool {
    let stamp = manager.route_health_revision(root).admit();
    manager.report_route_failure(root, target, family, stamp, error)
}

fn fail_prefix(manager: &GroupManager, root: &str, target: &OwnedTarget, family: IpVersion) {
    let refusal = crate::proxy::test_prefix_refusal(1);
    for _ in 0..traffic_failure_threshold(TCP) {
        assert!(refuse(manager, root, target, family, refusal.as_ref()));
    }
}

#[test]
fn ordered_prefix_threshold_shared_episode_and_traffic_aba() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = nodes();
    let mut long = Group {
        name: "long".into(),
        groups: vec!["A".into()],
        ..Default::default()
    };
    long.exit = Some("far".into());
    let gm = manager(
        &alive,
        &[group("A", &nodes[0]), group("B", &nodes[1]), long],
        &nodes,
    );
    gm.publish_route_health();
    let (a, b, longer) = (pick(&gm, "A"), pick(&gm, "B"), pick(&gm, "long"));
    let early = gm.route_health_revision("A").admit();
    let first = SharedError::fanout(crate::proxy::test_prefix_refusal(1));
    let second = SharedError::fanout(crate::proxy::test_prefix_refusal(1));
    for cause in [&second, &first] {
        for index in 0..traffic_failure_threshold(TCP) {
            assert_eq!(
                refuse(&gm, "A", &a, V4, &SharedError::clone(cause)),
                index == 0
            );
        }
    }
    // The same cause does not consume another ordered prefix's claim.
    assert!(refuse(&gm, "B", &b, V4, &second));
    let b_prefix = Prefix::new(physical_hops(&b.key()), RouteScope::new(TCP, V4));
    assert_eq!(alive.route_health.read().rows[&b_prefix].failures, 1);
    let refusal = crate::proxy::test_prefix_refusal(1);
    for _ in 3..traffic_failure_threshold(TCP) {
        assert!(refuse(&gm, "A", &a, V4, refusal.as_ref()));
    }
    assert!(gm.route_prefix_available(a.route().unwrap(), V4));
    assert!(refuse(&gm, "A", &a, V4, refusal.as_ref()));
    assert!(!gm.route_prefix_available(a.route().unwrap(), V4));
    assert!(!gm.route_prefix_available(longer.route().unwrap(), V4));
    assert!(gm.route_prefix_available(a.route().unwrap(), V6));
    assert!(gm.route_prefix_available(b.route().unwrap(), V4));
    assert!(alive.is_alive_for(nodes[2].id, TCP, V4));
    for node in &nodes {
        assert_eq!(
            alive
                .read_state(node.id, alive_index(TCP, V4))
                .traffic_failures,
            0
        );
        assert_eq!(
            alive
                .read_state(node.id, alive_index(TCP, V6))
                .traffic_failures,
            0
        );
    }

    let old = alive.take_route_probe().unwrap();
    assert_eq!(old.target(), a.key());
    assert!(alive.take_route_probe().is_none());
    gm.report_route_response("A", a.key(), V4, early, None);
    gm.report_route_response(
        "B",
        b.key(),
        V4,
        gm.route_health_revision("B").admit(),
        None,
    );
    alive.report_available_traffic(nodes[2].id, TCP, V4);
    gm.report_route_response(
        "A",
        a.key(),
        V6,
        gm.route_health_revision("A").admit(),
        None,
    );
    assert!(!gm.route_prefix_available(a.route().unwrap(), V4));
    let unseen = SharedError::fanout(crate::proxy::test_prefix_refusal(1));
    gm.report_route_response(
        "long",
        longer.key(),
        V4,
        gm.route_health_revision("long").admit(),
        None,
    );
    assert!(gm.route_prefix_available(a.route().unwrap(), V4));
    assert!(!refuse(&gm, "A", &a, V4, &first));
    assert!(!refuse(&gm, "A", &a, V4, &unseen));
    for _ in 1..traffic_failure_threshold(TCP) {
        assert!(refuse(&gm, "A", &a, V4, refusal.as_ref()));
    }
    assert!(gm.route_prefix_available(a.route().unwrap(), V4));
    assert!(refuse(&gm, "A", &a, V4, refusal.as_ref()));
    assert!(alive.take_route_probe().is_none());
    assert!(!old.is_current());
    old.finish(true);
    let current = alive.take_route_probe().unwrap();
    assert!(current.is_current());
    assert!(!gm.route_prefix_available(a.route().unwrap(), V4));
    current.finish(true);
    assert!(gm.route_prefix_available(a.route().unwrap(), V4));

    gm.publish_route_health();
    assert!(!refuse(&gm, "A", &a, V4, &first));
    let a_prefix = Prefix::new(physical_hops(&a.key()), RouteScope::new(TCP, V4));
    assert!(!alive.route_health.read().rows.contains_key(&a_prefix));
}

#[test]
fn publication_reattaches_alternate_root_and_rejects_retired_receipts() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = nodes();
    let original = manager(&alive, &[group("old", &nodes[0])], &nodes);
    original.publish_route_health();
    let target = pick(&original, "old");
    fail_prefix(&original, "old", &target, V4);
    let old = alive.take_route_probe().unwrap();
    let stamp = original.route_health_revision("old").admit();
    let mut next = group("new", &nodes[0]);
    next.check_url = Some("http://replacement.example/check".into());
    let successor = manager(&alive, &[next], &nodes);
    assert!(old.is_current()); // constructing a rejected candidate has no effect
    successor.publish_route_health();
    old.finish(true);
    original.report_route_response("old", target.key(), V4, stamp, None);
    successor.report_route_response("new", target.key(), V4, stamp, None);
    assert!(!successor.route_prefix_available(target.route().unwrap(), V4));
    for row in alive.route_health.write().rows.values_mut() {
        row.due = Instant::now();
    }
    let current = alive.take_route_probe().unwrap();
    assert_eq!(current.target(), target.key());
    assert_eq!(current.url(), "http://replacement.example/check");
    // Cancellation releases only the claim. A due row can be taken again.
    drop(current);
    for row in alive.route_health.write().rows.values_mut() {
        row.due = Instant::now();
    }
    assert!(alive.take_route_probe().is_some());
    let empty = manager(&alive, &[group("new", &nodes[1])], &nodes);
    empty.publish_route_health();
    assert!(alive.route_health.read().rows.is_empty());
    assert!(alive.take_route_probe().is_none());
}

#[test]
fn only_attributed_hop_charges_uuid_and_probes_its_own_path() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = nodes();
    let gm = manager(
        &alive,
        &[group("A", &nodes[0]), group("B", &nodes[1])],
        &nodes,
    );
    gm.publish_route_health();
    let a = pick(&gm, "A");
    let id = a.key().success_owner();
    let refused = TargetFailure(anyhow::anyhow!("destination refused"));
    let ambiguous = std::io::Error::other("reset");
    let local = PacketRejection::Capacity;
    for error in [
        &refused as &(dyn std::error::Error + 'static),
        &ambiguous,
        &local,
    ] {
        for _ in 0..traffic_failure_threshold(TCP) {
            assert!(!gm.report_route_failure(
                "A",
                &a,
                V4,
                gm.route_health_revision("A").admit(),
                error
            ));
        }
    }
    assert!(alive.route_health.read().rows.is_empty());
    let cause = ChainHopFailure {
        node: id,
        hop: 1,
        error: NodeFailure(anyhow::anyhow!("carrier closed")).into(),
    };
    let shared = crate::SharedError::fanout(cause.into());
    for index in 0..traffic_failure_threshold(TCP) {
        assert_eq!(
            gm.report_route_failure("A", &a, V4, gm.route_health_revision("A").admit(), &shared),
            index == 0
        );
    }
    assert!(alive.is_alive_for(id, TCP, V4));
    for _ in 1..traffic_failure_threshold(TCP) {
        let cause = ChainHopFailure {
            node: id,
            hop: 1,
            error: NodeFailure(anyhow::anyhow!("carrier closed")).into(),
        };
        assert!(gm.report_route_failure(
            "A",
            &a,
            V4,
            gm.route_health_revision("A").admit(),
            &cause
        ));
    }
    assert!(!alive.is_registered(id));
    assert!(!alive.is_alive_for(id, TCP, V4));
    assert!(alive.is_alive_for(id, TCP, V6));
    assert!(alive.is_alive_for(nodes[0].id, TCP, V4));
    assert_eq!(
        alive.read_state(id, alive_index(TCP, V4)).traffic_failures,
        traffic_failure_threshold(TCP)
    );
    assert_eq!(
        alive.read_state(id, alive_index(TCP, V6)).traffic_failures,
        0
    );
    assert_eq!(
        alive
            .read_state(nodes[0].id, alive_index(TCP, V4))
            .traffic_failures,
        0
    );
    let probe = alive.take_route_probe().unwrap();
    assert_eq!(probe.target(), a.key());
    probe.finish(true);
    assert!(alive.is_alive_for(id, TCP, V4));
    assert!(alive.take_route_probe().is_none());

    for _ in 0..traffic_failure_threshold(TCP) {
        let cause = ChainHopFailure {
            node: id,
            hop: 1,
            error: NodeFailure(anyhow::anyhow!("carrier closed again")).into(),
        };
        gm.report_route_failure("A", &a, V4, gm.route_health_revision("A").admit(), &cause);
    }
    let successor = manager(&alive, &[group("B", &nodes[1])], &nodes);
    alive.sync_registrations_retaining_routes(
        Default::default(),
        |_| true,
        |node| [nodes[1].id, id].contains(node),
    );
    successor.publish_route_health();
    // The actual hop is still down, but config removed the path that could recover it.
    assert!(!alive.is_alive_for(id, TCP, V4));
    assert!(alive.route_health.read().rows.is_empty());
    assert!(alive.take_route_probe().is_none());
    let removed = manager(&alive, &[], &nodes);
    alive.sync_registrations_retaining_routes(Default::default(), |_| true, |_| false);
    removed.publish_route_health();
    assert!(!alive.states.read().contains_key(&id));
}

#[test]
fn stale_http_and_business_successes_keep_the_original_hop_witness() {
    for prefix_down in [false, true] {
        let alive = Arc::new(AliveDialerSet::new());
        let nodes = nodes();
        let gm = manager(
            &alive,
            &[group("A", &nodes[0]), group("B", &nodes[1])],
            &nodes,
        );
        gm.publish_route_health();
        let a_revision = gm.route_health_revision("A");
        let b_revision = gm.route_health_revision("B");
        let (a, b) = (pick(&gm, "A"), pick(&gm, "B"));
        let id = a.key().success_owner();
        let prefix = Prefix::new(physical_hops(&a.key()), RouteScope::new(TCP, V4));
        let fault = ChainHopFailure {
            node: id,
            hop: 1,
            error: NodeFailure(anyhow::anyhow!("carrier closed")).into(),
        };
        for _ in 0..traffic_failure_threshold(TCP) {
            assert!(gm.report_route_failure("A", &a, V4, a_revision.admit(), &fault));
        }
        if prefix_down {
            fail_prefix(&gm, "A", &a, V4);
        }
        let episode = alive.hop_episode(prefix, u64::MAX).unwrap();
        let old = alive.take_route_probe().unwrap();
        assert_eq!((old.target(), old.url()), (a.key(), URL));
        assert!(old.is_current());
        let business = a_revision.admit();

        assert!(gm.report_route_failure("B", &b, V4, b_revision.admit(), &fault));
        assert_eq!(
            alive.read_state(id, alive_index(TCP, V4)).traffic_failures,
            traffic_failure_threshold(TCP) + 1
        );
        assert_eq!(
            alive
                .read_state(nodes[1].id, alive_index(TCP, V4))
                .traffic_failures,
            0
        );
        assert_eq!(alive.hop_episode(prefix, u64::MAX), Some(episode));
        assert_eq!(old.is_current(), prefix_down);
        old.finish(true);
        assert!(gm.route_prefix_available(a.route().unwrap(), V4));
        assert!(!alive.is_alive_for(id, TCP, V4));
        assert_eq!(
            alive.route_health.read().rows[&prefix].hop_failure,
            Some(episode)
        );

        gm.report_route_response("A", a.key(), V4, business, None);
        assert!(!alive.is_alive_for(id, TCP, V4));
        assert_eq!(
            alive.route_health.read().rows[&prefix].hop_failure,
            Some(episode)
        );
        alive
            .route_health
            .write()
            .rows
            .get_mut(&prefix)
            .unwrap()
            .due = Instant::now();
        let dropped = alive.take_route_probe().unwrap();
        assert_eq!((dropped.target(), dropped.url()), (a.key(), URL));
        assert!(dropped.is_current());
        drop(dropped);

        alive
            .route_health
            .write()
            .rows
            .get_mut(&prefix)
            .unwrap()
            .due = Instant::now();
        let current = alive.take_route_probe().unwrap();
        assert_eq!(current.target(), a.key());
        current.finish(true);
        assert!(alive.is_alive_for(id, TCP, V4));
        assert!(
            alive.route_health.read().rows[&prefix]
                .hop_failure
                .is_none()
        );
        assert!(alive.take_route_probe().is_none());
    }
}

#[test]
fn a_ticket_cannot_recover_a_replacement_hop_episode() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = nodes();
    let gm = manager(&alive, &[group("A", &nodes[0])], &nodes);
    gm.publish_route_health();
    let revision = gm.route_health_revision("A");
    let a = pick(&gm, "A");
    let id = a.key().success_owner();
    let prefix = Prefix::new(physical_hops(&a.key()), RouteScope::new(TCP, V4));
    let fault = ChainHopFailure {
        node: id,
        hop: 1,
        error: NodeFailure(anyhow::anyhow!("carrier closed")).into(),
    };
    let fail_hop = || {
        for _ in 0..traffic_failure_threshold(TCP) {
            assert!(gm.report_route_failure("A", &a, V4, revision.admit(), &fault));
        }
    };
    fail_hop();
    let old = alive.take_route_probe().unwrap();
    let first_episode = alive.hop_episode(prefix, u64::MAX).unwrap();
    gm.report_route_response("A", a.key(), V4, revision.admit(), None);
    assert!(
        alive.route_health.read().rows[&prefix]
            .hop_failure
            .is_none()
    );

    fail_hop();
    let next_episode = alive.hop_episode(prefix, u64::MAX).unwrap();
    assert_ne!(first_episode, next_episode);
    assert!(!old.is_current());
    old.finish(true);
    assert_eq!(
        alive.route_health.read().rows[&prefix].hop_failure,
        Some(next_episode)
    );

    alive
        .route_health
        .write()
        .rows
        .get_mut(&prefix)
        .unwrap()
        .due = Instant::now();
    let current = alive.take_route_probe().unwrap();
    assert_eq!(current.target(), a.key());
    current.finish(true);
    assert!(alive.is_alive_for(id, TCP, V4));
}

#[test]
fn reversed_shared_hop_failures_each_count_once_in_their_scope() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = nodes();
    let gm = manager(
        &alive,
        &[group("A", &nodes[0]), group("B", &nodes[1])],
        &nodes,
    );
    gm.publish_route_health();
    let a_revision = gm.route_health_revision("A");
    let b_revision = gm.route_health_revision("B");
    let (a, b) = (pick(&gm, "A"), pick(&gm, "B"));
    let id = a.key().success_owner();
    let fault = || ChainHopFailure {
        node: id,
        hop: 1,
        error: NodeFailure(anyhow::anyhow!("carrier closed")).into(),
    };
    let first = SharedError::fanout(fault().into());
    let second = SharedError::fanout(fault().into());
    let idx = alive_index(TCP, V4);
    for _ in 2..traffic_failure_threshold(TCP) {
        assert!(gm.report_route_failure("A", &a, V4, a_revision.admit(), &fault()));
    }
    assert!(gm.report_route_failure("B", &b, V4, b_revision.admit(), &second.clone()));
    assert!(gm.report_route_failure("A", &a, V4, a_revision.admit(), &first.clone()));
    for cause in [&first, &second] {
        assert!(!gm.report_route_failure("B", &b, V4, b_revision.admit(), cause));
    }
    assert_eq!(
        alive.read_state(id, idx).traffic_failures,
        traffic_failure_threshold(TCP)
    );
    assert!(!alive.is_alive_for(id, TCP, V4));

    let unseen = SharedError::fanout(fault().into());
    gm.report_route_response("A", a.key(), V4, a_revision.admit(), None);
    assert!(!gm.report_route_failure("A", &a, V4, a_revision.admit(), &unseen));
    assert_eq!(alive.read_state(id, idx).traffic_failures, 0);
    assert!(alive.is_alive_for(id, TCP, V4));

    assert!(gm.report_route_failure("B", &b, V6, b_revision.admit(), &first));
    assert!(!gm.report_route_failure("A", &a, V6, a_revision.admit(), &first));
    assert_eq!(
        alive.read_state(id, alive_index(TCP, V6)).traffic_failures,
        1
    );
    for front in &nodes[..2] {
        assert_eq!(alive.read_state(front.id, idx).traffic_failures, 0);
        assert_eq!(
            alive
                .read_state(front.id, alive_index(TCP, V6))
                .traffic_failures,
            0
        );
    }
}

#[test]
fn dropping_leaf_registration_retains_only_the_routed_hop_verdict() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = nodes();
    let id = nodes[2].id;
    alive.register_node(id, nodes[2].name.clone(), Some(nodes[2].address.clone()));
    alive.node_registered_at.write().remove(&id);
    let gm = manager(&alive, &[group("A", &nodes[0])], &nodes);
    gm.publish_route_health();
    let a = pick(&gm, "A");
    for _ in 0..traffic_failure_threshold(TCP) {
        let cause = ChainHopFailure {
            node: id,
            hop: 1,
            error: NodeFailure(anyhow::anyhow!("carrier closed")).into(),
        };
        gm.report_route_failure("A", &a, V4, gm.route_health_revision("A").admit(), &cause);
    }
    // Legacy raw failure has no routed receipt for v6.
    for _ in 0..super::super::probe_failure_threshold(TCP) {
        alive.unavailable_change(id, TCP, V6, false, false);
    }
    assert!(!alive.is_alive_for(id, TCP, V4));
    assert!(!alive.is_alive_for(id, TCP, V6));
    assert!(alive.take_route_probe().is_none());
    let successor = manager(&alive, &[group("new", &nodes[0])], &nodes);
    alive.sync_registrations_retaining_routes(
        Default::default(),
        |_| true,
        |candidate| *candidate == id,
    );
    assert_eq!(gm.route_health_revision("A").generation, 0);
    successor.publish_route_health();
    assert!(!alive.is_registered(id));
    assert!(!alive.is_alive_for(id, TCP, V4));
    assert!(alive.is_alive_for(id, TCP, V6));
    let probe = alive.take_route_probe().unwrap();
    assert_eq!((probe.target(), probe.family()), (a.key(), V4));
    probe.finish(true);
    assert!(alive.is_alive_for(id, TCP, V4));
}

#[test]
fn releasing_old_ticket_during_deregistration_preserves_the_staged_hop() {
    for finish in [false, true] {
        let alive = Arc::new(AliveDialerSet::new());
        let nodes = nodes();
        let exit = &nodes[2];
        alive.register_node(exit.id, exit.name.clone(), Some(exit.address.clone()));
        alive.node_registered_at.write().remove(&exit.id);
        let mut alternate = group("B", &nodes[1]);
        alternate.final_outbound = Some("block".into());
        let groups = [group("A", &nodes[0]), alternate];
        let original = manager(&alive, &groups, &nodes);
        original.publish_route_health();
        let revision = original.route_health_revision("A");
        let a = pick(&original, "A");
        assert_eq!(pick(&original, "B").node.id, nodes[1].id);
        let fault = ChainHopFailure {
            node: exit.id,
            hop: 1,
            error: NodeFailure(anyhow::anyhow!("carrier closed")).into(),
        };
        for _ in 0..traffic_failure_threshold(TCP) {
            assert!(original.report_route_failure("A", &a, V4, revision.admit(), &fault));
        }
        assert!(alive.take_route_probe().is_none());
        fail_prefix(&original, "A", &a, V4);
        let old = alive.take_route_probe().unwrap();
        assert_eq!(old.target(), a.key());
        assert!(old.is_current());

        let successor = manager(&alive, &groups, &nodes);
        alive.sync_registrations_retaining_routes(
            Default::default(),
            |_| true,
            |id| *id == exit.id,
        );
        assert!(!alive.states.read().contains_key(&exit.id));
        if finish {
            old.finish(true);
        } else {
            drop(old);
        }
        successor.publish_route_health();

        assert_eq!(
            pick(&successor, "B").node.id,
            honk_config::config::BLOCK_NODE_ID
        );
        assert!(!alive.is_alive_for(exit.id, TCP, V4));
        assert!(alive.is_alive_for(exit.id, TCP, V6));
        let prefix = Prefix::new(physical_hops(&a.key()), RouteScope::new(TCP, V4));
        alive
            .route_health
            .write()
            .rows
            .get_mut(&prefix)
            .unwrap()
            .due = Instant::now();
        let current = alive.take_route_probe().unwrap();
        assert_eq!(current.target(), a.key());
        current.finish(true);
        assert_eq!(pick(&successor, "B").node.id, nodes[1].id);
    }
}

#[test]
fn selector_change_fences_probe_and_never_borrows_its_custom_url() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = nodes();
    let mut g = group("root", &nodes[0]);
    g.nodes.push(nodes[1].id);
    g.policy = GroupPolicy::Selector;
    let gm = manager(&alive, &[g], &nodes);
    gm.publish_route_health();
    let revision = gm.route_health_revision("root");
    let a = pick(&gm, "root");
    for _ in 0..traffic_failure_threshold(TCP) {
        let stamp = revision.admit();
        alive
            .route_failed(
                Failure {
                    manager: &gm,
                    witness: (Some("root"), a.key(), None),
                    udp: None,
                    hops: a.route().unwrap().hops(),
                    scope: RouteScope::new(TCP, V4),
                    selector: stamp.selector,
                    stamp,
                    end: 1,
                    node: None,
                    prefix: true,
                    shared: None,
                },
                || true,
            )
            .unwrap();
    }
    assert!(alive.take_route_probe().is_none());
    *alive.check_url.write() = "http://global.example/ready".into();
    let old = alive.take_route_probe().unwrap();
    assert_eq!(old.url(), "http://global.example/ready");
    gm.set_selector_choice("root", "b", crate::group::SelectorNetworks::Tcp)
        .unwrap();
    assert!(!old.is_current());
    gm.report_route_response("root", a.key(), V4, revision.admit(), None);
    old.finish(true);
    assert!(!gm.route_prefix_available(a.route().unwrap(), V4));
    assert!(alive.take_route_probe().is_none());
    gm.set_selector_choice("root", "a", crate::group::SelectorNetworks::Tcp)
        .unwrap();
    for row in alive.route_health.write().rows.values_mut() {
        row.due = Instant::now();
    }
    let current = alive.take_route_probe().unwrap();
    alive
        .health_mode
        .send_replace(super::super::runner::HealthMode::Stopped);
    assert!(!current.is_current());
    current.finish(true);
    assert!(!gm.route_prefix_available(a.route().unwrap(), V4));
}

#[test]
fn a_leaf_that_is_its_own_exit_can_supply_a_collapsed_witness() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = nodes();
    let exit = &nodes[2];
    let collapsed = group("exit", exit);
    let mut plain = group("plain", exit);
    plain.exit = None;
    let gm = manager(&alive, &[plain, collapsed], &nodes);
    gm.publish_route_health();
    let target = pick(&gm, "exit");
    let plain = pick(&gm, "plain");
    assert_eq!(target.key(), plain.key());
    assert!(target.uses_route_evidence());
    assert!(!plain.uses_route_evidence());
    let error = NodeFailure(anyhow::anyhow!("carrier closed"));
    for _ in 0..traffic_failure_threshold(TCP) {
        assert!(gm.report_route_failure(
            "exit",
            &target,
            V4,
            gm.route_health_revision("exit").admit(),
            &error
        ));
    }
    assert_eq!(
        alive
            .read_state(exit.id, alive_index(TCP, V4))
            .traffic_failures,
        traffic_failure_threshold(TCP)
    );
    assert_eq!(
        alive
            .read_state(exit.id, alive_index(TCP, V6))
            .traffic_failures,
        0
    );
    let ticket = alive.take_route_probe().unwrap();
    assert_eq!(ticket.target(), DialKey::Node(exit.id));
    ticket.finish(true);
    assert!(alive.is_alive_for(exit.id, TCP, V4));
}

#[test]
fn only_the_proven_attempt_can_report_its_late_hop_failure() {
    let alive = Arc::new(AliveDialerSet::new());
    let nodes = nodes();
    let gm = manager(&alive, &[group("A", &nodes[0])], &nodes);
    gm.publish_route_health();
    let target = pick(&gm, "A");
    let id = target.key().success_owner();
    let failure = || ChainHopFailure {
        node: id,
        hop: 1,
        error: NodeFailure(anyhow::anyhow!("carrier closed")).into(),
    };
    let revision = gm.route_health_revision("A");
    let proven = revision.admit();
    let peer = revision.admit();
    let old_shared = crate::SharedError::fanout(failure().into());
    gm.report_route_response("A", target.key(), V4, proven, None);

    assert!(!gm.report_route_failure("A", &target, V4, peer, &failure()));
    assert!(!gm.report_route_failure("A", &target, V4, proven, &old_shared));
    let late = crate::SharedError::fanout(failure().into());
    assert!(gm.report_route_failure("A", &target, V4, proven, &late));
    assert!(!gm.report_route_failure("A", &target, V4, proven, &late));
    assert!(!gm.report_route_failure("A", &target, V4, proven, &failure()));
    assert_eq!(
        alive.read_state(id, alive_index(TCP, V4)).traffic_failures,
        1
    );
    assert_eq!(
        alive
            .read_state(target.node.id, alive_index(TCP, V4))
            .traffic_failures,
        0
    );
}

#[test]
fn first_proof_fences_older_attempts_only_on_its_actual_prefix() {
    for proof_root in ["B", "A"] {
        let alive = Arc::new(AliveDialerSet::new());
        let nodes = nodes();
        let mut a_group = group("A", &nodes[0]);
        a_group.final_outbound = Some("block".into());
        let gm = manager(&alive, &[a_group, group("B", &nodes[1])], &nodes);
        gm.publish_route_health();
        let revision = gm.route_health_revision("A");
        let (a, b) = (pick(&gm, "A"), pick(&gm, "B"));
        let older: [_; traffic_failure_threshold(TCP) as usize] =
            std::array::from_fn(|_| (revision.admit(), crate::proxy::test_prefix_refusal(1)));
        assert!(alive.route_health.read().rows.is_empty());
        let proof = if proof_root == "A" { &a } else { &b };
        let proof_stamp = gm.route_health_revision(proof_root).admit();
        gm.report_route_response(proof_root, proof.key(), V4, proof_stamp, None);

        for (stamp, error) in older {
            assert_eq!(
                crate::proxy::dial_failure_scope(error.as_ref()),
                crate::proxy::DialFailureScope::Prefix(1)
            );
            assert_eq!(
                gm.report_route_failure("A", &a, V4, stamp, error.as_ref()),
                proof_root != "A"
            );
        }
        for node in &nodes {
            assert_eq!(
                alive
                    .read_state(node.id, alive_index(TCP, V4))
                    .traffic_failures,
                0
            );
            assert_eq!(
                alive
                    .read_state(node.id, alive_index(TCP, V6))
                    .traffic_failures,
                0
            );
        }
        assert!(gm.route_prefix_available(b.route().unwrap(), V4));
        let wanted = if proof_root == "A" {
            a.node.id
        } else {
            honk_config::config::BLOCK_NODE_ID
        };
        assert_eq!(
            pick(&gm, "A").node.id,
            wanted,
            "next selected member after proof via {proof_root}"
        );
        assert_eq!(
            gm.route_prefix_available(a.route().unwrap(), V4),
            proof_root == "A",
            "proof via {proof_root}"
        );
        if proof_root == "A" {
            let prefix = Prefix::new(physical_hops(&a.key()), RouteScope::new(TCP, V4));
            {
                let state = alive.route_health.read();
                assert!(!state.rows.contains_key(&prefix));
                assert!(state.positive.contains_key(&prefix));
            }
            let refusal = crate::proxy::test_prefix_refusal(1);
            assert!(refuse(&gm, "A", &a, V4, refusal.as_ref()));
            let state = alive.route_health.read();
            assert_eq!(state.rows[&prefix].failures, 1);
            assert!(!state.positive.contains_key(&prefix));
        }
    }
}

mod udp;
