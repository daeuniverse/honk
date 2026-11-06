use super::*;
use crate::ebpf::interface::Topology;
use crate::ebpf::test_support::{LinkExt, link, planned};

fn keys(plan: &InterfacePlan) -> Vec<Key> {
    plan.bindings.iter().map(|b| b.key()).collect()
}

fn entry(name: &str, state: EntryState) -> Entry {
    Entry {
        name: name.into(),
        state,
        detail: String::new(),
    }
}

fn states(
    plan: &InterfacePlan,
    owned: &[Key],
    failures: &[BindFailure],
) -> Vec<(String, EntryState)> {
    entry_states(plan, owned, failures)
        .into_iter()
        .map(|e| (e.name, e.state))
        .collect()
}

#[test]
fn degradation_reason_orders_attach_failed_over_unsupported_over_pending_and_clears() {
    use EntryState::*;
    let reason = |states: &[EntryState]| {
        let entries: Vec<_> = states.iter().map(|s| entry("x", *s)).collect();
        degradation_reason(&entries)
    };
    assert_eq!(reason(&[]), None);
    assert_eq!(reason(&[Bound, Bound]), None);
    assert_eq!(reason(&[Bound, Pending]), Some(Pending));
    assert_eq!(reason(&[Pending, Unsupported]), Some(Unsupported));
    assert_eq!(
        reason(&[Unsupported, Pending, AttachFailed, Bound]),
        Some(AttachFailed)
    );
    assert_eq!(interface_issue(Bound), None);
    for (state, reason) in [
        (Pending, "pending"),
        (Unsupported, "unsupported_type"),
        (AttachFailed, "attach_failed"),
    ] {
        assert_eq!(interface_issue(state).unwrap().reason, reason);
    }
}

#[test]
fn entry_states_follow_the_plan_the_owner_and_the_failures() {
    let plan = planned(
        &["eth0", "gone"],
        &["lo", "eth1"],
        &Topology {
            links: vec![link(1, "lo").arphrd(772), link(2, "eth0"), link(3, "eth1")],
            default_route: None,
        },
    );
    let all = keys(&plan);
    let state = |plan: &InterfacePlan, owned: &[Key], failures: &[BindFailure]| {
        states(plan, owned, failures)
    };
    let got = state(&plan, &all, &[]);
    assert!(got.contains(&("gone".into(), EntryState::Pending)));
    assert!(got.contains(&("lo".into(), EntryState::Unsupported)));
    assert!(got.contains(&("eth0".into(), EntryState::Bound)));
    assert!(got.contains(&("eth1".into(), EntryState::Bound)));

    // eth1's egress is not owned and nothing failed: it is still converging.
    let eth1 = NonZeroU32::new(3).unwrap();
    let owned: Vec<Key> = all
        .iter()
        .copied()
        .filter(|k| *k != (eth1, Direction::Egress))
        .collect();
    assert!(state(&plan, &owned, &[]).contains(&("eth1".into(), EntryState::Pending)));

    // A failure on a derived ifindex wins, owned or not.
    let failure = BindFailure {
        key: (eth1, Direction::Ingress),
        program: "wan_ingress_l2",
        interface: "eth1".into(),
        message: "boom".into(),
    };
    let got = entry_states(&plan, &owned, std::slice::from_ref(&failure));
    let eth1_entry = got.iter().find(|e| e.name == "eth1").unwrap();
    assert_eq!(eth1_entry.state, EntryState::AttachFailed);
    assert!(eth1_entry.detail.contains("boom"), "{}", eth1_entry.detail);
    assert!(
        got.iter()
            .find(|e| e.name == "eth0")
            .is_some_and(|e| e.state == EntryState::Bound)
    );
}

#[test]
fn a_bridge_entry_is_unbound_when_any_port_is_unbound() {
    let mut bridge = link(10, "br0");
    bridge.kind = Some("bridge".into());
    let mut port = link(11, "p1");
    port.master = NonZeroU32::new(10);
    let plan = planned(
        &["br0"],
        &[],
        &Topology {
            links: vec![bridge, port],
            default_route: None,
        },
    );
    assert_eq!(plan.bound[0].1.len(), 2);
    let port_ingress = (NonZeroU32::new(11).unwrap(), Direction::Ingress);
    let owned: Vec<Key> = keys(&plan)
        .into_iter()
        .filter(|k| *k != port_ingress)
        .collect();
    assert_eq!(
        states(&plan, &owned, &[]),
        [("br0".to_string(), EntryState::Pending)]
    );
}

#[test]
fn episodes_warn_once_log_recovery_and_keep_a_refusal_quiet() {
    use EntryState::{AttachFailed, Pending, Unsupported};
    use Transition::{Begins, Continues, Lost};
    let bound = EntryState::Bound;
    let mut episodes = Episodes::default();
    let step = |episodes: &mut Episodes, state| {
        episodes
            .observe(&[entry("eth1", state)])
            .into_iter()
            .map(|(_, t)| t)
            .collect::<Vec<_>>()
    };
    assert_eq!(step(&mut episodes, Pending), [Begins]);
    assert_eq!(step(&mut episodes, Pending), [Continues]);
    assert_eq!(step(&mut episodes, Pending), [Continues]);
    assert_eq!(step(&mut episodes, bound), [Transition::Bound]);
    assert_eq!(step(&mut episodes, bound), []);
    // Deleted: an expected loss, then DEBUG while it persists.
    assert_eq!(step(&mut episodes, Pending), [Lost]);
    assert_eq!(step(&mut episodes, Pending), [Continues]);
    // A device that is there but cannot be attached starts a new episode.
    assert_eq!(step(&mut episodes, AttachFailed), [Begins]);
    assert_eq!(step(&mut episodes, AttachFailed), [Continues]);
    assert_eq!(step(&mut episodes, bound), [Transition::Bound]);
    // A bound entry that now fails verification is a WARN, not a quiet loss.
    assert_eq!(step(&mut episodes, AttachFailed), [Begins]);
    // Deletion after a failed attach is still an expected lifecycle event.
    assert_eq!(step(&mut episodes, Pending), [Lost]);
    assert_eq!(step(&mut episodes, Pending), [Continues]);

    let mut episodes = Episodes::default();
    assert_eq!(step(&mut episodes, Unsupported), [Begins]);
    for _ in 0..3 {
        assert_eq!(step(&mut episodes, Unsupported), [Continues]);
    }
    // Started bound: one INFO, then silence; dropped entries are forgotten.
    let mut episodes = Episodes::default();
    assert_eq!(step(&mut episodes, bound), [Transition::Bound]);
    assert_eq!(step(&mut episodes, bound), []);
    assert!(episodes.observe(&[]).is_empty());
    assert!(episodes.last.is_empty());
}

#[test]
fn a_failing_step_warns_once_and_recovers_once() {
    let mut steps = StepEpisode::default();
    assert_eq!(
        steps.failed(ReconcileStep::Snapshot),
        StepTransition::Begins
    );
    assert_eq!(
        steps.failed(ReconcileStep::Snapshot),
        StepTransition::Continues
    );
    assert_eq!(
        steps.failed(ReconcileStep::Topology),
        StepTransition::Begins
    );
    assert_eq!(steps.recovered(), Some(ReconcileStep::Topology));
    assert_eq!(steps.recovered(), None);
    assert_eq!(
        steps.failed(ReconcileStep::Topology),
        StepTransition::Begins
    );
}
