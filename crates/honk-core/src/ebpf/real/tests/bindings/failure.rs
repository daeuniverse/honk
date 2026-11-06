//! Failure boundaries of `apply`: a rejected update, a device that vanishes
//! between planning and applying, and a device renamed under a fresh link. Each
//! asserts what the kernel holds afterwards, not just what was reported.

use super::*;
use TcProgram::*;

/// The program the kernel says an owned link runs.
fn kernel_program(lab: &Lab, ifindex: u32, direction: Direction) -> u32 {
    let held = lab.held();
    let held = held
        .iter()
        .find(|h| (h.binding.ifindex.get(), h.binding.direction) == (ifindex, direction))
        .expect("owned binding");
    owner::link_info(held.link.as_raw_fd()).unwrap().program_id
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn rejected_update_keeps_old_link_and_commits_the_healthy_direction() {
    private_netns(|| {
        let mut lab = Lab::new();
        let ifindex = lab.veth("hbt_a", "hbt_ap");
        let foreign = foreign_link(ifindex, Direction::Ingress).unwrap();
        let round = lab.round(&["hbt_a"], &[]);
        assert!(round.settled(), "{round:?}");
        let key_in = (ifindex, Direction::Ingress);
        let key_out = (ifindex, Direction::Egress);
        let ids = (lab.owned()[&key_in].1, lab.owned()[&key_out].1);
        let baseline = held_bpf_link_count();

        // The snapshot's "old" ingress program FD is really WanIngressL2, so
        // BPF_LINK_UPDATE with BPF_F_REPLACE finds a mismatch on that link only.
        let (plan, topology) = plan_for(&[], &["hbt_a"]);
        let mut snapshot = lab.snapshot();
        let wan = snapshot
            .programs
            .iter()
            .find(|(program, _)| *program == WanIngressL2)
            .unwrap()
            .1
            .try_clone()
            .unwrap();
        snapshot
            .programs
            .iter_mut()
            .find(|(program, _)| *program == LanIngressL2)
            .unwrap()
            .1 = wan;

        let round = lab.reconcile_with(snapshot, &plan, &topology);
        assert!(!round.topology_changed, "{round:?}");
        assert_eq!(round.failed.len(), 1, "{round:?}");
        assert_eq!(round.failed[0].0.direction, Direction::Ingress);
        assert!(round.added.is_empty() && round.removed.is_empty() && round.closed == 0);
        assert_eq!(
            round.reprogrammed,
            [(ifindex, Direction::Egress, WanEgressL2)]
        );

        let owned = lab.owned();
        assert_eq!(
            owned[&key_in],
            (LanIngressL2, ids.0),
            "old ingress owner kept"
        );
        assert_eq!(
            owned[&key_out],
            (WanEgressL2, ids.1),
            "healthy egress committed"
        );
        assert_eq!(
            kernel_program(&lab, ifindex, Direction::Ingress),
            lab.program_id(LanIngressL2),
            "kernel ingress link still runs the old program"
        );
        assert_eq!(
            kernel_program(&lab, ifindex, Direction::Egress),
            lab.program_id(WanEgressL2)
        );
        assert_eq!(chain(ifindex, Direction::Ingress), [foreign.id, ids.0]);
        assert_eq!(chain(ifindex, Direction::Egress), [ids.1]);
        assert_eq!(held_bpf_link_count(), baseline);
        lab.assert_truthful();

        // Retry with the real snapshot: only ingress changes, nothing stacks.
        let round = lab.reconcile(&plan, &topology);
        assert!(round.settled(), "{round:?}");
        assert!(round.added.is_empty() && round.removed.is_empty() && round.closed == 0);
        assert_eq!(
            round.reprogrammed,
            [(ifindex, Direction::Ingress, WanIngressL2)]
        );
        let owned = lab.owned();
        assert_eq!(owned[&key_in], (WanIngressL2, ids.0));
        assert_eq!(owned[&key_out], (WanEgressL2, ids.1));
        assert_eq!(chain(ifindex, Direction::Ingress), [foreign.id, ids.0]);
        assert_eq!(chain(ifindex, Direction::Egress), [ids.1]);
        assert_eq!(held_bpf_link_count(), baseline);
        lab.assert_truthful();
        let round = lab.reconcile(&plan, &topology);
        assert!(round.unchanged(), "{round:?}");
    });
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn device_deleted_before_verified_apply_reports_failure_without_recreating() {
    private_netns(|| {
        let mut lab = Lab::new();
        let ifindex = lab.veth("hbx_a", "hbx_ap");
        let baseline = held_bpf_link_count();
        let round = lab.round(&["hbx_a"], &[]);
        assert!(round.settled() && round.added.len() == 2, "{round:?}");
        let owned = lab.owned();
        assert_eq!(held_bpf_link_count(), baseline + 2);

        // Plan and snapshot are taken while the device exists; it is gone by apply.
        let (plan, topology) = plan_for(&["hbx_a"], &[]);
        let snapshot = lab.snapshot();
        lab.netlink.del_link(ifindex).unwrap();
        let round = lab.reconcile_with(snapshot, &plan, &topology);

        assert_eq!(round.failed.len(), 2, "{round:?}");
        for (binding, error) in &round.failed {
            assert!(
                has_errno(error, libc::ENODEV),
                "{:?}: query must fail with ENODEV, got {error:#}",
                binding.direction
            );
        }
        assert!(
            round.added.is_empty() && round.removed.is_empty() && round.reprogrammed.is_empty(),
            "a failed query must not recreate or forget: {round:?}"
        );
        assert!(!round.topology_changed && round.closed == 0, "{round:?}");
        assert_eq!(lab.owned(), owned, "owner keeps its FDs and ids");
        assert_eq!(held_bpf_link_count(), baseline + 2);
    });
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn rename_after_planning_is_not_confirmed_and_update_rolls_back() {
    private_netns(|| {
        let mut lab = Lab::new();
        let ifindex = lab.veth("hbi_a", "hbi_ap");
        let baseline = held_bpf_link_count();

        // Create: the plan names the device before the rename, the kernel link
        // lands on the (renamed) index, and the identity check refuses it.
        let (plan, topology) = plan_for(&["hbi_a"], &[]);
        ip(&["link", "set", "hbi_a", "name", "hbi_x"]);
        let round = lab.reconcile(&plan, &topology);
        assert!(round.topology_changed, "{round:?}");
        assert!(round.failed.is_empty(), "{round:?}");
        assert!(
            round.added.is_empty() && round.removed.is_empty() && round.reprogrammed.is_empty()
        );
        assert!(lab.owned().is_empty(), "no owner for an unconfirmed link");
        assert!(chain(ifindex, Direction::Ingress).is_empty());
        assert!(chain(ifindex, Direction::Egress).is_empty());
        assert_eq!(
            held_bpf_link_count(),
            baseline,
            "unconfirmed FDs are closed"
        );

        // Bind the device under its new name as LAN, then plan WAN and rename it
        // again before applying: the update is confirmed against the new name.
        let round = lab.round(&["hbi_x"], &[]);
        assert!(round.settled() && round.added.len() == 2, "{round:?}");
        let key_in = (ifindex, Direction::Ingress);
        let key_out = (ifindex, Direction::Egress);
        let owned = lab.owned();
        assert_eq!(owned[&key_in].0, LanIngressL2);
        assert_eq!(owned[&key_out].0, LanEgressL2);
        let (plan, topology) = plan_for(&[], &["hbi_x"]);
        ip(&["link", "set", "hbi_x", "name", "hbi_y"]);
        let round = lab.reconcile(&plan, &topology);

        assert!(round.topology_changed, "{round:?}");
        assert!(round.failed.is_empty(), "rollback succeeded: {round:?}");
        assert!(
            round.added.is_empty() && round.removed.is_empty() && round.closed == 0,
            "{round:?}"
        );
        assert!(
            round.reprogrammed.is_empty(),
            "no reprogram commit: {round:?}"
        );
        assert_eq!(lab.owned(), owned, "old program and link ids kept");
        assert_eq!(
            kernel_program(&lab, ifindex, Direction::Ingress),
            lab.program_id(LanIngressL2),
            "ingress program rolled back"
        );
        assert_eq!(
            kernel_program(&lab, ifindex, Direction::Egress),
            lab.program_id(LanEgressL2),
            "egress program rolled back"
        );
        assert_eq!(chain(ifindex, Direction::Ingress), [owned[&key_in].1]);
        assert_eq!(chain(ifindex, Direction::Egress), [owned[&key_out].1]);
        assert_eq!(held_bpf_link_count(), baseline + 2);
        lab.assert_truthful();

        // With a topology that matches the device, the update goes through.
        let round = lab.round(&["hbi_y"], &[]);
        assert!(round.unchanged(), "{round:?}");
        let round = lab.round(&[], &["hbi_y"]);
        assert!(
            round.settled() && round.reprogrammed.len() == 2,
            "{round:?}"
        );
        assert_eq!(lab.owned()[&key_in], (WanIngressL2, owned[&key_in].1));
        lab.assert_truthful();
    });
}

/// The device is deleted between the dump and the attach: `-ENODEV` says the
/// topology moved, not that the attach failed, so nothing is reported failed
/// and the owner binds nothing.
#[test]
#[ignore = "requires root; run via just test-netns"]
fn device_deleted_before_attach_is_a_topology_change_not_an_attach_failure() {
    private_netns(|| {
        let mut lab = Lab::new();
        let ifindex = lab.veth("hbt_gone", "hbt_gonep");
        let (plan, topology) = plan_for(&["hbt_gone"], &[]);
        assert_eq!(plan.bindings.len(), 2);
        lab.netlink.del_link(ifindex).unwrap();

        let round = lab.reconcile(&plan, &topology);
        assert!(round.failed.is_empty(), "{round:?}");
        assert!(round.topology_changed, "{round:?}");
        assert!(round.added.is_empty() && lab.owned().is_empty());
    });
}
