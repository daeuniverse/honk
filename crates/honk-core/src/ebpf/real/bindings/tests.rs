use super::*;
use crate::ebpf::interface::Direction::{Egress, Ingress};
use crate::ebpf::interface::TcProgram::{LanEgressL2, LanIngressL2, WanEgressL2, WanIngressL3};

fn binding(index: u32, direction: Direction, program: TcProgram) -> Binding {
    Binding {
        ifindex: NonZeroU32::new(index).unwrap(),
        direction,
        program,
        interface: format!("v{index}"),
    }
}

fn held(binding: &Binding, link_id: u32) -> Held {
    Held {
        key: binding.key(),
        program: binding.program,
        link_id,
        interface: binding.interface.clone(),
    }
}

#[test]
fn diff_keeps_unchanged_keys_and_only_checks_when_verifying() {
    let wanted = [
        binding(2, Ingress, LanIngressL2),
        binding(2, Egress, LanEgressL2),
    ];
    let held = [held(&wanted[0], 10), held(&wanted[1], 11)];
    assert!(diff(&held, &wanted, false).is_empty());
    assert_eq!(
        diff(&held, &wanted, true),
        [
            Step::Check {
                binding: &wanted[0],
                link_id: 10
            },
            Step::Check {
                binding: &wanted[1],
                link_id: 11
            },
        ]
    );
    let chain = Chain {
        links: vec![10, 20, 0],
    };
    assert!(chain.contains_link(10));
    assert!(!chain.contains_link(30));
    assert!(
        !chain.contains_link(0),
        "legacy attachment is not an owned link"
    );
    // A diagnostic name is not the resource key: no relink, and no Check
    // unless verifying, but the new name is reported.
    let mut renamed = wanted.clone();
    renamed[0].interface = "renamed".into();
    assert_eq!(diff(&held, &renamed, false), [Step::Rename(&renamed[0])]);
    assert_eq!(
        diff(&held, &renamed, true),
        [
            Step::Rename(&renamed[0]),
            Step::Check {
                binding: &renamed[0],
                link_id: 10
            },
            Step::Check {
                binding: &renamed[1],
                link_id: 11
            },
        ]
    );
}

#[test]
fn diff_reprograms_instead_of_stacking_and_removes_only_absent_keys() {
    let old = [
        binding(2, Ingress, LanIngressL2),
        binding(2, Egress, LanEgressL2),
        binding(3, Egress, WanEgressL2),
    ];
    let held = [held(&old[0], 10), held(&old[1], 11), held(&old[2], 12)];
    let wanted = [
        binding(2, Ingress, WanIngressL3),
        binding(2, Egress, WanEgressL2),
        binding(4, Ingress, LanIngressL2),
    ];
    assert_eq!(
        diff(&held, &wanted, false),
        [
            Step::Remove(old[2].key()),
            Step::Reprogram {
                to: &wanted[0],
                from: LanIngressL2,
                link_id: 10
            },
            Step::Reprogram {
                to: &wanted[1],
                from: LanEgressL2,
                link_id: 11
            },
            Step::Create(&wanted[2]),
        ]
    );
}

#[test]
fn target_comparison_rejects_name_framing_master_and_kind_changes_only() {
    let old = LinkSnapshot {
        ifindex: NonZeroU32::new(2).unwrap(),
        name: "v2".into(),
        arphrd: 1,
        flags: 0,
        master: None,
        kind: Some("veth".into()),
        mac: None,
    };
    let mut after = old.clone();
    after.flags = u32::MAX;
    after.mac = Some([2; 6]);
    assert!(same_device(&old, &after));
    for changed in [
        LinkSnapshot {
            name: "new".into(),
            ..old.clone()
        },
        LinkSnapshot {
            arphrd: 512,
            ..old.clone()
        },
        LinkSnapshot {
            master: NonZeroU32::new(3),
            ..old.clone()
        },
        LinkSnapshot {
            kind: None,
            ..old.clone()
        },
    ] {
        assert!(!same_device(&old, &changed));
    }
}

#[test]
fn only_a_vanished_device_is_not_an_attach_failure() {
    let gone = anyhow::Error::from(io::Error::from_raw_os_error(libc::ENODEV))
        .context("attach lan_ingress_l2 to eth0");
    assert!(device_gone(&gone));
    let full = anyhow::Error::from(io::Error::from_raw_os_error(libc::ERANGE))
        .context("attach lan_ingress_l2 to eth0");
    assert!(!device_gone(&full));
    assert!(!device_gone(&anyhow::anyhow!(
        "TC program is not preloaded"
    )));
}
