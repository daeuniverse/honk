//! Framing classification against devices the kernel really creates: the
//! planner refuses what the programs cannot parse instead of mounting `_l3` on
//! it, and binds point-to-point GRE and `collect_md` GRE as `_l3`.

use super::*;
use crate::ebpf::interface::{RefusedReason, UnboundReason};
use TcProgram::*;

const ARPHRD_NONE: u16 = 0xfffe;

fn link_of<'a>(topology: &'a Topology, name: &str) -> &'a crate::netlink::LinkSnapshot {
    topology
        .links
        .iter()
        .find(|link| link.name == name)
        .unwrap_or_else(|| panic!("{name} missing from {:?}", topology.links))
}

fn unsupported(arphrd: u16) -> UnboundReason {
    UnboundReason::Refused(RefusedReason::UnsupportedType { arphrd })
}

/// Reconciles `lan`/`wan` and asserts the refusal left no TCX link anywhere.
fn assert_refused(lab: &mut Lab, lan: &[&str], wan: &[&str], entry: &str, want: UnboundReason) {
    let baseline = held_bpf_link_count();
    let (plan, topology) = plan_for(lan, wan);
    assert_eq!(plan.unbound, [(entry.to_string(), want)], "{plan:?}");
    assert!(plan.bindings.is_empty(), "{:?}", plan.bindings);
    let round = lab.reconcile(&plan, &topology);
    assert!(round.settled() && round.added.is_empty(), "{round:?}");
    assert!(lab.owned().is_empty());
    for link in &topology.links {
        for direction in [Direction::Ingress, Direction::Egress] {
            assert!(
                chain(link.ifindex.get(), direction).is_empty(),
                "{} {direction:?} carries a TCX link",
                link.name
            );
        }
    }
    assert_eq!(held_bpf_link_count(), baseline);
}

/// Which side of the rule a multicast-remote GRE lands on depends on the
/// kernel's `CONFIG_NET_IPGRE_BROADCAST`, so its verdict follows the reported
/// flags; the other two variants have a fixed verdict.
#[test]
#[ignore = "requires root; run via just test-netns"]
fn gre_binds_l3_only_when_point_to_point() {
    for (name, remote, refused) in [
        ("hbgre0", None, Some(true)),
        ("hbgre1", Some("192.0.2.2"), Some(false)),
        ("hbgrem", Some("224.0.0.9"), None),
    ] {
        private_netns(move || {
            let mut lab = Lab::new();
            let mut args = vec!["link", "add", name, "type", "gre", "local", "192.0.2.1"];
            args.extend(remote.into_iter().flat_map(|remote| ["remote", remote]));
            ip(&args);
            let (plan, topology) = plan_for(&[name], &[]);
            let link = link_of(&topology, name);
            let unsupported_flags = link.flags & libc::IFF_POINTOPOINT as u32 == 0
                || link.flags & libc::IFF_BROADCAST as u32 != 0;
            if let Some(expected) = refused {
                assert_eq!(
                    expected, unsupported_flags,
                    "{name}: flags {:#x}",
                    link.flags
                );
            }
            if unsupported_flags {
                assert_refused(&mut lab, &[name], &[], name, unsupported(link.arphrd));
            } else {
                assert_ne!(link.flags & libc::IFF_POINTOPOINT as u32, 0);
                let round = lab.reconcile(&plan, &topology);
                assert!(round.settled(), "{round:?}");
                let ifindex = link.ifindex.get();
                let owned = lab.owned();
                assert_eq!(owned[&(ifindex, Direction::Ingress)].0, LanIngressL3);
                assert_eq!(owned[&(ifindex, Direction::Egress)].0, LanEgressL3);
                lab.assert_truthful();
            }
        });
    }
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn collect_md_gre_binds_l3() {
    private_netns(|| {
        let mut lab = Lab::new();
        ip(&["link", "add", "hbgrex", "type", "gre", "external"]);
        let (plan, topology) = plan_for(&["hbgrex"], &[]);
        let link = link_of(&topology, "hbgrex");
        assert_eq!(
            link.arphrd, ARPHRD_NONE,
            "collect_md GRE reports ARPHRD_NONE"
        );
        let round = lab.reconcile(&plan, &topology);
        assert!(round.settled(), "{round:?}");
        let ifindex = link.ifindex.get();
        let owned = lab.owned();
        assert_eq!(owned[&(ifindex, Direction::Ingress)].0, LanIngressL3);
        assert_eq!(owned[&(ifindex, Direction::Egress)].0, LanEgressL3);
        lab.assert_truthful();
    });
}
