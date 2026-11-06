use super::*;
use crate::ebpf::test_support::{LinkExt, link, planned};

const NONE: u16 = 0xfffe;
const PPP: u16 = 512;

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn base() -> Vec<LinkSnapshot> {
    vec![link(1, "lo").arphrd(772), link(2, "ens3"), link(3, "eth1")]
}

/// br0 (10) with ports p1 (11) and p2 (12).
fn bridge() -> Vec<LinkSnapshot> {
    vec![
        link(10, "br0").kind("bridge"),
        link(11, "p1").master(10),
        link(12, "p2").master(10),
    ]
}

/// bond0 (20) with members m1 (21) and m2 (22).
fn bond() -> Vec<LinkSnapshot> {
    vec![
        link(20, "bond0").kind("bond"),
        link(21, "m1").master(20),
        link(22, "m2").master(20),
    ]
}

/// br0 (10) with port p1 (11) and port bond0 (20, members m1 21, m2 22).
fn bond_in_bridge() -> Vec<LinkSnapshot> {
    vec![
        link(10, "br0").kind("bridge"),
        link(11, "p1").master(10),
        link(20, "bond0").kind("bond").master(10),
        link(21, "m1").master(20),
        link(22, "m2").master(20),
    ]
}

fn topology(groups: &[Vec<LinkSnapshot>]) -> Topology {
    Topology {
        links: groups.iter().flatten().cloned().collect(),
        default_route: None,
    }
}

fn run(lan: &[&str], wan: &[&str], groups: &[Vec<LinkSnapshot>]) -> InterfacePlan {
    planned(lan, wan, &topology(groups))
}

/// `"<ifindex> in|eg <program>"`, in plan order.
fn set(plan: &InterfacePlan) -> Vec<String> {
    plan.bindings
        .iter()
        .map(|binding| {
            let direction = match binding.direction {
                Direction::Ingress => "in",
                Direction::Egress => "eg",
            };
            format!("{} {direction} {}", binding.ifindex, binding.program.name())
        })
        .collect()
}

/// Every ifindex the entry (as written) derives its bindings from, sorted.
fn bound(plan: &InterfacePlan, entry: &str) -> Vec<NonZeroU32> {
    let (_, derived) = plan
        .bound
        .iter()
        .find(|(name, _)| name == entry)
        .unwrap_or_else(|| panic!("{entry} is not a bound entry in {:?}", plan.bound));
    let mut derived = derived.clone();
    derived.sort_unstable();
    derived
}

fn ids(values: &[u32]) -> Vec<NonZeroU32> {
    values
        .iter()
        .map(|v| NonZeroU32::new(*v).unwrap())
        .collect()
}

#[test]
fn program_names_are_unique_and_cover_all_variants() {
    let mut names: Vec<_> = TcProgram::ALL
        .iter()
        .map(|program| program.name())
        .collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 8);
}

#[test]
fn single_lan() {
    let plan = run(&["ens3"], &[], &[base()]);
    assert_eq!(set(&plan), ["2 in lan_ingress_l2", "2 eg lan_egress_l2"]);
    assert_eq!(plan.lan, ["ens3"]);
    assert!(plan.wan.is_empty() && plan.wan_roots.is_empty() && plan.unbound.is_empty());
    assert_eq!(plan.lan_roots, ["ens3"]);
    assert_eq!(bound(&plan, "ens3"), ids(&[2]));
    assert_eq!(plan.bindings[0].interface, "ens3");
}

#[test]
fn wan_only_synthesizes_no_lan_or_loopback() {
    let plan = run(&[], &["ens3"], &[base()]);
    assert_eq!(set(&plan), ["2 in wan_ingress_l2", "2 eg wan_egress_l2"]);
    assert!(plan.lan_roots.is_empty());
    assert_eq!(
        plan.wan_roots,
        [(NonZeroU32::new(2).unwrap(), "ens3".to_string())]
    );
    assert_eq!(bound(&plan, "ens3"), ids(&[2]));
}

#[test]
fn fully_shared_interface_is_lan_wan() {
    let plan = run(&["ens3"], &["ens3"], &[base()]);
    assert_eq!(set(&plan), ["2 in lan_ingress_l2", "2 eg wan_egress_l2"]);
    assert_eq!(plan.lan_roots, ["ens3"]);
    assert_eq!(
        plan.wan_roots,
        [(NonZeroU32::new(2).unwrap(), "ens3".to_string())]
    );
    assert_eq!(bound(&plan, "ens3"), ids(&[2]));
}

#[test]
fn shared_second_lan_is_lan_wan_and_the_first_stays_lan() {
    // A name in both lists is one entry that binds once.
    let plan = run(&["ens3", "eth1"], &["eth1"], &[base()]);
    assert_eq!(plan.lan_roots, ["ens3", "eth1"]);
    assert_eq!(bound(&plan, "eth1"), ids(&[3]));
    assert_eq!(
        set(&plan),
        [
            "2 in lan_ingress_l2",
            "2 eg lan_egress_l2",
            "3 in lan_ingress_l2",
            "3 eg wan_egress_l2",
        ]
    );
}

#[test]
fn config_order_and_duplicates_do_not_change_bindings() {
    let expected = run(&["ens3", "eth1"], &["ens3"], &[base()]).bindings;
    for (lan, wan) in [
        (&["eth1", "ens3"][..], &["ens3"][..]),
        (&["ens3", "eth1", "ens3"], &["ens3", "ens3"]),
        (&["eth1", "ens3", "eth1"], &["ens3"]),
    ] {
        assert_eq!(
            run(lan, wan, &[base()]).bindings,
            expected,
            "{lan:?} {wan:?}"
        );
    }
    let plan = run(&["ens3", "eth1", "ens3"], &["ens3", "ens3"], &[base()]);
    assert_eq!(plan.lan, ["ens3", "eth1"]);
    assert_eq!(plan.wan, ["ens3"]);
}

#[test]
fn bridge_root_and_port_alias_cover_the_same_links() {
    let expected = [
        "10 in lan_ingress_l2",
        "10 eg lan_egress_l2",
        "11 in lan_ingress_l2",
        "11 eg lan_egress_l2",
        "12 in lan_ingress_l2",
        "12 eg lan_egress_l2",
    ];
    for lan in [&["br0"][..], &["p1"], &["p2", "br0"], &["p1", "p2"]] {
        let plan = run(lan, &[], &[base(), bridge()]);
        assert_eq!(set(&plan), expected, "{lan:?}");
        assert_eq!(plan.lan_roots, ["br0"], "{lan:?}");
        assert_eq!(bound(&plan, lan[0]), ids(&[10, 11, 12]), "{lan:?}");
    }
}

#[test]
fn wan_bridge_root_binds_only_itself() {
    let plan = run(&[], &["br0"], &[bridge()]);
    assert_eq!(set(&plan), ["10 in wan_ingress_l2", "10 eg wan_egress_l2"]);
    assert_eq!(bound(&plan, "br0"), ids(&[10]));
}

#[test]
fn bond_root_binds_only_itself_whatever_alias_names_it() {
    let lan_expected = ["20 in lan_ingress_l2", "20 eg lan_egress_l2"];
    for lan in [&["bond0"][..], &["m1"], &["m1", "bond0", "m2"]] {
        let plan = run(lan, &[], &[bond()]);
        assert_eq!(set(&plan), lan_expected, "{lan:?}");
        assert_eq!(plan.lan_roots, ["bond0"], "{lan:?}");
        assert_eq!(bound(&plan, lan[0]), ids(&[20]), "{lan:?}");
    }
    let wan_expected = ["20 in wan_ingress_l2", "20 eg wan_egress_l2"];
    for wan in [&["bond0"][..], &["m2", "bond0"]] {
        let plan = run(&[], wan, &[bond()]);
        assert_eq!(set(&plan), wan_expected, "{wan:?}");
        assert_eq!(
            plan.wan_roots,
            [(NonZeroU32::new(20).unwrap(), "bond0".to_string())]
        );
    }
    // Shared LAN/WAN through a member name and the master: one LanWan root.
    let plan = run(&["m1"], &["bond0"], &[bond()]);
    assert_eq!(set(&plan), ["20 in lan_ingress_l2", "20 eg wan_egress_l2"]);
}

#[test]
fn lan_bridge_with_wan_bond_port_upgrades_only_the_bridge() {
    let expected = [
        "10 in lan_ingress_l2",
        "10 eg wan_egress_l2",
        "11 in lan_ingress_l2",
        "11 eg lan_egress_l2",
        "20 in lan_ingress_l2",
        "20 eg lan_egress_l2",
    ];
    // WAN names the bond port or one of its physical members: same plan, no members bound.
    for wan in ["bond0", "m1", "br0"] {
        let plan = run(&["br0"], &[wan], &[bond_in_bridge()]);
        assert_eq!(set(&plan), expected, "{wan}");
        assert_eq!(plan.lan_roots, ["br0"]);
        assert_eq!(
            plan.wan_roots,
            [(NonZeroU32::new(10).unwrap(), "br0".to_string())]
        );
    }
    let plan = run(&["br0"], &["bond0"], &[bond_in_bridge()]);
    assert_eq!(bound(&plan, "br0"), ids(&[10, 11, 20]));
    assert_eq!(bound(&plan, "bond0"), ids(&[10, 11, 20]));
}

#[test]
fn bond_in_bridge_member_and_port_alias_resolve_to_the_bridge() {
    let reference = run(&["br0"], &[], &[bond_in_bridge()]).bindings;
    for lan in ["bond0", "m1", "m2", "p1"] {
        assert_eq!(
            run(&[lan], &[], &[bond_in_bridge()]).bindings,
            reference,
            "{lan}"
        );
    }
}

#[test]
fn explicit_vlan_keeps_its_own_boundary() {
    let links = vec![link(4, "eth0"), link(5, "eth0.100").kind("vlan")];
    let plan = run(&["eth0.100"], &[], &[links]);
    assert_eq!(set(&plan), ["5 in lan_ingress_l2", "5 eg lan_egress_l2"]);
    assert_eq!(plan.lan_roots, ["eth0.100"]);
}

#[test]
fn vrf_member_is_not_promoted() {
    let links = vec![link(30, "vrf0").kind("vrf"), link(31, "eth2").master(30)];
    let plan = run(&["eth2"], &[], &[links]);
    assert_eq!(set(&plan), ["31 in lan_ingress_l2", "31 eg lan_egress_l2"]);
    assert_eq!(plan.lan_roots, ["eth2"]);

    let links = vec![
        link(32, "ovs-system").kind("openvswitch"),
        link(33, "eth3").master(32),
    ];
    let plan = run(&[], &["eth3"], &[links]);
    assert_eq!(set(&plan), ["33 in wan_ingress_l2", "33 eg wan_egress_l2"]);
}

#[test]
fn team_member_is_promoted_without_member_expansion() {
    let links = vec![
        link(40, "team0").kind("team"),
        link(41, "eth3").master(40),
        link(42, "eth4").master(40),
    ];
    let plan = run(&["eth3"], &[], &[links]);
    assert_eq!(set(&plan), ["40 in lan_ingress_l2", "40 eg lan_egress_l2"]);
    assert_eq!(plan.lan_roots, ["team0"]);
    // The configured name stays the resolved name; only the root is bound.
    assert_eq!(plan.lan, ["eth3"]);
}

#[test]
fn master_without_kind_is_promoted() {
    let links = vec![link(40, "m0"), link(41, "eth3").master(40)];
    let plan = run(&["eth3"], &[], &[links]);
    assert_eq!(set(&plan), ["40 in lan_ingress_l2", "40 eg lan_egress_l2"]);
}

#[test]
fn l3_devices_use_l3_programs_per_device() {
    let links = vec![link(50, "wg0").arphrd(NONE), link(51, "ppp0").arphrd(PPP)];
    let plan = run(&["wg0"], &["ppp0"], &[links]);
    assert_eq!(
        set(&plan),
        [
            "50 in lan_ingress_l3",
            "50 eg lan_egress_l3",
            "51 in wan_ingress_l3",
            "51 eg wan_egress_l3",
        ]
    );

    // Ports classify by their own ARPHRD, not the root's.
    let mut links = bridge();
    links.push(link(13, "p3").master(10).arphrd(NONE));
    let plan = run(&["br0"], &[], &[links]);
    assert!(set(&plan).contains(&"13 in lan_ingress_l3".to_string()));
    assert!(set(&plan).contains(&"13 eg lan_egress_l3".to_string()));
    assert!(set(&plan).contains(&"12 eg lan_egress_l2".to_string()));
}

#[test]
fn unresolved_auto_is_pending_without_dropping_explicit_entries() {
    for auto in ["auto", "AUTO", " auto ", ""] {
        let plan = run(&[auto, "eth1"], &[auto], &[base()]);
        assert_eq!(plan.lan, ["eth1"], "{auto:?}");
        assert!(plan.wan.is_empty() && plan.wan_roots.is_empty(), "{auto:?}");
        assert_eq!(
            plan.unbound,
            [(auto.to_string(), UnboundReason::AutoUnresolved)],
            "{auto:?}"
        );
        assert_eq!(set(&plan), ["3 in lan_ingress_l2", "3 eg lan_egress_l2"]);
        assert_eq!(bound(&plan, "eth1"), ids(&[3]));
    }
}

#[test]
fn resolved_auto_follows_default_route_and_dedups() {
    let mut topo = topology(&[base()]);
    topo.default_route = Some("ens3".into());
    let plan = plan(
        &strings(&["auto", "ens3", "eth1"]),
        &strings(&[" Auto "]),
        &topo,
    );
    assert_eq!(plan.lan, ["ens3", "eth1"]);
    assert_eq!(plan.wan, ["ens3"]);
    assert!(plan.unbound.is_empty());
    assert_eq!(
        set(&plan),
        [
            "2 in lan_ingress_l2",
            "2 eg wan_egress_l2",
            "3 in lan_ingress_l2",
            "3 eg lan_egress_l2",
        ]
    );

    // Resolved to a link that is gone: reported under the entry as written.
    topo.default_route = Some("gone0".into());
    let plan = planned(&["auto"], &[], &topo);
    assert_eq!(plan.lan, ["gone0"]);
    assert_eq!(plan.unbound, [("auto".to_string(), UnboundReason::Absent)]);
}

#[test]
fn absent_names_are_unbound_and_not_bound_entries() {
    let plan = run(&["nope", "ens3"], &["eth1"], &[base()]);
    assert_eq!(plan.unbound, [("nope".to_string(), UnboundReason::Absent)]);
    assert_eq!(plan.lan, ["nope", "ens3"]);
    assert_eq!(plan.bound.len(), 2, "{:?}", plan.bound);
    assert_eq!(bound(&plan, "ens3"), ids(&[2]));
    assert_eq!(plan.lan_roots, ["ens3"]);

    // A name in both lists is one absent entry, reported once.
    let plan = run(&["nope"], &["nope"], &[base()]);
    assert_eq!(plan.unbound, [("nope".to_string(), UnboundReason::Absent)]);
    assert!(plan.bindings.is_empty() && plan.bound.is_empty());
}

#[test]
fn bound_entries_cover_roots_and_bridge_ports() {
    let plan = run(&["br0", "ens3"], &["eth1"], &[base(), bridge()]);
    assert_eq!(bound(&plan, "br0"), ids(&[10, 11, 12]));
    assert_eq!(bound(&plan, "ens3"), ids(&[2]));
    assert_eq!(bound(&plan, "eth1"), ids(&[3]));
    let plan = run(&["ens3"], &["bond0", "eth1"], &[base(), bond()]);
    assert_eq!(bound(&plan, "bond0"), ids(&[20]));
}
#[test]
fn unsupported_nesting_refuses_only_the_affected_entry() {
    // bridge enslaved to a bond, bond enslaved to a bridge: loop.
    let looped = vec![
        link(10, "br0").kind("bridge").master(20),
        link(20, "bond0").kind("bond").master(10),
        link(21, "m1").master(20),
    ];
    for name in ["br0", "bond0", "m1"] {
        let plan = plan(
            &strings(&[name]),
            &[],
            &topology(std::slice::from_ref(&looped)),
        );
        assert_eq!(
            plan.unbound,
            [(
                name.into(),
                UnboundReason::Refused(RefusedReason::UnsupportedNesting)
            )],
            "{name}"
        );
        assert!(plan.bindings.is_empty());
    }
    // bridge under bridge, bond under bond, three levels, own master.
    let cases: Vec<Vec<LinkSnapshot>> = vec![
        vec![
            link(1, "a").kind("bridge"),
            link(2, "b").kind("bridge").master(1),
            link(3, "c").master(2),
        ],
        vec![
            link(1, "a").kind("bond"),
            link(2, "b").kind("bond").master(1),
            link(3, "c").master(2),
        ],
        vec![
            link(1, "a").kind("bridge").master(4),
            link(2, "b").kind("bond").master(1),
            link(4, "x").kind("bridge"),
            link(3, "c").master(2),
        ],
        vec![
            link(1, "a").kind("bridge").master(1),
            link(2, "c").master(1),
        ],
    ];
    for (index, links) in cases.iter().enumerate() {
        let result = plan(
            &strings(&["c"]),
            &[],
            &topology(std::slice::from_ref(links)),
        );
        assert_eq!(
            result.unbound,
            [(
                "c".into(),
                UnboundReason::Refused(RefusedReason::UnsupportedNesting)
            )],
            "case {index}"
        );
        assert!(result.bindings.is_empty());
    }
    let plan = plan(&strings(&["ens3", "m1"]), &[], &topology(&[base(), looped]));
    assert_eq!(set(&plan), ["2 in lan_ingress_l2", "2 eg lan_egress_l2"]);
    assert_eq!(
        plan.unbound,
        [(
            "m1".into(),
            UnboundReason::Refused(RefusedReason::UnsupportedNesting)
        )]
    );
}

#[test]
fn bond_or_bridge_under_other_master_stays_the_root() {
    let links = vec![
        link(30, "vrf0").kind("vrf"),
        link(10, "br0").kind("bridge").master(30),
        link(11, "p1").master(10),
    ];
    let plan = run(&["p1"], &[], &[links]);
    assert_eq!(plan.lan_roots, ["br0"]);
    assert_eq!(bound(&plan, "p1"), ids(&[10, 11]));
}

#[test]
fn local_ip_interface_is_the_canonical_root_the_binding_uses() {
    let topo = topology(&[base(), bridge()]);
    // A port binds its bridge: the address is the bridge's.
    let plan = planned(&["nope", "p1"], &["ens3"], &topo);
    assert_eq!(local_ip_interface(&plan), Some("br0"));

    let plan = planned(&[], &["eth1", "ens3"], &topo);
    assert_eq!(local_ip_interface(&plan), Some("eth1"));

    let plan = planned(&["nope"], &["ens3"], &topo);
    assert_eq!(local_ip_interface(&plan), Some("ens3"));

    // A vrf member binds itself, so its own address is used, not the vrf's.
    let vrf = topology(&[vec![
        link(30, "vrf0").kind("vrf"),
        link(31, "eth2").master(30),
    ]]);
    let plan = planned(&["eth2"], &[], &vrf);
    assert_eq!(local_ip_interface(&plan), Some("eth2"));

    // A bond that is a bridge port resolves to the bridge, member or not.
    let nested = topology(&[bond_in_bridge()]);
    for lan in ["m1", "bond0", "p1"] {
        let plan = planned(&[lan], &[], &nested);
        assert_eq!(local_ip_interface(&plan), Some("br0"), "{lan}");
    }

    // Unresolved auto and nothing configured: none.
    let plan = planned(&["auto"], &[], &topo);
    assert_eq!(local_ip_interface(&plan), None);
    assert_eq!(local_ip(&plan), 0);
    let plan = planned(&[], &[], &topo);
    assert_eq!(local_ip_interface(&plan), None);
}

#[test]
fn default_route_read_error_is_an_error_not_no_route() {
    let error = default_route(Err(io::Error::from_raw_os_error(libc::EIO))).unwrap_err();
    assert!(format!("{error:#}").contains("/proc/net/route"));
    let header =
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n";
    let route = format!("{header}eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n");
    assert_eq!(default_route(Ok(route)).unwrap().as_deref(), Some("eth0"));
    assert_eq!(default_route(Ok(header.into())).unwrap(), None);
}

#[test]
fn dump_retry_stops_at_the_attempt_limit() {
    let interrupted = || io::Error::from(io::ErrorKind::Interrupted);
    let mut calls = 0;
    let ok = retry_interrupted(|| {
        calls += 1;
        if calls < DUMP_ATTEMPTS {
            Err(interrupted())
        } else {
            Ok(calls)
        }
    });
    assert_eq!(ok.unwrap(), DUMP_ATTEMPTS);

    let mut calls = 0;
    let err = retry_interrupted(|| -> io::Result<()> {
        calls += 1;
        Err(interrupted())
    })
    .unwrap_err();
    assert_eq!(
        (calls, err.kind()),
        (DUMP_ATTEMPTS, io::ErrorKind::Interrupted)
    );

    let mut calls = 0;
    let err = retry_interrupted(|| -> io::Result<()> {
        calls += 1;
        Err(io::Error::from(io::ErrorKind::InvalidData))
    })
    .unwrap_err();
    assert_eq!((calls, err.kind()), (1, io::ErrorKind::InvalidData));
}

const LOOPBACK: u16 = 772;
const IPGRE: u16 = 778;
const IP6GRE: u16 = 823;
const P2P: u32 = libc::IFF_POINTOPOINT as u32;
const BROADCAST: u32 = libc::IFF_BROADCAST as u32;

#[test]
fn framing_table() {
    use Framing::*;
    for (arphrd, flags, want) in [
        (1, 0, L2),
        (0xfffe, 0, L3),
        (512, 0, L3),
        (519, 0, L3),
        (768, 0, L3),
        (769, 0, L3),
        (776, 0, L3),
        (IPGRE, P2P, L3),
        (IP6GRE, P2P, L3),
        (IPGRE, P2P | BROADCAST, Unsupported),
        (IP6GRE, P2P | BROADCAST, Unsupported),
        (IPGRE, 0, Unsupported),
        (IP6GRE, BROADCAST, Unsupported),
        (LOOPBACK, 0, Unsupported),
        (32, 0, Unsupported),
        (280, 0, Unsupported),
        (803, 0, Unsupported),
        (804, 0, Unsupported),
        (824, 0, Unsupported),
        (825, 0, Unsupported),
        (0xffff, 0, Unsupported),
        (778 + 1, 0, Unsupported),
    ] {
        assert_eq!(Framing::of(arphrd, flags), want, "{arphrd} {flags:#x}");
    }
    // Ethernet framing never depends on flags.
    assert_eq!(Framing::of(1, P2P | BROADCAST), L2);
}

fn refused(arphrd: u16) -> UnboundReason {
    UnboundReason::Refused(RefusedReason::UnsupportedType { arphrd })
}

#[test]
fn unsupported_roots_are_refused_per_entry_and_bind_nothing() {
    let links = vec![
        link(1, "lo").arphrd(LOOPBACK).flags(P2P),
        link(2, "ib0").arphrd(32),
        link(3, "vcan0").arphrd(280),
        link(4, "gre1").arphrd(IPGRE).flags(P2P | BROADCAST),
        link(5, "gre2").arphrd(IPGRE),
        link(6, "ens3"),
    ];
    let plan = run(&["ens3", "lo", "ib0", "gre1"], &["vcan0", "gre2"], &[links]);
    assert_eq!(set(&plan), ["6 in lan_ingress_l2", "6 eg lan_egress_l2"]);
    assert_eq!(
        plan.unbound,
        [
            ("lo".to_string(), refused(LOOPBACK)),
            ("ib0".to_string(), refused(32)),
            ("gre1".to_string(), refused(IPGRE)),
            ("vcan0".to_string(), refused(280)),
            ("gre2".to_string(), refused(IPGRE)),
        ]
    );
    // Refused entries derive nothing; the bindable entry does.
    assert_eq!(bound(&plan, "ens3"), ids(&[6]));
    assert_eq!(plan.lan_roots, ["ens3"]);
    assert!(plan.wan_roots.is_empty());
}

#[test]
fn vrf_root_is_refused_while_its_member_binds_itself() {
    let links = vec![link(30, "vrf0").kind("vrf"), link(31, "m1").master(30)];
    let plan = run(&["vrf0"], &["m1"], std::slice::from_ref(&links));
    assert_eq!(
        plan.unbound,
        [(
            "vrf0".to_string(),
            UnboundReason::Refused(RefusedReason::VrfRoot)
        )]
    );
    assert_eq!(set(&plan), ["31 in wan_ingress_l2", "31 eg wan_egress_l2"]);
    assert_eq!(
        plan.wan_roots,
        [(NonZeroU32::new(31).unwrap(), "m1".to_string())]
    );
    // The member alone is fine.
    let plan = run(&["m1"], &[], &[links]);
    assert!(plan.unbound.is_empty());
}

#[test]
fn honk_owned_links_are_refused_even_when_absent() {
    let links = vec![link(40, "dae0")];
    let plan = run(&["dae0", "dae0peer"], &[], &[base(), links]);
    assert!(plan.bindings.is_empty());
    assert_eq!(
        plan.unbound,
        [
            (
                "dae0".to_string(),
                UnboundReason::Refused(RefusedReason::OwnedLink)
            ),
            (
                "dae0peer".to_string(),
                UnboundReason::Refused(RefusedReason::OwnedLink)
            ),
        ]
    );
}

#[test]
fn non_ethernet_bond_root_is_refused() {
    // An INFINIBAND bond is refused as a root; its members are never bound.
    let links = vec![
        link(20, "bond0").kind("bond").arphrd(32),
        link(21, "m1").master(20).arphrd(32),
    ];
    for entry in ["bond0", "m1"] {
        let plan = run(&[entry], &[], std::slice::from_ref(&links));
        assert!(plan.bindings.is_empty(), "{entry}");
        assert_eq!(plan.unbound, [(entry.to_string(), refused(32))], "{entry}");
    }
}

#[test]
fn unsupported_bridge_ports_are_skipped_silently() {
    let mut links = bridge();
    links.push(link(13, "p3").master(10).arphrd(32));
    let plan = run(&["br0"], &[], &[links]);
    assert!(plan.unbound.is_empty());
    assert!(set(&plan).iter().all(|b| !b.starts_with("13 ")));
    assert!(set(&plan).contains(&"11 in lan_ingress_l2".to_string()));
}
#[test]
fn local_ip_interface_never_names_a_refused_root() {
    let vrf = vec![link(30, "vrf0").kind("vrf"), link(31, "m1").master(30)];
    let topo = topology(&[base(), vrf]);
    // `lo`, a vrf root and `dae0` are refused: the first bindable root wins.
    let plan = planned(&["lo", "vrf0", "dae0", "ens3"], &[], &topo);
    assert_eq!(local_ip_interface(&plan), Some("ens3"));
    // Refused LAN entries leave the WAN root as the source address.
    let plan = planned(&["lo"], &["eth1"], &topo);
    assert_eq!(local_ip_interface(&plan), Some("eth1"));
    // Nothing bindable: no address, never `lo`'s.
    let plan = planned(&["lo", "vrf0"], &[], &topo);
    assert_eq!(local_ip_interface(&plan), None);
    assert_eq!(local_ip(&plan), 0);
}

#[test]
fn commit_replaces_existing_add_and_ignores_missing_removals() {
    use std::os::fd::AsRawFd;

    use Direction::{Egress, Ingress};
    use TcProgram::{LanEgressL2, LanIngressL2, WanEgressL2, WanIngressL3};

    let binding = |index, direction, program| Binding {
        ifindex: NonZeroU32::new(index).unwrap(),
        direction,
        program,
        interface: format!("v{index}"),
    };
    let fd = || -> OwnedFd { std::fs::File::open("/dev/null").unwrap().into() };

    let old = binding(2, Ingress, LanIngressL2);
    let other = binding(3, Egress, LanEgressL2);
    let mut owned = vec![(old.clone(), 10, fd()), (other.clone(), 11, fd())];
    let first_fd = owned[0].2.as_raw_fd();
    let updated = binding(2, Ingress, WanIngressL3);
    let commit = BindingCommit {
        add: vec![(updated.clone(), 12, fd())],
        remove: vec![(NonZeroU32::new(99).unwrap(), Egress)],
        reprogram: vec![(other.ifindex, other.direction, WanEgressL2)],
        rename: vec![
            (other.ifindex, other.direction, "p9".into()),
            (NonZeroU32::new(99).unwrap(), Egress, "gone".into()),
        ],
    };
    assert_eq!(
        commit.keys_after(&[old.key(), other.key()]),
        [old.key(), other.key()]
    );
    let closed = commit.apply_to(&mut owned);
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].as_raw_fd(), first_fd);
    assert_eq!(owned.len(), 2);
    assert_eq!(owned[0].0, updated);
    assert_eq!(owned[0].1, 12);
    assert_eq!(owned[1].0.program, WanEgressL2);
    assert_eq!(owned[1].0.interface, "p9");
    assert_eq!(owned[1].1, 11, "a rename keeps the link");

    let commit = BindingCommit {
        remove: vec![updated.key()],
        ..BindingCommit::default()
    };
    assert_eq!(
        commit.keys_after(&[updated.key(), other.key()]),
        [other.key()]
    );
    assert_eq!(commit.apply_to(&mut owned).len(), 1);
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].0.key(), other.key());
    assert!(BindingCommit::default().is_empty());
}
