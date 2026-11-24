use super::super::tests::{attribute, capture_notification};
use super::*;

fn link_body(index: u32, mtu: u32, up: bool, arphrd: u16, name: &[u8]) -> Vec<u8> {
    let mut body = vec![0; 16];
    body[2..4].copy_from_slice(&arphrd.to_ne_bytes());
    body[4..8].copy_from_slice(&index.to_ne_bytes());
    body[8..12].copy_from_slice(&u32::from(up).to_ne_bytes());
    attribute(&mut body, 3, name);
    attribute(&mut body, 4, &mtu.to_ne_bytes());
    body
}

fn route_body(family: u8, prefix: u8) -> Vec<u8> {
    let mut body = vec![0; 12];
    body[0] = family;
    body[1] = prefix;
    body[4] = 219;
    body[7] = 1;
    body
}

const ACTIVE: AuxLinkInfo = AuxLinkInfo {
    ifindex: 7,
    mtu: 1420,
    is_l2: false,
    local_mac: [0; 6],
    up: true,
};

#[test]
fn absence_and_valid_down_differ_from_invalid_links() {
    let name = interface_name(b"aux0").unwrap();
    assert!(Snapshot::default().aux_link(name).unwrap().is_none());
    let mut snapshot = Snapshot::default();
    let mut down = link_body(7, 1420, false, libc::ARPHRD_NONE, b"aux0\0");
    attribute(
        &mut down,
        IFLA_GRO_IPV4_MAX_SIZE,
        &LEGACY_OFFLOAD_MAX_SIZE.to_ne_bytes(),
    );
    snapshot.push(libc::RTM_NEWLINK, &down).unwrap();
    let info = AuxLinkInfo::from_link(snapshot.aux_link(name).unwrap().unwrap()).unwrap();
    assert_eq!(
        info,
        AuxLinkInfo {
            up: false,
            ..ACTIVE
        }
    );
    let mut big_tcp = link_body(7, 1420, true, libc::ARPHRD_NONE, b"aux0\0");
    attribute(
        &mut big_tcp,
        IFLA_GRO_IPV4_MAX_SIZE,
        &(LEGACY_OFFLOAD_MAX_SIZE + 1).to_ne_bytes(),
    );
    for body in [
        link_body(7, 1420, false, libc::ARPHRD_ETHER, b"aux0\0"),
        link_body(7, 1279, true, libc::ARPHRD_NONE, b"aux0\0"),
        link_body(7, 65_536, true, libc::ARPHRD_NONE, b"aux0\0"),
        big_tcp,
    ] {
        let mut snapshot = Snapshot::default();
        snapshot.push(libc::RTM_NEWLINK, &body).unwrap();
        let link = snapshot.aux_link(name).unwrap().unwrap();
        assert_eq!(link.index, 7);
        assert_eq!(
            AuxLinkInfo::from_link(link).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
    attribute(
        &mut down,
        IFLA_GRO_IPV4_MAX_SIZE,
        &LEGACY_OFFLOAD_MAX_SIZE.to_ne_bytes(),
    );
    assert_eq!(
        snapshot.push(libc::RTM_NEWLINK, &down).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn link_notifications_keep_transient_incarnation_changes() {
    let name = interface_name(b"aux0").unwrap();
    let valid = link_body(7, 1420, true, libc::ARPHRD_NONE, b"aux0\0");
    for (kind, body) in [
        (libc::RTM_DELLINK, valid.clone()),
        (
            libc::RTM_NEWLINK,
            link_body(7, 1380, true, libc::ARPHRD_NONE, b"aux0\0"),
        ),
        (
            libc::RTM_NEWLINK,
            link_body(7, 1420, false, libc::ARPHRD_NONE, b"aux0\0"),
        ),
        (
            libc::RTM_NEWLINK,
            link_body(7, 1420, true, libc::ARPHRD_NONE, b"renamed\0"),
        ),
    ] {
        let mut messages = capture_notification(kind, &body);
        messages.extend(capture_notification(libc::RTM_NEWLINK, &valid));
        let mut changes = Changes::default();
        changes
            .inspect(
                &messages,
                name,
                Some(ACTIVE),
                None,
                Default::default(),
                None,
            )
            .unwrap();
        assert!(changes.invalidated, "{kind}: {body:?}");
    }
    let mut changes = Changes::default();
    changes
        .inspect(
            &capture_notification(libc::RTM_NEWLINK, &valid),
            name,
            Some(ACTIVE),
            None,
            Default::default(),
            None,
        )
        .unwrap();
    assert!(!changes.invalidated);
    let unrelated = link_body(8, 1420, true, libc::ARPHRD_NONE, b"unrelated\0");
    changes
        .inspect(
            &capture_notification(libc::RTM_DELLINK, &unrelated),
            name,
            Some(ACTIVE),
            None,
            Default::default(),
            None,
        )
        .unwrap();
    assert!(!changes.invalidated);
    changes
        .inspect(
            &capture_notification(libc::RTM_NEWLINK, &valid),
            name,
            None,
            None,
            Default::default(),
            None,
        )
        .unwrap();
    assert!(changes.invalidated);
    let mut malformed = capture_notification(libc::RTM_NEWLINK, &valid);
    malformed.pop();
    assert_eq!(
        changes
            .inspect(
                &malformed,
                name,
                Some(ACTIVE),
                None,
                Default::default(),
                None
            )
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn auxiliary_defaults_resolve_direct_multipath_and_named_nexthops() {
    let mut direct = route_body(2, 0);
    attribute(&mut direct, 4, &7u32.to_ne_bytes());
    let mut multi = route_body(10, 0);
    let mut member = [0; 8];
    member[..2].copy_from_slice(&8u16.to_ne_bytes());
    member[4..8].copy_from_slice(&7u32.to_ne_bytes());
    attribute(&mut multi, 9, &member);
    let mut indirect = route_body(10, 0);
    attribute(&mut indirect, 30, &23u32.to_ne_bytes());
    for route in [&direct, &multi, &indirect] {
        let mut snapshot = Snapshot::default();
        snapshot.push(libc::RTM_NEWROUTE, route).unwrap();
        let mut group = vec![0; 8];
        attribute(&mut group, 1, &23u32.to_ne_bytes());
        let mut member = [0; 8];
        member[..4].copy_from_slice(&24u32.to_ne_bytes());
        attribute(&mut group, 2, &member);
        snapshot.push(RTM_NEWNEXTHOP, &group).unwrap();
        let mut next = vec![0; 8];
        attribute(&mut next, 1, &24u32.to_ne_bytes());
        attribute(&mut next, 5, &7u32.to_ne_bytes());
        snapshot.push(RTM_NEWNEXTHOP, &next).unwrap();
        assert!(snapshot.check_aux_defaults(7).is_err());
        snapshot.check_aux_defaults(8).unwrap();
    }
    let name = interface_name(b"aux0").unwrap();
    let mut changes = Changes::default();
    changes
        .inspect(
            &capture_notification(libc::RTM_NEWROUTE, &indirect),
            name,
            Some(ACTIVE),
            None,
            Default::default(),
            None,
        )
        .unwrap();
    assert!(changes.recheck);
    changes
        .inspect(
            &capture_notification(libc::RTM_DELROUTE, &direct),
            name,
            Some(ACTIVE),
            None,
            Default::default(),
            None,
        )
        .unwrap();
    assert!(changes.invalidated);
}

#[test]
fn legacy_ingress_notifications_distinguish_shared_blocks_and_egress() {
    let name = interface_name(b"aux0").unwrap();
    let observed = ObservedAuxLink {
        index: Some(7),
        ingress: Some(LegacyIngress {
            index: 7,
            parent: TC_H_CLSACT_INGRESS,
            shared_block: Some(42),
        }),
        ..ObservedAuxLink::default()
    };
    for (ifindex, parent, invalidated) in [
        (8, TC_H_CLSACT_INGRESS, false),
        (7, 0xffff_fff3, false),
        (7, TC_H_CLSACT_INGRESS, true),
        (TCM_IFINDEX_MAGIC_BLOCK, 41, false),
        (TCM_IFINDEX_MAGIC_BLOCK, 42, true),
    ] {
        let body = TcTarget { ifindex, parent }.body();
        for previous in [None, Some(ACTIVE)] {
            let mut changes = Changes::default();
            changes
                .inspect(
                    &capture_notification(libc::RTM_DELTFILTER, &body),
                    name,
                    previous,
                    None,
                    observed,
                    None,
                )
                .unwrap();
            assert_eq!(changes.invalidated, invalidated);
        }
    }
}

#[test]
fn rejected_default_guard_wakes_on_route_replacement_and_nexthop_change() {
    let name = interface_name(b"aux0").unwrap();
    let observed = ObservedAuxLink {
        index: Some(7),
        default_refused: true,
        ..ObservedAuxLink::default()
    };
    let mut replacement = route_body(2, 0);
    attribute(&mut replacement, 4, &8u32.to_ne_bytes());
    let mut nexthop = vec![0; 8];
    attribute(&mut nexthop, 1, &42u32.to_ne_bytes());
    attribute(&mut nexthop, 5, &8u32.to_ne_bytes());
    for (kind, body) in [(libc::RTM_NEWROUTE, replacement), (RTM_NEWNEXTHOP, nexthop)] {
        let event = capture_notification(kind, &body);
        let mut changes = Changes::default();
        changes
            .inspect(&event, name, None, None, Default::default(), None)
            .unwrap();
        assert!(!changes.invalidated);
        changes
            .inspect(&event, name, None, None, observed, None)
            .unwrap();
        assert!(changes.invalidated);
    }
}

#[test]
fn broadcast_notifications_refresh_only_the_local_ipv4_inventory() {
    let name = interface_name(b"aux0").unwrap();
    let address = Ipv4Addr::new(192, 0, 2, 255);
    let mut route = route_body(2, 32);
    route[4] = 255;
    route[7] = 3;
    attribute(&mut route, 1, &address.octets());
    attribute(&mut route, 4, &9u32.to_ne_bytes());
    let mut snapshot = Snapshot::default();
    let before = snapshot.ipv4_broadcasts().unwrap();
    snapshot.push(libc::RTM_NEWROUTE, &route).unwrap();
    let after = snapshot.ipv4_broadcasts().unwrap();
    assert_eq!(&after.0[..after.1], &[address]);

    for (kind, current) in [(libc::RTM_NEWROUTE, before), (libc::RTM_DELROUTE, after)] {
        let mut changes = Changes::default();
        changes
            .inspect(
                &capture_notification(kind, &route),
                name,
                Some(ACTIVE),
                None,
                ObservedAuxLink::default(),
                Some(&current),
            )
            .unwrap();
        assert!(changes.broadcasts_dirty);
        assert!(!changes.recheck && !changes.invalidated);
    }

    route[4] = 254;
    let mut changes = Changes::default();
    changes
        .inspect(
            &capture_notification(libc::RTM_NEWROUTE, &route),
            name,
            Some(ACTIVE),
            None,
            ObservedAuxLink::default(),
            Some(&after),
        )
        .unwrap();
    assert!(!changes.broadcasts_dirty);
}

#[test]
fn host_admission_uses_link_geometry_and_preserves_l3_lan_refusals() {
    let mac = [0x02, 1, 2, 3, 4, 5];
    for (type_, kind, address, admitted) in [
        (libc::ARPHRD_ETHER, "", Some(mac), true),
        (libc::ARPHRD_ETHER, "vlan", Some(mac), true),
        (libc::ARPHRD_ETHER, "bridge", Some(mac), true),
        (libc::ARPHRD_NONE, "tun", None, true),
        (libc::ARPHRD_NONE, "wireguard", None, true),
        (libc::ARPHRD_NONE, "bareudp", None, false),
        (libc::ARPHRD_NONE, "wireguard", Some(mac), false),
        (libc::ARPHRD_ETHER, "veth", None, false),
        (libc::ARPHRD_ETHER, "veth", Some([0xff; 6]), false),
        (libc::ARPHRD_ETHER, "gretap", Some(mac), false),
        (libc::ARPHRD_PPP, "tun", None, false),
        (libc::ARPHRD_IPGRE, "gre", None, false),
        (ARPHRD_IP6GRE, "ip6gre", None, false),
    ] {
        let mut body = link_body(7, 1420, true, type_, b"wg-wan\0");
        if !kind.is_empty() {
            let mut info = Vec::new();
            attribute(&mut info, 1, format!("{kind}\0").as_bytes());
            attribute(&mut body, 18, &info);
        }
        if kind == "vlan" {
            attribute(&mut body, 5, &12u32.to_ne_bytes());
        }
        if let Some(mac) = address {
            attribute(&mut body, 1, &mac);
        }
        let mut snapshot = Snapshot::default();
        snapshot.push(libc::RTM_NEWLINK, &body).unwrap();
        let link = &snapshot.links[0];
        assert_eq!(
            AuxLinkInfo::from_host_link(link).is_ok(),
            admitted,
            "{type_} {kind}"
        );
        if type_ == libc::ARPHRD_ETHER {
            assert!(AuxLinkInfo::from_link(link).is_err());
            attribute(
                &mut body,
                IFLA_GRO_IPV4_MAX_SIZE,
                &(LEGACY_OFFLOAD_MAX_SIZE + 1).to_ne_bytes(),
            );
            snapshot.push(libc::RTM_NEWLINK, &body).unwrap();
            assert!(AuxLinkInfo::from_host_link(&snapshot.links[1]).is_err());
        }
    }
}

#[test]
fn host_overlap_walks_master_and_vlan_edges_but_never_veth_peers() {
    let mut snapshot = Snapshot::default();
    let mut add = |index, name: &[u8], kind: &[u8], parent: Option<u32>, master: Option<u32>| {
        let mut body = link_body(index, 1500, true, libc::ARPHRD_ETHER, name);
        let mut info = Vec::new();
        attribute(&mut info, 1, kind);
        attribute(&mut body, 18, &info);
        if let Some(i) = parent {
            attribute(&mut body, 5, &i.to_ne_bytes());
        }
        if let Some(i) = master {
            attribute(&mut body, 10, &i.to_ne_bytes());
        }
        snapshot.push(libc::RTM_NEWLINK, &body).unwrap();
    };
    add(10, b"bond0\0", b"bond\0", None, None);
    add(11, b"member\0", b"veth\0", Some(20), Some(10));
    add(12, b"bond0.5\0", b"vlan\0", Some(10), None);
    add(20, b"peer\0", b"veth\0", Some(11), None);
    let captures = [interface_name(b"bond0").unwrap()];
    for index in [10, 11, 12] {
        assert!(snapshot.check_host_overlap(index, &captures).is_err());
    }
    snapshot.check_host_overlap(20, &captures).unwrap();
}

#[test]
fn host_broadcast_refresh_preserves_l2_and_l3_bindings_and_concurrent_mac_changes() {
    let ethernet = AuxLinkInfo {
        is_l2: true,
        local_mac: [2; 6],
        ..ACTIVE
    };
    let changed_mac = AuxLinkInfo {
        local_mac: [4; 6],
        ..ethernet
    };
    for (old, new) in [
        (ACTIVE, ACTIVE),
        (ethernet, ethernet),
        (ethernet, changed_mac),
    ] {
        assert_eq!(
            HostLinkChange::compare(old, new, true, true),
            HostLinkChange::Refresh(new)
        );
        assert_eq!(
            HostLinkChange::compare(old, new, false, true),
            HostLinkChange::Rebind
        );
        let changed_mtu = AuxLinkInfo {
            mtu: old.mtu + 1,
            ..new
        };
        assert_eq!(
            HostLinkChange::compare(old, changed_mtu, true, true),
            HostLinkChange::Rebind
        );
    }
}

#[test]
fn host_mac_notice_rechecks_without_retiring_but_unregister_and_down_are_sticky() {
    let name = interface_name(b"eth0").unwrap();
    let previous = AuxLinkInfo {
        is_l2: true,
        local_mac: [2; 6],
        ..ACTIVE
    };
    let observed = ObservedAuxLink {
        host: true,
        index: Some(7),
        ..Default::default()
    };
    for (kind, up, invalidated) in [
        (libc::RTM_NEWLINK, true, false),
        (libc::RTM_DELLINK, true, true),
        (libc::RTM_NEWLINK, false, true),
    ] {
        let mut body = link_body(7, 1420, up, libc::ARPHRD_ETHER, b"eth0\0");
        attribute(&mut body, 1, &[4; 6]);
        let mut changes = Changes::default();
        changes
            .inspect(
                &capture_notification(kind, &body),
                name,
                Some(previous),
                None,
                observed,
                None,
            )
            .unwrap();
        assert_eq!(changes.invalidated, invalidated);
        assert!(changes.recheck);
    }
    let mut default = route_body(2, 0);
    attribute(&mut default, 4, &7u32.to_ne_bytes());
    let mut changes = Changes::default();
    changes
        .inspect(
            &capture_notification(libc::RTM_NEWROUTE, &default),
            name,
            Some(previous),
            None,
            observed,
            None,
        )
        .unwrap();
    assert!(!changes.invalidated && !changes.recheck);
}

#[test]
fn host_private_tc_allows_delay_and_refuses_tag_writers() {
    let name = interface_name(b"wg0").unwrap();
    let inner = Some((interface_name(b"honk-host-0").unwrap(), 9, 1500));
    let observed = ObservedAuxLink {
        host: true,
        host_fifo: Some((9, 8)),
        ..Default::default()
    };
    for (kind, index, qdisc, invalid) in [
        (libc::RTM_NEWQDISC, 9, b"netem\0".as_slice(), false),
        (libc::RTM_NEWQDISC, 9, b"clsact\0", true),
        (libc::RTM_NEWTFILTER, 9, b"bpf\0", true),
        (libc::RTM_NEWTFILTER, 7, b"bpf\0", false),
    ] {
        let mut body = TcTarget {
            ifindex: index,
            parent: u32::MAX,
        }
        .body()
        .to_vec();
        attribute(&mut body, TCA_KIND, qdisc);
        if qdisc == b"netem\0" {
            let mut options = [0u8; 24];
            options[4..8].copy_from_slice(&8u32.to_ne_bytes());
            attribute(&mut body, 2, &options);
            private_host_qdisc(&body, 8, false).unwrap();
            assert!(private_host_qdisc(&body, 7, false).is_err());
        }
        let mut changes = Changes::default();
        changes
            .inspect(
                &capture_notification(kind, &body),
                name,
                Some(ACTIVE),
                inner,
                observed,
                None,
            )
            .unwrap();
        assert_eq!(changes.invalidated, invalid);
    }
}
