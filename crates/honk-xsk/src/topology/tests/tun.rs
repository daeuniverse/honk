use super::*;

const CAPTURE: [(IpAddr, u8); 2] = [
    (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
];

fn spec(v4: bool, v6: bool) -> TunSpec<'static> {
    TunSpec {
        name: "honk0",
        mtu: 1500,
        address4: v4.then_some(Ipv4Addr::new(198, 18, 0, 1)),
        address6: v6.then(|| "fd00:100::1".parse().unwrap()),
        table: 202,
        rule_priority: 10000,
        bypass_mark: 0x100,
        capture: match (v4, v6) {
            (true, true) => &CAPTURE,
            (true, false) => &CAPTURE[..1],
            (false, true) => &CAPTURE[1..],
            _ => &[],
        },
    }
}

fn bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

fn link(index: u32, name: &str, kind: Option<&str>, flags: u32, arphrd: u16) -> Link {
    let mut body = vec![0; 16];
    body[2..4].copy_from_slice(&arphrd.to_ne_bytes());
    body[4..8].copy_from_slice(&index.to_ne_bytes());
    body[8..12].copy_from_slice(&flags.to_ne_bytes());
    attribute(&mut body, 3, format!("{name}\0").as_bytes());
    attribute(&mut body, 4, &1500u32.to_ne_bytes());
    if let Some(kind) = kind {
        let mut info = Vec::new();
        attribute(&mut info, 1, format!("{kind}\0").as_bytes());
        attribute(&mut body, 18, &info);
    }
    let mut parsed = Snapshot::default();
    parsed.push(16, &body).unwrap();
    parsed.links.pop().unwrap()
}

fn address(index: u32, ip: IpAddr, owned: bool) -> Address {
    let family = if ip.is_ipv6() { 10 } else { 2 };
    let mut body = address_body(family, index, &bytes(ip), None);
    let flags = IFA_F_PERMANENT
        | if owned {
            IFA_F_NOPREFIXROUTE | if family == 10 { IFA_F_NODAD } else { 0 }
        } else {
            0
        };
    attribute(&mut body, 8, &flags.to_ne_bytes());
    let mut cache = Vec::new();
    cache.extend_from_slice(&u32::MAX.to_ne_bytes());
    cache.extend_from_slice(&u32::MAX.to_ne_bytes());
    cache.extend_from_slice(&[0; 8]);
    attribute(&mut body, 6, &cache);
    let mut parsed = Snapshot::default();
    parsed.push(20, &body).unwrap();
    parsed.addresses.pop().unwrap()
}

fn rule_body(rule: TunRule, name: &str) -> Vec<u8> {
    let mut body = vec![0; 12];
    body[0] = if rule.ipv6 { 10 } else { 2 };
    let table = match rule.action {
        TunRuleAction::Lookup(table) => {
            body[7] = 1;
            table
        }
        TunRuleAction::Prohibit => {
            body[7] = 8;
            0
        }
    };
    attribute(&mut body, 15, &table.to_ne_bytes());
    attribute(&mut body, 6, &rule.priority.to_ne_bytes());
    match rule.selector {
        TunRuleSelector::Fwmark(mark) => {
            attribute(&mut body, 10, &mark.to_ne_bytes());
            attribute(&mut body, 16, &u32::MAX.to_ne_bytes());
        }
        TunRuleSelector::Iif => attribute(&mut body, 3, format!("{name}\0").as_bytes()),
        TunRuleSelector::All => {}
    }
    body
}

fn route_body(route: TunRoute) -> Vec<u8> {
    let mut body = vec![0; 12];
    let v6 = route.destination.is_ipv6();
    body[0] = if v6 { 10 } else { 2 };
    body[1] = route.prefix_len;
    body[5] = RTPROT_STATIC;
    match route.kind {
        TunRouteKind::Blackhole => {
            body[7] = RTN_BLACKHOLE;
            if v6 {
                attribute(&mut body, 4, &1u32.to_ne_bytes());
            }
        }
        TunRouteKind::Unicast { oif } => {
            body[6] = if v6 { 0 } else { 253 };
            body[7] = 1;
            attribute(&mut body, 4, &oif.to_ne_bytes());
        }
    }
    attribute(&mut body, 15, &route.table.to_ne_bytes());
    attribute(&mut body, 1, &bytes(route.destination));
    attribute(&mut body, 6, &route.metric.to_ne_bytes());
    body
}

fn owned_local_route_body(ip: IpAddr, ifindex: u32) -> Vec<u8> {
    let family = if ip.is_ipv6() { 10 } else { 2 };
    let mut local = local_route_body(
        family,
        if family == 2 { 32 } else { 128 },
        2,
        Some(&bytes(ip)),
    );
    local[6] = if family == 2 { 254 } else { 0 };
    let output = local.len() - 12;
    assert_eq!(
        u16::from_ne_bytes(local[output - 2..output].try_into().unwrap()),
        4
    );
    local[output..output + 4].copy_from_slice(&ifindex.to_ne_bytes());
    local
}

fn fixture(spec: &TunSpec<'_>, stage: Option<TunStage>) -> Snapshot {
    let mut snapshot = Snapshot::default();
    snapshot.links.push(link(1, "lo", None, 0x10049, 772));
    snapshot
        .links
        .push(link(3, "uplink", Some("veth"), 0x11043, 1));
    for ipv6 in spec.families() {
        let family = if ipv6 { 10 } else { 2 };
        let source = if ipv6 { "2001:db8::1" } else { "192.0.2.1" }
            .parse()
            .unwrap();
        snapshot.addresses.push(address(3, source, false));
        for (priority, table) in [(0, 255), (32766, 254), (32767, 253)] {
            snapshot.rules.push(xdp_rule(family, priority, table, None));
        }
        snapshot.routes.push(xdp_route(family, 254, 3, true, 1));
    }
    if let Some(stage) = stage {
        snapshot
            .links
            .push(link(17, "honk0", Some("tun"), 0x110d1, 0xfffe));
        for ip in spec.addresses() {
            snapshot.addresses.push(address(17, ip, true));
            snapshot.push(24, &owned_local_route_body(ip, 17)).unwrap();
        }
        for rule in spec.rules() {
            snapshot.push(32, &rule_body(rule, spec.name)).unwrap();
        }
        for route in spec.guard_routes() {
            snapshot.push(24, &route_body(route)).unwrap();
        }
        if stage == TunStage::Active {
            for route in spec.capture_routes(17) {
                snapshot.push(24, &route_body(route)).unwrap();
            }
        }
    }
    snapshot
}

fn admit(snapshot: &Snapshot, spec: &TunSpec<'_>, stage: Option<TunStage>) -> io::Result<()> {
    snapshot.admit_tun(spec, spec.validate()?, stage.map(|stage| (17, stage)))
}

fn device_fixture(spec: &TunSpec<'_>) -> Snapshot {
    let mut snapshot = fixture(spec, Some(TunStage::Guarded));
    snapshot
        .rules
        .retain(|rule| !(spec.rule_priority..=spec.rule_priority + 4).contains(&rule.priority));
    snapshot.routes.retain(|route| route.table != spec.table);
    snapshot
}

#[test]
fn tun_device_readiness_waits_only_for_its_parsed_ipv6_local_route() {
    for (v4, v6) in [(true, false), (false, true), (true, true)] {
        let spec = spec(v4, v6);
        let name = spec.validate().unwrap();
        let mut snapshot = device_fixture(&spec);
        assert!(snapshot.tun_ready(&spec, name, Some(17), None).unwrap());
        if !v6 {
            continue;
        }
        snapshot
            .routes
            .retain(|route| route.family != 10 || route.table != 255);
        assert!(!snapshot.tun_ready(&spec, name, Some(17), None).unwrap());
        let local = owned_local_route_body(IpAddr::V6(spec.address6.unwrap()), 17);
        snapshot.push(24, &local).unwrap();
        assert!(snapshot.tun_ready(&spec, name, Some(17), None).unwrap());

        for stage in [TunStage::Guarded, TunStage::Active] {
            let mut snapshot = fixture(&spec, Some(stage));
            snapshot
                .routes
                .retain(|route| route.family != 10 || route.table != 255);
            assert!(
                !snapshot
                    .tun_ready(&spec, name, Some(17), Some(stage))
                    .unwrap()
            );
            assert_eq!(
                admit(&snapshot, &spec, Some(stage)).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            snapshot.push(24, &local).unwrap();
            admit(&snapshot, &spec, Some(stage)).unwrap();
        }
    }
}

#[test]
fn tun_device_readiness_never_retries_foreign_or_conflicting_parsed_state() {
    let spec = spec(true, true);
    let name = spec.validate().unwrap();
    let address6 = IpAddr::V6(spec.address6.unwrap());
    for change in 0..13 {
        let mut snapshot = device_fixture(&spec);
        snapshot
            .routes
            .retain(|route| route.family != 10 || route.table != 255);
        assert!(!snapshot.tun_ready(&spec, name, Some(17), None).unwrap());
        match change {
            0 => snapshot.rules.push(xdp_rule(2, 99, 100, Some(0x100))),
            1 => snapshot
                .push(24, &route_body(spec.guard_routes()[0]))
                .unwrap(),
            2 => snapshot.routes.push(xdp_route(2, 254, 17, false, 1)),
            3 => snapshot
                .routes
                .retain(|route| route.family != 2 || route.table != 255),
            4 => snapshot
                .push(24, &owned_local_route_body(address6, 3))
                .unwrap(),
            5 => {
                let mut local = owned_local_route_body(address6, 17);
                local[7] = 1;
                snapshot.push(24, &local).unwrap();
            }
            6 => snapshot
                .push(
                    24,
                    &owned_local_route_body(IpAddr::V4(spec.address4.unwrap()), 17),
                )
                .unwrap(),
            7 => {
                let mut local = owned_local_route_body(address6, 17);
                attribute(&mut local, 99, &[0; 8]);
                snapshot.push(24, &local).unwrap();
            }
            8 => {
                snapshot.links.pop();
                snapshot
                    .links
                    .push(link(17, "honk0", Some("tun"), 0x100d1, 0xfffe));
            }
            9 => snapshot.addresses.push(address(3, address6, false)),
            10 => snapshot.addresses.push(address(17, address6, true)),
            11 => {
                let mut local = owned_local_route_body(address6, 17);
                local[1] = 64;
                snapshot.push(24, &local).unwrap();
            }
            _ => snapshot.addresses.retain(|address| address.family != 10),
        }
        assert!(
            snapshot.tun_ready(&spec, name, Some(17), None).is_err(),
            "accepted pending state mutation {change}"
        );
    }
}

#[test]
fn tun_device_readback_does_not_refresh_an_expired_deadline() {
    let fd = std::fs::File::open("/dev/null").unwrap();
    let error = snapshot(fd.as_fd(), Some(Instant::now())).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn tun_admission_requires_five_exact_rules_per_enabled_family() {
    for (v4, v6) in [(true, false), (false, true), (true, true)] {
        let spec = spec(v4, v6);
        for stage in [None, Some(TunStage::Guarded), Some(TunStage::Active)] {
            admit(&fixture(&spec, stage), &spec, stage).unwrap();
        }
    }
    let spec = spec(true, true);
    for change in 0..12 {
        let mut snapshot = fixture(&spec, Some(TunStage::Active));
        let first = snapshot
            .rules
            .iter()
            .position(|rule| rule.priority == 10000)
            .unwrap();
        match change {
            0 => snapshot.rules[first].mask = 0xff,
            1 => snapshot.rules[first].mark = Some(0x200),
            2 => snapshot.rules[first].table = 202,
            3 => snapshot.rules[first + 1].action = 1,
            4 => snapshot.rules[first + 2].iif = Some(interface_name(b"foreign").unwrap()),
            5 => snapshot.rules[first + 3].action = 1,
            6 => snapshot.rules[first + 4].priority = 10005,
            7 => snapshot.rules[first + 2].flags = FIB_RULE_IIF_DETACHED,
            8 => {
                snapshot.rules.remove(first);
            }
            9 => snapshot.rules.push(snapshot.rules[first].clone()),
            10 => snapshot.rules.push(xdp_rule(2, 99, 101, None)),
            _ => snapshot.rules.push(xdp_rule(2, 0, 255, None)),
        }
        assert!(
            admit(&snapshot, &spec, Some(TunStage::Active)).is_err(),
            "accepted mutation {change}"
        );
    }
}

#[test]
fn tun_resources_and_main_routes_cannot_borrow_foreign_authority() {
    let spec = spec(true, true);
    for change in 0..6 {
        let mut snapshot = fixture(&spec, None);
        match change {
            0 => snapshot
                .links
                .push(link(17, "honk0", Some("tun"), 0x110d1, 0xfffe)),
            1 => snapshot.routes.push(xdp_route(2, 202, 3, true, 1)),
            2 => snapshot.rules.push(xdp_rule(10, 10003, 100, None)),
            3 => snapshot
                .addresses
                .push(address(3, spec.address4.unwrap().into(), false)),
            4 => snapshot.rules.push(xdp_rule(2, 30000, 202, None)),
            _ => snapshot.links.push(link(19, "vrf0", Some("vrf"), 1, 1)),
        }
        assert!(
            admit(&snapshot, &spec, None).is_err(),
            "accepted preflight mutation {change}"
        );
    }
    for change in 0..12 {
        let mut snapshot = fixture(&spec, Some(TunStage::Active));
        match change {
            0 => snapshot.links.last_mut().unwrap().mtu = Some(1400),
            1 => snapshot.addresses.last_mut().unwrap().flags &= !IFA_F_NOPREFIXROUTE,
            2 => snapshot.routes[0].output = 17,
            3 => snapshot.routes.push(xdp_route(2, 99, 17, true, 1)),
            4 => snapshot.links.last_mut().unwrap().master = 19,
            5 => snapshot.routes[0].unsupported = true,
            6 => snapshot.routes[0].default = false,
            7 => snapshot.addresses[0].flags |= IFA_F_TENTATIVE,
            8 => snapshot
                .routes
                .retain(|route| route.kind != 2 || route.family != 2),
            9 => snapshot.links[1].kind = Some(interface_name(b"tun").unwrap()),
            10 => snapshot.routes.last_mut().unwrap().metric = 0,
            _ => {
                snapshot.routes.pop();
            }
        }
        assert!(
            admit(&snapshot, &spec, Some(TunStage::Active)).is_err(),
            "accepted owned mutation {change}"
        );
    }
    let mut point_to_point = fixture(&spec, Some(TunStage::Active));
    point_to_point.links[1] = link(3, "uplink", None, 0x10051, 512);
    admit(&point_to_point, &spec, Some(TunStage::Active)).unwrap();
}

#[test]
fn tun_cleanup_retains_foreign_slots_and_recognizes_detached_owned_rules() {
    let spec = spec(true, true);
    let mut snapshot = fixture(&spec, Some(TunStage::Active));
    let live = snapshot.tun_readback(&spec, 17).unwrap();
    assert!(live.link);
    assert_eq!(
        live.routes.iter().filter(|entry| entry.4.is_some()).count(),
        4
    );
    assert_eq!(
        live.rules.iter().filter(|entry| entry.2.is_some()).count(),
        10
    );
    snapshot.links.retain(|link| link.index != 17);
    snapshot.addresses.retain(|address| address.index != 17);
    snapshot.routes.retain(|route| route.output != 17);
    for rule in &mut snapshot.rules {
        if rule.iif.is_some() {
            rule.flags = FIB_RULE_IIF_DETACHED;
        }
    }
    let closed = snapshot.tun_readback(&spec, 17).unwrap();
    assert!(!closed.link && closed.addresses.is_empty());
    assert_eq!(
        closed
            .routes
            .iter()
            .filter(|entry| entry.4.is_some())
            .count(),
        2
    );
    assert_eq!(
        closed
            .rules
            .iter()
            .filter(|entry| entry.2.is_some())
            .count(),
        10
    );
    snapshot
        .rules
        .iter_mut()
        .find(|rule| rule.priority == 10000)
        .unwrap()
        .mask = 0xff;
    snapshot
        .routes
        .iter_mut()
        .find(|route| route.table == 202)
        .unwrap()
        .protocol = 99;
    let foreign = snapshot.tun_readback(&spec, 17).unwrap();
    assert!(foreign.routes.iter().any(|entry| entry.4.is_none()));
    assert!(foreign.rules.iter().any(|entry| entry.2.is_none()));
    snapshot
        .links
        .push(link(17, "replacement", Some("tun"), 0x110d1, 0xfffe));
    let replaced = snapshot.tun_readback(&spec, 17).unwrap();
    assert!(replaced.link);
    assert!(
        replaced
            .rules
            .iter()
            .filter(|entry| matches!(entry.1, 10002 | 10003))
            .all(|entry| entry.2.is_none())
    );
}

#[test]
fn tun_parser_refuses_unrepresented_route_and_rule_execution() {
    let spec = spec(true, false);
    for kind in [8, 9, 18, 21, 30, 99] {
        let mut snapshot = fixture(&spec, Some(TunStage::Active));
        let route = spec.capture_routes(17)[0];
        let mut body = route_body(route);
        attribute(&mut body, kind, &[0; 8]);
        snapshot.routes.pop();
        snapshot.push(24, &body).unwrap();
        assert!(
            admit(&snapshot, &spec, Some(TunStage::Active)).is_err(),
            "route attribute {kind}"
        );
    }
    for kind in [17, 19, 20, 22, 23, 99] {
        let mut snapshot = fixture(&spec, Some(TunStage::Active));
        let mut body = rule_body(spec.rules()[0], spec.name);
        attribute(&mut body, kind, &[0; 8]);
        snapshot.rules.retain(|rule| rule.priority != 10000);
        snapshot.push(32, &body).unwrap();
        assert!(
            admit(&snapshot, &spec, Some(TunStage::Active)).is_err(),
            "rule attribute {kind}"
        );
    }
    let mut duplicate = rule_body(spec.rules()[0], spec.name);
    attribute(&mut duplicate, 10, &0x100u32.to_ne_bytes());
    assert!(Snapshot::default().push(32, &duplicate).is_err());
}

#[test]
fn tun_spec_rejects_inexact_keys_before_constructing_ownership() {
    let good = spec(true, true);
    good.validate().unwrap();
    for bad in [
        TunSpec { name: "lo", ..good },
        TunSpec {
            name: "bad/name",
            ..good
        },
        TunSpec { mtu: 1279, ..good },
        TunSpec {
            rule_priority: u32::MAX,
            ..good
        },
        TunSpec {
            rule_priority: 32762,
            ..good
        },
        TunSpec { table: 255, ..good },
        TunSpec {
            bypass_mark: 0,
            ..good
        },
    ] {
        assert!(bad.validate().is_err());
    }
    for capture in [
        vec![("192.0.2.1".parse().unwrap(), 24)],
        vec![CAPTURE[0], CAPTURE[0]],
    ] {
        assert!(
            TunSpec {
                capture: &capture,
                ..good
            }
            .validate()
            .is_err()
        );
    }
}
