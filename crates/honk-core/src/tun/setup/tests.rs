use super::*;
use std::os::unix::fs::{PermissionsExt as _, symlink};

fn journal() -> (tempfile::TempDir, Journal) {
    let root = tempfile::tempdir().unwrap();
    let directory = state::state_directory(root.path(), true, state::private).unwrap();
    let journal =
        Journal::create(directory, root.path().join("state"), 17, 41, "honk0", 1).unwrap();
    (root, journal)
}

fn stored(journal: &Journal) -> Value {
    serde_json::from_slice(&std::fs::read(journal.path()).unwrap()).unwrap()
}

#[test]
fn strict_global_reverse_path_filter_is_refused_without_a_write() {
    for value in ["0", "0\n", "2", "2\n"] {
        admit_all_rp_filter(true, || Ok(value.into())).unwrap();
    }
    let error = admit_all_rp_filter(true, || Ok("1\n".into())).unwrap_err();
    assert!(error.to_string().contains("net.ipv4.conf.all.rp_filter"));
    assert!(error.to_string().contains("set it to 0 or 2"));
    assert!(admit_all_rp_filter(true, || Ok("3".into())).is_err());
    assert!(admit_all_rp_filter(true, || Err(io::ErrorKind::PermissionDenied.into())).is_err());
    admit_all_rp_filter(false, || {
        panic!("IPv6-only startup must not read IPv4 policy")
    })
    .unwrap();
}

#[test]
fn tun_attachment_requires_plain_single_queue_flags_and_a_bounded_name() {
    let flags = libc::IFF_TUN | libc::IFF_NO_PI;
    assert!(valid_attachment_flags(flags));
    assert!(valid_attachment_flags(flags | libc::IFF_TUN_EXCL));
    for wrong in [
        flags | libc::IFF_MULTI_QUEUE,
        flags | libc::IFF_VNET_HDR,
        flags | libc::IFF_NAPI,
        libc::IFF_TUN,
        libc::IFF_TAP | libc::IFF_NO_PI,
    ] {
        assert!(!valid_attachment_flags(wrong));
    }
    for name in ["", "abcdefghijklmnop", "honk\0other"] {
        assert!(interface_request(name).is_err());
    }
    let request = interface_request("abcdefghijklmno").unwrap();
    assert_eq!(request.ifr_name[15], 0);
}

#[test]
fn receipt_is_private_exclusive_and_preserves_exact_durable_states() {
    let (root, mut journal) = journal();
    assert_eq!(
        std::fs::metadata(journal.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let initial = stored(&journal);
    assert_eq!(initial["source_sha"], SOURCE_SHA);
    assert_eq!(initial["netns_cookie"], 17);
    assert_eq!(initial["incarnation"], 1);
    assert!(initial["starttime"].as_u64().unwrap() > 0);
    assert!(create_private(&journal.directory, &journal.file_name).is_err());
    let foreign = root.path().join("foreign");
    std::fs::write(&foreign, b"untouched").unwrap();
    symlink(&foreign, root.path().join("state/symlink")).unwrap();
    assert!(create_private(&journal.directory, "symlink").is_err());
    assert_eq!(std::fs::read(&foreign).unwrap(), b"untouched");
    let route = TunRoute {
        table: 202,
        destination: "0.0.0.0".parse().unwrap(),
        prefix_len: 0,
        kind: TunRouteKind::Blackhole,
        metric: 32760,
    };
    journal
        .entries
        .push((Resource::Route(route), State::Intent));
    journal.persist().unwrap();
    let intent = stored(&journal);
    assert_eq!(intent["ambiguous"], true);
    assert_eq!(intent["resources"][0]["state"], "intent");
    assert_eq!(intent["resources"][0]["table"], 202);
    assert_eq!(intent["resources"][0]["metric"], 32760);
    journal.entries[0].1 = State::Acknowledged;
    journal.persist().unwrap();
    assert_eq!(stored(&journal)["ambiguous"], false);
    assert_eq!(stored(&journal)["resources"][0]["state"], "acknowledged");
    journal.remove().unwrap();
    assert!(!journal.path().exists());
}

#[test]
fn replaced_receipt_cannot_be_overwritten_or_unlinked() {
    let (_root, mut journal) = journal();
    let original = journal.path().with_extension("retained");
    std::fs::rename(journal.path(), &original).unwrap();
    std::fs::write(journal.path(), b"foreign-owner").unwrap();
    journal.entries.push((Resource::Link, State::Intent));
    assert!(journal.persist().is_err());
    assert!(journal.remove().is_err());
    assert_eq!(std::fs::read(journal.path()).unwrap(), b"foreign-owner");
    assert!(original.exists());
}

#[test]
fn write_ahead_precedes_the_mutation_and_unconfirmed_outcomes_stay_ambiguous() {
    let (_root, journal) = journal();
    let receipt = journal.path();
    let mut setup = TunSetup {
        plan: Plan {
            name: "honk0".into(),
            mtu: 1500,
            address4: Some("198.18.0.1".parse().unwrap()),
            address6: None,
            table: 202,
            rule_priority: 10000,
            mark: 0x100,
            capture: vec![("0.0.0.0".parse().unwrap(), 0)],
        },
        journal,
        netlink: NlSock::new().unwrap(),
    };
    setup
        .mutate(Resource::LinkUp, |_| {
            let recorded: Value =
                serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
            assert_eq!(recorded["resources"][0]["state"], "intent");
            Ok(())
        })
        .unwrap();
    assert_eq!(
        stored(&setup.journal)["resources"][0]["state"],
        "acknowledged"
    );
    assert!(
        setup
            .mutate(Resource::Mtu(1500), |_| Err(MutationError::Unconfirmed(
                io::ErrorKind::TimedOut.into()
            )))
            .is_err()
    );
    assert_eq!(stored(&setup.journal)["resources"][1]["state"], "intent");
    assert!(setup.journal.ambiguous());
    assert!(setup.remove_containment().is_err());
    assert!(receipt.exists());
}

#[test]
fn cleanup_requires_unique_exact_keys_and_removes_capture_before_guards() {
    let route = TunRoute {
        table: 202,
        destination: "0.0.0.0".parse().unwrap(),
        prefix_len: 0,
        kind: TunRouteKind::Blackhole,
        metric: 32760,
    };
    let capture = TunRule {
        ipv6: false,
        priority: 10004,
        selector: TunRuleSelector::All,
        action: TunRuleAction::Lookup(202),
    };
    let bypass = TunRule {
        priority: 10000,
        selector: TunRuleSelector::Fwmark(0x100),
        action: TunRuleAction::Lookup(254),
        ..capture
    };
    let mut facts = TunReadback {
        link: false,
        addresses: Vec::new(),
        routes: vec![(202, route.destination, 0, 32760, Some(route))],
        rules: vec![(false, 10004, Some(capture))],
    };
    assert_eq!(slot(&facts, &Resource::Route(route)), Slot::Exact);
    assert_eq!(slot(&facts, &Resource::Rule(capture)), Slot::Exact);
    facts.routes.push(facts.routes[0]);
    assert_eq!(slot(&facts, &Resource::Route(route)), Slot::Foreign);
    facts.routes.pop();
    facts.routes[0].4 = None;
    assert_eq!(slot(&facts, &Resource::Route(route)), Slot::Foreign);
    facts.rules[0].2 = Some(bypass);
    assert_eq!(slot(&facts, &Resource::Rule(capture)), Slot::Foreign);
    facts.rules.clear();
    assert_eq!(slot(&facts, &Resource::Rule(capture)), Slot::Empty);
    let entries = [
        (Resource::Route(route), State::Acknowledged),
        (Resource::Rule(bypass), State::Acknowledged),
        (Resource::Rule(capture), State::Acknowledged),
        (Resource::Link, State::Acknowledged),
        (Resource::Rule(capture), State::Refused),
    ];
    assert_eq!(removal_order(&entries, 10004), [2, 0, 1]);
}

#[cfg(feature = "ebpf")]
#[test]
#[ignore = "requires the disposable kernel VM gate"]
fn kernel_tun_exclusive_fd_and_containment_are_owned() {
    let expected = std::env::var("HONK_CI_EXPECTED_KERNEL").unwrap_or_default();
    assert!(std::env::var_os("HONK_CI_VM_LANE").is_some() && !expected.is_empty());
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap()
            .trim(),
        expected
    );
    assert!(
        std::fs::read_to_string("/proc/cmdline")
            .unwrap()
            .contains("virtme.")
    );
    std::thread::spawn(|| {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", b"0").unwrap();
        std::fs::write("/proc/sys/net/ipv6/conf/default/disable_ipv6", b"1").unwrap();
        let mut netlink = NlSock::new().unwrap();
        netlink.add_veth_pair("uplink", "peer").unwrap();
        let uplink = nix::net::if_::if_nametoindex("uplink").unwrap();
        let peer = nix::net::if_::if_nametoindex("peer").unwrap();
        netlink
            .addr_op(true, uplink, 2, &[192, 0, 2, 1], 24)
            .unwrap();
        netlink.set_link_up(uplink, true).unwrap();
        netlink.set_link_up(peer, true).unwrap();
        netlink
            .add_route(2, 254, 1, 253, 4, None, None, Some(uplink))
            .unwrap();
        let config = honk_config::parser::parse_dae_config(
            r#"
            global { nfqueue_enable: false }
            datapath {
                backend: tun
                direct: endpoint
                tun {
                    name: honk0
                    address4: 198.18.0.1/32
                    table: 202
                    rule_priority: 10000
                    capture { 0.0.0.0/0 }
                }
            }
            routing { fallback: direct }
        "#,
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let (mut setup, device, guarded) = TunSetup::prepare_in(&config, root.path()).unwrap();
        assert!(
            TunDevice::open("honk0", 2).is_err(),
            "cannot adopt an occupied name"
        );
        let final_watch = setup.activate(&device).unwrap();
        let facts = setup.readback().unwrap();
        assert!(facts.link);
        assert_eq!(facts.routes.len(), 2);
        assert_eq!(facts.rules.len(), 5);
        let owned = setup.plan.spec().capture_routes(device.ifindex)[0];
        let other_metric = TunRoute {
            metric: 2048,
            kind: TunRouteKind::Unicast { oif: uplink },
            ..owned
        };
        let other_table = TunRoute {
            table: 203,
            kind: TunRouteKind::Unicast { oif: uplink },
            ..owned
        };
        netlink.add_tun_route(&other_metric).unwrap();
        netlink.add_tun_route(&other_table).unwrap();
        for absent in [
            TunRoute {
                metric: 4096,
                ..owned
            },
            TunRoute {
                kind: TunRouteKind::Unicast { oif: uplink },
                ..owned
            },
            TunRoute {
                table: 204,
                ..owned
            },
        ] {
            assert!(netlink.del_tun_route(&absent).is_err());
            assert_eq!(
                slot(&setup.readback().unwrap(), &Resource::Route(owned)),
                Slot::Exact
            );
        }
        setup.close_capture(&device).unwrap();
        let remaining = setup.readback().unwrap();
        assert_eq!(slot(&remaining, &Resource::Route(owned)), Slot::Empty);
        assert!(
            remaining
                .routes
                .iter()
                .any(|(table, destination, prefix, metric, _)| (
                    *table,
                    *destination,
                    *prefix,
                    *metric
                ) == (
                    202,
                    owned.destination,
                    owned.prefix_len,
                    2048
                ))
        );
        let other_spec = TunSpec {
            table: 203,
            ..setup.plan.spec()
        };
        let other = tun_readback(&other_spec, device.ifindex).unwrap();
        assert!(
            other
                .routes
                .iter()
                .any(|(table, destination, prefix, metric, _)| (
                    *table,
                    *destination,
                    *prefix,
                    *metric
                ) == (
                    203,
                    owned.destination,
                    owned.prefix_len,
                    1024
                ))
        );
        netlink.del_tun_route(&other_metric).unwrap();
        netlink.del_tun_route(&other_table).unwrap();
        let receipt = setup.journal.path();
        drop(final_watch);
        drop(guarded);
        drop(device);
        assert!(!setup.readback().unwrap().link);
        setup.finish(true).unwrap();
        assert!(!receipt.exists());
        Topology::preflight_tun(&Plan::from_config(&config).unwrap().spec()).unwrap();
    })
    .join()
    .unwrap();
}
