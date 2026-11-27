use super::*;
use std::cell::Cell;
use std::io::Read as _;
use std::os::unix::{
    fs::{PermissionsExt as _, symlink},
    net::UnixStream,
};

const IFINDEX: u32 = 17;

fn journal(queues: u8) -> (tempfile::TempDir, Journal) {
    let root = tempfile::tempdir().unwrap();
    let directory = state::state_directory(root.path(), true, state::private).unwrap();
    let journal = Journal::create(
        directory,
        root.path().join("state"),
        17,
        41,
        "honk0",
        1,
        queues,
    )
    .unwrap();
    (root, journal)
}

fn setup(queues: u8) -> (tempfile::TempDir, TunSetup) {
    let (root, journal) = journal(queues);
    let setup = TunSetup {
        plan: Plan {
            name: "honk0".into(),
            mtu: 1500,
            queues,
            address4: Some("198.18.0.1".parse().unwrap()),
            address6: Some("fd00:100::1".parse().unwrap()),
            table: 202,
            rule_priority: 10000,
            mark: 0x100,
            capture: vec![
                ("0.0.0.0".parse().unwrap(), 1),
                ("128.0.0.0".parse().unwrap(), 1),
                ("::".parse().unwrap(), 0),
            ],
        },
        journal,
        netlink: NlSock::new().unwrap(),
    };
    (root, setup)
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
fn tun_attachment_requires_exact_queue_flags_and_a_bounded_name() {
    let flags = libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR;
    let mq = flags | libc::IFF_MULTI_QUEUE;
    assert!(valid_attachment_flags(flags, false));
    assert!(valid_attachment_flags(flags | libc::IFF_TUN_EXCL, false));
    assert!(valid_attachment_flags(mq, true));
    assert!(valid_attachment_flags(mq | libc::IFF_TUN_EXCL, true));
    assert!(!valid_attachment_flags(flags, true));
    for wrong in [
        flags | libc::IFF_MULTI_QUEUE,
        flags | libc::IFF_DETACH_QUEUE,
        flags | libc::IFF_ATTACH_QUEUE,
        flags & !libc::IFF_VNET_HDR,
        flags | libc::IFF_NAPI,
        flags | libc::IFF_PERSIST,
        flags | libc::IFF_NAPI_FRAGS,
        flags | libc::IFF_ONE_QUEUE,
        flags | libc::IFF_NO_CARRIER,
        libc::IFF_TUN,
        libc::IFF_TAP | libc::IFF_NO_PI,
    ] {
        assert!(!valid_attachment_flags(wrong, false));
    }
    assert!(!valid_attachment_flags(mq | libc::IFF_DETACH_QUEUE, true));
    assert!(!valid_attachment_flags(mq | libc::IFF_PERSIST, true));
    for name in ["", "abcdefghijklmnop", "honk\0other"] {
        assert!(interface_request(name).is_err());
    }
    let request = interface_request("abcdefghijklmno").unwrap();
    assert_eq!(request.ifr_name[15], 0);
}

#[test]
fn vnet_setup_refuses_an_unsupported_descriptor_without_fallback() {
    let (socket, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    let error = configure_vnet(socket.as_raw_fd()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    let error = verify_vnet(socket.as_raw_fd()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
}

#[test]
fn receipt_is_private_exclusive_and_preserves_exact_durable_states() {
    let (root, mut journal) = journal(1);
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
    let (_root, mut journal) = journal(1);
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
    let (_root, mut setup) = setup(1);
    let receipt = setup.journal.path();
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
        owned_tun: false,
        num_queues: None,
        num_disabled_queues: None,
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

fn queue_readback(active: Option<u32>, disabled: Option<u32>) -> TunReadback {
    TunReadback {
        link: true,
        owned_tun: true,
        num_queues: active,
        num_disabled_queues: disabled,
        addresses: Vec::new(),
        routes: Vec::new(),
        rules: Vec::new(),
    }
}

fn released_readback() -> TunReadback {
    TunReadback {
        link: false,
        owned_tun: false,
        ..queue_readback(None, None)
    }
}

fn open_fixture_queue(peers: &mut Vec<UnixStream>) -> io::Result<OwnedFd> {
    let (device, peer) = UnixStream::pair()?;
    peer.set_nonblocking(true)?;
    peers.push(peer);
    Ok(device.into())
}

fn assert_live(peers: &mut [UnixStream]) {
    for peer in peers {
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

fn assert_closed(peers: &mut [UnixStream]) {
    for peer in peers {
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}

fn prepared_fixture_queues(setup: &mut TunSetup, peers: &mut Vec<UnixStream>) -> Vec<TunDevice> {
    let (devices, ()) = setup
        .with_queues(
            |_, _| open_fixture_queue(peers),
            |_, _, _| Ok(IFINDEX),
            |setup, _| {
                let active = Some(u32::from(setup.plan.queues));
                setup.record_queue_counts(&queue_readback(active, Some(0)))
            },
        )
        .unwrap();
    devices
}

#[test]
fn failed_queue_attach_releases_every_descriptor_before_link_readback() {
    for fail_open in [true, false] {
        let (_root, mut setup) = setup(4);
        let receipt = setup.journal.path();
        let attempts = Cell::new(0usize);
        let mut peers = Vec::new();
        let error = setup
            .with_queues(
                |name, flags| {
                    assert_eq!(name, "honk0");
                    assert_live(&mut peers);
                    let queue = attempts.get();
                    attempts.set(queue + 1);
                    let expected = libc::IFF_TUN
                        | libc::IFF_NO_PI
                        | libc::IFF_VNET_HDR
                        | libc::IFF_MULTI_QUEUE;
                    let expected = if queue == 0 {
                        expected | libc::IFF_TUN_EXCL
                    } else {
                        expected
                    };
                    assert_eq!(flags, expected);
                    let recorded: Value =
                        serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
                    let entry = &recorded["resources"][queue];
                    assert_eq!(entry["state"], "intent");
                    assert_eq!(entry["queue"], queue);
                    if queue == 0 {
                        assert_eq!(entry["kind"], "link");
                        assert_eq!(entry["expected_queues"], 4);
                        assert!(entry["observed_counts"].is_null());
                    } else {
                        assert_eq!(entry["kind"], "queue_attach");
                        assert_eq!(entry["ifindex"], IFINDEX);
                    }
                    if fail_open && queue == 2 {
                        Err(io::ErrorKind::PermissionDenied.into())
                    } else {
                        open_fixture_queue(&mut peers)
                    }
                },
                |_, name, multi_queue| {
                    assert_eq!(name, "honk0");
                    assert!(multi_queue);
                    Ok(IFINDEX + u32::from(attempts.get() == 3))
                },
                |_, _| -> anyhow::Result<()> { panic!("partial queues reached route setup") },
            )
            .err()
            .expect("partial queue attachment must fail");
        assert_eq!(attempts.get(), 3);
        let after_attach = stored(&setup.journal);
        assert_eq!(after_attach["resources"].as_array().unwrap().len(), 3);
        assert_eq!(after_attach["resources"][0]["state"], "acknowledged");
        assert_eq!(after_attach["resources"][1]["state"], "acknowledged");
        assert_eq!(
            after_attach["resources"][2]["state"],
            if fail_open { "refused" } else { "removed" }
        );
        let error = setup.abandon(error, |setup| {
            assert_eq!(setup.journal.ifindex, Some(IFINDEX));
            assert_closed(&mut peers);
            Ok(released_readback())
        });
        assert!(error.to_string().contains("attach TUN queue 2"));
        assert!(!receipt.exists());
    }
}

#[test]
fn final_queue_readback_precedes_every_capture_route() {
    for (queues, active, disabled, link, ok) in [
        (3, Some(3), Some(1), true, false),
        (3, Some(2), Some(0), true, false),
        (3, None, None, true, false),
        (3, Some(3), None, true, false),
        (3, Some(3), Some(0), false, false),
        (3, Some(3), Some(0), true, true),
        (1, None, None, true, true),
    ] {
        let (_root, mut setup) = setup(queues);
        let mut peers = Vec::new();
        let devices = prepared_fixture_queues(&mut setup, &mut peers);
        let first_route = setup.journal.entries.len();
        let checked = Cell::new(0);
        let mut writes = Vec::new();
        let result = setup.publish_capture(
            devices.iter(),
            |fd, name, multi_queue| {
                assert_eq!(fd.as_raw_fd(), devices[checked.get()].as_raw_fd());
                assert_eq!(name, "honk0");
                assert_eq!(multi_queue, queues > 1);
                checked.set(checked.get() + 1);
                Ok(IFINDEX)
            },
            |_| {
                assert_eq!(checked.get(), usize::from(queues));
                Ok(TunReadback {
                    link,
                    owned_tun: link,
                    ..queue_readback(active, disabled)
                })
            },
            |_, route| {
                writes.push(*route);
                Ok(())
            },
        );
        assert_eq!(
            writes,
            if ok {
                setup.plan.spec().capture_routes(IFINDEX)
            } else {
                Vec::new()
            },
            "route mutation preceded final readback with {active:?} active, {disabled:?} disabled"
        );
        assert_eq!(result.is_ok(), ok);
        assert_eq!(setup.journal.entries.len(), first_route + writes.len());
        let recorded = stored(&setup.journal);
        let counts = &recorded["resources"][0]["observed_counts"];
        assert_eq!(counts["num_queues"], json!(active));
        assert_eq!(counts["num_disabled_queues"], json!(disabled));
    }
}

#[test]
fn final_descriptor_identity_requires_every_original_queue() {
    let (_root, mut setup) = setup(3);
    let mut peers = Vec::new();
    let devices = prepared_fixture_queues(&mut setup, &mut peers);
    let first_route = setup.journal.entries.len();
    let original = [&devices[0], &devices[1], &devices[2]];
    let repeated = [&devices[0], &devices[1], &devices[1]];
    let reordered = [&devices[0], &devices[2], &devices[1]];
    for (present, wrong_index) in [
        (&original[..2], false),
        (repeated.as_slice(), false),
        (reordered.as_slice(), false),
        (original.as_slice(), true),
    ] {
        let result = setup.publish_capture(
            present.iter().copied(),
            |fd, _, _| {
                let changed = wrong_index && fd.as_raw_fd() == devices[1].as_raw_fd();
                Ok(IFINDEX + u32::from(changed))
            },
            |_| panic!("netlink readback followed invalid FD identity"),
            |_, _| panic!("capture route publication followed invalid FD identity"),
        );
        assert!(result.is_err());
        assert_eq!(setup.journal.entries.len(), first_route);
    }
}

#[test]
fn mid_teardown_error_keeps_containment_until_all_queues_close() {
    let (_root, mut setup) = setup(3);
    let receipt = setup.journal.path();
    let mut peers = Vec::new();
    let mut devices = prepared_fixture_queues(&mut setup, &mut peers);
    let guard = setup.plan.spec().guard_routes()[0];
    let capture_rule = setup.plan.spec().rules()[4];
    setup.mutate(Resource::Route(guard), |_| Ok(())).unwrap();
    setup
        .mutate(Resource::Rule(capture_rule), |_| Ok(()))
        .unwrap();
    let first_route = setup.journal.entries.len();
    setup
        .publish_capture(
            devices.iter(),
            |_, _, _| Ok(IFINDEX),
            |_| Ok(queue_readback(Some(3), Some(0))),
            |_, _| Ok(()),
        )
        .unwrap();
    let routes = setup.plan.spec().capture_routes(IFINDEX);
    // A degraded queue count still permits withdrawal of exact owned routes.
    let mut facts = queue_readback(Some(2), Some(1));
    facts.routes.extend(routes.iter().map(|&route| {
        (
            route.table,
            route.destination,
            route.prefix_len,
            route.metric,
            Some(route),
        )
    }));
    let mut withdrawn = Vec::new();
    let error = setup
        .withdraw_capture(
            |_| Ok(facts),
            |_, route| {
                assert_live(&mut peers);
                withdrawn.push(*route);
                if withdrawn.len() == 2 {
                    Err(MutationError::Unconfirmed(io::ErrorKind::TimedOut.into()))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("remove TUN"));
    assert_eq!(withdrawn, routes[..2]);
    let recorded = stored(&setup.journal);
    assert_eq!(recorded["ambiguous"], true);
    for (offset, state) in ["removed", "removing", "acknowledged"]
        .into_iter()
        .enumerate()
    {
        assert_eq!(recorded["resources"][first_route + offset]["state"], state);
    }
    assert!(
        setup
            .release_link(|_| Ok(queue_readback(Some(3), Some(0))))
            .is_err()
    );
    assert_eq!(stored(&setup.journal), recorded);
    while let Some(device) = devices.pop() {
        drop(device);
    }
    let route = routes[1];
    let mut stale = released_readback();
    stale.routes.push((
        route.table,
        route.destination,
        route.prefix_len,
        route.metric,
        None,
    ));
    assert!(setup.release_link(|_| Ok(stale)).is_err());
    assert_eq!(stored(&setup.journal), recorded);
    setup
        .finish_with_readback(false, |_| {
            assert_closed(&mut peers);
            Ok(released_readback())
        })
        .unwrap();
    let retained: Value = serde_json::from_slice(&std::fs::read(receipt).unwrap()).unwrap();
    assert_eq!(retained["ambiguous"], false);
    for (index, resource) in retained["resources"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            resource["state"],
            if (3..first_route).contains(&index) {
                "acknowledged"
            } else {
                "removed"
            }
        );
    }
}

#[cfg(feature = "packet-ebpf")]
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
        let (mut setup, devices, guarded) = TunSetup::prepare_in(
            &config,
            1,
            root.path(),
            #[cfg(feature = "packet-ebpf")]
            None,
        )
        .unwrap();
        let [device] = <[TunDevice; 1]>::try_from(devices).ok().unwrap();
        for (request, expected) in [(libc::TUNGETVNETHDRSZ, 10), (libc::TUNGETVNETLE, 1)] {
            let mut actual: libc::c_int = -1;
            // SAFETY: both readbacks write one int to actual and device retains its FD.
            assert_eq!(
                unsafe { libc::ioctl(device.as_raw_fd(), request, &mut actual) },
                0
            );
            assert_eq!(actual, expected);
        }
        assert_eq!(
            read_attachment(&device.fd, "honk0", false).unwrap(),
            device.ifindex
        );
        assert!(
            TunDevice::new_auxiliary("honk0").is_err(),
            "cannot adopt an occupied name"
        );
        let final_watch = setup.activate(std::iter::once(&device)).unwrap();
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
        Topology::preflight_tun(&Plan::from_config(&config, 1).unwrap().spec()).unwrap();
    })
    .join()
    .unwrap();
}
