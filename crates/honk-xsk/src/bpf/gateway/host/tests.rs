use super::super::tests::{auxiliary_tun, require_vm};
use super::*;
use honk_ebpf_common::xdp_gateway::{HOLD_IDLE_NS, HOLD_MANAGED, HOLD_NATIVE};

fn tuple(realm_id: u32, dport: u16) -> GatewayKey {
    GatewayKey {
        realm_id,
        family: 4,
        proto: 17,
        dport: dport.to_be(),
        ..Default::default()
    }
}

#[test]
fn host_realms_reject_reserved_overlapping_and_excess_members_before_map_creation() {
    let physical = [(
        CaptureRealmKey {
            physical_ifindex: 1,
            ..Default::default()
        },
        1,
    )];
    for ids in [&[0][..], &[1], &[2], &[3, 3], &[3, 4, 5, 6, 7]] {
        assert_eq!(
            GatewayMaps::new_with_host(&physical, &[], &[2], ids)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert!(GatewayMaps::new_with_aux(&[], &[], &[1]).is_err());
}

#[test]
#[ignore = "requires disposable VM root and private network namespace"]
fn kernel_host_flow_capacity_charge() {
    require_vm();
    let budget = MemoryBudget::new(128 << 20);
    let physical_realm = (
        CaptureRealmKey {
            physical_ifindex: 1,
            ..Default::default()
        },
        32,
    );
    let maps = GatewayMaps::new_with_host(&[physical_realm], &[], &[], &[1])
        .unwrap()
        .account(&budget)
        .unwrap();
    let fd = maps.host_meta_fd().unwrap();
    let mut info = MapInfo::default();
    object_info(fd, &mut info).unwrap();
    assert_eq!(
        (
            info.kind,
            info.flags,
            info.entries,
            info.key_size,
            info.value_size
        ),
        (
            1,
            0,
            HOST_META_ENTRIES,
            size_of::<GatewayKey>() as u32,
            size_of::<HostFlowMeta>() as u32
        )
    );
    let empty = kernel_memory_bytes(fd).unwrap();
    assert!(empty >= (info.key_size + info.value_size) as usize * HOST_META_ENTRIES as usize);
    assert_eq!(
        maps.object_fds()
            .into_iter()
            .filter(|map| map.as_raw_fd() == fd.as_raw_fd())
            .count(),
        1
    );
    assert_eq!(
        budget.used(),
        maps.object_fds()
            .into_iter()
            .map(|map| kernel_memory_bytes(map).unwrap())
            .sum::<usize>()
            + maps.memory_bytes()
            + 2 * size_of::<usize>()
            + scan::INITIAL_BATCH
                * (3 * size_of::<GatewayKey>()
                    + 2 * size_of::<HostFlowOwner>()
                    + size_of::<HostFlowMeta>())
            + HOST_HOLD_ENTRIES as usize * (size_of::<GatewayKey>() + size_of::<HostFlowOwner>())
            + GATEWAY_FRAGMENT_ENTRIES as usize
                * (size_of::<FragmentKey>() + size_of::<FragmentVerdict>())
    );
    for i in 0..HOST_META_ENTRIES {
        update(
            fd,
            &tuple(1, i as u16),
            &HostFlowMeta {
                stamp: HOLD_MANAGED | (u64::from(i) + 1),
                binding: 1,
                ..Default::default()
            },
            1,
        )
        .unwrap();
    }
    let full = kernel_memory_bytes(fd).unwrap();
    eprintln!(
        "HOST_FLOW_META rows={HOST_META_ENTRIES} preallocated_bytes={empty} full_bytes={full}"
    );
    assert_eq!(full, empty);
    assert!(matches!(
        update(
            fd,
            &tuple(1, HOST_META_ENTRIES as u16),
            &HostFlowMeta::default(),
            1
        )
        .unwrap_err()
        .raw_os_error(),
        Some(libc::E2BIG | libc::ENOSPC)
    ));
    assert_eq!(
        lookup::<_, HostFlowMeta>(fd, &tuple(1, 0))
            .unwrap()
            .unwrap()
            .stamp,
        HOLD_MANAGED | 1
    );
    let direct = maps.host_hold_fd().unwrap();
    object_info(direct, &mut info).unwrap();
    assert_eq!(
        (
            info.kind,
            info.flags,
            info.entries,
            info.key_size,
            info.value_size
        ),
        (
            1,
            0,
            HOST_HOLD_ENTRIES,
            size_of::<GatewayKey>() as u32,
            size_of::<HostFlowOwner>() as u32
        )
    );
    let direct_empty = kernel_memory_bytes(direct).unwrap();
    assert!(
        direct_empty >= (info.key_size + info.value_size) as usize * HOST_HOLD_ENTRIES as usize
    );
    for i in 1..=u64::from(HOST_HOLD_ENTRIES) {
        update(
            direct,
            &tuple(1, (i - 1) as u16),
            &HostFlowOwner {
                stamp: HOLD_NATIVE | i,
                last_seen_ns: 1,
                socket_cookie: i,
                binding: 1,
            },
            1,
        )
        .unwrap();
    }
    let direct_full = kernel_memory_bytes(direct).unwrap();
    eprintln!(
        "HOST_HOLD rows={HOST_HOLD_ENTRIES} preallocated_bytes={direct_empty} full_bytes={direct_full}"
    );
    assert_eq!(direct_full, direct_empty);
    let overflow = GatewayKey {
        sport: 1,
        ..tuple(1, 0)
    };
    assert!(matches!(
        update(direct, &overflow, &HostFlowOwner::default(), 1)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::E2BIG | libc::ENOSPC)
    ));
    let physical = tuple(32, 53);
    maps.insert_hold(&physical, 1).unwrap();
    assert!(maps.lookup_hold(&physical).unwrap().is_some());
    let tcp = maps.host_direct_tcp_fd().unwrap();
    object_info(tcp, &mut info).unwrap();
    assert_eq!(
        (
            info.kind,
            info.flags,
            info.entries,
            info.key_size,
            info.value_size
        ),
        (
            1,
            0,
            HOST_DIRECT_TCP_ENTRIES,
            size_of::<GatewayKey>() as u32,
            size_of::<HostFlowOwner>() as u32
        )
    );
    let tcp_empty = kernel_memory_bytes(tcp).unwrap();
    assert!(
        tcp_empty >= (info.key_size + info.value_size) as usize * HOST_DIRECT_TCP_ENTRIES as usize
    );
    for i in 0..HOST_DIRECT_TCP_ENTRIES {
        let key = GatewayKey {
            proto: 6,
            ..tuple(1, i as u16)
        };
        let row = HostFlowOwner {
            stamp: HOLD_NATIVE | (u64::from(i) + 1),
            last_seen_ns: 1,
            socket_cookie: u64::from(i) + 1,
            binding: 11,
        };
        update(tcp, &key, &row, 1).unwrap();
    }
    let tcp_full = kernel_memory_bytes(tcp).unwrap();
    eprintln!(
        "HOST_DIRECT_TCP rows={HOST_DIRECT_TCP_ENTRIES} preallocated_bytes={tcp_empty} full_bytes={tcp_full}"
    );
    assert_eq!(tcp_full, tcp_empty);
    let extra = GatewayKey {
        proto: 6,
        ..tuple(1, HOST_DIRECT_TCP_ENTRIES as u16)
    };
    assert!(matches!(
        update(tcp, &extra, &HostFlowOwner::default(), 1)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::E2BIG | libc::ENOSPC)
    ));
    drop(maps);
    assert_eq!(budget.used(), 0);
    let ordinary = GatewayMaps::new(
        &[(
            CaptureRealmKey {
                physical_ifindex: 1,
                ..Default::default()
            },
            1,
        )],
        &[],
    )
    .unwrap();
    assert!(ordinary.host_meta_fd().is_none());
    assert!(ordinary.host_hold_fd().is_none());
    assert!(ordinary.host_direct_tcp_fd().is_none());
    assert!(ordinary.host_devices_fd().is_none());
    assert!(ordinary.host_bindings_fd().is_none());
    assert_eq!(ordinary.object_fds().into_iter().count(), 7);
}

#[test]
#[ignore = "requires disposable VM root and private network namespace"]
fn kernel_host_flow_owner_and_drain() {
    require_vm();
    let budget = MemoryBudget::new(128 << 20);
    let maps = GatewayMaps::new_with_host(&[], &[], &[], &[1, 2, 3, 4])
        .unwrap()
        .account(&budget)
        .unwrap();
    let arb = GatewayArbitration::new(9).unwrap();
    let key = tuple(1, 443);
    for realm in 2..=4 {
        assert_eq!(
            GatewayMaps::guard_key(&key),
            GatewayMaps::guard_key(&tuple(realm, 443))
        );
    }
    let (outer_fd, outer) = auxiliary_tun(None);
    let (_inner, inner) = auxiliary_tun(None);
    let pair = Arc::new(AuxDevicePair::new(outer, inner, &budget).unwrap());
    assert!(maps.bind_host_realm(1, 7).is_err());
    maps.bind_aux_realm(&pair, 1).unwrap();
    maps.bind_host_realm(1, 7).unwrap();
    let gate_key = HostBindingKey {
        realm: 1,
        binding: 7,
        reserved: 0,
    };
    let gates = maps.host_bindings_fd().unwrap();
    let mut gate_info = MapInfo::default();
    object_info(pair.object_fds()[1], &mut gate_info).unwrap();
    assert_eq!(lookup(gates, &gate_key).unwrap(), Some(gate_info.id));
    let devices = maps.host_devices_fd().unwrap();
    let mut dev_info = MapInfo::default();
    object_info(pair.object_fds()[0], &mut dev_info).unwrap();
    assert_eq!(lookup(devices, &gate_key).unwrap(), Some(dev_info.id));
    let host_hold = maps.host_hold_fd().unwrap();
    let endpoint = HostFlowOwner {
        binding: 7,
        socket_cookie: 1,
        stamp: HOLD_MANAGED | 1,
        last_seen_ns: 1,
    };
    update(host_hold, &key, &endpoint, 1).unwrap();
    let fd = maps.host_meta_fd().unwrap();
    let mut meta = HostFlowMeta {
        stamp: endpoint.stamp,
        binding: 7,
        socket_cookie: 1,
        pid: 42,
        pname_len: 48,
        ..Default::default()
    };
    meta.pname.fill(b'x');
    update(fd, &key, &meta, 1).unwrap();
    assert_eq!(maps.lookup_host_meta(&arb, &key, 7).unwrap(), None);
    pair.set_open(true).unwrap();
    assert_eq!(maps.lookup_host_meta(&arb, &key, 7).unwrap(), Some(meta));
    for foreign in [tuple(2, 443), tuple(1, 444)] {
        assert_eq!(maps.lookup_host_meta(&arb, &foreign, 7).unwrap(), None);
    }
    assert_eq!(maps.lookup_host_meta(&arb, &key, 8).unwrap(), None);
    for bad in [
        HostFlowMeta {
            stamp: HOLD_MANAGED | 2,
            ..meta
        },
        HostFlowMeta { binding: 8, ..meta },
        HostFlowMeta {
            socket_cookie: 0,
            ..meta
        },
    ] {
        update(fd, &key, &bad, 0).unwrap();
        assert_eq!(maps.lookup_host_meta(&arb, &key, 7).unwrap(), None);
    }
    update(fd, &key, &meta, 0).unwrap();
    let guard = GatewayMaps::guard_key(&key);
    update(arb.guards.as_fd(), &guard, &1u32, 1).unwrap();
    assert_eq!(
        maps.lookup_host_meta(&arb, &key, 7).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    bpf(
        BPF_MAP_DELETE_ELEM,
        &mut elem(arb.guards.as_fd(), &guard, 0, 0),
    )
    .unwrap();

    let direct = tuple(1, 80);
    let direct_hold = HostFlowOwner {
        stamp: HOLD_NATIVE | 2,
        ..endpoint
    };
    assert!(direct_hold.is_direct());
    update(host_hold, &direct, &direct_hold, 1).unwrap();
    let cutoff = endpoint.last_seen_ns + HOLD_REFRESH_NS + FRAGMENT_TTL_NS + HOST_PRIVATE_DELAY_NS;
    let sweep = |retains| maps.retire_host_flows(cutoff + 2, &arb, &budget, move |_| retains);
    maps.request_host_drain(&arb, cutoff).unwrap();
    assert_eq!(maps.host_pending_drain(1, 7).unwrap(), None);
    assert_eq!(sweep(true).unwrap(), 1);
    assert_eq!(
        lookup::<_, HostFlowOwner>(host_hold, &direct).unwrap(),
        None
    );
    assert_eq!(arb.pending(), 0);
    maps.request_host_drain(&arb, cutoff).unwrap();
    maps.request_host_drain(&arb, cutoff + 1).unwrap();
    assert_eq!(maps.host_pending_drain(1, 7).unwrap(), Some(cutoff));
    assert!(maps.host_input_drained(1, 8, cutoff).is_err());
    assert!(maps.host_input_drained(1, 7, cutoff + 1).is_err());
    assert_eq!(sweep(false).unwrap(), 0);
    maps.host_input_drained(1, 7, cutoff).unwrap();
    assert_eq!(sweep(false).unwrap(), 0); // The last legal tail can reach the TUN filter at equality.
    maps.request_host_drain(&arb, cutoff + 1).unwrap();
    maps.host_input_drained(1, 7, cutoff + 1).unwrap();
    assert_eq!(sweep(true).unwrap(), 0); // Source/queued application work survives input drain.
    assert_eq!(sweep(false).unwrap(), 1);
    assert_eq!(lookup::<_, HostFlowMeta>(fd, &key).unwrap(), None);
    assert_eq!(arb.pending(), 0);
    let tcp_fd = maps.host_direct_tcp_fd().unwrap();
    let tcp_key = GatewayKey { proto: 6, ..key };
    let original = HostFlowOwner {
        stamp: HOLD_NATIVE | 41,
        last_seen_ns: 1,
        socket_cookie: 9,
        binding: 7,
    };
    update(tcp_fd, &tcp_key, &original, 1).unwrap();
    assert_eq!(
        lookup::<_, HostFlowOwner>(host_hold, &tcp_key).unwrap(),
        None
    );
    assert!(
        !maps
            .retire_native(tcp_fd, &tcp_key, original, 1 + HOLD_IDLE_NS, &arb)
            .unwrap()
    );
    let recent = HostFlowOwner {
        last_seen_ns: 2,
        ..original
    };
    update(tcp_fd, &tcp_key, &recent, 2).unwrap();
    assert!(
        !maps
            .retire_native(tcp_fd, &tcp_key, original, 5 + HOLD_IDLE_NS, &arb)
            .unwrap()
    );
    let successor = HostFlowOwner {
        stamp: HOLD_NATIVE | 42,
        socket_cookie: 10,
        ..recent
    };
    update(tcp_fd, &tcp_key, &successor, 2).unwrap();
    assert!(
        !maps
            .retire_native(tcp_fd, &tcp_key, recent, 5 + HOLD_IDLE_NS, &arb)
            .unwrap()
    );
    assert_eq!(lookup(tcp_fd, &tcp_key).unwrap(), Some(successor));
    assert_eq!(
        maps.retire_host_flows(cutoff + 2 + HOLD_IDLE_NS, &arb, &budget, |_| true)
            .unwrap(),
        1
    );
    assert_eq!(lookup::<_, HostFlowOwner>(tcp_fd, &tcp_key).unwrap(), None);
    update(
        tcp_fd,
        &tcp_key,
        &HostFlowOwner {
            stamp: HOLD_NATIVE | 43,
            ..successor
        },
        1,
    )
    .unwrap();

    let reused = HostFlowOwner {
        socket_cookie: 2,
        binding: 7,
        stamp: HOLD_MANAGED | 3,
        last_seen_ns: cutoff + 2,
    };
    let mut later = HostFlowMeta {
        stamp: reused.stamp,
        pid: 99,
        socket_cookie: 2,
        ..meta
    };
    update(host_hold, &key, &reused, 1).unwrap();
    update(fd, &key, &later, 1).unwrap();
    assert!(
        !maps
            .retire_endpoint(&key, endpoint, cutoff + 2, &arb, |_| false)
            .unwrap()
    );
    assert_eq!(maps.lookup_host_meta(&arb, &key, 7).unwrap(), Some(later));
    assert!(maps.clear_host_binding(1, 7, &arb, &budget).is_err());
    pair.set_open(false).unwrap();
    assert_eq!(maps.lookup_host_meta(&arb, &key, 7).unwrap(), None);
    maps.unbind_aux_realm(&pair, 1).unwrap();
    assert!(maps.clear_host_binding(1, 8, &arb, &budget).is_err());
    later.binding = 8;
    update(fd, &key, &later, 0).unwrap();
    assert!(maps.clear_host_binding(1, 7, &arb, &budget).is_err());
    assert_eq!(lookup(fd, &key).unwrap(), Some(later));
    later.binding = 7;
    update(fd, &key, &later, 0).unwrap();
    for _ in 0..2 {
        assert_eq!(
            maps.clear_host_binding(1, 7, &arb, &budget)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }
    maps.clear_host_binding(1, 7, &arb, &budget).unwrap();
    assert_eq!(lookup::<_, u32>(gates, &gate_key).unwrap(), None);
    assert_eq!(lookup::<_, u32>(devices, &gate_key).unwrap(), None);
    assert_eq!(lookup::<_, HostFlowOwner>(tcp_fd, &tcp_key).unwrap(), None);
    assert_eq!(lookup::<_, HostFlowOwner>(host_hold, &key).unwrap(), None);
    assert_eq!(lookup::<_, HostFlowMeta>(fd, &key).unwrap(), None);
    maps.bind_aux_realm(&pair, 1).unwrap();
    assert!(maps.bind_host_realm(1, 7).is_err());
    maps.bind_host_realm(1, 8).unwrap();
    assert_eq!(maps.host_pending_drain(1, 8).unwrap(), None);
    assert!(maps.host_input_drained(1, 7, cutoff).is_err());
    pair.set_open(true).unwrap();
    let origin = HostBindingKey {
        binding: 8,
        ..gate_key
    };
    let id: u32 = lookup(devices, &origin).unwrap().unwrap();
    let original_devices = bpf_fd(14, &mut [id, 0u32, 0u32]).unwrap();
    assert_eq!(
        lookup(original_devices.as_fd(), &0u32).unwrap(),
        Some(outer)
    );
    drop(outer_fd);
    let (_replacement, _) = auxiliary_tun(Some(outer));
    assert_eq!(
        lookup::<_, u32>(original_devices.as_fd(), &0u32).unwrap(),
        None
    );
    assert_eq!(
        lookup(original_devices.as_fd(), &1u32).unwrap(),
        Some(inner)
    );
    assert_eq!(lookup(pair.object_fds()[1], &0u32).unwrap(), Some(1u32));
}

#[test]
#[ignore = "requires disposable VM root and private network namespace"]
fn kernel_host_batch_reclaims_short_endpoint_flows() {
    require_vm();
    let budget = MemoryBudget::new(128 << 20);
    let maps = GatewayMaps::new_with_host(&[], &[], &[], &[1, 2])
        .unwrap()
        .account(&budget)
        .unwrap();
    let arb = GatewayArbitration::new(15_000).unwrap();
    let (_outer, outer) = auxiliary_tun(None);
    let (_inner, inner) = auxiliary_tun(None);
    let pair = Arc::new(AuxDevicePair::new(outer, inner, &budget).unwrap());
    maps.bind_aux_realm(&pair, 1).unwrap();
    maps.bind_host_realm(1, 7).unwrap();
    let meta_fd = maps.host_meta_fd().unwrap();
    let host_hold = maps.host_hold_fd().unwrap();
    let mut outstanding = 0usize;
    let mut peak = 0usize;
    let mut retired = 0;
    let retained = tuple(1, 0);
    // Advance the policy clock by one second per turn. Only this test writes rows;
    // neither temporary TUN has a packet producer or queued records.
    for turn in 0..150u16 {
        let now = 1 + u64::from(turn) * 1_000_000_000;
        for i in turn * 100..(turn + 1) * 100 {
            let key = tuple(1, i);
            let stamp = HOLD_MANAGED | (u64::from(i) + 1);
            let hold = HostFlowOwner {
                stamp,
                last_seen_ns: now,
                binding: 7,
                socket_cookie: 0,
            };
            let meta = HostFlowMeta {
                stamp,
                born_ns: now,
                binding: 7,
                ..Default::default()
            };
            update(host_hold, &key, &hold, 1).unwrap();
            update(meta_fd, &key, &meta, 1).unwrap();
        }
        outstanding += 100;
        peak = peak.max(outstanding);
        let removed = maps
            .retire_host_flows(now, &arb, &budget, |key| key == &retained)
            .unwrap();
        assert!(removed <= 2048);
        retired += removed;
        outstanding -= removed;
        maps.request_host_drain(&arb, now).unwrap();
        if let Some(cutoff) = maps.host_pending_drain(1, 7).unwrap() {
            maps.host_input_drained(1, 7, cutoff).unwrap();
        }
    }
    eprintln!("Host batch GC admitted=15000 turns=150 retired={retired} peak_rows={peak}");
    assert!(peak < HOST_META_ENTRIES as usize);
    assert!(retired >= 15_000 - HOST_META_ENTRIES as usize);
    assert_eq!(
        lookup::<_, HostFlowOwner>(host_hold, &retained)
            .unwrap()
            .unwrap()
            .stamp,
        HOLD_MANAGED | 1
    );
    assert!(
        lookup::<_, HostFlowMeta>(meta_fd, &retained)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        lookup::<_, HostFlowOwner>(host_hold, &tuple(1, 1)).unwrap(),
        None
    );
    assert_eq!(
        lookup::<_, HostFlowMeta>(meta_fd, &tuple(1, 1)).unwrap(),
        None
    );

    let (_second_outer, outer2) = auxiliary_tun(None);
    let (_second_inner, inner2) = auxiliary_tun(None);
    let second = Arc::new(AuxDevicePair::new(outer2, inner2, &budget).unwrap());
    maps.bind_aux_realm(&second, 2).unwrap();
    maps.bind_host_realm(2, 8).unwrap();
    let other = tuple(2, 80);
    update(
        host_hold,
        &other,
        &HostFlowOwner {
            stamp: HOLD_NATIVE | 15_001,
            last_seen_ns: 1,
            binding: 8,
            socket_cookie: 11,
        },
        1,
    )
    .unwrap();
    maps.unbind_aux_realm(&pair, 1).unwrap();
    maps.unbind_aux_realm(&second, 2).unwrap();
    let _full_budget = budget.reserve(budget.limit() - budget.used()).unwrap();
    assert_eq!(
        maps.clear_host_binding(1, 7, &arb, &budget)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let still_owned = (0..15_000u16)
        .filter(|&i| {
            lookup::<_, HostFlowOwner>(host_hold, &tuple(1, i))
                .unwrap()
                .is_some()
        })
        .count();
    assert!(outstanding - still_owned <= scan::INITIAL_BATCH);
    assert_ne!(still_owned, 0);
    let second_key = HostBindingKey {
        realm: 2,
        binding: 8,
        reserved: 0,
    };
    let roots = [
        maps.host_bindings_fd().unwrap(),
        maps.host_devices_fd().unwrap(),
    ];
    let original_ids = roots.map(|fd| lookup::<_, u32>(fd, &second_key).unwrap().unwrap());
    assert_eq!(
        maps.clear_host_binding(2, 8, &arb, &budget)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    for (root, original) in roots.into_iter().zip(original_ids) {
        assert_eq!(lookup(root, &second_key).unwrap(), Some(original));
    }
    // The second caller can drive both closures to completion without a retry from the first.
    let mut completed = false;
    for _ in 0..(2 * HOST_HOLD_ENTRIES as usize / scan::INITIAL_BATCH + 8) {
        match maps.clear_host_binding(2, 8, &arb, &budget) {
            Ok(()) => {
                completed = true;
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
            Err(error) => panic!("Host FIFO retirement failed: {error}"),
        }
    }
    assert!(completed);
    for root in roots {
        assert_eq!(lookup::<_, u32>(root, &second_key).unwrap(), None);
    }
    maps.clear_host_binding(1, 7, &arb, &budget).unwrap();
    assert_eq!(lookup::<_, HostFlowOwner>(host_hold, &other).unwrap(), None);
    assert_eq!(lookup::<_, HostFlowMeta>(meta_fd, &retained).unwrap(), None);
}
