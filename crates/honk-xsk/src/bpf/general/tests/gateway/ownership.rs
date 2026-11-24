use super::*;
use crate::{GatewayArbitration, GatewayDnsMaps};
use honk_ebpf_common::xdp_gateway::{
    HOLD_IDLE_NS, HOLD_MANAGED, HOLD_NATIVE, HOLD_SEQUENCE_MAX, NATIVE_PENDING_CAP,
};
use std::sync::Barrier;
use std::time::Duration;

fn dns_key(tuple: GatewayKey, export_epoch: u64) -> GatewayDnsKey {
    GatewayDnsKey {
        realm_id: tuple.realm_id,
        canonical_dst: tuple.dst,
        export_epoch,
        reserved: 0,
    }
}

fn permit(dns: &GatewayDnsMaps, tuple: GatewayKey, export_epoch: u64) {
    let key = dns_key(tuple, export_epoch);
    let mut value = GatewayDnsValue {
        valid_before_mono_ns: u64::MAX,
        ..Default::default()
    };
    value.bitmap.bitmap[7] = 1;
    dns.insert(&key, &value).unwrap();
    dns.set_epoch(key.realm_id, key.export_epoch);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_gateway_tcp_dns_ownership() {
    let fixture = Fixture::new();
    let arb = GatewayArbitration::new(0).unwrap();
    let (key, syn) = tcp(46100, 2);
    let dns = GatewayDnsMaps::new(9).unwrap();
    permit(&dns, key, 1);
    let programs = load_dns_fixture(&fixture, &dns, Some(&arb));
    let send = |frame: &[u8]| run(&programs.data, frame, 0).0;
    let hold = |key: &GatewayKey| fixture.maps.lookup_hold(key).unwrap().unwrap();
    let (other_key, other_syn) = tcp(46101, 2);

    // Hold the exact transition key. Only the other tuple may acquire an owner.
    put(arb.guards.as_fd(), &key, &1u32);
    assert_eq!(send(&syn), XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::DropHoldContention), 1);
    assert_eq!(fixture.stat(GatewayReason::DropHoldUnavailable), 0);
    assert_eq!(fixture.maps.lookup_hold(&key).unwrap(), None);
    assert_eq!((arb.pending(), arb.last_issued()), (0, 0));
    assert_eq!(programs.counters().unwrap().per_queue[0], 0);
    assert_eq!(send(&other_syn), XDP_PASS as u32);
    remove(arb.guards.as_fd(), &key); // the losing invocation must leave our guard in place
    assert_eq!(send(&syn), XDP_PASS as u32);
    let stamp = hold(&key).stamp;
    assert!(hold(&key).is_native_pending());
    assert!(hold(&other_key).is_native_pending());
    assert_ne!(stamp, hold(&other_key).stamp);
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1), 2);
    assert_eq!(send(&syn), XDP_PASS as u32);
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1PendingRetry), 1);
    assert_eq!(hold(&key).stamp, stamp);
    assert_eq!(arb.pending(), 2);

    let (_, ack) = tcp(46100, 0x10);
    assert_eq!(send(&ack), XDP_DROP as u32);
    dns.set_epoch(key.realm_id, 2);
    assert_eq!(send(&syn), XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::DropNativePendingConflict), 2);
    assert_eq!(programs.counters().unwrap().per_queue[0], 0);

    // With the epoch withdrawn a fresh tuple is born Endpoint. Reauthorization cannot steal it.
    let (endpoint_key, endpoint_syn) = tcp(46102, 2);
    assert_eq!(send(&endpoint_syn), XDP_DROP as u32); // empty XSK
    let endpoint = hold(&endpoint_key);
    assert_ne!(endpoint.stamp & HOLD_MANAGED, 0);
    assert!(!endpoint.is_native_pending());
    permit(&dns, key, 2);
    assert_eq!(send(&endpoint_syn), XDP_DROP as u32);
    assert_eq!(hold(&endpoint_key).stamp, endpoint.stamp);
    assert_eq!(fixture.stat(GatewayReason::XskNewFlow), 1);
    assert_eq!(fixture.stat(GatewayReason::XskEndpointHold), 1);

    let direct = [
        instruction(MOV_K, 0, 0, 0, 1),
        instruction(EXIT, 0, 0, 0, 0),
    ];
    let next = programs
        .reload_general_gateway(GatewayLoad {
            routing: &direct,
            maps: &fixture.maps,
            conntrack: Some(&fixture.ct),
            dns: None,
            arbitration: Some(&arb),
        })
        .unwrap();
    let after_reload = |frame: &[u8]| run(&next.data, frame, 0).0;
    assert_eq!(after_reload(&tcp(46103, 2).1), XDP_PASS as u32);
    assert_eq!(after_reload(&syn), XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::PassD1), 1);
    assert_eq!(fixture.stat(GatewayReason::DropNativePendingConflict), 3);
    assert_eq!(hold(&key).stamp, stamp);
    assert_eq!(arb.pending(), 2);
    assert_eq!(next.counters().unwrap().per_queue[0], 2);

    insert_conntrack(key);
    for count in 1..=2 {
        assert_eq!(after_reload(&ack), XDP_PASS as u32);
        assert_eq!(fixture.stat(GatewayReason::PassCtOriginal), count);
        assert_eq!(fixture.maps.lookup_hold(&key).unwrap(), None);
        assert_eq!(arb.pending(), 1);
    }
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1), 2);
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1PendingRetry), 1);
    assert_eq!(next.counters().unwrap().per_queue[0], 2);

    let expiry = hold(&other_key).last_seen_ns + HOLD_IDLE_NS;
    let collect = |at| {
        fixture
            .maps
            .retire_if_unretained(at, Duration::from_nanos(HOLD_IDLE_NS), Some(&arb), |key| {
                key == &endpoint_key
            })
            .unwrap()
    };
    assert_eq!(collect(expiry), 0);
    put(arb.guards.as_fd(), &other_key, &1u32);
    assert_eq!(collect(expiry + 1), 0);
    assert_eq!(arb.pending(), 1);
    remove(arb.guards.as_fd(), &other_key);
    assert_eq!(collect(expiry + 1), 1);
    assert_eq!(fixture.maps.lookup_hold(&other_key).unwrap(), None);
    assert_eq!(collect(expiry + 1), 0);
    assert_eq!(arb.pending(), 0);
    assert_eq!(hold(&endpoint_key).stamp, endpoint.stamp);
    assert_eq!(fixture.stat(GatewayReason::HoldGuardReleaseFailed), 0);
}

// TEST_RUN uses queue zero. The barrier and affinity give two real CPU producers, but
// their results only establish terminal ownership, not an overlap inside a BPF instruction.
fn two_senders(program: &OwnedFd, frames: [&[u8]; 2]) -> [u32; 2] {
    let mut allowed: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let size = size_of::<libc::cpu_set_t>();
    assert_eq!(unsafe { libc::sched_getaffinity(0, size, &mut allowed) }, 0);
    let mut cpus =
        (0..libc::CPU_SETSIZE as usize).filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &allowed) });
    let cpus = [
        cpus.next().unwrap(),
        cpus.next().expect("requires two allowed guest CPUs"),
    ];
    let barrier = &Barrier::new(2);
    std::thread::scope(|scope| {
        let workers = std::array::from_fn::<_, 2, _>(|i| {
            let cpu = cpus[i];
            let frame = frames[i];
            scope.spawn(move || {
                let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
                unsafe { libc::CPU_SET(cpu, &mut mask) };
                let pinned = unsafe { libc::sched_setaffinity(0, size, &mask) };
                barrier.wait();
                assert_eq!(pinned, 0, "failed to pin producer to guest CPU {cpu}");
                assert_eq!(unsafe { libc::sched_getcpu() }, cpu as i32);
                run(program, frame, 0).0
            })
        });
        workers.map(|worker| worker.join().unwrap())
    })
}

#[test]
#[ignore = "requires two CPUs and root in a disposable virtme guest private netns"]
fn kernel_gateway_tcp_dns_two_producers() {
    let fixture = Fixture::new();
    let arb = GatewayArbitration::new(0).unwrap();
    let (key, syn) = tcp(47000, 2);
    let dns = GatewayDnsMaps::new(9).unwrap();
    permit(&dns, key, 1);
    let programs = load_dns_fixture(&fixture, &dns, Some(&arb));
    let both = two_senders(&programs.data, [syn.as_slice(); 2]);
    let retries = fixture.stat(GatewayReason::PassDnsD1PendingRetry);
    let busy = fixture.stat(GatewayReason::DropHoldContention);
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1), 1);
    assert_eq!(retries + busy, 1);
    assert_eq!(
        both.iter().filter(|&&r| r == XDP_PASS as u32).count() as u64,
        1 + retries
    );
    assert_eq!(
        both.iter().filter(|&&r| r == XDP_DROP as u32).count() as u64,
        busy
    );
    assert!(
        fixture
            .maps
            .lookup_hold(&key)
            .unwrap()
            .unwrap()
            .is_native_pending()
    );
    assert_eq!((arb.pending(), arb.last_issued()), (1, 1));
    assert_eq!(programs.counters().unwrap().per_queue[0], 0);

    assert_eq!(NATIVE_PENDING_CAP, 8192);
    for port in 10000..10000 + (NATIVE_PENDING_CAP as u16 - 2) {
        assert_eq!(run(&programs.data, &tcp(port, 2).1, 0).0, XDP_PASS as u32);
    }
    assert_eq!(arb.pending(), NATIVE_PENDING_CAP - 1);
    let ports = [47001, 47002];
    let [first, second] = ports.map(|port| tcp(port, 2).1);
    let actions = two_senders(&programs.data, [&first, &second]);
    assert_eq!(arb.pending(), NATIVE_PENDING_CAP);
    assert_eq!(arb.last_issued(), NATIVE_PENDING_CAP + 1);
    for (action, port) in actions.into_iter().zip(ports) {
        // Each CPU has one scratch slot. Both distinct source ports must survive the joined runs.
        assert_eq!(fixture.input(u32::from(port)).dst_port, 443);
        let owner = fixture.maps.lookup_hold(&tcp(port, 2).0).unwrap().unwrap();
        assert_ne!(owner.stamp & HOLD_MANAGED, 0);
        assert_eq!(
            action,
            if owner.is_native_pending() {
                XDP_PASS
            } else {
                XDP_DROP
            } as u32
        );
    }
    assert_ne!(
        actions[0], actions[1],
        "exactly one remaining native credit"
    );
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1), NATIVE_PENDING_CAP);
    assert_eq!(fixture.stat(GatewayReason::DnsNativePendingCapped), 1);
    assert_eq!(fixture.stat(GatewayReason::XskNewFlow), 1);
    assert_eq!(programs.counters().unwrap().per_queue[0], 1);
    assert_eq!(fixture.stat(GatewayReason::DropHoldContention), busy);
    assert_eq!(fixture.stat(GatewayReason::DropHoldUnavailable), 0);
    assert_eq!(fixture.stat(GatewayReason::DropNativePendingConflict), 0);
    assert_eq!(fixture.stat(GatewayReason::HoldInsertFailed), 0);
    assert_eq!(fixture.stat(GatewayReason::HoldGuardReleaseFailed), 0);
}

const IPV4_UDP_OFFSET: usize = 14 + 20;
const IPV6_UDP_OFFSET: usize = 14 + 40;
const UDP_PAYLOAD: &[u8; 16] = b"gateway-udp-test";
const XDP_REDIRECT: u32 = 4;

fn udp_test_key(port: u16, ipv6: bool) -> GatewayKey {
    // Use the isolated daemon smoke topology's client and server addresses.
    let (source, destination) = if ipv6 {
        (
            SocketAddr::from(([0xfd00, 1, 0, 0, 0, 0, 0, 2], port)),
            SocketAddr::from(([0xfd00, 2, 0, 0, 0, 0, 0, 2], 443)),
        )
    } else {
        (
            SocketAddr::from(([192, 0, 2, 2], port)),
            SocketAddr::from(([198, 51, 100, 2], 443)),
        )
    };
    tuple_key(source, destination, 17)
}

fn udp_with_payload(key: GatewayKey) -> Vec<u8> {
    let mut frame = frame_for(key);
    let udp_len = 8 + UDP_PAYLOAD.len();
    if key.family == 4 {
        // The parent builder leaves the optional IPv4 UDP checksum disabled.
        let ip_len = (20 + udp_len) as u16;
        frame[16..18].copy_from_slice(&ip_len.to_be_bytes());
        ipv4_checksum(&mut frame, 20);
        frame[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());
        frame[42..42 + UDP_PAYLOAD.len()].copy_from_slice(UDP_PAYLOAD);
    } else {
        frame.resize(IPV6_UDP_OFFSET + udp_len, 0);
        frame[18..20].copy_from_slice(&(udp_len as u16).to_be_bytes());
        frame[58..60].copy_from_slice(&(udp_len as u16).to_be_bytes());
        frame[60..62].fill(0);
        frame[62..].copy_from_slice(UDP_PAYLOAD);
        let mut pseudo = [0; 40 + 8 + UDP_PAYLOAD.len()];
        pseudo[..32].copy_from_slice(&frame[22..54]);
        pseudo[32..36].copy_from_slice(&(udp_len as u32).to_be_bytes());
        pseudo[39] = 17;
        pseudo[40..].copy_from_slice(&frame[IPV6_UDP_OFFSET..]);
        let sum = checksum(&pseudo);
        let sum = if sum == 0 { u16::MAX } else { sum };
        frame[60..62].copy_from_slice(&sum.to_be_bytes());
    }
    frame
}

fn ipv6_udp_fragment(frame: &mut Vec<u8>, id: u16, offset_and_flags: u16) {
    let mut header = [17, 0, 0, 0, 0, 0, 0, 0];
    header[2..4].copy_from_slice(&offset_and_flags.to_be_bytes());
    header[4..8].copy_from_slice(&u32::from(id).to_be_bytes());
    frame.splice(IPV6_UDP_OFFSET..IPV6_UDP_OFFSET, header);
    let payload_len = (frame.len() - IPV6_UDP_OFFSET) as u16;
    frame[18..20].copy_from_slice(&payload_len.to_be_bytes());
    frame[20] = 44;
}

fn udp_fragment_key(key: GatewayKey, id: u16) -> FragmentKey {
    let wire_id = if key.family == 4 {
        u32::from(id.to_be())
    } else {
        u32::from(id).to_be()
    };
    fragment_key(key, wire_id)
}

fn udp_fragment_pair(key: GatewayKey, id: u16) -> (FragmentKey, Vec<u8>, Vec<u8>) {
    let mut first = udp_with_payload(key);
    let transport = if key.family == 4 {
        IPV4_UDP_OFFSET
    } else {
        IPV6_UDP_OFFSET
    };
    let split = transport + 16;
    let mut tail = Vec::with_capacity(first.len());
    tail.extend_from_slice(&first[..transport]);
    tail.extend_from_slice(&first[split..split + 8]);
    first.truncate(split);
    if key.family == 4 {
        for (frame, offset_and_flags) in [(&mut first, 0x2000), (&mut tail, 2)] {
            let ip_len = (frame.len() - 14) as u16;
            frame[16..18].copy_from_slice(&ip_len.to_be_bytes());
            frame.resize(60, 0);
            ipv4_fragment(frame, id, offset_and_flags);
        }
    } else {
        ipv6_udp_fragment(&mut first, id, 1);
        ipv6_udp_fragment(&mut tail, id, 16);
    }
    (udp_fragment_key(key, id), first, tail)
}

fn fragment_verdict(fixture: &Fixture, key: &FragmentKey) -> Option<u32> {
    let mut value = FragmentVerdict::default();
    match bpf(
        BPF_MAP_LOOKUP_ELEM,
        &mut MapElemAttr {
            map_fd: fixture.maps.fragments.as_raw_fd() as u32,
            reserved: 0,
            key: key as *const _ as u64,
            value: &mut value as *mut _ as u64,
            flags: 0,
        },
    ) {
        Ok(_) => Some(value.verdict),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => None,
        Err(error) => panic!("fragment verdict lookup failed: {error}"),
    }
}

fn hold_stamp(fixture: &Fixture, key: &GatewayKey) -> Option<u64> {
    fixture
        .maps
        .lookup_hold(key)
        .unwrap()
        .map(|hold| hold.stamp)
}

fn expect_gateway_action(
    fixture: &Fixture,
    program: &OwnedFd,
    frame: &[u8],
    action: i32,
    reason: GatewayReason,
) {
    let before = fixture.stat(reason);
    let (actual, _, output) = run(program, frame, 0);
    assert_eq!(actual, action as u32, "{reason:?}");
    assert_eq!(output.as_slice(), frame, "{reason:?}");
    assert_eq!(fixture.stat(reason), before + 1, "{reason:?}");
}

fn one_entry_hash<K, V>(name: &[u8]) -> OwnedFd {
    bpf_fd(
        BPF_MAP_CREATE,
        &mut MapCreateAttr {
            map_type: 1,
            key_size: size_of::<K>() as u32,
            value_size: size_of::<V>() as u32,
            max_entries: 1,
            map_flags: 0,
            inner_map_fd: 0,
            numa_node: 0,
            map_name: object_name(name),
        },
    )
    .unwrap()
}

fn assert_udp_publication_failures() {
    let mut fixture = Fixture::new();
    fixture.maps.hold = one_entry_hash::<GatewayKey, GatewayHold>(b"honk_gw_full_h");
    // A non-LRU hash gives a deterministic publication failure at capacity.
    fixture.maps.fragments = one_entry_hash::<FragmentKey, FragmentVerdict>(b"honk_gw_full_f");
    let arb = GatewayArbitration::new(0).unwrap();
    let dns = GatewayDnsMaps::new(9).unwrap();
    let occupying = udp_test_key(48200, false);
    let candidate = udp_test_key(48201, false);
    permit(&dns, candidate, 1);
    let programs = load_dns_fixture(&fixture, &dns, Some(&arb));
    let expect = |frame: &[u8], reason| {
        expect_gateway_action(&fixture, &programs.data, frame, XDP_DROP, reason);
    };

    let (occupied_fragment, occupying_first, _) = udp_fragment_pair(occupying, 201);
    expect(&occupying_first, GatewayReason::XskNewFlow);
    assert_eq!(hold_stamp(&fixture, &occupying), Some(HOLD_MANAGED | 1));
    assert_eq!(
        fragment_verdict(&fixture, &occupied_fragment),
        Some(XDP_REDIRECT)
    );
    expect(
        &udp_with_payload(candidate),
        GatewayReason::HoldInsertFailed,
    );
    assert_eq!(hold_stamp(&fixture, &candidate), None);
    assert_eq!(hold_stamp(&fixture, &occupying), Some(HOLD_MANAGED | 1));
    assert_eq!((arb.pending(), arb.last_issued()), (0, 2));
    assert_eq!(programs.counters().unwrap().per_queue[0], 1);

    // Free the Endpoint hold while leaving its different fragment ID in the cache.
    remove(fixture.maps.hold.as_fd(), &occupying);
    let (fragment, first, tail) = udp_fragment_pair(candidate, 202);
    expect(&first, GatewayReason::XskNewFlow);
    assert_eq!(fixture.stat(GatewayReason::FragmentVerdictInsertFailed), 1);
    assert_eq!(
        fragment_verdict(&fixture, &occupied_fragment),
        Some(XDP_REDIRECT)
    );
    assert_eq!(fragment_verdict(&fixture, &fragment), None);
    expect(&tail, GatewayReason::FragmentMiss);
    assert_eq!(hold_stamp(&fixture, &candidate), Some(HOLD_MANAGED | 3));
    assert_eq!((arb.pending(), arb.last_issued()), (0, 3));
    assert_eq!(programs.counters().unwrap().per_queue[0], 2);
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1), 0);
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1PendingRetry), 0);
}

#[test]
#[ignore = "requires two CPUs and root in a disposable virtme guest private netns"]
fn kernel_gateway_udp_dns_ownership() {
    assert_udp_publication_failures();

    let fixture = Fixture::new();
    let arb = GatewayArbitration::new(0).unwrap();
    let dns = GatewayDnsMaps::new(9).unwrap();
    let programs = load_dns_fixture(&fixture, &dns, Some(&arb));
    let expect = |frame: &[u8], action, reason| {
        expect_gateway_action(&fixture, &programs.data, frame, action, reason);
    };
    let stamp = |key: &GatewayKey| hold_stamp(&fixture, key);
    let state = || (arb.pending(), arb.last_issued());
    let selections = || programs.counters().unwrap().per_queue[0];

    let missing = udp_test_key(48000, false);
    let zero = udp_test_key(48001, false);
    dns.set_epoch(missing.realm_id, 1);
    expect(
        &udp_with_payload(missing),
        XDP_DROP,
        GatewayReason::XskNewFlow,
    );
    assert_eq!(stamp(&missing), Some(HOLD_MANAGED | 1));
    assert_eq!(state(), (0, 1));
    dns.insert(
        &dns_key(zero, 2),
        &GatewayDnsValue {
            valid_before_mono_ns: u64::MAX,
            ..Default::default()
        },
    )
    .unwrap();
    dns.set_epoch(zero.realm_id, 2);
    expect(&udp_with_payload(zero), XDP_DROP, GatewayReason::XskNewFlow);
    assert_eq!(stamp(&zero), Some(HOLD_MANAGED | 2));
    assert_eq!(state(), (0, 2));
    assert_eq!(selections(), 2);

    let full4 = udp_test_key(48002, false);
    let full6 = udp_test_key(48102, true);
    permit(&dns, full4, 3);
    permit(&dns, full6, 3);
    for (key, sequence) in [(missing, 1), (zero, 2)] {
        expect(
            &udp_with_payload(key),
            XDP_DROP,
            GatewayReason::XskEndpointHold,
        );
        assert_eq!(stamp(&key), Some(HOLD_MANAGED | sequence));
    }

    for (index, (key, empty, atomic_id)) in [
        (full4, false, None),
        (udp_test_key(48003, false), true, None),
        (full6, false, None),
        (udp_test_key(48103, true), true, None),
        (udp_test_key(48104, true), false, Some(301)),
        (udp_test_key(48105, true), true, Some(302)),
    ]
    .into_iter()
    .enumerate()
    {
        let mut frame = if empty {
            frame_for(key)
        } else {
            udp_with_payload(key)
        };
        if let Some(id) = atomic_id {
            ipv6_udp_fragment(&mut frame, id, 0);
        }
        let sequence = 3 + index as u64;
        let native_stamp = Some(HOLD_MANAGED | HOLD_NATIVE | sequence);
        expect(&frame, XDP_PASS, GatewayReason::PassDnsD1);
        assert_eq!(stamp(&key), native_stamp);
        assert_eq!(state(), (sequence - 2, sequence));
        expect(&frame, XDP_PASS, GatewayReason::PassDnsD1PendingRetry);
        assert_eq!(stamp(&key), native_stamp);
        assert_eq!(state(), (sequence - 2, sequence));
        if let Some(id) = atomic_id {
            assert_eq!(fragment_verdict(&fixture, &udp_fragment_key(key, id)), None);
        }
    }
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1), 6);
    assert_eq!(selections(), 4);

    for (pending_key, endpoint_key) in [
        (full4, udp_test_key(48004, false)),
        (full6, udp_test_key(48106, true)),
    ] {
        let (pending, last_issued) = state();
        let before_selections = selections();
        let pending_stamp = stamp(&pending_key);
        let (fragment, first, tail) = udp_fragment_pair(endpoint_key, 101);
        let evaluations = fixture.stat(GatewayReason::D1Evaluated);
        expect(&tail, XDP_DROP, GatewayReason::FragmentMiss);
        assert_eq!(fixture.stat(GatewayReason::D1Evaluated), evaluations);
        assert_eq!(stamp(&endpoint_key), None);
        assert_eq!(fragment_verdict(&fixture, &fragment), None);
        assert_eq!(state(), (pending, last_issued));

        expect(&first, XDP_DROP, GatewayReason::XskNewFlow);
        let endpoint_stamp = Some(HOLD_MANAGED | (last_issued + 1));
        assert_eq!(stamp(&endpoint_key), endpoint_stamp);
        assert_eq!(fragment_verdict(&fixture, &fragment), Some(XDP_REDIRECT));
        let evaluations = fixture.stat(GatewayReason::D1Evaluated);
        expect(&tail, XDP_DROP, GatewayReason::XskFragment);
        assert_eq!(fixture.stat(GatewayReason::D1Evaluated), evaluations);
        expect(
            &udp_with_payload(endpoint_key),
            XDP_DROP,
            GatewayReason::XskEndpointHold,
        );

        let (fragment, first, tail) = udp_fragment_pair(pending_key, 102);
        let retries = fixture.stat(GatewayReason::PassDnsD1PendingRetry);
        expect(&first, XDP_DROP, GatewayReason::DropNativePendingConflict);
        assert_eq!(stamp(&pending_key), pending_stamp);
        assert_eq!(fragment_verdict(&fixture, &fragment), None);
        let evaluations = fixture.stat(GatewayReason::D1Evaluated);
        expect(&tail, XDP_DROP, GatewayReason::FragmentMiss);
        assert_eq!(fixture.stat(GatewayReason::D1Evaluated), evaluations);
        assert_eq!(fixture.stat(GatewayReason::PassDnsD1PendingRetry), retries);
        expect(
            &udp_with_payload(pending_key),
            XDP_PASS,
            GatewayReason::PassDnsD1PendingRetry,
        );
        assert_eq!(stamp(&pending_key), pending_stamp);
        assert_eq!(stamp(&endpoint_key), endpoint_stamp);
        assert_eq!(state(), (pending, last_issued + 1));
        assert_eq!(selections(), before_selections + 3);
    }
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1), 6);

    let key = udp_test_key(48005, false);
    let frame = udp_with_payload(key);
    let (pending, last_issued) = state();
    let retries = fixture.stat(GatewayReason::PassDnsD1PendingRetry);
    let before_selections = selections();
    let mut actions = two_senders(&programs.data, [frame.as_slice(); 2]);
    let retried = fixture.stat(GatewayReason::PassDnsD1PendingRetry) - retries;
    let contended = fixture.stat(GatewayReason::DropHoldContention);
    assert_eq!(retried + contended, 1);
    actions.sort_unstable();
    let second_action = if retried == 1 { XDP_PASS } else { XDP_DROP };
    assert_eq!(actions, [second_action as u32, XDP_PASS as u32]);
    let native_stamp = Some(HOLD_MANAGED | HOLD_NATIVE | (last_issued + 1));
    assert_eq!(stamp(&key), native_stamp);
    assert_eq!(state(), (pending + 1, last_issued + 1));
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1), 7);

    dns.set_epoch(key.realm_id, 4);
    expect(&frame, XDP_DROP, GatewayReason::DropNativePendingConflict);
    assert_eq!(stamp(&key), native_stamp);
    assert_eq!(state(), (pending + 1, last_issued + 1));

    // Confirm the exact tuple through ctnetlink in the default CT zone.
    insert_conntrack(key);
    let (fragment, first, tail) = udp_fragment_pair(key, 103);
    expect(&first, XDP_PASS, GatewayReason::PassCtOriginal);
    assert_eq!(stamp(&key), None);
    assert_eq!(state(), (pending, last_issued + 1));
    assert_eq!(fragment_verdict(&fixture, &fragment), Some(XDP_PASS as u32));
    expect(&tail, XDP_PASS, GatewayReason::PassFragment);
    expect(&frame, XDP_PASS, GatewayReason::PassCtOriginal);
    assert_eq!(stamp(&key), None);
    assert_eq!(state(), (pending, last_issued + 1));
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1), 7);
    assert_eq!(
        fixture.stat(GatewayReason::PassDnsD1PendingRetry),
        retries + retried
    );
    assert_eq!(selections(), before_selections);

    let direct = [
        instruction(MOV_K, 0, 0, 0, 1),
        instruction(EXIT, 0, 0, 0, 0),
    ];
    let static_programs = programs
        .reload_general_gateway(GatewayLoad {
            routing: &direct,
            maps: &fixture.maps,
            conntrack: Some(&fixture.ct),
            dns: Some(&dns),
            arbitration: Some(&arb),
        })
        .unwrap();
    let key = udp_test_key(48107, true);
    let (fragment, first, tail) = udp_fragment_pair(key, 104);
    expect_gateway_action(
        &fixture,
        &static_programs.data,
        &first,
        XDP_PASS,
        GatewayReason::PassD1,
    );
    assert_eq!(fragment_verdict(&fixture, &fragment), Some(XDP_PASS as u32));
    expect_gateway_action(
        &fixture,
        &static_programs.data,
        &tail,
        XDP_PASS,
        GatewayReason::PassFragment,
    );
    assert_eq!(stamp(&key), None);
    assert_eq!(state(), (pending, last_issued + 1));
    assert_eq!(
        static_programs.counters().unwrap().per_queue[0],
        before_selections
    );
    for reason in [
        GatewayReason::WouldPassDns,
        GatewayReason::HoldInsertFailed,
        GatewayReason::HoldRetireFailed,
        GatewayReason::DropHoldUnavailable,
        GatewayReason::HoldGuardReleaseFailed,
    ] {
        assert_eq!(fixture.stat(reason), 0, "{reason:?}");
    }
}

#[test]
#[ignore = "requires two CPUs and root in a disposable virtme guest private netns"]
fn kernel_gateway_udp_dns_quota() {
    let fixture = Fixture::new();
    let arb = GatewayArbitration::new(0).unwrap();
    let dns = GatewayDnsMaps::new(9).unwrap();
    let mut key = udp_test_key(10000, false);
    permit(&dns, key, 1);
    let programs = load_dns_fixture(&fixture, &dns, Some(&arb));
    assert_eq!(NATIVE_PENDING_CAP, 8192);

    // Each tuple occupies the production quota through one ordinary non-live TEST_RUN.
    let mut frame = udp_with_payload(key);
    for sequence in 1..NATIVE_PENDING_CAP {
        let port = 10000 + (sequence - 1) as u16;
        key.sport = port.to_be();
        frame[IPV4_UDP_OFFSET..IPV4_UDP_OFFSET + 2].copy_from_slice(&port.to_be_bytes());
        assert_eq!(
            run(&programs.data, &frame, 0).0,
            XDP_PASS as u32,
            "source port {port}"
        );
        assert_eq!(
            hold_stamp(&fixture, &key),
            Some(HOLD_MANAGED | HOLD_NATIVE | sequence)
        );
    }
    let before_cap = NATIVE_PENDING_CAP - 1;
    assert_eq!((arb.pending(), arb.last_issued()), (before_cap, before_cap));
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1), before_cap);
    assert_eq!(programs.counters().unwrap().per_queue[0], 0);

    let keys = [udp_test_key(49000, false), udp_test_key(49001, false)];
    let [first, second] = keys.map(udp_with_payload);
    let actions = two_senders(&programs.data, [&first, &second]);
    assert_ne!(
        actions[0], actions[1],
        "exactly one remaining native credit"
    );
    let mut sequences = [0; 2];
    for (index, (key, action)) in keys.into_iter().zip(actions).enumerate() {
        let input = fixture.input(u32::from(u16::from_be(key.sport)));
        assert_eq!(
            (input.dst_port, input.l4proto),
            (443, L4ProtoType::Udp as u32)
        );
        let stamp = hold_stamp(&fixture, &key).unwrap();
        let flags = match action as i32 {
            XDP_PASS => HOLD_MANAGED | HOLD_NATIVE,
            XDP_DROP => HOLD_MANAGED,
            _ => panic!("unexpected XDP action {action}"),
        };
        assert_eq!(stamp & !HOLD_SEQUENCE_MAX, flags);
        sequences[index] = stamp & HOLD_SEQUENCE_MAX;
    }
    sequences.sort_unstable();
    assert_eq!(sequences, [NATIVE_PENDING_CAP, NATIVE_PENDING_CAP + 1]);
    assert_eq!(
        (arb.pending(), arb.last_issued()),
        (NATIVE_PENDING_CAP, NATIVE_PENDING_CAP + 1)
    );
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1), NATIVE_PENDING_CAP);
    assert_eq!(fixture.stat(GatewayReason::DnsNativePendingCapped), 1);
    assert_eq!(fixture.stat(GatewayReason::XskNewFlow), 1);
    assert_eq!(programs.counters().unwrap().per_queue[0], 1);

    // The empty XSK map exposes Endpoint selection through the queue counter.
    let fresh = udp_test_key(49002, false);
    expect_gateway_action(
        &fixture,
        &programs.data,
        &udp_with_payload(fresh),
        XDP_DROP,
        GatewayReason::XskNewFlow,
    );
    assert_eq!(
        hold_stamp(&fixture, &fresh),
        Some(HOLD_MANAGED | (NATIVE_PENDING_CAP + 2))
    );
    assert_eq!(
        (arb.pending(), arb.last_issued()),
        (NATIVE_PENDING_CAP, NATIVE_PENDING_CAP + 2)
    );
    assert_eq!(fixture.stat(GatewayReason::PassDnsD1), NATIVE_PENDING_CAP);
    assert_eq!(fixture.stat(GatewayReason::DnsNativePendingCapped), 2);
    assert_eq!(programs.counters().unwrap().per_queue[0], 2);
    for reason in [
        GatewayReason::WouldPassDns,
        GatewayReason::PassDnsD1PendingRetry,
        GatewayReason::DropNativePendingConflict,
        GatewayReason::DropHoldContention,
        GatewayReason::DropHoldUnavailable,
        GatewayReason::HoldInsertFailed,
        GatewayReason::HoldGuardReleaseFailed,
    ] {
        assert_eq!(fixture.stat(reason), 0, "{reason:?}");
    }
}
