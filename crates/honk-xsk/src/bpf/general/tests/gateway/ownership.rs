use super::*;
use crate::{GatewayArbitration, GatewayDnsMaps};
use honk_ebpf_common::xdp_gateway::{HOLD_IDLE_NS, HOLD_MANAGED, NATIVE_PENDING_CAP};
use std::sync::Barrier;
use std::time::Duration;

fn permit(dns: &GatewayDnsMaps, tuple: GatewayKey, export_epoch: u64) {
    let key = GatewayDnsKey {
        realm_id: tuple.realm_id,
        canonical_dst: tuple.dst,
        export_epoch,
        reserved: 0,
    };
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
            conntrack: &fixture.ct,
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
fn two_senders(program: &OwnedFd, ports: [u16; 2]) -> [u32; 2] {
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
            let port = ports[i];
            scope.spawn(move || {
                let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
                unsafe { libc::CPU_SET(cpu, &mut mask) };
                let pinned = unsafe { libc::sched_setaffinity(0, size, &mask) };
                let (_, syn) = tcp(port, 2);
                barrier.wait();
                assert_eq!(pinned, 0, "failed to pin producer to guest CPU {cpu}");
                assert_eq!(unsafe { libc::sched_getcpu() }, cpu as i32);
                run(program, &syn, 0).0
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
    let (key, _) = tcp(47000, 2);
    let dns = GatewayDnsMaps::new(9).unwrap();
    permit(&dns, key, 1);
    let programs = load_dns_fixture(&fixture, &dns, Some(&arb));
    let both = two_senders(&programs.data, [47000, 47000]);
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
    let actions = two_senders(&programs.data, ports);
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
