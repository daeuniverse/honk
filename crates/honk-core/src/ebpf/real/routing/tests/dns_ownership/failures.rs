use super::*;
use aya::Pod;
use aya::maps::{HashMap, MapError, PerCpuArray};

const AUX_MAP_CAPACITY: u32 = 65_536;

fn filler_tuple(index: u32) -> TuplesKey {
    tuple(
        IpAddr::V4(Ipv4Addr::from(0xac10_0000u32 + index)),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 254)),
        9,
        9,
        IPPROTO_UDP,
    )
}

fn fill_hash_map<K: Pod, V: Pod>(
    backend: &mut RealEbpfBackend,
    name: &str,
    key: impl Fn(u32) -> K,
    value: &V,
) {
    let map = backend.bpf_mut().unwrap().map_mut(name).unwrap();
    let mut map = HashMap::<_, K, V>::try_from(map).unwrap();
    for index in 0..AUX_MAP_CAPACITY {
        map.insert(key(index), value, 0).unwrap();
    }
    let error = map.insert(key(AUX_MAP_CAPACITY), value, 0).unwrap_err();
    assert!(
        matches!(
            &error,
            MapError::SyscallError(error)
                if matches!(
                    error.io_error.raw_os_error(),
                    Some(libc::ENOSPC) | Some(libc::E2BIG)
                )
        ),
        "{name} overflow: {error}"
    );
}

fn pressure_rules() -> Vec<honk_config::routing::RoutingRule> {
    let mut rules = vec![rule(
        "native-direct-must-dns",
        RoutingCondition {
            port: vec!["53".into()],
            dscp: vec!["8".into()],
            ..Default::default()
        },
        "direct",
        USER_MARK,
        true,
    )];
    rules.extend(dns_ordering_rules());
    rules
}

fn dns_packet(source: IpAddr, source_port: u16, protocol: u8, dscp: u8) -> Vec<u8> {
    packet(
        source,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)),
        protocol,
        source_port,
        53,
        dscp,
        if protocol == IPPROTO_TCP { 0x02 } else { 0 },
    )
}

fn fragmented_dns_packet(source_port: u16, dscp: u8) -> Vec<u8> {
    let mut frame = dns_packet(
        IpAddr::V4(Ipv4Addr::new(10, 92, 0, 2)),
        source_port,
        IPPROTO_UDP,
        dscp,
    );
    frame[..6].fill(0);
    frame.truncate(14 + 20 + 8);
    frame[16..18].copy_from_slice(&28u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
    frame[24..26].fill(0);
    let checksum = internet_checksum(&[&frame[14..34]]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn assert_staging_readers_released(backend: &RealEbpfBackend) {
    let readers = PerCpuArray::<_, u32>::try_from(
        backend.bpf().unwrap().map("UDP_DECISION_INFLIGHT").unwrap(),
    )
    .unwrap();
    for slot in [0, 1] {
        assert!(
            readers
                .get(&slot, 0)
                .unwrap()
                .iter()
                .all(|count| *count == 0),
            "failed publication must not strand a reload-fence reader"
        );
    }
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn routing_handoff_map_exhaustion_preserves_raw_udp_dns_carriers_and_fails_closed_required_handoffs()
 {
    isolated(|| {
        let (mut backend, _, _listeners) = publish(&pressure_rules());
        let generation = backend.routing_policy_generation();
        fill_hash_map(
            &mut backend,
            "ROUTING_HANDOFF_MAP",
            filler_tuple,
            &RoutingHandoffEntry::default(),
        );
        backend
            .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
            .unwrap();
        for (dscp, expected) in [(0, TC_ACT_SHOT), (46, TC_ACT_OK)] {
            let result = run(
                &backend,
                "lan_ingress_l2",
                &fragmented_dns_packet(47_000 + u16::from(dscp), dscp),
                SkbInput::default(),
            );
            assert_eq!(result.verdict, expected);
            if expected == TC_ACT_OK {
                assert_eq!(
                    UdpDnsRoute::from_nfqueue_mark(result.mark),
                    UdpDnsRoute::new(2, generation)
                );
            }
            assert_staging_readers_released(&backend);
        }

        for (side_index, side) in ["lan_ingress_l2", "wan_egress_l2"].into_iter().enumerate() {
            let source = IpAddr::V4(Ipv4Addr::new(10, 90, side_index as u8, 2));
            let source_port = 45_000 + side_index as u16 * 100;
            let raw = run(
                &backend,
                side,
                &dns_packet(source, source_port, IPPROTO_UDP, 46),
                SkbInput::default(),
            );
            assert_eq!(raw.verdict, TC_ACT_REDIRECT, "{side} raw UDP DNS");
            assert_eq!(
                raw.cb[2],
                UdpDnsRoute::new(2, generation).unwrap().to_mark(),
                "{side} raw UDP DNS carrier"
            );

            for (case_index, (label, protocol, dscp)) in [
                ("controller UDP DNS", IPPROTO_UDP, 0),
                ("raw TCP DNS", IPPROTO_TCP, 46),
                ("controller TCP DNS", IPPROTO_TCP, 0),
            ]
            .into_iter()
            .enumerate()
            {
                let result = run(
                    &backend,
                    side,
                    &dns_packet(source, source_port + case_index as u16 + 1, protocol, dscp),
                    SkbInput::default(),
                );
                assert_eq!(result.verdict, TC_ACT_SHOT, "{side} {label}");
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn redirect_track_exhaustion_fails_closed_redirected_dns_but_preserves_native_direct_must() {
    isolated(|| {
        let (mut backend, _, _listeners) = publish(&pressure_rules());
        fill_hash_map(
            &mut backend,
            "REDIRECT_TRACK",
            |index| RedirectTuple::from_tuples(&filler_tuple(index)),
            &RedirectEntry::default(),
        );
        backend
            .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
            .unwrap();
        for (dscp, expected) in [(0, TC_ACT_SHOT), (46, TC_ACT_SHOT), (8, TC_ACT_OK)] {
            let result = run(
                &backend,
                "lan_ingress_l2",
                &fragmented_dns_packet(48_000 + u16::from(dscp), dscp),
                SkbInput::default(),
            );
            assert_eq!(result.verdict, expected);
            assert_staging_readers_released(&backend);
        }

        for (side_index, side) in ["lan_ingress_l2", "wan_egress_l2"].into_iter().enumerate() {
            let source = IpAddr::V4(Ipv4Addr::new(10, 91, side_index as u8, 2));
            let source_port = 46_000 + side_index as u16 * 100;
            for (case_index, (label, protocol, dscp)) in [
                ("raw UDP DNS", IPPROTO_UDP, 46),
                ("controller UDP DNS", IPPROTO_UDP, 0),
                ("raw TCP DNS", IPPROTO_TCP, 46),
                ("controller TCP DNS", IPPROTO_TCP, 0),
            ]
            .into_iter()
            .enumerate()
            {
                let result = run(
                    &backend,
                    side,
                    &dns_packet(source, source_port + case_index as u16, protocol, dscp),
                    SkbInput::default(),
                );
                assert_eq!(result.verdict, TC_ACT_SHOT, "{side} {label}");
            }

            for (case_index, (label, protocol)) in [
                ("native UDP DNS", IPPROTO_UDP),
                ("native TCP DNS", IPPROTO_TCP),
            ]
            .into_iter()
            .enumerate()
            {
                let result = run(
                    &backend,
                    side,
                    &dns_packet(source, source_port + case_index as u16 + 10, protocol, 8),
                    SkbInput::default(),
                );
                if side_index == 0 {
                    assert_eq!(result.verdict, TC_ACT_OK, "{side} {label}");
                    assert_eq!(
                        result.mark,
                        USER_MARK | CLASSIFIED_MARK,
                        "{side} {label} mark"
                    );
                } else {
                    assert_eq!(
                        result.verdict, TC_ACT_SHOT,
                        "{side} marked direct needs redirect"
                    );
                }
            }
        }
    });
}
