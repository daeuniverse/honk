use super::{assert_route, decision, input, object};
use crate::control::routing_matcher::{
    KernelCondition, KernelPredicate, KernelRule, RoutingFactMaps, RoutingPushPlan,
};
use crate::ebpf::EbpfBackend;
use crate::ebpf::maps::LpmKey;
use crate::ebpf::real::RealEbpfBackend;
use crate::routing::golden;
use honk_ebpf_common::DomainRouting;
use std::net::IpAddr;

fn condition(not: bool, predicate: KernelPredicate) -> KernelCondition {
    KernelCondition { not, predicate }
}

fn kernel_rule(
    id: u32,
    conditions: Vec<KernelCondition>,
    outbound: u8,
    mark: u32,
    must: bool,
) -> KernelRule {
    KernelRule {
        id,
        source: format!("readiness-{id}"),
        conditions,
        outbound,
        must,
        mark,
    }
}

fn bitmap(mask: u32) -> DomainRouting {
    let mut value = DomainRouting::default();
    value.bitmap[0] = mask;
    value
}

fn key(bytes: [u8; 16], prefix_len: u32) -> LpmKey {
    LpmKey {
        prefix_len,
        data: std::array::from_fn(|index| {
            u32::from_ne_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())
        }),
    }
}

fn ip_key(value: &str) -> LpmKey {
    let ip: IpAddr = value.parse().unwrap();
    let mut bytes = [0; 16];
    let prefix_len = match ip {
        IpAddr::V4(ip) => {
            bytes[..4].copy_from_slice(&ip.octets());
            32
        }
        IpAddr::V6(ip) => {
            bytes.copy_from_slice(&ip.octets());
            128
        }
    };
    key(bytes, prefix_len)
}

fn mac_key(mac: [u8; 6]) -> LpmKey {
    let mut bytes = [0; 16];
    bytes[10..].copy_from_slice(&mac);
    key(bytes, 128)
}

fn readiness_plan(facts: RoutingFactMaps) -> RoutingPushPlan {
    RoutingPushPlan {
        rules: vec![
            // Each failure edge is deliberately reachable: the scalar gate can
            // fail before any fact, while each fact and the family gate can fail
            // after a different prefix of the fact categories was computed.
            kernel_rule(
                0,
                vec![
                    condition(false, KernelPredicate::Protocol(1)),
                    condition(false, KernelPredicate::DestinationIp(0)),
                    condition(false, KernelPredicate::SourceIp(0)),
                    condition(false, KernelPredicate::Mac(0)),
                    condition(false, KernelPredicate::IpVersion(1)),
                ],
                0,
                0xa00,
                false,
            ),
            kernel_rule(
                1,
                vec![
                    condition(false, KernelPredicate::DestinationIp(1)),
                    condition(false, KernelPredicate::SourceIp(1)),
                    condition(false, KernelPredicate::Mac(1)),
                ],
                2,
                0xa01,
                true,
            ),
            kernel_rule(
                2,
                vec![condition(true, KernelPredicate::DestinationIp(1))],
                1,
                0xa02,
                false,
            ),
            kernel_rule(
                3,
                vec![condition(true, KernelPredicate::SourceIp(1))],
                1,
                0xa03,
                false,
            ),
            kernel_rule(
                4,
                vec![condition(true, KernelPredicate::Mac(1))],
                1,
                0xa04,
                false,
            ),
        ],
        facts,
        fallback: 0,
        features: 0,
        fingerprint: [0; 32],
        has_domain_rules: false,
        domain_predicate_count: 0,
    }
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn fact_readiness_failure_joins_preserve_full_decisions() {
    let all = bitmap(0b11);
    let second_only = bitmap(0b10);
    let facts = RoutingFactMaps {
        destination_v4: vec![
            (ip_key("192.0.2.10"), all),
            (ip_key("192.0.2.11"), second_only),
        ],
        destination_v6: vec![(ip_key("2001:db8::10"), all)],
        source_v4: vec![
            (ip_key("198.51.100.10"), all),
            (ip_key("198.51.100.11"), second_only),
        ],
        source_v6: vec![(ip_key("2001:db8::20"), all)],
        mac: vec![
            (mac_key([2, 0, 0, 0, 0, 10]), all),
            (mac_key([2, 0, 0, 0, 0, 11]), second_only),
            (mac_key([0; 6]), DomainRouting::default()),
        ],
    };
    let plan = readiness_plan(facts);
    let mut backend = RealEbpfBackend::load_routing_test_fixture(&object()).unwrap();
    backend.publish_routing_plan(&plan, &[]).unwrap();

    let mut full = golden::connection();
    full.dst_ip = "192.0.2.10".parse().unwrap();
    full.src_ip = "198.51.100.10".parse().unwrap();
    full.mac = Some("02:00:00:00:00:0a".into());

    let mut scalar_miss = full.clone();
    scalar_miss.protocol = "udp";
    let mut destination_miss = full.clone();
    destination_miss.dst_ip = "192.0.2.11".parse().unwrap();
    let mut source_miss = full.clone();
    source_miss.src_ip = "198.51.100.11".parse().unwrap();
    let mut mac_miss = full.clone();
    mac_miss.mac = Some("02:00:00:00:00:0b".into());
    let mut ipv6 = golden::connection();
    ipv6.dst_ip = "2001:db8::10".parse().unwrap();
    ipv6.src_ip = "2001:db8::20".parse().unwrap();
    ipv6.mac = full.mac.clone();
    let mut absent_mac = full.clone();
    absent_mac.mac = None;
    let mut zero_mac = full.clone();
    zero_mac.mac = Some("00:00:00:00:00:00".into());

    let positive = decision(2, 0xa01, true, 1, 1);
    assert_route(
        &mut backend,
        "IPv4 all-positive first rule",
        &input(&full),
        decision(0, 0xa00, false, 1, 0),
    );

    for (label, connection, expected) in [
        ("scalar failure before first lookup", &scalar_miss, positive),
        (
            "destination failure after destination lookup",
            &destination_miss,
            positive,
        ),
        (
            "source failure after destination/source lookups",
            &source_miss,
            positive,
        ),
        ("MAC failure after all fact categories", &mac_miss, positive),
        (
            "scalar failure after a prior cached path",
            &scalar_miss,
            positive,
        ),
        ("IPv6 family selects IPv6 fact maps", &ipv6, positive),
    ] {
        assert_route(&mut backend, label, &input(connection), expected);
    }

    let mut invalid = input(&full);
    invalid.ip_version = 3;
    assert_route(
        &mut backend,
        "invalid family is an absent destination fact",
        &invalid,
        decision(1, 0xa02, false, 1, 2),
    );
    assert_route(
        &mut backend,
        "absent MAC is a cached NULL negative fact",
        &input(&absent_mac),
        decision(1, 0xa04, false, 1, 4),
    );
    assert_route(
        &mut backend,
        "present all-zero MAC is also a negative fact",
        &input(&zero_mac),
        decision(1, 0xa04, false, 1, 4),
    );
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn fact_readiness_independent_bitmap_states() {
    // Missing, present-zero, first bit, second bit, and both bits must remain
    // independent across categories at every failure join.
    let masks = [0, 0, 1, 2, 3];
    let mut facts = RoutingFactMaps::default();
    for (index, mask) in masks.iter().copied().enumerate().skip(1) {
        let value = bitmap(mask);
        facts
            .destination_v4
            .push((ip_key(&format!("192.0.2.{index}")), value));
        facts
            .source_v4
            .push((ip_key(&format!("198.51.100.{index}")), value));
        facts
            .destination_v6
            .push((ip_key(&format!("2001:db8::{index}")), value));
        facts
            .source_v6
            .push((ip_key(&format!("2001:db9::{index}")), value));
        facts
            .mac
            .push((mac_key([2, 0, 0, 0, 0, index as u8]), value));
    }
    let mut backend = RealEbpfBackend::load_routing_test_fixture(&object()).unwrap();
    backend
        .publish_routing_plan(&readiness_plan(facts), &[])
        .unwrap();
    let mut comparisons = 0;
    for ipv6 in [false, true] {
        for tcp in [false, true] {
            for (destination, destination_bits) in masks.iter().enumerate() {
                for (source, source_bits) in masks.iter().enumerate() {
                    for (mac, mac_bits) in masks.iter().enumerate() {
                        let mut connection = golden::connection();
                        connection.protocol = if tcp { "tcp" } else { "udp" };
                        connection.dst_ip = if ipv6 {
                            format!("2001:db8::{destination}")
                        } else {
                            format!("192.0.2.{destination}")
                        }
                        .parse()
                        .unwrap();
                        connection.src_ip = if ipv6 {
                            format!("2001:db9::{source}")
                        } else {
                            format!("198.51.100.{source}")
                        }
                        .parse()
                        .unwrap();
                        connection.mac = Some(format!("02:00:00:00:00:{mac:02x}"));
                        let common = destination_bits & source_bits & mac_bits;
                        let expected = if tcp && !ipv6 && common & 1 != 0 {
                            decision(0, 0xa00, false, 1, 0)
                        } else if common & 2 != 0 {
                            decision(2, 0xa01, true, 1, 1)
                        } else if destination_bits & 2 == 0 {
                            decision(1, 0xa02, false, 1, 2)
                        } else if source_bits & 2 == 0 {
                            decision(1, 0xa03, false, 1, 3)
                        } else {
                            decision(1, 0xa04, false, 1, 4)
                        };
                        assert_route(
                            &mut backend,
                            &format!(
                                "v6={ipv6}/tcp={tcp}/dst={destination}/src={source}/mac={mac}"
                            ),
                            &input(&connection),
                            expected,
                        );
                        comparisons += 1;
                    }
                }
            }
        }
    }
    eprintln!("readiness: {comparisons} independent bitmap-state decisions");
}
