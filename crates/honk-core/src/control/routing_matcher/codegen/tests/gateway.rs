use super::*;
use crate::mode::ModeState;
use crate::routing::{ConnectionInfo, GeoSourceSet};
use honk_ebpf_common::{DATAPATH_FLAG_OFFLOAD_RULE_DIRECT, DomainRouting, LpmKey, OutboundIndex};
use std::net::IpAddr;

const FDS: RoutingMapFds = RoutingMapFds {
    destination_v4: 11,
    destination_v6: 12,
    source_v4: 13,
    source_v6: 14,
    mac: 15,
    domain: 16,
};
const INPUT: usize = 512;
const OUTPUT: usize = 1024;
const MAP_VALUE: usize = 3072;
const DIAL_MODES: [DialMode; 4] = [
    DialMode::Ip,
    DialMode::Domain,
    DialMode::DomainPlus,
    DialMode::DomainPlusPlus,
];

fn load(memory: &[u8], address: usize, width: usize) -> u64 {
    let mut bytes = [0; 8];
    bytes[..width].copy_from_slice(&memory[address..address + width]);
    u64::from_le_bytes(bytes)
}

fn store(memory: &mut [u8], address: usize, value: u64, width: usize) {
    memory[address..address + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

fn store_bitmap(memory: &mut [u8], address: usize, bitmap: DomainRouting) {
    for (word, value) in bitmap.bitmap.into_iter().enumerate() {
        store(memory, address + word * 4, value.into(), 4);
    }
}

fn lpm(entries: &[(LpmKey, DomainRouting)], key: &[u8]) -> Option<DomainRouting> {
    entries
        .iter()
        .filter(|(prefix, _)| {
            let bytes: Vec<_> = prefix
                .data
                .iter()
                .flat_map(|word| word.to_ne_bytes())
                .collect();
            (0..prefix.prefix_len as usize)
                .all(|bit| (bytes[bit / 8] ^ key[4 + bit / 8]) & (0x80 >> (bit % 8)) == 0)
        })
        .max_by_key(|(prefix, _)| prefix.prefix_len)
        .map(|(_, bitmap)| *bitmap)
}

// Executes the emitted instruction subset, including real canonical LPM bitmap lookups.
// This checks decisions without claiming verifier, helper, or kernel execution coverage.
fn execute(
    insns: &[bpf_insn],
    plan: &RoutingPushPlan,
    input: &RoutingInput,
    domain: Option<DomainRouting>,
    gateway: bool,
) -> (i64, RoutingDecision, Vec<i32>) {
    execute_with_pointers(insns, plan, input, domain, gateway, [INPUT, OUTPUT])
}

fn execute_with_pointers(
    insns: &[bpf_insn],
    plan: &RoutingPushPlan,
    input: &RoutingInput,
    domain: Option<DomainRouting>,
    gateway: bool,
    [in_ptr, out_ptr]: [usize; 2],
) -> (i64, RoutingDecision, Vec<i32>) {
    let mut memory = [0xa5; 4096];
    memory[INPUT..INPUT + 128].fill(0);
    for (offset, bytes) in [
        (INPUT_SRC_IP, input.src_ip.as_slice()),
        (INPUT_DST_IP, input.dst_ip.as_slice()),
        (INPUT_MAC, input.mac.as_slice()),
        (INPUT_PNAME, input.pname.as_slice()),
    ] {
        let start = INPUT + offset as usize;
        memory[start..start + bytes.len()].copy_from_slice(bytes);
    }
    for (offset, value) in [
        (INPUT_SRC_PORT, input.src_port),
        (INPUT_DST_PORT, input.dst_port),
        (INPUT_PROTO, input.l4proto),
        (INPUT_VERSION, input.ip_version),
        (INPUT_DSCP, input.dscp),
        (INPUT_PNAME_LEN, input.pname_len),
        (INPUT_FLAGS, input.flags),
    ] {
        store(&mut memory, INPUT + offset as usize, value.into(), 4);
    }
    let original_input = memory[INPUT..INPUT + 128].to_vec();
    let mut registers = [0u64; 11];
    registers[R1 as usize] = in_ptr as u64;
    registers[R2 as usize] = out_ptr as u64;
    if let (true, Some(bitmap)) = (gateway, domain) {
        store_bitmap(&mut memory, OUTPUT + GATEWAY_DNS_BITMAP_OFFSET, bitmap);
        registers[R3 as usize] = GATEWAY_DNS_READY as u64;
    }
    registers[R10 as usize] = 2560;
    let mut calls = Vec::new();
    let mut pc = 0;
    for _ in 0..insns.len() * 2 {
        let (code, dst, src, off, imm) = fields(&insns[pc]);
        let (dst, src) = (dst as usize, src as usize);
        let immediate = imm as i64 as u64;
        let width = match code & 0x18 {
            BPF_B => 1,
            BPF_W => 4,
            BPF_DW => 8,
            _ => panic!("unsupported width in opcode {code:#x}"),
        };
        let mut next = pc + 1;
        match code & 7 {
            BPF_LD => {
                assert_eq!(code, BPF_LD | BPF_DW | BPF_IMM);
                assert_eq!(src, PSEUDO_MAP_FD as usize);
                registers[dst] = imm as u32 as u64;
                next += 1;
            }
            BPF_LDX => {
                let address = registers[src].wrapping_add_signed(off.into()) as usize;
                registers[dst] = load(&memory, address, width);
            }
            BPF_ST | BPF_STX => {
                let address = registers[dst].wrapping_add_signed(off.into()) as usize;
                if gateway {
                    assert!(
                        (OUTPUT..OUTPUT + std::mem::size_of::<KernelRouteOutput>())
                            .contains(&address)
                    );
                    assert!(address + width <= OUTPUT + std::mem::size_of::<KernelRouteOutput>());
                }
                let value = if code & 7 == BPF_ST {
                    immediate
                } else {
                    registers[src]
                };
                store(&mut memory, address, value, width);
            }
            BPF_ALU64 => {
                let value = if code & BPF_X != 0 {
                    registers[src]
                } else {
                    immediate
                };
                match code & 0xf0 {
                    BPF_MOV => registers[dst] = value,
                    0 => registers[dst] = registers[dst].wrapping_add(value),
                    BPF_AND => registers[dst] &= value,
                    BPF_OR => registers[dst] |= value,
                    _ => panic!("unsupported ALU opcode {code:#x}"),
                }
            }
            BPF_JMP => match code & 0xf0 {
                BPF_CALL => {
                    assert_eq!(imm, MAP_LOOKUP_ELEM);
                    let fd = registers[R1 as usize] as i32;
                    calls.push(fd);
                    let address = registers[R2 as usize] as usize;
                    let key = &memory[address..address + 20];
                    let bitmap = match fd {
                        11 => lpm(&plan.facts.destination_v4, key),
                        12 => lpm(&plan.facts.destination_v6, key),
                        13 => lpm(&plan.facts.source_v4, key),
                        14 => lpm(&plan.facts.source_v6, key),
                        15 => lpm(&plan.facts.mac, key),
                        16 => domain,
                        _ => panic!("unexpected map fd {fd}"),
                    };
                    registers[0] = bitmap.map_or(0, |bitmap| {
                        store_bitmap(&mut memory, MAP_VALUE, bitmap);
                        MAP_VALUE as u64
                    });
                    registers[1..=5].fill(0);
                }
                BPF_EXIT => {
                    assert_eq!(&memory[INPUT..INPUT + 128], original_input.as_slice());
                    let field = |offset: i16| load(&memory, OUTPUT + offset as usize, 4) as u32;
                    return (
                        registers[0] as i64,
                        RoutingDecision {
                            outbound: field(OUTBOUND),
                            mark: field(MARK),
                            must: field(MUST),
                            domain_final: field(DOMAIN_FINAL),
                            rule_id: field(RULE_ID),
                            direct_mark_index: field(DIRECT_MARK_INDEX),
                        },
                        calls,
                    );
                }
                op => {
                    let taken = match op {
                        BPF_JA => true,
                        BPF_JEQ => registers[dst] == immediate,
                        BPF_JNE => registers[dst] != immediate,
                        BPF_JGE => registers[dst] >= immediate,
                        BPF_JGT => registers[dst] > immediate,
                        BPF_JSET => registers[dst] & immediate != 0,
                        _ => panic!("unsupported jump opcode {code:#x}"),
                    };
                    if taken {
                        next = (pc as isize + 1 + off as isize) as usize;
                    }
                }
            },
            _ => panic!("unsupported opcode {code:#x}"),
        }
        assert!(next < insns.len(), "program fell off its end");
        pc = next;
    }
    panic!("generated program did not terminate");
}

fn router(policy: &str) -> Router {
    let config =
        honk_config::parser::parse_dae_config(&format!("routing {{\n{policy}\n}}")).unwrap();
    let sources = GeoSourceSet::from_bytes(
        b"\x0a\x13\x0a\x03lab\x12\x0c\x08\x03\x12\x08lab.test".to_vec(),
        vec![
            10, 37, 10, 3, 108, 97, 98, 18, 8, 10, 4, 198, 51, 100, 0, 16, 24, 18, 20, 10, 16, 32,
            1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 32,
        ],
    );
    Router::from_config_with_geo_sources(&config.routing, &sources).unwrap()
}

fn ids() -> std::collections::HashMap<String, u8> {
    std::collections::HashMap::from([
        ("direct".into(), OutboundIndex::Direct as u8),
        ("block".into(), OutboundIndex::Block as u8),
        ("proxy".into(), OutboundIndex::UserBase as u8),
    ])
}

fn sample() -> ConnectionInfo {
    ConnectionInfo {
        domain: None,
        dst_ip: "198.51.100.9".parse().unwrap(),
        dst_port: 443,
        src_ip: "10.0.0.9".parse().unwrap(),
        src_port: 12345,
        protocol: "tcp",
        process_name: None,
        mac: Some("02:00:00:00:00:01".into()),
        dscp: Some(4),
    }
}

fn input(connection: &ConnectionInfo, allow: bool) -> RoutingInput {
    let address = |ip: IpAddr| match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    };
    let mut input = RoutingInput {
        src_ip: address(connection.src_ip),
        dst_ip: address(connection.dst_ip),
        src_port: connection.src_port.into(),
        dst_port: connection.dst_port.into(),
        l4proto: if connection.protocol == "tcp" { 1 } else { 2 },
        ip_version: if connection.dst_ip.is_ipv4() { 1 } else { 2 },
        dscp: connection.dscp.unwrap_or(0).into(),
        flags: if allow {
            ROUTING_INPUT_ALLOW_DIRECT_FINALITY
        } else {
            0
        },
        ..Default::default()
    };
    if let Some(mac) = &connection.mac {
        for (byte, hex) in input.mac[10..].iter_mut().zip(mac.split(':')) {
            *byte = u8::from_str_radix(hex, 16).unwrap();
        }
        input.flags |= ROUTING_INPUT_MAC_PRESENT;
    }
    input
}

fn differential(policy: &str, connection: ConnectionInfo, allow: bool, expected: bool) {
    let router = router(policy);
    let ids = ids();
    for dial in DIAL_MODES {
        let plan = RoutingPushPlan::compile(&router, &ids, dial).unwrap();
        let gateway = emit_gateway_routing_program(&plan, FDS, false).unwrap();
        let tc = emit_routing_program(&plan, FDS).unwrap();
        let canonical_input = input(&connection, allow);
        let mut lan_input = canonical_input;
        lan_input.pname[..5].copy_from_slice(b"rogue");
        lan_input.pname_len = 5;
        let (pass, _, gateway_calls) = execute(&gateway.insns, &plan, &lan_input, None, true);
        assert_eq!(pass, i64::from(expected), "{dial:?}: {policy}");
        assert!(!gateway_calls.contains(&FDS.domain));
        for name in [None, Some("lab.test"), Some("other.test")] {
            let mut endpoint_input = connection.clone();
            endpoint_input.domain = name.map(str::to_owned);
            let bitmap = name.and_then(|name| router.domain_bitmap(name));
            let (status, decision, _) = execute(&tc.insns, &plan, &canonical_input, bitmap, false);
            assert_eq!(status, 0);
            let (endpoint, _) = router.route_action(&endpoint_input);
            if decision.outbound != OutboundIndex::ControlPlaneRouting as u32 {
                assert_eq!(
                    decision.outbound,
                    u32::from(ids[&endpoint.outbound]),
                    "{policy}"
                );
            } else {
                assert_eq!(dial, DialMode::DomainPlusPlus);
                assert_ne!(endpoint.outbound, "direct");
                assert_ne!(endpoint.outbound, "block");
            }
            assert_eq!(decision.must != 0, endpoint.must);
            assert_eq!(decision.mark, endpoint.mark.unwrap_or(0));
            if expected {
                assert_eq!(
                    endpoint.outbound, "direct",
                    "PASS with domain {name:?}: {policy}"
                );
                assert_eq!(decision.outbound, OutboundIndex::Direct as u32);
                assert!(decision.must != 0 || decision.domain_final != 0);
                assert!(endpoint.must || allow && connection.dst_port != 53);
                assert!(!endpoint.mark.is_some_and(|mark| mark != 0));
            }
        }
    }
}

#[test]
fn gateway_ordered_static_direct_is_a_subset_of_tc_and_endpoint() {
    for (policy, allow, pass) in [
        ("default: direct", true, true),
        ("default: direct", false, false),
        ("default: direct(must)", false, true),
        (
            "dport(443) -> block\nl4proto(tcp) -> direct\ndefault: direct",
            true,
            false,
        ),
        (
            "dport(443) -> proxy\nl4proto(tcp) -> direct\ndefault: direct",
            true,
            false,
        ),
        ("domain(lab.test) -> block\ndefault: direct", true, false),
        ("!domain(lab.test) -> block\ndefault: direct", true, false),
        ("domain(geosite:lab) -> block\ndefault: direct", true, false),
        (
            "domain(lab.test) -> block\ndefault: direct(must)",
            true,
            false,
        ),
        (
            "mac(02:00:00:00:00:01) -> direct\ndomain(lab.test) -> block\ndefault: proxy",
            true,
            true,
        ),
        (
            "mac(02:00:00:00:00:01) -> direct\ndomain(lab.test) -> block\ndefault: proxy",
            false,
            false,
        ),
        ("pname(rogue) -> proxy\ndefault: direct", true, true),
        ("!pname(rogue) -> block\ndefault: direct", true, false),
        (
            "!pname(rogue) -> direct\ndomain(lab.test) -> block\ndefault: proxy",
            true,
            true,
        ),
        (
            "dport(443) -> direct(must, mark: 0)\ndefault: proxy",
            false,
            true,
        ),
        (
            "dport(443) -> direct(must, mark: 7)\ndefault: proxy",
            true,
            false,
        ),
    ] {
        differential(policy, sample(), allow, pass);
    }
}

#[test]
fn gateway_ports_exclude_domain_before_a_later_must_direct() {
    for (port, pass) in [(53, true), (80, true), (443, false)] {
        let mut connection = sample();
        connection.dst_port = port;
        differential(
            "domain(lab.test) && dport(443) -> proxy\nl4proto(tcp, udp) -> direct(must)\ndefault: block",
            connection,
            false,
            pass,
        );
    }
    for (port, pass) in [(80, true), (443, false)] {
        let mut connection = sample();
        connection.dst_port = port;
        differential(
            "domain(lab.test) && !dport(80) -> proxy\nl4proto(tcp, udp) -> direct(must)\ndefault: block",
            connection,
            false,
            pass,
        );
    }
}

#[test]
fn gateway_dns_and_missing_mac_are_not_unconditional_direct() {
    for must in [false, true] {
        let mut connection = sample();
        connection.protocol = "udp";
        connection.dst_port = 53;
        differential(
            if must {
                "default: direct(must)"
            } else {
                "default: direct"
            },
            connection,
            true,
            must,
        );
    }
    let mut connection = sample();
    connection.mac = None;
    differential(
        "mac(02:00:00:00:00:01) -> direct\ndefault: proxy",
        connection.clone(),
        true,
        false,
    );
    differential(
        "!mac(02:00:00:00:00:01) -> direct\ndefault: proxy",
        connection,
        true,
        true,
    );
}

#[test]
fn gateway_full_negation_and_inherited_geoip_prefixes() {
    let policy = "!sip(192.0.2.0/24) && !dip(203.0.113.0/24) && !sport(1-100) && !dport(1-100) && !l4proto(udp) && !ipversion(6) && !dscp(8) && !mac(02:00:00:00:00:02) -> direct\ndefault: proxy";
    differential(policy, sample(), true, true);
    let changes: [fn(&mut ConnectionInfo); 8] = [
        |c: &mut ConnectionInfo| c.src_ip = "192.0.2.1".parse().unwrap(),
        |c: &mut ConnectionInfo| c.dst_ip = "203.0.113.1".parse().unwrap(),
        |c: &mut ConnectionInfo| c.src_port = 100,
        |c: &mut ConnectionInfo| c.dst_port = 1,
        |c: &mut ConnectionInfo| c.protocol = "udp",
        |c: &mut ConnectionInfo| c.dst_ip = "2001:db8::9".parse().unwrap(),
        |c: &mut ConnectionInfo| c.dscp = Some(8),
        |c: &mut ConnectionInfo| c.mac = Some("02:00:00:00:00:02".into()),
    ];
    for change in changes {
        let mut connection = sample();
        change(&mut connection);
        differential(policy, connection, true, false);
    }
    for (destination, pass) in [
        ("198.51.100.9", true),
        ("198.51.100.200", false),
        ("198.51.101.9", false),
        ("2001:db8:1::9", true),
        ("2001:db8:2::9", false),
    ] {
        let mut connection = sample();
        connection.dst_ip = destination.parse().unwrap();
        differential(
            "dip(198.51.100.128/25, 2001:db8:2::/48) -> block\ndip(geoip:lab) -> direct\ndefault: proxy",
            connection,
            true,
            pass,
        );
    }
}

#[test]
fn gateway_fingerprint_identifies_full_plan_and_ignores_fd_numbers() {
    let policy_router = router("dip(geoip:lab) -> direct\ndefault: proxy");
    let plan = RoutingPushPlan::compile(&policy_router, &ids(), DialMode::Domain).unwrap();
    let first = emit_gateway_routing_program(&plan, FDS, false).unwrap();
    let second = emit_gateway_routing_program(
        &plan,
        RoutingMapFds {
            destination_v4: 111,
            destination_v6: 112,
            domain: -1,
            ..FDS
        },
        false,
    )
    .unwrap();
    assert_eq!(first.fingerprint, plan.fingerprint);
    assert_eq!(first.fingerprint, second.fingerprint);
    assert!(!first.source_lines.is_empty());
    let changed_mode = RoutingPushPlan::compile(&policy_router, &ids(), DialMode::Ip).unwrap();
    let mut changed_ids = ids();
    changed_ids.insert("proxy".into(), OutboundIndex::UserBase as u8 + 1);
    let changed_binding =
        RoutingPushPlan::compile(&policy_router, &changed_ids, DialMode::Domain).unwrap();
    for changed in [&changed_mode, &changed_binding] {
        assert_eq!(changed.policy_fingerprint, plan.policy_fingerprint);
        assert_ne!(
            emit_gateway_routing_program(changed, FDS, false)
                .unwrap()
                .fingerprint,
            first.fingerprint,
        );
    }
    assert!(emit_gateway_routing_program(&plan, RoutingMapFds { mac: -1, ..FDS }, false).is_err());
}

#[test]
fn gateway_preserves_canonical_nonmust_finality_after_an_excluded_domain_rule() {
    let router = router("domain(lab.test) && dport(80) -> proxy\ndefault: direct");
    for dial in DIAL_MODES {
        let plan = RoutingPushPlan::compile(&router, &ids(), dial).unwrap();
        let static_gateway = emit_gateway_routing_program(&plan, FDS, false).unwrap();
        let shadow_gateway = emit_gateway_routing_program(&plan, FDS, true).unwrap();
        let tc = emit_routing_program(&plan, FDS).unwrap();
        let input = input(&sample(), true);
        let (_, canonical, _) = execute(&tc.insns, &plan, &input, None, false);
        for gateway in [&static_gateway, &shadow_gateway] {
            let (pass, _, _) = execute(&gateway.insns, &plan, &input, None, true);
            assert_eq!(pass != 0, canonical.domain_final != 0);
            assert_eq!(
                pass != 0,
                matches!(dial, DialMode::Ip | DialMode::DomainPlus)
            );
        }
    }
}

#[test]
fn gateway_completes_positive_and_negative_ports_before_looking_up_facts() {
    let router = router(
        "dip(geoip:lab) && sip(10.0.0.0/8) && dport(80, 443-445) && sport(1024-65535) && !dport(444) && !sport(2000-3000) -> direct\ndefault: proxy",
    );
    let plan = RoutingPushPlan::compile(&router, &ids(), DialMode::Ip).unwrap();
    let gateway = emit_gateway_routing_program(&plan, FDS, false).unwrap();
    for (port, source, pass) in [
        (443, 12345, true),
        (445, 12345, true),
        (444, 12345, false),
        (81, 12345, false),
        (443, 2000, false),
    ] {
        let mut connection = sample();
        connection.dst_port = port;
        connection.src_port = source;
        let (decision, _, calls) =
            execute(&gateway.insns, &plan, &input(&connection, true), None, true);
        assert_eq!(decision != 0, pass);
        if pass {
            assert_eq!(calls, [FDS.destination_v4, FDS.source_v4]);
        } else {
            assert!(calls.is_empty());
        }
    }
}

#[test]
fn gateway_generated_jump_overflow_is_an_io_error() {
    let router = router("dport(443) -> direct\ndefault: proxy");
    let mut plan = RoutingPushPlan::compile(&router, &ids(), DialMode::Ip).unwrap();
    plan.rules[0].conditions = vec![KernelCondition {
        not: false,
        predicate: KernelPredicate::DestinationPort(
            (0..9000)
                .map(|port| crate::routing::PortRange {
                    start: port,
                    end: port,
                })
                .collect(),
        ),
    }];
    let error = emit_gateway_routing_program(&plan, FDS, false).unwrap_err();
    assert!(error.to_string().contains("routing jump out of range"));
}

#[test]
fn gateway_dns_shadow_preserves_static_decisions_until_a_reachable_domain() {
    for (policy, port, static_result) in [
        (
            "dport(53) -> direct(must)\ndomain(lab.test) -> block\ndefault: proxy",
            53,
            1,
        ),
        (
            "dport(443) -> proxy\ndomain(lab.test) -> direct(must)\ndefault: block",
            443,
            0,
        ),
        (
            "domain(lab.test) && dport(80) -> block\n!pname(rogue) -> direct(must)\ndefault: proxy",
            53,
            1,
        ),
        (
            "pname(rogue) && !domain(full:lab.test) -> block\ndefault: direct(must)",
            443,
            1,
        ),
    ] {
        let router = router(policy);
        for dial in DIAL_MODES {
            let plan = RoutingPushPlan::compile(&router, &ids(), dial).unwrap();
            let mut connection = sample();
            connection.dst_port = port;
            let mut lan = input(&connection, true);
            lan.pname[..5].copy_from_slice(b"rogue");
            lan.pname_len = 5;
            for enabled in [false, true] {
                let gateway = emit_gateway_routing_program(&plan, FDS, enabled).unwrap();
                let (status, _, calls) = execute(&gateway.insns, &plan, &lan, None, true);
                assert_eq!(status, static_result, "{dial:?} {enabled} {policy}");
                assert!(calls.is_empty());
            }
        }
    }
}

#[test]
fn gateway_dns_shadow_terminal_matches_canonical_action_with_mode_and_port_gates() {
    let ids = ids();
    for action in [
        "direct",
        "direct(must)",
        "direct(must, mark: 0)",
        "direct(must, mark: 7)",
        "block",
        "proxy",
    ] {
        for policy in [
            format!("domain(full:lab.test) -> {action}\ndefault: block"),
            format!("domain(full:lab.test) -> block\nl4proto(tcp) -> {action}\ndefault: proxy"),
            format!("!domain(full:lab.test) -> block\ndefault: {action}"),
        ] {
            let router = router(&policy);
            for dial in DIAL_MODES {
                let plan = RoutingPushPlan::compile(&router, &ids, dial).unwrap();
                let gateway = emit_gateway_routing_program(&plan, FDS, true).unwrap();
                let tc = emit_routing_program(&plan, FDS).unwrap();
                for mode in ["Rule", "Global", "Direct"] {
                    let mode_bits = ModeState::new(mode, "direct").direct_offload_mode_bits();
                    let allow = mode_bits & DATAPATH_FLAG_OFFLOAD_RULE_DIRECT != 0;
                    assert_eq!(allow, mode == "Rule");
                    for port in [53, 443] {
                        let mut connection = sample();
                        connection.dst_port = port;
                        let input = input(&connection, allow);
                        let (first, _, calls) = execute(&gateway.insns, &plan, &input, None, true);
                        assert_eq!(first, i64::from(GATEWAY_ROUTE_NEED_DNS), "{policy}");
                        assert!(calls.is_empty());
                        for name in ["lab.test", "other.test"] {
                            connection.domain = Some(name.into());
                            let bitmap = router.domain_bitmap(name).unwrap();
                            assert_eq!(bitmap == DomainRouting::default(), name == "other.test");
                            let (endpoint, matched) = router.route_action(&connection);
                            let (tc_status, canonical, _) =
                                execute(&tc.insns, &plan, &input, Some(bitmap), false);
                            let (result, decision, calls) =
                                execute(&gateway.insns, &plan, &input, Some(bitmap), true);
                            assert_eq!(tc_status, 0);
                            assert!(calls.is_empty());
                            assert_eq!(decision.rule_id, matched.map_or(u32::MAX, |r| r.rule_id));
                            assert_eq!(decision.outbound, u32::from(ids[&endpoint.outbound]));
                            assert_eq!(decision.mark, endpoint.mark.unwrap_or(0));
                            assert_eq!(decision.must != 0, endpoint.must);
                            assert_eq!(
                                (
                                    decision.rule_id,
                                    decision.outbound,
                                    decision.mark,
                                    decision.must
                                ),
                                (
                                    canonical.rule_id,
                                    canonical.outbound,
                                    canonical.mark,
                                    canonical.must
                                ),
                            );
                            let would_pass = endpoint.outbound == "direct"
                                && endpoint.mark.unwrap_or(0) == 0
                                && port != 53
                                && (endpoint.must || (dial == DialMode::Ip && mode == "Rule"));
                            assert_eq!(
                                result,
                                i64::from(would_pass),
                                "{dial:?} {mode} {port} {name} {policy}",
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn gateway_dns_shadow_uses_the_canonical_domain_bitmap() {
    for (matcher, name) in [
        ("full:exact.test", "exact.test"),
        ("suffix:suffix.test", "sub.suffix.test"),
        (r#"regex: "^rx[0-9]+[.]test$""#, "rx42.test"),
        ("geosite:lab", "lab.test"),
    ] {
        for not in ["", "!"] {
            let router = router(&format!(
                "{not}domain({matcher}) -> direct(must)\ndefault: block"
            ));
            let plan = RoutingPushPlan::compile(&router, &ids(), DialMode::Ip).unwrap();
            let fds = RoutingMapFds { domain: -1, ..FDS };
            let gateway = emit_gateway_routing_program(&plan, fds, true).unwrap();
            let input = input(&sample(), false);
            let (missing, _, calls) = execute(&gateway.insns, &plan, &input, None, true);
            assert_eq!(missing, i64::from(GATEWAY_ROUTE_NEED_DNS));
            assert!(calls.is_empty());
            for (name, matched) in [(name, true), ("other.test", false)] {
                let bitmap = router.domain_bitmap(name).unwrap();
                let (status, _, calls) = execute(&gateway.insns, &plan, &input, Some(bitmap), true);
                assert_eq!(
                    status,
                    i64::from(matched == not.is_empty()),
                    "{matcher} {name}"
                );
                assert!(calls.is_empty());
            }
        }
    }
}

#[test]
fn gateway_dns_shadow_keeps_ready_across_lazy_fact_lookups() {
    let router = router(
        "dip(geoip:lab) && sip(10.0.0.0/8) && mac(02:00:00:00:00:01) && !domain(suffix:test) -> block\n\
         pname(rogue) -> block\n\
         dip(geoip:lab) && sip(10.0.0.0/8) && mac(02:00:00:00:00:01) && !pname(rogue) -> direct(must)\n\
         default: block",
    );
    let plan = RoutingPushPlan::compile(&router, &ids(), DialMode::Ip).unwrap();
    let gateway = emit_gateway_routing_program(&plan, FDS, true).unwrap();
    for (port, expected) in [(53, 0), (443, 1)] {
        let mut connection = sample();
        connection.dst_port = port;
        let mut lan = input(&connection, false);
        lan.pname[..5].copy_from_slice(b"rogue");
        lan.pname_len = 5;
        let (status, _, calls) = execute(&gateway.insns, &plan, &lan, None, true);
        assert_eq!(status, i64::from(GATEWAY_ROUTE_NEED_DNS));
        assert_eq!(calls, [FDS.destination_v4, FDS.source_v4, FDS.mac]);
        let (status, decision, calls) = execute(
            &gateway.insns,
            &plan,
            &lan,
            router.domain_bitmap("lab.test"),
            true,
        );
        assert_eq!(status, expected);
        assert_eq!(decision.rule_id, 2);
        assert_eq!(calls, [FDS.destination_v4, FDS.source_v4, FDS.mac]);
    }
}

#[test]
fn gateway_dns_shadow_without_domains_emits_identical_instructions() {
    let router = router("dip(geoip:lab) -> direct\ndefault: direct(must)");
    let plan = RoutingPushPlan::compile(&router, &ids(), DialMode::Ip).unwrap();
    let disabled = emit_gateway_routing_program(&plan, FDS, false).unwrap();
    let enabled = emit_gateway_routing_program(&plan, FDS, true).unwrap();
    assert!(
        disabled
            .insns
            .iter()
            .map(fields)
            .eq(enabled.insns.iter().map(fields))
    );
}

#[test]
fn gateway_dns_shadow_retains_negative_null_pointer_error_in_both_passes() {
    let router = router("domain(full:lab.test) -> direct(must)\ndefault: block");
    let plan = RoutingPushPlan::compile(&router, &ids(), DialMode::Ip).unwrap();
    let gateway = emit_gateway_routing_program(&plan, FDS, true).unwrap();
    let input = input(&sample(), true);
    for bitmap in [None, router.domain_bitmap("lab.test")] {
        for args in [[0, OUTPUT], [INPUT, 0]] {
            let (status, _, calls) =
                execute_with_pointers(&gateway.insns, &plan, &input, bitmap, true, args);
            assert_eq!(status, -i64::from(libc::EFAULT));
            assert!(calls.is_empty());
        }
    }
}
