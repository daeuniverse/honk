use super::{ConnectionInfo, Router, geo::GeoSourceSet};
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_ebpf_common::RoutingDecision;
use serde_json::{Value, json};

pub(crate) struct GoldenCase {
    pub label: String,
    pub connection: ConnectionInfo,
    pub decision: RoutingDecision,
    #[cfg(feature = "ebpf")]
    pub generic_port_punt: bool,
}

pub(crate) fn connection() -> ConnectionInfo {
    ConnectionInfo {
        domain: None,
        dst_ip: "192.0.2.9".parse().unwrap(),
        dst_port: 8443,
        src_ip: "192.0.2.2".parse().unwrap(),
        src_port: 40000,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: Some(0),
    }
}

fn sample(change: impl FnOnce(&mut ConnectionInfo)) -> ConnectionInfo {
    let mut value = connection();
    change(&mut value);
    value
}

fn expected(id: Option<usize>, outbound: u32, mark: u32, must: bool) -> RoutingDecision {
    RoutingDecision {
        outbound,
        mark,
        must: must as u32,
        domain_final: 0,
        rule_id: id.map_or(u32::MAX, |id| id as u32),
    }
}

/// Hand-authored hit/miss facts, independent of both evaluators and compiler lowering.
pub(crate) fn fixtures() -> (Router, Vec<GoldenCase>) {
    let mut fields = vec![
        (
            "domain",
            json!(["exact.test", "*.wild.test"]),
            vec![
                (sample(|c| c.domain = Some("exact.test".into())), true),
                (sample(|c| c.domain = Some("a.wild.test".into())), true),
                (sample(|c| c.domain = Some("other.test".into())), false),
                (connection(), false),
            ],
        ),
        (
            "domain_suffix",
            json!(["suffix.test"]),
            vec![
                (sample(|c| c.domain = Some("a.suffix.test".into())), true),
                (sample(|c| c.domain = Some("other.test".into())), false),
                (connection(), false),
            ],
        ),
        (
            "domain_keyword",
            json!(["needle"]),
            vec![
                (sample(|c| c.domain = Some("a-needle-b.test".into())), true),
                (sample(|c| c.domain = Some("other.test".into())), false),
            ],
        ),
        (
            "domain_regex",
            json!([r"^rx[0-9]+\.test$"]),
            vec![
                (sample(|c| c.domain = Some("rx42.test".into())), true),
                (sample(|c| c.domain = Some("rx.test".into())), false),
            ],
        ),
        (
            "ip",
            json!(["10.0.0.0/8", "2001:db8::/32"]),
            vec![
                (sample(|c| c.dst_ip = "10.2.3.4".parse().unwrap()), true),
                (
                    sample(|c| {
                        c.dst_ip = "2001:db8::9".parse().unwrap();
                        c.src_ip = "2001:db8::2".parse().unwrap();
                    }),
                    true,
                ),
                (connection(), false),
            ],
        ),
        (
            "source_ip",
            json!(["172.16.0.0/12", "2001:db8:1::/48"]),
            vec![
                (sample(|c| c.src_ip = "172.31.9.2".parse().unwrap()), true),
                (
                    sample(|c| {
                        c.src_ip = "2001:db8:1::2".parse().unwrap();
                        c.dst_ip = "2001:db8::9".parse().unwrap();
                    }),
                    true,
                ),
                (connection(), false),
            ],
        ),
        (
            "port",
            json!(["80", "100-102", "65535"]),
            vec![
                (sample(|c| c.dst_port = 80), true),
                (sample(|c| c.dst_port = 100), true),
                (sample(|c| c.dst_port = 102), true),
                (sample(|c| c.dst_port = 65535), true),
                (sample(|c| c.dst_port = 99), false),
                (sample(|c| c.dst_port = 103), false),
            ],
        ),
        (
            "source_port",
            json!(["0", "50000-50002"]),
            vec![
                (sample(|c| c.src_port = 0), true),
                (sample(|c| c.src_port = 50000), true),
                (sample(|c| c.src_port = 50002), true),
                (sample(|c| c.src_port = 49999), false),
                (sample(|c| c.src_port = 50003), false),
            ],
        ),
        (
            "protocol",
            json!(["udp"]),
            vec![
                (sample(|c| c.protocol = "udp"), true),
                (connection(), false),
            ],
        ),
        (
            "process_name",
            json!(["curl", "abcdefghijklmnop"]),
            vec![
                (sample(|c| c.process_name = Some("my-curl".into())), true),
                (
                    sample(|c| c.process_name = Some("abcdefghijklmno".into())),
                    true,
                ),
                (
                    sample(|c| c.process_name = Some(format!("{}curl", "\u{fffd}".repeat(11)))),
                    true,
                ),
                (sample(|c| c.process_name = Some("wget".into())), false),
                (connection(), false),
            ],
        ),
        (
            "mac",
            json!(["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]),
            vec![
                (sample(|c| c.mac = Some("00:11:22:33:44:55".into())), true),
                (sample(|c| c.mac = Some("AA:BB:CC:DD:EE:FF".into())), true),
                (sample(|c| c.mac = Some("00:00:00:00:00:00".into())), false),
                (connection(), false),
            ],
        ),
        (
            "geo_ip",
            json!(["lab"]),
            vec![
                (sample(|c| c.dst_ip = "198.51.100.9".parse().unwrap()), true),
                (
                    sample(|c| {
                        c.dst_ip = "2001:db8::9".parse().unwrap();
                        c.src_ip = "2001:db8::2".parse().unwrap();
                    }),
                    true,
                ),
                (connection(), false),
            ],
        ),
        (
            "geosite",
            json!(["lab"]),
            vec![
                (sample(|c| c.domain = Some("GEO.TEST".into())), true),
                (sample(|c| c.domain = Some("a.geo.test".into())), true),
                (sample(|c| c.domain = Some("notgeo.test".into())), false),
                (connection(), false),
            ],
        ),
        (
            "ip_version",
            json!(["6"]),
            vec![
                (
                    sample(|c| {
                        c.dst_ip = "2001:db8::9".parse().unwrap();
                        c.src_ip = "2001:db8::2".parse().unwrap();
                    }),
                    true,
                ),
                (connection(), false),
            ],
        ),
        (
            "dscp",
            json!(["8", "46"]),
            vec![
                (sample(|c| c.dscp = Some(8)), true),
                (sample(|c| c.dscp = Some(46)), true),
                (sample(|c| c.dscp = Some(63)), false),
                (sample(|c| c.dscp = None), false),
            ],
        ),
    ];
    let mut rules = Vec::new();
    let mut cases = Vec::new();
    for (field, values, samples) in fields.drain(..) {
        for negated in [false, true] {
            let id = rules.len();
            let gate = (1000 + id) as u16;
            let mut value =
                Value::Object(serde_json::Map::from_iter([(field.into(), values.clone())]));
            if negated {
                value = json!({"not": value});
            }
            let gate_field = if field == "source_port" {
                "port"
            } else {
                "source_port"
            };
            value[gate_field] = json!([gate.to_string()]);
            let outbound = if negated { "block" } else { "proxy" };
            let mark = 0x200 + id as u32;
            rules.push(RoutingRule {
                name: format!("{field}-{negated}"),
                condition: serde_json::from_value(value).unwrap(),
                outbound: RoutingOutbound::Simple(outbound.into()),
                priority: 0,
                must: false,
                mark,
            });
            for (sample_index, (source, hit)) in samples.iter().enumerate() {
                let mut connection = source.clone();
                if gate_field == "port" {
                    connection.dst_port = gate;
                } else {
                    connection.src_port = gate;
                }
                let matched = *hit != negated;
                cases.push(GoldenCase {
                    label: format!("{field}/{negated}/{sample_index}"),
                    connection,
                    decision: if matched {
                        expected(Some(id), if negated { 1 } else { 2 }, mark, false)
                    } else {
                        expected(None, 0, 0, false)
                    },
                    #[cfg(feature = "ebpf")]
                    generic_port_punt: matched
                        && !negated
                        && matches!(field, "port" | "source_port"),
                });
            }
        }
    }

    struct CompoundCase {
        name: &'static str,
        condition: Value,
        must: bool,
        #[cfg(feature = "ebpf")]
        generic_port_punt: bool,
        samples: Vec<(ConnectionInfo, bool)>,
    }

    let extras = [
        CompoundCase {
            name: "ordinary-domain-alternatives",
            condition: json!({"source_port":["60000"], "domain":["exact.test"], "domain_suffix":["suffix.test"], "domain_keyword":["needle"], "domain_regex":[r"^rx[0-9]+\.test$"]}),
            must: false,
            #[cfg(feature = "ebpf")]
            generic_port_punt: false,
            samples: vec![
                (
                    sample(|c| {
                        c.src_port = 60000;
                        c.domain = Some("exact.test".into());
                    }),
                    true,
                ),
                (
                    sample(|c| {
                        c.src_port = 60000;
                        c.domain = Some("a.suffix.test".into());
                    }),
                    true,
                ),
                (
                    sample(|c| {
                        c.src_port = 60000;
                        c.domain = Some("needle.test".into());
                    }),
                    true,
                ),
                (
                    sample(|c| {
                        c.src_port = 60000;
                        c.domain = Some("rx3.test".into());
                    }),
                    true,
                ),
            ],
        },
        CompoundCase {
            name: "ordinary-geosite-conjunction",
            condition: json!({"source_port":["60001"], "domain":["other.test"], "domain_suffix":["geo.test"], "geosite":["lab"]}),
            must: false,
            #[cfg(feature = "ebpf")]
            generic_port_punt: false,
            samples: vec![
                (
                    sample(|c| {
                        c.src_port = 60001;
                        c.domain = Some("a.geo.test".into());
                    }),
                    true,
                ),
                (
                    sample(|c| {
                        c.src_port = 60001;
                        c.domain = Some("other.test".into());
                    }),
                    false,
                ),
            ],
        },
        CompoundCase {
            name: "ipv6-only-prefix",
            condition: json!({"source_port":["60002"], "ip":["::/0"]}),
            must: false,
            #[cfg(feature = "ebpf")]
            generic_port_punt: false,
            samples: vec![
                (
                    sample(|c| {
                        c.src_port = 60002;
                        c.dst_ip = "2001:db8::9".parse().unwrap();
                        c.src_ip = "2001:db8::2".parse().unwrap();
                    }),
                    true,
                ),
                (sample(|c| c.src_port = 60002), false),
            ],
        },
        CompoundCase {
            name: "destination-specific-port-miss",
            condition: json!({"source_port":["60003"], "ip":["10.1.0.0/16"], "port":["80"]}),
            must: false,
            #[cfg(feature = "ebpf")]
            generic_port_punt: false,
            samples: vec![],
        },
        CompoundCase {
            name: "destination-parent-must",
            condition: json!({"source_port":["60003"], "ip":["10.0.0.0/8"], "port":["443"]}),
            must: true,
            #[cfg(feature = "ebpf")]
            generic_port_punt: false,
            samples: vec![(
                sample(|c| {
                    c.src_port = 60003;
                    c.dst_ip = "10.1.2.3".parse().unwrap();
                    c.dst_port = 443;
                }),
                true,
            )],
        },
        CompoundCase {
            name: "source-specific-port-miss",
            condition: json!({"port":["60004"], "source_ip":["172.16.1.0/24"], "source_port":["80"]}),
            must: false,
            #[cfg(feature = "ebpf")]
            generic_port_punt: false,
            samples: vec![],
        },
        CompoundCase {
            name: "source-parent-port-punt",
            condition: json!({"port":["60004"], "source_ip":["172.16.0.0/12"], "source_port":["443"]}),
            must: false,
            #[cfg(feature = "ebpf")]
            generic_port_punt: true,
            samples: vec![(
                sample(|c| {
                    c.src_port = 443;
                    c.src_ip = "172.16.1.2".parse().unwrap();
                    c.dst_port = 60004;
                }),
                true,
            )],
        },
    ];
    for (index, case) in extras.into_iter().enumerate() {
        let id = rules.len();
        let mark = 0x400 + index as u32;
        rules.push(RoutingRule {
            name: case.name.into(),
            condition: serde_json::from_value(case.condition).unwrap(),
            outbound: RoutingOutbound::Simple("proxy".into()),
            priority: 0,
            must: case.must,
            mark,
        });
        for (sample_index, (connection, hit)) in case.samples.into_iter().enumerate() {
            cases.push(GoldenCase {
                label: format!("{}/{sample_index}", case.name),
                connection,
                decision: if hit {
                    expected(Some(id), 2, mark, case.must)
                } else {
                    expected(None, 0, 0, false)
                },
                #[cfg(feature = "ebpf")]
                generic_port_punt: hit && case.generic_port_punt,
            });
        }
    }
    let priority_id = rules.len();
    for (name, port, priority, outbound, must, mark) in [
        ("priority-late", 60005, 1, "proxy", false, 0x501),
        ("priority-first", 60005, 0, "block", true, 0x502),
        ("tie-first", 60006, 0, "direct", true, 0x503),
        ("tie-later", 60006, 0, "block", false, 0x504),
    ] {
        rules.push(RoutingRule {
            name: name.into(),
            condition: RoutingCondition {
                source_port: vec![port.to_string()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple(outbound.into()),
            priority,
            must,
            mark,
        });
    }
    cases.push(GoldenCase {
        label: "priority".into(),
        connection: sample(|c| {
            c.src_port = 60005;
            c.dst_port = 53;
        }),
        decision: expected(Some(priority_id), 1, 0x502, true),
        #[cfg(feature = "ebpf")]
        generic_port_punt: false,
    });
    cases.push(GoldenCase {
        label: "stable-tie".into(),
        connection: sample(|c| {
            c.src_port = 60006;
            c.dst_port = 53;
        }),
        decision: expected(Some(priority_id + 1), 0, 0x503, true),
        #[cfg(feature = "ebpf")]
        generic_port_punt: false,
    });
    cases.push(GoldenCase {
        label: "fallback".into(),
        connection: connection(),
        decision: expected(None, 0, 0, false),
        #[cfg(feature = "ebpf")]
        generic_port_punt: false,
    });

    // Protobuf fixtures: geosite lab = geo.test suffix; geoip lab = v4 /24 + v6 /32.
    let sources = GeoSourceSet::from_bytes(
        vec![
            10, 19, 10, 3, 108, 97, 98, 18, 12, 8, 2, 18, 8, 103, 101, 111, 46, 116, 101, 115, 116,
        ],
        vec![
            10, 37, 10, 3, 108, 97, 98, 18, 8, 10, 4, 198, 51, 100, 0, 16, 24, 18, 20, 10, 16, 32,
            1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 32,
        ],
    );
    (
        Router::new_with_geo_sources(&rules, "direct", &sources).unwrap(),
        cases,
    )
}

#[test]
fn reference_matches_independent_goldens() {
    let (router, cases) = fixtures();
    for case in cases {
        let observed = router.route_full(&case.connection).map_or_else(
            || expected(None, 0, 0, false),
            |result| {
                expected(
                    Some(result.rule_id as usize),
                    match result.outbound_name {
                        "direct" => 0,
                        "block" => 1,
                        "proxy" => 2,
                        other => panic!("unexpected outbound {other}"),
                    },
                    result.mark,
                    result.must,
                )
            },
        );
        assert_eq!(observed, case.decision, "{}", case.label);
        let bitmap = case
            .connection
            .domain
            .as_deref()
            .and_then(|domain| router.domain_bitmap(domain));
        let mut projected = case.connection.clone();
        projected.domain = None;
        let projected = router.route_full_with_domain_bitmap(&projected, bitmap.as_ref());
        assert_eq!(
            projected.map(|result| (result.rule_id, result.mark, result.must)),
            router.route_full(&case.connection).map(|result| (
                result.rule_id,
                result.mark,
                result.must
            )),
            "{} projection",
            case.label
        );
    }
}
