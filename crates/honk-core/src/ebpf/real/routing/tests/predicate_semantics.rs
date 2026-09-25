use super::{assert_route, decision, input, object, outbound_ids};
use crate::control::routing_matcher::RoutingPushPlan;
use crate::ebpf::EbpfBackend;
use crate::ebpf::real::RealEbpfBackend;
use crate::routing::{ConnectionInfo, GeoSourceSet, Router, golden};
use honk_config::types::DialMode;
use honk_ebpf_common::DaeParam;
use std::collections::HashSet;

fn field(tag: u8, payload: &[u8]) -> Vec<u8> {
    // ponytail: these fixed protobuf messages stay below 128 bytes; use varints if expanded.
    assert!(payload.len() < 128);
    let mut bytes = vec![tag, payload.len() as u8];
    bytes.extend_from_slice(payload);
    bytes
}

fn geo_domain(kind: u8, value: &str, attributes: &[(&str, bool)]) -> Vec<u8> {
    let mut bytes = vec![8, kind];
    bytes.extend(field(18, value.as_bytes()));
    for (key, value) in attributes {
        let mut attribute = field(10, key.as_bytes());
        attribute.extend([16, u8::from(*value)]);
        bytes.extend(field(26, &attribute));
    }
    bytes
}

fn sources() -> GeoSourceSet {
    let mut geosite = Vec::new();
    for (code, domains) in [
        ("FULL", vec![geo_domain(3, "full.test", &[])]),
        ("SUFFIX", vec![geo_domain(2, "suffix.test", &[])]),
        ("KEYWORD", vec![geo_domain(0, "needle", &[])]),
        ("REGEX", vec![geo_domain(1, r"^rx[0-9]+\.test$", &[])]),
        (
            "ATTR",
            vec![
                geo_domain(3, "yes.test", &[("cn", true)]),
                geo_domain(3, "false.test", &[("CN", false)]),
                geo_domain(3, "plain.test", &[]),
                geo_domain(3, "bang.test", &[("!cn", true)]),
            ],
        ),
    ] {
        let mut category = field(10, code.as_bytes());
        for domain in domains {
            category.extend(field(18, &domain));
        }
        geosite.extend(field(10, &category));
    }
    // The same lab IPv4 /24 + IPv6 /32 asset used by golden::fixtures.
    let geoip = vec![
        10, 37, 10, 3, 108, 97, 98, 18, 8, 10, 4, 198, 51, 100, 0, 16, 24, 18, 20, 10, 16, 32, 1,
        13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 32,
    ];
    GeoSourceSet::from_bytes(geosite, geoip)
}

fn sample(change: impl FnOnce(&mut ConnectionInfo)) -> ConnectionInfo {
    let mut connection = golden::connection();
    change(&mut connection);
    connection
}

fn assert_predicate(
    backend: &mut RealEbpfBackend,
    sources: &GeoSourceSet,
    label: &str,
    expression: &str,
    samples: &[(ConnectionInfo, bool)],
) -> usize {
    let config = honk_config::parser::parse_dae_config(&format!(
        "routing {{\n{expression} -> proxy(must)\ndefault: block\n}}"
    ))
    .unwrap();
    let router = Router::from_config_with_geo_sources(&config.routing, sources).unwrap();
    for (index, (connection, hit)) in samples.iter().enumerate() {
        let (action, _) = router.route_action(connection);
        assert_eq!(
            (action.outbound.as_str(), action.must),
            if *hit {
                ("proxy", true)
            } else {
                ("block", false)
            },
            "{label}/{index}: userspace action"
        );
    }
    let has_domain = router.domain_predicate_count() != 0;
    let mut comparisons = 0;
    for mode in [
        DialMode::Ip,
        DialMode::Domain,
        DialMode::DomainPlus,
        DialMode::DomainPlusPlus,
    ] {
        let plan = RoutingPushPlan::compile(&router, &outbound_ids(), mode).unwrap();
        backend.publish_routing_plan(&plan, &[]).unwrap();
        let mut present = HashSet::new();
        for (index, (connection, hit)) in samples.iter().enumerate() {
            let key = crate::ebpf::maps::ip_addr_to_lpm_key(connection.dst_ip);
            if let Some(domain) = connection.domain.as_deref().filter(|_| has_domain) {
                backend
                    .set_domain_ip_bitmap(&key, &router.domain_bitmap(domain).unwrap())
                    .unwrap();
                present.insert(key.data);
            } else if present.remove(&key.data) {
                backend.remove_domain_ip_bitmap(&key).unwrap();
            }
            let domain_final = (!has_domain
                || !matches!(mode, DialMode::Domain | DialMode::DomainPlusPlus)
                || connection.domain.is_some()) as u32;
            let expected = if *hit {
                decision(2, 0, true, domain_final, 0)
            } else {
                decision(1, 0, false, domain_final, u32::MAX)
            };
            assert_route(
                backend,
                &format!("{label}/{mode:?}/{index}"),
                &input(connection),
                expected,
            );
            comparisons += 1;
        }
    }
    comparisons
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn parsed_predicates_match_independent_cases() {
    let sources = sources();
    let mut backend =
        RealEbpfBackend::load_routing_test_fixture(&object(), DaeParam::default()).unwrap();
    let mut comparisons = 0;
    let domain_variants = &[
        (
            "bare-domain-suffix",
            "domain(alias.test)",
            &[
                ("alias.test", true),
                ("a.alias.test", true),
                ("notalias.test", true),
                ("ALIAS.TEST", false),
            ][..],
        ),
        (
            "explicit-domain-suffix",
            "domain(suffix:alias.test)",
            &[
                ("alias.test", true),
                ("a.alias.test", true),
                ("notalias.test", true),
                ("other.test", false),
            ],
        ),
        (
            "question-wildcard",
            "domain(full:q?.wild.test)",
            &[
                ("q1.wild.test", true),
                ("qa.wild.test", true),
                ("q.wild.test", false),
                ("qab.wild.test", false),
            ],
        ),
        (
            "geosite-full",
            "domain(geosite:full)",
            &[("FULL.TEST", true), ("a.full.test", false)],
        ),
        (
            "geosite-domain",
            "domain(geosite:suffix)",
            &[
                ("SUFFIX.TEST", true),
                ("a.suffix.test", true),
                ("notsuffix.test", false),
            ],
        ),
        (
            "geosite-keyword",
            "domain(geosite:keyword)",
            &[
                ("a-needle-b.test", true),
                ("NEEDLE.test", false),
                ("other.test", false),
            ],
        ),
        (
            "geosite-regex",
            "domain(geosite:regex)",
            &[
                ("rx42.test", true),
                ("rx.test", false),
                ("RX42.test", false),
            ],
        ),
        (
            "geosite-attribute-key-presence",
            "domain(geosite:AtTr@Cn)",
            &[
                ("yes.test", true),
                ("false.test", true),
                ("plain.test", false),
                ("bang.test", false),
            ],
        ),
        (
            "geosite-literal-negated-attribute-key",
            "domain(geosite:attr@!cn)",
            &[
                ("bang.test", true),
                ("yes.test", false),
                ("false.test", false),
            ],
        ),
        (
            "geosite-unfiltered-attributes",
            "domain(geosite:attr)",
            &[
                ("yes.test", true),
                ("false.test", true),
                ("plain.test", true),
                ("bang.test", true),
            ],
        ),
        (
            "geosite-unknown-attribute",
            "domain(geosite:attr@missing)",
            &[("yes.test", false)],
        ),
        (
            "geosite-first-at-remainder",
            "domain(geosite:attr@cn@extra)",
            &[("yes.test", false)],
        ),
        (
            "geosite-unknown-category",
            "domain(geosite:missing)",
            &[("yes.test", false)],
        ),
    ];
    for (label, expression, domains) in domain_variants {
        let mut samples = domains
            .iter()
            .map(|(domain, hit)| (sample(|c| c.domain = Some((*domain).into())), *hit))
            .collect::<Vec<_>>();
        samples.push((golden::connection(), false));
        comparisons += assert_predicate(&mut backend, &sources, label, expression, &samples);
    }
    for source in [false, true] {
        let field = if source { "sport" } else { "dport" };
        for (values, endpoints) in [
            (
                "0,1,65535",
                vec![
                    (0, true),
                    (1, true),
                    (65535, true),
                    (2, false),
                    (65534, false),
                ],
            ),
            (
                "0-65535",
                vec![(0, true), (1, true), (32768, true), (65535, true)],
            ),
        ] {
            let samples = endpoints
                .into_iter()
                .map(|(port, hit)| {
                    (
                        sample(|c| {
                            if source {
                                c.src_port = port
                            } else {
                                c.dst_port = port
                            }
                        }),
                        hit,
                    )
                })
                .collect::<Vec<_>>();
            comparisons += assert_predicate(
                &mut backend,
                &sources,
                &format!("{field}-{values}"),
                &format!("{field}({values})"),
                &samples,
            );
        }
    }
    comparisons += assert_predicate(
        &mut backend,
        &sources,
        "dscp-endpoints",
        "dscp(0,63)",
        &[
            (sample(|c| c.dscp = Some(0)), true),
            (sample(|c| c.dscp = Some(63)), true),
            (sample(|c| c.dscp = Some(46)), false),
            (sample(|c| c.dscp = None), false),
        ],
    );
    comparisons += assert_predicate(
        &mut backend,
        &sources,
        "protocol-union",
        "l4proto(tcp,udp)",
        &[
            (golden::connection(), true),
            (sample(|c| c.protocol = "udp"), true),
        ],
    );
    let ipv6 = sample(|c| {
        c.src_ip = "2001:db8::2".parse().unwrap();
        c.dst_ip = "2001:db8::9".parse().unwrap();
    });
    for (expression, v4_hit, v6_hit) in [
        ("ipversion(ipv4)", true, false),
        ("ipversion(ipv6)", false, true),
        ("ipversion(ipv4,ipv6)", true, true),
        ("!ipversion(ipv4)", false, true),
    ] {
        comparisons += assert_predicate(
            &mut backend,
            &sources,
            expression,
            expression,
            &[(golden::connection(), v4_hit), (ipv6.clone(), v6_hit)],
        );
    }
    comparisons += assert_predicate(
        &mut backend,
        &sources,
        "geoip-literal-union",
        "dip(203.0.113.9,geoip:lab)",
        &[
            (sample(|c| c.dst_ip = "203.0.113.9".parse().unwrap()), true),
            (sample(|c| c.dst_ip = "198.51.100.9".parse().unwrap()), true),
            (ipv6, true),
            (golden::connection(), false),
        ],
    );
    comparisons += assert_predicate(
        &mut backend,
        &sources,
        "geoip-private-builtin",
        "dip(geoip:private)",
        &[
            (sample(|c| c.dst_ip = "10.9.8.7".parse().unwrap()), true),
            (
                sample(|c| {
                    c.src_ip = "fd01::2".parse().unwrap();
                    c.dst_ip = "fd01::9".parse().unwrap();
                }),
                true,
            ),
            (golden::connection(), true),
            (sample(|c| c.dst_ip = "8.8.8.8".parse().unwrap()), false),
            (
                sample(|c| {
                    c.src_ip = "2001:4860::2".parse().unwrap();
                    c.dst_ip = "2001:4860::9".parse().unwrap();
                }),
                false,
            ),
        ],
    );
    eprintln!("native routing: {comparisons} parsed complete-decision comparisons");
}
