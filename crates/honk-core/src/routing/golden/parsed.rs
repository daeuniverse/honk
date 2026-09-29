//! Parsed dae-expression goldens shared by the unprivileged userspace check and
//! the root-gated real-object comparison, so every rule text is proven on both.

use super::sample;
use crate::routing::{ConnectionInfo, GeoSourceSet, Router};

pub(crate) struct ParsedCase {
    pub label: String,
    pub expression: String,
    pub samples: Vec<(ConnectionInfo, bool)>,
}

impl ParsedCase {
    fn new(label: impl Into<String>, expression: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            expression: expression.into(),
            samples: Vec::new(),
        }
    }

    fn domains(self, domains: &[(&str, bool)]) -> Self {
        self.values(set_domain, domains)
    }

    fn destinations(self, destinations: &[(&str, bool)]) -> Self {
        self.values(set_destination, destinations)
    }

    fn values(mut self, set: Setter, values: &[(&str, bool)]) -> Self {
        for &(value, hit) in values {
            self = self.with(hit, |c| set(c, value));
        }
        self
    }

    fn with(mut self, hit: bool, change: impl FnOnce(&mut ConnectionInfo)) -> Self {
        self.samples.push((sample(change), hit));
        self
    }

    /// `-> proxy(must)` with `default: block`, so a hit and a miss differ in
    /// both outbound and `must`.
    pub fn router(&self, sources: &GeoSourceSet) -> Router {
        let config = honk_config::parser::parse_dae_config(&format!(
            "routing {{\n{} -> proxy(must)\ndefault: block\n}}",
            self.expression
        ))
        .unwrap_or_else(|error| panic!("{}: {error}", self.label));
        Router::from_config_with_geo_sources(&config.routing, sources).unwrap()
    }
}

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

pub(crate) fn sources() -> GeoSourceSet {
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

type Setter = fn(&mut ConnectionInfo, &str);
/// `(label, argument, sample)`: the sample is matched by that argument alone.
type Kind = (&'static str, &'static str, &'static str);

fn set_domain(connection: &mut ConnectionInfo, domain: &str) {
    connection.domain = Some(domain.into());
}

fn set_destination(connection: &mut ConnectionInfo, destination: &str) {
    connection.dst_ip = destination.parse().unwrap();
    if connection.dst_ip.is_ipv6() {
        connection.src_ip = "fd00::2".parse().unwrap();
    }
}

const DOMAIN_KINDS: &[Kind] = &[
    ("bare", "alias.test", "a.alias.test"),
    ("suffix", "suffix:plain.test", "a.plain.test"),
    ("full", "full:exact.test", "exact.test"),
    ("keyword", "keyword:kw", "a-kw-b.test"),
    ("regex", r"regex:^re[0-9]+\.test$", "re7.test"),
    ("geosite-full", "geosite:full", "full.test"),
    ("geosite-suffix", "geosite:suffix", "a.suffix.test"),
    ("geosite-keyword", "geosite:keyword", "a-needle-b.test"),
    ("geosite-regex", "geosite:regex", "rx42.test"),
];
const DOMAIN_MISS: &str = "miss.example";

// geoip:private also covers the TEST-NET ranges, so lab's exclusive sample is v6.
const DESTINATION_KINDS: &[Kind] = &[
    ("v4-cidr", "45.0.0.0/16", "45.0.7.7"),
    ("v4-host", "8.8.4.4", "8.8.4.4"),
    ("v6-cidr", "2001:db9::/32", "2001:db9::5"),
    ("v6-host", "2606:4700::1111", "2606:4700::1111"),
    ("geoip-lab", "geoip:lab", "2001:db8::9"),
    ("geoip-private", "geoip:private", "10.9.8.7"),
];
const DESTINATION_MISSES: &[&str] = &["8.8.8.8", "2606:4700::1"];

pub(crate) fn cases() -> Vec<ParsedCase> {
    let mut cases = single_domain_cases();
    cases.extend(
        union_cases("domain", DOMAIN_KINDS, &[DOMAIN_MISS], set_domain)
            .into_iter()
            .map(|case| {
                // An unknown domain is "not x", so only a negated call matches.
                let negated = case.expression.starts_with('!');
                case.with(negated, |_| {})
            }),
    );
    cases.extend(union_cases(
        "dip",
        DESTINATION_KINDS,
        DESTINATION_MISSES,
        set_destination,
    ));
    cases.extend(destination_overlap_cases());
    cases.extend(cross_function_cases());
    cases.extend(scalar_cases());
    cases
}

fn single_domain_cases() -> Vec<ParsedCase> {
    [
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
    ]
    .into_iter()
    .map(|(label, expression, domains)| {
        ParsedCase::new(label, expression)
            .domains(domains)
            .with(false, |_| {})
    })
    .collect()
}

/// Every pair of argument kinds inside one call, and all kinds together, plain
/// and negated: one call is a union, so each member's own sample hits and only
/// the shared misses fail.
fn union_cases(call: &str, kinds: &[Kind], misses: &[&str], set: Setter) -> Vec<ParsedCase> {
    let mut groups = Vec::new();
    for (index, first) in kinds.iter().enumerate() {
        for second in &kinds[index + 1..] {
            groups.push(vec![first, second]);
        }
    }
    groups.push(kinds.iter().collect());
    let mut cases = Vec::new();
    for members in groups {
        let label = members.iter().map(|kind| kind.0).collect::<Vec<_>>();
        let arguments = members.iter().map(|kind| kind.1).collect::<Vec<_>>();
        for negated in [false, true] {
            let bang = if negated { "!" } else { "" };
            let hits = members.iter().map(|kind| (kind.2, !negated));
            let misses = misses.iter().map(|miss| (*miss, negated));
            cases.push(
                ParsedCase::new(
                    format!("{bang}{call}:{}", label.join("+")),
                    format!("{bang}{call}({})", arguments.join(", ")),
                )
                .values(set, &hits.chain(misses).collect::<Vec<_>>()),
            );
        }
    }
    cases
}

/// Literal prefixes nested in, equal to, or covering geoip prefixes, within one
/// call and across a positive and a negated call.
fn destination_overlap_cases() -> Vec<ParsedCase> {
    vec![
        ParsedCase::new("cidr-inside-geoip", "dip(198.51.100.128/25, geoip:lab)").destinations(&[
            ("198.51.100.9", true),
            ("198.51.100.200", true),
            ("2001:db8::9", true),
            ("198.51.101.1", false),
        ]),
        ParsedCase::new("geoip-inside-cidr", "dip(198.51.0.0/16, geoip:lab)").destinations(&[
            ("198.51.7.7", true),
            ("198.51.100.9", true),
            ("198.52.0.1", false),
        ]),
        ParsedCase::new("cidr-equal-to-geoip", "dip(198.51.100.0/24, geoip:lab)").destinations(&[
            ("198.51.100.9", true),
            ("2001:db8::9", true),
            ("198.51.101.1", false),
        ]),
        ParsedCase::new("default-route-and-geoip", "dip(0.0.0.0/0, geoip:lab)").destinations(&[
            ("8.8.8.8", true),
            ("2001:db8::9", true),
            ("2606:4700::1", false),
        ]),
        ParsedCase::new(
            "unknown-geoip-keeps-cidr",
            "dip(geoip:missing, 45.0.0.0/16)",
        )
        .destinations(&[("45.0.7.7", true), ("8.8.8.8", false)]),
        ParsedCase::new(
            "geoip-minus-nested-cidr",
            "dip(geoip:lab) && !dip(198.51.100.128/25)",
        )
        .destinations(&[
            ("198.51.100.9", true),
            ("2001:db8::9", true),
            ("198.51.100.200", false),
            ("8.8.8.8", false),
        ]),
        ParsedCase::new(
            "cidr-minus-covering-geoip",
            "dip(198.51.100.128/25) && !dip(geoip:lab)",
        )
        .destinations(&[("198.51.100.200", false), ("198.51.100.9", false)]),
        ParsedCase::new(
            "cidr-minus-geoip-hole",
            "dip(198.51.0.0/16, 2001:db8::/31) && !dip(geoip:lab)",
        )
        .destinations(&[
            ("198.51.7.7", true),
            ("2001:db9::5", true),
            ("198.51.100.9", false),
            ("2001:db8::9", false),
        ]),
        ParsedCase::new(
            "negated-union-of-geoip-and-cidr",
            "!dip(geoip:private, 2001:db9::/32) && l4proto(udp)",
        )
        .with(true, |c| {
            set_destination(c, "8.8.8.8");
            c.protocol = "udp";
        })
        .with(false, |c| {
            set_destination(c, "2001:db9::5");
            c.protocol = "udp";
        })
        .with(false, |c| {
            set_destination(c, "fd01::9");
            c.protocol = "udp";
        })
        .with(false, |c| set_destination(c, "8.8.8.8")),
    ]
}

fn cross_function_cases() -> Vec<ParsedCase> {
    let lab_ip = |c: &mut ConnectionInfo| c.dst_ip = "198.51.100.9".parse().unwrap();
    vec![
        ParsedCase::new(
            "reported-geosite-with-unrelated-suffix",
            "domain(geosite:suffix, suffix:imgur.test)",
        )
        .domains(&[
            ("www.suffix.test", true),
            ("i.imgur.test", true),
            (DOMAIN_MISS, false),
        ]),
        ParsedCase::new(
            "unknown-geosite-keeps-ordinary-alternative",
            "domain(geosite:missing, suffix:alias.test)",
        )
        .domains(&[("a.alias.test", true), ("yes.test", false)]),
        ParsedCase::new(
            "alternatives-keep-their-own-case-rules",
            "domain(suffix:alias.test, geosite:suffix)",
        )
        .domains(&[
            ("ALIAS.TEST", false),
            ("SUFFIX.TEST", true),
            ("a.alias.test", true),
        ]),
        ParsedCase::new(
            "several-geosite-codes-with-ordinary",
            "domain(geosite:full, geosite:regex, keyword:kw)",
        )
        .domains(&[
            ("full.test", true),
            ("rx42.test", true),
            ("a-kw-b.test", true),
            ("a.full.test", false),
        ]),
        ParsedCase::new(
            "mixed-domain-and-port",
            "domain(geosite:suffix, full:exact.test) && dport(443)",
        )
        .with(true, |c| {
            c.domain = Some("exact.test".into());
            c.dst_port = 443;
        })
        .with(true, |c| {
            c.domain = Some("a.suffix.test".into());
            c.dst_port = 443;
        })
        .with(false, |c| c.domain = Some("exact.test".into()))
        .with(false, |c| {
            c.domain = Some(DOMAIN_MISS.into());
            c.dst_port = 443;
        }),
        ParsedCase::new(
            "mixed-domain-and-negated-geoip",
            "domain(geosite:keyword, suffix:alias.test) && !dip(geoip:lab)",
        )
        .with(true, |c| c.domain = Some("a.alias.test".into()))
        .with(true, |c| c.domain = Some("a-needle-b.test".into()))
        .with(false, |c| {
            c.domain = Some("a.alias.test".into());
            lab_ip(c);
        })
        .with(false, |c| c.domain = Some(DOMAIN_MISS.into())),
        ParsedCase::new(
            "negated-mixed-domain-and-protocol",
            "!domain(geosite:full, keyword:kw) && l4proto(udp)",
        )
        .with(true, |c| {
            c.domain = Some(DOMAIN_MISS.into());
            c.protocol = "udp";
        })
        .with(true, |c| c.protocol = "udp")
        .with(false, |c| {
            c.domain = Some("full.test".into());
            c.protocol = "udp";
        })
        .with(false, |c| {
            c.domain = Some("a-kw-b.test".into());
            c.protocol = "udp";
        })
        .with(false, |c| c.domain = Some(DOMAIN_MISS.into())),
        ParsedCase::new(
            "geoip-union-and-mixed-domain",
            "dip(geoip:lab, 203.0.113.9) && domain(geosite:regex, suffix:alias.test)",
        )
        .with(true, |c| {
            lab_ip(c);
            c.domain = Some("rx42.test".into());
        })
        .with(true, |c| {
            c.dst_ip = "203.0.113.9".parse().unwrap();
            c.domain = Some("a.alias.test".into());
        })
        .with(false, |c| c.domain = Some("rx42.test".into()))
        .with(false, |c| {
            lab_ip(c);
            c.domain = Some(DOMAIN_MISS.into());
        }),
        ParsedCase::new(
            "positive-and-negated-domain-calls",
            "domain(geosite:suffix, keyword:kw) && !domain(full:deny.suffix.test)",
        )
        .domains(&[
            ("a.suffix.test", true),
            ("a-kw-b.test", true),
            ("deny.suffix.test", false),
            (DOMAIN_MISS, false),
        ]),
    ]
}

fn scalar_cases() -> Vec<ParsedCase> {
    let mut cases = Vec::new();
    for source in [false, true] {
        let field = if source { "sport" } else { "dport" };
        for (values, endpoints) in [
            (
                "0,1,65535",
                &[
                    (0, true),
                    (1, true),
                    (65535, true),
                    (2, false),
                    (65534, false),
                ][..],
            ),
            (
                "0-65535",
                &[(0, true), (1, true), (32768, true), (65535, true)],
            ),
        ] {
            let mut case =
                ParsedCase::new(format!("{field}-{values}"), format!("{field}({values})"));
            for &(port, hit) in endpoints {
                case = case.with(hit, |c| {
                    if source {
                        c.src_port = port
                    } else {
                        c.dst_port = port
                    }
                });
            }
            cases.push(case);
        }
    }
    cases.push(
        ParsedCase::new("dscp-endpoints", "dscp(0,63)")
            .with(true, |c| c.dscp = Some(0))
            .with(true, |c| c.dscp = Some(63))
            .with(false, |c| c.dscp = Some(46))
            .with(false, |c| c.dscp = None),
    );
    cases.push(
        ParsedCase::new("protocol-union", "l4proto(tcp,udp)")
            .with(true, |_| {})
            .with(true, |c| c.protocol = "udp"),
    );
    let ipv6 = |c: &mut ConnectionInfo| {
        c.src_ip = "2001:db8::2".parse().unwrap();
        c.dst_ip = "2001:db8::9".parse().unwrap();
    };
    for (expression, v4_hit, v6_hit) in [
        ("ipversion(ipv4)", true, false),
        ("ipversion(ipv6)", false, true),
        ("ipversion(ipv4,ipv6)", true, true),
        ("!ipversion(ipv4)", false, true),
    ] {
        cases.push(
            ParsedCase::new(expression, expression)
                .with(v4_hit, |_| {})
                .with(v6_hit, ipv6),
        );
    }
    cases.push(
        ParsedCase::new("geoip-literal-union", "dip(203.0.113.9,geoip:lab)")
            .with(true, |c| c.dst_ip = "203.0.113.9".parse().unwrap())
            .with(true, |c| c.dst_ip = "198.51.100.9".parse().unwrap())
            .with(true, ipv6)
            .with(false, |_| {}),
    );
    cases.push(
        ParsedCase::new("geoip-private-builtin", "dip(geoip:private)")
            .with(true, |c| c.dst_ip = "10.9.8.7".parse().unwrap())
            .with(true, |c| {
                c.src_ip = "fd01::2".parse().unwrap();
                c.dst_ip = "fd01::9".parse().unwrap();
            })
            .with(true, |_| {})
            .with(false, |c| c.dst_ip = "8.8.8.8".parse().unwrap())
            .with(false, |c| {
                c.src_ip = "2001:4860::2".parse().unwrap();
                c.dst_ip = "2001:4860::9".parse().unwrap();
            }),
    );
    cases
}

#[test]
fn parsed_expressions_match_independent_cases() {
    let sources = sources();
    for case in cases() {
        let router = case.router(&sources);
        for (index, (connection, hit)) in case.samples.iter().enumerate() {
            let (action, _) = router.route_action(connection);
            assert_eq!(
                (action.outbound.as_str(), action.must),
                if *hit {
                    ("proxy", true)
                } else {
                    ("block", false)
                },
                "{}/{index}: `{}`",
                case.label,
                case.expression
            );
            // The kernel sees only the userspace domain bitmap, never the name.
            let bitmap = connection
                .domain
                .as_deref()
                .and_then(|domain| router.domain_bitmap(domain));
            let mut projected = connection.clone();
            projected.domain = None;
            assert_eq!(
                router
                    .route_full_with_domain_bitmap(&projected, bitmap.as_ref())
                    .map(|result| result.rule_id),
                router.route_full(connection).map(|result| result.rule_id),
                "{}/{index}: bitmap projection",
                case.label
            );
        }
    }
}

/// Union cases prove each member only if its sample is matched by that kind
/// alone and the shared misses are matched by none.
#[test]
fn union_kind_samples_are_exclusive() {
    let sources = sources();
    for (call, kinds, misses, set) in [
        (
            "domain",
            DOMAIN_KINDS,
            &[DOMAIN_MISS][..],
            set_domain as Setter,
        ),
        (
            "dip",
            DESTINATION_KINDS,
            DESTINATION_MISSES,
            set_destination,
        ),
    ] {
        for kind in kinds {
            let router = ParsedCase::new(kind.0, format!("{call}({})", kind.1)).router(&sources);
            for &other in kinds.iter().map(|other| &other.2).chain(misses) {
                let expected = if other == kind.2 { "proxy" } else { "block" };
                let connection = sample(|c| set(c, other));
                assert_eq!(router.route(&connection), expected, "{} on {other}", kind.0);
            }
        }
    }
}
