use super::{CompiledPredicate, PortRange, Router, protocol_value};
use std::net::IpAddr;

impl Router {
    /// Confirms unconditional direct(must) coverage, not listener or firewall reachability.
    pub(crate) fn confirms_lan_self_protection(&self, address: IpAddr) -> bool {
        ["tcp", "udp"].into_iter().all(|protocol| {
            'rules: for route in self.compiled_routes() {
                if route.conditions.is_empty() {
                    continue;
                }
                let mut certain = true;
                for condition in &route.conditions {
                    let matched = match &condition.predicate {
                        CompiledPredicate::DestinationIp(matcher) => {
                            Some(matcher.matches(&address))
                        }
                        CompiledPredicate::DestinationPort(ranges) => non_dns_ports_match(ranges),
                        CompiledPredicate::Protocol(mask) => {
                            Some(protocol_value(protocol) & mask != 0)
                        }
                        CompiledPredicate::IpVersion(mask) => {
                            Some(mask & if address.is_ipv4() { 1 } else { 2 } != 0)
                        }
                        CompiledPredicate::Domain(_)
                        | CompiledPredicate::SourceIp(_)
                        | CompiledPredicate::SourcePort(_)
                        | CompiledPredicate::Dscp(_)
                        | CompiledPredicate::ProcessName(_)
                        | CompiledPredicate::Mac(_) => None,
                    };
                    match matched.map(|matched| matched != condition.not) {
                        Some(false) => continue 'rules,
                        Some(true) => {}
                        None => certain = false,
                    }
                }
                if route.action.outbound != "direct" || !route.action.must {
                    return false;
                }
                if certain {
                    return true;
                }
            }
            // Reached only when no earlier rule may intercept, like a final catch-all rule.
            let fallback = self.fallback();
            fallback.must && fallback.outbound == "direct"
        })
    }
}

fn non_dns_ports_match(ranges: &[PortRange]) -> Option<bool> {
    // Partial unions remain unconfirmed rather than growing a second policy solver.
    let covers = |start, end| {
        ranges
            .iter()
            .any(|range| range.contains(start) && range.contains(end))
    };
    if covers(1, 52) && covers(54, u16::MAX) {
        Some(true)
    } else if ranges.iter().all(|range| {
        range.start > range.end || range.end == 0 || (range.start == 53 && range.end == 53)
    }) {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::routing::{
        RoutingCondition, RoutingConfig, RoutingNotCondition, RoutingOutbound, RoutingRule,
    };

    fn rule(condition: RoutingCondition, outbound: &str) -> RoutingRule {
        RoutingRule {
            name: "local-access".into(),
            condition,
            outbound: RoutingOutbound::Simple(outbound.into()),
            priority: 0,
            must: true,
            mark: 0,
        }
    }

    fn local_rule() -> RoutingRule {
        rule(
            RoutingCondition {
                ip: vec!["192.168.50.0/24".into(), "fd00:50::/64".into()],
                not: RoutingNotCondition {
                    port: vec!["53".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            "direct",
        )
    }

    fn check(rules: &[RoutingRule], fallback: &str, cases: &[(IpAddr, bool)]) {
        let router = Router::new(rules, fallback).unwrap();
        for &(address, expected) in cases {
            assert_eq!(
                router.confirms_lan_self_protection(address),
                expected,
                "{address}, fallback={fallback}, rules={rules:?}"
            );
        }
    }

    #[test]
    fn explicit_native_coverage_requires_both_families_and_terminal_ownership() {
        let ipv4 = "192.168.50.1".parse().unwrap();
        let ipv6 = "fd00:50::1".parse().unwrap();
        let outside = "192.168.51.1".parse().unwrap();
        check(&[], "direct", &[(ipv4, false)]);
        check(
            &[local_rule()],
            "block",
            &[(ipv4, true), (ipv6, true), (outside, false)],
        );
        let mut ordinary = local_rule();
        ordinary.must = false;
        check(&[ordinary], "direct", &[(ipv4, false)]);
        check(
            &[rule(RoutingCondition::default(), "direct")],
            "direct",
            &[(ipv4, false)],
        );
    }

    #[test]
    fn earlier_possible_interception_is_not_hidden_by_a_later_protection_rule() {
        let address = "192.168.50.1".parse().unwrap();
        let conditional = rule(
            RoutingCondition {
                source_ip: vec!["192.168.50.0/25".into()],
                ..Default::default()
            },
            "block",
        );
        let mut harmless = conditional.clone();
        harmless.outbound = RoutingOutbound::Simple("direct".into());
        let mut impossible = conditional.clone();
        impossible.condition.ip = vec!["203.0.113.0/24".into()];
        impossible.condition.domain_suffix = vec!["example.org".into()];
        let negated_source = rule(
            RoutingCondition {
                not: RoutingNotCondition {
                    source_ip: vec!["192.168.50.0/25".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            "direct",
        );
        for (rules, fallback, expected) in [
            (vec![conditional.clone(), local_rule()], "direct", false),
            (vec![local_rule(), conditional], "block", true),
            (vec![harmless, local_rule()], "block", true),
            (vec![impossible, local_rule()], "block", true),
            (vec![negated_source], "block", false),
        ] {
            check(&rules, fallback, &[(address, expected)]);
        }
        for (port, fallback, expected) in [("53", "block", true), ("22", "direct", false)] {
            let block = rule(
                RoutingCondition {
                    port: vec![port.into()],
                    ..Default::default()
                },
                "block",
            );
            check(&[block, local_rule()], fallback, &[(address, expected)]);
        }
    }

    #[test]
    fn port_and_protocol_boundaries_cannot_hide_uncovered_management_traffic() {
        let address = "192.168.50.1".parse().unwrap();
        for (ports, expected) in [
            (vec!["1-65535"], true),
            (vec!["1-52", "54-65535"], true),
            (vec!["2-65535"], false),
            (vec!["1-52", "55-65535"], false),
            (vec!["1-65534"], false),
            (vec!["53"], false),
        ] {
            let candidate = rule(
                RoutingCondition {
                    port: ports.into_iter().map(str::to_owned).collect(),
                    ..Default::default()
                },
                "direct",
            );
            check(&[candidate], "block", &[(address, expected)]);
        }
        let mut tcp = local_rule();
        tcp.condition.protocol = vec!["tcp".into()];
        check(&[tcp.clone()], "block", &[(address, false)]);
        let mut udp = local_rule();
        udp.condition.protocol = vec!["udp".into()];
        check(&[tcp, udp], "block", &[(address, true)]);
        let mut ipv4_only = local_rule();
        ipv4_only.condition.ip_version = vec!["4".into()];
        check(
            &[ipv4_only],
            "block",
            &[(address, true), ("fd00:50::1".parse().unwrap(), false)],
        );
    }

    fn source_rule(outbound: &str) -> RoutingRule {
        rule(
            RoutingCondition {
                source_ip: vec!["192.168.50.0/25".into()],
                ..Default::default()
            },
            outbound,
        )
    }

    #[test]
    fn must_direct_fallback_covers_only_what_every_rule_leaves_to_it() {
        for (rules, fallback, must, expected) in [
            (vec![], "direct", true, true),
            (vec![source_rule("direct")], "direct", true, true),
            (vec![], "direct", false, false),
            (vec![], "block", true, false),
            (vec![source_rule("block")], "direct", true, false),
        ] {
            let mut routing = RoutingConfig::default();
            routing.rules = rules;
            routing.default_outbound = fallback.into();
            routing.default_must = must;
            routing.default_mark = 0x200;
            let router = Router::from_config(&routing).unwrap();
            for address in ["192.168.50.1", "fd00:50::1"] {
                assert_eq!(
                    router.confirms_lan_self_protection(address.parse().unwrap()),
                    expected,
                    "{address}, fallback={fallback}, must={must}"
                );
            }
        }
    }
}
