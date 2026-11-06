//! Typed firewall/NAT actions sharing the traffic condition compiler and matcher.
use super::{
    CompiledCondition, DomainRegistry, GeoAssets, GeoRequirements, GeoSourceSet, PredicateInput,
    Router, SharedMatchers, append_conditions,
};
use honk_config::{datapath::InterfaceRole, firewall as config, routing::RoutingCondition};
use honk_datapath::firewall::{DestinationNat, PortPool, SourceNat, Tuple};

#[derive(Debug)]
struct Rule<A> {
    ingress: Option<InterfaceRole>,
    conditions: Vec<CompiledCondition>,
    action: A,
}
#[derive(Debug)]
pub(crate) struct FirewallPolicy {
    evaluator: Router,
    original: Vec<Rule<config::FirewallVerdict>>,
    forward: Vec<Rule<config::FirewallVerdict>>,
    dnat: Vec<Rule<DestinationNat>>,
    snat: Vec<Rule<SourceNat>>,
    original_default: config::FirewallVerdict,
    forward_default: config::FirewallVerdict,
    configured: config::FirewallConfig,
    nat: config::NatConfig,
    geo_fingerprint: [u8; 32],
    #[cfg(feature = "native-api")]
    geo_assets: Vec<super::GeoAssetSnapshot>,
}
impl FirewallPolicy {
    #[cfg(feature = "native-api")]
    pub(crate) fn geo_assets(&self) -> &[super::GeoAssetSnapshot] {
        &self.geo_assets
    }
    pub(crate) fn requirements(
        firewall: &config::FirewallConfig,
        nat: &config::NatConfig,
    ) -> GeoRequirements {
        let conditions = firewall
            .original
            .rules
            .iter()
            .chain(&firewall.forward.rules)
            .map(|rule| &rule.condition)
            .chain(nat.prerouting.iter().map(|rule| &rule.condition))
            .chain(nat.postrouting.iter().map(|rule| &rule.condition));
        let mut requirements = GeoRequirements::default();
        for condition in conditions {
            for code in condition.geo_ip.iter().chain(&condition.not.geo_ip) {
                requirements.add_geoip(code);
            }
        }
        requirements
    }
    pub(crate) fn matches(
        &self,
        firewall: &config::FirewallConfig,
        nat: &config::NatConfig,
        sources: &GeoSourceSet,
    ) -> bool {
        &self.configured == firewall
            && &self.nat == nat
            && self.geo_fingerprint == sources.fingerprint_for(&Self::requirements(firewall, nat))
    }
    pub(crate) fn compile(
        firewall: &config::FirewallConfig,
        nat: &config::NatConfig,
        sources: &GeoSourceSet,
        shared: &mut SharedMatchers,
    ) -> anyhow::Result<Self> {
        config::validate(Some(firewall), nat)?;
        let requirements = Self::requirements(firewall, nat);
        let assets = GeoAssets::from_sources(&requirements, sources);
        let mut registry = DomainRegistry::default();
        let mut compile = |condition: &RoutingCondition| -> anyhow::Result<Vec<CompiledCondition>> {
            anyhow::ensure!(
                condition
                    .geo_ip
                    .iter()
                    .chain(&condition.not.geo_ip)
                    .all(|code| assets.has_geoip(code)),
                "firewall/NAT GeoIP category is missing or empty in the captured asset snapshot"
            );
            let mut result = Vec::new();
            for not in [false, true] {
                append_conditions(&mut result, not, condition, &assets, &mut registry, shared)?;
            }
            anyhow::ensure!(
                !result.is_empty(),
                "firewall/NAT rules require a packet condition; use the explicit chain default for unconditional policy"
            );
            Ok(result)
        };
        let original = firewall
            .original
            .rules
            .iter()
            .map(|rule| {
                Ok(Rule {
                    ingress: rule.ingress,
                    conditions: compile(&rule.condition)?,
                    action: rule.verdict,
                })
            })
            .collect::<anyhow::Result<_>>()?;
        let forward = firewall
            .forward
            .rules
            .iter()
            .map(|rule| {
                Ok(Rule {
                    ingress: rule.ingress,
                    conditions: compile(&rule.condition)?,
                    action: rule.verdict,
                })
            })
            .collect::<anyhow::Result<_>>()?;
        let dnat = nat
            .prerouting
            .iter()
            .map(|rule| {
                Ok(Rule {
                    ingress: None,
                    conditions: compile(&rule.condition)?,
                    action: DestinationNat {
                        address: rule.action.address,
                        port: rule.action.port,
                    },
                })
            })
            .collect::<anyhow::Result<_>>()?;
        let snat = nat
            .postrouting
            .iter()
            .map(|rule| {
                Ok(Rule {
                    ingress: None,
                    conditions: compile(&rule.condition)?,
                    action: match rule.action {
                        config::SourceNat::Snat { address, ports } => SourceNat::Snat {
                            address,
                            ports: ports.map(|pool| PortPool {
                                first: pool.first,
                                last: pool.last,
                            }),
                        },
                        config::SourceNat::Masquerade { ports } => SourceNat::Masquerade {
                            ports: PortPool {
                                first: ports.first,
                                last: ports.last,
                            },
                        },
                    },
                })
            })
            .collect::<anyhow::Result<_>>()?;
        // Domain/process/MAC matchers were rejected above. The existing evaluator's
        // packet predicates need no domain registry or alternate routing actions.
        let evaluator = Router::from_config_sharing(
            &honk_config::routing::RoutingConfig::default(),
            sources,
            shared,
        )?;
        Ok(Self {
            evaluator,
            original,
            forward,
            dnat,
            snat,
            original_default: firewall.original.default,
            forward_default: firewall.forward.default,
            configured: firewall.clone(),
            nat: nat.clone(),
            geo_fingerprint: sources.fingerprint_for(&requirements),
            #[cfg(feature = "native-api")]
            geo_assets: sources.snapshots(&requirements),
        })
    }
    fn select<A: Copy>(
        &self,
        rules: &[Rule<A>],
        tuple: Tuple,
        traffic_class: u8,
        ingress: Option<InterfaceRole>,
    ) -> Option<A> {
        let input = PredicateInput {
            domain: None,
            src_ip: Some(tuple.source),
            dst_ip: Some(tuple.destination),
            src_port: matches!(tuple.protocol, 6 | 17).then_some(tuple.source_port),
            dst_port: matches!(tuple.protocol, 6 | 17).then_some(tuple.destination_port),
            protocol: match tuple.protocol {
                6 => "tcp",
                17 => "udp",
                _ => "icmp",
            },
            process_name: None,
            mac: None,
            dscp: Some(traffic_class >> 2),
        };
        rules
            .iter()
            .find(|rule| {
                rule.ingress.is_none_or(|zone| Some(zone) == ingress)
                    && rule.conditions.iter().all(|condition| {
                        // Missing facts fail before negation; absent ICMP ports must not match
                        // a negated port allow rule.
                        self.evaluator
                            .evaluate_predicate::<false>(&condition.predicate, input, None, None)
                            .is_some_and(|matched| if condition.not { !matched } else { matched })
                    })
            })
            .map(|rule| rule.action)
    }
    pub(crate) fn original(
        &self,
        tuple: Tuple,
        traffic_class: u8,
        ingress: InterfaceRole,
    ) -> config::FirewallVerdict {
        self.select(&self.original, tuple, traffic_class, Some(ingress))
            .unwrap_or(self.original_default)
    }
    pub(crate) fn forward(
        &self,
        tuple: Tuple,
        traffic_class: u8,
        ingress: InterfaceRole,
    ) -> config::FirewallVerdict {
        self.select(&self.forward, tuple, traffic_class, Some(ingress))
            .unwrap_or(self.forward_default)
    }
    pub(crate) fn dnat(&self, tuple: Tuple, traffic_class: u8) -> Option<DestinationNat> {
        self.select(&self.dnat, tuple, traffic_class, None)
    }
    pub(crate) fn snat(&self, tuple: Tuple, traffic_class: u8) -> SourceNat {
        self.select(&self.snat, tuple, traffic_class, None)
            .unwrap_or(SourceNat::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlapping_firewall_and_nat_rules_keep_first_match_order() {
        let configuration = honk_config::parser::parse_dae_config(
            r#"
datapath {
    backend: xdp
    direct: core
    interface { lan0: lan }
    firewall {
        original {
            sip(192.0.2.0/24) -> allow
            sip(192.0.2.2) -> drop
            default: reject
        }
        forward {
            dip(10.0.0.0/24) -> reject
            dip(10.0.0.7) -> allow
            default: drop
        }
    }
    nat {
        prerouting {
            dport(80) -> dnat(10.0.0.7:8080)
            dport(80) -> dnat(10.0.0.8:8081)
        }
        postrouting {
            sip(192.0.2.0/24) -> snat(203.0.113.1)
            sip(192.0.2.2) -> snat(203.0.113.2)
        }
    }
}
"#,
        )
        .unwrap();
        let sources = GeoSourceSet::load(&GeoRequirements::for_forwarding(&configuration));
        let mut router = Router::from_config(&configuration.routing).unwrap();
        router
            .bind_firewall(
                &configuration,
                None,
                &sources,
                &mut SharedMatchers::default(),
            )
            .unwrap();
        let policy = router.firewall_policy().unwrap();
        let tuple = Tuple {
            source: "192.0.2.2".parse().unwrap(),
            destination: "198.51.100.7".parse().unwrap(),
            protocol: 6,
            source_port: 40000,
            destination_port: 80,
        };
        assert_eq!(
            policy.original(tuple, 0, InterfaceRole::Lan),
            config::FirewallVerdict::Allow
        );
        let dnat = policy.dnat(tuple, 0).unwrap();
        assert_eq!(
            (dnat.address, dnat.port),
            ("10.0.0.7".parse().unwrap(), Some(8080))
        );
        let translated = honk_datapath::firewall::destination_tuple(tuple, Some(dnat)).unwrap();
        assert_eq!(
            policy.forward(translated, 0, InterfaceRole::Lan),
            config::FirewallVerdict::Reject
        );
        assert_eq!(
            policy.snat(translated, 0),
            SourceNat::Snat {
                address: "203.0.113.1".parse().unwrap(),
                ports: None,
            }
        );
    }

    #[test]
    fn empty_security_condition_is_rejected_at_router_binding() {
        let mut configuration = honk_config::parser::parse_dae_config(
            "datapath { backend: xdp\n direct: core\n interface { lan0: lan }\n firewall { original { default: allow }\n forward { default: allow } } }",
        ).unwrap();
        configuration
            .datapath
            .as_mut()
            .unwrap()
            .firewall
            .as_mut()
            .unwrap()
            .original
            .rules
            .push(config::FirewallRule {
                ingress: None,
                condition: RoutingCondition::default(),
                verdict: config::FirewallVerdict::Allow,
            });
        let sources = GeoSourceSet::load(&GeoRequirements::for_forwarding(&configuration));
        let mut router = Router::from_config(&configuration.routing).unwrap();
        assert!(
            router
                .bind_firewall(
                    &configuration,
                    None,
                    &sources,
                    &mut SharedMatchers::default()
                )
                .is_err()
        );
        assert!(router.firewall_policy().is_none());
        assert_eq!(router.security_epoch(), 0);
    }

    #[test]
    fn original_and_translated_views_share_canonical_matchers() {
        let mut firewall = config::FirewallConfig::default();
        firewall.original.rules.push(config::FirewallRule {
            ingress: Some(InterfaceRole::Lan),
            condition: RoutingCondition {
                ip: vec!["198.51.100.7".into()],
                ..Default::default()
            },
            verdict: config::FirewallVerdict::Allow,
        });
        firewall.forward.rules.push(config::FirewallRule {
            ingress: Some(InterfaceRole::Lan),
            condition: RoutingCondition {
                ip: vec!["10.0.0.8".into()],
                ..Default::default()
            },
            verdict: config::FirewallVerdict::Allow,
        });
        let sources = GeoSourceSet::load(&FirewallPolicy::requirements(
            &firewall,
            &config::NatConfig::default(),
        ));
        let policy = FirewallPolicy::compile(
            &firewall,
            &config::NatConfig::default(),
            &sources,
            &mut SharedMatchers::default(),
        )
        .unwrap();
        let tuple = Tuple {
            source: "10.0.0.2".parse().unwrap(),
            destination: "198.51.100.7".parse().unwrap(),
            protocol: 17,
            source_port: 4000,
            destination_port: 80,
        };
        assert_eq!(
            policy.original(tuple, 0, InterfaceRole::Lan),
            config::FirewallVerdict::Allow
        );
        assert_eq!(
            policy.forward(tuple, 0, InterfaceRole::Lan),
            config::FirewallVerdict::Drop
        );
        assert_eq!(
            policy.original(tuple, 0, InterfaceRole::Wan),
            config::FirewallVerdict::Drop
        );
        let translated = Tuple {
            destination: "10.0.0.8".parse().unwrap(),
            ..tuple
        };
        assert_eq!(
            policy.original(translated, 0, InterfaceRole::Lan),
            config::FirewallVerdict::Drop
        );
        assert_eq!(
            policy.forward(translated, 0, InterfaceRole::Lan),
            config::FirewallVerdict::Allow
        );
    }
    #[test]
    fn security_epoch_survives_route_changes_removal_and_failed_candidates() {
        let mut configuration = honk_config::parser::parse_dae_config("datapath { backend: xdp\n direct: core\n interface { lan0: lan }\n firewall { original { default: allow }\n forward { default: allow } } }").unwrap();
        let sources = GeoSourceSet::load(&GeoRequirements::for_forwarding(&configuration));
        let mut shared = SharedMatchers::default();
        let mut first = Router::from_config(&configuration.routing).unwrap();
        first
            .bind_firewall(&configuration, None, &sources, &mut shared)
            .unwrap();
        assert_eq!(first.security_epoch(), 1);
        configuration.routing.default_outbound = "block".into();
        let mut second = Router::from_config(&configuration.routing).unwrap();
        second
            .bind_firewall(&configuration, Some(&first), &sources, &mut shared)
            .unwrap();
        assert_eq!(second.security_epoch(), 1);
        assert!(std::sync::Arc::ptr_eq(
            first.firewall_policy().unwrap(),
            second.firewall_policy().unwrap()
        ));
        let firewall = configuration.datapath.as_mut().unwrap().firewall.take();
        let mut disabled = second.clone();
        disabled
            .bind_firewall(&configuration, Some(&second), &sources, &mut shared)
            .unwrap();
        assert_eq!(disabled.security_epoch(), 2);
        assert!(disabled.firewall_policy().is_none());
        configuration.datapath.as_mut().unwrap().firewall = firewall;
        let mut enabled = disabled.clone();
        enabled
            .bind_firewall(&configuration, Some(&disabled), &sources, &mut shared)
            .unwrap();
        assert_eq!(enabled.security_epoch(), 3);
        configuration
            .datapath
            .as_mut()
            .unwrap()
            .firewall
            .as_mut()
            .unwrap()
            .original
            .rules
            .push(config::FirewallRule {
                ingress: None,
                condition: RoutingCondition::default(),
                verdict: config::FirewallVerdict::Allow,
            });
        let mut rejected = enabled.clone();
        assert!(
            rejected
                .bind_firewall(&configuration, Some(&enabled), &sources, &mut shared)
                .is_err()
        );
        assert_eq!(rejected.security_epoch(), 3);
        assert!(std::sync::Arc::ptr_eq(
            enabled.firewall_policy().unwrap(),
            rejected.firewall_policy().unwrap()
        ));
    }
}
