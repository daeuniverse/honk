use sha2::{Digest, Sha256};

use super::{CompiledCondition, CompiledPredicate, CompiledRoute, DomainMatcher};

/// Hash the policy's semantic inputs without depending on derived compiler state.
pub(super) fn policy(
    routes: &[CompiledRoute],
    domain_matchers: &[DomainMatcher],
    default_outbound: &str,
    geo_fingerprint: [u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"honk.routing-policy.v2\0");
    let mut encoder = Encoder { hash: &mut hash };
    encoder.string(default_outbound);
    encoder.fixed(&geo_fingerprint);
    encoder.list(routes, encode_route);
    encoder.list(domain_matchers, encode_domain_key);
    hash.finalize().into()
}

struct Encoder<'a> {
    hash: &'a mut Sha256,
}

impl Encoder<'_> {
    fn tag(&mut self, value: u8) {
        self.hash.update([value]);
    }

    fn bool(&mut self, value: bool) {
        self.hash.update([u8::from(value)]);
    }

    fn u8(&mut self, value: u8) {
        self.hash.update([value]);
    }

    fn u16(&mut self, value: u16) {
        self.hash.update(value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.hash.update(value.to_le_bytes());
    }

    fn fixed(&mut self, value: &[u8]) {
        self.hash.update(value);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.hash.update((value.len() as u64).to_le_bytes());
        self.hash.update(value);
    }

    fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn list<T>(&mut self, values: &[T], mut encode: impl FnMut(&mut Self, &T)) {
        self.hash.update((values.len() as u64).to_le_bytes());
        for value in values {
            encode(self, value);
        }
    }
}

fn encode_route(encoder: &mut Encoder<'_>, route: &CompiledRoute) {
    encoder.u32(route.id);
    encoder.string(&route.name);
    encoder.string(&route.rule_type);
    encoder.string(&route.rule_payload);
    encoder.u32(route.priority);
    encoder.list(&route.conditions, encode_condition);
    encoder.string(&route.outbound);
    encoder.bool(route.must);
    encoder.u32(route.mark);
}

fn encode_condition(encoder: &mut Encoder<'_>, condition: &CompiledCondition) {
    encoder.bool(condition.not);
    match &condition.predicate {
        CompiledPredicate::Domain(id) => {
            encoder.tag(0);
            encoder.u32(*id);
        }
        CompiledPredicate::DestinationIp(matcher) => {
            encoder.tag(1);
            encode_ip_nets(encoder, matcher.nets());
        }
        CompiledPredicate::SourceIp(matcher) => {
            encoder.tag(2);
            encode_ip_nets(encoder, matcher.nets());
        }
        CompiledPredicate::DestinationPort(ranges) => {
            encoder.tag(3);
            encoder.list(ranges, |encoder, range| {
                encoder.u16(range.start);
                encoder.u16(range.end);
            });
        }
        CompiledPredicate::SourcePort(ranges) => {
            encoder.tag(4);
            encoder.list(ranges, |encoder, range| {
                encoder.u16(range.start);
                encoder.u16(range.end);
            });
        }
        CompiledPredicate::Protocol(mask) => {
            encoder.tag(5);
            encoder.u8(*mask);
        }
        CompiledPredicate::IpVersion(mask) => {
            encoder.tag(6);
            encoder.u8(*mask);
        }
        CompiledPredicate::Dscp(values) => {
            encoder.tag(7);
            encoder.list(values, |encoder, value| encoder.u8(*value));
        }
        CompiledPredicate::ProcessName(patterns) => {
            encoder.tag(8);
            encoder.list(patterns, |encoder, pattern| encoder.string(pattern));
        }
        CompiledPredicate::Mac(macs) => {
            encoder.tag(9);
            encoder.list(macs, |encoder, mac| encoder.fixed(mac));
        }
    }
}

fn encode_ip_nets(encoder: &mut Encoder<'_>, nets: &[ipnet::IpNet]) {
    encoder.list(nets, |encoder, net| {
        let address = net.addr();
        match address {
            std::net::IpAddr::V4(address) => {
                encoder.tag(4);
                encoder.fixed(&address.octets());
            }
            std::net::IpAddr::V6(address) => {
                encoder.tag(6);
                encoder.fixed(&address.octets());
            }
        }
        encoder.u8(net.prefix_len());
    });
}

fn encode_domain_key(encoder: &mut Encoder<'_>, matcher: &DomainMatcher) {
    let key = matcher.key();
    encoder.u8(key.class);
    encoder.list(&key.alternatives, |encoder, (tag, alternative)| {
        encoder.u8(*tag);
        encoder.string(alternative);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{GeositeDomain, IpMatcher, PortRange};
    use std::sync::Arc;

    fn route(condition: CompiledPredicate) -> CompiledRoute {
        CompiledRoute {
            id: 0,
            name: "rule".into(),
            rule_type: "Match".into(),
            rule_payload: String::new(),
            priority: 0,
            conditions: vec![CompiledCondition {
                not: false,
                predicate: condition,
            }],
            outbound: "direct".into(),
            must: false,
            mark: 0,
        }
    }

    fn digest(routes: &[CompiledRoute], matchers: &[DomainMatcher]) -> [u8; 32] {
        policy(routes, matchers, "direct", [0; 32])
    }

    #[test]
    fn semantic_encoder_frames_strings_and_lists() {
        let first = route(CompiledPredicate::ProcessName(vec![
            "ab".into(),
            "c".into(),
        ]));
        let second = route(CompiledPredicate::ProcessName(vec![
            "a".into(),
            "bc".into(),
        ]));
        assert_ne!(digest(&[first], &[]), digest(&[second], &[]));

        let mut first = route(CompiledPredicate::Protocol(1));
        let mut second = route(CompiledPredicate::Protocol(1));
        first.name = "a".into();
        first.rule_type = "bc".into();
        second.name = "ab".into();
        second.rule_type = "c".into();
        assert_ne!(digest(&[first], &[]), digest(&[second], &[]));
    }

    #[test]
    fn semantic_encoder_uses_stored_ip_nets_and_mac_values() {
        let first = route(CompiledPredicate::DestinationIp(Arc::new(IpMatcher::new(
            vec![
                "192.0.2.1/24".parse().unwrap(),
                "2001:db8::1/64".parse().unwrap(),
            ],
        ))));
        let second = route(CompiledPredicate::DestinationIp(Arc::new(IpMatcher::new(
            vec![
                "192.0.2.2/24".parse().unwrap(),
                "2001:db8::2/64".parse().unwrap(),
            ],
        ))));
        assert_ne!(digest(&[first], &[]), digest(&[second], &[]));

        let first = route(CompiledPredicate::Mac(vec![[0, 1, 2, 3, 4, 5]]));
        let second = route(CompiledPredicate::Mac(vec![[0, 1, 2, 3, 4, 6]]));
        assert_ne!(digest(&[first], &[]), digest(&[second], &[]));
    }

    #[test]
    fn semantic_encoder_preserves_domain_class_tags_and_registry_order() {
        let ordinary = DomainMatcher::ordinary(&[], &[], &["example.com".into()], &[]).unwrap();
        let geosite = DomainMatcher::geosite(vec![GeositeDomain::Keyword("example.com".into())]);
        assert_ne!(
            digest(&[], std::slice::from_ref(&ordinary)),
            digest(&[], std::slice::from_ref(&geosite))
        );

        let full = DomainMatcher::geosite(vec![GeositeDomain::Full("example.com".into())]);
        assert_ne!(
            digest(&[], std::slice::from_ref(&geosite)),
            digest(&[], &[full])
        );
        assert_ne!(
            digest(&[], &[ordinary.clone(), geosite.clone()]),
            digest(&[], &[geosite, ordinary]),
        );
    }

    #[test]
    fn semantic_encoder_keeps_action_metadata_and_geo_distinct() {
        let base = route(CompiledPredicate::Protocol(1));
        let mut changed = base.clone();
        changed.outbound = "proxy".into();
        assert_ne!(
            digest(std::slice::from_ref(&base), &[]),
            digest(&[changed], &[])
        );

        let mut changed = base.clone();
        changed.rule_payload = "tcp".into();
        changed.must = true;
        changed.mark = 7;
        assert_ne!(
            digest(std::slice::from_ref(&base), &[]),
            digest(&[changed], &[])
        );
        assert_ne!(
            policy(std::slice::from_ref(&base), &[], "direct", [0; 32]),
            policy(std::slice::from_ref(&base), &[], "direct", [1; 32]),
        );
    }

    #[test]
    fn normalized_process_name_is_a_no_op_after_compilation() {
        use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};

        let make_rule = |name: &str| RoutingRule {
            name: "same-display-name".into(),
            condition: RoutingCondition {
                domain_suffix: vec!["example.com".into()],
                process_name: vec![name.into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: false,
            mark: 0,
        };
        let first =
            crate::routing::Router::new(&[make_rule("abcdefghijklmnop-first")], "direct").unwrap();
        let second =
            crate::routing::Router::new(&[make_rule("abcdefghijklmnop-second")], "direct").unwrap();
        assert_eq!(first.policy_fingerprint(), second.policy_fingerprint());
    }

    #[test]
    fn port_ranges_are_encoded_as_ordered_lists() {
        let first = route(CompiledPredicate::DestinationPort(vec![
            PortRange { start: 1, end: 2 },
            PortRange { start: 3, end: 4 },
        ]));
        let second = route(CompiledPredicate::DestinationPort(vec![
            PortRange { start: 3, end: 4 },
            PortRange { start: 1, end: 2 },
        ]));
        assert_ne!(digest(&[first], &[]), digest(&[second], &[]));
    }
}
