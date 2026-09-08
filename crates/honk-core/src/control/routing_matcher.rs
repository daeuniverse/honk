//! Fallible compiler for the native routing decision plane.
//!
//! This module is deliberately only a compiler.  It has no map side effects;
//! publication is delegated to the backend after a complete plan exists.

use crate::ebpf::maps;
use crate::routing::{CompiledPredicate, CompiledRoute, Router};
use honk_config::types::DialMode;
use honk_ebpf_common::{
    DomainRouting, LpmKey, OutboundIndex, ROUTING_FACT_CAPACITY, ROUTING_FEATURE_DOMAIN,
    ROUTING_FEATURE_DOMAIN_REROUTE, ROUTING_FEATURE_PROCESS, ROUTING_PROCESS_MAX_LEN,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[cfg(feature = "ebpf")]
pub mod codegen;

/// A condition in the native rule representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelCondition {
    pub not: bool,
    pub predicate: KernelPredicate,
}

/// A predicate evaluated by a generated routing function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelPredicate {
    /// Policy-local domain predicate ID.
    Domain(u32),
    /// Bit in the destination fact map (family is selected by the input).
    DestinationIp(u32),
    SourceIp(u32),
    Mac(u32),
    DestinationPort(Vec<crate::routing::PortRange>),
    SourcePort(Vec<crate::routing::PortRange>),
    /// TCP=1, UDP=2, and their union is represented by bitwise OR.
    Protocol(u8),
    /// IPv4=1, IPv6=2, and their union is represented by bitwise OR.
    IpVersion(u8),
    Dscp(Vec<u8>),
    /// Canonical process-name bytes, without a trailing NUL.
    ProcessName(Vec<Vec<u8>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRule {
    pub id: u32,
    pub source: String,
    pub conditions: Vec<KernelCondition>,
    pub outbound: u8,
    pub must: bool,
    pub mark: u32,
}

/// Generation-owned LPM fact maps.  Domain facts are staged by the backend
/// from the projection writer and intentionally do not live in this plan.
#[derive(Debug, Clone, Default)]
pub struct RoutingFactMaps {
    pub destination_v4: Vec<(LpmKey, DomainRouting)>,
    pub destination_v6: Vec<(LpmKey, DomainRouting)>,
    pub source_v4: Vec<(LpmKey, DomainRouting)>,
    pub source_v6: Vec<(LpmKey, DomainRouting)>,
    pub mac: Vec<(LpmKey, DomainRouting)>,
}

/// Immutable, validated inputs for one policy generation.
#[derive(Debug, Clone)]
pub struct RoutingPushPlan {
    pub(crate) rules: Vec<KernelRule>,
    pub(crate) facts: RoutingFactMaps,
    pub(crate) fallback: u8,
    pub(crate) features: u32,
    pub(crate) fingerprint: [u8; 32],
    pub has_domain_rules: bool,
    pub(crate) domain_predicate_count: usize,
}

impl RoutingPushPlan {
    pub fn semantically_eq(&self, other: &Self) -> bool {
        self.fallback == other.fallback
            && self.features == other.features
            && self.fingerprint == other.fingerprint
            && self.has_domain_rules == other.has_domain_rules
            && self.domain_predicate_count == other.domain_predicate_count
            && self.rules == other.rules
            && fact_maps_equal(&self.facts, &other.facts)
    }

    /// Compile a Router into native rules and generation-owned fact indexes.
    pub fn compile(
        router: &Router,
        outbound_ids: &HashMap<String, u8>,
        fallback: &str,
        dial_mode: DialMode,
    ) -> anyhow::Result<Self> {
        let fallback = outbound_ids
            .get(fallback)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("unknown fallback outbound '{fallback}'"))?;

        let mut facts = RoutingFactMaps::default();
        let mut dest_fact = FactAllocator::default();
        let mut source_fact = FactAllocator::default();
        let domain_predicate_count = router.domain_predicate_count();
        anyhow::ensure!(
            domain_predicate_count <= ROUTING_FACT_CAPACITY,
            "domain predicate capacity exceeded ({domain_predicate_count} > {ROUTING_FACT_CAPACITY})"
        );
        let mut mac_fact = FactAllocator::default();
        let mut rules = Vec::with_capacity(router.compiled_routes().len());
        let mut has_process = false;
        let has_domain = domain_predicate_count != 0;

        for route in router.compiled_routes() {
            let outbound = outbound_ids
                .get(route.outbound.as_str())
                .copied()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "unknown outbound '{}' in rule '{}'",
                        route.outbound,
                        route.name
                    )
                })?;
            let mut conditions = Vec::with_capacity(route.conditions.len());
            for condition in &route.conditions {
                let predicate = match &condition.predicate {
                    CompiledPredicate::Domain(id) => {
                        anyhow::ensure!(
                            (*id as usize) < domain_predicate_count,
                            "unknown domain predicate id {id}"
                        );
                        KernelPredicate::Domain(*id)
                    }
                    CompiledPredicate::DestinationIp(matcher) => {
                        let id = dest_fact.alloc("destination IP")?;
                        add_ip_facts(
                            &mut facts.destination_v4,
                            &mut facts.destination_v6,
                            matcher.nets(),
                            id,
                        );
                        KernelPredicate::DestinationIp(id)
                    }
                    CompiledPredicate::SourceIp(matcher) => {
                        let id = source_fact.alloc("source IP")?;
                        add_ip_facts(
                            &mut facts.source_v4,
                            &mut facts.source_v6,
                            matcher.nets(),
                            id,
                        );
                        KernelPredicate::SourceIp(id)
                    }
                    CompiledPredicate::Mac(macs) => {
                        let id = mac_fact.alloc("MAC")?;
                        for mac in macs {
                            add_mac_fact(&mut facts.mac, mac, id);
                        }
                        KernelPredicate::Mac(id)
                    }
                    CompiledPredicate::DestinationPort(ranges) => {
                        validate_ranges(ranges, &route.name)?;
                        KernelPredicate::DestinationPort(ranges.clone())
                    }
                    CompiledPredicate::SourcePort(ranges) => {
                        validate_ranges(ranges, &route.name)?;
                        KernelPredicate::SourcePort(ranges.clone())
                    }
                    CompiledPredicate::Protocol(mask) => {
                        anyhow::ensure!(*mask & !0b11 == 0, "invalid protocol mask {mask:#x}");
                        KernelPredicate::Protocol(*mask)
                    }
                    CompiledPredicate::IpVersion(mask) => {
                        anyhow::ensure!(*mask & !0b11 == 0, "invalid IP version mask {mask:#x}");
                        KernelPredicate::IpVersion(*mask)
                    }
                    CompiledPredicate::Dscp(values) => KernelPredicate::Dscp(values.clone()),
                    CompiledPredicate::ProcessName(names) => {
                        anyhow::ensure!(
                            names
                                .iter()
                                .all(|name| name.len() <= ROUTING_PROCESS_MAX_LEN),
                            "process matcher exceeds {ROUTING_PROCESS_MAX_LEN} bytes in rule '{}'",
                            route.name
                        );
                        has_process = true;
                        KernelPredicate::ProcessName(
                            names.iter().map(|name| name.as_bytes().to_vec()).collect(),
                        )
                    }
                };
                conditions.push(KernelCondition {
                    not: condition.not,
                    predicate,
                });
            }
            // Empty authored rules never match in userspace and need no code.
            if conditions.is_empty() {
                continue;
            }
            let punt = !route.must
                && dial_mode == DialMode::DomainPlusPlus
                && is_generic_port_rule(&conditions)
                && !matches!(outbound, x if x == OutboundIndex::Direct as u8 || x == OutboundIndex::Block as u8);
            rules.push(KernelRule {
                id: route.id,
                source: rule_source(route),
                conditions,
                outbound: if punt {
                    OutboundIndex::ControlPlaneRouting as u8
                } else {
                    outbound
                },
                must: route.must,
                mark: route.mark,
            });
        }

        inherit_prefix_bits(&mut facts.destination_v4);
        inherit_prefix_bits(&mut facts.destination_v6);
        inherit_prefix_bits(&mut facts.source_v4);
        inherit_prefix_bits(&mut facts.source_v6);
        inherit_prefix_bits(&mut facts.mac);
        let mut features = 0;
        if has_domain {
            features |= ROUTING_FEATURE_DOMAIN;
            if matches!(dial_mode, DialMode::Domain | DialMode::DomainPlusPlus) {
                features |= ROUTING_FEATURE_DOMAIN_REROUTE;
            }
        }
        if has_process {
            features |= ROUTING_FEATURE_PROCESS;
        }

        let mut hash = Sha256::new();
        hash.update(b"honk.routing.plan.v2\0");
        hash.update(router.policy_fingerprint());
        hash.update([dial_mode as u8]);
        hash.update([fallback]);
        let mut bindings: Vec<_> = outbound_ids.iter().collect();
        bindings.sort_by_key(|(name, _)| *name);
        for (name, id) in bindings {
            hash.update(name.as_bytes());
            hash.update([0]);
            hash.update([*id]);
        }

        Ok(Self {
            rules,
            facts,
            fallback,
            features,
            fingerprint: hash.finalize().into(),
            has_domain_rules: has_domain,
            domain_predicate_count,
        })
    }
}

fn fact_maps_equal(a: &RoutingFactMaps, b: &RoutingFactMaps) -> bool {
    fn eq(x: &[(LpmKey, DomainRouting)], y: &[(LpmKey, DomainRouting)]) -> bool {
        x.len() == y.len()
            && x.iter().zip(y).all(|((ka, va), (kb, vb))| {
                ka.prefix_len == kb.prefix_len && ka.data == kb.data && va.bitmap == vb.bitmap
            })
    }
    eq(&a.destination_v4, &b.destination_v4)
        && eq(&a.destination_v6, &b.destination_v6)
        && eq(&a.source_v4, &b.source_v4)
        && eq(&a.source_v6, &b.source_v6)
        && eq(&a.mac, &b.mac)
}

#[derive(Default)]
struct FactAllocator {
    next: usize,
}

impl FactAllocator {
    fn alloc(&mut self, kind: &str) -> anyhow::Result<u32> {
        let id = self.next;
        self.next += 1;
        anyhow::ensure!(
            id < ROUTING_FACT_CAPACITY,
            "{kind} fact capacity exceeded ({ROUTING_FACT_CAPACITY})"
        );
        Ok(id as u32)
    }
}

fn validate_ranges(ranges: &[crate::routing::PortRange], source: &str) -> anyhow::Result<()> {
    for range in ranges {
        anyhow::ensure!(
            range.start <= range.end,
            "invalid port range {}-{} in rule '{source}'",
            range.start,
            range.end
        );
    }
    Ok(())
}

fn is_generic_port_rule(conditions: &[KernelCondition]) -> bool {
    conditions.iter().any(|condition| {
        !condition.not && matches!(&condition.predicate, KernelPredicate::DestinationPort(_))
    }) && conditions.iter().all(|condition| {
        !matches!(
            &condition.predicate,
            KernelPredicate::Domain(_)
                | KernelPredicate::ProcessName(_)
                | KernelPredicate::Mac(_)
                | KernelPredicate::Dscp(_)
        )
    })
}

fn rule_source(route: &CompiledRoute) -> String {
    let source = if route.rule_payload.is_empty() {
        route.name.clone()
    } else {
        format!("{} {} {}", route.name, route.rule_type, route.rule_payload)
    };
    source
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

fn bitmap_bit(id: u32) -> DomainRouting {
    let mut value = DomainRouting::default();
    let word = id as usize / 32;
    value.bitmap[word] |= 1u32 << (id % 32);
    value
}

fn canonical_lpm_key(bytes: &[u8; 16], prefix_len: u32) -> LpmKey {
    let mut data = [0u32; 4];
    for (index, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        data[index] = u32::from_ne_bytes(*chunk);
    }
    LpmKey { prefix_len, data }
}

fn add_ip_facts(
    v4: &mut Vec<(LpmKey, DomainRouting)>,
    v6: &mut Vec<(LpmKey, DomainRouting)>,
    nets: &[ipnet::IpNet],
    id: u32,
) {
    for net in nets {
        let mut bytes = [0u8; 16];
        match net {
            ipnet::IpNet::V4(net) => {
                bytes[..4].copy_from_slice(&net.network().octets());
                v4.push((
                    canonical_lpm_key(&bytes, net.prefix_len() as u32),
                    bitmap_bit(id),
                ));
            }
            ipnet::IpNet::V6(net) => {
                bytes.copy_from_slice(&net.network().octets());
                v6.push((
                    canonical_lpm_key(&bytes, net.prefix_len() as u32),
                    bitmap_bit(id),
                ));
            }
        }
    }
}

fn add_mac_fact(facts: &mut Vec<(LpmKey, DomainRouting)>, mac: &[u8; 6], id: u32) {
    let mut bytes = [0u8; 16];
    bytes[10..].copy_from_slice(mac);
    facts.push((canonical_lpm_key(&bytes, 128), bitmap_bit(id)));
}

/// Canonicalize duplicate keys and propagate ancestor bits with a bounded
/// prefix stack.  The stack is at most 129 entries (never O(N²)).
fn inherit_prefix_bits(entries: &mut Vec<(LpmKey, DomainRouting)>) {
    let mut merged: HashMap<[u8; 20], (LpmKey, DomainRouting)> =
        HashMap::with_capacity(entries.len());
    for (key, value) in entries.drain(..) {
        let raw = maps::lpm_key_bytes(&key);
        merged
            .entry(raw)
            .and_modify(|(_, current)| {
                for (left, right) in current.bitmap.iter_mut().zip(value.bitmap) {
                    *left |= right;
                }
            })
            .or_insert((key, value));
    }
    entries.extend(merged.into_values());
    entries.sort_by(|(a, _), (b, _)| {
        let a_bytes = maps::lpm_key_bytes(a);
        let b_bytes = maps::lpm_key_bytes(b);
        a_bytes[4..20]
            .cmp(&b_bytes[4..20])
            .then(a.prefix_len.cmp(&b.prefix_len))
    });
    let mut stack: Vec<(LpmKey, DomainRouting)> = Vec::with_capacity(129);
    for (key, value) in entries.iter_mut() {
        while let Some((ancestor, _)) = stack.last() {
            if prefix_contains(ancestor, key) {
                break;
            }
            stack.pop();
        }
        if let Some((_, ancestor_value)) = stack.last() {
            for (left, right) in value.bitmap.iter_mut().zip(ancestor_value.bitmap) {
                *left |= right;
            }
        }
        stack.push((*key, *value));
    }
    entries.shrink_to_fit();
}

fn prefix_contains(parent: &LpmKey, child: &LpmKey) -> bool {
    if parent.prefix_len > child.prefix_len {
        return false;
    }
    let parent_bytes = maps::lpm_key_bytes(parent);
    let child_bytes = maps::lpm_key_bytes(child);
    (0..parent.prefix_len).all(|bit| {
        let byte = 4 + bit as usize / 8;
        let mask = 1u8 << (7 - bit % 8);
        parent_bytes[byte] & mask == child_bytes[byte] & mask
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_prefixes_inherit_without_cross_family_matches() {
        let parent = "10.0.0.0/8".parse().unwrap();
        let child = "10.1.0.0/16".parse().unwrap();
        let sibling = "10.2.0.0/16".parse().unwrap();
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        add_ip_facts(&mut v4, &mut v6, &[child], 255);
        add_ip_facts(&mut v4, &mut v6, &[parent], 0);
        add_ip_facts(&mut v4, &mut v6, &[sibling], 31);
        add_ip_facts(&mut v4, &mut v6, &[child, child], 1);
        add_ip_facts(&mut v4, &mut v6, &["::/0".parse().unwrap()], 63);
        add_ip_facts(&mut v4, &mut v6, &["2001:db8::/32".parse().unwrap()], 255);
        inherit_prefix_bits(&mut v4);
        inherit_prefix_bits(&mut v6);
        let bitmaps = |entries: &[(LpmKey, DomainRouting)]| {
            entries
                .iter()
                .map(|(_, value)| value.bitmap)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            bitmaps(&v4),
            vec![
                [1, 0, 0, 0, 0, 0, 0, 0],
                [3, 0, 0, 0, 0, 0, 0, 1 << 31],
                [1 | (1 << 31), 0, 0, 0, 0, 0, 0, 0],
            ]
        );
        assert_eq!(
            bitmaps(&v6),
            vec![
                [0, 1 << 31, 0, 0, 0, 0, 0, 0],
                [0, 1 << 31, 0, 0, 0, 0, 0, 1 << 31],
            ]
        );
    }
}
