//! Frozen source-owned dictionaries; decoding never evaluates a router or reads current policy.

use super::record::RouteInput;
use crate::native_api::routing::{RuleCondition, RuleEvaluation, rule_id};
use crate::{
    control::routing_matcher::{KernelTraceDisposition, KernelTraceLayout, RoutingPushPlan},
    routing::Router,
};
use honk_ebpf_common::*;
use std::{
    collections::VecDeque,
    mem::size_of,
    net::{IpAddr, Ipv6Addr},
};

const MAX_DICTIONARIES: usize = 16;
const MAX_DICTIONARY_BYTES: usize = 64 * 1024;
pub(super) const MAX_RETAINED_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct KernelRouteReference {
    pub trace_id: u32,
    pub decision_token: u32,
    pub routing_generation: u64,
    pub effective_outbound: u8,
    pub mark: Option<u32>,
    pub must: Option<u8>,
}

impl From<&RoutingHandoffEntry> for KernelRouteReference {
    fn from(entry: &RoutingHandoffEntry) -> Self {
        Self {
            trace_id: entry.trace_id,
            decision_token: entry.result.decision_token,
            routing_generation: entry.routing_generation,
            effective_outbound: entry.result.outbound,
            mark: Some(entry.result.mark),
            must: Some(entry.result.must),
        }
    }
}

#[derive(Debug)]
pub struct KernelTraceDictionary {
    instance: String,
    generation: u64,
    fingerprint: [u8; 32],
    layout: KernelTraceLayout,
    rules: Vec<(Option<u32>, RuleEvaluation)>,
    outbounds: Vec<(u8, String)>,
    bytes: usize,
}

impl KernelTraceDictionary {
    pub(crate) fn prepare(
        instance: &str,
        generation: u64,
        router: &Router,
        config: &honk_config::Config,
        plan: &RoutingPushPlan,
    ) -> Option<Self> {
        let layout = plan.trace_layout()?;
        let mut rules = Vec::new();
        for slot in &layout.slots {
            if rules.iter().any(|(id, _)| *id == slot.rule_id) {
                continue;
            }
            let id = rule_id(instance, generation, slot.rule_id);
            let compiled = slot
                .rule_id
                .and_then(|id| router.compiled_routes().iter().find(|rule| rule.id == id));
            let conditions = compiled
                .map(|rule| {
                    rule.conditions
                        .iter()
                        .enumerate()
                        .filter(|(ordinal, _)| {
                            layout.slots.iter().any(|slot| {
                                slot.rule_id == Some(rule.id)
                                    && slot.condition_ordinal == Some(*ordinal)
                            })
                        })
                        .map(|(ordinal, _)| RuleCondition {
                            id: format!("{id}/condition:{ordinal}"),
                            expression: rule.condition_expressions[ordinal].clone(),
                            result: "indeterminate",
                            missing_inputs: Vec::new(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let expression = compiled
                .map(|rule| rule.expression.clone())
                .unwrap_or_else(|| "fallback".into());
            rules.push((
                slot.rule_id,
                RuleEvaluation {
                    rule_id: id,
                    expression,
                    result: "indeterminate",
                    missing_inputs: Vec::new(),
                    conditions,
                },
            ));
            if rules
                .iter()
                .map(|(_, row)| row.heap_bytes() + size_of::<RuleEvaluation>())
                .sum::<usize>()
                > MAX_DICTIONARY_BYTES
            {
                return None;
            }
        }
        let mut outbounds = vec![
            (0, "direct".into()),
            (1, "block".into()),
            (0xfc, "must_rules".into()),
            (0xfd, "control_plane_routing".into()),
        ];
        for (index, group) in config.groups.iter().enumerate() {
            let index = u8::try_from(index).ok()?.checked_add(2)?;
            if index >= 0xfc {
                break;
            }
            outbounds.push((index, group.name.clone()));
        }
        let bytes = size_of::<Self>()
            + instance.len()
            + layout.slots.capacity()
                * size_of::<crate::control::routing_matcher::KernelTraceSlot>()
            + rules.capacity() * size_of::<(Option<u32>, RuleEvaluation)>()
            + rules.iter().map(|(_, row)| row.heap_bytes()).sum::<usize>()
            + outbounds.capacity() * size_of::<(u8, String)>()
            + outbounds
                .iter()
                .map(|(_, name)| name.capacity())
                .sum::<usize>();
        if bytes > MAX_DICTIONARY_BYTES {
            return None;
        }
        Some(Self {
            instance: instance.into(),
            generation,
            fingerprint: plan.fingerprint,
            layout,
            rules,
            outbounds,
            bytes,
        })
    }

    fn outbound(&self, index: u8) -> Option<String> {
        self.outbounds
            .iter()
            .find(|(id, _)| *id == index)
            .map(|(_, name)| name.clone())
    }

    fn decode(&self, witness: &KernelRouteWitness, effective: u8) -> CapturedKernelRoute {
        let output = &witness.output;
        let complete = output.flags & ROUTE_TRACE_COMPLETE != 0;
        let mut rules: Vec<_> = self.rules.iter().map(|(_, row)| row.clone()).collect();
        let mut invalid = false;
        for (index, slot) in self.layout.slots.iter().enumerate() {
            let result = match slot.disposition {
                KernelTraceDisposition::Runtime => match output.outcome(index) {
                    Some(0) if complete => "skipped",
                    Some(1) => "matched",
                    Some(2) => "not_matched",
                    _ => {
                        invalid = true;
                        "indeterminate"
                    }
                },
                _ => "skipped",
            };
            let Some(position) = self.rules.iter().position(|(id, _)| *id == slot.rule_id) else {
                continue;
            };
            let row = &mut rules[position];
            if let Some(ordinal) = slot.condition_ordinal {
                let id = format!("{}/condition:{ordinal}", row.rule_id);
                if let Some(condition) = row
                    .conditions
                    .iter_mut()
                    .find(|condition| condition.id == id)
                {
                    condition.result = result;
                }
            } else {
                row.result = result;
            }
        }
        let input = &output.input;
        let pname = (input.pname_len != 0).then(|| {
            String::from_utf8_lossy(
                &input.pname[..(input.pname_len as usize).min(input.pname.len())],
            )
            .into_owned()
        });
        let src_mac = (input.mac_present != 0).then(|| {
            input.mac[10..]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        });
        let truncated = output.flags & ROUTE_TRACE_OVERFLOW != 0;
        let ambiguous = output.flags & ROUTE_TRACE_AMBIGUOUS != 0;
        let outbound = u8::try_from(output.decision.outbound)
            .ok()
            .and_then(|index| self.outbound(index));
        let effective_outbound = self.outbound(effective);
        let missing_binding = outbound.is_none() || effective_outbound.is_none();
        CapturedKernelRoute {
            generation: self.generation,
            evaluation_id: format!("{}:kernel:{}", self.instance, witness.capture_id),
            input: RouteInput {
                network: if witness.tuple.l4proto == 6 {
                    "tcp"
                } else {
                    "udp"
                },
                src_ip: ip(input.src_ip),
                src_port: input.src_port as u16,
                dst_ip: ip(input.dst_ip),
                dst_port: input.dst_port as u16,
                domain: None,
                pname,
                src_mac,
                dscp: Some(input.dscp as u8),
                mark: (),
                ingress: Some(if input.is_wan == 0 { "lan" } else { "wan" }),
                domain_rule_ids: None,
                domain_fact_bitmap: None,
                domain_fact_state: None,
            },
            rules,
            rule_id: complete.then(|| {
                rule_id(
                    &self.instance,
                    self.generation,
                    (output.decision.rule_id != u32::MAX).then_some(output.decision.rule_id),
                )
            }),
            outbound,
            effective_outbound,
            must: output.decision.must != 0,
            mark: output.decision.mark,
            truncated,
            ambiguous,
            gap: if !complete {
                Some("kernel_trace_incomplete")
            } else if invalid {
                Some("kernel_trace_invalid_outcome")
            } else if missing_binding {
                Some("kernel_trace_outbound_binding_missing")
            } else if ambiguous {
                Some("kernel_tcp_history_ambiguous")
            } else if truncated {
                Some("kernel_trace_truncated")
            } else {
                None
            },
            fact_state: output.fact_state,
            domain_bitmap: output.domain_bitmap.bitmap,
        }
    }
}

fn ip(bytes: [u8; 16]) -> IpAddr {
    let ip = Ipv6Addr::from(bytes);
    ip.to_ipv4_mapped()
        .map(IpAddr::V4)
        .unwrap_or(IpAddr::V6(ip))
}

#[derive(Debug, Clone)]
pub struct CapturedKernelRoute {
    pub(crate) generation: u64,
    pub(crate) evaluation_id: String,
    pub(crate) input: RouteInput,
    pub(crate) rules: Vec<RuleEvaluation>,
    pub(crate) rule_id: Option<String>,
    pub(crate) outbound: Option<String>,
    pub(crate) effective_outbound: Option<String>,
    pub(crate) must: bool,
    pub(crate) mark: u32,
    pub(crate) truncated: bool,
    pub(crate) ambiguous: bool,
    pub(crate) gap: Option<&'static str>,
    pub(crate) fact_state: u32,
    pub(crate) domain_bitmap: [u32; 8],
}

#[derive(Debug, Default)]
pub(crate) struct KernelTraceDictionaries {
    owners: VecDeque<(u32, KernelTraceDictionary)>,
    bytes: usize,
    highest_bound_policy: u32,
}

impl KernelTraceDictionaries {
    pub(crate) fn bind(
        &mut self,
        policy: u32,
        fingerprint: [u8; 32],
        dictionary: KernelTraceDictionary,
    ) {
        if policy == 0
            || policy == u32::MAX
            || policy <= self.highest_bound_policy
            || dictionary.fingerprint != fingerprint
        {
            return;
        }
        self.highest_bound_policy = policy;
        while self.owners.len() >= MAX_DICTIONARIES
            || self.bytes + dictionary.bytes > MAX_RETAINED_BYTES
        {
            let Some((_, old)) = self.owners.pop_front() else {
                return;
            };
            self.bytes -= old.bytes;
        }
        self.bytes += dictionary.bytes;
        self.owners.push_back((policy, dictionary));
    }

    pub(crate) fn capture(
        &self,
        witness: &KernelRouteWitness,
        key: &TuplesKey,
        reference: KernelRouteReference,
    ) -> Result<CapturedKernelRoute, &'static str> {
        let KernelRouteReference {
            trace_id,
            decision_token: token,
            routing_generation: generation,
            effective_outbound: effective,
            mark,
            must,
        } = reference;
        if trace_id == 0 {
            return Err("kernel_trace_not_captured");
        }
        if trace_id == ROUTE_TRACE_LOST {
            return Err("kernel_trace_lost");
        }
        let output = &witness.output;
        if witness.capture_id != trace_id
            || witness.decision_token != token
            || witness.tuple.src_ip.as_bytes() != key.src_ip.as_bytes()
            || witness.tuple.dst_ip.as_bytes() != key.dst_ip.as_bytes()
            || witness.tuple.src_port != key.src_port
            || witness.tuple.dst_port != key.dst_port
            || witness.tuple.l4proto != key.l4proto
            || output.generation != generation
            || generation == 0
            || output.flags & ROUTE_TRACE_VERSION_MASK != ROUTE_TRACE_VERSION
            || output.flags & ROUTE_TRACE_ENABLED == 0
        {
            return Err("kernel_trace_identity_mismatch");
        }
        let input = &output.input;
        if input.src_ip != *key.src_ip.as_bytes()
            || input.dst_ip != *key.dst_ip.as_bytes()
            || input.src_port != u32::from(key.src_port)
            || input.dst_port != u32::from(key.dst_port)
            || !matches!((key.l4proto, input.l4proto), (6, 1) | (17, 2))
            || input.pname_len as usize > input.pname.len()
            || output.decision.outbound > u8::MAX as u32
            || output.decision.must > 1
        {
            return Err("kernel_trace_input_mismatch");
        }
        let mut decision = output.decision;
        if output.flags & ROUTE_TRACE_DNS_OVERRIDE != 0 {
            if key.dst_port != 53 || decision.must != 0 {
                return Err("kernel_trace_action_mismatch");
            }
            decision.outbound = 0xfd;
        }
        if decision.handoff_outbound() != effective
            || mark.is_some_and(|mark| mark != decision.mark)
            || must.is_some_and(|must| u32::from(must) != decision.must)
        {
            return Err("kernel_trace_action_mismatch");
        }
        let dictionary = self
            .owners
            .iter()
            .find(|(id, _)| *id == output.policy_id)
            .map(|(_, dictionary)| dictionary)
            .ok_or("kernel_trace_dictionary_missing")?;
        Ok(dictionary.decode(witness, effective))
    }
}

#[cfg(test)]
mod tests;
