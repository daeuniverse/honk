//! Canonical in-memory publication/storage shared by software policy and test fixtures.

use super::{DomainRouteWriteError, RoutingPushPhase};
use honk_ebpf_common::*;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub(super) struct PolicyGeneration {
    pub(super) fingerprint: [u8; 32],
    pub(super) rule_count: usize,
    pub(super) facts: crate::control::routing_matcher::RoutingFactMaps,
    pub(super) domain: HashMap<[u32; 4], DomainRouting>,
}

#[derive(Debug, Default)]
pub(super) struct PolicyState {
    /// Only the generation selected by the stable root remains resident.
    pub(super) routing_generation: Option<PolicyGeneration>,
    pub(super) active_slot: u32,
    pub(super) descriptor: RoutingPolicyDescriptor,
    pub(super) next_generation: u64,
    pub(super) next_domain_map_id: u32,
    pub(super) next_trace_policy: u32,
    pub(super) outbound_alive: HashMap<u32, u32>,
}

impl PolicyState {
    pub(super) fn publish(
        &mut self,
        plan: &crate::control::routing_matcher::RoutingPushPlan,
        learned_domains: &[(LpmKey, DomainRouting)],
        mut phase: impl FnMut(RoutingPushPhase, u32) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let generation = self
            .next_generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("routing generation counter exhausted"))?;
        anyhow::ensure!(
            generation <= DNS_ROUTE_GENERATION_MAX,
            "routing generation counter exhausted at {DNS_ROUTE_GENERATION_MAX}"
        );
        anyhow::ensure!(
            self.active_slot < 2,
            "invalid active routing slot {}",
            self.active_slot
        );
        let slot = self.active_slot ^ 1;
        let trace_policy = if plan.trace_enabled() {
            self.next_trace_policy = self.next_trace_policy.saturating_add(1);
            self.next_trace_policy
        } else {
            0
        };
        phase(RoutingPushPhase::DomainRouting, slot)?;
        let domain: HashMap<_, _> = learned_domains
            .iter()
            .map(|(key, bitmap)| (key.data, *bitmap))
            .collect();
        phase(RoutingPushPhase::DestinationLpm, slot)?;
        phase(RoutingPushPhase::SourceLpm, slot)?;
        phase(RoutingPushPhase::MacLpm, slot)?;
        phase(RoutingPushPhase::Program, slot)?;
        phase(RoutingPushPhase::Attach, slot)?;

        let domain_map_id = self
            .next_domain_map_id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("domain map id counter exhausted"))?;
        let candidate = PolicyGeneration {
            fingerprint: plan.fingerprint,
            rule_count: plan.rules.len(),
            facts: plan.facts.clone(),
            domain,
        };
        phase(RoutingPushPhase::Root, slot)?;
        self.routing_generation = Some(candidate);
        self.active_slot = slot;
        self.descriptor = RoutingPolicyDescriptor {
            slot,
            features: plan.features,
            generation,
            domain_map_id,
            trace_policy,
        };
        self.next_generation = generation;
        self.next_domain_map_id = domain_map_id;
        Ok(())
    }

    pub(super) fn add_domain(
        &mut self,
        key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        let generation = self
            .routing_generation
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no active routing generation"))?;
        let current = generation.domain.entry(key.data).or_default();
        for (current, update) in current.bitmap.iter_mut().zip(bitmap.bitmap) {
            *current |= update;
        }
        Ok(())
    }

    pub(super) fn set_domain(
        &mut self,
        key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> Result<(), DomainRouteWriteError> {
        self.domain()?.insert(key.data, *bitmap);
        Ok(())
    }

    pub(super) fn remove_domain(&mut self, key: &LpmKey) -> Result<(), DomainRouteWriteError> {
        self.domain()?.remove(&key.data);
        Ok(())
    }

    fn domain(&mut self) -> Result<&mut HashMap<[u32; 4], DomainRouting>, DomainRouteWriteError> {
        self.routing_generation
            .as_mut()
            .map(|generation| &mut generation.domain)
            .ok_or_else(|| {
                DomainRouteWriteError::Other(anyhow::anyhow!("no active routing generation"))
            })
    }

    pub(super) fn set_alive(&mut self, outbound: u8, domain: u32, ipver: u32, alive: bool) {
        self.outbound_alive
            .insert(Self::alive_key(outbound, domain, ipver), u32::from(alive));
    }

    pub(super) fn alive(&self, outbound: u8, domain: u32, ipver: u32) -> bool {
        self.outbound_alive
            .get(&Self::alive_key(outbound, domain, ipver))
            .copied()
            .unwrap_or(0)
            != 0
    }

    fn alive_key(outbound: u8, domain: u32, ipver: u32) -> u32 {
        (outbound as u32)
            .wrapping_mul(6)
            .wrapping_add(domain.wrapping_mul(2))
            .wrapping_add(ipver)
    }

    pub(super) fn clear(&mut self) {
        self.routing_generation = None;
        self.descriptor = RoutingPolicyDescriptor::default();
        self.outbound_alive.clear();
    }
}
