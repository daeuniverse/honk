//! One backend-exclusive retirement protocol for every tuple-map deletion.
use super::*;
use crate::ebpf::retirement::{
    Owners, RedirectEffect, account_retirement, plan_retirement, plan_udp_commit, retire_staged_udp,
};
use crate::ebpf::udp_state_is_staged;
use aya::maps::ArrayOfMaps;
use honk_ebpf_common::conn::RetirementFence;
use std::collections::HashSet;

const IPPROTO_TCP: u8 = libc::IPPROTO_TCP as u8;
const IPPROTO_UDP: u8 = libc::IPPROTO_UDP as u8;

#[cfg(test)]
#[derive(Default)]
pub(super) struct RetirementFaults {
    pub(super) acquire: Option<usize>,
    pub(super) barrier: bool,
    pub(super) release: Option<usize>,
    pub(super) delete: Option<usize>,
    pub(super) quiesce_after_scan: Option<fn(&mut RealEbpfBackend) -> anyhow::Result<()>>,
}

#[cfg(test)]
pub(super) fn inject_indexed_fault(index: &mut Option<usize>, kind: &str) -> anyhow::Result<()> {
    if let Some(remaining) = index {
        if *remaining == 0 {
            *index = None;
            anyhow::bail!("injected retirement {kind} failure");
        }
        *remaining -= 1;
    }
    Ok(())
}

pub(super) fn init_retirement_grace(bpf: &mut Ebpf) -> anyhow::Result<AyaArray<AyaMapData, u32>> {
    let inner = AyaArray::create(1, 0)?;
    let root = bpf
        .map_mut("RETIRE_GRACE_ROOT")
        .ok_or_else(|| anyhow::anyhow!("RETIRE_GRACE_ROOT unavailable"))?;
    ArrayOfMaps::<_, AyaArray<AyaMapData, u32>>::try_from(root)?.set(0, &inner, 0)?;
    Ok(inner)
}

fn combine_error(original: &mut Option<anyhow::Error>, error: anyhow::Error) {
    *original = Some(match original.take() {
        Some(previous) => previous.context(format!("additional retirement failure: {error:#}")),
        None => error,
    });
}

impl RealEbpfBackend {
    pub(super) fn grace_barrier(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.retirement_failed,
            "retirement ownership is unresolved"
        );
        #[cfg(test)]
        if std::mem::take(&mut self.retirement_faults.barrier) {
            anyhow::bail!("injected retirement barrier failure");
        }
        let bpf = self
            .bpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("BPF backend closed"))?;
        let root = bpf
            .map_mut("RETIRE_GRACE_ROOT")
            .ok_or_else(|| anyhow::anyhow!("RETIRE_GRACE_ROOT unavailable"))?;
        // Linux map-in-map replacement synchronously waits for pre-update BPF
        // readers even when reinstalling the same inner FD. Never route through
        // policy publication: this private map is owned for this backend lifetime.
        ArrayOfMaps::<_, AyaArray<AyaMapData, u32>>::try_from(root)?.set(
            0,
            &self.retirement_grace_inner,
            0,
        )?;
        Ok(())
    }

    pub(super) fn with_retirement_fences<T>(
        &mut self,
        keys: &[(TuplesKey, u32)],
        operation: impl FnOnce(&mut Self) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        anyhow::ensure!(
            !self.retirement_failed,
            "retirement ownership is unresolved"
        );
        anyhow::ensure!(
            keys.len() <= RETIRE_BATCH_CAPACITY,
            "retirement batch exceeds capacity"
        );
        anyhow::ensure!(
            keys.iter().all(|(key, _)| key.padding == [0; 3]),
            "noncanonical retirement tuple"
        );
        let Some(owner) = self.retirement_owner.checked_add(1) else {
            self.retirement_failed = true;
            anyhow::bail!("retirement operation owner exhausted");
        };
        self.retirement_owner = owner;
        // Keep wide batches off the blocking worker's stack and preserve
        // acquisition order without scanning every previously acquired key.
        let mut acquired = Vec::with_capacity(keys.len());
        let mut seen = HashSet::with_capacity(keys.len());
        let mut failure = None;
        let mut value = None;
        let mut unresolved = false;
        self.array_set("RETIRE_ACTIVE", 0, &1u32)?;
        for (key, token) in keys {
            let identity = (
                unsafe { key.src_ip.u6_addr8 },
                unsafe { key.dst_ip.u6_addr8 },
                key.src_port,
                key.dst_port,
                key.l4proto,
            );
            if !seen.insert(identity) {
                continue;
            }
            let mut canonical = *key;
            canonical.padding = [0; 3];
            let fence = RetirementFence {
                owner,
                decision_token: *token,
                padding: 0,
            };
            #[cfg(test)]
            let acquisition = inject_indexed_fault(&mut self.retirement_faults.acquire, "acquire")
                .and_then(|()| self.hash_insert_noexist(RETIRE_FENCE_MAP, &canonical, &fence));
            #[cfg(not(test))]
            let acquisition = self.hash_insert_noexist(RETIRE_FENCE_MAP, &canonical, &fence);
            match acquisition {
                Ok(()) => {
                    acquired.push(canonical);
                }
                Err(error) => {
                    failure = Some(error);
                    match self.hash_lookup::<_, RetirementFence>(RETIRE_FENCE_MAP, &canonical) {
                        Ok(None) => {}
                        Ok(Some(_)) => unresolved = true,
                        Err(error) => {
                            unresolved = true;
                            combine_error(&mut failure, error);
                        }
                    }
                    break;
                }
            }
        }
        if failure.is_none() {
            match self.grace_barrier().and_then(|()| {
                for key in &acquired {
                    let current = self.hash_lookup::<_, RetirementFence>(RETIRE_FENCE_MAP, key)?;
                    anyhow::ensure!(
                        current.is_some_and(|fence| fence.owner == owner),
                        "retirement fence owner {owner} changed before mutation"
                    );
                }
                operation(self)
            }) {
                Ok(result) => value = Some(result),
                Err(error) => failure = Some(error),
            }
        }
        for key in &acquired {
            let release = (|| {
                #[cfg(test)]
                inject_indexed_fault(&mut self.retirement_faults.release, "release")?;
                let current = self.hash_lookup::<_, RetirementFence>(RETIRE_FENCE_MAP, key)?;
                anyhow::ensure!(
                    current.is_some_and(|fence| fence.owner == owner),
                    "retirement fence owner {owner} disappeared or changed"
                );
                anyhow::ensure!(
                    self.hash_remove_present::<_, RetirementFence>(RETIRE_FENCE_MAP, key)?,
                    "retirement fence owner {owner} disappeared during release"
                );
                Ok(())
            })();
            if let Err(error) = release {
                unresolved = true;
                combine_error(&mut failure, error);
            }
        }
        if unresolved {
            self.retirement_failed = true;
        } else if let Err(error) = self.array_set("RETIRE_ACTIVE", 0, &0u32) {
            self.retirement_failed = true;
            combine_error(&mut failure, error);
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(value.expect("successful retirement operation produced a result")),
        }
    }

    pub(super) fn retire_flows(
        &mut self,
        requests: &[RetireRequest<'_>],
        outcomes: &mut [RetireOutcome],
    ) -> Result<RetireCounts, RetireError> {
        outcomes.fill(RetireOutcome::NotRun);
        let mut counts = RetireCounts::default();
        let run = (|| {
            anyhow::ensure!(
                requests.len() == outcomes.len() && requests.len() <= RETIRE_BATCH_CAPACITY,
                "retirement input/output length mismatch or capacity exceeded"
            );
            anyhow::ensure!(
                !self.retirement_failed,
                "retirement ownership is unresolved"
            );
            if requests.is_empty() {
                return Ok(());
            }
            let mut keys = Vec::with_capacity(requests.len());
            for request in requests {
                anyhow::ensure!(
                    request.key.padding == [0; 3]
                        && matches!(request.key.l4proto, IPPROTO_TCP | IPPROTO_UDP),
                    "noncanonical retirement tuple"
                );
                let token = match request.kind {
                    RetireKind::Tcp { incarnation } => {
                        anyhow::ensure!(
                            request.key.l4proto == IPPROTO_TCP && incarnation != 0,
                            "invalid TCP retirement owner"
                        );
                        0
                    }
                    RetireKind::Udp {
                        token, incarnation, ..
                    } => {
                        anyhow::ensure!(
                            request.key.l4proto == IPPROTO_UDP
                                && incarnation != Some(0)
                                && (token != 0 || incarnation.is_some()),
                            "invalid UDP retirement owner"
                        );
                        token
                    }
                    RetireKind::ExpiredConn { expected, .. } => expected.decision_token,
                    RetireKind::ExpiredRedirect { expected, .. } => expected.decision_token,
                    RetireKind::ExpiredHandoff { expected, .. } => expected.result.decision_token,
                    RetireKind::ExpiryHint { incarnation, .. } => {
                        anyhow::ensure!(incarnation != 0, "invalid expiry incarnation");
                        0
                    }
                };
                keys.push((request.key, token));
            }
            self.with_retirement_fences(&keys[..requests.len()], |backend| {
                for (request, outcome) in requests.iter().zip(outcomes) {
                    *outcome = backend.retire_one(request, &mut counts)?;
                }
                Ok(())
            })
        })();
        let result = match run {
            Ok(()) => Ok(counts),
            Err(source) => Err(RetireError { counts, source }),
        };
        account_retirement(&result);
        self.aux_deletes.record(&result);
        result
    }

    fn retire_one(
        &mut self,
        request: &RetireRequest<'_>,
        counts: &mut RetireCounts,
    ) -> anyhow::Result<RetireOutcome> {
        let key = &request.key;
        let track_key = RedirectTuple::from_tuples(key);
        let reads = request.kind.owner_reads();
        let conn = if reads.conn {
            self.flow_lookup::<_, ConnState>("CONN_STATE_MAP", key)?
        } else {
            None
        };
        let handoff = if reads.handoff {
            self.flow_lookup::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?
        } else {
            None
        };
        let redirect = if reads.redirect {
            self.flow_lookup::<_, RedirectEntry>("REDIRECT_TRACK", &track_key)?
        } else {
            None
        };
        let owners = Owners {
            conn: conn.as_ref(),
            handoff: handoff.as_ref(),
            redirect: redirect.as_ref(),
        };
        let plan = match plan_retirement(request, &owners) {
            Ok(plan) => plan,
            Err(result) => return Ok(result.into()),
        };
        // Native lifetimes are never zero; only explicit model fixtures use that identity.
        if plan.conn && matches!(request.kind, RetireKind::Udp { .. }) {
            anyhow::ensure!(
                conn.is_some_and(|state| state.incarnation != 0),
                "UDP conn has no lifetime identity"
            );
        }
        let before = *counts;
        if plan.handoff {
            counts.handoff += u64::from(
                self.hash_remove_present::<_, FlowMapValue<RoutingHandoffEntry>>(
                    "ROUTING_HANDOFF_MAP",
                    key,
                )?,
            );
        }
        if plan.redirect {
            counts.redirect +=
                u64::from(self.hash_remove_present::<_, FlowMapValue<RedirectEntry>>(
                    "REDIRECT_TRACK",
                    &track_key,
                )?);
        }
        if plan.conn {
            counts.conn += u64::from(
                self.hash_remove_present::<_, FlowMapValue<ConnState>>("CONN_STATE_MAP", key)?,
            );
        }
        Ok(plan.outcome((*counts).since(before)))
    }

    pub(super) fn quiesce_staged_udp(&mut self) -> anyhow::Result<()> {
        self.udp_staging_quiesce_incomplete = true;
        self.grace_barrier()?;

        let mut staged = Vec::new();
        self.flow_for_each_chunk::<TuplesKey, ConnState>("CONN_STATE_MAP", 256, &mut |chunk| {
            staged.extend(chunk.iter().filter_map(|(key, state)| {
                (key.l4proto == IPPROTO_UDP && udp_state_is_staged(state.state)).then_some((
                    *key,
                    state.decision_token,
                    state.incarnation,
                ))
            }));
            true
        })?;
        #[cfg(test)]
        if let Some(complete_publication) = self.retirement_faults.quiesce_after_scan.take() {
            complete_publication(self)?;
        }
        retire_staged_udp(&staged, |requests, outcomes| {
            self.retire_flows(requests, outcomes)
        })?;
        self.fence_routing_generation()?;
        self.udp_staging_quiesce_incomplete = false;
        Ok(())
    }

    pub(super) fn activate_udp_direct(
        &mut self,
        key: &TuplesKey,
        token: u32,
        transition: UdpDecisionTransition,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        anyhow::ensure!(
            !self.retirement_failed,
            "retirement ownership is unresolved"
        );
        validate_udp_decision_transition(transition)?;
        if token == 0 {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        let Some(state) = self.flow_lookup::<_, ConnState>("CONN_STATE_MAP", key)? else {
            return Ok(UdpDecisionCommitResult::Missing);
        };
        if state.decision_token != token {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        anyhow::ensure!(
            state.incarnation != 0,
            "UDP commit has no lifetime identity"
        );
        let handoff = self.flow_lookup::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?;
        let track = self
            .flow_lookup::<_, RedirectEntry>("REDIRECT_TRACK", &RedirectTuple::from_tuples(key))?;
        let plan = match plan_udp_commit(state, token, transition, handoff.as_ref(), track.as_ref())
        {
            Ok(plan) => plan,
            Err(result) => return Ok(result),
        };
        // DirectArmed is immutable to the kernel; backend W excludes all other
        // writers and deleters. EXIST|LOCK copies into this same element, so no
        // reader can retain an element freed by a replacement or deletion.
        match self
            .hash_map_mut::<TuplesKey, FlowMapValue<ConnState>>("CONN_STATE_MAP")?
            .insert(
                key,
                &FlowMapValue::new(plan.state),
                (aya_obj::generated::BPF_EXIST | aya_obj::generated::BPF_F_LOCK) as u64,
            ) {
            Ok(()) => Ok(UdpDecisionCommitResult::Applied),
            Err(error) if Self::map_error_is_missing(&error) => {
                Ok(UdpDecisionCommitResult::Missing)
            }
            Err(error) => Err(anyhow::anyhow!("in-place UDP activation: {error}")),
        }
    }

    pub(super) fn commit_udp_fenced(
        &mut self,
        key: &TuplesKey,
        token: u32,
        transition: UdpDecisionTransition,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        anyhow::ensure!(
            !self.retirement_failed,
            "retirement ownership is unresolved"
        );
        validate_udp_decision_transition(transition)?;
        if token == 0 {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        let Some(captured) = self.flow_lookup::<_, ConnState>("CONN_STATE_MAP", key)? else {
            return Ok(UdpDecisionCommitResult::Missing);
        };
        self.with_retirement_fences(&[(*key, token)], |backend| {
            backend.commit_udp_checked(key, token, captured.incarnation, transition)
        })
    }

    pub(super) fn commit_udp_decisions(
        &mut self,
        requests: &[crate::ebpf::UdpDecisionCommit],
        visit: &mut crate::ebpf::UdpCommitVisit<'_>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            requests.len() <= RETIRE_BATCH_CAPACITY,
            "UDP commit batch exceeds capacity"
        );
        anyhow::ensure!(
            !self.retirement_failed,
            "retirement ownership is unresolved"
        );
        let mut captured = vec![None; requests.len()];
        let mut keys = Vec::with_capacity(requests.len());
        for (index, request) in requests.iter().enumerate() {
            validate_udp_decision_transition(request.transition)?;
            anyhow::ensure!(
                !matches!(request.transition, UdpDecisionTransition::ActivateDirect(_)),
                "direct activation cannot enter a fenced batch"
            );
            anyhow::ensure!(
                request.key.padding == [0; 3] && request.key.l4proto == IPPROTO_UDP,
                "noncanonical UDP commit tuple"
            );
            if request.token != 0 {
                captured[index] = self
                    .flow_lookup::<_, ConnState>("CONN_STATE_MAP", &request.key)?
                    .map(|state| state.incarnation);
                if captured[index].is_some() {
                    keys.push((request.key, request.token));
                }
            }
        }
        let mut operation = |backend: &mut Self| {
            for (index, request) in requests.iter().enumerate() {
                visit(index, &mut || match (request.token, captured[index]) {
                    (0, _) => Ok(UdpDecisionCommitResult::TokenMismatch),
                    (_, None) => Ok(UdpDecisionCommitResult::Missing),
                    (token, Some(incarnation)) => backend.commit_udp_checked(
                        &request.key,
                        token,
                        incarnation,
                        request.transition,
                    ),
                })?;
            }
            Ok(())
        };
        if keys.is_empty() {
            operation(self)
        } else {
            self.with_retirement_fences(&keys, operation)
        }
    }

    fn commit_udp_checked(
        &mut self,
        key: &TuplesKey,
        token: u32,
        incarnation: u64,
        transition: UdpDecisionTransition,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        let Some(state) = self.flow_lookup::<_, ConnState>("CONN_STATE_MAP", key)? else {
            return Ok(UdpDecisionCommitResult::Missing);
        };
        if state.decision_token != token || state.incarnation != incarnation {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        anyhow::ensure!(
            state.incarnation != 0,
            "UDP commit has no lifetime identity"
        );
        let handoff = self.flow_lookup::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?;
        let track_key = RedirectTuple::from_tuples(key);
        let track = self.flow_lookup::<_, RedirectEntry>("REDIRECT_TRACK", &track_key)?;
        let plan = match plan_udp_commit(state, token, transition, handoff.as_ref(), track.as_ref())
        {
            Ok(plan) => plan,
            Err(result) => return Ok(result),
        };
        if plan.remove_handoff {
            self.hash_remove::<_, FlowMapValue<RoutingHandoffEntry>>("ROUTING_HANDOFF_MAP", key)?;
            self.aux_deletes.handoff += 1;
        }
        match plan.redirect {
            Some(RedirectEffect::Rewrite(track)) => {
                self.flow_insert("REDIRECT_TRACK", &track_key, &track)?
            }
            Some(RedirectEffect::Remove) => {
                self.hash_remove::<_, FlowMapValue<RedirectEntry>>("REDIRECT_TRACK", &track_key)?;
                self.aux_deletes.redirect += 1;
            }
            None => {}
        }
        self.flow_insert("CONN_STATE_MAP", key, &plan.state)?;
        Ok(UdpDecisionCommitResult::Applied)
    }
}
