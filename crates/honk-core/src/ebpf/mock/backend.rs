use super::*;
use crate::ebpf;

#[async_trait]
impl EbpfBackend for MockEbpfBackend {
    fn observe_datapath(&self) -> ebpf::DatapathObservation {
        #[cfg(test)]
        if let Some(observation) = &self.datapath_observation_fixture {
            return observation.clone();
        }
        ebpf::DatapathObservation::unknown(ebpf::DatapathKind::Mock)
    }

    #[cfg(test)]
    fn pname_support(&self) -> ebpf::PnameSupport {
        self.pname_support
    }

    fn inject_routing_fault(
        &mut self,
        phase: RoutingPushPhase,
        times: usize,
    ) -> anyhow::Result<()> {
        self.routing_fault = (times != 0).then_some((phase, times));
        Ok(())
    }

    #[cfg(test)]
    fn inject_projection_fault(
        &mut self,
        operation: ProjectionMapOperation,
        times: usize,
        map_full: bool,
    ) -> anyhow::Result<()> {
        self.projection_fault = (times != 0).then_some((operation, times, map_full));
        Ok(())
    }

    #[cfg(test)]
    fn inject_domain_bitmap_add_fault(&mut self, times: usize) -> anyhow::Result<()> {
        self.domain_bitmap_add_faults = times;
        Ok(())
    }

    #[cfg(test)]
    fn projection_map_snapshot(&self) -> Vec<([u8; 20], DomainRouting)> {
        let mut snapshot = self
            .routing_generation
            .as_ref()
            .map(|generation| {
                generation
                    .domain
                    .iter()
                    .map(|(key, bitmap)| {
                        (
                            Self::lpm_key_bytes(&LpmKey {
                                prefix_len: 128,
                                data: *key,
                            }),
                            *bitmap,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        snapshot.sort_by_key(|(key, _)| *key);
        snapshot
    }

    #[cfg(test)]
    fn projection_write_log(&self) -> Vec<ProjectionMapOperation> {
        self.projection_writes.clone()
    }

    #[cfg(test)]
    fn clear_projection_write_log(&mut self) {
        self.projection_writes.clear();
    }
    fn publish_listener_sockets(
        &mut self,
        tcp4_fd: std::os::fd::RawFd,
        tcp6_fd: Option<std::os::fd::RawFd>,
        udp4_fds: &[std::os::fd::RawFd],
        udp6_fds: &[std::os::fd::RawFd],
    ) -> anyhow::Result<()> {
        self.listener_socket_slots.insert(0, tcp4_fd);
        if let Some(fd) = tcp6_fd {
            self.listener_socket_slots.insert(1, fd);
        }
        for (base, fds) in [(2, udp4_fds), (6, udp6_fds)] {
            for (offset, fd) in fds.iter().enumerate() {
                self.listener_socket_slots.insert(base + offset as u32, *fd);
            }
        }
        self.listener_sockets_published = true;
        Ok(())
    }

    fn clear_listener_sockets(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.datapath_ready,
            "datapath admission must be closed before clearing listeners"
        );
        self.listener_sockets_published = false;
        for key in 0..10 {
            #[cfg(test)]
            if self.listener_clear_fault_at == Some(key) {
                self.listener_clear_fault_at = None;
                anyhow::bail!("injected listener clear failure");
            }
            self.listener_socket_slots.remove(&key);
        }
        Ok(())
    }

    fn set_datapath_ready(&mut self, ready: bool) -> anyhow::Result<()> {
        if ready && !self.listener_sockets_published {
            anyhow::bail!("listener socket generation is not fully published");
        }
        self.datapath_ready = ready;
        Ok(())
    }

    fn set_datapath_flags(&mut self, flags: u32) -> anyhow::Result<()> {
        self.datapath_flags_writes.lock().push(flags);
        #[cfg(test)]
        {
            self.datapath_flags_writes_after_arm =
                self.datapath_flags_writes_after_arm.saturating_add(1);
            let ordinal = self.datapath_flags_writes_after_arm;
            let failed = self.datapath_flags_fault_nth == Some(ordinal);
            self.datapath_flags_write_trace
                .push(DatapathFlagsWriteTrace {
                    ordinal,
                    origin: std::mem::take(&mut self.datapath_flags_write_origin),
                    flags,
                    failed,
                });
            if failed {
                self.datapath_flags_fault_nth = None;
                anyhow::bail!("injected datapath flags write failure at ordinal {ordinal}");
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn arm_datapath_flags_write_fault(&mut self, nth: usize) -> anyhow::Result<()> {
        anyhow::ensure!(nth != 0, "datapath flags write ordinal must be non-zero");
        self.datapath_flags_fault_nth = Some(nth);
        self.datapath_flags_writes_after_arm = 0;
        Ok(())
    }

    #[cfg(test)]
    fn arm_quiesce_fault(&mut self) {
        self.fail_next_quiesce = true;
    }

    #[cfg(test)]
    fn mark_datapath_flags_write_origin(&mut self, origin: DatapathFlagsWriteOrigin) {
        self.datapath_flags_write_origin = origin;
    }

    #[cfg(test)]
    fn datapath_flags_write_log(&self) -> Vec<u32> {
        self.datapath_flags_writes.lock().clone()
    }

    #[cfg(test)]
    fn datapath_flags_write_trace(&self) -> Vec<DatapathFlagsWriteTrace> {
        self.datapath_flags_write_trace.clone()
    }

    #[cfg(test)]
    fn clear_datapath_flags_write_log(&mut self) {
        self.datapath_flags_writes.lock().clear();
        self.datapath_flags_write_trace.clear();
        self.datapath_flags_writes_after_arm = 0;
    }

    fn quiesce_udp_staging(&mut self) -> anyhow::Result<()> {
        #[cfg(test)]
        self.quiesce_datapath_ready.lock().push(self.datapath_ready);
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_quiesce) {
            anyhow::bail!("injected quiesce failure");
        }
        let staged = self
            .udp_conn_states
            .iter()
            .filter(|(_, state)| udp_state_is_staged(state.state))
            .map(|(key, state)| {
                (
                    Self::bytes_to_tuples_key(key),
                    state.decision_token,
                    state.incarnation,
                )
            })
            .collect::<Vec<_>>();
        retire_staged_udp(&staged, |requests, outcomes| {
            self.retire_batch(requests, outcomes)
        })?;
        if self.routing_generation.is_some() {
            let generation = self
                .next_generation
                .checked_add(1)
                .filter(|generation| *generation <= DNS_ROUTE_GENERATION_MAX)
                .ok_or_else(|| anyhow::anyhow!("routing generation counter exhausted"))?;
            self.next_generation = generation;
            self.descriptor.generation = generation;
        }
        Ok(())
    }

    fn publish_routing_plan(
        &mut self,
        plan: &crate::control::routing_matcher::RoutingPushPlan,
        learned_domains: &[(LpmKey, DomainRouting)],
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
        self.take_routing_fault(RoutingPushPhase::DomainRouting)?;
        let domain: HashMap<_, _> = learned_domains
            .iter()
            .map(|(key, bitmap)| (key.data, *bitmap))
            .collect();
        self.take_routing_fault(RoutingPushPhase::DestinationLpm)?;
        self.take_routing_fault(RoutingPushPhase::SourceLpm)?;
        self.take_routing_fault(RoutingPushPhase::MacLpm)?;
        let domain_write_count = domain.len();
        self.routing_publication_order
            .push(MockRoutingPublicationWrite::FactMaps(slot));
        self.take_routing_fault(RoutingPushPhase::Program)?;
        self.routing_publication_order
            .push(MockRoutingPublicationWrite::Program(slot));
        self.take_routing_fault(RoutingPushPhase::Attach)?;
        self.routing_publication_order
            .push(MockRoutingPublicationWrite::Attach(slot));

        let domain_map_id = self
            .next_domain_map_id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("domain map id counter exhausted"))?;
        let candidate = MockRoutingGeneration {
            fingerprint: plan.fingerprint,
            rule_count: plan.rules.len(),
            facts: plan.facts.clone(),
            domain,
        };
        self.take_routing_fault(RoutingPushPhase::Root)?;
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
        self.routing_publication_order
            .push(MockRoutingPublicationWrite::Root(slot));
        self.count_routing_writes(
            (plan.facts.destination_v4.len()
                + plan.facts.destination_v6.len()
                + plan.facts.source_v4.len()
                + plan.facts.source_v6.len()
                + plan.facts.mac.len()
                + plan.rules.len()
                + domain_write_count
                + 1) as u64,
        );
        Ok(())
    }

    fn routing_policy_generation(&self) -> u64 {
        self.next_generation
    }

    fn active_routing_slot(&self) -> anyhow::Result<u32> {
        Ok(self.active_slot)
    }

    fn add_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        #[cfg(test)]
        if self.domain_bitmap_add_faults > 0 {
            self.domain_bitmap_add_faults -= 1;
            anyhow::bail!("injected domain bitmap write failure");
        }
        let generation = self
            .routing_generation
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no active routing generation"))?;
        let current = generation.domain.entry(ip_key.data).or_default();
        for (current, update) in current.bitmap.iter_mut().zip(bitmap.bitmap) {
            *current |= update;
        }
        self.count_routing_writes(1);
        Ok(())
    }

    fn set_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> Result<(), ebpf::DomainRouteWriteError> {
        #[cfg(test)]
        self.take_projection_fault(ProjectionMapOperation::Set)?;
        let generation = self.routing_generation.as_mut().ok_or_else(|| {
            ebpf::DomainRouteWriteError::Other(anyhow::anyhow!("no active routing generation"))
        })?;
        generation.domain.insert(ip_key.data, *bitmap);
        self.count_routing_writes(1);
        Ok(())
    }

    fn remove_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
    ) -> Result<(), ebpf::DomainRouteWriteError> {
        #[cfg(test)]
        self.take_projection_fault(ProjectionMapOperation::Remove)?;
        let generation = self.routing_generation.as_mut().ok_or_else(|| {
            ebpf::DomainRouteWriteError::Other(anyhow::anyhow!("no active routing generation"))
        })?;
        generation.domain.remove(&ip_key.data);
        self.count_routing_writes(1);
        Ok(())
    }

    fn conn_state_lookup(&self, key: &TuplesKey) -> anyhow::Result<Option<ConnState>> {
        Ok(self
            .conn_states(key.l4proto)
            .get(&Self::tuples_key_bytes(key))
            .copied())
    }

    #[cfg(test)]
    fn tcp_conn_state_store(&mut self, key: &TuplesKey, state: &ConnState) -> anyhow::Result<()> {
        self.tcp_conn_states
            .insert(Self::tuples_key_bytes(key), *state);
        Ok(())
    }

    fn udp_flow_owner(
        &self,
        token: u32,
        state: Option<ConnState>,
    ) -> anyhow::Result<ebpf::UdpFlowOwner> {
        #[cfg(test)]
        anyhow::ensure!(
            !self.commit_fence_unresolved,
            "retirement ownership is unresolved"
        );
        let Some(state) = state else {
            anyhow::ensure!(token == 0, "model staged UDP admission has no conn-state");
            return ebpf::UdpFlowOwner::new(token, None);
        };
        anyhow::ensure!(
            state.decision_token == token,
            "model UDP decision token mismatch"
        );
        ebpf::UdpFlowOwner::new(token, (state.incarnation != 0).then_some(state.incarnation))
    }

    #[cfg(test)]
    fn udp_conn_state_store(&mut self, key: &TuplesKey, state: &ConnState) -> anyhow::Result<()> {
        self.udp_conn_states
            .insert(Self::tuples_key_bytes(key), *state);
        Ok(())
    }

    fn commit_udp_decision(
        &mut self,
        key: &TuplesKey,
        token: u32,
        transition: UdpDecisionTransition,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        #[cfg(test)]
        anyhow::ensure!(
            !self.commit_fence_unresolved,
            "retirement ownership is unresolved"
        );
        #[cfg(test)]
        if let Some(delay) = self.commit_delay {
            std::thread::sleep(delay);
        }
        validate_udp_decision_transition(transition)?;
        if token == 0 {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        let key_bytes = Self::tuples_key_bytes(key);
        let Some(state) = self.udp_conn_states.get(&key_bytes).copied() else {
            return Ok(UdpDecisionCommitResult::Missing);
        };
        if state.decision_token != token {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        #[cfg(test)]
        if !matches!(transition, UdpDecisionTransition::ActivateDirect(_))
            && std::mem::take(&mut self.commit_barrier_fault)
        {
            anyhow::bail!("injected UDP commit barrier failure");
        }
        let handoff = self.routing_handoffs.lock().get(&key_bytes).copied();
        // Explicit model fixtures may commit a zero-identity staged flow.
        let track_key = Self::redirect_tuple_bytes(&RedirectTuple::from_tuples(key));
        let track = self.redirect_tracks.get(&track_key).copied();
        let plan = match plan_udp_commit(state, token, transition, handoff.as_ref(), track.as_ref())
        {
            Ok(plan) => plan,
            Err(result) => return Ok(result),
        };
        if plan.remove_handoff {
            self.routing_handoffs.lock().remove(&key_bytes);
        }
        match plan.redirect {
            Some(RedirectEffect::Rewrite(track)) => {
                self.redirect_tracks.insert(track_key, track);
            }
            Some(RedirectEffect::Remove) => {
                self.redirect_tracks.remove(&track_key);
            }
            None => {}
        }
        self.udp_conn_states.insert(key_bytes, plan.state);
        #[cfg(test)]
        self.commit_trace.lock().push((token, transition));
        Ok(UdpDecisionCommitResult::Applied)
    }

    fn commit_udp_batch(
        &mut self,
        requests: &[ebpf::UdpDecisionCommit],
        visit: &mut ebpf::UdpCommitVisit<'_>,
    ) -> anyhow::Result<()> {
        #[cfg(test)]
        anyhow::ensure!(
            !self.commit_fence_unresolved,
            "retirement ownership is unresolved"
        );
        anyhow::ensure!(
            requests.len() <= RETIRE_BATCH_CAPACITY,
            "UDP commit batch exceeds capacity"
        );
        for request in requests {
            validate_udp_decision_transition(request.transition)?;
            anyhow::ensure!(
                !matches!(request.transition, UdpDecisionTransition::ActivateDirect(_)),
                "direct activation cannot enter a fenced batch"
            );
            anyhow::ensure!(
                request.key.padding == [0; 3] && request.key.l4proto == libc::IPPROTO_UDP as u8,
                "noncanonical UDP commit tuple"
            );
        }
        #[cfg(test)]
        let delay = self.commit_delay.take();
        #[cfg(test)]
        let fenced = requests.iter().any(|request| {
            request.token != 0
                && self
                    .udp_conn_states
                    .contains_key(&Self::tuples_key_bytes(&request.key))
        });
        let result = (|| {
            #[cfg(test)]
            {
                self.commit_batch_sizes.lock().push(requests.len());
                if let Some(delay) = delay
                    && fenced
                {
                    std::thread::sleep(delay);
                }
                if fenced && std::mem::take(&mut self.commit_barrier_fault) {
                    anyhow::bail!("injected UDP commit barrier failure");
                }
            }
            for (index, request) in requests.iter().enumerate() {
                #[cfg(test)]
                if let Some((delayed, duration)) = self.commit_item_delay
                    && delayed == index
                {
                    std::thread::sleep(duration);
                }
                visit(index, &mut || {
                    self.commit_udp_decision(&request.key, request.token, request.transition)
                })?;
            }
            #[cfg(test)]
            if let Some(delay) = self.commit_release_delay
                && fenced
            {
                std::thread::sleep(delay);
            }
            #[cfg(test)]
            if fenced && std::mem::take(&mut self.commit_release_fault) {
                self.commit_fence_unresolved = true;
                anyhow::bail!("injected UDP commit fence release failure");
            }
            Ok(())
        })();
        #[cfg(test)]
        {
            self.commit_delay = delay;
        }
        result
    }
    fn adopt_tcp(
        &self,
        _fd: std::os::fd::BorrowedFd<'_>,
        tuples: &TuplesKey,
        _errors: ebpf::TcpPinErrorSink,
    ) -> anyhow::Result<ebpf::TcpAdoption> {
        #[cfg(test)]
        if self
            .adopt_proof_pending
            .try_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            return Err(ebpf::TcpChildProofPending.into());
        }
        let current = self
            .conn_state_lookup(tuples)?
            .ok_or_else(|| anyhow::anyhow!("accepted TCP flow has no conn-state: {tuples:?}"))?;
        Ok(ebpf::TcpAdoption {
            incarnation: current.incarnation,
            handoff: self.routing_handoff_lookup(tuples)?,
            pin: ebpf::TcpPin::Model,
        })
    }

    #[cfg(test)]
    fn tcp_socket_ownership(
        &self,
        _fd: std::os::fd::BorrowedFd<'_>,
    ) -> anyhow::Result<TcpSocketOwnership> {
        Ok(TcpSocketOwnership::Model)
    }

    fn take_expiry_hints(&mut self) -> Option<tokio::sync::mpsc::Receiver<FlowExpiryHint>> {
        None
    }

    fn conn_state_occupancy(&self) -> anyhow::Result<(u64, u64)> {
        #[cfg(test)]
        anyhow::ensure!(
            !self.telemetry_faults.lock().conn_occupancy,
            "injected conn occupancy read failure"
        );
        Ok((0, 0))
    }

    fn aux_occupancy(&self) -> anyhow::Result<(u64, u64)> {
        #[cfg(test)]
        anyhow::ensure!(
            !self.telemetry_faults.lock().aux_occupancy,
            "injected auxiliary occupancy read failure"
        );
        Ok((
            self.redirect_tracks.len() as u64,
            self.routing_handoffs.lock().len() as u64,
        ))
    }

    fn set_admission_pressure(&mut self, pressured: bool) -> anyhow::Result<()> {
        self.admission_pressure
            .store(pressured, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn retire_batch(
        &mut self,
        requests: &[RetireRequest<'_>],
        outcomes: &mut [RetireOutcome],
    ) -> Result<RetireCounts, RetireError> {
        outcomes.fill(RetireOutcome::NotRun);
        let mut counts = RetireCounts::default();
        let result = self
            .retire_model_batch(requests, outcomes, &mut counts)
            .map(|()| counts)
            .map_err(|source| RetireError { counts, source });
        account_retirement(&result);
        result
    }

    fn verify_udp_decision_sequence(&self) -> anyhow::Result<()> {
        self.udp_decision_sequence_status().map(|_| ())
    }
    fn udp_decision_sequence_status(&self) -> anyhow::Result<UdpDecisionSequenceStatus> {
        anyhow::ensure!(
            self.udp_decision_sequence_next <= honk_ebpf_common::UDP_DECISION_SEQUENCE_MASK,
            "invalid mock UDP decision sequence"
        );
        anyhow::ensure!(
            self.udp_decision_sequence_generation <= honk_ebpf_common::UDP_DECISION_GENERATION_MASK,
            "invalid mock UDP decision generation"
        );
        Ok(UdpDecisionSequenceStatus {
            next: self.udp_decision_sequence_next,
            generation: self.udp_decision_sequence_generation,
        })
    }

    fn reset_udp_decision_sequence(&mut self, generation: u32) -> anyhow::Result<bool> {
        anyhow::ensure!(
            generation <= honk_ebpf_common::UDP_DECISION_GENERATION_MASK,
            "invalid UDP decision generation {generation}"
        );
        anyhow::ensure!(
            self.udp_decision_sequence_status()?.exhausted(),
            "UDP decision sequence is not exhausted"
        );
        let conflicts_with_rollback = |token| {
            token != 0 && honk_ebpf_common::udp_decision_token_generation(token) >= generation
        };
        let generation_is_live = self
            .udp_conn_states
            .values()
            .any(|state| conflicts_with_rollback(state.decision_token))
            || self
                .retire_fences
                .values()
                .any(|fence| conflicts_with_rollback(fence.decision_token))
            || self
                .routing_handoffs
                .lock()
                .values()
                .any(|entry| conflicts_with_rollback(entry.result.decision_token))
            || self
                .redirect_tracks
                .values()
                .any(|entry| conflicts_with_rollback(entry.decision_token));
        if generation_is_live {
            return Ok(false);
        }
        self.udp_decision_sequence_next = 0;
        self.udp_decision_sequence_generation = generation;
        Ok(true)
    }

    fn routing_handoff_lookup(
        &self,
        key: &TuplesKey,
    ) -> anyhow::Result<Option<RoutingHandoffEntry>> {
        Ok(self
            .routing_handoffs
            .lock()
            .get(&Self::tuples_key_bytes(key))
            .copied())
    }

    fn redirect_track_lookup(&self, key: &RedirectTuple) -> anyhow::Result<Option<RedirectEntry>> {
        Ok(self
            .redirect_tracks
            .get(&Self::redirect_tuple_bytes(key))
            .copied())
    }

    #[cfg(test)]
    fn redirect_track_store(
        &mut self,
        key: &RedirectTuple,
        entry: &RedirectEntry,
    ) -> anyhow::Result<()> {
        self.redirect_tracks
            .insert(Self::redirect_tuple_bytes(key), *entry);
        Ok(())
    }

    #[cfg(feature = "native-api")]
    fn bind_kernel_trace_dictionary(
        &mut self,
        dictionary: crate::observe::flows::kernel::KernelTraceDictionary,
    ) {
        if let Some(owner) = &self.routing_generation {
            self.trace_dictionaries.bind(
                self.descriptor.trace_policy,
                owner.fingerprint,
                dictionary,
            );
        }
    }

    #[cfg(feature = "native-api")]
    fn capture_kernel_route(
        &self,
        key: &TuplesKey,
        reference: crate::observe::flows::kernel::KernelRouteReference,
    ) -> Result<crate::observe::flows::kernel::CapturedKernelRoute, &'static str> {
        if reference.trace_id == 0 {
            return Err("kernel_trace_not_captured");
        }
        if reference.trace_id == ROUTE_TRACE_LOST {
            return Err("kernel_trace_lost");
        }
        let witness = self
            .route_witnesses
            .get(&reference.trace_id)
            .ok_or("kernel_trace_sidecar_missing")?;
        self.trace_dictionaries.capture(witness, key, reference)
    }

    fn set_outbound_alive(
        &mut self,
        outbound: u8,
        domain: u32,
        ipver: u32,
        alive: bool,
    ) -> anyhow::Result<()> {
        let key = (outbound as u32)
            .wrapping_mul(6)
            .wrapping_add(domain.wrapping_mul(2))
            .wrapping_add(ipver);
        self.count_outbound_alive_write();
        self.outbound_alive.insert(key, if alive { 1 } else { 0 });
        Ok(())
    }

    fn get_outbound_alive(&self, outbound: u8, domain: u32, ipver: u32) -> anyhow::Result<bool> {
        let key = (outbound as u32)
            .wrapping_mul(6)
            .wrapping_add(domain.wrapping_mul(2))
            .wrapping_add(ipver);
        Ok(self.outbound_alive.get(&key).copied().unwrap_or(0) != 0)
    }

    fn get_bpf_stats(&self, key: u32) -> anyhow::Result<Option<u64>> {
        #[cfg(test)]
        anyhow::ensure!(
            !self.telemetry_faults.lock().stats,
            "injected BPF stats read failure"
        );
        Ok(self.bpf_stats.get(&key).copied())
    }

    fn redirect_track_for_each_chunk(
        &self,
        chunk_size: usize,
        cursor: &mut ebpf::FlowScanCursor,
        visit: &mut ebpf::RedirectTrackChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        scan_model(
            self.redirect_tracks
                .iter()
                .map(|(key, value)| (*key, *value)),
            chunk_size,
            cursor,
            Self::bytes_to_redirect_tuple,
            visit,
        );
        Ok(())
    }

    fn routing_handoff_for_each_chunk(
        &self,
        chunk_size: usize,
        cursor: &mut ebpf::FlowScanCursor,
        visit: &mut ebpf::RoutingHandoffChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        scan_model(
            self.routing_handoffs
                .lock()
                .iter()
                .map(|(key, value)| (*key, *value)),
            chunk_size,
            cursor,
            Self::bytes_to_tuples_key,
            visit,
        );
        Ok(())
    }

    fn conn_state_for_each_chunk(
        &self,
        chunk_size: usize,
        cursor: &mut ebpf::FlowScanCursor,
        visit: &mut ebpf::ConnStateChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        scan_model(
            self.tcp_conn_states
                .iter()
                .chain(self.udp_conn_states.iter())
                .map(|(key, value)| (*key, *value)),
            chunk_size,
            cursor,
            Self::bytes_to_tuples_key,
            visit,
        );
        Ok(())
    }

    fn detach_hooks(&mut self) -> anyhow::Result<()> {
        self.detach_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn attach_dynamic_interface(
        &mut self,
        _ifname: &str,
        _role: ebpf::IfaceRole,
        _single_homed: bool,
    ) -> anyhow::Result<ebpf::DynamicHooks> {
        #[cfg(test)]
        anyhow::ensure!(
            !self.dynamic_attach_fault,
            "injected dynamic attach failure"
        );
        self.dynamic_attach_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(ebpf::DynamicHooks {
            ingress: true,
            egress: true,
        })
    }

    fn forget_dynamic_interface(&mut self, _ifindex: u32) {
        self.dynamic_forget_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    async fn cleanup(&mut self) -> anyhow::Result<()> {
        self.datapath_ready = false;
        self.admission_pressure
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.listener_sockets_published = false;
        self.listener_socket_slots.clear();
        self.routing_generation = None;
        self.descriptor = RoutingPolicyDescriptor::default();
        self.tcp_conn_states.clear();
        self.udp_conn_states.clear();
        self.redirect_tracks.clear();
        self.routing_handoffs.get_mut().clear();
        self.retire_fences.clear();
        self.route_witnesses.clear();
        self.outbound_alive.clear();
        self.bpf_stats.clear();
        Ok(())
    }
}
