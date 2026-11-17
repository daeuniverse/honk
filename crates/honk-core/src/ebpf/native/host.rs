use super::*;
use crate::xdp::host::native::{HostNativeGeneration, HostNativeTarget};

pub(super) struct HostTarget {
    pub(super) target: Arc<HostNativeTarget>,
    pub(super) active: Option<HostCandidate>,
}
pub(super) struct HostCandidate {
    programs: HostNativeGeneration,
    resources: Option<CandidateResources>,
}
pub(super) struct PreparedHostPlan {
    pub(super) writer_id: u64,
    operation_id: u64,
    reservation: HostPlanReservations,
}
pub(super) struct HostPlanReservations {
    plan: RoutingPushPlan,
    pub(super) plan_memory: Option<MemoryReservation>,
    pub(super) facts: Option<[MemoryReservation; 5]>,
    pub(super) proof: Option<MemoryReservation>,
    actions: Vec<Option<u32>>,
    hosts: Vec<HostPreparation>,
}
struct HostPreparation {
    target: Arc<HostNativeTarget>,
    domain_count: u32,
    bytecode_insns: usize,
    compiler: MemoryReservation,
    retained: MemoryReservation,
    domain: MemoryReservation,
    staging: MemoryReservation,
    generation: MemoryReservation,
}
impl Drop for HostCandidate {
    fn drop(&mut self) {
        if let Some(resources) = self.resources.take() {
            let mut charges = Vec::new();
            resources.retire(&mut charges);
            for charge in charges {
                std::mem::forget(charge);
            }
        }
    }
}
impl NativePublication {
    pub(crate) fn host_map_fds(&self) -> [BorrowedFd<'_>; 3] {
        [
            self.root.map.fd.as_fd(),
            self.claims.fd.as_fd(),
            self.scratch.fd.as_fd(),
        ]
    }
    pub(crate) fn register_host(
        self: &Arc<Self>,
        target: Arc<HostNativeTarget>,
        writer: &NativeWrite,
    ) -> anyhow::Result<()> {
        self.change(writer, NativeReason::Startup, |state| {
            ensure!(
                state.targets.is_empty(),
                "combined Host and physical Native requires actual Host reverse exclusion"
            );
            ensure!(
                !state
                    .hosts
                    .iter()
                    .any(|h| h.target.namespace == target.namespace),
                "Host Native namespace already registered"
            );
            state.hosts.try_reserve_exact(1)?;
            state.hosts.push(HostTarget {
                target,
                active: None,
            });
            if let Some(plan) = state.plan.take() {
                let result = self.publish_candidates(state, &plan, None);
                state.plan = Some(plan);
                result?;
            }
            Ok(())
        })
    }
    fn host_actions(&self, plan: &RoutingPushPlan) -> anyhow::Result<Vec<Option<u32>>> {
        let mut actions = vec![None];
        merge_plan_actions(&mut actions, plan)?;
        // Old ordinary owners retain their selected full effect across reload.
        let mut previous: Option<NativeKey> = None;
        for step in 0..=u64::from(self.capacity) {
            let mut next = NativeKey::default();
            match element(
                4,
                self.claims.fd(),
                previous
                    .as_ref()
                    .map_or(0, |k| k as *const NativeKey as u64),
                &mut next as *mut NativeKey as u64,
                0,
            ) {
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(actions),
                Err(error) => return Err(error.into()),
                Ok(_) => ensure!(
                    step < u64::from(self.capacity),
                    "Host Native action scan failed to terminate"
                ),
            }
            if let Some(claim) = self.claims.lookup::<_, NativeClaim>(&next)? {
                ensure!(
                    claim.is_valid(&next),
                    "Host Native action scan found invalid owner"
                );
                if claim.owner_cookie != 0 && claim.executor == NATIVE_EXECUTOR_KERNEL {
                    insert_action(
                        &mut actions,
                        match claim.mark_kind {
                            NATIVE_MARK_KEEP => None,
                            NATIVE_MARK_SET => Some(claim.mark_value),
                            _ => anyhow::bail!("Host Native owner has invalid mark operation"),
                        },
                    )?;
                }
            }
            previous = Some(next);
        }
        unreachable!("bounded scan returns on exhaustion")
    }
    pub(crate) fn preflight_host_plan(
        self: &Arc<Self>,
        plan: &RoutingPushPlan,
    ) -> anyhow::Result<Option<HostPlanPreparation>> {
        let state = self.state.lock();
        if state.hosts.is_empty() {
            return Ok(None);
        }
        if let Some(prepared) = &state.host_preparation {
            ensure!(
                state
                    .recording
                    .is_live_writer(prepared.writer_id, prepared.operation_id)
                    && prepared.reservation.plan.semantically_eq(plan),
                "Host Native preparation belongs to another operation"
            );
            self.check_host_preparation(&state, &prepared.reservation)?;
            return Ok(Some(HostPlanPreparation {
                publication: self.clone(),
                reservation: None,
                owner: Some(prepared.writer_id),
            }));
        }
        let plan_memory = reserve(&self.budget, plan_bytes(plan)?)?;
        let mut compiler = Some(reserve(&self.budget, compiler_bytes(plan, false)?)?);
        let mut actions = self.host_actions(plan)?;
        // An open producer can only introduce effects from the installed plan.
        if let Some(current) = &state.plan {
            merge_plan_actions(&mut actions, current)?;
        }
        let fd = self.root.map.fd();
        // Dry emission counts instructions; only the closed preparation binds real fact maps.
        let bytecode = crate::control::routing_matcher::codegen::emit_host_routing_program(
            plan,
            RoutingMapFds {
                destination_v4: fd,
                destination_v6: fd,
                source_v4: fd,
                source_v6: fd,
                mac: fd,
                domain: fd,
            },
        )?;
        let preparation =
            HostNativeTarget::preparation_memory_bytes(bytecode.insns.len(), actions.len())?;
        let scope = state
            .scopes
            .get(&ScopeId::HOST)
            .filter(|s| s.fingerprint == plan.policy_fingerprint);
        let domain_count = u32::try_from(scope.map_or(0, |s| s.facts.len()).max(1))?;
        let mut hosts = Vec::with_capacity(state.hosts.len());
        for host in &state.hosts {
            let compiler = match compiler.take() {
                Some(memory) => memory,
                None => reserve(&self.budget, compiler_bytes(plan, false)?)?,
            };
            let staging = reserve(&self.budget, preparation)?;
            let config = NativeProgramConfig {
                bytecode: &bytecode.insns,
                root: self.root.map.fd(),
                claims: self.claims.fd(),
                scratch: self.scratch.fd(),
                closed_counters: 0,
                hook_ids: [0; 2],
                epoch: next_closed(self.root.epoch().load(Ordering::SeqCst))
                    .context("Host Native epoch exhausted")?,
                scope: host.target.scope,
                expires_boottime_ns: u64::MAX,
                reply_block_rules: &[],
                preparation_memory_bytes: preparation,
                redirect_limit: self.capacity,
                captured: None,
            };
            let generation = reserve(
                &self.budget,
                host.target.generation_memory_bytes(&config, &actions)?,
            )?;
            hosts.push(HostPreparation {
                target: host.target.clone(),
                domain_count,
                bytecode_insns: bytecode.insns.len(),
                compiler,
                retained: reserve(&self.budget, 4 * PAGE_BYTES)?,
                domain: reserve(
                    &self.budget,
                    Map::allocation_bytes(1, 16, size_of::<DomainRouting>(), domain_count)?,
                )?,
                staging,
                generation,
            });
        }
        let mut facts: [Option<MemoryReservation>; 5] = std::array::from_fn(|_| None);
        for (slot, entries) in facts.iter_mut().zip([
            &plan.facts.destination_v4,
            &plan.facts.destination_v6,
            &plan.facts.source_v4,
            &plan.facts.source_v6,
            &plan.facts.mac,
        ]) {
            *slot = Some(reserve(
                &self.budget,
                Map::allocation_bytes(
                    LPM_TRIE,
                    size_of::<LpmKey>(),
                    size_of::<DomainRouting>(),
                    u32::try_from(entries.len().max(1))?,
                )?,
            )?);
        }
        let proof = reserve(
            &self.budget,
            (plan.rules.len() + 1)
                .checked_mul(size_of::<u32>())
                .context("Host reply proof overflow")?,
        )?;
        Ok(Some(HostPlanPreparation {
            publication: self.clone(),
            owner: None,
            reservation: Some(HostPlanReservations {
                plan: plan.clone(),
                plan_memory: Some(plan_memory),
                facts: Some(facts.map(|memory| memory.expect("reserved fact map"))),
                proof: Some(proof),
                actions,
                hosts,
            }),
        }))
    }
    fn check_host_preparation(
        &self,
        state: &State,
        prepared: &HostPlanReservations,
    ) -> anyhow::Result<()> {
        let count = state
            .scopes
            .get(&ScopeId::HOST)
            .filter(|s| s.fingerprint == prepared.plan.policy_fingerprint)
            .map_or(0, |scope| scope.facts.len())
            .max(1);
        ensure!(
            state.hosts.len() == prepared.hosts.len()
                && state
                    .hosts
                    .iter()
                    .zip(&prepared.hosts)
                    .all(|(host, reserved)| {
                        Arc::ptr_eq(&host.target, &reserved.target)
                            && count <= reserved.domain_count as usize
                    }),
            "Host Native preparation target or scope capacity changed"
        );
        let mut actions = self.host_actions(&prepared.plan)?;
        if let Some(current) = &state.plan {
            merge_plan_actions(&mut actions, current)?;
        }
        ensure!(
            actions
                .iter()
                .all(|action| prepared.actions.binary_search(action).is_ok()),
            "Host Native installed action union changed after preparation"
        );
        Ok(())
    }
    pub(crate) fn write_prepared_plan(
        self: &Arc<Self>,
        reason: NativeReason,
        preparation: Option<HostPlanPreparation>,
    ) -> anyhow::Result<NativeWrite> {
        ensure!(
            matches!(reason, NativeReason::Reload | NativeReason::Policy),
            "Host Native preparation requires a Reload or Policy writer"
        );
        let Some(mut preparation) = preparation else {
            return self.write(reason);
        };
        ensure!(
            Arc::ptr_eq(self, &preparation.publication),
            "Host Native preparation belongs to another publication"
        );
        let mut state = self.state.lock();
        if let Some(owner) = preparation.owner {
            let prepared = state
                .host_preparation
                .as_ref()
                .filter(|prepared| {
                    prepared.writer_id == owner
                        && state.recording.is_live_writer(owner, prepared.operation_id)
                })
                .context("Host Native preparation owner is no longer live")?;
            self.check_host_preparation(&state, &prepared.reservation)?;
        } else {
            ensure!(
                state.host_preparation.is_none(),
                "Host Native preparation slot is occupied"
            );
            self.check_host_preparation(
                &state,
                preparation
                    .reservation
                    .as_ref()
                    .context("Host Native reservation absent")?,
            )?;
        }
        let mut writer = self.write_locked(&mut state, reason)?;
        writer.host_preparation = Some(preparation.owner.unwrap_or(writer.writer_id));
        if let Some(reservation) = preparation.reservation.take() {
            state.host_preparation = Some(PreparedHostPlan {
                writer_id: writer.writer_id,
                operation_id: writer.operation_id,
                reservation,
            });
        }
        Ok(writer)
    }
    pub(super) fn take_host_preparation(
        &self,
        state: &mut State,
        plan: &RoutingPushPlan,
        writer: &NativeWrite,
    ) -> anyhow::Result<Option<HostPlanReservations>> {
        let Some(owner) = writer.host_preparation else {
            return Ok(None);
        };
        let prepared = state
            .host_preparation
            .as_ref()
            .filter(|prepared| {
                prepared.writer_id == owner
                    && state.recording.is_live_writer(owner, prepared.operation_id)
            })
            .context("Host Native plan reservation was already consumed or withdrawn")?;
        ensure!(
            prepared.reservation.plan.semantically_eq(plan),
            "Host Native prepared plan changed"
        );
        self.check_host_preparation(state, &prepared.reservation)?;
        Ok(Some(
            state
                .host_preparation
                .take()
                .expect("checked Host preparation")
                .reservation,
        ))
    }
    pub(super) fn prepare_host_candidates(
        &self,
        state: &mut State,
        plan: &RoutingPushPlan,
        facts: &Arc<Facts>,
        prepared: Option<HostPlanReservations>,
    ) -> anyhow::Result<Vec<HostCandidate>> {
        if state.hosts.is_empty() {
            return Ok(Vec::new());
        }
        let (actions, mut prepared) = match prepared {
            Some(prepared) => (prepared.actions, prepared.hosts.into_iter()),
            None => (self.host_actions(plan)?, Vec::new().into_iter()),
        };
        let mut candidates = Vec::with_capacity(state.hosts.len());
        state.failed_resources.try_reserve(state.hosts.len())?;
        let scope = state
            .scopes
            .get(&ScopeId::HOST)
            .filter(|s| s.fingerprint == plan.policy_fingerprint);
        for host in &state.hosts {
            let entries = scope.map_or(&[][..], |s| s.facts.as_slice());
            host.target.check_publication()?;
            let (temporary, retained, domain_memory, funded) = match prepared.next() {
                Some(prepared) => (
                    prepared.compiler,
                    prepared.retained,
                    Some(prepared.domain),
                    Some((
                        prepared.bytecode_insns,
                        prepared.staging,
                        prepared.generation,
                    )),
                ),
                None => (
                    reserve(&self.budget, compiler_bytes(plan, false)?)?,
                    reserve(&self.budget, 4 * PAGE_BYTES)?,
                    None,
                    None,
                ),
            };
            let count = u32::try_from(entries.len().max(1))?;
            let domain = match domain_memory {
                Some(memory) => Map::new_reserved(
                    &self.budget,
                    1,
                    16,
                    size_of::<DomainRouting>(),
                    count,
                    0,
                    memory,
                )?,
                None => Map::new(&self.budget, 1, 16, size_of::<DomainRouting>(), count, 0)?,
            };
            state.failed_resources.push(CandidateResources {
                facts: facts.clone(),
                domain,
                memory: temporary,
            });
            let resources = state
                .failed_resources
                .last()
                .expect("retained Host preparation");
            let mut deadline = u64::MAX;
            for (key, bitmap, expires, _) in entries {
                resources.domain.insert(key, bitmap, 0)?;
                deadline = deadline.min(*expires);
            }
            resources.domain.freeze()?;
            let bytecode = crate::control::routing_matcher::codegen::emit_host_routing_program(
                plan,
                facts.fds(resources.domain.fd()),
            )?;
            let preparation =
                HostNativeTarget::preparation_memory_bytes(bytecode.insns.len(), actions.len())?;
            let config = NativeProgramConfig {
                bytecode: &bytecode.insns,
                root: self.root.map.fd(),
                claims: self.claims.fd(),
                scratch: self.scratch.fd(),
                closed_counters: 0,
                hook_ids: [0; 2],
                epoch: self.root.epoch().load(Ordering::SeqCst),
                scope: host.target.scope,
                expires_boottime_ns: deadline,
                reply_block_rules: &[],
                preparation_memory_bytes: preparation,
                redirect_limit: self.capacity,
                captured: None,
            };
            let (_staging, generation) = match funded {
                Some((insns, staging, generation)) => {
                    ensure!(
                        bytecode.insns.len() == insns && preparation <= staging.bytes(),
                        "Host Native compiler exceeded its prepared bounds"
                    );
                    (staging, generation)
                }
                None => {
                    let staging = reserve(&self.budget, preparation)?;
                    let generation = reserve(
                        &self.budget,
                        host.target.generation_memory_bytes(&config, &actions)?,
                    )?;
                    (staging, generation)
                }
            };
            let programs = match host.target.prepare(&config, &actions, generation) {
                Ok(programs) => programs,
                Err(error) => {
                    state.retired_hosts.extend(candidates);
                    return Err(error);
                }
            };
            drop(bytecode);
            let mut resources = state
                .failed_resources
                .pop()
                .expect("retained Host preparation");
            drop(std::mem::replace(&mut resources.memory, retained));
            candidates.push(HostCandidate {
                programs,
                resources: Some(resources),
            });
        }
        Ok(candidates)
    }
    pub(super) fn publish_host_candidates(
        &self,
        state: &mut State,
        candidates: Vec<HostCandidate>,
    ) -> anyhow::Result<()> {
        let mut candidates = candidates.into_iter();
        for host in &mut state.hosts {
            let candidate = candidates
                .next()
                .context("missing prepared Host Native family")?;
            if let Err(error) = host
                .target
                .publish(&candidate.programs)
                .and_then(|()| host.target.check_publication())
            {
                state.retired_hosts.push(candidate);
                state.retired_hosts.extend(candidates);
                return Err(error);
            }
            if let Some(previous) = host.active.replace(candidate) {
                state.retired_hosts.push(previous);
            }
        }
        Ok(())
    }
    pub(crate) fn close_host_admission(&self) -> anyhow::Result<()> {
        let state = self.state.lock();
        ensure!(
            self.root.epoch().load(Ordering::SeqCst) & 1 == 0,
            "Host Native close requires closed root"
        );
        for host in &state.hosts {
            host.target.close_admission()?;
        }
        Ok(())
    }
    pub(crate) fn host_source_may_retire(
        &self,
        key: &NativeKey,
        claim: &NativeClaim,
        now_ns: u64,
    ) -> io::Result<bool> {
        if claim.owner_cookie == 0 {
            return Ok(false);
        }
        let target = {
            let state = self.state.lock();
            state
                .hosts
                .iter()
                .find(|h| {
                    h.target.namespace == key.namespace_cookie
                        && h.target.attachment == claim.attachment_generation
                })
                .map(|h| h.target.clone())
        };
        // Unknown advisory snapshots request the authoritative closed scan.
        Ok(target.is_none_or(|target| {
            (target.scope == claim.scope && host_udp_cache_expired(key, claim, now_ns))
                || !target.source_alive(key, claim).unwrap_or(false)
        }))
    }
    pub(crate) fn retire_host_sources(
        &self,
        writer: &NativeWrite,
        retains: impl FnMut(&NativeKey, &NativeClaim) -> bool,
    ) -> anyhow::Result<()> {
        self.retire_host_sources_at(Some(writer), retains)
    }
    pub(crate) fn retire_closed_host_sources(
        &self,
        retains: impl FnMut(&NativeKey, &NativeClaim) -> bool,
    ) -> anyhow::Result<()> {
        self.retire_host_sources_at(None, retains)
    }
    fn retire_host_sources_at(
        &self,
        writer: Option<&NativeWrite>,
        mut retains: impl FnMut(&NativeKey, &NativeClaim) -> bool,
    ) -> anyhow::Result<()> {
        let (epoch, hosts) = {
            let mut state = self.state.lock();
            ensure!(
                self.root.epoch().load(Ordering::SeqCst) & 1 == 0
                    && self.host_retirement_boundary(&state, writer),
                "Host source retirement requires its same-publication closed/joined boundary"
            );
            if writer.is_none() {
                for host in &state.hosts {
                    host.target.record_retained_sources(None);
                }
            }
            self.drain_recorded(&mut state, NativeReason::Shutdown)?;
            (
                self.root.epoch().load(Ordering::SeqCst),
                state
                    .hosts
                    .iter()
                    .map(|host| host.target.clone())
                    .collect::<Vec<_>>(),
            )
        };
        let result = (|| -> anyhow::Result<()> {
            let claims = self.scan_host_claims()?;
            let now_ns = if writer.is_some() {
                self.monotonic_ns()?
            } else {
                0
            };
            let _group_memory = reserve(
                &self.budget,
                (self.capacity as usize)
                    .checked_mul(96)
                    .and_then(|n| n.checked_add(4 * PAGE_BYTES))
                    .context("Host source group scan overflow")?,
            )?;
            let mut blocked = HashMap::<(u64, u64, u64, u64), HostSourceRetention>::new();
            blocked.try_reserve(claims.len())?;
            for (key, claim) in claims.iter() {
                if claim.owner_cookie == 0 {
                    continue;
                }
                retain_source_group(&mut blocked, key, claim, retains(key, claim));
            }
            for (key, claim) in claims.iter() {
                if claim.owner_cookie == 0 {
                    continue;
                }
                let Some(host) = hosts.iter().find(|h| {
                    h.namespace == key.namespace_cookie
                        && h.attachment == claim.attachment_generation
                }) else {
                    continue;
                };
                let Some(retention) = blocked.get_mut(&source_identity(key, claim)) else {
                    continue;
                };
                if !retention.tails && !retention.socket {
                    retention.socket = host.source_alive(key, claim)?;
                }
            }
            let state = self.state.lock();
            if !self.host_retirement_boundary(&state, writer)
                || self.root.epoch().load(Ordering::SeqCst) != epoch
            {
                ensure!(
                    writer.is_some(),
                    "Host terminal source retirement boundary changed; custody retained"
                );
                return Ok(());
            }
            ensure!(
                !state.writers.failed,
                "Host source retirement has failed closed; custody retained"
            );
            for (key, claim) in claims.iter() {
                if claim.owner_cookie != 0
                    && blocked
                        .get(&source_identity(key, claim))
                        .is_some_and(|retention| {
                            !retention.tails
                                && (!retention.socket
                                    || (writer.is_some()
                                        && host_udp_cache_expired(key, claim, now_ns)))
                        })
                    && hosts.iter().any(|h| {
                        h.namespace == key.namespace_cookie
                            && h.attachment == claim.attachment_generation
                            && h.scope == claim.scope
                    })
                {
                    self.delete_claim(key, claim).with_context(|| format!(
                        "Host source alias retirement cookie={} incarnation={} original_state={}",
                        claim.owner_cookie, claim.owner_incarnation, claim.state))?;
                }
            }
            if writer.is_none() {
                for (key, claim) in claims.iter().filter(|(_, claim)| claim.owner_cookie != 0) {
                    if let Some(current) = self.claims.lookup::<_, NativeClaim>(key)? {
                        ensure!(
                            current == *claim
                                && blocked
                                    .get(&source_identity(key, claim))
                                    .is_some_and(|retention| retention.tails || retention.socket)
                                && hosts
                                    .iter()
                                    .any(|host| host.namespace == key.namespace_cookie
                                        && host.attachment == claim.attachment_generation
                                        && host.scope == claim.scope),
                            "Host source ownership changed during terminal joins; custody retained"
                        );
                    }
                }
                for host in &hosts {
                    let retained = blocked
                        .iter()
                        .filter(|((namespace, _, _, attachment), retention)| {
                            (retention.tails || retention.socket)
                                && *namespace == host.namespace
                                && *attachment == host.attachment
                        })
                        .count();
                    host.record_retained_sources(Some(retained));
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.state.lock().writers.failed = true;
        }
        result
    }
    fn host_retirement_boundary(&self, state: &State, writer: Option<&NativeWrite>) -> bool {
        match writer {
            Some(writer) => {
                std::ptr::eq(self, Arc::as_ptr(&writer.publication))
                    && state
                        .recording
                        .is_live_writer(writer.writer_id, writer.operation_id)
                    && state.writers.count != 0
                    && !state.writers.terminal
            }
            None => state.writers.terminal && state.writers.count == 0,
        }
    }
    fn scan_host_claims(&self) -> anyhow::Result<NativeClaims> {
        let memory = reserve(
            &self.budget,
            (self.capacity as usize)
                .checked_mul(size_of::<(NativeKey, NativeClaim)>())
                .and_then(|n| n.checked_add(4 * PAGE_BYTES))
                .context("Host Native retirement scan overflow")?,
        )?;
        let mut entries = Vec::with_capacity(self.capacity as usize);
        let mut previous: Option<NativeKey> = None;
        for step in 0..=u64::from(self.capacity) {
            let mut next = NativeKey::default();
            match element(
                4,
                self.claims.fd(),
                previous
                    .as_ref()
                    .map_or(0, |k| k as *const NativeKey as u64),
                &mut next as *mut NativeKey as u64,
                0,
            ) {
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                    return Ok(NativeClaims {
                        entries,
                        _memory: memory,
                    });
                }
                Err(error) => return Err(error.into()),
                Ok(_) => ensure!(
                    step < u64::from(self.capacity),
                    "Host Native retirement traversal did not terminate"
                ),
            }
            if let Some(claim) = self.claims.lookup::<_, NativeClaim>(&next)? {
                ensure!(
                    claim.is_valid(&next),
                    "invalid Host Native retirement identity"
                );
                entries.push((next, claim));
            }
            previous = Some(next);
        }
        unreachable!("bounded traversal returns on exhaustion")
    }
}
#[derive(Default)]
struct HostSourceRetention {
    tails: bool,
    socket: bool,
}
fn host_udp_cache_expired(key: &NativeKey, claim: &NativeClaim, now_ns: u64) -> bool {
    claim.is_valid(key)
        && key.domain == NATIVE_DOMAIN_SOURCE
        && key.direction == NATIVE_DIRECTION_ORIGINAL
        && key.zone_state == NATIVE_ZONE_UNBOUND
        && key.zone == 0
        && key.l4proto == 17
        && !honk_ebpf_common::conn::is_stateless_udp_ports(
            u16::from_be(key.src_port),
            u16::from_be(key.dst_port),
        )
        && claim.executor == NATIVE_EXECUTOR_KERNEL
        && claim.state == NATIVE_PHASE_ACTIVE
        && native_claim_udp_expired(claim.last_seen_ns, now_ns)
}
fn source_identity(key: &NativeKey, claim: &NativeClaim) -> (u64, u64, u64, u64) {
    (
        key.namespace_cookie,
        claim.owner_cookie,
        claim.owner_incarnation,
        claim.attachment_generation,
    )
}
fn retain_source_group(
    groups: &mut HashMap<(u64, u64, u64, u64), HostSourceRetention>,
    key: &NativeKey,
    claim: &NativeClaim,
    retained: bool,
) {
    let retention = groups.entry(source_identity(key, claim)).or_default();
    // SourcePending is a negative index; real bank final-free plus joined
    // operation tails, rather than a fabricated zero count, ends this owner.
    retention.tails |= retained;
}
fn merge_plan_actions(
    actions: &mut Vec<Option<u32>>,
    plan: &RoutingPushPlan,
) -> anyhow::Result<()> {
    for action in plan
        .rules
        .iter()
        .map(|r| &r.action)
        .chain(std::iter::once(&plan.fallback))
    {
        if action.outbound == honk_ebpf_common::OutboundIndex::Direct as u8 {
            insert_action(actions, action.mark)?;
        }
    }
    Ok(())
}
fn insert_action(actions: &mut Vec<Option<u32>>, mark: Option<u32>) -> anyhow::Result<()> {
    if let Err(at) = actions.binary_search(&mark) {
        ensure!(
            actions.len() < honk_nfqueue::native::MAX_ACTIONS,
            "Host Native live/frozen action union exceeds 257 cases"
        );
        actions.insert(at, mark);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_pending_retention_uses_real_tails_and_scoped_identity() {
        let key = NativeKey {
            namespace_cookie: 7,
            ..Default::default()
        };
        let claim = NativeClaim {
            owner_cookie: 42,
            owner_incarnation: 8,
            attachment_generation: 9,
            state: NATIVE_PHASE_SOURCE_PENDING | (1 << 4),
            ..Default::default()
        };
        let mut groups = HashMap::new();
        retain_source_group(&mut groups, &key, &claim, true);
        let bound = NativeClaim {
            state: NATIVE_PHASE_ACTIVE,
            ..claim
        };
        retain_source_group(&mut groups, &key, &bound, false);
        assert!(groups[&source_identity(&key, &bound)].tails);
        let other = NativeKey {
            namespace_cookie: 8,
            ..key
        };
        retain_source_group(&mut groups, &other, &claim, false);
        assert!(!groups[&source_identity(&other, &bound)].tails);
        retain_source_group(&mut groups, &other, &bound, true);
        assert!(groups[&source_identity(&other, &bound)].tails);
    }
    #[test]
    fn udp_cache_expiry_does_not_authorize_alias_or_source_retirement() {
        let key = NativeKey {
            namespace_cookie: 7,
            domain: NATIVE_DOMAIN_SOURCE,
            l4proto: 17,
            ip_version: 4,
            src_port: 1234u16.to_be(),
            dst_port: 4321u16.to_be(),
            ..Default::default()
        };
        let claim = NativeClaim {
            epoch: 3,
            incarnation: 3,
            scope: 5,
            executor: NATIVE_EXECUTOR_KERNEL,
            state: NATIVE_PHASE_ACTIVE,
            owner_cookie: 42,
            owner_incarnation: 8,
            attachment_generation: 9,
            last_seen_ns: 11,
            ..Default::default()
        };
        let deadline = claim.last_seen_ns + honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS;
        assert!(!host_udp_cache_expired(&key, &claim, deadline));
        assert!(host_udp_cache_expired(&key, &claim, deadline + 1));
        assert!(!host_udp_cache_expired(
            &key,
            &NativeClaim {
                last_seen_ns: deadline,
                ..claim
            },
            deadline + 1
        ));
        for key in [
            NativeKey {
                domain: NATIVE_DOMAIN_FLOW,
                zone_state: NATIVE_ZONE_BOUND_ACTUAL,
                ..key
            },
            NativeKey {
                domain: NATIVE_DOMAIN_UNBOUND_SOURCE,
                ..key
            },
            NativeKey {
                zone_state: NATIVE_ZONE_BOUND_ACTUAL,
                ..key
            },
            NativeKey { zone: 1, ..key },
            NativeKey {
                direction: NATIVE_DIRECTION_REPLY,
                ..key
            },
            NativeKey { l4proto: 6, ..key },
            NativeKey {
                src_port: 53u16.to_be(),
                ..key
            },
            NativeKey {
                dst_port: 53u16.to_be(),
                ..key
            },
        ] {
            assert!(!host_udp_cache_expired(&key, &claim, deadline + 1));
        }
        for (executor, state) in [
            (NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_ARMED),
            (NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_ACTIVE | (1 << 4)),
            (NATIVE_EXECUTOR_CAPTURE, NATIVE_PHASE_CAPTURE_COMMITTED),
            (
                NATIVE_EXECUTOR_PENDING,
                NATIVE_PHASE_SOURCE_PENDING | (1 << 4),
            ),
        ] {
            assert!(!host_udp_cache_expired(
                &key,
                &NativeClaim {
                    executor,
                    state,
                    ..claim
                },
                deadline + 1
            ));
        }
    }
    #[test]
    fn full_mark_union_distinguishes_keep_zero_and_high_bits() {
        let mut actions = vec![None];
        for mark in [Some(u32::MAX), Some(0), None, Some(1 << 31), Some(0)] {
            insert_action(&mut actions, mark).unwrap();
        }
        assert_eq!(actions, [None, Some(0), Some(1 << 31), Some(u32::MAX)]);
        for value in 1..254 {
            insert_action(&mut actions, Some(value)).unwrap();
        }
        assert_eq!(actions.len(), 257);
        assert!(insert_action(&mut actions, Some(254)).is_err());
        insert_action(&mut actions, Some(0)).unwrap();
    }
}
