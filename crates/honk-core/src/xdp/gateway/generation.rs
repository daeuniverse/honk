use super::*;
use honk_xsk::GatewayArbitration;

pub(super) struct Arbitration {
    pub(super) kernel: GatewayArbitration,
    _objects: MemoryReservation,
    _allocation: MemoryReservation,
}

impl Arbitration {
    pub(super) fn new(budget: &Arc<MemoryBudget>, last_issued: u64) -> io::Result<Arc<Self>> {
        let allocation = budget
            .reserve(size_of::<Self>() + 2 * size_of::<usize>())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::OutOfMemory, "gateway arbitration memory")
            })?;
        let kernel = GatewayArbitration::new(last_issued)?;
        let objects = reserve_objects(budget, kernel.object_fds())?;
        Ok(Arc::new(Self {
            kernel,
            _objects: objects,
            _allocation: allocation,
        }))
    }
}

fn optional_map_failure(error: io::Error) -> (&'static str, io::Error) {
    let reason = match error.kind() {
        io::ErrorKind::Unsupported => "unsupported_arch",
        io::ErrorKind::OutOfMemory => "memory_budget",
        _ if matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) => "candidate_fds",
        _ => "map_admission",
    };
    (reason, error)
}

fn needs_lan_arbitration(realms: &[(ScopeId, u32)], host_enabled: bool) -> bool {
    realms.iter().any(|&(_, realm)| {
        !host_enabled || realm != honk_ebpf_common::xdp_gateway::GATEWAY_REALM_CAPACITY
    })
}

impl GatewayPublisher {
    fn build_generation(
        &self,
        inner: &mut PublisherInner,
        plan: &RoutingPushPlan,
        bank: Option<Arc<GatewayDnsBank>>,
        arbitration: Option<Arc<Arbitration>>,
        status: DnsProjectionState,
    ) -> Result<(Generation, Candidates), PrepareError> {
        let host = !self.maps.host_realms().is_empty();
        let policy = GatewayPolicy::prepare(
            plan,
            bank.is_some() && arbitration.is_some(),
            host.then_some(bank.is_some()),
        )
        .map_err(PrepareError::Policy)?;
        let mut generation = Generation {
            policy,
            bank,
            arbitration,
            status,
            memory: Vec::with_capacity(inner.members.len() + 1),
        };
        generation.memory.push(
            reserve_objects(&self.budget, generation.policy.fact_fds())
                .map_err(PrepareError::Candidate)?,
        );
        let mut candidates = Vec::with_capacity(inner.members.len());
        for member in &inner.members {
            drop(self.state.open_links().map_err(PrepareError::Authority)?);
            let program = member
                .programs
                .reload_general_gateway(self.gateway_load(&generation))
                .map_err(PrepareError::Candidate)?;
            generation.memory.push(
                reserve_objects(&self.budget, program.object_fds().into_iter().skip(2))
                    .map_err(PrepareError::Candidate)?,
            );
            candidates.push(program);
        }
        let mut auxiliary_memory = None;
        let mut auxiliary = Vec::new();
        if let Some(aux) = inner.auxiliary.as_mut() {
            let count = aux.members.iter().filter(|m| m.link.is_some()).count();
            if count != 0 {
                auxiliary_memory = Some(
                    self.budget
                        .reserve(count * size_of::<(u32, AuxProgram)>())
                        .ok_or_else(|| {
                            PrepareError::Candidate(io::ErrorKind::OutOfMemory.into())
                        })?,
                );
                auxiliary.reserve_exact(count);
            }
            for member in &mut aux.members {
                if member.link.is_none() {
                    continue;
                }
                drop(self.state.open_links().map_err(PrepareError::Authority)?);
                match self.load_auxiliary(member, &generation, aux.conntrack.as_ref()) {
                    Ok(program) => auxiliary.push((member.realm, program)),
                    Err(error) if Self::device_gone(&member.pair) => {
                        tracing::debug!(realm = member.realm, errno = ?error.raw_os_error(), %error, "auxiliary device left during gateway preparation");
                        self.close_member(member, &aux.grace)
                            .map_err(PrepareError::Authority)?;
                    }
                    Err(error) => return Err(PrepareError::Candidate(error)),
                }
            }
        }
        Ok((
            generation,
            Candidates {
                physical: candidates,
                auxiliary,
                _auxiliary_memory: auxiliary_memory,
            },
        ))
    }

    /// Returns the static fallback status only when a DNS candidate was not staged.
    fn try_stage_dns(
        &self,
        inner: &mut PublisherInner,
        plan: &RoutingPushPlan,
    ) -> io::Result<Option<DnsProjectionState>> {
        if self.shadow.notrack_latched() {
            return Ok(Some(NOTRACK_FALLBACK));
        }
        if self.shadow.realms.is_empty() || !plan.has_domain_rules {
            return Ok(Some(self.shadow.base_status));
        }
        let candidate = GatewayDnsBank::new(&self.budget, plan.fingerprint, &self.shadow.realms)
            .and_then(|bank| {
                let arb = if needs_lan_arbitration(
                    &self.shadow.realms,
                    !self.maps.host_realms().is_empty(),
                ) {
                    Some(match &inner.current.arbitration {
                        Some(arb) => Arc::clone(arb),
                        None => Arbitration::new(&self.budget, inner.last_issued)?,
                    })
                } else {
                    None
                };
                Ok((bank, arb))
            });
        let (reason, error) = match candidate {
            Err(error) => optional_map_failure(error),
            Ok((bank, arb)) => match self.build_generation(
                inner,
                plan,
                Some(bank),
                arb,
                DnsProjectionState::Staged,
            ) {
                Ok((generation, programs)) => {
                    let suspended = inner
                        .current
                        .bank
                        .as_ref()
                        .and_then(|_| self.shadow.suspend());
                    self.stage(
                        inner,
                        Previous {
                            generation,
                            programs,
                            suspended,
                        },
                    )?;
                    return Ok(None);
                }
                Err(PrepareError::Authority(error)) => return Err(self.fail_capture(error)),
                Err(error) => error.shadow_failure()?,
            },
        };
        tracing::debug!(reason, %error, "gateway DNS candidate unavailable");
        Ok(Some(DnsProjectionState::Fallback(reason)))
    }

    pub(in crate::xdp) fn capture_error(&self) -> Option<io::Error> {
        self.failure.get().map(|error| {
            error.raw_os_error().map_or_else(
                || io::Error::new(error.kind(), Arc::clone(error)),
                io::Error::from_raw_os_error,
            )
        })
    }

    pub(super) fn check_hold_custody(&self) -> io::Result<()> {
        for (reason, message) in [
            (
                GatewayReason::HoldGuardReleaseFailed,
                "gateway hold guard release failed",
            ),
            (
                GatewayReason::HoldRetireFailed,
                "gateway native hold retirement failed",
            ),
        ] {
            match self.maps.reason_count(reason) {
                Ok(0) => {}
                Ok(_) => return Err(self.fail_capture(io::Error::other(message))),
                Err(error) => return Err(self.fail_capture(error)),
            }
        }
        Ok(())
    }

    pub(super) fn fail_capture(&self, error: io::Error) -> io::Error {
        // Keep both generations charged until terminal withdrawal has taken the physical links.
        self.failure.get_or_init(|| Arc::new(error));
        self.shadow.admission.store(false, Ordering::Release);
        self.stop_dns();
        self.capture_error().unwrap()
    }

    fn static_arbitration(&self, inner: &PublisherInner) -> io::Result<Option<Arc<Arbitration>>> {
        let Some(arb) = &inner.current.arbitration else {
            return Ok(None);
        };
        // Epochs are closed. Readers which passed their last epoch check can still reserve credit.
        if let Err(error) = arb.kernel.synchronize_readers() {
            return Err(self.fail_capture(error));
        }
        self.check_hold_custody()?;
        Ok((arb.kernel.pending() != 0).then(|| Arc::clone(arb)))
    }

    pub(crate) fn publish(&self, plan: &RoutingPushPlan) -> io::Result<()> {
        self.publish_inner(plan, false)
    }

    pub(super) fn publish_inner(
        &self,
        plan: &RoutingPushPlan,
        initial_static: bool,
    ) -> io::Result<()> {
        drop(self.state.open_links()?);
        let mut inner = self.state.inner.lock();
        drop(self.state.open_links()?);
        if let Some(error) = self.capture_error() {
            return Err(error);
        }
        if inner.previous.is_some() {
            return Err(io::Error::other(
                "gateway publication is awaiting commit or rollback",
            ));
        }
        let host_enabled = !self.maps.host_realms().is_empty();
        #[cfg(feature = "packet-ebpf")]
        let prepared = self.host.is_some();
        #[cfg(not(feature = "packet-ebpf"))]
        let prepared = false;
        if host_enabled != prepared || host_enabled != inner.current.policy.host_bytecode.is_some()
        {
            return Err(self.fail_capture(io::Error::other("Host gateway preparation mismatch")));
        }
        #[cfg(feature = "packet-ebpf")]
        if let Some(host) = &self.host
            && host.identity.pname_support() == crate::ebpf::PnameSupport::Unavailable
            && plan.features & honk_ebpf_common::ROUTING_FEATURE_PROCESS != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Host gateway process-name rules require cgroup socket identity",
            ));
        }
        for member in &inner.members {
            if member.reload.capture.authority.ifindex != member.ifindex
                || member.reload.queues == 0
                || member.reload.ipv4_broadcasts.len() > 64
            {
                let error = io::Error::new(
                    io::ErrorKind::InvalidData,
                    "gateway reload identity mismatch",
                );
                return Err(self.fail_capture(error));
            }
        }
        let Some(status) = self.try_stage_dns(&mut inner, plan)? else {
            return Ok(());
        };
        if initial_static
            && inner
                .auxiliary
                .as_ref()
                .is_none_or(|aux| aux.members.is_empty())
            && inner.current.bank.is_none()
            && inner.current.policy.bytecode.fingerprint == plan.fingerprint
        {
            for (index, member) in inner.members.iter().enumerate() {
                let verified =
                    self.state.open_links()?[index].verify(member.programs.data_prog_id());
                verified.map_err(|error| self.fail_capture(error))?;
            }
            let _links = self.state.open_links()?;
            inner.current.status = status;
            self.shadow.report_status(status);
            return Ok(());
        }
        let suspended = inner
            .current
            .bank
            .as_ref()
            .and_then(|_| self.shadow.suspend());
        let arb = self.static_arbitration(&inner)?;
        let (generation, programs) =
            match self.build_generation(&mut inner, plan, None, arb, status) {
                Ok(candidate) => candidate,
                Err(PrepareError::Authority(error)) => return Err(self.fail_capture(error)),
                Err(error) => {
                    let _links = self.state.open_links()?;
                    self.shadow.resume(&inner, suspended);
                    return Err(error.into_error());
                }
            };
        self.stage(
            &mut inner,
            Previous {
                programs,
                generation,
                suspended,
            },
        )
    }

    // The staged slots own both possible link targets, even when link identity or grace fails.
    fn stage(&self, inner: &mut PublisherInner, candidate: Previous) -> io::Result<()> {
        inner.previous = Some(candidate);
        let previous = inner.previous.as_ref().unwrap();
        for (index, program) in previous.programs.physical.iter().enumerate() {
            let old = &inner.members[index].programs;
            let replaced =
                self.state.open_links()?[index].replace(old.data_fd(), program.data_fd());
            if let Err(error) = replaced {
                let changed = {
                    let links = self.state.open_links()?;
                    if links[index].verify_fd(old.data_prog_id()).is_ok() {
                        Some(index)
                    } else if links[index].verify_fd(program.data_prog_id()).is_ok() {
                        Some(index + 1)
                    } else {
                        None
                    }
                };
                let Some(changed) = changed else {
                    self.restore_links(inner, index, 0, false)?;
                    tracing::error!(errno = ?error.raw_os_error(), %error, "gateway XDP program identity lost after update");
                    return Err(self.fail_capture(error));
                };
                return self.reject_update(inner, changed, 0, error);
            }
        }
        let physical = inner.members.len();
        for (index, (realm, target)) in previous.programs.auxiliary.iter().enumerate() {
            drop(self.state.open_links()?);
            let aux = inner.auxiliary.as_mut().unwrap();
            match self.update_auxiliary(aux, *realm, target, true) {
                Ok(None) => {}
                Ok(Some((error, changed))) => {
                    return self.reject_update(
                        inner,
                        physical,
                        index + usize::from(changed),
                        error,
                    );
                }
                Err(error) => {
                    self.restore_links(inner, physical, index, false)?;
                    return Err(self.fail_capture(error));
                }
            }
        }
        self.finish_transition(inner, true)?;
        let _links = self.state.open_links()?;
        Self::exchange(inner);
        self.shadow.report_status(inner.current.status);
        Ok(())
    }

    fn reject_update(
        &self,
        inner: &mut PublisherInner,
        physical: usize,
        auxiliary: usize,
        error: io::Error,
    ) -> io::Result<()> {
        self.restore_links(inner, physical, auxiliary, false)?;
        for (index, member) in inner.members.iter().enumerate() {
            let verified = self.state.open_links()?[index].verify(member.programs.data_prog_id());
            verified.map_err(|error| self.fail_capture(error))?;
        }
        self.finish_transition(inner, false)?;
        let _links = self.state.open_links()?;
        let discarded = inner.previous.take().unwrap();
        self.shadow.resume(inner, discarded.suspended);
        Err(error)
    }

    fn device_gone(pair: &AuxDevicePair) -> bool {
        matches!(pair.unavailable(), Ok(true))
    }

    // An UPDATE can succeed before its readback fails. Record the exact installed prefix.
    fn update_auxiliary(
        &self,
        aux: &mut Auxiliary,
        realm: u32,
        staged: &AuxProgram,
        to_staged: bool,
    ) -> io::Result<Option<(io::Error, bool)>> {
        let member = aux
            .members
            .iter_mut()
            .find(|m| m.realm == realm)
            .ok_or_else(lost_capture)?;
        let Some((link, _)) = &member.link else {
            return Ok(None);
        };
        let current = &member.program.as_ref().unwrap().program;
        let (old, new) = if to_staged {
            (current, &staged.program)
        } else {
            (&staged.program, current)
        };
        match link
            .replace(old.as_fd(), new.as_fd())
            .and_then(|()| member.pair.verify())
        {
            Ok(()) => Ok(None),
            Err(error) => {
                let changed = if link.verify_fd(old.id()).is_ok() {
                    Some(false)
                } else if link.verify_fd(new.id()).is_ok() {
                    Some(true)
                } else {
                    None
                };
                if Self::device_gone(&member.pair) {
                    tracing::debug!(realm, errno = ?error.raw_os_error(), %error, "auxiliary device left during gateway update");
                    self.close_member(member, &aux.grace)?;
                    return Ok(None);
                }
                match changed {
                    Some(changed) => Ok(Some((error, changed))),
                    None => {
                        tracing::error!(realm, errno = ?error.raw_os_error(), %error, "auxiliary TCX program identity lost after update");
                        Err(error)
                    }
                }
            }
        }
    }

    fn restore_links(
        &self,
        inner: &mut PublisherInner,
        physical: usize,
        auxiliary: usize,
        to_staged: bool,
    ) -> io::Result<()> {
        let staged = &inner.previous.as_ref().unwrap().programs;
        let mut failure = None;
        for (realm, target) in staged.auxiliary[..auxiliary].iter().rev() {
            drop(self.state.open_links()?);
            match self.update_auxiliary(
                inner.auxiliary.as_mut().unwrap(),
                *realm,
                target,
                to_staged,
            ) {
                Err(error) | Ok(Some((error, false))) => {
                    failure.get_or_insert(error);
                }
                Ok(_) => {}
            }
        }
        for index in (0..physical).rev() {
            let current = &inner.members[index].programs;
            let target = &staged.physical[index];
            let (old, new) = if to_staged {
                (current, target)
            } else {
                (target, current)
            };
            let replaced = {
                let links = self.state.open_links()?;
                links[index]
                    .replace(old.data_fd(), new.data_fd())
                    .or_else(|error| links[index].verify(new.data_prog_id()).map_err(|_| error))
            };
            if let Err(error) = replaced {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), |error| Err(self.fail_capture(error)))
    }

    pub(super) fn verify_auxiliary_targets(
        &self,
        aux: Option<&mut Auxiliary>,
        targets: Option<&[(u32, AuxProgram)]>,
    ) -> io::Result<()> {
        let Some(aux) = aux else { return Ok(()) };
        for member in &mut aux.members {
            let Some((link, _)) = &member.link else {
                continue;
            };
            let target = match targets {
                Some(programs) => programs
                    .iter()
                    .find(|(r, _)| *r == member.realm)
                    .map(|(_, program)| program),
                None => member.program.as_ref(),
            }
            .ok_or_else(lost_capture)?;
            let verified = member.pair.unavailable().and_then(|unavailable| {
                if unavailable {
                    Ok(false)
                } else {
                    link.verify(target.program.id())?;
                    member.pair.verify().map(|()| true)
                }
            });
            match verified {
                Ok(true) => continue,
                Err(error) if !Self::device_gone(&member.pair) => return Err(error),
                _ => self.close_member(member, &aux.grace)?,
            }
        }
        Ok(())
    }

    // `to_previous` names the generation now attached to every link, before the userspace swap.
    fn finish_transition(&self, inner: &mut PublisherInner, to_previous: bool) -> io::Result<()> {
        let previous = inner.previous.as_ref().unwrap();
        let targets = to_previous.then_some(previous.programs.auxiliary.as_slice());
        self.verify_auxiliary_targets(inner.auxiliary.as_deref_mut(), targets)
            .map_err(|error| self.fail_capture(error))?;
        let staged = &previous.generation.arbitration;
        let current = &inner.current.arbitration;
        let departing = if to_previous { current } else { staged };
        let arriving = if to_previous { staged } else { current };
        if inner.auxiliary.is_some() || current.is_some() != staged.is_some() {
            // Synchronize outside physical link custody so terminal withdrawal can take its FDs.
            if let Some(arb) = current.as_ref().or(staged.as_ref()) {
                arb.kernel
                    .synchronize_readers()
                    .map_err(|error| self.fail_capture(error))?;
            } else if let Some(aux) = &inner.auxiliary {
                aux.grace
                    .synchronize()
                    .map_err(|error| self.fail_capture(error))?;
            }
        }
        if let Some(arb) = departing.as_ref().filter(|_| arriving.is_none()) {
            inner.last_issued = arb.kernel.last_issued();
            self.shadow.diagnostics.sample_dns_decisions(&self.maps);
            self.check_hold_custody()?;
            if arb.kernel.pending() != 0 {
                return Err(self.fail_capture(io::Error::other(
                    "gateway arbitration still owns pending tuples",
                )));
            }
        }
        Ok(())
    }

    fn exchange(inner: &mut PublisherInner) {
        let previous = inner.previous.as_mut().unwrap();
        for (member, programs) in inner
            .members
            .iter_mut()
            .zip(&mut previous.programs.physical)
        {
            std::mem::swap(&mut member.programs, programs);
        }
        if let Some(aux) = &mut inner.auxiliary {
            for (realm, program) in &mut previous.programs.auxiliary {
                if let Some(active) = aux
                    .members
                    .iter_mut()
                    .find(|m| m.realm == *realm)
                    .and_then(|m| m.program.as_mut())
                {
                    std::mem::swap(active, program);
                }
            }
        }
        std::mem::swap(&mut inner.current, &mut previous.generation);
    }

    pub(crate) fn commit(&self) {
        let mut inner = self.state.inner.lock();
        if self.failure.get().is_none() && inner.previous.take().is_some() {
            inner.final_publication = None;
        }
    }

    pub(crate) fn rollback(&self) -> io::Result<()> {
        let mut inner = self.state.inner.lock();
        drop(self.state.open_links()?);
        if let Some(error) = self.capture_error() {
            return Err(error);
        }
        let Some(previous) = inner.previous.as_ref() else {
            return Err(self.fail_capture(io::Error::other(
                "gateway rollback has no previous generation",
            )));
        };
        if previous.programs.physical.len() != inner.members.len() {
            return Err(self.fail_capture(io::Error::other("gateway rollback member mismatch")));
        }
        let physical = inner.members.len();
        let auxiliary = previous.programs.auxiliary.len();
        self.restore_links(&mut inner, physical, auxiliary, true)?;
        self.finish_transition(&mut inner, true)?;
        let _links = self.state.open_links()?;
        Self::exchange(&mut inner);
        self.shadow.report_status(inner.current.status);
        let suspended = inner.previous.take().unwrap().suspended;
        self.shadow.resume(&inner, suspended);
        Ok(())
    }

    pub(super) fn compact_static(&self, inner: &mut PublisherInner) -> io::Result<()> {
        // Reload takes the plan writer before the publisher. Never wait in the reverse order.
        let Some(plan) = self
            .active_plan
            .try_read()
            .map(|plan| Arc::clone(&plan.plan))
        else {
            return Ok(());
        };
        if inner.current.policy.bytecode.fingerprint != plan.fingerprint {
            return Ok(());
        }
        let status = if self.shadow.notrack_latched() {
            NOTRACK_FALLBACK
        } else {
            inner.current.status
        };
        let arb = self.static_arbitration(inner)?;
        let (generation, programs) = match self.build_generation(inner, &plan, None, arb, status) {
            Ok(candidate) => candidate,
            Err(PrepareError::Authority(error)) => return Err(self.fail_capture(error)),
            Err(error) => {
                tracing::debug!(error = %error.into_error(), "retaining closed coordinated gateway until static policy fits");
                return Ok(());
            }
        };
        if let Err(error) = self.stage(
            inner,
            Previous {
                generation,
                programs,
                suspended: None,
            },
        ) {
            if self.failure.get().is_some() || inner.previous.is_some() {
                return Err(error);
            }
            tracing::debug!(%error, "retaining coordinated gateway after static link rollback");
        } else {
            inner.previous.take();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_ebpf_common::xdp_gateway::GATEWAY_REALM_CAPACITY;

    #[test]
    fn host_only_dns_allocates_no_lan_arbitration() {
        let first = (ScopeId::allocate().unwrap(), 1);
        let last = (ScopeId::allocate().unwrap(), GATEWAY_REALM_CAPACITY);
        assert!(!needs_lan_arbitration(&[], true));
        assert!(!needs_lan_arbitration(&[last], true));
        assert!(needs_lan_arbitration(&[first, last], true));
        assert!(needs_lan_arbitration(&[last], false));
    }
}
