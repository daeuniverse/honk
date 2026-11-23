use super::*;
use honk_xsk::GatewayArbitration;

pub(super) struct Arbitration {
    pub(super) kernel: GatewayArbitration,
    _objects: MemoryReservation,
    _allocation: MemoryReservation,
}

impl Arbitration {
    fn new(budget: &Arc<MemoryBudget>, last_issued: u64) -> io::Result<Arc<Self>> {
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

impl GatewayPublisher {
    fn build_generation(
        &self,
        inner: &PublisherInner,
        plan: &RoutingPushPlan,
        bank: Option<Arc<GatewayDnsBank>>,
        arbitration: Option<Arc<Arbitration>>,
        status: DnsProjectionState,
    ) -> Result<(Generation, Vec<Programs>), PrepareError> {
        let policy = GatewayPolicy::prepare(plan, bank.is_some()).map_err(PrepareError::Policy)?;
        let mut memory = Vec::with_capacity(inner.members.len() + 1);
        memory.push(
            reserve_objects(&self.budget, policy.fact_fds()).map_err(PrepareError::Candidate)?,
        );
        let mut candidates = Vec::with_capacity(inner.members.len());
        for member in &inner.members {
            drop(self.state.open_links().map_err(PrepareError::Authority)?);
            let program = member
                .programs
                .reload_general_gateway(GatewayLoad {
                    routing: &policy.bytecode.insns,
                    maps: &self.maps,
                    conntrack: &self.conntrack,
                    dns: bank.as_ref().map(|bank| bank.maps()),
                    arbitration: arbitration.as_ref().map(|arb| &arb.kernel),
                })
                .map_err(PrepareError::Candidate)?;
            memory.push(
                reserve_objects(&self.budget, program.object_fds().into_iter().skip(2))
                    .map_err(PrepareError::Candidate)?,
            );
            candidates.push(program);
        }
        Ok((
            Generation {
                policy,
                bank,
                arbitration,
                status,
                memory,
            },
            candidates,
        ))
    }

    fn prepare_generation(
        &self,
        inner: &PublisherInner,
        plan: &RoutingPushPlan,
    ) -> io::Result<PreparedGeneration> {
        if self.shadow.notrack_latched() {
            return Ok(PreparedGeneration::KeepStatic(NOTRACK_FALLBACK));
        }
        if self.shadow.realms.is_empty() || !plan.has_domain_rules {
            return Ok(PreparedGeneration::KeepStatic(self.shadow.base_status));
        }
        let candidate = GatewayDnsBank::new(&self.budget, plan.fingerprint, &self.shadow.realms)
            .and_then(|bank| {
                let arb = match &inner.current.arbitration {
                    Some(arb) => Arc::clone(arb),
                    None => Arbitration::new(&self.budget, inner.last_issued)?,
                };
                Ok((bank, arb))
            });
        let (reason, error) = match candidate {
            Err(error) => optional_map_failure(error),
            Ok((bank, arb)) => match self.build_generation(
                inner,
                plan,
                Some(bank),
                Some(arb),
                DnsProjectionState::Staged,
            ) {
                Ok((generation, programs)) => {
                    return Ok(PreparedGeneration::Replace(generation, programs));
                }
                Err(PrepareError::Authority(error)) => return Err(self.fail_capture(error)),
                Err(error) => error.shadow_failure()?,
            },
        };
        tracing::debug!(reason, %error, "gateway DNS candidate unavailable");
        Ok(PreparedGeneration::KeepStatic(
            DnsProjectionState::Fallback(reason),
        ))
    }

    pub(in crate::xdp) fn capture_error(&self) -> Option<io::Error> {
        self.failure
            .get()
            .map(|error| io::Error::new(error.kind(), Arc::clone(error)))
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
        let failure = self.failure.get_or_init(|| Arc::new(error));
        self.shadow.admission.store(false, Ordering::Release);
        self.stop_dns();
        io::Error::new(failure.kind(), Arc::clone(failure))
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
        let candidate = self.prepare_generation(&inner, plan)?;
        if let PreparedGeneration::KeepStatic(status) = &candidate
            && initial_static
            && inner.current.arbitration.is_none()
            && inner.current.policy.bytecode.fingerprint == plan.fingerprint
        {
            for (index, member) in inner.members.iter().enumerate() {
                let verified =
                    self.state.open_links()?[index].verify(member.programs.data_prog_id());
                verified.map_err(|error| self.fail_capture(error))?;
            }
            let _links = self.state.open_links()?;
            inner.current.status = *status;
            self.shadow.report_status(*status);
            return Ok(());
        }
        let suspended = inner
            .current
            .bank
            .as_ref()
            .and_then(|_| self.shadow.suspend());
        let (generation, programs) = match candidate {
            PreparedGeneration::Replace(generation, programs) => (generation, programs),
            PreparedGeneration::KeepStatic(status) => {
                let arb = self.static_arbitration(&inner)?;
                match self.build_generation(&inner, plan, None, arb, status) {
                    Ok(candidate) => candidate,
                    Err(PrepareError::Authority(error)) => return Err(self.fail_capture(error)),
                    Err(error) => {
                        let _links = self.state.open_links()?;
                        self.shadow.resume(suspended);
                        return Err(error.into_error());
                    }
                }
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
        for (index, program) in previous.programs.iter().enumerate() {
            let old = &inner.members[index].programs;
            let replaced =
                self.state.open_links()?[index].replace(old.data_fd(), program.data_fd());
            if let Err(error) = replaced {
                let changed = {
                    let links = self.state.open_links()?;
                    if links[index].verify(old.data_prog_id()).is_ok() {
                        Some(index)
                    } else if links[index].verify(program.data_prog_id()).is_ok() {
                        Some(index + 1)
                    } else {
                        None
                    }
                };
                let Some(changed) = changed else {
                    return Err(self.fail_capture(io::Error::other(format!(
                        "gateway link identity lost after update: {error}"
                    ))));
                };
                self.restore_links(inner, changed)?;
                self.finish_transition(inner, false)?;
                let _links = self.state.open_links()?;
                let discarded = inner.previous.take().unwrap();
                self.shadow.resume(discarded.suspended);
                return Err(error);
            }
        }
        self.finish_transition(inner, true)?;
        let _links = self.state.open_links()?;
        Self::exchange(inner);
        self.shadow.report_status(inner.current.status);
        Ok(())
    }

    fn restore_links(&self, inner: &mut PublisherInner, changed: usize) -> io::Result<()> {
        let staged = inner.previous.as_ref().unwrap();
        for index in (0..changed).rev() {
            let old = &inner.members[index].programs;
            let replaced = self.state.open_links()?[index]
                .replace(staged.programs[index].data_fd(), old.data_fd());
            if let Err(error) = replaced {
                return Err(self.fail_capture(error));
            }
        }
        Ok(())
    }

    // `to_previous` names the generation now attached to every link, before the userspace swap.
    fn finish_transition(&self, inner: &mut PublisherInner, to_previous: bool) -> io::Result<()> {
        let staged = &inner.previous.as_ref().unwrap().generation.arbitration;
        let current = &inner.current.arbitration;
        if let Some(arb) = current.as_ref().xor(staged.as_ref()) {
            // Wait outside link custody, so terminal withdrawal can always take the FDs.
            if let Err(error) = arb.kernel.synchronize_readers() {
                return Err(self.fail_capture(error));
            }
            if (to_previous && staged.is_none()) || (!to_previous && current.is_none()) {
                inner.last_issued = arb.kernel.last_issued();
                self.shadow.diagnostics.sample_dns_decisions(&self.maps);
                self.check_hold_custody()?;
                if arb.kernel.pending() != 0 {
                    return Err(self.fail_capture(io::Error::other(
                        "gateway arbitration still owns pending tuples",
                    )));
                }
            }
        }
        Ok(())
    }

    fn exchange(inner: &mut PublisherInner) {
        let previous = inner.previous.as_mut().unwrap();
        for (member, programs) in inner.members.iter_mut().zip(&mut previous.programs) {
            std::mem::swap(&mut member.programs, programs);
        }
        std::mem::swap(&mut inner.current, &mut previous.generation);
    }

    pub(crate) fn commit(&self) {
        let mut inner = self.state.inner.lock();
        if self.failure.get().is_none() {
            inner.previous.take();
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
        if previous.programs.len() != inner.members.len() {
            return Err(self.fail_capture(io::Error::other("gateway rollback member mismatch")));
        }
        for index in (0..inner.members.len()).rev() {
            let current = &inner.members[index].programs;
            let restored = self.state.open_links()?[index]
                .replace(current.data_fd(), previous.programs[index].data_fd());
            if let Err(error) = restored {
                return Err(self.fail_capture(error));
            }
        }
        self.finish_transition(&mut inner, true)?;
        let _links = self.state.open_links()?;
        Self::exchange(&mut inner);
        self.shadow.report_status(inner.current.status);
        self.shadow.resume(inner.previous.take().unwrap().suspended);
        Ok(())
    }

    pub(super) fn compact_static(&self, inner: &mut PublisherInner) -> io::Result<()> {
        // Reload takes the plan writer before the publisher. Never wait in the reverse order.
        let Some(plan) = self.active_plan.try_read().map(|plan| Arc::clone(&plan)) else {
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
