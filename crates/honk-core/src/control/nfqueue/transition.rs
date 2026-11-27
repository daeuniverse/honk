use super::*;

impl PendingUdpVerdicts {
    pub(in crate::control) async fn activate_direct(
        self: &Arc<Self>,
        identity: PendingUdpIdentity,
        lease: UdpInitLease,
        direct_rule_mark: u32,
    ) -> Result<(), PendingUdpDecisionError> {
        if skb_mark_has_reserved_bits(direct_rule_mark) {
            return Err(PendingUdpDecisionError::ReservedDirectMark);
        }
        if Self::identity_for_lease(&lease) != identity {
            return Err(PendingUdpDecisionError::StaleIdentity);
        }
        let cell = self.matching_cell(identity)?;
        self.commit_pending(
            cell,
            UdpDecisionTransition::ArmDirect(direct_rule_mark),
            Some(lease),
        )
        .await
    }

    pub(super) async fn finish_armed_direct(
        &self,
        cell: &Arc<FlowCell>,
        identity: PendingUdpIdentity,
        direct_rule_mark: u32,
    ) -> Result<(), PendingUdpDecisionError> {
        let final_mark = direct_rule_mark | CLASSIFIED_MARK;
        loop {
            if matches!(&*cell.state.lock(), CellState::Pending { started_at, .. } if started_at.elapsed() >= HARD_HOLD_TIMEOUT)
            {
                self.fail_armed(cell, identity);
                return Err(PendingUdpDecisionError::ArmedInProgress);
            }
            let batch = {
                let mut state = cell.state.lock();
                match &mut *state {
                    CellState::Pending {
                        armed: true,
                        verdicts,
                        ..
                    } => std::mem::take(verdicts),
                    _ => {
                        return Err(self.fatal_error(
                            "direct verdict",
                            "armed correlator changed phase before activation".into(),
                        ));
                    }
                }
            };
            for verdict in batch {
                self.accept_one_fatal(verdict, final_mark)?;
            }
            let mut backend = self.armed_backend_before_deadline(cell, identity).await?;
            let mut state = cell.state.lock();
            let CellState::Pending {
                armed: true,
                started_at,
                verdicts,
                ..
            } = &mut *state
            else {
                return Err(self.fatal_error(
                    "activate direct",
                    "armed correlator changed phase before backend activation".into(),
                ));
            };
            if started_at.elapsed() >= HARD_HOLD_TIMEOUT {
                drop(state);
                drop(backend);
                self.fail_armed(cell, identity);
                return Err(PendingUdpDecisionError::ArmedInProgress);
            }
            if !verdicts.is_empty() {
                drop(state);
                drop(backend);
                continue;
            }
            let result = blocking_section(|| {
                backend.tc_mut()?.commit_udp_decision(
                    &identity.tuples(),
                    identity.owner.token,
                    UdpDecisionTransition::ActivateDirect(direct_rule_mark),
                )
            })
            .map_err(|error| self.fatal_error("activate direct", format!("{error:#}")))?;
            if result != UdpDecisionCommitResult::Applied {
                self.record_commit_mismatch(result);
                return Err(self.fatal_error(
                    "activate direct",
                    format!("backend rejected armed transition: {result:?}"),
                ));
            }
            *state = CellState::ActiveDirect {
                expires_at: Instant::now() + TERMINAL_GRACE,
                final_mark,
            };
            break;
        }
        cell.changed.notify_waiters();
        Ok(())
    }

    pub(in crate::control) async fn activate_proxy(
        self: &Arc<Self>,
        identity: PendingUdpIdentity,
        lease: &UdpInitLease,
        final_outbound: u8,
        final_rule_mark: u32,
    ) -> Result<(), PendingUdpDecisionError> {
        if Self::identity_for_lease(lease) != identity {
            return Err(PendingUdpDecisionError::StaleIdentity);
        }
        let cell = self.matching_cell(identity)?;
        self.commit_pending(
            cell,
            UdpDecisionTransition::ActivateProxy(final_outbound, final_rule_mark),
            None,
        )
        .await
    }

    pub(in crate::control) async fn block(
        self: &Arc<Self>,
        identity: PendingUdpIdentity,
        lease: UdpInitLease,
    ) -> Result<(), PendingUdpDecisionError> {
        if Self::identity_for_lease(&lease) != identity {
            return Err(PendingUdpDecisionError::StaleIdentity);
        }
        let cell = self.matching_cell(identity)?;
        self.commit_pending(cell, UdpDecisionTransition::Block, Some(lease))
            .await
    }

    pub(in crate::control) async fn cancel(
        &self,
        identity: PendingUdpIdentity,
    ) -> Result<(), PendingUdpDecisionError> {
        match self.cancel_unarmed(identity).await {
            Err(PendingUdpDecisionError::ArmedInProgress) => {
                let cell = self.matching_cell(identity)?;
                self.wait_armed(&cell, identity).await
            }
            result => result,
        }
    }

    pub(super) async fn cancel_unarmed(
        &self,
        identity: PendingUdpIdentity,
    ) -> Result<(), PendingUdpDecisionError> {
        let cell = self.matching_cell(identity)?;
        let armed = {
            let state = cell.state.lock();
            match &*state {
                CellState::Pending { armed, .. } => *armed,
                _ => return Ok(()),
            }
        };
        if armed {
            return Err(PendingUdpDecisionError::ArmedInProgress);
        }
        let (verdicts, mismatch) = {
            let mut backend = self.backend_before_deadline(&cell).await?;
            let armed = matches!(&*cell.state.lock(), CellState::Pending { armed: true, .. });
            if armed {
                drop(backend);
                return Err(PendingUdpDecisionError::ArmedInProgress);
            }
            let mut state = cell.state.lock();
            let CellState::Pending {
                started_at,
                armed: false,
                verdicts,
                ..
            } = &mut *state
            else {
                return Ok(());
            };
            if started_at.elapsed() >= HARD_HOLD_TIMEOUT {
                drop(state);
                drop(backend);
                return Err(self.expire_unarmed_pending(&cell, identity));
            }
            let mismatch = self.retire_pending(backend.as_mut(), CleanupRequest::Flow(identity))?;
            if let Some(refusal) = mismatch {
                self.record_commit_mismatch(refusal);
            }
            let verdicts = std::mem::take(verdicts);
            *state = CellState::Dead {
                expires_at: Instant::now() + TERMINAL_GRACE,
            };
            (verdicts, mismatch)
        };
        cell.changed.notify_waiters();
        self.drop_many(verdicts, DropOutcome::Cancel);
        self.endpoints.retire_staged_identity(
            identity.scope,
            identity.client(),
            identity.destination(),
            identity.owner.token,
            identity.endpoint_generation,
        );
        match mismatch {
            Some(UdpDecisionCommitResult::TokenMismatch) => {
                Err(PendingUdpDecisionError::StaleIdentity)
            }
            Some(UdpDecisionCommitResult::StateMismatch) => {
                let fatal = PendingUdpFatal::new(
                    "abort pending flow",
                    "backend left Pending while retaining a non-pending token state",
                );
                self.signal_fatal(fatal.clone());
                Err(fatal.into())
            }
            None => Ok(()),
            Some(
                UdpDecisionCommitResult::Applied
                | UdpDecisionCommitResult::Missing
                | UdpDecisionCommitResult::Superseded,
            ) => unreachable!("successful abort results are not mismatches"),
        }
    }

    pub(super) async fn wait_armed(
        &self,
        cell: &Arc<FlowCell>,
        identity: PendingUdpIdentity,
    ) -> Result<(), PendingUdpDecisionError> {
        loop {
            let changed = cell.changed.notified();
            let deadline = {
                let state = cell.state.lock();
                let CellState::Pending {
                    armed: true,
                    started_at,
                    ..
                } = &*state
                else {
                    return Ok(());
                };
                *started_at + HARD_HOLD_TIMEOUT
            };
            if tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), changed)
                .await
                .is_err()
            {
                self.fail_armed(cell, identity);
                return Err(PendingUdpDecisionError::ArmedInProgress);
            }
        }
    }

    pub(super) fn fail_armed(&self, cell: &Arc<FlowCell>, identity: PendingUdpIdentity) {
        let verdicts = {
            let mut state = cell.state.lock();
            let CellState::Pending {
                armed: true,
                verdicts,
                ..
            } = &mut *state
            else {
                return;
            };
            let verdicts = std::mem::take(verdicts);
            *state = CellState::Dead {
                expires_at: Instant::now() + TERMINAL_GRACE,
            };
            verdicts
        };
        cell.changed.notify_waiters();
        self.drop_many(verdicts, DropOutcome::Cancel);
        self.endpoints.retire_staged_identity(
            identity.scope,
            identity.client(),
            identity.destination(),
            identity.owner.token,
            identity.endpoint_generation,
        );
        self.signal_fatal(PendingUdpFatal::new(
            "armed flow cancellation",
            "DirectArmed flow lost its initializer before activation",
        ));
    }
}
