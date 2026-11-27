use super::*;

pub(in crate::control) struct PendingEndpointAdmission {
    authority: RoutingAuthority,
    scope: ScopeId,
    generation: PolicyGeneration,
}

impl RoutingAuthority {
    pub(in crate::control) fn pending_endpoint(
        &self,
        scope: ScopeId,
        generation: PolicyGeneration,
    ) -> PendingEndpointAdmission {
        PendingEndpointAdmission {
            authority: self.clone(),
            scope,
            generation,
        }
    }
}

impl PendingEndpointAdmission {
    pub(in crate::control) fn commit<R>(
        self,
        scope: ScopeId,
        commit: impl FnOnce() -> R,
    ) -> io::Result<R> {
        let stale = || {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "pending packet admission is stale or publication is busy",
            )
        };
        if scope != self.scope || !self.authority.admitting() {
            return Err(stale());
        }
        let read = self.authority.try_read_policy()?;
        let mode = self
            .authority
            .0
            .mode_state
            .as_ref()
            .map(|state| state.try_read().ok_or_else(stale))
            .transpose()?;
        if !Arc::ptr_eq(read.registration, &self.authority.0)
            || !self
                .generation
                .same_policy(self.authority.generation(mode.as_deref()))
        {
            return Err(stale());
        }
        let facts = if let Some(stamp) = self.generation.facts {
            let mut facts = self
                .authority
                .0
                .projection
                .try_packet_facts()
                .ok_or_else(stale)?;
            if !facts.is_current(stamp) {
                return Err(stale());
            }
            Some(facts)
        } else {
            None
        };
        if !self.authority.admitting() {
            return Err(stale());
        }
        let result = commit();
        drop(facts);
        drop(mode);
        drop(read);
        Ok(result)
    }
}
