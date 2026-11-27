use super::*;

impl Stack {
    /// Includes live assemblies, tombstones and queued timeout quotes in this exact owner.
    pub fn retains_fragment(&self, fragment: crate::FragmentInfo) -> bool {
        self.reasm.retains_fragment(fragment)
    }

    /// Whether this Stack still owns application, protocol or queued-control obligations for
    /// the original TCP handle, including after close and TIME_WAIT compaction.
    ///
    /// The handle must come from this Stack. A false result does not release packets already
    /// returned by `poll_transmit_with`: the driver must separately drain their saved `flow`
    /// ownership, other producers and application tasks before retiring the scoped flow.
    pub fn tcp_retained(&self, id: FlowId) -> bool {
        if id.generation == 0 {
            return false;
        }
        self.table
            .slots
            .get(id.idx as usize)
            .is_some_and(|slot| match &slot.flow {
                Some(Flow::Tcp(_)) => slot.generation == id.generation,
                Some(Flow::TimeWait(t)) => t.handle_generation == id.generation,
                _ => false,
            })
            || self.controls.iter().any(|control| control.flow == Some(id))
    }

    /// Takes and clears the coalesced hint that a TCP or TIME_WAIT owner was removed, or a
    /// queued flow-owned control reply was emitted or suppressed, since the last take.
    /// A true result asks the caller to recheck [`Self::tcp_retained`] for its original handles
    /// and to honor any ownership already handed to the driver.
    pub fn take_tcp_retention_change(&mut self) -> bool {
        std::mem::take(&mut self.table.tcp_retention_changed)
    }

    /// Visits actual retained owners, including killed fragment identity tombstones.
    /// The visitor must not re-enter the embedding's owner; repeated contexts are allowed.
    pub fn visit_retained_source_contexts(&self, mut visit: impl FnMut(SourceContext)) {
        for (index, slot) in self.table.slots.iter().enumerate() {
            if matches!(slot.flow, Some(Flow::Tcp(_) | Flow::TimeWait(_)))
                && let Some(source) = self.table.source(index as u32)
            {
                visit(source);
            }
        }
        for control in &self.controls {
            if let Some(source) = control.source {
                visit(source);
            }
        }
        self.udp_tx.visit_retained_source_contexts(&mut visit);
        self.reasm.visit_retained_source_contexts(visit);
    }

    /// Read-only execution ownership through pending TCP, TIME_WAIT and flow-owned
    /// control output. This is not packet validation or admission authority.
    pub fn retains_tcp(&self, source: SocketAddr, destination: SocketAddr) -> bool {
        self.retains_tcp_with_lineage(source, destination, None)
    }

    /// Selects only the requested source lineage; `None` selects non-contextual owners.
    pub fn retains_tcp_with_lineage(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        lineage: Option<NonZeroU64>,
    ) -> bool {
        let tuple = FourTuple {
            local: destination,
            remote: source,
        };
        self.table
            .tcp
            .get(&tuple)
            .into_iter()
            .chain(self.table.timewait.get(&tuple))
            .any(|&index| self.table.source(index).map(|source| source.lineage) == lineage)
            || self.controls.iter().any(|control| {
                control.flow.is_some()
                    && control.tuple == tuple
                    && control.source.map(|source| source.lineage) == lineage
            })
    }

    /// Unfinished reassembly lacks ports. Unpulled transport replies retain their wire tuple.
    pub fn retains_packet_obligation(
        &self,
        client: SocketAddr,
        destination: SocketAddr,
        protocol: u8,
    ) -> bool {
        self.reasm
            .obligations()
            .any(|key| key == (client.ip(), destination.ip(), protocol))
            || match protocol {
                wire::PROTO_TCP => self.controls.iter().any(|control| {
                    control.tuple.remote == client && control.tuple.local == destination
                }),
                wire::PROTO_UDP => self.udp_tx.retains_tuple(destination, client),
                _ => false,
            }
    }

    /// Whether this peer still owns protocol state or an unpulled reply. Packets already
    /// exported to an adapter and its application work need separate retention there.
    pub fn retains_source(&self, address: IpAddr) -> bool {
        self.table
            .tcp
            .keys()
            .chain(self.table.timewait.keys())
            .any(|tuple| tuple.remote.ip() == address)
            || self.retains_pending_source(address)
    }

    /// Whether unpulled control replies, UDP fragments or reassembly retain this peer.
    pub fn retains_pending_source(&self, address: IpAddr) -> bool {
        self.pending_sources().any(|source| source == address)
    }

    /// Constant-time hint for [`Self::visit_pending_sources`]. Fragment tombstones can keep
    /// this true without yielding addresses.
    pub fn has_pending_sources(&self) -> bool {
        !self.controls.is_empty() || self.udp_tx.pending() || !self.reasm.is_quiescent()
    }

    /// Visits queued control replies, pending UDP datagrams and live reassembly obligations.
    /// Repeated addresses are allowed. Contextual owners use [`Self::visit_retained_source_contexts`]
    /// for original source lineages and identity-only tombstones.
    pub fn visit_pending_sources(&self, visit: impl FnMut(IpAddr)) {
        self.pending_sources().for_each(visit);
    }

    /// Upper bound on the number of visits in [`Self::visit_pending_sources`].
    pub fn pending_source_bound(&self) -> usize {
        let udp = crate::udp_t::UdpTx::pending_bound(usize::from(self.cfg.mtu));
        let bound = self.control_limit() + udp;
        if self.transparent()
            && self
                .shard
                .as_ref()
                .is_none_or(|shard| shard.reassembly_owner)
        {
            bound.saturating_add(self.reasm.obligation_bound())
        } else {
            bound
        }
    }

    fn pending_sources(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.controls
            .iter()
            .map(|control| control.tuple.remote.ip())
            .chain(self.udp_tx.pending_destinations())
            .chain(self.reasm.obligations().map(|(source, _, _)| source))
    }

    /// Reply materialization still pending inside the Stack, before adapter ownership.
    pub fn retains_source_output(&self, address: IpAddr) -> bool {
        self.table.slots.iter().any(|slot| match &slot.flow {
            Some(Flow::Tcp(t)) => t.tuple.remote.ip() == address && (slot.on_tx || slot.on_control),
            Some(Flow::TimeWait(t)) => t.tuple.remote.ip() == address && t.ack_due,
            _ => false,
        }) || self.retains_pending_source(address)
    }

    /// Pending output for one original source lineage, excluding identity-only tombstones.
    pub fn retains_source_output_with_lineage(&self, lineage: NonZeroU64) -> bool {
        self.table.slots.iter().enumerate().any(|(index, slot)| {
            self.table
                .source(index as u32)
                .is_some_and(|source| source.lineage == lineage)
                && match &slot.flow {
                    Some(Flow::Tcp(_)) => slot.on_tx || slot.on_control,
                    Some(Flow::TimeWait(t)) => t.ack_due,
                    _ => false,
                }
        }) || self.controls.iter().any(|control| {
            control
                .source
                .is_some_and(|source| source.lineage == lineage)
        }) || self.udp_tx.retains_source_output_with_lineage(lineage)
            || self.reasm.retains_source_output_with_lineage(lineage)
    }
}
