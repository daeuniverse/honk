use super::*;

#[allow(
    clippy::large_enum_variant,
    reason = "keep admitted source ownership inline without another allocation"
)]
pub(in crate::control) enum SourcePreparation {
    Reused(SourceAttachment),
    Fresh {
        scope: SourceScope,
        prepared: PreparedSourceTransport,
        source_permit: OwnedSemaphorePermit,
        packet_source: Option<SourceWork>,
        runtime: Arc<NodeRuntime>,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        stats: Arc<StatsManager>,
        node_id: uuid::Uuid,
        node_name: String,
        health_family: honk_outbound::alive::IpVersion,
        evidence: Option<Arc<UdpTrafficEvidence>>,
    },
}

impl SourcePreparation {
    pub(in crate::control) fn with_evidence(
        mut self,
        creator_evidence: Option<Arc<UdpTrafficEvidence>>,
    ) -> Self {
        if let Self::Fresh { evidence, .. } = &mut self {
            *evidence = creator_evidence;
        }
        self
    }

    #[cfg(all(test, feature = "rprx"))]
    pub(in crate::control::udp_endpoint) fn attached_owner(&self) -> Option<Arc<SourceOwner>> {
        match self {
            Self::Reused(attachment) => Some(attachment.owner()),
            Self::Fresh { .. } => None,
        }
    }

    pub(in crate::control) async fn commit(
        self,
        pool: &Arc<UdpEndpointPool>,
    ) -> anyhow::Result<SourceAttachment> {
        match self {
            Self::Reused(attachment) => {
                if attachment.owner.is_ready()
                    && packet_binding_active(attachment.owner.packet_source.as_ref())
                {
                    attachment.owner.transport.observe_reuse();
                    Ok(attachment)
                } else {
                    Err(honk_outbound::proxy::PacketRejection::Cancelled.into())
                }
            }
            Self::Fresh {
                scope,
                prepared,
                source_permit,
                packet_source,
                runtime,
                alive_set,
                stats,
                node_id,
                node_name,
                health_family,
                evidence,
            } => {
                let mut prepared = Some(prepared);
                let mut transport = None;
                loop {
                    if pool.terminal.load(Ordering::Acquire)
                        || !packet_binding_active(packet_source.as_ref())
                    {
                        return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
                    }
                    let changed = pool.source_changed.notified();
                    if let Some(owner) = pool
                        .sources
                        .get(&scope)
                        .map(|entry| Arc::clone(entry.value()))
                    {
                        if owner.packet_source.as_ref().map(SourceWork::identity)
                            != packet_source.as_ref().map(SourceWork::identity)
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "shared UDP source execution owner mismatch",
                            )
                            .into());
                        }
                        if let Some(attachment) = owner.attach() {
                            owner.transport.observe_reuse();
                            return Ok(attachment);
                        }
                        changed.await;
                        continue;
                    }

                    if let Some(prepared) = prepared.take() {
                        transport = Some(prepared.commit().await?);
                    }

                    {
                        let mut tasks = pool.source_tasks.lock();
                        while let Some(result) = tasks.try_join_next() {
                            if let Err(error) = result {
                                debug!("UDP source receiver join failed: {}", error);
                            }
                        }
                        if tasks.closed || pool.terminal.load(Ordering::Acquire) {
                            return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
                        }
                        let entry = pool.sources.entry(scope.clone());
                        if !packet_binding_active(packet_source.as_ref()) {
                            return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
                        }
                        match entry {
                            dashmap::mapref::entry::Entry::Occupied(entry) => {
                                let owner = Arc::clone(entry.get());
                                drop(entry);
                                drop(tasks);
                                if let Some(attachment) = owner.attach() {
                                    owner.transport.observe_reuse();
                                    return Ok(attachment);
                                }
                            }
                            dashmap::mapref::entry::Entry::Vacant(entry) => {
                                let owner = SourceOwner::new(
                                    pool.next_source_owner.fetch_add(1, Ordering::Relaxed),
                                    scope.clone(),
                                    transport.expect("prepared source transport"),
                                    runtime,
                                    pool,
                                    alive_set,
                                    node_id,
                                    health_family,
                                    stats.outbound_tracker(
                                        &node_name,
                                        crate::stats::OutboundKind::Node,
                                    ),
                                    stats,
                                    source_permit,
                                    packet_source,
                                    evidence,
                                )?;
                                let receiver =
                                    run_source_receiver(Arc::clone(pool), Arc::clone(&owner));
                                drop(
                                    tasks
                                        .spawn(receiver, super::super::budget::RECEIVE_BYTES)
                                        .map_err(|_| {
                                            honk_outbound::proxy::PacketRejection::Capacity
                                        })?,
                                );
                                entry.insert(Arc::clone(&owner));
                                drop(tasks);
                                return Ok(SourceAttachment {
                                    owner,
                                    committed: false,
                                });
                            }
                        }
                    }
                    changed.await;
                }
            }
        }
    }
}
