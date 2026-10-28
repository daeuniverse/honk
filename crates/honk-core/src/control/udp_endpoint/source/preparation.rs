use super::*;

pub(in crate::control) enum SourcePreparation {
    Reused(SourceAttachment),
    Fresh {
        scope: SourceScope,
        prepared: PreparedSourceTransport,
        source_permit: OwnedSemaphorePermit,
        runtime: Arc<NodeRuntime>,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        stats: Arc<StatsManager>,
        node_id: uuid::Uuid,
        node_name: String,
        health_family: honk_outbound::alive::IpVersion,
    },
}

impl SourcePreparation {
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
                if attachment.owner.is_ready() {
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
                runtime,
                alive_set,
                stats,
                node_id,
                node_name,
                health_family,
            } => {
                let mut prepared = Some(prepared);
                let mut transport = None;
                loop {
                    if pool.terminal.load(Ordering::Acquire) {
                        return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
                    }
                    let changed = pool.source_changed.notified();
                    if let Some(owner) = pool
                        .sources
                        .get(&scope)
                        .map(|entry| Arc::clone(entry.value()))
                    {
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
                        match pool.sources.entry(scope.clone()) {
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
