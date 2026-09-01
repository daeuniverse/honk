use super::*;

const JANITOR_INTERVAL: Duration = Duration::from_secs(5);

/// Why a UDP pool entry went away.  The removal worker retires the flow's
/// conntrack entries only when userspace owned the datapath.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RemovalReason {
    /// A userspace endpoint (or its uncommitted reservation) is gone; the
    /// flow's conntrack entries are retired with it.
    UserspaceEndpointRetired,
    #[cfg(any(feature = "ebpf", test))]
    /// The flow was handed to the kernel; its terminal conn_state must remain.
    KernelHandoff,
}

/// Message sent to the endpoint-removal sink.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct EndpointRemoval {
    pub(crate) client: SocketAddr,
    pub(crate) dst: SocketAddr,
    pub(crate) decision_token: u32,
    pub(crate) generation: u64,
    pub(crate) conn_id: Option<String>,
    pub(crate) reason: RemovalReason,
}

impl UdpEndpointPool {
    pub(crate) fn set_remove_sink(&self, tx: tokio::sync::mpsc::Sender<EndpointRemoval>) {
        *self.remove_sink.lock() = Some(tx);
        self.flush_removal_dirty();
    }

    pub(in crate::control) fn flush_removal_dirty(&self) {
        let Some(tx) = self.remove_sink.lock().clone() else {
            return;
        };
        let mut dirty = self.removal_dirty.lock();
        dirty.retain(|removal| match tx.try_send(removal.clone()) {
            Ok(()) => false,
            Err(mpsc::error::TrySendError::Full(_)) | Err(mpsc::error::TrySendError::Closed(_)) => {
                true
            }
        });
    }

    async fn drain_removal_dirty(&self) {
        let Some(tx) = self.remove_sink.lock().clone() else {
            return;
        };
        let pending = std::mem::take(&mut *self.removal_dirty.lock());
        for removal in pending {
            if tx.send(removal).await.is_err() {
                break;
            }
        }
    }

    pub(super) fn notify_removed(
        &self,
        client: SocketAddr,
        dst: SocketAddr,
        conn_id: Option<String>,
        reason: RemovalReason,
        decision_token: u32,
        generation: u64,
    ) {
        let removal = EndpointRemoval {
            client,
            dst,
            decision_token,
            generation,
            conn_id,
            reason,
        };
        #[cfg(test)]
        if self.remove_sink.lock().is_none() {
            self.complete_removal(client, dst, decision_token, generation);
            return;
        }
        let delivered = self
            .remove_sink
            .lock()
            .as_ref()
            .is_some_and(|tx| tx.try_send(removal.clone()).is_ok());
        if !delivered {
            self.removal_dirty.lock().insert(removal);
        }
        self.flush_removal_dirty();
    }

    /// Begin exact retirement of the currently observed incarnation.
    pub fn remove(&self, client: SocketAddr, dst: SocketAddr) {
        let key = EndpointKey::new(client, dst);
        let identity = self.endpoints.get(&key).and_then(|entry| {
            (!matches!(entry.value(), EndpointEntry::Retiring { .. }))
                .then(|| (entry.value().decision_token(), entry.value().generation()))
        });
        if let Some((token, generation)) = identity {
            self.retire_if_same(key, token, generation);
        }
    }

    #[cfg(any(feature = "ebpf", test))]
    pub(in crate::control) fn retire_staged_identity(
        &self,
        client: SocketAddr,
        dst: SocketAddr,
        decision_token: u32,
        generation: u64,
    ) -> bool {
        decision_token != 0
            && self.retire_if_same(EndpointKey::new(client, dst), decision_token, generation)
    }

    /// Replace only the exact live incarnation with its removal tombstone.
    pub(super) fn retire_if_same(&self, key: EndpointKey, token: u32, generation: u64) -> bool {
        let entry = match self.endpoints.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied)
                if occupied.get().matches_identity(generation, token)
                    && !matches!(occupied.get(), EndpointEntry::Retiring { .. }) =>
            {
                if let EndpointEntry::Initializing(initializing) = occupied.get() {
                    initializing.cancel();
                }
                self.active_retirements.fetch_add(1, Ordering::AcqRel);
                occupied.insert(EndpointEntry::Retiring { generation, token })
            }
            _ => return false,
        };
        let conn_id = entry.retire();
        drop(entry);
        self.notify_removed(
            SocketAddr::new(key.client_ip(), key.client_port),
            SocketAddr::new(key.dst_ip(), key.dst_port),
            conn_id,
            RemovalReason::UserspaceEndpointRetired,
            token,
            generation,
        );
        true
    }

    /// Acknowledge backend/tracker cleanup and delete only its exact tombstone.
    pub(crate) fn complete_removal(
        &self,
        client: SocketAddr,
        dst: SocketAddr,
        decision_token: u32,
        generation: u64,
    ) -> bool {
        let key = EndpointKey::new(client, dst);
        let removed = match self.endpoints.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(occupied)
                if matches!(
                    occupied.get(),
                    EndpointEntry::Retiring { generation: found, token }
                        if *found == generation && *token == decision_token
                ) =>
            {
                occupied.remove();
                true
            }
            _ => false,
        };
        if removed && self.active_retirements.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.retirements_empty.notify_waiters();
        }
        removed
    }

    /// Retire Ready and bound-Initializing mappings for a dead node.
    /// Only Initializing entries whose finalized winner is `node_id` are
    /// removed; an unbound reservation is still awaiting a winner. Removal is
    /// generation-safe.
    pub fn remove_by_node(&self, node_id: uuid::Uuid) {
        let _binding_gate = self.node_binding_gate.lock();
        let stale: Vec<(EndpointKey, u32, u64)> = self
            .endpoints
            .iter()
            .filter_map(|entry| match entry.value() {
                EndpointEntry::Ready(ready) if ready.endpoint.node_id == node_id => {
                    Some((*entry.key(), ready.decision_token, ready.generation))
                }
                EndpointEntry::Initializing(initializing)
                    if initializing.selected_node_is(node_id) =>
                {
                    Some((
                        *entry.key(),
                        initializing.decision_token,
                        initializing.generation,
                    ))
                }
                _ => None,
            })
            .collect();
        let removed = stale
            .into_iter()
            .filter(|(key, token, generation)| self.retire_if_same(*key, *token, *generation))
            .count();
        if removed != 0 {
            debug!(
                "Removed {} UDP endpoints bound to dead node {}",
                removed, node_id
            );
        }
    }

    /// The driver owns liveness and removes its mapping on reply timeout or
    /// I/O failure. Keep this janitor as a conservative backstop for entries
    /// whose reply task has already released its reference.
    pub fn janitor_cycle(&self) -> usize {
        let stale: Vec<(EndpointKey, u32, u64)> = self
            .endpoints
            .iter()
            .filter_map(|entry| match entry.value() {
                EndpointEntry::Ready(ready)
                    if ready.endpoint.ref_count() <= 0 && ready.endpoint.is_expired() =>
                {
                    Some((*entry.key(), ready.decision_token, ready.generation))
                }
                _ => None,
            })
            .collect();
        let removed = stale
            .iter()
            .filter(|(key, token, generation)| self.retire_if_same(*key, *token, *generation))
            .count();
        if removed > 0 {
            debug!("UDP endpoint janitor removed {} expired endpoints", removed);
        }
        removed
    }

    pub fn spawn_janitor(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(JANITOR_INTERVAL).await;
                pool.janitor_cycle();
            }
        })
    }

    pub(in crate::control) async fn wait_for_retirements(&self) -> bool {
        let wait = async {
            loop {
                if self.active_retirements.load(Ordering::Acquire) == 0 {
                    return;
                }
                let notified = self.retirements_empty.notified();
                if self.active_retirements.load(Ordering::Acquire) == 0 {
                    return;
                }
                notified.await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .is_ok()
    }

    /// Terminally close UDP admission, retire every mapping, and wait for all
    /// generation-owned slow-path tasks and endpoint drivers. The removal sink
    /// is closed only after task cleanup has completed so its consumer can
    /// drain before the control plane tears down generic background tasks.
    pub(in crate::control) async fn shutdown(&self) -> bool {
        self.advance_initialization_epoch(true);
        let slow_tasks = {
            let mut tasks = self.slow_tasks.lock();
            tasks.closed = true;
            std::mem::take(&mut tasks.tasks)
        };
        {
            let mut drivers = self.drivers.lock();
            drivers.closed = true;
        }

        let initializers_graceful = self.wait_for_initializers().await;
        let slow_tasks_clean = join_registered_tasks(
            slow_tasks,
            "slow-path",
            DRIVER_ABORT_TIMEOUT,
            !initializers_graceful,
        )
        .await;
        let initializers_clean =
            slow_tasks_clean && self.active_initializers.load(Ordering::Acquire) == 0;

        let stale: Vec<(EndpointKey, u32, u64)> = self
            .endpoints
            .iter()
            .filter_map(|entry| match entry.value() {
                EndpointEntry::Initializing(initializing) => Some((
                    *entry.key(),
                    initializing.decision_token,
                    initializing.generation,
                )),
                EndpointEntry::Ready(ready) => {
                    Some((*entry.key(), ready.decision_token, ready.generation))
                }
                EndpointEntry::Retiring { .. } => None,
            })
            .collect();
        for (key, token, generation) in stale {
            self.retire_if_same(key, token, generation);
        }

        let driver_tasks = {
            let mut drivers = self.drivers.lock();
            std::mem::take(&mut drivers.tasks)
        };
        let drivers_clean = join_registered_tasks(
            driver_tasks,
            "endpoint driver",
            DRIVER_SHUTDOWN_TIMEOUT,
            false,
        )
        .await;

        self.drain_removal_dirty().await;
        let retirements_clean = self.wait_for_retirements().await;
        self.remove_sink.lock().take();
        initializers_clean && drivers_clean && retirements_clean
    }
}
