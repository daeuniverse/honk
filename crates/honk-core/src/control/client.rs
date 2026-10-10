//! Shared command client for state changes that must serialize with reload.

#[cfg(feature = "native-api")]
use honk_outbound::group::SelectorMember;
#[cfg(any(feature = "native-api", feature = "clash-api"))]
use honk_outbound::group::SelectorNetworks;
use std::sync::Arc;
use tokio::sync::mpsc;
#[cfg(any(feature = "native-api", feature = "clash-api"))]
use tokio::sync::oneshot;

#[derive(Clone)]
pub struct ControlClient {
    sender: mpsc::Sender<super::ControlCommand>,
}

#[cfg(all(feature = "native-api", feature = "clash-api"))]
#[derive(Debug)]
pub(crate) enum ModeRequest {
    ClashMode(String),
    ClashSelection(String),
}

#[cfg(any(feature = "native-api", feature = "clash-api"))]
#[derive(Debug)]
pub(crate) enum SelectionRequest {
    #[cfg(feature = "clash-api")]
    Name { group: String, member: String },
    #[cfg(feature = "native-api")]
    Native {
        group_id: String,
        member_id: String,
        networks: SelectorNetworks,
    },
    #[cfg(feature = "native-api")]
    ClearOverride {
        group_id: String,
        networks: SelectorNetworks,
    },
}

#[cfg(any(feature = "native-api", feature = "clash-api"))]
#[derive(Debug)]
pub(crate) struct SelectionResult {
    #[cfg(feature = "native-api")]
    pub(crate) revision: u64,
    #[cfg(feature = "native-api")]
    pub(crate) interrupted: bool,
    /// The group is automatic, so the choice is a runtime pin.
    #[cfg(feature = "native-api")]
    pub(crate) overridden: bool,
    /// A cleared group's selections, read under the same reload lock as the
    /// clear so they match `revision`.
    #[cfg(feature = "native-api")]
    pub(crate) selection: Option<serde_json::Value>,
}

#[cfg(any(feature = "native-api", feature = "clash-api"))]
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub(crate) enum ControlError {
    #[error("resource not found")]
    NotFound,
    #[error("selection is unsupported")]
    Unsupported,
    #[error("a selector has no override to clear")]
    Conflict,
    #[error("control owner is unavailable")]
    Unavailable,
    #[error("transport interruption could not be confirmed")]
    InterruptionFailed,
}

impl ControlClient {
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.sender
            .send(super::ControlCommand::Shutdown)
            .await
            .map_err(|_| anyhow::anyhow!("control command owner is unavailable"))
    }
    pub(crate) fn new(sender: mpsc::Sender<super::ControlCommand>) -> Self {
        Self { sender }
    }

    #[cfg(any(feature = "native-api", feature = "clash-api"))]
    pub(crate) async fn select(
        &self,
        request: SelectionRequest,
    ) -> Result<SelectionResult, ControlError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(super::ControlCommand::SetSelector { request, reply })
            .map_err(|_| ControlError::Unavailable)?;
        response.await.map_err(|_| ControlError::Unavailable)?
    }

    #[cfg(all(feature = "native-api", feature = "clash-api"))]
    pub(crate) async fn mode(
        &self,
        request: ModeRequest,
    ) -> Result<crate::mode::ModeState, ControlError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(super::ControlCommand::SetRuntimeMode { request, reply })
            .map_err(|_| ControlError::Unavailable)?;
        response.await.map_err(|_| ControlError::Unavailable)?
    }
}

impl super::ControlPlane {
    /// Drive mutations for an embedded engine whose caller owns ingress and shutdown.
    pub async fn serve_control_commands(&mut self) -> anyhow::Result<()> {
        let mut receiver = self
            .command_rx
            .take()
            .ok_or_else(|| anyhow::anyhow!("control command receiver is already owned"))?;
        let mut authorizations = crate::subscription::SubscriptionAuthorizations::new(
            &self.config.read().await.subscriptions,
        )?;
        let drain = Arc::clone(&self.drain_tracker);
        while let Some(command) = receiver.recv().await {
            if !self
                .dispatch_control_command(command, &drain, &mut authorizations)
                .await
            {
                break;
            }
        }
        Ok(())
    }
    #[cfg(any(feature = "native-api", feature = "clash-api"))]
    pub(super) async fn apply_selector_request(
        &self,
        request: SelectionRequest,
    ) -> Result<SelectionResult, ControlError> {
        let _reload = self.reload_lock.lock().await;
        #[cfg(feature = "native-api")]
        if self.native.is_some() {
            match self.phase.as_ref().map(|phase| *phase.borrow()) {
                Some(super::EnginePhase::Running) if self.is_datapath_healthy() => {}
                _ => return Err(ControlError::Unavailable),
            }
        }
        let config = self.config.read().await;
        let manager = self.group_manager.read().clone();
        let (name, member, networks) = match request {
            #[cfg(feature = "clash-api")]
            SelectionRequest::Name { group, member } => {
                let selected = manager
                    .selector_member_by_name(&group, &member)
                    .map_err(selection_error)?;
                (group, Some(selected), SelectorNetworks::Both)
            }
            #[cfg(feature = "native-api")]
            SelectionRequest::Native {
                group_id,
                member_id,
                networks,
            } => {
                let catalog = self.native_catalog()?;
                let name = native_group_name(&catalog, &group_id)?;
                let selected = manager
                    .group_members(&name)
                    .find_map(|member| match member {
                        honk_outbound::group::GroupMember::Node(node)
                            if node.id.to_string() == member_id =>
                        {
                            Some(SelectorMember::Node(node.id))
                        }
                        honk_outbound::group::GroupMember::Group(group)
                            if catalog.groups.get(&group.name) == Some(&member_id) =>
                        {
                            Some(SelectorMember::Group(group.name.clone()))
                        }
                        _ => None,
                    })
                    .ok_or(ControlError::Unsupported)?;
                (name, Some(selected), networks)
            }
            #[cfg(feature = "native-api")]
            SelectionRequest::ClearOverride { group_id, networks } => {
                let catalog = self.native_catalog()?;
                let name = native_group_name(&catalog, &group_id)?;
                (name, None, networks)
            }
        };
        let group = config
            .groups
            .iter()
            .rev()
            .find(|group| group.name == name)
            .ok_or(ControlError::NotFound)?;
        let group_id = group.id.to_string();
        #[cfg(feature = "native-api")]
        let group_id = if let Some(native) = &self.native {
            native
                .catalog
                .snapshot()
                .groups
                .get(&name)
                .cloned()
                .ok_or(ControlError::NotFound)?
        } else {
            group_id
        };
        let mut selected = Vec::new();
        if group.interrupt_connections {
            for (network, label) in [
                (honk_outbound::group::SelectionNetwork::Tcp, "tcp"),
                (honk_outbound::group::SelectionNetwork::Udp, "udp"),
            ] {
                if networks.contains(network) {
                    selected.push((
                        network,
                        self.connection_tracker
                            .snapshot_group(&group_id, Some(label)),
                    ));
                }
            }
        }
        let overridden = group.policy != honk_config::group::GroupPolicy::Selector;
        let update = match &member {
            Some(member) if overridden => manager.publish_override(&name, member, networks),
            Some(member) => manager.publish_selector_choice(&name, member, networks),
            None => manager.clear_override(&name, networks),
        }
        .map_err(selection_error)?;
        #[cfg(feature = "native-api")]
        let revision = update.revision;
        #[cfg(feature = "native-api")]
        let selection = match (&member, &self.native) {
            (None, Some(native)) => Some(crate::observe::catalog::runtime_selection(
                &manager,
                &native.catalog.snapshot(),
                &name,
            )),
            _ => None,
        };
        let changed = update.changed_networks.clone();
        drop(config);
        update.run_callbacks_without_interrupt();
        use futures::StreamExt;
        let mut pending: futures::stream::FuturesUnordered<_> = selected
            .into_iter()
            .filter(|(network, _)| changed.contains(network))
            .flat_map(|(_, connections)| connections)
            .map(|connection| self.connection_tracker.start_close(connection).wait())
            .collect();
        #[cfg(feature = "native-api")]
        let mut interrupted = false;
        let mut uncertain = false;
        while let Some(outcome) = pending.next().await {
            match outcome {
                crate::connection_tracker::CloseOutcome::Closed => {
                    #[cfg(feature = "native-api")]
                    {
                        interrupted = true;
                    }
                }
                crate::connection_tracker::CloseOutcome::Gone => {}
                _ => uncertain = true,
            }
        }
        if uncertain {
            return Err(ControlError::InterruptionFailed);
        }
        Ok(SelectionResult {
            #[cfg(feature = "native-api")]
            revision,
            #[cfg(feature = "native-api")]
            interrupted,
            #[cfg(feature = "native-api")]
            overridden,
            #[cfg(feature = "native-api")]
            selection,
        })
    }

    #[cfg(feature = "native-api")]
    fn native_catalog(
        &self,
    ) -> Result<Arc<crate::observe::catalog::CatalogIdentity>, ControlError> {
        Ok(self
            .native
            .as_ref()
            .ok_or(ControlError::Unavailable)?
            .catalog
            .snapshot())
    }
}

#[cfg(feature = "native-api")]
fn native_group_name(
    catalog: &crate::observe::catalog::CatalogIdentity,
    group_id: &str,
) -> Result<String, ControlError> {
    catalog
        .groups
        .iter()
        .find(|(_, id)| **id == group_id)
        .map(|(name, _)| name.clone())
        .ok_or(ControlError::NotFound)
}

#[cfg(any(feature = "native-api", feature = "clash-api"))]
fn selection_error(error: honk_outbound::group::SelectorError) -> ControlError {
    match error {
        honk_outbound::group::SelectorError::GroupNotFound => ControlError::NotFound,
        honk_outbound::group::SelectorError::RevisionExhausted => ControlError::Unavailable,
        honk_outbound::group::SelectorError::IsSelector => ControlError::Conflict,
        _ => ControlError::Unsupported,
    }
}
