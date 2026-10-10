mod completion;
mod geodata;
mod revisions;
#[cfg(test)]
mod tests;
mod validation;

use super::super::management::{self, Completion, Mutation};
use super::super::{
    config_write::WriteError,
    offline,
    store::{Committed, SourceStore},
};
use super::*;
use crate::configuration::{Activation, ActivationRequest};
use crate::control::{ControlCommand, LogFiles};
use crate::subscription::SubscriptionSupervisorHandle;
use honk_config::parser::LoadedConfig;
use tokio::sync::watch;
use validation::{config_error, diagnostics_error, not_included, restart_diagnostics};

pub(crate) struct ConfigCoordinator {
    service: Arc<ConfigService>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

struct Worker {
    service: Arc<ConfigService>,
    store: SourceStore,
    data_dir: PathBuf,
    source_managed: bool,
    active: Arc<tokio::sync::RwLock<Arc<Config>>>,
    log_files: LogFiles,
    diagnostics: crate::config_diagnostics::SharedDiagnostics,
    subscriptions: SubscriptionSupervisorHandle,
    activation: Activation,
    stopping: watch::Receiver<bool>,
}

impl ConfigService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn start(
        self: &Arc<Self>,
        store: SourceStore,
        initial: Option<SourceUpdate>,
        data_dir: PathBuf,
        active: Arc<tokio::sync::RwLock<Arc<Config>>>,
        log_files: LogFiles,
        diagnostics: crate::config_diagnostics::SharedDiagnostics,
        commands: mpsc::Sender<ControlCommand>,
        subscriptions: SubscriptionSupervisorHandle,
    ) -> ConfigCoordinator {
        if let Some(initial) = &initial {
            let config = active.read().await;
            let generation = diagnostics.read().generation;
            self.sources
                .accept(self.sources.prepare_accept(initial), generation);
            self.sources
                .generation_committed(&crate::observe::catalog::revision_for(&config), generation);
        }
        *self.store.write() = Some(store.clone());
        self.warn_secret_collisions();
        let (sender, mut receiver) = mpsc::channel(16);
        *self.sender.lock() = Some(sender);
        let (stop, mut stopping) = watch::channel(false);
        let service = Arc::clone(self);
        let task = tokio::spawn(async move {
            let mut worker = Worker {
                service,
                store,
                data_dir,
                source_managed: initial.is_some(),
                active,
                log_files,
                diagnostics,
                activation: Activation::new(commands, subscriptions.clone()),
                subscriptions,
                stopping: stopping.clone(),
            };
            loop {
                let work = tokio::select! { biased; _=stopping.changed()=>break, work=receiver.recv()=>match work{Some(work)=>work,None=>break} };
                worker.perform(work).await;
            }
            receiver.close();
            while let Some(work) = receiver.recv().await {
                match work {
                    Work::Validate { response, .. } => {
                        let _ = response.send(Err(unavailable()));
                    }
                    Work::Manage { response, .. } => {
                        let _ = response.send(Err(unavailable()));
                    }
                    _ => {}
                }
            }
        });
        ConfigCoordinator {
            service: Arc::clone(self),
            stop,
            task,
        }
    }
}

impl ConfigCoordinator {
    pub(crate) async fn shutdown(self) {
        self.service.sender.lock().take();
        let _ = self.stop.send(true);
        if self.task.await.is_err() {
            tracing::error!("native configuration coordinator stopped unexpectedly");
        }
    }
}

impl Worker {
    async fn perform(&mut self, work: Work) {
        if let Err(error) = self.service.check_phase(&work) {
            match work {
                Work::Manage { response, .. } => {
                    let _ = response.send(Err(error));
                }
                Work::Replace { reservation, .. }
                | Work::Create { reservation, .. }
                | Work::GeoUpdate { reservation, .. }
                | Work::GroupPatch { reservation, .. }
                | Work::Reload { reservation }
                | Work::Import { reservation }
                | Work::ActivateRevision { reservation, .. } => {
                    self.service.operations.reject(&reservation.id, error);
                }
                Work::Sighup => tracing::warn!("SIGHUP refused while engine is not running"),
                _ => unreachable!("excluded non-activation work"),
            }
            return;
        }
        match work {
            Work::GeoUpdate { plan, reservation } => {
                self.perform_geodata(*plan, reservation).await;
            }
            Work::Manage {
                mutation,
                catalog,
                group_manager,
                alive_set,
                response,
            } => {
                let result = self
                    .manage(mutation, &catalog, &group_manager, &alive_set)
                    .await;
                let _ = response.send(result);
            }
            Work::GroupPatch { patch, reservation } => {
                let id = reservation.id.clone();
                let group_id = patch.id.clone();
                let revision = patch.revision.clone();
                match self
                    .prepare_group_patch(*patch, &reservation.principal)
                    .await
                {
                    Ok(Some((candidate, sources, diagnostics, committed))) => {
                        self.replace_operation(
                            &id,
                            ActivationRequest {
                                candidate,
                                sources: Some(sources),
                                diagnostics,
                                expected_group_revision: Some(revision),
                                deferred_provider: None,
                            },
                            Some(&group_id),
                            committed,
                        )
                        .await;
                    }
                    Ok(None) => {
                        self.service.operations.accept(&id);
                        self.service.operations.running(&id);
                        self.service.operations.succeed(
                            &id,
                            crate::native_api::operations::OperationResult::GroupUpdate {
                                group_id,
                                config_revision: revision,
                            },
                        );
                    }
                    Err(error) => {
                        self.service.operations.reject(&id, error);
                    }
                }
            }
            Work::Validate { request, response } => {
                let result = self.validate(request).await;
                let _ = response.send(result);
            }
            Work::Replace {
                source_id,
                content,
                if_match,
                reservation,
            } => {
                let id = reservation.id.clone();
                match self
                    .prepare_replace(
                        &source_id,
                        content,
                        Precondition::Source(if_match),
                        None,
                        &reservation.principal,
                    )
                    .await
                {
                    Ok((candidate, sources, diagnostics, committed)) => {
                        self.replace_operation(
                            &id,
                            ActivationRequest {
                                candidate,
                                sources: Some(sources),
                                diagnostics,
                                expected_group_revision: None,
                                deferred_provider: None,
                            },
                            None,
                            committed,
                        )
                        .await;
                    }
                    Err(error) => {
                        self.service.operations.reject(&id, error);
                    }
                }
            }
            Work::Create {
                path,
                content,
                reservation,
            } => {
                let id = reservation.id.clone();
                let prepared = self
                    .prepare_create(path, content, &reservation.principal)
                    .await;
                self.tree_operation(&id, prepared).await;
            }
            Work::Import { reservation } => {
                let id = reservation.id.clone();
                let prepared = self.prepare_import(&reservation.principal).await;
                self.tree_operation(&id, prepared).await;
            }
            Work::ActivateRevision {
                number,
                reservation,
            } => {
                let id = reservation.id.clone();
                let (head, blocked) = match &self.store {
                    SourceStore::Db(database) => (
                        database.cached_head().map(|(head, _)| head),
                        database.blocked(),
                    ),
                    SourceStore::File(_) => (None, false),
                };
                let current = head == Some(number);
                if current && !blocked {
                    self.service.operations.accept(&id);
                    self.service.operations.running(&id);
                    let generation = self.diagnostics.read().generation;
                    self.service.operations.succeed(
                        &id,
                        super::super::operations::OperationResult::Reload {
                            active_generation_id: Some(format!(
                                "{}:{generation}",
                                self.service.instance_id
                            )),
                            datapath_generation_id: None,
                        },
                    );
                } else {
                    let origin =
                        (!current).then_some(crate::native_api::store::db::Origin::Activate);
                    let prepared = self
                        .prepare_revision(number, &reservation.principal, origin)
                        .await;
                    self.tree_operation(&id, prepared).await;
                }
            }
            Work::Reload { reservation } => {
                let id = reservation.id.clone();
                self.service.operations.accept(&id);
                self.service.operations.running(&id);
                match self.load().await {
                    Ok((candidate, sources, diagnostics)) => {
                        self.reload_operation(
                            &id,
                            ActivationRequest {
                                candidate,
                                sources,
                                diagnostics,
                                expected_group_revision: None,
                                deferred_provider: None,
                            },
                        )
                        .await;
                    }
                    Err(error) => {
                        let (code, message, mut details) = error.into_safe();
                        if let Some(details) =
                            details.get_or_insert_with(|| json!({})).as_object_mut()
                        {
                            details.insert("committed".into(), json!(false));
                        }
                        // Every warning of the files rides along; when they overflow the
                        // operation's details, keep the rows that explain the failure.
                        if let Some(rows) = details
                            .as_mut()
                            .filter(|details| {
                                !crate::native_api::operations::error_details_fit(details)
                            })
                            .and_then(|details| details.get_mut("diagnostics"))
                            .and_then(Value::as_array_mut)
                        {
                            rows.retain(|row| row["level"] == "error");
                        }
                        self.failed(&id, code, message, details);
                    }
                }
            }
            Work::Sighup => match self.load().await {
                Ok((candidate, sources, diagnostics)) => {
                    honk_config::diagnostic::report_detailed_diagnostics(&diagnostics);
                    let completion = self
                        .activation
                        .activate(ActivationRequest {
                            candidate,
                            sources,
                            diagnostics,
                            expected_group_revision: None,
                            deferred_provider: None,
                        })
                        .await;
                    completion::log_sighup(completion);
                }
                Err(error) => {
                    let (code, message, details) = error.into_safe();
                    let details = details.map(|details| details.to_string());
                    tracing::warn!(
                        code,
                        message,
                        details = details.as_deref(),
                        "SIGHUP configuration admission rejected"
                    );
                }
            },
        }
    }

    async fn manage(
        &mut self,
        mutation: Mutation,
        catalog: &crate::observe::catalog::Catalog,
        group_manager: &honk_outbound::group::SharedGroupManager,
        alive_set: &honk_outbound::alive::AliveDialerSet,
    ) -> Result<Completion, ApiError> {
        self.service.manage_admission()?;
        let active = self.active.read().await.clone();
        let accepted = self
            .service
            .sources
            .accepted
            .read()
            .clone()
            .ok_or_else(management::unsupported)?;
        if let Some(reason) = self.service.source_refusal(&accepted, 0) {
            return Err(management::unsupported().with_reason(reason));
        }
        let main = &accepted.update.sources[0];
        use honk_config::parser::source_edit::{
            append_node_source, append_subscription_source, remove_node_source,
            remove_subscription_source,
        };
        let content = match &mutation {
            Mutation::CreateNode(input) => {
                if active.nodes.iter().any(|node| node.name == input.name) {
                    return Err(management::conflict());
                }
                append_node_source(main, &input.name, &input.link).map_err(|_| {
                    management::unsupported_value(
                        "The main source cannot hold this node name and share link",
                        json!({"resource":"/nodes","fields":["name","link"]}),
                    )
                })?
            }
            Mutation::CreateProvider(input) => {
                if active
                    .subscriptions
                    .iter()
                    .any(|subscription| subscription.name == input.name)
                {
                    return Err(management::conflict());
                }
                append_subscription_source(main, &input.name, &input.url, &input.options())
                    .map_err(|_| {
                        management::unsupported_value(
                            "The main source cannot hold this provider name, URL or user agent",
                            json!({"resource":"/providers","fields":["name","url","user_agent"]}),
                        )
                    })?
            }
            Mutation::DeleteNode(id) => {
                let node = uuid::Uuid::parse_str(id)
                    .ok()
                    .and_then(|id| active.nodes.iter().find(|node| node.id == id));
                let Some(node) = node else {
                    return Ok(Completion::Deleted(0));
                };
                if node.subscription_id.is_some()
                    || matches!(
                        node.protocol(),
                        honk_config::types::NodeProtocol::Direct
                            | honk_config::types::NodeProtocol::Block
                    )
                {
                    return Err(management::unsupported());
                }
                let identity = catalog.snapshot();
                let groups: Vec<_> = active
                    .groups
                    .iter()
                    .filter(|group| group.final_outbound.as_deref() == Some(node.name.as_str()))
                    .filter_map(|group| identity.groups.get(&group.name))
                    .collect();
                if !groups.is_empty() {
                    return Err(management::referenced(&groups));
                }
                remove_node_source(main, node.id)
                    .map_err(|_| management::unsupported())?
                    .ok_or_else(management::unsupported)?
            }
            Mutation::DeleteProvider(id) => {
                if id == "inline" {
                    return Err(management::unsupported());
                }
                let subscription = uuid::Uuid::parse_str(id).ok().and_then(|id| {
                    active
                        .subscriptions
                        .iter()
                        .find(|subscription| subscription.id == id)
                });
                let Some(subscription) = subscription else {
                    return Ok(Completion::Deleted(0));
                };
                if active.subscriptions.iter().any(|other| {
                    other.id != subscription.id
                        && crate::subscription::same_subscription_fetch_identity(
                            other,
                            subscription,
                        )
                }) {
                    return Err(management::unsupported());
                }
                if !(subscription.url.starts_with("http://")
                    || subscription.url.starts_with("https://"))
                {
                    return Err(management::unsupported());
                }
                remove_subscription_source(main, subscription, &active.assets)
                    .map_err(|_| management::unsupported())?
                    .ok_or_else(management::unsupported)?
            }
        };
        drop(active);
        let (candidate, sources, diagnostics, committed) = self
            .prepare_replace(
                &accepted.ids[&main.path],
                content,
                Precondition::Internal {
                    sha256: accepted.hashes[0].clone(),
                    revision: accepted.revision.clone(),
                },
                match &mutation {
                    Mutation::CreateProvider(input) => Some(input.name.clone()),
                    _ => None,
                },
                self.service.principal(),
            )
            .await?;
        let created = match &mutation {
            Mutation::CreateNode(input) => candidate
                .nodes
                .iter()
                .find(|node| node.name == input.name && node.subscription_id.is_none())
                .map(|node| ("nodes", node.id)),
            Mutation::CreateProvider(input) => candidate
                .subscriptions
                .iter()
                .find(|subscription| subscription.name == input.name)
                .map(|subscription| ("providers", subscription.id)),
            _ => None,
        };
        let deferred = created
            .filter(|(collection, _)| *collection == "providers")
            .map(|(_, id)| id);
        self.begin_record(&committed);
        let completion = self
            .activation
            .activate(ActivationRequest {
                candidate,
                sources: Some(sources),
                diagnostics,
                expected_group_revision: Some(accepted.revision),
                deferred_provider: deferred,
            })
            .await;
        let stored = self
            .record(committed, &completion)
            .await
            .map_err(|mut details| {
                details["stage"] = json!(completion::record_failure(&completion).0);
                unavailable().with_details(details)
            })?;
        completion
            .map_err(|failure| failure.management_error(stored, &self.service.instance_id))?;
        if mutation.deleting() {
            return Ok(Completion::Deleted(1));
        }
        let (collection, id) = created.ok_or_else(|| {
            management::activation_error(
                "resource_unavailable",
                Some(true),
                Some(true),
                Some(true),
                None,
            )
        })?;
        // Capture under the publication barrier before the queue can delete this resource.
        let active = self.active.read().await;
        let value = if collection == "nodes" {
            let secrets = self.service.secrets_with(&active);
            super::super::catalog::node_value(
                &active,
                &catalog.snapshot(),
                &group_manager.read(),
                alive_set,
                id,
                &secrets,
            )
        } else {
            super::super::providers::provider_value(
                &active,
                Some(&self.subscriptions),
                id,
                Some(&self.service),
                |name| super::super::geodata::group_id(catalog, name),
            )
        }
        .ok_or_else(|| {
            management::activation_error(
                "resource_unavailable",
                Some(true),
                Some(true),
                Some(true),
                None,
            )
        })?;
        Ok(Completion::Created {
            collection,
            id,
            value,
        })
    }

    async fn tree_operation(&mut self, id: &str, prepared: Result<Prepared, ApiError>) {
        match prepared {
            Ok((candidate, sources, diagnostics, committed)) => {
                self.replace_operation(
                    id,
                    ActivationRequest {
                        candidate,
                        sources: Some(sources),
                        diagnostics,
                        expected_group_revision: None,
                        deferred_provider: None,
                    },
                    None,
                    committed,
                )
                .await;
            }
            Err(error) => {
                self.service.operations.reject(id, error);
            }
        }
    }

    async fn load(
        &self,
    ) -> Result<(Config, Option<SourceUpdate>, Vec<DetailedDiagnostic>), ApiError> {
        let store = self.store.clone();
        let source_managed = self.source_managed;
        // Diagnostics name the accepted source IDs, as a write to the same file would.
        let accepted = self
            .service
            .sources
            .accepted
            .read()
            .as_ref()
            .map(|accepted| {
                let main = accepted
                    .update
                    .sources
                    .first()
                    .and_then(|main| accepted.ids.get(&main.path))
                    .cloned();
                (accepted.ids.clone(), main)
            });
        tokio::task::spawn_blocking(move || {
            let (ids, main) = accepted
                .as_ref()
                .map_or((None, None), |(ids, main)| (Some(ids), main.as_deref()));
            let reject = |error, diagnostics: &[DetailedDiagnostic], sources: &[SourceSnapshot]| {
                config_error(error, diagnostics, sources, main, ids)
            };
            let mut diagnostics = Vec::new();
            if !source_managed {
                let mut config = crate::load_operator_config(
                    store.entry().to_str().ok_or_else(invalid)?,
                    &mut diagnostics,
                )
                .map_err(|error| reject(error, &diagnostics, &[]))?;
                config.ensure_builtin_nodes();
                return Ok((config, None, diagnostics));
            }
            let loaded = store
                .load(&HashMap::new(), &mut diagnostics)
                .map_err(|error| reject(error, &diagnostics, &[]))?;
            let mut config = crate::admit_operator_config(
                loaded.config,
                loaded.sources[0].source.clone(),
                &mut diagnostics,
            )
            .map_err(|error| reject(error, &diagnostics, &loaded.sources))?;
            config.ensure_builtin_nodes();
            Ok((
                config,
                Some(SourceUpdate {
                    sources: loaded.sources,
                    dependencies: Vec::new(),
                    geo_sources: None,
                }),
                diagnostics,
            ))
        })
        .await
        .map_err(|_| unavailable())?
    }

    async fn prepare_group_patch(
        &self,
        patch: super::super::groups::GroupPatch,
        principal: &str,
    ) -> Result<Option<Prepared>, ApiError> {
        let if_match = patch.expected.clone()?;
        patch.validate_shape()?;
        let accepted = self
            .service
            .sources
            .accepted
            .read()
            .clone()
            .ok_or_else(unavailable)?;
        if !if_match.matches(&accepted.revision) {
            return Err(ApiError::new(
                StatusCode::PRECONDITION_FAILED,
                ErrorCode::StaleRevision,
                "Group configuration revision changed",
                None,
            ));
        }
        if accepted.revision != patch.revision {
            return Err(changed());
        }
        let index = *accepted
            .group_sources
            .get(&patch.name)
            .ok_or_else(not_found)?;
        if let Some(reason) = self.service.source_refusal(&accepted, index) {
            return Err(super::super::groups::read_only().with_reason(reason));
        }
        let changes = patch.changes()?;
        let content = honk_config::parser::source_edit::edit_group_source(
            &accepted.update.sources[index],
            &patch.name,
            &changes,
        )
        .map_err(|_| invalid())?;
        let condition = Precondition::Group {
            if_match,
            sha256: accepted.hashes[index].clone(),
            revision: patch.revision,
        };
        if content == accepted.update.sources[index].content.as_ref() {
            let store = self.store.clone();
            let service = Arc::clone(&self.service);
            tokio::task::spawn_blocking(move || {
                let mut diagnostics = Vec::new();
                let moved = || condition.refused(&store, None, &service);
                let baseline = store
                    .load(&HashMap::new(), &mut diagnostics)
                    .map_err(|_| moved())?;
                if service.sources.revision().as_deref() != condition.revision()
                    || !same_source_documents(&accepted.update.sources, &baseline.sources)
                {
                    return Err(moved());
                }
                Ok(())
            })
            .await
            .map_err(|_| unavailable())??;
            return Ok(None);
        }
        self.prepare_replace(
            &accepted.ids[&accepted.update.sources[index].path],
            content,
            condition,
            None,
            principal,
        )
        .await
        .map(Some)
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_replace(
        &self,
        source_id: &str,
        content: String,
        condition: Precondition,
        new_provider: Option<String>,
        principal: &str,
    ) -> Result<Prepared, ApiError> {
        if content.len() > MAX_SOURCE_BYTES {
            return Err(too_large());
        }
        let accepted = self
            .service
            .sources
            .accepted
            .read()
            .clone()
            .ok_or_else(not_found)?;
        let index = accepted
            .update
            .sources
            .iter()
            .position(|source| accepted.ids[&source.path] == source_id)
            .ok_or_else(not_found)?;
        if let Some(reason) = self.service.source_refusal(&accepted, index) {
            return Err(denied().with_reason(reason));
        }
        let target = accepted.update.sources[index].path.clone();
        let mut check = self.candidate_check().await?;
        let source_id = source_id.to_owned();
        let principal = principal.to_owned();
        #[cfg(test)]
        let before_replace = self.service.before_replace.lock().take();
        let service = Arc::clone(&self.service);
        tokio::task::spawn_blocking(move || {
            let store = check.store.clone();
            let moved = || condition.refused(&store, Some(&target), &service);
            let refused = |error| match error {
                WriteError::Conflict => moved(),
                error => store_write_error(&store, error),
            };
            let pin = store.pin(&target).map_err(refused)?;
            if !condition.holds(&pin.sha256()) {
                return Err(moved());
            }
            if let Some(revision) = condition.revision() {
                if service.sources.revision().as_deref() != Some(revision) {
                    return Err(moved());
                }
                let mut diagnostics = Vec::new();
                let baseline = store
                    .load(&HashMap::new(), &mut diagnostics)
                    .map_err(|_| moved())?;
                if !same_source_documents(&accepted.update.sources, &baseline.sources) {
                    return Err(moved());
                }
            }
            let mut overlay = HashMap::new();
            overlay.insert(target.clone(), Arc::<str>::from(content.as_str()));
            let mut diagnostics = Vec::new();
            let loaded = store.load(&overlay, &mut diagnostics).map_err(|error| {
                config_error(
                    error,
                    &diagnostics,
                    &accepted.update.sources,
                    Some(&source_id),
                    Some(&accepted.ids),
                )
            })?;
            if let Some(name) = &new_provider {
                let provider = loaded
                    .config
                    .subscriptions
                    .iter()
                    .find(|provider| provider.name == *name)
                    .ok_or_else(|| {
                        management::unsupported_value(
                            "The engine did not admit this provider name",
                            json!({"resource":"/providers","field":"name"}),
                        )
                    })?;
                if check.active.subscriptions.iter().any(|other| {
                    crate::subscription::same_subscription_fetch_identity(other, provider)
                }) {
                    return Err(management::unsupported_value(
                        "A provider with the same URL and user agent already exists",
                        json!({"resource":"/providers","fields":["url","user_agent"]}),
                    ));
                }
                check.deferred.push(provider.clone());
            }
            let validated = check.validate(
                loaded,
                &mut diagnostics,
                Some((&accepted, &target, &content)),
                Some(&source_id),
                Some(&accepted.ids),
            )?;
            let recheck = Box::new(|| {
                #[cfg(test)]
                if let Some(hook) = before_replace {
                    hook();
                }
                if condition
                    .revision()
                    .is_some_and(|revision| service.sources.revision().as_deref() != Some(revision))
                {
                    return Err(WriteError::Conflict);
                }
                check.recheck(&overlay, &validated)
            });
            let committed = pin
                .commit(&content, &validated.sources, &principal, recheck)
                .map_err(refused)?;
            Ok(prepared(validated, diagnostics, committed))
        })
        .await
        .map_err(|_| unavailable())?
    }

    async fn prepare_create(
        &self,
        label: String,
        content: String,
        principal: &str,
    ) -> Result<Prepared, ApiError> {
        if content.len() > MAX_SOURCE_BYTES {
            return Err(too_large());
        }
        let accepted = self
            .service
            .sources
            .accepted
            .read()
            .clone()
            .ok_or_else(unsupported)?;
        let check = self.candidate_check().await?;
        let principal = principal.to_owned();
        #[cfg(test)]
        let before_replace = self.service.before_replace.lock().take();
        tokio::task::spawn_blocking(move || {
            let store = &check.store;
            let accepted = &accepted;
            let target = store.resolve(&label)?;
            if accepted.ids.contains_key(&target)
                || (matches!(store, SourceStore::File(_)) && target.symlink_metadata().is_ok())
            {
                return Err(exists());
            }
            let main = accepted.ids[&accepted.update.sources[0].path].as_str();
            // The new source has no accepted ID until it loads; this one names it in diagnostics.
            let mut ids = accepted.ids.clone();
            ids.insert(target.clone(), uuid::Uuid::new_v4().to_string());
            let overlay = HashMap::from([(target.clone(), Arc::<str>::from(content.as_str()))]);
            let mut diagnostics = Vec::new();
            let loaded = store.load(&overlay, &mut diagnostics).map_err(|error| {
                config_error(
                    error,
                    &diagnostics,
                    &accepted.update.sources,
                    Some(main),
                    Some(&ids),
                )
            })?;
            let validated = check.validate(
                loaded,
                &mut diagnostics,
                Some((accepted, &target, &content)),
                Some(main),
                Some(&ids),
            )?;
            if !validated.sources.iter().any(|source| source.path == target) {
                return Err(not_included(main));
            }
            let recheck = Box::new(|| {
                #[cfg(test)]
                if let Some(hook) = before_replace {
                    hook();
                }
                check.recheck(&overlay, &validated)
            });
            let committed = store
                .create(&target, &content, &validated.sources, &principal, recheck)
                .map_err(|error| match error {
                    WriteError::Conflict => changed(),
                    // The parent became a symlink after resolution: still a path outside the root.
                    WriteError::UnsafePath => invalid().with_reason(WriteRefusal::UnsafePath),
                    WriteError::SecretSource => {
                        invalid().with_reason(WriteRefusal::ListenerSecretSource)
                    }
                    WriteError::SecretContent => {
                        invalid().with_reason(WriteRefusal::ListenerSecretInContent)
                    }
                    error => store_write_error(store, error),
                })?;
            Ok(prepared(validated, diagnostics, committed))
        })
        .await
        .map_err(|_| unavailable())?
    }

    async fn candidate_check(&self) -> Result<CandidateCheck, ApiError> {
        let active = self.active.read().await.clone();
        Ok(CandidateCheck {
            store: self.store.clone(),
            secrets: self.service.secrets_with(&active),
            active,
            log_files: self.log_files.clone(),
            data_dir: self.data_dir.clone(),
            deferred: self
                .subscriptions
                .deferred_subscriptions()
                .await
                .map_err(|_| unavailable())?,
        })
    }
}

/// What a candidate validates against, captured before blocking work.
struct CandidateCheck {
    store: SourceStore,
    /// The set the source listing's `writable` uses, so a write it offers is not refused here.
    secrets: ListenerSecrets,
    active: Arc<Config>,
    log_files: LogFiles,
    data_dir: PathBuf,
    deferred: Vec<honk_config::subscription::Subscription>,
}

impl CandidateCheck {
    /// Full validation of a candidate, refusing anything the write or the following reload
    /// must not admit. `write` is a source write of `content` at `target` over `accepted`;
    /// `None` is a whole-tree candidate.
    fn validate(
        &self,
        loaded: LoadedConfig,
        diagnostics: &mut Vec<DetailedDiagnostic>,
        write: Option<(&Accepted, &Path, &str)>,
        fallback: Option<&str>,
        ids: Option<&HashMap<PathBuf, String>>,
    ) -> Result<offline::ValidatedConfig, ApiError> {
        let active = &self.active;
        let parsed_sources = loaded.sources.clone();
        let validated = offline::validate_for_coordinator(
            loaded,
            self.store.dependency_root(),
            active,
            &self.data_dir,
            SourceLimits::DEFAULT,
            diagnostics,
            &self.deferred,
            None,
            &[],
        )
        .map_err(|error| config_error(error, diagnostics, &parsed_sources, fallback, ids))?;
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
        {
            return Err(diagnostics_error(
                diagnostics,
                &validated.sources,
                fallback,
                ids,
            ));
        }
        let mut written = &validated.sources[0];
        let refusal = if let Some((accepted, target, content)) = write {
            let old_credentials: Vec<_> = accepted
                .update
                .sources
                .iter()
                .filter(|source| source.contains_api_secret)
                .map(|source| (&source.path, &source.content))
                .collect();
            let new_credentials: Vec<_> = validated
                .sources
                .iter()
                .filter(|source| source.contains_api_secret)
                .map(|source| (&source.path, &source.content))
                .collect();
            // The target's own declaration implies a changed credential set, so it goes first.
            let refusal = if validated
                .sources
                .iter()
                .any(|source| source.path == target && source.contains_api_secret)
            {
                Some(WriteRefusal::ListenerSecretSource)
            } else if self.secrets.contains(content) {
                Some(WriteRefusal::ListenerSecretInContent)
            } else if old_credentials != new_credentials {
                Some(WriteRefusal::CredentialSourcesChanged)
            } else {
                None
            };
            if let Some(source) = validated
                .sources
                .iter()
                .find(|source| source.path == target)
            {
                written = source;
            }
            refusal
        } else {
            None
        };
        let refusal = refusal.or_else(|| {
            (validated.config.experimental.native_api != active.experimental.native_api
                || validated.config.experimental.clash_api.secret
                    != active.experimental.clash_api.secret
                || (matches!(self.store, SourceStore::Db(_))
                    && validated.config.global.data_dir != active.global.data_dir))
                .then_some(WriteRefusal::ListenerSettingsChanged)
        });
        if let Some(reason) = refusal {
            return Err(denied().with_reason(reason));
        }
        // The reload would reject these, and a rejected reload leaves the written file
        // ahead of the accepted hash; refuse before writing.
        let restart = restart_diagnostics(
            active,
            &validated.config,
            &self.log_files,
            &written.source,
            Severity::Error,
        );
        if !restart.is_empty() {
            diagnostics.extend(restart);
            return Err(diagnostics_error(
                diagnostics,
                &validated.sources,
                fallback,
                ids,
            ));
        }
        Ok(validated)
    }

    fn recheck(
        &self,
        overlay: &HashMap<PathBuf, Arc<str>>,
        validated: &offline::ValidatedConfig,
    ) -> Result<(), WriteError> {
        unchanged(
            &self.store,
            overlay,
            validated,
            &self.active,
            &self.data_dir,
            &self.deferred,
        )
    }
}

/// Fails with `Conflict` unless `store` still yields `validated`: the same documents, loading
/// without errors, over the same dependencies.
fn unchanged(
    store: &SourceStore,
    overlay: &HashMap<PathBuf, Arc<str>>,
    validated: &offline::ValidatedConfig,
    active: &Config,
    data_dir: &Path,
    deferred: &[honk_config::subscription::Subscription],
) -> Result<(), WriteError> {
    let mut notices = Vec::new();
    let loaded = store
        .load(overlay, &mut notices)
        .map_err(|_| WriteError::Conflict)?;
    if notices
        .iter()
        .any(|notice| notice.severity == Severity::Error)
        || !same_source_documents(&validated.sources, &loaded.sources)
    {
        return Err(WriteError::Conflict);
    }
    let dependencies = validated
        .recapture_dependencies(active, data_dir, SourceLimits::DEFAULT, deferred)
        .map_err(|_| WriteError::Conflict)?;
    if validated.dependencies != dependencies {
        return Err(WriteError::Conflict);
    }
    Ok(())
}

fn prepared(
    validated: offline::ValidatedConfig,
    diagnostics: Vec<DetailedDiagnostic>,
    committed: Committed,
) -> Prepared {
    let update = SourceUpdate {
        sources: validated.sources,
        dependencies: validated.dependencies,
        geo_sources: None,
    };
    (validated.config, update, diagnostics, committed)
}

type Prepared = (Config, SourceUpdate, Vec<DetailedDiagnostic>, Committed);

/// What a source replacement is conditional on.
enum Precondition {
    /// The client's `If-Match` over the stored content hash of the source.
    Source(IfMatch),
    /// The client's `If-Match` over the configuration revision, with the accepted content hash
    /// and revision the patch was built from.
    Group {
        if_match: IfMatch,
        sha256: String,
        revision: String,
    },
    /// The accepted content hash and revision a management mutation was built from.
    Internal { sha256: String, revision: String },
}

impl Precondition {
    /// Whether the pinned source still has the content this write expects.
    fn holds(&self, sha256: &str) -> bool {
        match self {
            Self::Source(if_match) => if_match.matches(sha256),
            Self::Group { sha256: pinned, .. } | Self::Internal { sha256: pinned, .. } => {
                pinned == sha256
            }
        }
    }

    fn revision(&self) -> Option<&str> {
        match self {
            Self::Source(_) => None,
            Self::Group { revision, .. } | Self::Internal { revision, .. } => Some(revision),
        }
    }

    /// The refusal once the state this write was validated against moved: the client's
    /// condition is evaluated again against the current state, and a change it still matches
    /// is a conflict rather than a failed precondition.
    fn refused(
        &self,
        store: &SourceStore,
        target: Option<&Path>,
        service: &ConfigService,
    ) -> ApiError {
        let still = match self {
            Self::Source(if_match) => target
                .and_then(|target| store.pin(target).ok())
                .is_some_and(|pin| if_match.matches(&pin.sha256())),
            Self::Group { if_match, .. } => service
                .sources
                .revision()
                .is_some_and(|revision| if_match.matches(&revision)),
            // No client condition: any concurrent change is a conflict.
            Self::Internal { .. } => true,
        };
        if still { changed() } else { stale() }
    }
}

fn store_write_error(store: &SourceStore, error: WriteError) -> ApiError {
    match store {
        SourceStore::Db(_) => db_write_error(error),
        SourceStore::File(_) => write_error(error),
    }
}

fn db_write_error(error: WriteError) -> ApiError {
    match error {
        WriteError::Unavailable => unavailable().with_details(json!({"stage":"store"})),
        error => write_error(error),
    }
}

fn refused_write(reason: WriteRefusal) -> ApiError {
    denied()
        .with_details(json!({"stage":"write"}))
        .with_reason(reason)
}

fn write_error(error: WriteError) -> ApiError {
    match error {
        WriteError::Conflict => stale(),
        WriteError::Exists => exists(),
        WriteError::TooLarge => too_large(),
        WriteError::UnsafePath => refused_write(WriteRefusal::UnsafePath),
        WriteError::SecretSource => refused_write(WriteRefusal::ListenerSecretSource),
        WriteError::SecretContent => refused_write(WriteRefusal::ListenerSecretInContent),
        WriteError::InvalidUtf8 => invalid(),
        WriteError::Unavailable => unavailable().with_details(json!({"stage":"write"})),
        WriteError::ChangedButNotDurable => {
            unavailable().with_details(json!({"stage":"durability","written":true,"durability_confirmed":false,"committed":false})).without_retry_after()
        }
    }
}
