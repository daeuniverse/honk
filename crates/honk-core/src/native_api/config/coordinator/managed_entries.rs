use super::*;
use crate::native_api::management::{Completion, Mutation};

impl Worker {
    pub(super) async fn manage(
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
                append_node_source(main, &input.name, &input.link).map_err(|error| {
                    management::unsupported_value(
                        error
                            .reason
                            .unwrap_or("The main source cannot hold this node name and share link"),
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
                    .map_err(|error| {
                        management::unsupported_value(
                            error.reason.unwrap_or(
                                "The main source cannot hold this provider name, URL or user agent",
                            ),
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
                            | honk_config::types::NodeProtocol::Chain
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
            super::super::super::catalog::node_value(
                &active,
                &catalog.snapshot(),
                &group_manager.read(),
                alive_set,
                id,
                &secrets,
            )
        } else {
            super::super::super::providers::provider_value(
                &active,
                Some(&self.subscriptions),
                id,
                Some(&self.service),
                |name| super::super::super::geodata::group_id(catalog, name),
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
}
