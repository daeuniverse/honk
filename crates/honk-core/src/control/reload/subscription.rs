use super::*;
use crate::config_diagnostics::DiagnosticUpdate;

/// Build the config produced by merging one subscription's freshly fetched
/// nodes. A non-empty result replaces the previous node set for
/// `subscription_id`; an empty result leaves the current config untouched.
/// Explicit membership follows matching provider chains before stale IDs are
/// pruned and filters are recomputed. Other providers and static nodes retain
/// their declarations. Re-merging the same subscription is idempotent.
pub(in crate::control) fn config_with_subscription_nodes(
    current: &Config,
    subscription_id: uuid::Uuid,
    mut nodes: Vec<Node>,
) -> Result<Config, honk_config::error::DetailedConfigError> {
    if nodes.is_empty() {
        return Ok(current.clone());
    }
    let has_incoming_chain = nodes.iter().any(|node| node.chain_hops().is_some());
    if has_incoming_chain {
        // Current declarations have unique bound IDs. An exact duplicate in
        // the new provider body will also fail the assembled ID check.
        let prior_chains: std::collections::HashMap<_, _> = current
            .nodes
            .iter()
            .filter(|node| node.subscription_id == Some(subscription_id))
            .filter_map(|node| Some(((node.name.as_str(), node.chain_hops()?), node.id)))
            .collect();
        for node in &mut nodes {
            if let Some(hops) = node.chain_hops() {
                // Only the admitted provider snapshot can supply membership aliases.
                node.id = prior_chains
                    .get(&(node.name.as_str(), hops))
                    .copied()
                    .unwrap_or_default();
            }
        }
    }
    let mut config = current.clone();
    let mut preserve_membership =
        has_incoming_chain || config.groups.iter().any(|group| group.exit.is_some());
    config.nodes.retain(|node| {
        // Removing the last chain still has explicit chain memberships to prune.
        preserve_membership = preserve_membership || node.chain_hops().is_some();
        node.subscription_id != Some(subscription_id)
    });
    config.nodes.extend(nodes);
    config.assemble(|groups, nodes, subscriptions| {
        let live: std::collections::HashSet<_> = nodes.iter().map(|node| node.id).collect();
        for group in &mut *groups {
            group.nodes.retain(|id| live.contains(id));
        }
        if preserve_membership {
            honk_config::parser::resolve_programmatic_groups(groups, nodes, subscriptions);
        } else {
            honk_config::parser::resolve_group_filters(groups, nodes, subscriptions);
        }
    })
}
fn subscription_provenance_error(index: usize) -> honk_config::error::DetailedConfigError {
    let ordinal = index + 1;
    let source = honk_config::diagnostic::DiagnosticSources::new(None).root();
    let mut error = honk_config::error::DetailedConfigError::new(
        honk_config::error::ErrorCategory::Validation,
        "invalid-subscription-provenance",
        source,
        honk_config::diagnostic::SettingPath::new("nodes").index(ordinal),
        "subscription node provenance does not match the authorized provider",
    );
    error.diagnostic.value = honk_config::diagnostic::SafeValue::Ordinal(ordinal);
    error.diagnostic.entry_index = Some(ordinal);
    error
}

impl ControlPlane {
    async fn merge_subscription_nodes_locked(
        &self,
        subscription_id: uuid::Uuid,
        mut nodes: Vec<Node>,
        mut diagnostics: Vec<honk_config::diagnostic::DetailedDiagnostic>,
        drain: &DrainTracker,
    ) -> Result<ReloadOutcome, honk_config::error::DetailedConfigError> {
        honk_config::node::validate_partial_node_collection(&nodes)?;
        if let Some(index) = nodes.iter().position(|node| {
            node.subscription_id
                .is_some_and(|provider| provider != subscription_id)
        }) {
            return Err(subscription_provenance_error(index));
        }
        for node in &mut nodes {
            if node.subscription_id.is_none() {
                node.subscription_id = Some(subscription_id);
            }
        }
        let config_guard = self.config.read().await;
        let current = Arc::clone(&config_guard);
        crate::subscription::drop_nodes_published_elsewhere(
            &current.nodes,
            &current.subscriptions,
            subscription_id,
            &mut nodes,
        );
        if nodes.is_empty() {
            return Ok(ReloadOutcome::Noop {
                generation: self
                    .dns_controller
                    .runtime_provider()
                    .current_generation()
                    .get(),
            });
        }
        let incoming_len = nodes.len();
        let mut new_config = config_with_subscription_nodes(&current, subscription_id, nodes)?;
        if let Some(subscription) = current
            .subscriptions
            .iter()
            .find(|subscription| subscription.id == subscription_id)
        {
            crate::config_diagnostics::declare_provider_diagnostics(subscription, &mut diagnostics);
        }
        let diagnostic_update = DiagnosticUpdate::ReplaceProvider {
            id: subscription_id,
            diagnostics,
        };
        let candidate_start = new_config.nodes.len() - incoming_len;
        if subscription_nodes_unchanged(
            &current,
            subscription_id,
            &mut new_config.nodes[candidate_start..],
        ) {
            drop(config_guard);
            let _config = self.config.write().await;
            self.diagnostics.write().buckets.apply(diagnostic_update);
            debug!(
                subscription_id = %subscription_id,
                "subscription unchanged; skipping runtime rebuild"
            );
            return Ok(ReloadOutcome::Noop {
                generation: self.diagnostics.read().generation,
            });
        }
        drop(config_guard);
        crate::dns::ecs::resolve_client_subnet(&mut new_config.dns).await;
        self.apply_resolved_runtime_config_locked(
            new_config,
            drain,
            diagnostic_update,
            None,
            #[cfg(feature = "native-api")]
            None,
        )
        .await
    }

    pub(in crate::control) async fn merge_authorized_subscription_nodes_with_drain(
        &self,
        subscription_id: uuid::Uuid,
        revision: u64,
        authorizations: &crate::subscription::SubscriptionAuthorizations,
        nodes: Vec<Node>,
        diagnostics: Vec<honk_config::diagnostic::DetailedDiagnostic>,
        drain: &DrainTracker,
    ) -> Result<ReloadOutcome, honk_config::error::DetailedConfigError> {
        let _reload = self.reload_lock.lock().await;
        if !authorizations.authorizes(subscription_id, revision) {
            debug!(
                %subscription_id,
                revision,
                "discarding stale subscription refresh"
            );
            return Ok(ReloadOutcome::Rejected);
        }
        self.merge_subscription_nodes_locked(subscription_id, nodes, diagnostics, drain)
            .await
    }

    /// Publish a programmatic provider candidate and its diagnostics.
    /// An empty node set leaves active nodes and diagnostics untouched.
    pub async fn merge_subscription_nodes(
        &self,
        subscription_id: uuid::Uuid,
        nodes: Vec<Node>,
        diagnostics: Vec<honk_config::diagnostic::DetailedDiagnostic>,
    ) {
        let drain = Arc::clone(&self.drain_tracker);
        let _reload = self.reload_lock.lock().await;
        if let Err(error) = self
            .merge_subscription_nodes_locked(subscription_id, nodes, diagnostics, &drain)
            .await
        {
            crate::report_runtime_admission_error(&error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subscription_node(subscription_id: uuid::Uuid) -> Node {
        let mut node = Node {
            name: "node".into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(
                honk_config::types::NodeProtocol::Socks5,
            ),
            address: "127.0.0.1:1080".into(),
            subscription_id: Some(subscription_id),
            ..Default::default()
        };
        node.id = node.derive_id();
        node
    }

    #[test]
    fn effective_subscription_state_ignores_parse_timestamps_only() {
        let subscription_id = uuid::Uuid::new_v4();
        let node = subscription_node(subscription_id);
        let mut current = Config::default();
        current.nodes.push(node.clone());

        let mut reparsed = node.clone();
        reparsed.created_at += chrono::Duration::seconds(1);
        reparsed.updated_at += chrono::Duration::seconds(1);
        assert!(subscription_nodes_unchanged(
            &current,
            subscription_id,
            &mut [reparsed.clone()]
        ));

        reparsed.address = "127.0.0.1:1081".into();
        assert!(!subscription_nodes_unchanged(
            &current,
            subscription_id,
            &mut [reparsed]
        ));
    }

    #[test]
    fn effective_subscription_state_detects_membership_and_order_changes() {
        let subscription_id = uuid::Uuid::new_v4();
        let first = subscription_node(subscription_id);
        let mut second = subscription_node(subscription_id);
        second.name = "second".into();
        second.address = "127.0.0.1:1081".into();
        second.id = second.derive_id();
        let mut current = Config::default();
        current.nodes.extend([first.clone(), second.clone()]);

        assert!(subscription_nodes_unchanged(
            &current,
            subscription_id,
            &mut [first.clone(), second.clone()]
        ));
        assert!(!subscription_nodes_unchanged(
            &current,
            subscription_id,
            &mut [second.clone(), first.clone()]
        ));
        assert!(!subscription_nodes_unchanged(
            &current,
            subscription_id,
            &mut [first]
        ));
    }
}
