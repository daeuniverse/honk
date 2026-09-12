use super::*;
use crate::config_diagnostics::DiagnosticUpdate;

/// Build the config produced by merging one subscription's freshly fetched
/// nodes. A non-empty result replaces the previous node set for
/// `subscription_id`; an empty result leaves the current config untouched.
/// Group memberships derived from replaced nodes are pruned and filter-based
/// membership is re-resolved against the merged node set. Nodes from other
/// subscriptions and static config nodes are untouched. Re-merging the same
/// subscription is idempotent — nodes are replaced, never duplicated.
pub(in crate::control) fn config_with_subscription_nodes(
    current: &Config,
    subscription_id: uuid::Uuid,
    nodes: Vec<Node>,
) -> Config {
    if nodes.is_empty() {
        return current.clone();
    }
    let mut config = current.clone();
    config
        .nodes
        .retain(|n| n.subscription_id != Some(subscription_id));
    config.nodes.extend(nodes);
    // Stable node IDs may survive a rename or move between subscriptions, so
    // prune dead members and rebuild filter-derived membership from provenance.
    let live: std::collections::HashSet<uuid::Uuid> = config.nodes.iter().map(|n| n.id).collect();
    for group in &mut config.groups {
        group.nodes.retain(|id| live.contains(id));
    }
    honk_config::parser::resolve_group_filters(
        &mut config.groups,
        &config.nodes,
        &config.subscriptions,
    );
    config
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
        diagnostics: Vec<honk_config::diagnostic::DetailedDiagnostic>,
        drain: &DrainTracker,
    ) -> Result<bool, honk_config::error::DetailedConfigError> {
        if nodes.is_empty() {
            return Ok(true);
        }
        honk_config::node::validate_node_collection(&nodes)?;
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
        let incoming_len = nodes.len();
        let mut new_config = config_with_subscription_nodes(&current, subscription_id, nodes);
        new_config.validate_assembled()?;
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
            info!(
                subscription_id = %subscription_id,
                "subscription unchanged; skipping runtime rebuild"
            );
            return Ok(true);
        }
        drop(config_guard);
        crate::dns::ecs::resolve_client_subnet(&mut new_config.dns).await;
        self.apply_resolved_runtime_config_locked(new_config, drain, diagnostic_update, None)
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
    ) -> Result<bool, honk_config::error::DetailedConfigError> {
        let _reload = self.reload_lock.lock().await;
        if !authorizations.authorizes(subscription_id, revision) {
            warn!(
                %subscription_id,
                revision,
                "discarding stale subscription refresh"
            );
            return Ok(false);
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
