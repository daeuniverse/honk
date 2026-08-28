use super::*;

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

impl ControlPlane {
    /// Merge freshly fetched subscription nodes into the running config,
    /// replacing the previous node set of `subscription_id`, and run the
    /// shared rebuild pipeline. The snapshot, no-op check, and build all stay
    /// under the reload lock so a concurrent reload cannot be overwritten.
    pub(in crate::control) async fn merge_subscription_nodes_with_drain(
        &self,
        subscription_id: uuid::Uuid,
        mut nodes: Vec<Node>,
        drain: &DrainTracker,
    ) -> bool {
        if nodes.is_empty() {
            return true;
        }
        let _reload = self.reload_lock.lock().await;
        let current = self.config.read().await.clone();
        if subscription_nodes_unchanged(&current, subscription_id, &mut nodes) {
            info!(
                subscription_id = %subscription_id,
                "subscription unchanged; skipping runtime rebuild"
            );
            return true;
        }
        let new_config = config_with_subscription_nodes(&current, subscription_id, nodes);
        self.apply_runtime_config_locked(new_config, drain).await
    }

    /// Public test/control wrapper for a subscription merge.
    pub async fn merge_subscription_nodes(&self, subscription_id: uuid::Uuid, nodes: Vec<Node>) {
        let drain = Arc::clone(&self.drain_tracker);
        let _ = self
            .merge_subscription_nodes_with_drain(subscription_id, nodes, &drain)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subscription_node(subscription_id: uuid::Uuid) -> Node {
        let mut node = Node {
            name: "node".into(),
            protocol: honk_config::types::NodeProtocol::Socks5,
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
