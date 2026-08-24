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
    /// shared rebuild pipeline.
    ///
    /// Production callers go through `ControlCommand::MergeSubscription` on
    /// the command channel (which keeps merges serialized against SIGHUP
    /// reloads); this public wrapper exists so integration tests can drive a
    /// merge without binding the TPROXY accept loop.
    pub async fn merge_subscription_nodes(&self, subscription_id: uuid::Uuid, nodes: Vec<Node>) {
        if nodes.is_empty() {
            return;
        }
        let new_config = {
            let current = self.config.read().await;
            config_with_subscription_nodes(&current, subscription_id, nodes)
        };
        self.reload_runtime_config(new_config).await;
    }
}
