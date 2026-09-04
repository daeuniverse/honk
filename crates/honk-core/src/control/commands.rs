use honk_config::{Config, node::Node, subscription::Subscription};

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ControlCommand {
    ReloadConfig {
        request_id: u64,
        config: Box<Config>,
        result: tokio::sync::oneshot::Sender<Option<Vec<Subscription>>>,
    },
    /// Merge freshly fetched subscription nodes into the running config,
    /// replacing the previous node set of that subscription. Used by
    /// late startup fetches and periodic refreshes; subscription nodes
    /// live in memory only and are never written back to the config file.
    MergeSubscription {
        subscription_id: uuid::Uuid,
        revision: u64,
        name: String,
        nodes: Vec<Node>,
    },
    /// Refresh generated gateway-address rules and bypass stale health
    /// backoff after a link, address, route, or interface-role change.
    NetworkChanged,
    Shutdown,
}
