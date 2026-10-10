use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::diagnostic::SourceRef;
use crate::types::SubscriptionType;

/// A proxy subscription (e.g., subscription link).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    #[serde(default = "uuid::Uuid::new_v4")]
    pub id: uuid::Uuid,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub sub_type: SubscriptionType,
    /// Update interval in seconds (0 = manual)
    #[serde(default = "default_update_interval")]
    pub update_interval: u64,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub headers: Vec<SubscriptionHeader>,
    #[serde(default = "crate::types::default_true")]
    pub enabled: bool,
    /// Keep the fetched body for offline startup; only with `global.store_subscribe`.
    #[serde(default = "crate::types::default_true")]
    pub cache: bool,
    /// How the fetch leaves: empty or `routing` follows the routing rules,
    /// `direct` goes straight to the host, anything else names a group.
    #[serde(default)]
    pub download_detour: String,
    /// Last update time
    #[serde(default)]
    pub last_updated: Option<DateTime<Utc>>,
    /// Number of nodes from this subscription
    #[serde(default)]
    pub node_count: u32,
    /// Created at
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    /// The dae file that declared this subscription; `None` when it was not
    /// parsed from one.
    #[serde(skip)]
    pub source: Option<DeclaringSource>,
}

/// Reparsing an unchanged document yields a fresh source table, so equality
/// compares only the table index and an identical reload stays unchanged.
#[derive(Debug, Clone)]
pub struct DeclaringSource(pub SourceRef);

impl PartialEq for DeclaringSource {
    fn eq(&self, other: &Self) -> bool {
        self.0.index() == other.0.index()
    }
}
impl Eq for DeclaringSource {}

fn default_update_interval() -> u64 {
    86400 // 24 hours
}

impl Default for Subscription {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            name: String::new(),
            url: String::new(),
            sub_type: SubscriptionType::default(),
            update_interval: default_update_interval(),
            user_agent: None,
            headers: Vec::new(),
            enabled: true,
            cache: true,
            download_detour: String::new(),
            last_updated: None,
            node_count: 0,
            created_at: Utc::now(),
            source: None,
        }
    }
}

/// Custom HTTP header for subscription fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionHeader {
    pub key: String,
    pub value: String,
}
