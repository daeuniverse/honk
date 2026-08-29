use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
    /// Last update time
    #[serde(default)]
    pub last_updated: Option<DateTime<Utc>>,
    /// Number of nodes from this subscription
    #[serde(default)]
    pub node_count: u32,
    /// Created at
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
}

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
            last_updated: None,
            node_count: 0,
            created_at: Utc::now(),
        }
    }
}

/// Custom HTTP header for subscription fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionHeader {
    pub key: String,
    pub value: String,
}
