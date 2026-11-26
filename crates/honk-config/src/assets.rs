//! The `assets {}` block: defaults for everything honk downloads.
//!
//! The geodata and UI links and routes are kept in the fields their old
//! `experimental` keys filled, so consumers read one place whichever spelling
//! the file used. The parser resolves the precedence once, when the file is
//! read: an entry or sub-block value, then `assets`, then the built-in default.
//! The geodata schedule and checksum keys have no `experimental` spelling and
//! stay in [`GeodataDefaults`].

use serde::{Deserialize, Serialize};

use crate::cron::Cron;
use crate::subscription::Subscription;

/// Settings of the `assets {}` block that apply to more than one download.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AssetsConfig {
    /// `assets.route`: `routing`, `direct` or a group name; empty follows the
    /// routing rules.
    pub route: String,
    /// `assets.geodata`: the automatic update and checksum settings the
    /// native API stores at startup.
    pub geodata: GeodataDefaults,
    /// `assets.subscription`: defaults for every subscription entry.
    pub subscription: SubscriptionDefaults,
}

/// `assets.geodata { auto_update cron checksum }`; `None` when the file does
/// not name the key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeodataDefaults {
    pub auto_update: Option<bool>,
    /// Evaluated in the system's local time zone.
    pub cron: Option<Cron>,
    pub checksum: Option<bool>,
}

/// `assets.subscription { … }`; `None` keeps the built-in default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SubscriptionDefaults {
    pub ua: Option<String>,
    /// Seconds; `0` turns scheduled refresh off.
    pub interval: Option<u64>,
    pub cache: Option<bool>,
}

impl AssetsConfig {
    /// The subscription an entry starts from before its own options apply.
    pub fn subscription_base(&self) -> Subscription {
        let defaults = Subscription::default();
        Subscription {
            user_agent: self.subscription.ua.clone(),
            update_interval: self
                .subscription
                .interval
                .unwrap_or(defaults.update_interval),
            cache: self.subscription.cache.unwrap_or(defaults.cache),
            download_detour: self.route.clone(),
            ..defaults
        }
    }
}
