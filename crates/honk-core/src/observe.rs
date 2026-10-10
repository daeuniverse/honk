//! Engine-side observation contract: identities and evidence the data path
//! records, independent of the native HTTP surface that serves them.

pub(crate) mod catalog;
mod dns;
pub(crate) mod flows;
pub(crate) mod rules;
pub(crate) mod vocab;

pub(crate) use dns::{DnsLog, DnsObserver, DnsOperation, DnsRecorder};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use futures::future::BoxFuture;
use honk_config::Config;
use serde_json::{Value, json};

use catalog::{Catalog, CatalogIdentity};
use flows::FlowStore;

/// Largest integer a JSON reader can hold exactly (2^53 - 1).
pub(crate) const MAX_SAFE_UINT: u64 = 9_007_199_254_740_991;

/// Where recorded evidence announces itself to readers.
pub(crate) trait Events: Send + Sync {
    fn publish(&self, kind: &'static str, data: Value, flow_id: Option<&str>);
    fn flow_updated(&self, flow_id: &str, revision: u64);
}

/// The observation surface that owns the recorders' runtime settings.
pub(crate) trait Owner: Send + Sync {
    /// Applies `config`'s recorder settings after a reload that replaced the accepted sources.
    fn activate(&self, config: &Config);
    /// Pauses background probes; an absent or stopped probe worker is success.
    fn pause_probes(&self) -> BoxFuture<'_, anyhow::Result<()>>;
}

/// What the engine records into and the generation bookkeeping readers see.
pub(crate) struct Observation {
    pub(crate) instance_id: String,
    pub(crate) flows: Arc<FlowStore>,
    pub(crate) catalog: Arc<Catalog>,
    pub(crate) dns: Arc<DnsRecorder>,
    pub(crate) events: Arc<dyn Events>,
    pub(crate) sources: Arc<crate::configuration::AcceptedSources>,
    reloading: AtomicBool,
    activated: parking_lot::Mutex<Option<(u64, SystemTime)>>,
}

/// Marks a configuration activation in progress until dropped.
pub(crate) struct ReloadGuard<'a>(&'a AtomicBool);

impl Drop for ReloadGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Observation {
    pub(crate) fn new(
        instance_id: String,
        flows: Arc<FlowStore>,
        catalog: Arc<Catalog>,
        dns: Arc<DnsRecorder>,
        events: Arc<dyn Events>,
        sources: Arc<crate::configuration::AcceptedSources>,
    ) -> Self {
        Self {
            instance_id,
            flows,
            catalog,
            dns,
            events,
            sources,
            reloading: AtomicBool::new(false),
            activated: parking_lot::Mutex::new(None),
        }
    }

    pub(crate) fn begin_reload(&self) -> ReloadGuard<'_> {
        self.reloading.store(true, Ordering::Release);
        ReloadGuard(&self.reloading)
    }

    pub(crate) fn reloading(&self) -> bool {
        self.reloading.load(Ordering::Acquire)
    }

    /// The startup generation has no commit; it becomes active when the engine first runs.
    pub(crate) fn started(&self, generation: u64) {
        self.activated
            .lock()
            .get_or_insert((generation, SystemTime::now()));
    }

    pub(crate) fn activated_at(&self, generation: u64) -> Option<SystemTime> {
        self.activated
            .lock()
            .filter(|(activated, _)| *activated == generation)
            .map(|(_, at)| at)
    }

    pub(crate) fn committed(&self, identity: Arc<CatalogIdentity>, previous: u64, generation: u64) {
        self.catalog.install_prepared(Arc::clone(&identity));
        self.sources
            .generation_committed(&identity.revision, generation);
        if previous != generation {
            *self.activated.lock() = Some((generation, SystemTime::now()));
            self.events.publish(
                "generation.changed",
                json!({
                    "previous_generation_id": format!("{}:{previous}", self.instance_id),
                    "generation_id": format!("{}:{generation}", self.instance_id),
                }),
                None,
            );
        }
        self.events.publish("runtime.updated", json!({}), None);
    }
}

pub(crate) fn timestamp(time: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(time).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Pins `$future` in place for a scope hook, which borrows it so the hook's
/// own state stays small. Inert hooks take the future by value, so their twin
/// of this macro leaves it unpinned and adds nothing to the caller's state.
macro_rules! scope_pin {
    ($future:ident) => {
        let $future = std::pin::pin!($future);
    };
}
pub(crate) use scope_pin;
