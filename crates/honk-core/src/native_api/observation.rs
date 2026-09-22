use std::sync::Arc;

use honk_config::Config;
use serde_json::json;

use super::{catalog::Catalog, events::EventHub, flows::FlowStore};

pub(crate) struct NativeObservation {
    pub(crate) instance_id: String,
    pub(crate) events: Arc<EventHub>,
    pub(crate) flows: Arc<FlowStore>,
    pub(crate) catalog: Arc<Catalog>,
    pub(crate) telemetry: super::telemetry::Telemetry,
    pub(crate) configuration: Arc<super::config::ConfigService>,
    pub(crate) operations: Arc<super::operations::OperationStore>,
    pub(crate) dns: Arc<super::dns::DnsApi>,
    pub(crate) probes: Arc<super::probes::ProbeService>,
    pub(crate) logs: Arc<super::logs::LogStore>,
    pub(crate) trace: super::routing::TraceState,
    pub(crate) settings: super::settings::Settings,
    pub(crate) providers: super::providers::ProviderApi,
}

impl NativeObservation {
    pub(crate) fn new(config: &Config) -> Self {
        let instance_id = uuid::Uuid::new_v4().to_string();
        let events = Arc::new(EventHub::new(instance_id.clone()));
        let flows = Arc::new(FlowStore::new(instance_id.clone(), Arc::clone(&events)));
        flows.set_recording(config.experimental.native_api.record_flows);
        let operations = Arc::new(super::operations::OperationStore::new(
            instance_id.clone(),
            Arc::clone(&events),
        ));
        let configuration = Arc::new(super::config::ConfigService::new(
            config.experimental.native_api.clone(),
            instance_id.clone(),
            Arc::clone(&operations),
        ));
        let dns = Arc::new(super::dns::DnsApi::new(
            instance_id.clone(),
            config.experimental.native_api.record_dns_log,
            Arc::downgrade(&flows),
        ));
        let probes = Arc::new(super::probes::ProbeService::new(
            &config.experimental.native_api,
            Arc::clone(&operations),
        ));
        let level = super::settings::Level::configured(&config.global.log_level);
        let logs = Arc::new(super::logs::LogStore::new(
            instance_id.clone(),
            config.experimental.native_api.record_logs,
            level.as_str(),
        ));
        let owner = Self {
            instance_id,
            events,
            flows,
            catalog: Arc::new(Catalog::new(config)),
            telemetry: super::telemetry::Telemetry::new(
                config.experimental.native_api.record_traffic,
                config.experimental.native_api.record_memory,
            ),
            configuration,
            operations,
            dns,
            probes,
            logs,
            trace: super::routing::TraceState::new(),
            settings: super::settings::Settings::new(config),
            providers: super::providers::ProviderApi::new(),
        };
        owner.settings.activate(&owner, config);
        owner
    }

    /// Fixtures that read flows directly stand in for an attached client,
    /// pinned so virtual time cannot expire the attachment grace.
    #[cfg(test)]
    pub(crate) fn attach_for_test(&self) {
        self.settings.pin_for_test(self);
        self.settings.renew(self, true);
    }

    pub(crate) fn committed(
        &self,
        identity: Arc<super::catalog::CatalogIdentity>,
        previous: u64,
        generation: u64,
    ) {
        self.catalog.install_prepared(Arc::clone(&identity));
        self.configuration
            .sources
            .generation_committed(&identity.revision, generation);
        if previous != generation {
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
