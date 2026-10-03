use std::sync::Arc;

use futures::future::BoxFuture;
use honk_config::Config;
use serde_json::json;

use super::{catalog::NodePages, events::EventHub};
use crate::control::ControlPlane;
use crate::observe::{Observation, Owner, catalog::Catalog, flows::FlowStore};

pub(crate) struct NativeObservation {
    pub(crate) core: Arc<Observation>,
    pub(crate) events: Arc<EventHub>,
    pub(crate) node_pages: NodePages,
    pub(crate) telemetry: super::telemetry::Telemetry,
    pub(crate) configuration: Arc<super::config::ConfigService>,
    pub(crate) operations: Arc<super::operations::OperationStore>,
    pub(crate) dns: Arc<super::dns::DnsApi>,
    pub(crate) probes: Arc<super::probes::ProbeService>,
    pub(crate) logs: Arc<super::logs::LogStore>,
    pub(crate) trace_rate: super::security::RequestRate,
    pub(crate) settings: super::settings::Settings,
    pub(crate) providers: super::providers::ProviderApi,
    pub(crate) degradations: Arc<crate::degradations::Degradations>,
}

impl NativeObservation {
    #[cfg(test)]
    pub(crate) fn new(config: &Config) -> Self {
        Self::with_degradations(config, Arc::default())
    }

    /// Builds the observation for `control` and wires the engine to record into it.
    pub(crate) async fn attach(control: &mut ControlPlane) -> Arc<Self> {
        let config = Arc::clone(&*control.config_handle().read().await);
        let native = Arc::new(Self::with_degradations(
            &config,
            control.degradations_handle(),
        ));
        control
            .attach_observation(
                Arc::clone(&native.core),
                Arc::clone(&native) as Arc<dyn Owner>,
            )
            .await;
        native
    }

    /// `degradations` may already hold startup entries; every later change
    /// publishes `runtime.updated`.
    pub(crate) fn with_degradations(
        config: &Config,
        degradations: Arc<crate::degradations::Degradations>,
    ) -> Self {
        let instance_id = uuid::Uuid::new_v4().to_string();
        let events = Arc::new(EventHub::new(instance_id.clone()));
        let flows = Arc::new(FlowStore::new(
            instance_id.clone(),
            Arc::clone(&events) as Arc<dyn crate::observe::Events>,
        ));
        flows.set_recording(config.experimental.native_api.record_flows);
        let operations = Arc::new(super::operations::OperationStore::new(
            instance_id.clone(),
            Arc::clone(&events),
        ));
        let configuration = Arc::new(super::config::ConfigService::new(
            config.experimental.native_api.clone(),
            config.experimental.clash_api.secret.clone(),
            instance_id.clone(),
            Arc::clone(&operations),
        ));
        let dns = Arc::new(super::dns::DnsApi::new(
            instance_id.clone(),
            config.experimental.native_api.record_dns_log,
            Arc::downgrade(&flows),
        ));
        let probes = Arc::new(super::probes::ProbeService::new(Arc::clone(&operations)));
        let level = super::settings::Level::configured(&config.global.log_level);
        let logs = Arc::new(super::logs::LogStore::new(
            instance_id.clone(),
            config.experimental.native_api.record_logs,
            level.as_str(),
        ));
        let hub = Arc::downgrade(&events);
        degradations.set_notify(Box::new(move || {
            if let Some(hub) = hub.upgrade() {
                hub.publish("runtime.updated", json!({}), None);
            }
        }));
        let core = Arc::new(Observation::new(
            instance_id,
            flows,
            Arc::new(Catalog::new(config)),
            Arc::clone(&dns.recorder),
            Arc::clone(&events) as Arc<dyn crate::observe::Events>,
            Arc::clone(&configuration.sources),
        ));
        let owner = Self {
            core,
            events,
            node_pages: NodePages::default(),
            telemetry: super::telemetry::Telemetry::new(
                config.experimental.native_api.record_traffic,
                config.experimental.native_api.record_memory,
            ),
            configuration,
            operations,
            dns,
            probes,
            logs,
            trace_rate: super::security::RequestRate::new(),
            settings: super::settings::Settings::new(config),
            providers: super::providers::ProviderApi::new(),
            degradations,
        };
        owner.settings.activate(&owner, config);
        owner
    }

    /// Fixtures that read flows directly stand in for an attached client,
    /// pinned so virtual time cannot expire the attachment grace.
    #[cfg(test)]
    pub(crate) fn attach_for_test(&self) {
        self.settings.pin_for_test(self);
        self.settings.renew(self, super::settings::Demand::FLOWS);
    }
}

impl Owner for NativeObservation {
    fn activate(&self, config: &Config) {
        self.settings.activate(self, config);
        self.configuration.warn_secret_collisions();
    }

    fn pause_probes(&self) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async {
            match self.probes.pause().await {
                Ok(()) | Err(super::probes::ProbeLifecycleError::Unavailable) => Ok(()),
                Err(error) => Err(error.into()),
            }
        })
    }
}
