//! Where DNS evidence lands: flow steps and the client query log.

use std::{
    net::SocketAddr,
    sync::{Arc, Weak},
    time::Duration,
};

use super::flows::{FlowStore, record::StepData};
use crate::dns::{outcome::DnsOutcome, query::IngressProfile};

pub(crate) trait DnsLog: Send + Sync {
    fn recording(&self) -> bool;
    #[allow(clippy::too_many_arguments)]
    fn capture(
        &self,
        query: &[u8],
        ingress: IngressProfile,
        source: Option<SocketAddr>,
        outcome: Option<&DnsOutcome>,
        response: &[u8],
        elapsed: Duration,
    );
}

pub(crate) struct DnsRecorder {
    instance: String,
    flows: Weak<FlowStore>,
    log: Arc<dyn DnsLog>,
}

impl DnsRecorder {
    pub(crate) fn new(instance: String, flows: Weak<FlowStore>, log: Arc<dyn DnsLog>) -> Self {
        Self {
            instance,
            flows,
            log,
        }
    }

    pub(crate) fn instance(&self) -> &str {
        &self.instance
    }

    pub(crate) fn record_flow(
        &self,
        context: honk_outbound::runtime::flow_observation::FlowContext,
        data: StepData,
    ) -> bool {
        self.flows.upgrade().is_some_and(|flows| {
            flows.record_step(&context.flow_id.to_string(), Some(context.generation), data)
        })
    }

    pub(crate) fn recording(&self) -> bool {
        self.log.recording()
    }
}

/// The recorder a DNS service reports to, attached after the service is built.
#[derive(Clone, Default)]
pub(crate) struct DnsObserver(Arc<parking_lot::RwLock<Weak<DnsRecorder>>>);

impl DnsObserver {
    pub(crate) fn attach(&self, recorder: Weak<DnsRecorder>) {
        *self.0.write() = recorder;
    }

    pub(crate) fn recording(&self) -> bool {
        self.0
            .read()
            .upgrade()
            .is_some_and(|recorder| recorder.recording())
    }

    pub(crate) fn observe_client(
        &self,
        query: &[u8],
        ingress: IngressProfile,
        source: Option<SocketAddr>,
        outcome: Option<&DnsOutcome>,
        response: &[u8],
        elapsed: Duration,
    ) {
        let recorder = self.0.read().upgrade();
        if let Some(recorder) = recorder {
            recorder
                .log
                .capture(query, ingress, source, outcome, response, elapsed);
        }
    }

    /// Captures the recorder for one operation, only inside an observed flow.
    pub(crate) fn operation(&self) -> DnsOperation {
        DnsOperation(
            if honk_outbound::runtime::flow_observation::current().is_some() {
                self.0.read().clone()
            } else {
                Weak::new()
            },
        )
    }
}

pub(crate) struct DnsOperation(Weak<DnsRecorder>);

impl DnsOperation {
    pub(crate) fn scope<F: Future>(&self, operation: F) -> impl Future<Output = F::Output> {
        super::flows::dns::scope_api(self.0.clone(), operation)
    }
}
