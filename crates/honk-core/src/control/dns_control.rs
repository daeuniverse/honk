//! Generation-pinned DNS query orchestration shared by transparent port-53
//! interception and the optional standalone listener.
//!
//! Transport adapters own admission and reply I/O. Successful outcomes are
//! submitted to the generation-aware routing projection; no adapter writes
//! domain routes directly.

#[cfg(test)]
use crate::dns::forwarder::DnsForwarder;
use crate::ebpf::EbpfBackend;
#[cfg(test)]
use crate::routing::Router;
use parking_lot::Mutex;
use std::future::Future;
#[cfg(test)]
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, RwLock, TryAcquireError};
use tracing::{debug, warn};

mod transport;

#[cfg(test)]
mod tests;

use crate::dns::query::{DnsRequestMeta, IngressProfile};
use crate::dns::response::{build_dns_refused, build_dns_servfail};

#[cfg(test)]
struct NoopRuntimeTransport;

#[cfg(test)]
#[async_trait::async_trait]
impl crate::dns::runtime::RuntimeTransport for NoopRuntimeTransport {
    async fn close(&self) {}
}

/// DNS Controller — resolves admitted queries and publishes domain routes.
/// Transport adapters own socket admission and replies.
pub struct DnsController {
    dns_service: crate::dns::DnsService,
    routing_projection: Arc<crate::dns::projection::RoutingProjection>,
}

/// Admission for one DNS request. The runtime lease and both runtime-owned
/// permits are held by the transport owner through response I/O.
pub(crate) struct AdmittedDnsQuery {
    runtime: crate::dns::runtime::RuntimeLease,
    _query_permit: OwnedSemaphorePermit,
    _udp_permit: Option<OwnedSemaphorePermit>,
}

pub(crate) struct DnsAdmissionError {
    error: TryAcquireError,
    pub(super) udp_reply: Option<(crate::dns::runtime::RuntimeLease, OwnedSemaphorePermit)>,
}

impl std::fmt::Debug for DnsAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.error, f)
    }
}

impl DnsAdmissionError {
    pub(crate) async fn run_reply<T>(
        &self,
        operation: impl Future<Output = T>,
    ) -> Result<T, crate::dns::runtime::RuntimeCancelled> {
        match &self.udp_reply {
            Some((runtime, _)) => runtime.run_reply(operation).await,
            None => Ok(operation.await),
        }
    }
}

impl AdmittedDnsQuery {
    pub(crate) async fn run_reply<T>(
        &self,
        operation: impl Future<Output = T>,
    ) -> Result<T, crate::dns::runtime::RuntimeCancelled> {
        self.runtime.run_reply(operation).await
    }
}

impl DnsController {
    #[cfg(test)]
    pub fn new(
        forwarder: Arc<DnsForwarder>,
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        _router: Arc<RwLock<Router>>,
        udp_query_limit: usize,
    ) -> Self {
        let config = honk_config::Config::default();
        let runtime_router = Arc::new(
            Router::new(&config.routing.rules, &config.routing.default_outbound)
                .unwrap_or_else(|_| Router::new(&[], "direct").unwrap()),
        );
        let runtime = crate::dns::runtime::DnsRuntime::new(crate::dns::runtime::DnsRuntimeParts {
            generation: crate::dns::runtime::RuntimeGeneration::new(0),
            forwarder: Arc::clone(&forwarder),
            routing_projection: Arc::new(crate::dns::runtime::RoutingProjectionSnapshot::new(
                0,
                runtime_router,
            )),
            outbound_runtime: None,
            transport: Arc::new(NoopRuntimeTransport),
            udp_query_limit,
        });
        Self::new_with_runtime(
            Arc::new(crate::dns::runtime::DnsServiceProvider::new(runtime)),
            ebpf,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_runtime(
        runtime_provider: Arc<crate::dns::runtime::DnsServiceProvider>,
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    ) -> Self {
        Self::new_with_service(
            crate::dns::DnsService::with_provider(runtime_provider),
            ebpf,
        )
    }

    pub(crate) fn new_with_service(
        dns_service: crate::dns::DnsService,
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    ) -> Self {
        let snapshot = {
            let runtime = dns_service
                .provider()
                .unwrap_or_else(|| unreachable!("controller requires runtime DNS service"))
                .acquire();
            Arc::clone(runtime.runtime().routing_projection())
        };
        let routing_projection =
            crate::dns::projection::RoutingProjection::spawn(Arc::clone(&ebpf), snapshot);
        Self {
            dns_service,
            routing_projection,
        }
    }

    /// Resolve a domain (A + AAAA) through the *currently installed*
    /// forwarder — reload-safe, unlike holding a resolver from startup.
    /// Used by the health-check resolver hook.
    pub async fn resolve_domain(&self, domain: &str) -> Vec<std::net::IpAddr> {
        match self.dns_service.resolve_name(domain).await {
            Ok(resolved) => resolved.ipv4.into_iter().chain(resolved.ipv6).collect(),
            Err(_) => {
                debug!(
                    error_kind = "lookup_failed",
                    "DNS controller name resolution failed"
                );
                Vec::new()
            }
        }
    }

    pub(crate) fn runtime_provider(&self) -> Arc<crate::dns::runtime::DnsServiceProvider> {
        self.dns_service
            .provider()
            .unwrap_or_else(|| unreachable!("controller always uses runtime DNS service"))
    }

    pub(crate) fn dns_service(&self) -> crate::dns::DnsService {
        self.dns_service.clone()
    }

    pub(crate) async fn shutdown(&self, timeout: Duration) {
        self.routing_projection.shutdown(timeout).await;
        // The provider retires runtimes through a JoinSet of supervisors,
        // and a dropped JoinSet aborts its tasks — a timeout here cannot
        // leave a detached worker behind.
        let provider = self.runtime_provider();
        if tokio::time::timeout(timeout, provider.shutdown())
            .await
            .is_err()
        {
            warn!(
                "DNS runtime provider shutdown exceeded {:?}; continuing",
                timeout
            );
        }
    }

    #[cfg(test)]
    pub(crate) fn project_routes(
        &self,
        snapshot: &crate::dns::projection::RoutingProjectionSnapshot,
    ) -> Vec<(std::net::IpAddr, honk_ebpf_common::DomainRouting)> {
        self.routing_projection.project(snapshot)
    }

    pub(crate) fn forwarder(&self) -> Arc<crate::dns::forwarder::DnsForwarder> {
        self.dns_service.forwarder()
    }

    pub(crate) fn prepare_projection_publication(
        &self,
    ) -> crate::dns::projection::PreparedProjectionPublication<'_> {
        self.routing_projection.prepare_snapshot_publication()
    }

    pub async fn cache(&self) -> Arc<tokio::sync::Mutex<crate::dns::cache::DnsCache>> {
        self.dns_service.cache()
    }

    /// Acquire a generation-pinned query admission. The runtime lease and
    /// permits remain owned by the caller through response I/O.
    pub(crate) fn try_admit_query(&self, udp: bool) -> Result<AdmittedDnsQuery, DnsAdmissionError> {
        let runtime = self.runtime_provider().acquire();
        let udp_permit =
            if udp {
                Some(runtime.runtime().try_acquire_udp_query().map_err(|error| {
                    DnsAdmissionError {
                        error,
                        udp_reply: None,
                    }
                })?)
            } else {
                None
            };
        let query_permit = match runtime.runtime().try_acquire_query() {
            Ok(permit) => permit,
            Err(error) => {
                return Err(DnsAdmissionError {
                    error,
                    udp_reply: udp_permit.map(|permit| (runtime, permit)),
                });
            }
        };
        Ok(AdmittedDnsQuery {
            runtime,
            _query_permit: query_permit,
            _udp_permit: udp_permit,
        })
    }

    /// Resolve and project one generation-pinned DNS query.
    pub(crate) async fn answer_query(
        &self,
        admission: &AdmittedDnsQuery,
        data: &[u8],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
    ) -> Vec<u8> {
        match self
            .dns_service
            .resolve_outcome_with_runtime(&admission.runtime, data, metadata, ingress)
            .await
        {
            Ok(outcome) => {
                self.submit_projection(admission.runtime.runtime(), &outcome);
                outcome.into_rendered()
            }
            Err(error)
                if error
                    .downcast_ref::<crate::dns::forwarder::DnsForwardError>()
                    .is_some_and(|error| {
                        matches!(
                            error.unshared(),
                            crate::dns::forwarder::DnsForwardError::Overloaded
                        )
                    }) =>
            {
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::OutcomeRejected);
                build_dns_refused(data)
            }
            Err(error) => {
                // A wedged upstream layer must be visible at the default
                // level without one line per query. Monotonic clock: a
                // wall-clock step must not mute the alarm.
                static LAST_SERVFAIL_LOG: Mutex<Option<Instant>> = Mutex::new(None);
                let mut last = LAST_SERVFAIL_LOG.lock();
                if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(10)) {
                    *last = Some(Instant::now());
                    warn!(error = %error, "DNS controller forward failed; sending SERVFAIL");
                }
                build_dns_servfail(data)
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn answer_query_for_test(
        &self,
        data: &[u8],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
    ) -> Vec<u8> {
        let admission = self
            .try_admit_query(false)
            .expect("test DNS query admission");
        self.answer_query(&admission, data, metadata, ingress).await
    }

    fn submit_projection(
        &self,
        runtime: &crate::dns::runtime::DnsRuntime,
        outcome: &crate::dns::outcome::DnsOutcome,
    ) {
        use crate::dns::outcome::{OutcomeStatus, ResponseClass};
        use crate::dns::projection::ProjectionObservation;

        let domain = outcome.domain();
        let observation = if crate::dns::response::is_truncated(outcome.reusable()) {
            ProjectionObservation::Retain
        } else {
            match (outcome.status(), outcome.response_class()) {
                (OutcomeStatus::Accepted, ResponseClass::Positive) => {
                    ProjectionObservation::Positive {
                        domain,
                        ips: outcome.answer_ips(),
                        advertised_ttl: outcome.expiry().ttl(),
                    }
                }
                (OutcomeStatus::Accepted, ResponseClass::Nodata | ResponseClass::Nxdomain) => {
                    ProjectionObservation::Clear { domain }
                }
                (OutcomeStatus::Accepted, ResponseClass::Servfail)
                | (OutcomeStatus::Rejected, _) => ProjectionObservation::Retain,
            }
        };
        self.routing_projection
            .submit(Arc::clone(runtime.routing_projection()), observation);
    }
}
