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
#[cfg(test)]
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, Semaphore};
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

/// Max concurrent in-flight DNS queries. Sized like dae's (16384 @ ~4KB
/// each) but conservative: 2048 ≈ 8MB of in-flight state, comfortably
/// covering thousands of QPS before degradation. Over the limit the answer
/// is REFUSED, not SERVFAIL — SERVFAIL invites client retry storms, REFUSED
/// says "busy, back off".
const DEFAULT_MAX_CONCURRENT_QUERIES: usize = 2048;

/// DNS Controller — resolves admitted queries and publishes domain routes.
/// Transport adapters own socket admission and replies.
pub struct DnsController {
    dns_service: crate::dns::DnsService,
    routing_projection: Arc<crate::dns::projection::RoutingProjection>,
    concurrency_limit: Arc<Semaphore>,
}

impl DnsController {
    #[cfg(test)]
    pub fn new(
        forwarder: Arc<DnsForwarder>,
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        _router: Arc<RwLock<Router>>,
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
                std::collections::HashMap::new(),
            )),
            outbound_runtime: None,
            transport: Arc::new(NoopRuntimeTransport),
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
            concurrency_limit: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_QUERIES)),
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

    pub(crate) fn update_projection_snapshot(
        &self,
        snapshot: Arc<crate::dns::projection::RoutingProjectionSnapshot>,
    ) {
        self.routing_projection.update_snapshot(snapshot);
    }

    pub(crate) fn project_routes(
        &self,
        snapshot: &crate::dns::projection::RoutingProjectionSnapshot,
    ) -> Vec<(std::net::IpAddr, honk_ebpf_common::DomainRouting)> {
        self.routing_projection.project(snapshot)
    }

    pub async fn cache(&self) -> Arc<tokio::sync::Mutex<crate::dns::cache::DnsCache>> {
        self.dns_service.cache()
    }

    /// Acquire admission for one complete query lifecycle. The owned permit
    /// can move into an adapter task and remain held through its reply write.
    pub(crate) fn try_acquire_query(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.concurrency_limit).try_acquire_owned()
    }

    /// Resolve and project one generation-pinned DNS query.
    pub(crate) async fn answer_query(
        &self,
        data: &[u8],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
    ) -> Vec<u8> {
        match self
            .dns_service
            .resolve_outcome_with_runtime(data, metadata, ingress)
            .await
        {
            Ok((outcome, runtime)) => {
                self.submit_projection(runtime.runtime(), &outcome);
                outcome.into_rendered()
            }
            Err(error)
                if error
                    .downcast_ref::<crate::dns::forwarder::DnsForwardError>()
                    .is_some_and(|error| {
                        matches!(error, crate::dns::forwarder::DnsForwardError::Overloaded)
                    }) =>
            {
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::OutcomeRejected);
                build_dns_refused(data)
            }
            Err(_) => {
                debug!(
                    error_kind = "resolve_failed",
                    "DNS controller forward failed; sending SERVFAIL"
                );
                build_dns_servfail(data)
            }
        }
    }

    fn submit_projection(
        &self,
        runtime: &crate::dns::runtime::DnsRuntime,
        outcome: &crate::dns::outcome::DnsOutcome,
    ) {
        use crate::dns::outcome::{OutcomeStatus, Provenance, ResponseClass};
        use crate::dns::projection::{ProjectionFreshness, ProjectionObservation};

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
                        freshness: if outcome.provenance() == Provenance::Stale {
                            ProjectionFreshness::Stale
                        } else {
                            ProjectionFreshness::Fresh
                        },
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
