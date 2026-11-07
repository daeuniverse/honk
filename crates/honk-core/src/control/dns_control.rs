//! Generation-pinned DNS query orchestration shared by transparent port-53
//! interception and the optional standalone listener.
//!
//! Transport adapters own admission and reply I/O. Successful outcomes are
//! submitted to the generation-aware routing projection; no adapter writes
//! domain routes directly.

#[cfg(test)]
use crate::dns::forwarder::DnsForwarder;
use crate::ebpf::PolicyBackend;
#[cfg(test)]
use crate::routing::Router;
use honk_datapath::ScopeId;
use std::future::Future;
#[cfg(test)]
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore, TryAcquireError};
use tracing::warn;

mod transport;
pub(in crate::control) use transport::DnsUdpReply;

#[cfg(test)]
mod tests;

pub(crate) const MAX_UDP_CLIENT_QUERIES: usize = 1536;

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
    udp_query_limit: Arc<Semaphore>,
    packet_scopes: std::sync::OnceLock<Box<[ScopeId]>>,
}

pub(crate) struct DnsClientAnswer(Result<crate::dns::outcome::DnsOutcome, Vec<u8>>);

impl DnsClientAnswer {
    pub(crate) fn wire(&self) -> &[u8] {
        match &self.0 {
            Ok(outcome) => outcome.rendered(),
            Err(response) => response,
        }
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn outcome(&self) -> Option<&crate::dns::outcome::DnsOutcome> {
        self.0.as_ref().ok()
    }

    #[cfg(test)]
    fn into_wire(self) -> Vec<u8> {
        match self.0 {
            Ok(outcome) => outcome.into_rendered(),
            Err(response) => response,
        }
    }
}

/// Admission retained by the transport through response I/O. The query permit
/// is generation-owned; the UDP permit comes from the controller's shared budget.
pub(crate) struct AdmittedDnsQuery {
    runtime: crate::dns::runtime::RuntimeLease,
    _query_permit: OwnedSemaphorePermit,
    _udp_permit: Option<OwnedSemaphorePermit>,
    projection_scope: ScopeId,
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
        ebpf: Arc<RwLock<Box<dyn PolicyBackend>>>,
        _router: Arc<RwLock<Router>>,
        udp_query_limit: usize,
    ) -> Self {
        let config = honk_config::Config::default();
        let runtime_router = Arc::new(
            Router::from_config(&config.routing)
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
        });
        Self::new_with_runtime(
            Arc::new(crate::dns::runtime::DnsServiceProvider::new(runtime)),
            ebpf,
            udp_query_limit,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_runtime(
        runtime_provider: Arc<crate::dns::runtime::DnsServiceProvider>,
        ebpf: Arc<RwLock<Box<dyn PolicyBackend>>>,
        udp_query_limit: usize,
    ) -> Self {
        Self::new_with_service(
            crate::dns::DnsService::with_provider(runtime_provider),
            ebpf,
            udp_query_limit,
        )
    }

    pub(crate) fn new_with_service(
        dns_service: crate::dns::DnsService,
        ebpf: Arc<RwLock<Box<dyn PolicyBackend>>>,
        udp_query_limit: usize,
    ) -> Self {
        let snapshot = {
            let runtime = dns_service
                .provider()
                .unwrap_or_else(|| unreachable!("controller requires runtime DNS service"))
                .current();
            Arc::clone(runtime.routing_projection())
        };
        let routing_projection =
            crate::dns::projection::RoutingProjection::spawn(Arc::clone(&ebpf), snapshot);
        Self {
            dns_service,
            routing_projection,
            packet_scopes: std::sync::OnceLock::new(),
            udp_query_limit: Arc::new(Semaphore::new(udp_query_limit.min(MAX_UDP_CLIENT_QUERIES))),
        }
    }

    /// Resolve a domain (A + AAAA) through the *currently installed*
    /// forwarder — reload-safe, unlike holding a resolver from startup.
    /// Used by the health-check resolver hook.
    pub async fn resolve_domain(&self, domain: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
        let resolved = self.dns_service.resolve_name(domain).await?;
        Ok(resolved.ipv4.into_iter().chain(resolved.ipv6).collect())
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
        // The provider's pause JoinSet, not this wait, owns every close task,
        // so abandoning the wait on timeout detaches nothing.
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

    pub(in crate::control) fn register_packet_scopes(
        &self,
        scopes: &[super::netstack::PacketScope],
    ) -> anyhow::Result<()> {
        let scopes = scopes
            .iter()
            .map(super::netstack::PacketScope::scope)
            .collect();
        self.packet_scopes
            .set(scopes)
            .map_err(|_| anyhow::anyhow!("packet DNS scopes are already registered"))
    }

    pub(in crate::control) fn packet_domain_bitmap(
        &self,
        scope: ScopeId,
        ip: std::net::IpAddr,
        router: &crate::routing::Router,
        generation: u64,
    ) -> anyhow::Result<Option<honk_ebpf_common::DomainRouting>> {
        if !self.owns_packet_scope(scope) {
            return Ok(None);
        }
        self.routing_projection
            .packet_bitmap(scope, ip, router, generation)
    }

    fn owns_packet_scope(&self, scope: ScopeId) -> bool {
        scope != ScopeId::HOST
            && self
                .packet_scopes
                .get()
                .is_some_and(|scopes| scopes.contains(&scope))
    }

    pub async fn cache(&self) -> Arc<tokio::sync::Mutex<crate::dns::cache::DnsCache>> {
        self.dns_service.cache()
    }

    /// Acquire a generation-pinned query admission. The runtime lease and
    /// permits remain owned by the caller through response I/O.
    pub(crate) fn try_admit_query(&self, udp: bool) -> Result<AdmittedDnsQuery, DnsAdmissionError> {
        let runtime = self
            .dns_service
            .try_acquire_runtime()
            .map_err(|_| DnsAdmissionError {
                error: TryAcquireError::Closed,
                udp_reply: None,
            })?;
        let udp_permit = if udp {
            Some(
                Arc::clone(&self.udp_query_limit)
                    .try_acquire_owned()
                    .map_err(|error| DnsAdmissionError {
                        error,
                        udp_reply: None,
                    })?,
            )
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
            projection_scope: ScopeId::HOST,
        })
    }

    pub(in crate::control) fn try_admit_packet_query(
        &self,
        udp: bool,
        scope: ScopeId,
    ) -> Result<AdmittedDnsQuery, DnsAdmissionError> {
        if !self.owns_packet_scope(scope) {
            return Err(DnsAdmissionError {
                error: TryAcquireError::Closed,
                udp_reply: None,
            });
        }
        self.try_admit_query(udp).map(|mut query| {
            query.projection_scope = scope;
            query
        })
    }

    /// Resolve and project one generation-pinned DNS query.
    pub(crate) async fn answer_query(
        &self,
        admission: &AdmittedDnsQuery,
        data: &[u8],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
    ) -> DnsClientAnswer {
        #[cfg(feature = "native-api")]
        let mut observed_route = self
            .dns_service
            .observation_enabled()
            .then(crate::dns::outcome::RouteSource::default);
        #[cfg(feature = "native-api")]
        let evidence = observed_route.as_mut();
        #[cfg(not(feature = "native-api"))]
        let evidence = None;
        // The match ends and the outcome moves into `project_answer` before
        // its await, so the answer future stores no second outcome.
        let response = 'failed: {
            let outcome = match self
                .dns_service
                .resolve_client_outcome_with_runtime(
                    &admission.runtime,
                    data,
                    metadata,
                    ingress,
                    evidence,
                )
                .await
            {
                Ok(outcome) => outcome,
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
                    break 'failed build_dns_refused(data);
                }
                Err(error) => {
                    crate::logging::warn_throttled!(
                        error = %error,
                        "DNS controller forward failed; sending SERVFAIL"
                    );
                    break 'failed build_dns_servfail(data);
                }
            };
            match self
                .project_answer(&admission.runtime, admission.projection_scope, outcome)
                .await
            {
                Ok(answer) => return answer,
                Err(error) => {
                    crate::observe::flows::dns::decision("cancelled", Some("runtime_retired"));
                    tracing::debug!(%error, "DNS projection wait cancelled with runtime retirement");
                    break 'failed build_dns_servfail(data);
                }
            }
        };
        #[cfg(feature = "native-api")]
        if let Some(source) = observed_route {
            return DnsClientAnswer(crate::dns::outcome::DnsOutcome::client_error(
                data, ingress, response, source,
            ));
        }
        DnsClientAnswer(Err(response))
    }

    /// Projects a resolved outcome before it is answered. Only a projection
    /// that meets a held publication waits, inside its own box; the outcome
    /// is fully moved there, so ready answers reserve no space for that wait.
    async fn project_answer(
        &self,
        lease: &crate::dns::runtime::RuntimeLease,
        scope: ScopeId,
        outcome: crate::dns::outcome::DnsOutcome,
    ) -> Result<DnsClientAnswer, crate::dns::runtime::RuntimeCancelled> {
        let observed_at = tokio::time::Instant::now();
        if !self.try_submit_projection(lease.runtime(), scope, &outcome, observed_at) {
            return Box::pin(async move {
                tokio::select! {
                    biased;
                    error = lease.cancelled() => return Err(error),
                    () = self.routing_projection.submit_after_publication(|| {
                        self.try_submit_projection(lease.runtime(), scope, &outcome, observed_at)
                    }) => {}
                }
                Ok(DnsClientAnswer(Ok(outcome)))
            })
            .await;
        }
        Ok(DnsClientAnswer(Ok(outcome)))
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
        self.answer_query(&admission, data, metadata, ingress)
            .await
            .into_wire()
    }

    /// Projects `outcome`, or returns `false` while a publication holds the
    /// projection fence.
    fn try_submit_projection(
        &self,
        runtime: &crate::dns::runtime::DnsRuntime,
        scope: ScopeId,
        outcome: &crate::dns::outcome::DnsOutcome,
        observed_at: tokio::time::Instant,
    ) -> bool {
        use crate::dns::outcome::{OutcomeStatus, ResponseClass};
        use crate::dns::projection::ProjectionObservation;
        use honk_outbound::alive::IpVersion;

        let projection = &self.routing_projection;
        let snapshot = runtime.routing_projection();
        let domain = outcome.domain();
        let family = match outcome.qtype() {
            1 => Some(IpVersion::V4),
            28 => Some(IpVersion::V6),
            _ => None,
        };
        let observation = if crate::dns::response::is_truncated(outcome.reusable()) {
            ProjectionObservation::Retain
        } else {
            match (outcome.status(), outcome.response_class(), family) {
                (OutcomeStatus::Accepted, ResponseClass::Positive, Some(family)) => {
                    // Uncacheable does not mean the accepted address has no routing lifetime.
                    let advertised_ttl = if outcome.expiry().is_cacheable() {
                        outcome.expiry().ttl()
                    } else {
                        Duration::from_secs(u64::from(crate::dns::forwarder::extract_min_ttl(
                            outcome.reusable(),
                        )))
                    };
                    let expires_at = observed_at + advertised_ttl;
                    if outcome.provenance() == crate::dns::outcome::Provenance::Cache {
                        return projection.try_submit_cache_hit(
                            scope,
                            snapshot,
                            domain,
                            family,
                            outcome.answer_ips(),
                            expires_at,
                        );
                    }
                    ProjectionObservation::Positive {
                        domain,
                        family,
                        ips: outcome.answer_ips(),
                        expires_at,
                    }
                }
                (OutcomeStatus::Accepted, ResponseClass::Nodata, Some(family)) => {
                    ProjectionObservation::Clear { domain, family }
                }
                (OutcomeStatus::Accepted, ResponseClass::Nxdomain, _) => {
                    ProjectionObservation::ClearName { domain }
                }
                // Other QTYPEs say nothing about the name's addresses.
                (
                    OutcomeStatus::Accepted,
                    ResponseClass::Positive | ResponseClass::Nodata,
                    None,
                )
                | (OutcomeStatus::Accepted, ResponseClass::Servfail, _)
                | (OutcomeStatus::Rejected, _, _) => ProjectionObservation::Retain,
            }
        };
        projection.try_submit(scope, snapshot, observation)
    }
}
