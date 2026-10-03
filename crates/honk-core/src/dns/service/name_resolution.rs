use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use honk_config::dns::DnsStrategy;
use tracing::debug;

use super::{DnsService, DnsServiceBackend, OperationToken};
use crate::dns::forwarder::{DnsForwarder, build_dns_query};
use crate::dns::planner::PlanError;
use crate::dns::query::{DnsRequestMeta, IngressProfile};
use crate::dns::resolver::ResolvedAddr;

#[derive(Debug, thiserror::Error)]
enum NameResolutionError {
    #[error("empty domain")]
    EmptyDomain,
    #[error("invalid domain {domain}")]
    InvalidDomain { domain: String },
    #[error("no A/AAAA records for {domain}")]
    NoAddresses { domain: String },
    #[error("resolve {domain}: {source}")]
    Bootstrap {
        domain: String,
        #[source]
        source: anyhow::Error,
    },
}

#[derive(Default)]
struct FamilyResponses<T = Vec<u8>> {
    ipv4: Option<anyhow::Result<T>>,
    ipv6: Option<anyhow::Result<T>>,
    ipv4_eligible: bool,
    ipv6_eligible: bool,
}

impl<T> FamilyResponses<T> {
    fn has_missing_original_destination(&self) -> bool {
        self.ipv4
            .iter()
            .chain(self.ipv6.iter())
            .filter_map(|response| response.as_ref().err())
            .any(|error| {
                error.chain().any(|cause| {
                    matches!(
                        cause.downcast_ref::<PlanError>(),
                        Some(PlanError::MissingOriginalDestination)
                    )
                })
            })
    }

    fn fail_on_packet_rejection(mut self) -> anyhow::Result<Self> {
        for response in [&mut self.ipv4, &mut self.ipv6] {
            let Some(Err(error)) = response.as_ref() else {
                continue;
            };
            if honk_outbound::proxy::is_packet_rejection(error) {
                let Some(Err(error)) = response.take() else {
                    unreachable!("checked family response error")
                };
                return Err(error);
            }
        }
        Ok(self)
    }
}

#[cfg(feature = "native-api")]
pub(crate) struct PinnedNameResolver {
    service: DnsService,
    runtime: Option<crate::dns::runtime::RuntimeLease>,
    forwarder: Arc<DnsForwarder>,
}

#[cfg(feature = "native-api")]
impl PinnedNameResolver {
    /// Resolve only through the captured generation, never bootstrap or system DNS.
    pub(crate) async fn resolve(&self, domain: &str) -> anyhow::Result<Vec<IpAddr>> {
        let domain = normalize_domain(domain)?;
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let mut responses = FamilyResponses {
            ipv4_eligible: self.forwarder.strategy != DnsStrategy::Ipv6Only,
            ipv6_eligible: self.forwarder.strategy != DnsStrategy::Ipv4Only,
            ipv4: None,
            ipv6: None,
        };
        if responses.ipv4_eligible {
            responses.ipv4 = Some(self.resolve_family(&domain, 1).await);
        }
        if responses.ipv6_eligible {
            responses.ipv6 = Some(self.resolve_family(&domain, 28).await);
        }
        let responses = responses.fail_on_packet_rejection()?;
        let mut addresses = Vec::new();
        for outcome in responses.ipv4.into_iter().chain(responses.ipv6).flatten() {
            addresses.extend_from_slice(outcome.answer_ips());
        }
        Ok(addresses)
    }

    async fn resolve_family(
        &self,
        domain: &str,
        qtype: u16,
    ) -> anyhow::Result<crate::dns::outcome::DnsOutcome> {
        let query = build_dns_query(domain, qtype);
        let mut operation = self.service.operation();
        let resolve = self.forwarder.resolve_outcome_with_context_and_profile(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Api,
        );
        let outcome = match &self.runtime {
            Some(runtime) => {
                let _permit = runtime.runtime().try_acquire_query()?;
                operation
                    .run(runtime.run(std::pin::pin!(resolve)))
                    .await??
            }
            None => operation.run(resolve).await?,
        };
        outcome.map_err(Into::into)
    }
}

impl DnsService {
    #[cfg(feature = "native-api")]
    pub(crate) fn pin_name_resolution(&self) -> anyhow::Result<PinnedNameResolver> {
        let runtime = self
            .provider()
            .map(|provider| provider.try_acquire())
            .transpose()?;
        let forwarder = runtime.as_ref().map_or_else(
            || self.forwarder(),
            |runtime| Arc::clone(runtime.runtime().forwarder()),
        );
        Ok(PinnedNameResolver {
            service: self.clone(),
            runtime,
            forwarder,
        })
    }

    pub(crate) async fn resolve_name(&self, domain: &str) -> anyhow::Result<ResolvedAddr> {
        self.resolve_name_with_fallback(domain, |name| async move {
            honk_outbound::bootstrap::resolve(&name)
                .await
                .map_err(anyhow::Error::from)
        })
        .await
    }

    pub(crate) async fn resolve_name_without_fallback(
        &self,
        domain: &str,
    ) -> anyhow::Result<ResolvedAddr> {
        let domain = normalize_domain(domain)?;
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(literal(ip));
        }
        debug!(lookup_kind = "name", "DNS lookup");
        let resolved = resolved_from_responses(self.resolve_name_families(&domain, None).await?);
        if resolved.ipv4.is_empty() && resolved.ipv6.is_empty() {
            return Err(NameResolutionError::NoAddresses { domain }.into());
        }
        debug!(
            ipv4_present = !resolved.ipv4.is_empty(),
            ipv6_present = !resolved.ipv6.is_empty(),
            ttl = resolved.min_ttl,
            "DNS resolved"
        );
        Ok(resolved)
    }

    pub(crate) async fn resolve_name_for_source(
        &self,
        domain: &str,
        source: SocketAddr,
    ) -> anyhow::Result<ResolvedAddr> {
        let domain = normalize_domain(domain)?;
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(literal(ip));
        }

        debug!(lookup_kind = "source_name", source_ip = %source.ip(), "DNS lookup");
        let metadata = Some((DnsRequestMeta::new(Some(source.ip()), None), source));
        let responses = self.resolve_name_families(&domain, metadata).await?;
        if responses.has_missing_original_destination() {
            return Err(PlanError::MissingOriginalDestination.into());
        }
        let resolved = resolved_from_responses(responses);
        if resolved.ipv4.is_empty() && resolved.ipv6.is_empty() {
            return Err(NameResolutionError::NoAddresses { domain }.into());
        }
        Ok(resolved)
    }

    pub(crate) async fn resolve_name_with_fallback<F, Fut>(
        &self,
        domain: &str,
        fallback: F,
    ) -> anyhow::Result<ResolvedAddr>
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = anyhow::Result<Vec<IpAddr>>>,
    {
        let domain = normalize_domain(domain)?;
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(literal(ip));
        }

        let lease = self
            .provider()
            .map(|provider| provider.try_acquire())
            .transpose()?;
        let forwarder = lease.as_ref().map_or_else(
            || self.forwarder(),
            |lease| Arc::clone(lease.runtime().forwarder()),
        );
        let mut operation = self.operation();
        let resolve = async {
            debug!(lookup_kind = "name", "DNS lookup");
            let responses = resolve_with_forwarder(self, &mut operation, &forwarder, &domain, None)
                .await?
                .fail_on_packet_rejection()?;
            let ipv4_eligible = responses.ipv4_eligible;
            let ipv6_eligible = responses.ipv6_eligible;
            let mut resolved = resolved_from_responses(responses);
            if resolved.ipv4.is_empty() && resolved.ipv6.is_empty() {
                let addresses =
                    operation
                        .run(fallback(domain.clone()))
                        .await?
                        .map_err(|source| NameResolutionError::Bootstrap {
                            domain: domain.clone(),
                            source,
                        })?;
                for address in addresses {
                    match address {
                        IpAddr::V4(_) if ipv4_eligible => resolved.ipv4.push(address),
                        IpAddr::V6(_) if ipv6_eligible => resolved.ipv6.push(address),
                        IpAddr::V4(_) | IpAddr::V6(_) => {}
                    }
                }
                if resolved.ipv4.is_empty() && resolved.ipv6.is_empty() {
                    return Err(NameResolutionError::NoAddresses { domain }.into());
                }
                resolved.min_ttl = 60;
            }
            debug!(
                ipv4_present = !resolved.ipv4.is_empty(),
                ipv6_present = !resolved.ipv6.is_empty(),
                ttl = resolved.min_ttl,
                "DNS resolved"
            );
            Ok(resolved)
        };
        match lease {
            Some(lease) => lease.run(std::pin::pin!(resolve)).await?,
            None => resolve.await,
        }
    }

    async fn resolve_name_families(
        &self,
        domain: &str,
        metadata: Option<(DnsRequestMeta, SocketAddr)>,
    ) -> anyhow::Result<FamilyResponses> {
        let mut operation = self.operation();
        let responses = match self.backend.as_ref() {
            DnsServiceBackend::Runtime(provider) => {
                let lease = provider.try_acquire()?;
                lease
                    .run(std::pin::pin!(resolve_with_forwarder(
                        self,
                        &mut operation,
                        lease.runtime().forwarder(),
                        domain,
                        metadata,
                    )))
                    .await??
            }
            DnsServiceBackend::Standalone(forwarder) => {
                resolve_with_forwarder(self, &mut operation, forwarder, domain, metadata).await?
            }
        };
        responses.fail_on_packet_rejection()
    }
}

fn normalize_domain(domain: &str) -> anyhow::Result<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return Err(NameResolutionError::EmptyDomain.into());
    }
    if domain.len() > 253
        || domain
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(NameResolutionError::InvalidDomain { domain }.into());
    }
    Ok(domain)
}

async fn resolve_with_forwarder(
    service: &DnsService,
    operation: &mut OperationToken,
    forwarder: &DnsForwarder,
    domain: &str,
    metadata: Option<(DnsRequestMeta, SocketAddr)>,
) -> anyhow::Result<FamilyResponses> {
    let ipv4_query = build_dns_query(domain, 1);
    let ipv6_query = build_dns_query(domain, 28);
    let operation_future = async {
        match &forwarder.strategy {
            DnsStrategy::Both | DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6 => {
                let (ipv4, ipv6) = tokio::join!(
                    resolve_family(service, forwarder, &ipv4_query, metadata),
                    resolve_family(service, forwarder, &ipv6_query, metadata),
                );
                FamilyResponses {
                    ipv4: Some(ipv4),
                    ipv6: Some(ipv6),
                    ipv4_eligible: true,
                    ipv6_eligible: true,
                }
            }
            DnsStrategy::Ipv4Only => FamilyResponses {
                ipv4: Some(resolve_family(service, forwarder, &ipv4_query, metadata).await),
                ipv6: None,
                ipv4_eligible: true,
                ipv6_eligible: false,
            },
            DnsStrategy::Ipv6Only => FamilyResponses {
                ipv4: None,
                ipv6: Some(resolve_family(service, forwarder, &ipv6_query, metadata).await),
                ipv4_eligible: false,
                ipv6_eligible: true,
            },
        }
    };
    operation
        .run(operation_future)
        .await
        .map_err(anyhow::Error::from)
}

fn resolve_family<'a>(
    _service: &'a DnsService,
    forwarder: &'a DnsForwarder,
    query: &'a [u8],
    metadata: Option<(DnsRequestMeta, SocketAddr)>,
) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send + 'a {
    // Family futures otherwise multiply through join and cancellation scopes.
    Box::pin(async move {
        match metadata {
            Some((metadata, _source)) => {
                #[cfg(feature = "native-api")]
                let started = std::time::Instant::now();
                #[cfg(feature = "native-api")]
                let mut route = crate::dns::outcome::RouteSource::Default;
                #[cfg(feature = "native-api")]
                let evidence = _service.observation_enabled().then_some(&mut route);
                #[cfg(not(feature = "native-api"))]
                let evidence = None;
                let result = forwarder
                    .resolve_inner(
                        query,
                        metadata,
                        IngressProfile::Internal,
                        &crate::dns::forwarder::ResolveOptions::default(),
                        crate::dns::forwarder::ResolveMode::Strict,
                        evidence,
                    )
                    .await;
                #[cfg(feature = "native-api")]
                if _service.observation_enabled() {
                    match &result {
                        Ok(outcome) => _service.observer.observe_client(
                            query,
                            IngressProfile::Internal,
                            Some(_source),
                            Some(outcome),
                            outcome.rendered(),
                            started.elapsed(),
                        ),
                        Err(_) => {
                            if let Ok(outcome) = crate::dns::outcome::DnsOutcome::client_error(
                                query,
                                IngressProfile::Internal,
                                crate::dns::response::build_dns_servfail(query),
                                route,
                            ) {
                                _service.observer.observe_client(
                                    query,
                                    IngressProfile::Internal,
                                    Some(_source),
                                    Some(&outcome),
                                    outcome.rendered(),
                                    started.elapsed(),
                                );
                            }
                        }
                    }
                }
                result
                    .map(|outcome| outcome.into_rendered())
                    .map_err(Into::into)
            }
            None => {
                forwarder
                    .resolve_with_profile(query, IngressProfile::Internal)
                    .await
            }
        }
    })
}

fn literal(ip: IpAddr) -> ResolvedAddr {
    match ip {
        IpAddr::V4(_) => ResolvedAddr {
            ipv4: vec![ip],
            ipv6: Vec::new(),
            min_ttl: 3600,
        },
        IpAddr::V6(_) => ResolvedAddr {
            ipv4: Vec::new(),
            ipv6: vec![ip],
            min_ttl: 3600,
        },
    }
}

fn resolved_from_responses(responses: FamilyResponses) -> ResolvedAddr {
    let (ipv4, ipv4_ttl) = parsed_family(responses.ipv4, true, "A");
    let (ipv6, ipv6_ttl) = parsed_family(responses.ipv6, false, "AAAA");
    ResolvedAddr {
        ipv4,
        ipv6,
        min_ttl: ipv4_ttl.into_iter().chain(ipv6_ttl).min().unwrap_or(60),
    }
}

fn parsed_family(
    response: Option<anyhow::Result<Vec<u8>>>,
    ipv4: bool,
    label: &str,
) -> (Vec<IpAddr>, Option<u32>) {
    let Some(response) = response else {
        return (Vec::new(), None);
    };
    let response = match response {
        Ok(response) => response,
        Err(_) => {
            debug!(
                record_type = label,
                error_kind = "lookup_failed",
                "DNS name-family lookup failed"
            );
            return (Vec::new(), None);
        }
    };
    let pairs = crate::dns::wire::extract_ips_with_ttl(&response);
    let addresses = pairs
        .iter()
        .filter(|(ip, _)| ip.is_ipv4() == ipv4)
        .map(|(ip, _)| *ip)
        .collect::<Vec<_>>();
    let ttl = (!addresses.is_empty())
        .then(|| {
            pairs
                .iter()
                .filter(|(ip, _)| ip.is_ipv4() == ipv4)
                .filter_map(|(_, ttl)| (*ttl > 0).then_some(*ttl))
                .min()
        })
        .flatten()
        .or_else(|| (!addresses.is_empty()).then_some(60));
    (addresses, ttl)
}
