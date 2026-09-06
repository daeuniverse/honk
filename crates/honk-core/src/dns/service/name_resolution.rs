use std::future::Future;
use std::net::IpAddr;

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
struct FamilyResponses {
    ipv4: Option<anyhow::Result<Vec<u8>>>,
    ipv6: Option<anyhow::Result<Vec<u8>>>,
    ipv4_eligible: bool,
    ipv6_eligible: bool,
}

impl FamilyResponses {
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
}

impl DnsService {
    pub(crate) async fn resolve_name(&self, domain: &str) -> anyhow::Result<ResolvedAddr> {
        self.resolve_name_with_fallback(domain, |name| async move {
            honk_outbound::bootstrap::resolve(&name)
                .await
                .map_err(anyhow::Error::from)
        })
        .await
    }

    pub(crate) async fn resolve_name_for_source(
        &self,
        domain: &str,
        source_ip: IpAddr,
    ) -> anyhow::Result<ResolvedAddr> {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return Err(NameResolutionError::EmptyDomain.into());
        }
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(literal(ip));
        }

        debug!(lookup_kind = "source_name", %source_ip, "DNS lookup");
        let mut operation = self.operation();
        let metadata = Some(DnsRequestMeta::new(Some(source_ip), None));
        let responses = match self.backend.as_ref() {
            DnsServiceBackend::Runtime(provider) => {
                let lease = provider.acquire();
                lease
                    .run(resolve_with_forwarder(
                        &mut operation,
                        lease.runtime().forwarder(),
                        &domain,
                        metadata,
                    ))
                    .await??
            }
            DnsServiceBackend::Standalone(forwarder) => {
                resolve_with_forwarder(&mut operation, forwarder, &domain, metadata).await?
            }
        };
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
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return Err(NameResolutionError::EmptyDomain.into());
        }
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(literal(ip));
        }

        debug!(lookup_kind = "name", "DNS lookup");
        let mut operation = self.operation();
        let responses = match self.backend.as_ref() {
            DnsServiceBackend::Runtime(provider) => {
                let lease = provider.acquire();
                lease
                    .run(resolve_with_forwarder(
                        &mut operation,
                        lease.runtime().forwarder(),
                        &domain,
                        None,
                    ))
                    .await??
            }
            DnsServiceBackend::Standalone(forwarder) => {
                resolve_with_forwarder(&mut operation, forwarder, &domain, None).await?
            }
        };
        let ipv4_eligible = responses.ipv4_eligible;
        let ipv6_eligible = responses.ipv6_eligible;
        let mut resolved = resolved_from_responses(responses);
        if resolved.ipv4.is_empty() && resolved.ipv6.is_empty() {
            let addresses = fallback(domain.clone()).await.map_err(|source| {
                NameResolutionError::Bootstrap {
                    domain: domain.clone(),
                    source,
                }
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
    }
}

async fn resolve_with_forwarder(
    operation: &mut OperationToken,
    forwarder: &DnsForwarder,
    domain: &str,
    metadata: Option<DnsRequestMeta>,
) -> anyhow::Result<FamilyResponses> {
    let ipv4_query = build_dns_query(domain, 1);
    let ipv6_query = build_dns_query(domain, 28);
    let operation_future = async {
        match &forwarder.strategy {
            DnsStrategy::Both | DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6 => {
                let (ipv4, ipv6) = tokio::join!(
                    resolve_family(forwarder, &ipv4_query, metadata),
                    resolve_family(forwarder, &ipv6_query, metadata),
                );
                FamilyResponses {
                    ipv4: Some(ipv4),
                    ipv6: Some(ipv6),
                    ipv4_eligible: true,
                    ipv6_eligible: true,
                }
            }
            DnsStrategy::Ipv4Only => FamilyResponses {
                ipv4: Some(resolve_family(forwarder, &ipv4_query, metadata).await),
                ipv6: None,
                ipv4_eligible: true,
                ipv6_eligible: false,
            },
            DnsStrategy::Ipv6Only => FamilyResponses {
                ipv4: None,
                ipv6: Some(resolve_family(forwarder, &ipv6_query, metadata).await),
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

async fn resolve_family(
    forwarder: &DnsForwarder,
    query: &[u8],
    metadata: Option<DnsRequestMeta>,
) -> anyhow::Result<Vec<u8>> {
    match metadata {
        Some(metadata) => {
            forwarder
                .resolve_strict_with_context_and_profile(query, metadata, IngressProfile::Internal)
                .await
        }
        None => {
            forwarder
                .resolve_with_profile(query, IngressProfile::Internal)
                .await
        }
    }
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
