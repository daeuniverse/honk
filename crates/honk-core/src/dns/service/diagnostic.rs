use std::time::{Duration, Instant};

use super::{DnsService, DnsServiceBackend, OperationToken};
use crate::dns::{
    forwarder::{DnsForwardError, DnsForwarder, ResolveMode, ResolveOptions, build_dns_query},
    outcome::DnsOutcome,
    query::{DnsRequestMeta, IngressProfile},
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum DiagnosticError {
    #[error("unknown configured DNS upstream")]
    UnknownUpstream,
    #[error("DNS query admission is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum DiagnosticFailure {
    Timeout,
    Refused,
    Error,
}

pub(crate) struct DiagnosticAnswer {
    pub(crate) query: Vec<u8>,
    pub(crate) outcome: Result<DnsOutcome, DiagnosticFailure>,
    pub(crate) elapsed: Duration,
    pub(crate) route: crate::dns::outcome::RouteSource,
}

impl DnsService {
    pub(crate) async fn diagnostic(
        &self,
        domain: &str,
        types: &[u16],
        options: &ResolveOptions,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<DiagnosticAnswer>, DiagnosticError> {
        let mut operation = self.operation();
        match self.backend.as_ref() {
            DnsServiceBackend::Runtime(provider) => {
                let lease = provider
                    .try_acquire()
                    .map_err(|_| DiagnosticError::Unavailable)?;
                let _permit = lease
                    .runtime()
                    .try_acquire_query()
                    .map_err(|_| DiagnosticError::Unavailable)?;
                lease
                    .run(std::pin::pin!(run(
                        &mut operation,
                        lease.runtime().forwarder(),
                        domain,
                        types,
                        options,
                        deadline,
                    )))
                    .await
                    .map_err(|_| DiagnosticError::Unavailable)?
            }
            DnsServiceBackend::Standalone(forwarder) => {
                run(&mut operation, forwarder, domain, types, options, deadline).await
            }
        }
    }
}

async fn run(
    operation: &mut OperationToken,
    forwarder: &DnsForwarder,
    domain: &str,
    types: &[u16],
    options: &ResolveOptions,
    deadline: tokio::time::Instant,
) -> Result<Vec<DiagnosticAnswer>, DiagnosticError> {
    if options
        .forced_upstream
        .as_ref()
        .is_some_and(|name| !forwarder.has_configured_upstream(name.as_str()))
    {
        return Err(DiagnosticError::UnknownUpstream);
    }
    operation
        .run(async {
            let mut results = Vec::with_capacity(types.len());
            for &qtype in types {
                let query = build_dns_query(domain.trim_end_matches('.'), qtype);
                let started = Instant::now();
                let mut route = crate::dns::outcome::RouteSource::Default;
                let outcome = if tokio::time::Instant::now() >= deadline {
                    Err(DiagnosticFailure::Timeout)
                } else {
                    match tokio::time::timeout_at(
                        deadline,
                        forwarder.resolve_inner(
                            &query,
                            DnsRequestMeta::EMPTY,
                            IngressProfile::Api,
                            options,
                            ResolveMode::Strict,
                            Some(&mut route),
                        ),
                    )
                    .await
                    {
                        Err(_) => Err(DiagnosticFailure::Timeout),
                        Ok(Ok(outcome)) => Ok(outcome),
                        Ok(Err(error)) => {
                            Err(if matches!(error.unshared(), DnsForwardError::Overloaded) {
                                DiagnosticFailure::Refused
                            } else {
                                DiagnosticFailure::Error
                            })
                        }
                    }
                };
                results.push(DiagnosticAnswer {
                    query,
                    outcome,
                    elapsed: started.elapsed(),
                    route,
                });
            }
            results
        })
        .await
        .map_err(|_| DiagnosticError::Unavailable)
}
