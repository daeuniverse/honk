use crate::dns::outcome::{DnsOutcome, OutcomeStatus, ResponseClass};
use crate::dns::query::{DnsRequestMeta, IngressProfile};

use super::{DnsForwardError, DnsForwarder, ResolveMode, ResolveOptions};

impl DnsForwarder {
    /// Resolve a raw DNS query (no original destination for `asis`).
    pub async fn resolve(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.resolve_with_profile(raw_query, IngressProfile::Internal)
            .await
    }

    /// Resolve a raw DNS query using an explicit caller ingress profile.
    pub async fn resolve_with_profile(
        &self,
        raw_query: &[u8],
        ingress: IngressProfile,
    ) -> anyhow::Result<Vec<u8>> {
        Ok(self
            .resolve_inner(
                raw_query,
                DnsRequestMeta::EMPTY,
                ingress,
                &ResolveOptions::default(),
                ResolveMode::Compatibility,
                None,
            )
            .await?
            .into_rendered())
    }

    /// Resolve a raw DNS query with caller metadata.
    pub async fn resolve_with_context(
        &self,
        raw_query: &[u8],
        metadata: DnsRequestMeta,
    ) -> anyhow::Result<Vec<u8>> {
        self.resolve_with_context_and_profile(raw_query, metadata, IngressProfile::Internal)
            .await
    }

    /// Resolve with caller metadata and an explicit ingress profile.
    pub async fn resolve_with_context_and_profile(
        &self,
        raw_query: &[u8],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
    ) -> anyhow::Result<Vec<u8>> {
        Ok(self
            .resolve_inner(
                raw_query,
                metadata,
                ingress,
                &ResolveOptions::default(),
                ResolveMode::Compatibility,
                None,
            )
            .await?
            .into_rendered())
    }

    pub(crate) async fn resolve_strict_with_context_and_profile(
        &self,
        raw_query: &[u8],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
    ) -> anyhow::Result<Vec<u8>> {
        Ok(self
            .resolve_inner(
                raw_query,
                metadata,
                ingress,
                &ResolveOptions::default(),
                ResolveMode::Strict,
                None,
            )
            .await?
            .into_rendered())
    }

    pub async fn resolve_outcome(&self, raw_query: &[u8]) -> Result<DnsOutcome, DnsForwardError> {
        self.resolve_outcome_with_context(raw_query, DnsRequestMeta::EMPTY)
            .await
    }

    pub async fn resolve_outcome_with_context(
        &self,
        raw_query: &[u8],
        metadata: DnsRequestMeta,
    ) -> Result<DnsOutcome, DnsForwardError> {
        self.resolve_outcome_with_context_and_profile(raw_query, metadata, IngressProfile::Internal)
            .await
    }

    pub async fn resolve_outcome_with_context_and_profile(
        &self,
        raw_query: &[u8],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
    ) -> Result<DnsOutcome, DnsForwardError> {
        self.resolve_inner(
            raw_query,
            metadata,
            ingress,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
    }

    pub(crate) async fn resolve_inner(
        &self,
        raw_query: &[u8],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
        options: &ResolveOptions,
        mode: ResolveMode,
        evidence: Option<&mut crate::dns::outcome::RouteSource>,
    ) -> Result<DnsOutcome, DnsForwardError> {
        let mut observation =
            crate::observe::flows::dns::LookupGuard::start(raw_query, ingress, metadata);
        let publication_epoch = self.cache_service().await.publication_epoch();
        let resolve = crate::dns::engine::pipeline::resolve(
            self,
            raw_query,
            metadata,
            ingress,
            options,
            mode,
            publication_epoch,
            evidence,
        );
        let result = match &observation {
            Some(observation) => observation.scope(resolve).await,
            None => resolve.await,
        };
        if let Some(observation) = &mut observation {
            observation.outcome(&result);
        }
        match &result {
            Ok(outcome) => {
                let event = match (outcome.status(), outcome.response_class()) {
                    (OutcomeStatus::Rejected, _) => crate::stats::DnsStatEvent::OutcomeRejected,
                    (OutcomeStatus::Accepted, ResponseClass::Positive) => {
                        crate::stats::DnsStatEvent::OutcomePositive
                    }
                    (OutcomeStatus::Accepted, ResponseClass::Nodata) => {
                        crate::stats::DnsStatEvent::OutcomeNodata
                    }
                    (OutcomeStatus::Accepted, ResponseClass::Nxdomain) => {
                        crate::stats::DnsStatEvent::OutcomeNxdomain
                    }
                    (OutcomeStatus::Accepted, ResponseClass::Servfail) => {
                        crate::stats::DnsStatEvent::OutcomeServfail
                    }
                };
                crate::stats::record_dns_event(event);
                tracing::debug!(
                    status = ?outcome.status(),
                    class = ?outcome.response_class(),
                    provenance = ?outcome.provenance(),
                    "DNS resolution outcome"
                );
            }
            Err(error) => {
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::OutcomeError);
                let error_kind = match error.unshared() {
                    DnsForwardError::Engine(_) => "engine",
                    DnsForwardError::Exchange { .. } => "exchange",
                    DnsForwardError::Response(_) => "response",
                    DnsForwardError::Internal(_) => "internal",
                    DnsForwardError::RejectedPlanEscaped => "rejected_plan",
                    DnsForwardError::Overloaded => "overloaded",
                    DnsForwardError::Shared(_) => unreachable!("unwrapped shared failure"),
                };
                tracing::debug!(error_kind, "DNS resolution failed");
            }
        }
        result
    }
}
