use tracing::debug;

use super::{DnsEngine, PreparedQuery};
use crate::dns::cache::{CacheKey, OperationKind, PublicationEpoch};
use crate::dns::forwarder::{DnsForwardError, DnsForwarder, ResolveMode, is_filtered_qtype};
use crate::dns::outcome::{DnsOutcome, OutcomeStatus};
use crate::dns::planner::{RequestPlan, RequestScope, UpstreamTag};
use crate::dns::query::{DnsRequestMeta, IngressProfile};
use crate::dns::singleflight::{FlightKey, FlightLeader, FlightRole};

mod cache;
mod flight {
    use std::sync::Arc;

    use super::{ExecutionContext, cache};
    use crate::dns::forwarder::DnsForwardError;
    use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance};
    use crate::dns::response::ResponseTemplate;
    use crate::dns::singleflight::FlightLeader;

    pub(super) fn publish_outcome(mut leader: FlightLeader, outcome: DnsOutcome) -> DnsOutcome {
        if let Some(template) = outcome.template() {
            leader.publish(Arc::new(template.clone()));
        }
        outcome
    }

    pub(super) async fn waiter_outcome(
        context: &ExecutionContext<'_>,
        template: Arc<ResponseTemplate>,
    ) -> Result<DnsOutcome, DnsForwardError> {
        if !context.bypass_cache_read
            && let Some(outcome) = cache::lookup(context, false).await?
        {
            return Ok(outcome);
        }
        context.forwarder.outcome_from_wire(
            context.engine,
            context.prepared,
            template.wire(),
            None,
            OutcomeStatus::Accepted,
            Provenance::Upstream,
            EffectiveExpiry::do_not_cache(),
            None,
            None,
            Vec::new(),
            context.mode,
        )
    }
}
mod operation;
mod plan {
    use super::super::{DnsEngine, EngineError, PreparedQuery};
    use crate::dns::forwarder::{DnsForwardError, DnsForwarder, ResolveMode, make_empty_response};
    use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance};
    use crate::dns::planner::{RequestPlan, RequestScope, UpstreamTag};

    pub(super) fn request_exchange(
        prepared: &PreparedQuery,
    ) -> Result<(UpstreamTag, &RequestScope), DnsForwardError> {
        match prepared.plan() {
            RequestPlan::Exchange(scope @ RequestScope::AsIs(_)) => {
                Ok((UpstreamTag::new("asis").map_err(EngineError::from)?, scope))
            }
            RequestPlan::Exchange(scope @ RequestScope::Upstream(upstream)) => {
                Ok((upstream.clone(), scope))
            }
            RequestPlan::Reject => Err(DnsForwardError::RejectedPlanEscaped),
        }
    }

    pub(super) fn rejected_outcome(
        forwarder: &DnsForwarder,
        engine: &DnsEngine,
        prepared: &PreparedQuery,
        raw_query: &[u8],
        mode: ResolveMode,
        status: OutcomeStatus,
    ) -> Result<DnsOutcome, DnsForwardError> {
        forwarder.outcome_from_wire(
            engine,
            prepared,
            make_empty_response(raw_query, prepared.query()),
            None,
            status,
            Provenance::Fresh,
            EffectiveExpiry::do_not_cache(),
            None,
            None,
            Vec::new(),
            mode,
        )
    }
}

use plan::{rejected_outcome, request_exchange};

pub(crate) struct ResolveExecution {
    refresh_owner: Option<FlightLeader>,
    publication_epoch: PublicationEpoch,
}

pub(super) struct ExecutionContext<'a> {
    pub(super) forwarder: &'a DnsForwarder,
    pub(super) engine: &'a DnsEngine,
    pub(super) prepared: &'a PreparedQuery,
    pub(super) raw_query: &'a [u8],
    pub(super) metadata: DnsRequestMeta,
    pub(super) cache_key: CacheKey,
    pub(super) logical_upstream: UpstreamTag,
    pub(super) request_scope: RequestScope,
    pub(super) reuse_eligible: bool,
    pub(super) bypass_cache_read: bool,
    pub(super) mode: ResolveMode,
    pub(super) publication_epoch: PublicationEpoch,
}

impl ResolveExecution {
    pub(crate) const fn foreground(publication_epoch: PublicationEpoch) -> Self {
        Self {
            refresh_owner: None,
            publication_epoch,
        }
    }

    pub(crate) const fn refresh(owner: FlightLeader, publication_epoch: PublicationEpoch) -> Self {
        Self {
            refresh_owner: Some(owner),
            publication_epoch,
        }
    }
}

pub(crate) async fn resolve(
    forwarder: &DnsForwarder,
    raw_query: &[u8],
    metadata: DnsRequestMeta,
    ingress: IngressProfile,
    bypass_cache_read: bool,
    mode: ResolveMode,
    publication_epoch: PublicationEpoch,
) -> Result<DnsOutcome, DnsForwardError> {
    resolve_with_owner(
        forwarder,
        raw_query,
        metadata,
        ingress,
        bypass_cache_read,
        mode,
        ResolveExecution::foreground(publication_epoch),
    )
    .await
}

pub(crate) async fn resolve_with_owner(
    forwarder: &DnsForwarder,
    raw_query: &[u8],
    metadata: DnsRequestMeta,
    ingress: IngressProfile,
    bypass_cache_read: bool,
    mode: ResolveMode,
    execution: ResolveExecution,
) -> Result<DnsOutcome, DnsForwardError> {
    let ResolveExecution {
        refresh_owner,
        publication_epoch,
    } = execution;
    debug!("DNS forwarder: resolving {} bytes", raw_query.len());
    let engine = forwarder.engine().await?;
    let parsed = DnsEngine::parse_query(raw_query, ingress)?;
    let qtype = parsed.qtype();
    if !is_filtered_qtype(qtype, &forwarder.strategy)
        && let Some(outcome) = forwarder.resolve_hosts(engine, &parsed, raw_query, mode)?
    {
        return Ok(outcome);
    }
    let prepared =
        engine.prepare_parsed(parsed, metadata, matches!(mode, ResolveMode::Compatibility))?;
    let reuse_eligible = prepared.is_cacheable() && prepared.is_coalescable();

    if is_filtered_qtype(qtype, &forwarder.strategy) {
        return rejected_outcome(
            forwarder,
            engine,
            &prepared,
            raw_query,
            mode,
            OutcomeStatus::Rejected,
        );
    }
    if matches!(prepared.plan(), RequestPlan::Reject) {
        return rejected_outcome(
            forwarder,
            engine,
            &prepared,
            raw_query,
            mode,
            OutcomeStatus::Rejected,
        );
    }

    let (logical_upstream, request_scope) = request_exchange(&prepared)?;
    let resolve_key = prepared.cache_key(request_scope.clone(), OperationKind::Resolve);
    let context = ExecutionContext {
        forwarder,
        engine,
        prepared: &prepared,
        raw_query,
        metadata,
        cache_key: resolve_key,
        logical_upstream,
        request_scope: request_scope.clone(),
        reuse_eligible,
        bypass_cache_read,
        mode,
        publication_epoch,
    };
    if reuse_eligible && let Some(outcome) = cache::lookup(&context, true).await? {
        return Ok(outcome);
    }

    if !reuse_eligible {
        return operation::run(&context).await;
    }

    if let Some(owner) = refresh_owner {
        return operation::run_as_leader(owner, &context).await;
    }

    let flight_key = if bypass_cache_read {
        FlightKey::Refresh(context.cache_key.with_operation(OperationKind::Refresh))
    } else {
        FlightKey::resolve(
            context.cache_key.clone(),
            mode,
            &forwarder.strategy,
            qtype,
            metadata,
        )
    };
    let flights = forwarder.cache_service().await.singleflight();
    loop {
        match flights.acquire(flight_key.clone()) {
            FlightRole::Rejected => return Err(DnsForwardError::Overloaded),
            FlightRole::Ready(template) => {
                return flight::waiter_outcome(&context, template).await;
            }
            FlightRole::Waiter(waiter) => match waiter.receive().await {
                Some(template) => {
                    return flight::waiter_outcome(&context, template).await;
                }
                None => continue,
            },
            FlightRole::Leader(leader) => {
                if !bypass_cache_read && let Some(outcome) = cache::lookup(&context, true).await? {
                    return Ok(flight::publish_outcome(leader, outcome));
                }
                return operation::run_as_leader(leader, &context).await;
            }
        }
    }
}
