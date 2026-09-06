use std::time::Duration;

use tracing::debug;

use super::{ExecutionContext, cache};
use crate::dns::engine::ResponseDirective;
use crate::dns::forwarder::{
    DnsForwardError, ResolveMode, SERVE_STALE_TTL_SECS, make_empty_response, traversal_strings,
};
use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance, ResponseClass};
use crate::dns::planner::{ResponseTraversal, UpstreamTag};
use crate::dns::singleflight::FlightLeader;

pub(super) async fn run_as_leader(
    leader: FlightLeader,
    context: &ExecutionContext<'_>,
) -> Result<DnsOutcome, DnsForwardError> {
    match run(context).await {
        Ok(outcome) => Ok(super::flight::publish_outcome(leader, outcome)),
        Err(error) => Err(leader.fail(error)),
    }
}

pub(super) async fn run(context: &ExecutionContext<'_>) -> Result<DnsOutcome, DnsForwardError> {
    let upstream_result = context
        .forwarder
        .exchange(
            &context.request_scope,
            context.raw_query,
            context.prepared.query().ingress(),
        )
        .await;
    let (mut response, mut upstream_name) = match upstream_result {
        Ok(response) => (response, context.logical_upstream.clone()),
        Err(source) => {
            if context.reuse_eligible
                && let Some(stale) = stale_outcome(
                    context,
                    &context.logical_upstream,
                    vec![context.logical_upstream.as_str().to_owned()],
                )
                .await?
            {
                return Ok(stale);
            }
            return Err(DnsForwardError::Exchange {
                upstream: context.logical_upstream.as_str().to_owned(),
                source,
            });
        }
    };

    let mut traversal = ResponseTraversal::start(context.logical_upstream.clone());
    let mut strict_reusable = true;
    let (status, class, analyzed_answer_ips) = loop {
        match context.engine.analyze(
            context.prepared,
            traversal,
            response,
            matches!(context.mode, ResolveMode::Strict) || context.bypass_cache_read,
        )? {
            ResponseDirective::Accept {
                response: analyzed,
                traversal: accepted,
            } => {
                strict_reusable &= analyzed.strict_reusable;
                let class = analyzed.class;
                if context.reuse_eligible
                    && class == ResponseClass::Servfail
                    && let Some(stale) =
                        stale_outcome(context, &upstream_name, traversal_strings(&accepted)).await?
                {
                    return Ok(stale);
                }
                let wire_len = analyzed.wire.len();
                response = analyzed.wire;
                traversal = accepted;
                break (
                    OutcomeStatus::Accepted,
                    class,
                    Some((wire_len, analyzed.answer_ips)),
                );
            }
            ResponseDirective::Reject {
                response: analyzed,
                traversal: rejected,
            } => {
                strict_reusable &= analyzed.strict_reusable;
                response = make_empty_response(context.raw_query, context.prepared.query());
                traversal = rejected;
                break (OutcomeStatus::Rejected, analyzed.class, None);
            }
            ResponseDirective::Requery {
                upstream,
                traversal: next,
                strict_reusable: response_strict_reusable,
            } => {
                strict_reusable &= response_strict_reusable;
                response = context
                    .forwarder
                    .upstream_pool
                    .query(upstream.as_str(), context.raw_query)
                    .await
                    .map_err(|source| DnsForwardError::Exchange {
                        upstream: upstream.as_str().to_owned(),
                        source,
                    })?;
                upstream_name = upstream;
                traversal = next;
            }
        }
    };

    let exact_cache_key = context.cache_key.clone();
    let expiry = if strict_reusable {
        cache::store(context, &exact_cache_key, &mut response, class).await
    } else {
        EffectiveExpiry::do_not_cache()
    };
    debug!(
        ttl = expiry.ttl().as_secs(),
        bytes = response.len(),
        "DNS forwarder: resolved query"
    );
    let response = context
        .forwarder
        .apply_prefer_strategy(
            context.raw_query,
            context.prepared.query(),
            context.prepared.qtype(),
            response.into(),
            context.metadata,
            context.mode,
        )
        .await?;
    context.forwarder.outcome_from_wire(
        context.engine,
        context.prepared,
        response,
        analyzed_answer_ips,
        status,
        Provenance::Upstream,
        expiry,
        Some(context.logical_upstream.as_str().to_owned()),
        Some(upstream_name.as_str().to_owned()),
        traversal_strings(&traversal),
        context.mode,
    )
}

async fn stale_outcome(
    context: &ExecutionContext<'_>,
    final_upstream: &UpstreamTag,
    history: Vec<String>,
) -> Result<Option<DnsOutcome>, DnsForwardError> {
    let Some(stale) = context
        .forwarder
        .try_serve_stale(&context.cache_key, context.raw_query, context.mode)
        .await
    else {
        return Ok(None);
    };
    let stale = context
        .forwarder
        .apply_prefer_strategy(
            context.raw_query,
            context.prepared.query(),
            context.prepared.qtype(),
            stale.into(),
            context.metadata,
            context.mode,
        )
        .await?;
    context
        .forwarder
        .outcome_from_wire(
            context.engine,
            context.prepared,
            stale,
            None,
            OutcomeStatus::Accepted,
            Provenance::Stale,
            EffectiveExpiry::cacheable(Duration::from_secs(u64::from(SERVE_STALE_TTL_SECS))),
            Some(context.logical_upstream.as_str().to_owned()),
            Some(final_upstream.as_str().to_owned()),
            history,
            context.mode,
        )
        .map(Some)
}
