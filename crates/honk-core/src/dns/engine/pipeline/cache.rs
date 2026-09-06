use tracing::debug;

use super::super::effective_expiry;
use super::ExecutionContext;
use crate::dns::cache::{CacheKey, ExactLookup, OperationKind};
use crate::dns::forwarder::{
    DnsForwardError, ResolveMode, extract_min_ttl, extract_soa_negative_ttl, rewrite_answer_ttls,
};
use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance, ResponseClass};

pub(super) async fn lookup(
    context: &ExecutionContext<'_>,
    allow_refresh: bool,
) -> Result<Option<DnsOutcome>, DnsForwardError> {
    if !context.forwarder.cache_enabled || context.bypass_cache_read {
        return Ok(None);
    }
    let cache = context.forwarder.cache_service().await;
    let entry = match cache.lookup_exact(
        &context.cache_key,
        matches!(context.mode, ResolveMode::Strict),
    ) {
        ExactLookup::Negative(hit) => {
            let response =
                crate::dns::response::build_dns_error_response(context.raw_query, hit.rcode);
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
            return context
                .forwarder
                .outcome_from_wire(
                    context.engine,
                    context.prepared,
                    response,
                    None,
                    OutcomeStatus::Accepted,
                    Provenance::Cache,
                    EffectiveExpiry::cacheable(hit.remaining_ttl),
                    None,
                    None,
                    Vec::new(),
                    context.mode,
                )
                .map(Some);
        }
        ExactLookup::Positive(entry) => entry,
        ExactLookup::Miss => return Ok(None),
    };
    let remaining = entry.remaining_ttl_secs();
    debug!(remaining, "DNS forwarder: positive cache hit");
    let refresh_after = (entry.min_ttl as u64 / 10).max(1);
    if allow_refresh && remaining <= refresh_after {
        let refresh_key = context.cache_key.with_operation(OperationKind::Refresh);
        context.forwarder.maybe_spawn_refresh(
            context.raw_query,
            context.metadata,
            context.mode,
            refresh_key,
            context.publication_epoch,
        );
    }
    let response = entry.response;
    let response = context
        .forwarder
        .apply_prefer_strategy(
            context.raw_query,
            context.prepared.query(),
            context.prepared.qtype(),
            response,
            context.metadata,
            context.mode,
        )
        .await?;
    context
        .forwarder
        .outcome_from_wire(
            context.engine,
            context.prepared,
            response,
            None,
            OutcomeStatus::Accepted,
            Provenance::Cache,
            EffectiveExpiry::cacheable(std::time::Duration::from_secs(remaining)),
            None,
            None,
            Vec::new(),
            context.mode,
        )
        .map(Some)
}

pub(super) async fn store(
    context: &ExecutionContext<'_>,
    cache_key: &CacheKey,
    response: &mut [u8],
    class: ResponseClass,
) -> EffectiveExpiry {
    if !context.reuse_eligible {
        return EffectiveExpiry::do_not_cache();
    }
    if matches!(class, ResponseClass::Nxdomain | ResponseClass::Servfail) {
        let negative_ttl = extract_soa_negative_ttl(response, 60).clamp(1, 300);
        if context.forwarder.cache_enabled {
            let rcode = response.get(3).copied().unwrap_or_default() & 0x0f;
            context
                .forwarder
                .cache_service()
                .await
                .put_negative_if_current(
                    context.publication_epoch,
                    cache_key.clone(),
                    negative_ttl,
                    rcode,
                );
        }
        return EffectiveExpiry::cacheable(std::time::Duration::from_secs(u64::from(negative_ttl)));
    }

    let answer_ttl = extract_min_ttl(response);
    let expiry = effective_expiry(
        context
            .forwarder
            .routing
            .fixed_ttl(context.prepared.domain()),
        context.forwarder.cache_ttl,
        answer_ttl,
    );
    if context.forwarder.cache_enabled && expiry.is_cacheable() {
        let cache_ttl = expiry.ttl().as_secs().min(u64::from(u32::MAX)) as u32;
        rewrite_answer_ttls(response, cache_ttl);
        context
            .forwarder
            .cache_service()
            .await
            .put_exact_if_current(
                context.publication_epoch,
                cache_key.clone(),
                response.to_owned(),
                cache_ttl,
            );
    }
    expiry
}
