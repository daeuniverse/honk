use tracing::debug;

use super::super::effective_expiry;
use super::ExecutionContext;
use crate::dns::cache::{CacheKey, ExactLookup, OperationKind};
use crate::dns::forwarder::{
    CacheAccess, DnsForwardError, ResolveMode, extract_min_ttl, extract_min_ttl_including_zero,
    extract_soa_negative_ttl, rewrite_answer_ttls,
};
use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance, ResponseClass};

pub(super) async fn lookup(
    context: &ExecutionContext<'_>,
    allow_refresh: bool,
) -> Result<Option<DnsOutcome>, DnsForwardError> {
    if !context.forwarder.cache_enabled || context.options.cache != CacheAccess::Normal {
        return Ok(None);
    }
    let cache = context.forwarder.cache_service().await;
    crate::observe::flows::dns::cache_state("miss");
    let (entry, revision) = match cache.lookup_exact(
        &context.cache_key,
        matches!(context.mode, ResolveMode::Strict),
    ) {
        ExactLookup::Negative {
            hit,
            revision: _revision,
        } => {
            crate::observe::flows::dns::cache_state("hit");
            #[cfg(feature = "native-api")]
            let entry_id = cache.entry_id_for_revision(&context.cache_key, _revision);
            #[cfg(feature = "native-api")]
            crate::observe::flows::dns::cache_entry(entry_id.as_deref());
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
                    context.options,
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
                .map(|outcome| {
                    #[cfg(feature = "native-api")]
                    let outcome = outcome.with_cache_entry_id(entry_id);
                    Some(outcome)
                });
        }
        ExactLookup::Positive { entry, revision } => {
            crate::observe::flows::dns::cache_state("hit");
            (entry, revision)
        }
        ExactLookup::Miss => return Ok(None),
    };
    #[cfg(feature = "native-api")]
    let entry_id = cache.entry_id_for_revision(&context.cache_key, revision);
    #[cfg(feature = "native-api")]
    crate::observe::flows::dns::cache_entry(entry_id.as_deref());
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
            revision,
            context.options,
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
            context.options,
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
        .map(|outcome| {
            #[cfg(feature = "native-api")]
            let outcome = outcome.with_cache_entry_id(entry_id);
            Some(outcome)
        })
}

pub(super) async fn store(
    context: &ExecutionContext<'_>,
    cache_key: &CacheKey,
    response: &mut [u8],
    rejected_wire: Option<&[u8]>,
    class: ResponseClass,
) -> (EffectiveExpiry, Option<u64>) {
    let lifetime_wire = rejected_wire.unwrap_or(response);
    if !context.reuse_eligible {
        return (EffectiveExpiry::do_not_cache(), None);
    }
    let fixed_ttl = context
        .forwarder
        .routing
        .fixed_ttl(context.prepared.domain());
    if fixed_ttl == Some(0) {
        return (EffectiveExpiry::do_not_cache(), None);
    }
    // Rejection rewrites the reply to NOERROR, not the upstream TTL policy.
    let rcode = lifetime_wire.get(3).copied().unwrap_or_default() & 0x0f;
    let negative = matches!(class, ResponseClass::Nxdomain | ResponseClass::Servfail);
    let expiry = if negative {
        let soa_ttl = extract_soa_negative_ttl(lifetime_wire);
        let ttl = if class == ResponseClass::Nxdomain {
            soa_ttl.unwrap_or(0).min(300)
        } else {
            soa_ttl.unwrap_or(60).clamp(1, 300)
        };
        effective_expiry(None, 0, ttl)
    } else if class == ResponseClass::Nodata && rcode == 0 {
        let ttl = fixed_ttl.unwrap_or_else(|| {
            extract_soa_negative_ttl(lifetime_wire)
                .unwrap_or(0)
                .min(300)
        });
        effective_expiry(None, 0, ttl)
    } else {
        let answer_ttl = if class == ResponseClass::Positive && rcode == 0 {
            extract_min_ttl_including_zero(lifetime_wire)
        } else {
            extract_min_ttl(lifetime_wire)
        };
        effective_expiry(fixed_ttl, context.forwarder.cache_ttl, answer_ttl)
    };
    let mut revision = None;
    if context.forwarder.cache_enabled {
        let cache = context.forwarder.cache_service().await;
        if !expiry.is_cacheable() {
            cache.supersede_exact_if_current(
                context.publication_epoch,
                cache_key.clone(),
                context.refreshing,
            );
        } else {
            let cache_ttl = expiry.ttl().as_secs().min(u64::from(u32::MAX)) as u32;
            if negative {
                revision = cache.put_negative_if_current(
                    context.publication_epoch,
                    cache_key.clone(),
                    cache_ttl,
                    rcode,
                    context.refreshing,
                );
            } else {
                rewrite_answer_ttls(response, cache_ttl);
                revision = cache.put_exact_if_current(
                    context.publication_epoch,
                    cache_key.clone(),
                    response.to_owned(),
                    cache_ttl,
                    context.refreshing,
                );
            }
        }
    }
    (expiry, revision)
}
