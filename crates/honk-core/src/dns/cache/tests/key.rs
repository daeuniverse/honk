use crate::dns::planner::{RequestScope, UpstreamTag};
use crate::dns::policy::PolicyId;
use crate::dns::query::{IngressProfile, QueryContext};

use super::CacheSlot;
use super::{CacheKey, DnsCache, ExactLookup, OperationKind, make_test_response};

#[test]
fn exact_key_has_stable_typed_identity() {
    let key = CacheKey::for_test(
        vec![0, 0, 1],
        IngressProfile::Internal,
        RequestScope::Upstream(UpstreamTag::new("default").expect("tag")),
        OperationKind::Resolve,
    );
    let identical = key.clone();

    assert_eq!(key, identical);
    assert_eq!(key.shard_hash(), identical.shard_hash());
}

#[test]
fn cache_key_canonical_fields_are_separated_and_collision_checked() {
    let base = CacheKey::for_test(
        vec![0, 0, 1],
        IngressProfile::Internal,
        RequestScope::Upstream(UpstreamTag::new("default").expect("tag")),
        OperationKind::Resolve,
    );
    let variants = [
        CacheKey::for_test(
            vec![0, 0, 2],
            IngressProfile::Internal,
            base.scope().clone(),
            OperationKind::Resolve,
        ),
        CacheKey::for_test(
            vec![0, 0, 1],
            IngressProfile::Tcp,
            base.scope().clone(),
            OperationKind::Resolve,
        ),
        CacheKey::for_test(
            vec![0, 0, 1],
            IngressProfile::Internal,
            RequestScope::Upstream(UpstreamTag::new("other").expect("tag")),
            OperationKind::Resolve,
        ),
        CacheKey::for_test(
            vec![0, 0, 1],
            IngressProfile::Internal,
            base.scope().clone(),
            OperationKind::Refresh,
        ),
    ];

    for variant in variants {
        assert_ne!(base, variant);
    }
}

#[test]
fn exact_key_separates_wire_profile_policy_scope_and_operation() {
    let base_wire = crate::dns::forwarder::build_dns_query("Example.com", 1);
    let base_query = QueryContext::parse(&base_wire).expect("base query");
    let scope = RequestScope::Upstream(UpstreamTag::new("default").expect("scope"));
    let base = CacheKey::new(&base_query, None, scope.clone(), OperationKind::Resolve);
    let mut variants = Vec::new();
    for mutate in [
        |wire: &mut Vec<u8>| wire[13] = b'e',
        |wire: &mut Vec<u8>| wire[2] ^= 0x10,
        |wire: &mut Vec<u8>| {
            let end = wire.len();
            wire[end - 1] = 3;
        },
    ] {
        let mut wire = base_wire.clone();
        mutate(&mut wire);
        variants.push(CacheKey::new(
            &QueryContext::parse(&wire).expect("wire variant"),
            None,
            scope.clone(),
            OperationKind::Resolve,
        ));
    }
    let mut edns_wire = base_wire.clone();
    edns_wire[10..12].copy_from_slice(&1_u16.to_be_bytes());
    edns_wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    variants.push(CacheKey::new(
        &QueryContext::parse(&edns_wire).expect("edns"),
        None,
        scope.clone(),
        OperationKind::Resolve,
    ));
    variants.push(CacheKey::new(
        &QueryContext::parse_with_profile(&base_wire, IngressProfile::Tcp).expect("profile"),
        None,
        scope.clone(),
        OperationKind::Resolve,
    ));
    variants.push(CacheKey::new(
        &base_query,
        Some(PolicyId::from_config(&Default::default()).expect("policy")),
        scope.clone(),
        OperationKind::Resolve,
    ));
    variants.push(CacheKey::new(
        &base_query,
        None,
        RequestScope::Upstream(UpstreamTag::new("other").expect("other scope")),
        OperationKind::Resolve,
    ));
    variants.push(CacheKey::new(
        &base_query,
        None,
        scope,
        OperationKind::Refresh,
    ));

    assert!(variants.iter().all(|variant| variant != &base));
}

#[tokio::test]
async fn exact_negative_identity_isolated_and_flush_fenced() {
    let wire = crate::dns::forwarder::build_dns_query("negative.example", 1);
    let query = QueryContext::parse(&wire).expect("query");
    let scope = RequestScope::Upstream(UpstreamTag::new("default").expect("scope"));
    let key = CacheKey::new(&query, None, scope.clone(), OperationKind::Resolve);
    let other_scope = CacheKey::new(
        &query,
        None,
        RequestScope::Upstream(UpstreamTag::new("other").expect("other scope")),
        OperationKind::Resolve,
    );
    let refresh = CacheKey::new(&query, None, scope, OperationKind::Refresh);
    let cache = DnsCache::new(16);
    let service = cache.service();
    let old_epoch = service.publication_epoch();

    let _ = service.put_negative_if_current(old_epoch, key.clone(), 60, 3, None);
    assert_eq!(
        service.negative_hit_exact(&key).map(|hit| hit.rcode),
        Some(3)
    );
    assert!(service.negative_hit_exact(&other_scope).is_none());
    assert!(service.negative_hit_exact(&refresh).is_none());

    service
        .invalidate(crate::dns::cache::CacheInvalidation::All)
        .await
        .unwrap();
    assert!(service.negative_hit_exact(&key).is_none());
    let _ = service.put_negative_if_current(old_epoch, key.clone(), 60, 2, None);
    assert!(service.negative_hit_exact(&key).is_none());

    let _ = service.put_negative_if_current(service.publication_epoch(), key.clone(), 60, 2, None);
    assert_eq!(
        service.negative_hit_exact(&key).map(|hit| hit.rcode),
        Some(2)
    );
}

#[test]
fn expired_exact_negative_preserves_the_stale_positive() {
    let wire = crate::dns::forwarder::build_dns_query("stale-after-error.example", 1);
    let query = QueryContext::parse(&wire).expect("query");
    let key = CacheKey::new(
        &query,
        None,
        RequestScope::Upstream(UpstreamTag::new("default").expect("scope")),
        OperationKind::Resolve,
    );
    let response = make_test_response([192, 0, 2, 1], 300);
    let cache = DnsCache::new(1);
    let service = cache.service();

    service.put_exact(key.clone(), response.clone(), 300, None);
    service.put_negative_exact(key.clone(), 60, 2);
    assert_eq!(service.len(), 1);
    assert_eq!(service.get_exact(&key).unwrap().response.as_ref(), response);
    assert_eq!(
        service.negative_hit_exact(&key).map(|hit| hit.rcode),
        Some(2)
    );

    service.expire_positive_exact_for_test(&key);
    assert!(service.get_stale_exact(&key, true).is_some());
    service.insert_expired_negative_exact_for_test(key.clone(), 2);
    assert!(service.negative_hit_exact(&key).is_none());
    assert_eq!(
        service
            .get_stale_exact(&key, true)
            .unwrap()
            .0
            .response
            .as_ref(),
        response
    );
}

#[test]
fn expired_exact_negative_only_slot_is_removed() {
    let wire = crate::dns::forwarder::build_dns_query("expired-negative.example", 1);
    let query = QueryContext::parse(&wire).expect("query");
    let key = CacheKey::new(
        &query,
        None,
        RequestScope::Upstream(UpstreamTag::new("default").expect("scope")),
        OperationKind::Resolve,
    );
    let cache = DnsCache::new(1);
    let service = cache.service();
    service.insert_expired_negative_exact_for_test(key.clone(), 2);

    assert_eq!(service.len(), 1);
    assert!(service.negative_hit_exact(&key).is_none());
    assert_eq!(service.len(), 0);
}

#[test]
fn combined_exact_lookup_preserves_precedence_and_counts_once() {
    let wire = crate::dns::forwarder::build_dns_query("combined.example", 1);
    let query = QueryContext::parse(&wire).expect("query");
    let key = CacheKey::new(
        &query,
        None,
        RequestScope::Upstream(UpstreamTag::new("default").expect("scope")),
        OperationKind::Resolve,
    );
    let miss = CacheKey::new(
        &query,
        None,
        RequestScope::Upstream(UpstreamTag::new("other").expect("scope")),
        OperationKind::Resolve,
    );
    let response = make_test_response([192, 0, 2, 1], 300);
    let cache = DnsCache::new(4);
    let service = cache.service();
    service.put_exact(key.clone(), response.clone(), 300, None);
    service.put_negative_exact(key.clone(), 60, 2);

    let before = service.counters();
    assert!(matches!(
        service.lookup_exact(&key, true),
        ExactLookup::Negative { hit, .. } if hit.rcode == 2
    ));
    let after_negative = service.counters();
    assert_eq!(after_negative.hits, before.hits + 1);
    assert_eq!(after_negative.misses, before.misses);

    service.insert_expired_negative_exact_for_test(key.clone(), 2);
    match service.lookup_exact(&key, true) {
        ExactLookup::Positive { entry, .. } => {
            assert_eq!(entry.response.as_ref(), response.as_slice())
        }
        _ => panic!("expired negative must reveal the live positive"),
    }
    let after_positive = service.counters();
    assert_eq!(after_positive.hits, before.hits + 2);
    assert_eq!(after_positive.misses, before.misses);

    assert!(matches!(
        service.lookup_exact(&miss, true),
        ExactLookup::Miss
    ));
    let after_miss = service.counters();
    assert_eq!(after_miss.hits, before.hits + 2);
    assert_eq!(after_miss.misses, before.misses + 1);
}

#[test]
fn exact_negative_hit_promotes_before_same_shard_eviction() {
    let cache = DnsCache::new(32);
    let shard_count = cache.shard_capacities().len() as u64;
    let scope = RequestScope::Upstream(UpstreamTag::new("default").expect("scope"));
    let keys: Vec<_> = (0u16..=u16::MAX)
        .map(|index| {
            CacheKey::for_test(
                index.to_be_bytes().to_vec(),
                IngressProfile::Internal,
                scope.clone(),
                OperationKind::Resolve,
            )
        })
        .filter(|key| key.shard_hash() % shard_count == 0)
        .take(3)
        .collect();
    assert_eq!(keys.len(), 3, "need three exact keys in one shard");

    let negative = keys[0].clone();
    let positive = keys[1].clone();
    let eviction = keys[2].clone();
    let service = cache.service();
    service.put_negative_exact(negative.clone(), 60, 3);
    service.put_exact(
        positive.clone(),
        make_test_response([192, 0, 2, 1], 300),
        300,
        None,
    );

    for _ in 0..3 {
        assert!(matches!(
            service.lookup_exact(&negative, true),
            ExactLookup::Negative { hit, .. } if hit.rcode == 3
        ));
    }

    service.put_exact(eviction, make_test_response([192, 0, 2, 2], 300), 300, None);

    assert!(matches!(
        service.lookup_exact(&negative, true),
        ExactLookup::Negative { hit, .. } if hit.rcode == 3
    ));
    assert!(matches!(
        service.lookup_exact(&positive, true),
        ExactLookup::Miss
    ));
}

#[test]
fn conditional_publication_rejects_stale_revision_after_each_publication() {
    let key = CacheKey::new(
        &QueryContext::parse(&crate::dns::forwarder::build_dns_query(
            "revision.example",
            1,
        ))
        .expect("query"),
        None,
        RequestScope::Upstream(UpstreamTag::new("default").expect("scope")),
        OperationKind::Resolve,
    );
    let cache = DnsCache::new(4);
    let service = cache.service();
    let epoch = service.publication_epoch();
    service.put_exact(
        key.clone(),
        make_test_response([192, 0, 2, 1], 300),
        300,
        None,
    );
    let revision = match service.lookup_exact(&key, true) {
        ExactLookup::Positive { revision, .. } => revision,
        _ => panic!("positive fixture"),
    };
    let replacement = make_test_response([192, 0, 2, 2], 300);
    service.put_exact(key.clone(), replacement.clone(), 300, None);
    let _ = service.put_negative_if_current(epoch, key.clone(), 60, 3, Some(revision));
    assert!(matches!(
        service.lookup_exact(&key, true),
        ExactLookup::Positive { entry, .. } if entry.response.as_ref() == replacement.as_slice()
    ));

    let cache = DnsCache::new(4);
    let service = cache.service();
    let epoch = service.publication_epoch();
    service.put_exact(
        key.clone(),
        make_test_response([192, 0, 2, 3], 300),
        300,
        None,
    );
    let revision = match service.lookup_exact(&key, true) {
        ExactLookup::Positive { revision, .. } => revision,
        _ => panic!("positive fixture"),
    };
    let _ = service.put_negative_if_current(epoch, key.clone(), 60, 2, None);
    let _ = service.put_negative_if_current(epoch, key.clone(), 60, 3, Some(revision));
    assert!(matches!(
        service.lookup_exact(&key, true),
        ExactLookup::Negative { hit, .. } if hit.rcode == 2
    ));

    // Restored entries require compatibility-mode lookup.
    let cache = DnsCache::new(4);
    let service = cache.service();
    let epoch = service.publication_epoch();
    service.put_exact(
        key.clone(),
        make_test_response([192, 0, 2, 4], 300),
        300,
        None,
    );
    let revision = match service.lookup_exact(&key, true) {
        ExactLookup::Positive { revision, .. } => revision,
        _ => panic!("positive fixture"),
    };
    let restored = make_test_response([192, 0, 2, 5], 300);
    service.put_restored_exact_if_current(epoch, key.clone(), restored.clone(), 300);
    let _ = service.put_negative_if_current(epoch, key.clone(), 60, 3, Some(revision));
    assert!(matches!(
        service.lookup_exact(&key, false),
        ExactLookup::Positive { entry, .. } if entry.response.as_ref() == restored.as_slice()
    ));
}

#[test]
fn conditional_publication_rejects_evicted_and_reinserted_slot() {
    let wire = crate::dns::forwarder::build_dns_query("eviction.example", 1);
    let query = QueryContext::parse(&wire).expect("query");
    let key = CacheKey::new(
        &query,
        None,
        RequestScope::Upstream(UpstreamTag::new("default").expect("scope")),
        OperationKind::Resolve,
    );
    let other_wire = crate::dns::forwarder::build_dns_query("other.example", 1);
    let other_query = QueryContext::parse(&other_wire).expect("other query");
    let other = CacheKey::new(
        &other_query,
        None,
        RequestScope::Upstream(UpstreamTag::new("default").expect("scope")),
        OperationKind::Resolve,
    );
    let cache = DnsCache::new(1);
    let service = cache.service();
    let epoch = service.publication_epoch();

    service.put_exact(
        key.clone(),
        make_test_response([192, 0, 2, 1], 300),
        300,
        None,
    );
    let revision = match service.lookup_exact(&key, true) {
        ExactLookup::Positive { revision, .. } => revision,
        _ => panic!("positive fixture"),
    };
    service.put_exact(other, make_test_response([192, 0, 2, 2], 300), 300, None);
    let _ = service.put_negative_if_current(epoch, key.clone(), 60, 3, Some(revision));
    assert!(matches!(
        service.lookup_exact(&key, true),
        ExactLookup::Miss
    ));

    let reinserted = make_test_response([192, 0, 2, 3], 300);
    service.put_exact(key.clone(), reinserted.clone(), 300, None);
    let _ = service.put_negative_if_current(epoch, key.clone(), 60, 3, Some(revision));
    assert!(matches!(
        service.lookup_exact(&key, true),
        ExactLookup::Positive { entry, .. } if entry.response.as_ref() == reinserted.as_slice()
    ));
}

#[test]
fn matching_revision_nxdomain_removes_positive_and_keeps_negative() {
    let wire = crate::dns::forwarder::build_dns_query("matching.example", 1);
    let query = QueryContext::parse(&wire).expect("query");
    let key = CacheKey::new(
        &query,
        None,
        RequestScope::Upstream(UpstreamTag::new("default").expect("scope")),
        OperationKind::Resolve,
    );
    let cache = DnsCache::new(4);
    let service = cache.service();
    let epoch = service.publication_epoch();

    service.put_exact(
        key.clone(),
        make_test_response([192, 0, 2, 1], 300),
        300,
        None,
    );
    let revision = match service.lookup_exact(&key, true) {
        ExactLookup::Positive { revision, .. } => revision,
        _ => panic!("positive fixture"),
    };
    let _ = service.put_negative_if_current(epoch, key.clone(), 60, 3, Some(revision));
    assert!(matches!(
        service.lookup_exact(&key, true),
        ExactLookup::Negative { hit, .. } if hit.rcode == 3
    ));

    // The old token must not mutate the negative-only slot either.
    let _ = service.put_negative_if_current(epoch, key.clone(), 60, 2, Some(revision));
    assert!(matches!(
        service.lookup_exact(&key, true),
        ExactLookup::Negative { hit, .. } if hit.rcode == 3
    ));

    service.insert_expired_negative_exact_for_test(key.clone(), 3);
    assert!(matches!(
        service.lookup_exact(&key, true),
        ExactLookup::Miss
    ));
}

fn supersede_key(id: u8) -> CacheKey {
    CacheKey::for_test(
        vec![0, 0, id],
        IngressProfile::Internal,
        RequestScope::Upstream(UpstreamTag::new("default").expect("scope")),
        OperationKind::Resolve,
    )
}

#[test]
fn supersede_matching_revision_removes_combined_slot_and_releases_capacity() {
    let key = supersede_key(1);
    let service = DnsCache::new(4).service();
    let epoch = service.publication_epoch();
    service.put_exact(
        key.clone(),
        make_test_response([192, 0, 2, 1], 300),
        300,
        None,
    );
    service.put_negative_exact(key.clone(), 60, 3);
    let slot = CacheSlot::Exact(key.clone());
    let revision = super::super::lock(&service.shards[service.shard_index(&slot)])
        .get(&slot)
        .expect("combined cache slot")
        .revision;

    service.supersede_exact_if_current(epoch, key.clone(), Some(revision));
    assert!(matches!(
        service.lookup_exact(&key, true),
        ExactLookup::Miss
    ));
    assert!(service.get_stale_exact(&key, true).is_none());
    assert!(service.negative_hit_exact(&key).is_none());

    let mut replacement = make_test_response([192, 0, 2, 2], 300);
    replacement.resize(65_524, 0);
    service.put_exact(key.clone(), replacement.clone(), 300, None);
    assert_eq!(
        service
            .get_exact(&key)
            .expect("replacement retained")
            .response
            .as_ref(),
        replacement.as_slice()
    );
}

#[tokio::test]
async fn supersede_rejects_stale_epoch_nonaccepting_and_newer_revision() {
    for case in ["stale epoch", "nonaccepting", "old revision"] {
        let service = DnsCache::new(4).service();
        let key = supersede_key(2);
        let epoch = service.publication_epoch();
        if case == "stale epoch" {
            service
                .invalidate(crate::dns::cache::CacheInvalidation::All)
                .await
                .unwrap();
        }
        let response = make_test_response([192, 0, 2, 1], 300);
        service.put_exact(key.clone(), response.clone(), 300, None);
        let revision = match service.lookup_exact(&key, true) {
            ExactLookup::Positive { revision, .. } => revision,
            _ => panic!("positive fixture"),
        };
        if case == "old revision" {
            service.put_exact(key.clone(), response.clone(), 300, None);
        }
        if case == "nonaccepting" {
            super::super::lock(&service.publication).accepting = false;
        }
        service.supersede_exact_if_current(epoch, key.clone(), Some(revision));
        assert!(
            matches!(
                service.lookup_exact(&key, true),
                ExactLookup::Positive { entry, .. } if entry.response.as_ref() == response.as_slice()
            ),
            "{case}"
        );
    }
}
