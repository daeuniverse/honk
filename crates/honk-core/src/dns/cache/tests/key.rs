use crate::dns::planner::{RequestScope, UpstreamTag};
use crate::dns::policy::PolicyId;
use crate::dns::query::{IngressProfile, QueryContext};

use super::{CacheKey, DnsCache, ExactLookup, OperationKind, make_test_response};

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

#[test]
fn exact_negative_identity_isolated_and_flush_fenced() {
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

    service.put_negative_if_current(old_epoch, key.clone(), 60, 3);
    assert_eq!(
        service.negative_hit_exact(&key).map(|hit| hit.rcode),
        Some(3)
    );
    assert!(service.negative_hit_exact(&other_scope).is_none());
    assert!(service.negative_hit_exact(&refresh).is_none());

    let flush = service.begin_flush();
    assert!(service.negative_hit_exact(&key).is_none());
    service.put_negative_if_current(old_epoch, key.clone(), 60, 2);
    assert!(service.negative_hit_exact(&key).is_none());
    drop(flush);

    service.put_negative_if_current(service.publication_epoch(), key.clone(), 60, 2);
    assert_eq!(
        service.negative_hit_exact(&key).map(|hit| hit.rcode),
        Some(2)
    );
}
#[test]
fn exact_removal_isolated_and_flush_fenced() {
    let wire = crate::dns::forwarder::build_dns_query("remove.example", 1);
    let query = QueryContext::parse(&wire).expect("query");
    let key = CacheKey::new(
        &query,
        None,
        RequestScope::Upstream(UpstreamTag::new("default").expect("scope")),
        OperationKind::Resolve,
    );
    let other = CacheKey::new(
        &query,
        None,
        RequestScope::Upstream(UpstreamTag::new("other").expect("scope")),
        OperationKind::Resolve,
    );
    let response = make_test_response([192, 0, 2, 10], 300);
    let cache = DnsCache::new(64);
    let service = cache.service();
    let old_epoch = service.publication_epoch();
    service.put_exact(key.clone(), response.clone(), 300);
    service.put_exact(other.clone(), response, 300);
    assert!(service.get_exact(&key).is_some());
    service.put_negative_if_current(old_epoch, key.clone(), 60, 3);
    assert!(service.negative_hit_exact(&key).is_some());

    service.remove_exact_if_current(old_epoch, key.clone());
    assert!(service.get_exact(&key).is_none());
    assert!(service.negative_hit_exact(&key).is_none());
    assert!(service.get_exact(&other).is_some());

    let flush = service.begin_flush();
    drop(flush);
    service.put_exact(key.clone(), make_test_response([192, 0, 2, 11], 300), 300);
    service.remove_exact_if_current(old_epoch, key.clone());
    assert!(service.get_exact(&key).is_some());
    service.remove_exact_if_current(service.publication_epoch(), key.clone());
    assert!(service.get_exact(&key).is_none());
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

    service.put_exact(key.clone(), response.clone(), 300);
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
    service.put_exact(key.clone(), response.clone(), 300);
    service.put_negative_exact(key.clone(), 60, 2);

    let before = service.counters();
    assert!(matches!(
        service.lookup_exact(&key, true),
        ExactLookup::Negative(hit) if hit.rcode == 2
    ));
    let after_negative = service.counters();
    assert_eq!(after_negative.hits, before.hits + 1);
    assert_eq!(after_negative.misses, before.misses);

    service.insert_expired_negative_exact_for_test(key.clone(), 2);
    match service.lookup_exact(&key, true) {
        ExactLookup::Positive(entry) => assert_eq!(entry.response.as_ref(), response.as_slice()),
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
