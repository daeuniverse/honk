use std::thread;
use std::time::Duration;

use crate::dns::planner::{RequestScope, UpstreamTag};
use crate::dns::query::IngressProfile;

use super::{CacheKey, DnsCache, ExactLookup, OperationKind, make_test_response};

#[test]
fn test_put_get() {
    let mut cache = DnsCache::new(10);
    let response = make_test_response([93, 184, 216, 34], 300);
    cache.put("example.com:1".into(), response.clone(), 300);

    let entry = cache.get("example.com:1").expect("entry should exist");
    assert_eq!(entry.response, response);
    assert_eq!(entry.min_ttl, 300);
    assert!(!entry.is_expired());
}

#[test]
fn truncated_responses_are_not_cached() {
    let mut cache = DnsCache::new(10);
    let mut response = make_test_response([192, 0, 2, 1], 300);
    response[2..4].copy_from_slice(&0x8380_u16.to_be_bytes());

    cache.put("truncated.example:1".into(), response, 300);

    assert!(cache.get("truncated.example:1").is_none());
}

#[test]
fn legacy_negative_replaces_the_positive_for_the_same_key() {
    let mut cache = DnsCache::new(10);
    let key = "negative.example:1";
    cache.put(key.into(), make_test_response([192, 0, 2, 1], 300), 300);

    cache.put_negative(key.into(), 60, 3);

    assert!(cache.get(key).is_none());
    assert_eq!(cache.negative_rcode(key), Some(3));
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.retained_bytes(), 0);
}

#[test]
fn test_expiry() {
    let mut cache = DnsCache::new(10);
    let response = make_test_response([93, 184, 216, 34], 0);
    cache.put("example.com:1".into(), response, 0);

    assert!(cache.get("example.com:1").is_some());
    thread::sleep(Duration::from_secs(2));
    assert!(cache.get("example.com:1").is_none());
}

#[test]
fn test_lru_eviction() {
    let mut cache = DnsCache::new(2);
    let keys: Vec<String> = (0..100)
        .map(|index| format!("same-shard-{index}:1"))
        .filter(|key| cache.shard_index(key) == 0)
        .take(2)
        .collect();
    let first = keys.first().expect("first key").clone();
    let second = keys.get(1).expect("second key").clone();

    cache.put(first.clone(), make_test_response([1, 1, 1, 1], 300), 300);
    cache.put(second.clone(), make_test_response([2, 2, 2, 2], 300), 300);

    assert!(cache.get(&first).is_none());
    assert!(cache.get(&second).is_some());
}

#[test]
fn maximum_answer_is_admitted_and_same_key_oversize_preserves_it() {
    let cache = DnsCache::new(1);
    let service = cache.service();
    let key = CacheKey::for_test(
        vec![0, 0, 1],
        IngressProfile::Internal,
        RequestScope::Upstream(UpstreamTag::new("default").expect("scope")),
        OperationKind::Resolve,
    );
    let mut response = make_test_response([192, 0, 2, 1], 300);
    response.resize(65_535, 0);
    let epoch = service.publication_epoch();
    let revision = service
        .put_exact_if_current(epoch, key.clone(), response.clone(), 300, None)
        .expect("the largest DNS answer fits a minimum-capacity shard");
    assert!(matches!(
        service.lookup_exact(&key, true),
        ExactLookup::Positive { entry, .. } if entry.response.as_ref() == response.as_slice()
    ));
    assert_eq!(cache.retained_bytes(), 65_535);

    let mut oversized = response.clone();
    oversized.push(0);
    assert!(
        service
            .put_exact_if_current(epoch, key.clone(), oversized, 300, None)
            .is_none()
    );
    assert!(matches!(
        service.lookup_exact(&key, true),
        ExactLookup::Positive { entry, revision: current }
            if entry.response.as_ref() == response.as_slice() && current == revision
    ));
    assert_eq!(service.len(), 1);
    assert_eq!(cache.retained_bytes(), 65_535);
}

#[test]
fn exact_byte_budget_scales_and_evicts_only_the_shard_lru_one_byte_above() {
    let cache = DnsCache::new(16 * 65);
    let shard_count = cache.shard_capacities().len() as u64;
    let scope = RequestScope::Upstream(UpstreamTag::new("default").expect("scope"));
    let mut candidates = (0u16..=u16::MAX).map(|index| {
        CacheKey::for_test(
            index.to_be_bytes().to_vec(),
            IngressProfile::Internal,
            scope.clone(),
            OperationKind::Resolve,
        )
    });
    let unrelated = candidates
        .find(|key| key.shard_hash() % shard_count != 0)
        .expect("key in another shard");
    let keys: Vec<_> = candidates
        .filter(|key| key.shard_hash() % shard_count == 0)
        .take(3)
        .collect();
    assert_eq!(keys.len(), 3, "need three exact keys in one shard");
    let service = cache.service();
    let epoch = service.publication_epoch();
    for (key, size) in [(&unrelated, 65_535), (&keys[0], 33_000), (&keys[1], 33_560)] {
        service
            .put_exact_if_current(epoch, key.clone(), vec![0; size], 300, None)
            .expect("answer admitted");
    }
    assert!(
        service
            .put_exact_if_current(epoch, keys[2].clone(), vec![0; 65_536], 300, None)
            .is_none()
    );

    for key in [&keys[1], &keys[0]] {
        assert!(matches!(
            service.lookup_exact(key, true),
            ExactLookup::Positive { .. }
        ));
    }
    assert_eq!(cache.retained_bytes(), 65_535 + 65 * 1024);

    service
        .put_exact_if_current(epoch, keys[2].clone(), vec![0; 1], 300, None)
        .expect("one-byte answer admitted");
    assert!(matches!(
        service.lookup_exact(&keys[1], true),
        ExactLookup::Miss
    ));
    for key in [&keys[0], &keys[2], &unrelated] {
        assert!(matches!(
            service.lookup_exact(key, true),
            ExactLookup::Positive { .. }
        ));
    }
    assert_eq!(service.len(), 3);
    assert_eq!(cache.retained_bytes(), 65_535 + 33_000 + 1);
}

#[test]
fn entry_count_eviction_releases_answer_bytes() {
    let mut cache = DnsCache::new(100);
    for index in 0..2_000 {
        cache.put(format!("churn-{index}:1"), vec![0; 500], 300);
    }

    assert_eq!(cache.len(), 100);
    assert_eq!(cache.retained_bytes(), 100 * 500);
}

#[test]
fn shard_capacities_sum_exactly_and_clamp_count() {
    for capacity in (1..=33).chain([10_000, 99_999, 100_000]) {
        let cache = DnsCache::new(capacity);
        let capacities = cache.shard_capacities();
        assert_eq!(capacities.len(), capacity.min(16));
        assert_eq!(capacities.iter().sum::<usize>(), capacity);
        assert!(capacities.windows(2).all(|pair| pair[0] >= pair[1]));
        assert!(capacities.windows(2).all(|pair| pair[0] - pair[1] <= 1));
    }
}

#[test]
fn max_cache_size_is_clamped_to_one_hundred_thousand() {
    for requested in [100_001, 1_000_000_000, usize::MAX] {
        let capacities = DnsCache::new(requested).shard_capacities();
        assert_eq!(capacities.iter().sum::<usize>(), 100_000, "{requested}");
    }
}

#[test]
fn test_remove_entry() {
    let mut cache = DnsCache::new(10);
    cache.put(
        "dns.google:1".into(),
        make_test_response([8, 8, 8, 8], 300),
        300,
    );

    assert!(cache.get("dns.google:1").is_some());
    assert!(cache.remove("dns.google:1").is_some());
    assert!(cache.get("dns.google:1").is_none());
    assert_eq!(cache.retained_bytes(), 0);
}

#[test]
fn test_clear() {
    let mut cache = DnsCache::new(10);
    cache.put("a.com:1".into(), make_test_response([1, 1, 1, 1], 300), 300);
    cache.put("b.com:1".into(), make_test_response([2, 2, 2, 2], 300), 300);
    assert_eq!(cache.len(), 2);

    cache.clear();
    assert!(cache.is_empty());
    assert_eq!(cache.retained_bytes(), 0);
}

#[test]
fn test_purge_expired() {
    let mut cache = DnsCache::new(10);
    cache.put("stale.com:1".into(), make_test_response([1, 1, 1, 1], 0), 0);
    let fresh = make_test_response([2, 2, 2, 2], 3600);
    cache.put("fresh.com:1".into(), fresh.clone(), 3600);
    assert_eq!(cache.len(), 2);

    thread::sleep(Duration::from_secs(2));
    cache.purge_expired();

    assert_eq!(cache.len(), 1);
    assert!(cache.get("fresh.com:1").is_some());
    assert!(cache.get("stale.com:1").is_none());
    assert_eq!(cache.retained_bytes(), fresh.len());
}

#[test]
fn test_zero_max_size_clamped() {
    let mut cache = DnsCache::new(0);
    cache.put(
        "dns.com:1".into(),
        make_test_response([8, 8, 8, 8], 300),
        300,
    );
    assert!(cache.get("dns.com:1").is_some());
}
