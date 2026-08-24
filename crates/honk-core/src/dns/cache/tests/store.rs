use std::thread;
use std::time::Duration;

use super::{DnsCache, make_test_response};

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
fn wire_byte_budget_evicts_with_entry_slots_remaining() {
    let mut cache = DnsCache::new(32);
    let keys: Vec<String> = (0..1000)
        .map(|index| format!("large-same-shard-{index}:1"))
        .filter(|key| cache.shard_index(key) == 0)
        .take(2)
        .collect();
    let first = keys.first().expect("first key").clone();
    let second = keys.get(1).expect("second key").clone();

    cache.put(first.clone(), vec![0; 40_000], 300);
    cache.put(second.clone(), vec![0; 40_000], 300);

    assert!(cache.get(&first).is_none());
    assert!(cache.get(&second).is_some());
}

#[test]
fn wire_byte_budget_rejects_an_oversized_key() {
    let mut cache = DnsCache::new(1);
    let key = "x".repeat(70_000);

    cache.put(key.clone(), vec![0; 1], 300);

    assert!(cache.get(&key).is_none());
}

#[test]
fn shard_capacities_sum_exactly_and_clamp_count() {
    for capacity in 1..=33 {
        let cache = DnsCache::new(capacity);
        let capacities = cache.shard_capacities();
        assert_eq!(capacities.len(), capacity.min(16));
        assert_eq!(capacities.iter().sum::<usize>(), capacity);
        assert!(capacities.windows(2).all(|pair| pair[0] >= pair[1]));
        assert!(capacities.windows(2).all(|pair| pair[0] - pair[1] <= 1));
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
}

#[test]
fn test_clear() {
    let mut cache = DnsCache::new(10);
    cache.put("a.com:1".into(), make_test_response([1, 1, 1, 1], 300), 300);
    cache.put("b.com:1".into(), make_test_response([2, 2, 2, 2], 300), 300);
    assert_eq!(cache.len(), 2);

    cache.clear();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_purge_expired() {
    let mut cache = DnsCache::new(10);
    cache.put("stale.com:1".into(), make_test_response([1, 1, 1, 1], 0), 0);
    cache.put(
        "fresh.com:1".into(),
        make_test_response([2, 2, 2, 2], 3600),
        3600,
    );
    assert_eq!(cache.len(), 2);

    thread::sleep(Duration::from_secs(2));
    cache.purge_expired();

    assert_eq!(cache.len(), 1);
    assert!(cache.get("fresh.com:1").is_some());
    assert!(cache.get("stale.com:1").is_none());
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
