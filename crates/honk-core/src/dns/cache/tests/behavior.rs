use std::thread;
use std::time::{Duration, Instant};

use super::{CacheCounters, CachedEntry, DnsCache, make_test_response};

#[test]
fn cache_counters_are_exact_for_hit_miss_and_stale_paths() {
    let mut cache = DnsCache::new(8);
    let response = make_test_response([192, 0, 2, 1], 60);

    assert!(cache.get("missing").is_none());
    cache.put("live".into(), response.clone(), 60);
    assert!(cache.get("live").is_some());
    cache.insert_expired_for_test("stale".into(), response, 60);
    assert!(cache.get("stale").is_none());
    assert!(cache.get_stale("stale").is_some());
    cache.put_negative("negative".into(), 60, 3);
    assert!(cache.negative_hit("negative").is_some());
    cache.insert_beyond_stale_retention_for_test(
        "retention-exceeded".into(),
        make_test_response([192, 0, 2, 2], 60),
        60,
    );
    assert!(cache.get("retention-exceeded").is_none());

    assert_eq!(
        cache.counters(),
        CacheCounters {
            hits: 2,
            misses: 3,
            stale: 1,
        }
    );
}

#[test]
fn test_serve_stale_window() {
    let mut cache = DnsCache::new(10);
    let response = make_test_response([93, 184, 216, 34], 0);
    cache.put("example.com:1".into(), response.clone(), 0);
    thread::sleep(Duration::from_secs(2));

    assert!(cache.get("example.com:1").is_none());
    let stale = cache.get_stale("example.com:1").expect("stale entry");
    assert_eq!(stale.response, response);
    assert!(stale.is_expired());
}

#[test]
fn test_stale_retention_exceeded() {
    let entry = CachedEntry {
        response: bytes::Bytes::new(),
        expires_at: Instant::now() - Duration::from_secs(7200),
        min_ttl: 1,
        strict_reusable: true,
        rejected: false,
    };
    assert!(entry.is_stale_retention_exceeded());
    let fresh = CachedEntry {
        response: bytes::Bytes::new(),
        expires_at: Instant::now() - Duration::from_secs(10),
        min_ttl: 1,
        strict_reusable: true,
        rejected: false,
    };
    assert!(!fresh.is_stale_retention_exceeded());
}

#[test]
fn test_remaining_ttl() {
    let entry = CachedEntry {
        response: bytes::Bytes::new(),
        expires_at: Instant::now() + Duration::from_secs(45),
        min_ttl: 45,
        strict_reusable: true,
        rejected: false,
    };
    let remaining = entry.remaining_ttl_secs();
    assert!(
        (44..=46).contains(&remaining),
        "expected ~45, got {}",
        remaining
    );
}
