use crate::dns::cache::{CacheKey, DnsCache, ExactLookup, OperationKind};
use crate::dns::forwarder::build_dns_query;
use crate::dns::query::{IngressProfile, QueryContext};
use crate::dns::response::ResponseTemplate;

use super::super::codec;
use super::*;

#[tokio::test]
async fn exact_entry_round_trips_across_restart_and_renders_caller_txid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = test_db(&dir);
    let active_policy = policy(600);
    let (key, response, _) = fixture(
        IngressProfile::Internal,
        Some(active_policy.clone()),
        upstream("default"),
    );
    let persister = DnsCachePersister::spawn(Arc::clone(&db));
    persister.save(key.clone(), response.clone().into(), unix_now() + 300);
    persister.shutdown().await.expect("shutdown");

    let restored = DnsCache::new(16);
    let restored_service = restored.service();
    let restart = DnsCachePersister::spawn(db);
    assert_eq!(
        restart
            .restore(Arc::clone(&restored_service), Some(active_policy))
            .await
            .expect("restore"),
        1
    );
    assert!(matches!(
        restored_service.lookup_exact(&key, true),
        ExactLookup::Miss
    ));
    assert!(matches!(
        restored_service.lookup_exact(&key, false),
        ExactLookup::Positive { .. }
    ));
    let entry = restored_service.get_exact(&key).expect("exact hit");
    let mut caller_wire = build_dns_query("example.com", 1);
    caller_wire[0..2].copy_from_slice(&0x1234_u16.to_be_bytes());
    let caller = QueryContext::parse(&caller_wire).expect("caller");
    let template = ResponseTemplate::validate(&caller, &entry.response).expect("template");
    let rendered = template.render(&caller).expect("render");
    assert_eq!(&rendered[0..2], &0x1234_u16.to_be_bytes());
    restored_service.expire_positive_exact_for_test(&key);
    assert!(restored_service.get_stale_exact(&key, true).is_none());
    assert!(restored_service.get_stale_exact(&key, false).is_some());
    restart.shutdown().await.expect("restart shutdown");
}

#[tokio::test]
async fn mismatched_policy_and_corrupt_or_unknown_entries_are_counted_and_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = test_db(&dir);
    let (key, response, _) = fixture(
        IngressProfile::Internal,
        Some(policy(600)),
        upstream("default"),
    );
    let encoded = codec::encode(&key, &response, unix_now() + 300);
    db.write_dns(vec![(
        encoded.suffix.clone(),
        unix_now() + 300,
        encoded.bytes.clone(),
    )])
    .expect("write policy row");
    let mut unknown = encoded.bytes;
    unknown[4] = 99;
    db.write_dns(vec![
        ("unknown".to_string(), unix_now() + 300, unknown),
        ("collision".to_string(), unix_now() + 300, vec![1, 2, 3]),
    ])
    .expect("write invalid rows");

    let persister = DnsCachePersister::spawn(db);
    assert_eq!(
        persister
            .restore(DnsCache::new(8).service(), Some(policy(601)))
            .await
            .expect("restore"),
        0
    );
    let counters = persister.counters();
    assert_eq!(counters.policy_mismatch, 1);
    assert_eq!(counters.version_mismatch, 1);
    assert_eq!(counters.corrupt, 1);
    persister.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn exact_restore_does_not_hit_profile_scope_wire_or_policy_variants() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = test_db(&dir);
    let active_policy = policy(600);
    let (key, response, _) = fixture(
        IngressProfile::Internal,
        Some(active_policy.clone()),
        upstream("default"),
    );
    let encoded = codec::encode(&key, &response, unix_now() + 300);
    db.write_dns(vec![(encoded.suffix, unix_now() + 300, encoded.bytes)])
        .expect("write");
    let cache = DnsCache::new(16);
    let service = cache.service();
    let persister = DnsCachePersister::spawn(db);
    assert_eq!(
        persister
            .restore(Arc::clone(&service), Some(active_policy.clone()))
            .await
            .expect("restore"),
        1
    );
    let profile = fixture(
        IngressProfile::Tcp,
        Some(active_policy.clone()),
        upstream("default"),
    )
    .0;
    let scope = fixture(
        IngressProfile::Internal,
        Some(active_policy.clone()),
        upstream("other"),
    )
    .0;
    let no_policy = fixture(IngressProfile::Internal, None, upstream("default")).0;
    let mut wire = build_dns_query("example.com", 1);
    wire[2] ^= 0x10;
    let wire_query = QueryContext::parse(&wire).expect("wire variant");
    let wire_key = CacheKey::new(
        &wire_query,
        Some(active_policy),
        upstream("default"),
        OperationKind::Resolve,
    );
    for variant in [profile, scope, no_policy, wire_key] {
        assert!(service.get_exact(&variant).is_none());
    }
    persister.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn expired_entry_is_skipped_and_counted_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = test_db(&dir);
    let (key, response, _) = fixture(IngressProfile::Internal, None, upstream("default"));
    let encoded = codec::encode(&key, &response, unix_now().saturating_sub(1));
    db.write_dns(vec![(encoded.suffix, unix_now() + 300, encoded.bytes)])
        .expect("write stale row");
    let persister = DnsCachePersister::spawn(db);

    assert_eq!(
        persister
            .restore(DnsCache::new(8).service(), None)
            .await
            .expect("restore"),
        0
    );
    assert_eq!(persister.counters().stale, 1);
    persister.shutdown().await.expect("shutdown");
}
